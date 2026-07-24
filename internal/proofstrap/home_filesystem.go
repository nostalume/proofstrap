package proofstrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type homeFilesystem interface {
	openRoot() (int, error)
	info(int) (PathInfo, error)
	openDirectoryAt(int, string) (int, error)
	mkdirAt(int, string, uint32) error
	chown(int, uint32, uint32) error
	chmod(int, uint32) error
	close(int) error
}

type unixHomeFilesystem struct{}

func (unixHomeFilesystem) openRoot() (int, error) {
	return unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}
func (unixHomeFilesystem) info(fd int) (PathInfo, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return PathInfo{}, err
	}
	kind := OtherPath
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		kind = DirectoryPath
	}
	return PathInfo{Kind: kind, Mode: stat.Mode & 0o7777, UID: stat.Uid, GID: stat.Gid}, nil
}
func (unixHomeFilesystem) openDirectoryAt(parent int, name string) (int, error) {
	return unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}
func (unixHomeFilesystem) mkdirAt(parent int, name string, mode uint32) error {
	return unix.Mkdirat(parent, name, mode)
}
func (unixHomeFilesystem) chown(fd int, uid, gid uint32) error {
	return unix.Fchown(fd, int(uid), int(gid))
}
func (unixHomeFilesystem) chmod(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }
func (unixHomeFilesystem) close(fd int) error              { return unix.Close(fd) }

func (OSRunner) CreateHome(creation HomeCreation) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("home creation requires root authority")
	}
	return createHome(unixHomeFilesystem{}, creation)
}

func createHome(filesystem homeFilesystem, creation HomeCreation) error {
	if creation.Path == "/" || !filepath.IsAbs(creation.Path) || filepath.Clean(creation.Path) != creation.Path {
		return fmt.Errorf("home path must be canonical, absolute, and non-root")
	}
	if creation.Mode > 0o777 {
		return fmt.Errorf("home mode must contain only permission bits")
	}
	components := strings.Split(strings.TrimPrefix(creation.Path, "/"), "/")
	parent, err := filesystem.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close(parent) }()
	if info, infoErr := filesystem.info(parent); infoErr != nil {
		return infoErr
	} else if !trustedHomeAncestor(info) {
		return fmt.Errorf("home ancestor / is not a trusted root-owned directory")
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := filesystem.openDirectoryAt(parent, component)
		if openErr != nil {
			return openErr
		}
		if info, infoErr := filesystem.info(next); infoErr != nil {
			_ = filesystem.close(next)
			return infoErr
		} else if !trustedHomeAncestor(info) {
			_ = filesystem.close(next)
			return fmt.Errorf("home ancestor %s is not a trusted root-owned directory", component)
		}
		_ = filesystem.close(parent)
		parent = next
	}
	leaf := components[len(components)-1]
	if err := filesystem.mkdirAt(parent, leaf, creation.Mode); err != nil {
		return err
	}
	home, err := filesystem.openDirectoryAt(parent, leaf)
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close(home) }()
	if err := filesystem.chown(home, creation.UID, creation.GID); err != nil {
		return err
	}
	return filesystem.chmod(home, creation.Mode)
}
