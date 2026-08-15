package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func validPath(value string) bool {
	return value != "" && value != "/" && !strings.ContainsRune(value, 0) && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func openDirectory(path string) (int, error) {
	if path == "/" {
		return unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func createBeneath(anchor string, components []string, mode uint32) error {
	fd, err := openDirectory(anchor)
	if err != nil {
		return err
	}
	for _, component := range components {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			if !errors.Is(openErr, unix.ENOENT) {
				_ = unix.Close(fd)
				return openErr
			}
			created := false
			if err := unix.Mkdirat(fd, component, mode); err == nil {
				created = true
			} else if !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return err
			}
			next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				_ = unix.Close(fd)
				return openErr
			}
			if created {
				if err := unix.Fchmod(next, mode); err != nil {
					_ = unix.Close(next)
					_ = unix.Close(fd)
					return err
				}
			}
		}
		_ = unix.Close(fd)
		fd = next
	}
	return unix.Close(fd)
}

func createLeaf(path string, mode uint32) error {
	parent := filepath.Dir(path)
	name := filepath.Base(path)
	fd, err := openDirectory(parent)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	created := false
	if err := unix.Mkdirat(fd, name, mode); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return err
	}
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if created {
		if err := unix.Fchmod(child, mode); err != nil {
			_ = unix.Close(child)
			return err
		}
	}
	return unix.Close(child)
}

func openScope(root string) (int, bool, error) {
	rootFD, err := openDirectory(root)
	if errors.Is(err, unix.ENOENT) {
		return -1, false, nil
	}
	if err != nil {
		return -1, true, err
	}
	shaFD, err := unix.Openat(rootFD, "sha256", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = unix.Close(rootFD)
	if err != nil {
		return -1, true, err
	}
	return shaFD, true, nil
}

func openRegularAt(directory int, name string) (*os.File, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, errors.New("object is not a regular file")
	}
	return os.NewFile(uintptr(fd), name), nil
}
