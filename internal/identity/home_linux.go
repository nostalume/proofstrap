package identity

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func systemHomeEffects() homeEffects {
	return homeEffects{observe: observeHomePath, create: createHomePath, chmod: chmodHomePath}
}

func observeHomePath(path string) (homeState, error) {
	parent, leaf, err := splitHomePath(path)
	if err != nil {
		return homeState{}, err
	}
	fd, err := openTrustedDirectory(parent)
	if err != nil {
		return homeState{}, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	err = unix.Fstatat(fd, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return homeState{trusted: true}, nil
	}
	if err != nil {
		return homeState{}, fmt.Errorf("inspect home %q: %w", path, err)
	}
	return homeState{
		exists: true, trusted: true, directory: stat.Mode&unix.S_IFMT == unix.S_IFDIR,
		uid: stat.Uid, gid: stat.Gid, mode: uint16(stat.Mode & 0o777),
	}, nil
}

func createHomePath(path string, uid, gid uint32) (started bool, err error) {
	parent, leaf, err := splitHomePath(path)
	if err != nil {
		return false, err
	}
	parentFD, err := openTrustedDirectory(parent)
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)
	return createHomeAt(parentFD, leaf, uid, gid)
}

func createHomeAt(parentFD int, leaf string, uid, gid uint32) (started bool, err error) {
	var target unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &target, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return false, fmt.Errorf("home target already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return false, fmt.Errorf("inspect home target: %w", err)
	}
	stage := "." + leaf + ".proofstrap-stage"
	if err := unix.Mkdirat(parentFD, stage, 0o700); err != nil {
		return false, fmt.Errorf("create home stage: %w", err)
	}
	started = true
	published := false
	defer func() {
		if published {
			return
		}
		cleanupErr := unix.Unlinkat(parentFD, stage, unix.AT_REMOVEDIR)
		if cleanupErr != nil && !errors.Is(cleanupErr, unix.ENOENT) {
			err = errors.Join(err, fmt.Errorf("cleanup home stage: %w", cleanupErr))
		}
	}()
	stageFD, err := linux.OpenDirAt(parentFD, stage)
	if err != nil {
		return started, fmt.Errorf("open home stage: %w", err)
	}
	if err := unix.Fchown(stageFD, int(uid), int(gid)); err != nil {
		unix.Close(stageFD)
		return started, fmt.Errorf("own home stage: %w", err)
	}
	if err := unix.Fchmod(stageFD, 0o700); err != nil {
		unix.Close(stageFD)
		return started, fmt.Errorf("mode home stage: %w", err)
	}
	if err := syncDirectory(stageFD); err != nil {
		unix.Close(stageFD)
		return started, fmt.Errorf("sync home stage: %w", err)
	}
	if err := unix.Close(stageFD); err != nil {
		return started, fmt.Errorf("close home stage: %w", err)
	}
	if err := unix.Renameat2(parentFD, stage, parentFD, leaf, unix.RENAME_NOREPLACE); err != nil {
		return started, fmt.Errorf("publish home without replacement: %w", err)
	}
	published = true
	if err := syncDirectory(parentFD); err != nil {
		return started, fmt.Errorf("sync home parent: %w", err)
	}
	return started, nil
}

func chmodHomePath(path string, mode uint16) (bool, error) {
	if mode > 0o777 {
		return false, fmt.Errorf("invalid home mode")
	}
	parent, leaf, err := splitHomePath(path)
	if err != nil {
		return false, err
	}
	parentFD, err := openTrustedDirectory(parent)
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)
	return chmodHomeAt(parentFD, leaf, mode)
}

func chmodHomeAt(parentFD int, leaf string, mode uint16) (bool, error) {
	homeFD, err := linux.OpenDirAt(parentFD, leaf)
	if err != nil {
		return false, fmt.Errorf("open exact home: %w", err)
	}
	defer unix.Close(homeFD)
	if err := unix.Fchmod(homeFD, uint32(mode)); err != nil {
		return true, fmt.Errorf("set home mode: %w", err)
	}
	if err := syncDirectory(homeFD); err != nil {
		return true, fmt.Errorf("sync home mode: %w", err)
	}
	return true, nil
}

func splitHomePath(path string) (string, string, error) {
	if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return "", "", fmt.Errorf("home path must be clean, absolute, and non-root")
	}
	return filepath.Dir(path), filepath.Base(path), nil
}

func openTrustedDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("trusted directory path is invalid")
	}
	current, err := linux.OpenDir("/")
	if err != nil {
		return -1, fmt.Errorf("open filesystem root: %w", err)
	}
	if err := requireTrustedDirectory(current, "/"); err != nil {
		unix.Close(current)
		return -1, err
	}
	if path == "/" {
		return current, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, openErr := linux.OpenDirAt(current, component)
		unix.Close(current)
		if openErr != nil {
			return -1, fmt.Errorf("open trusted directory component %q: %w", component, openErr)
		}
		if err := requireTrustedDirectory(next, component); err != nil {
			unix.Close(next)
			return -1, err
		}
		current = next
	}
	return current, nil
}

func requireTrustedDirectory(fd int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect trusted directory component %q: %w", name, err)
	}
	if stat.Uid != 0 || stat.Mode&0o022 != 0 {
		return fmt.Errorf("directory component %q is not trusted root-owned state", name)
	}
	return nil
}

func syncDirectory(fd int) error {
	err := unix.Fsync(fd)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	return err
}
