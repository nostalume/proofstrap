package linux

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrNotRegular = errors.New("not a regular file")

// CleanAbsoluteNonRoot reports whether path is canonical, absolute, and not root.
func CleanAbsoluteNonRoot(path string) bool {
	return path != "" && path != "/" && !strings.ContainsRune(path, 0) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path
}

// OpenDir opens a clean absolute directory without following path components.
// The caller owns the returned descriptor.
func OpenDir(path string) (int, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return -1, fmt.Errorf("directory path must be clean and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := OpenDirAt(fd, component)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

// OpenDirAt opens one directory component without following it. The caller
// owns the returned descriptor.
func OpenDirAt(directory int, name string) (int, error) {
	if name != "." && !component(name) {
		return -1, fmt.Errorf("directory name must be one clean path component")
	}
	return unix.Openat(directory, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// OpenRegular opens a clean absolute regular-file leaf without following it.
// The caller owns the returned descriptor.
func OpenRegular(path string) (int, error) {
	if !CleanAbsoluteNonRoot(path) {
		return -1, fmt.Errorf("file path must be clean, absolute, and non-root")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	return admitRegular(fd, err)
}

// OpenRegularAt opens one regular-file leaf without following it. The caller
// owns the returned descriptor.
func OpenRegularAt(directory int, name string) (int, error) {
	if !component(name) {
		return -1, fmt.Errorf("file name must be one clean path component")
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	return admitRegular(fd, err)
}

func admitRegular(fd int, err error) (int, error) {
	if err != nil {
		return -1, err
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: object", ErrNotRegular)
	}
	return fd, nil
}

func component(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

// CreateStageAt allocates a mode-0600 staging file with at most 16 attempts.
// The caller owns the returned descriptor and staged name.
func CreateStageAt(directory int, random io.Reader, prefix string) (int, string, error) {
	if prefix == "" || filepath.Base(prefix) != prefix || strings.ContainsRune(prefix, 0) {
		return -1, "", fmt.Errorf("stage prefix must be one nonempty path component")
	}
	for range 16 {
		var token [16]byte
		if _, err := io.ReadFull(random, token[:]); err != nil {
			return -1, "", err
		}
		name := fmt.Sprintf("%s%x", prefix, token)
		fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return fd, name, nil
		}
		if err != unix.EEXIST {
			return -1, "", err
		}
	}
	return -1, "", fmt.Errorf("staging collision retry limit exceeded")
}
