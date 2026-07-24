package proofstrap

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func (OSRunner) Readlink(path string) (string, error) { return os.Readlink(path) }

func (OSRunner) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func (OSRunner) ReadRegularFilePrefixBeneath(root, relative string, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("regular file prefix size must be non-negative")
	}
	if !filepath.IsAbs(root) || relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || strings.HasPrefix(relative, "../") {
		return nil, fmt.Errorf("invalid rooted path %q beneath %q", relative, root)
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(root), "/"), "/")
	components = append(components, strings.Split(relative, "/")...)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for index, component := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	path := filepath.Join(root, relative)
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open %s returned invalid descriptor", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	contents := make([]byte, size)
	if _, err := io.ReadFull(file, contents); err != nil {
		return nil, err
	}
	return contents, nil
}
