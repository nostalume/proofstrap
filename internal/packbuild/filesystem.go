package packbuild

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func validPath(value string) bool {
	return value != "" && value != "/" && !strings.ContainsRune(value, 0) && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func openDirectory(path string) (int, error) {
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

func createStage(directory int, random io.Reader) (int, string, error) {
	for range 16 {
		var token [16]byte
		if _, err := io.ReadFull(random, token[:]); err != nil {
			return -1, "", err
		}
		name := fmt.Sprintf(".proofstrap-pack-%x", token)
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
