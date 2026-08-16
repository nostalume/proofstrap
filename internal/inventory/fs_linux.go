package inventory

import (
	"errors"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func createBeneath(anchor string, components []string, mode uint32) error {
	fd, err := linux.OpenDir(anchor)
	if err != nil {
		return err
	}
	for _, component := range components {
		next, openErr := linux.OpenDirAt(fd, component)
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
			next, openErr = linux.OpenDirAt(fd, component)
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

func openScope(root string) (int, bool, error) {
	rootFD, err := linux.OpenDir(root)
	if errors.Is(err, unix.ENOENT) {
		return -1, false, nil
	}
	if err != nil {
		return -1, true, err
	}
	shaFD, err := linux.OpenDirAt(rootFD, "sha256")
	_ = unix.Close(rootFD)
	if err != nil {
		return -1, true, err
	}
	return shaFD, true, nil
}
