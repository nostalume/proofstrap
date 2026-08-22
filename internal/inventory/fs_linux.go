package inventory

import (
	"errors"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func createBeneath(anchor string, components []string, mode uint32) (err error) {
	fd, err := linux.OpenDir(anchor)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unix.Close(fd); err == nil {
			err = closeErr
		}
	}()
	for _, component := range components {
		next, openErr := linux.OpenDirAt(fd, component)
		if openErr != nil {
			if !errors.Is(openErr, unix.ENOENT) {
				return openErr
			}
			created := false
			if err := unix.Mkdirat(fd, component, mode); err == nil {
				created = true
			} else if !errors.Is(err, unix.EEXIST) {
				return err
			}
			next, openErr = linux.OpenDirAt(fd, component)
			if openErr != nil {
				return openErr
			}
			if created {
				if err := unix.Fchmod(next, mode); err != nil {
					_ = unix.Close(next)
					return err
				}
			}
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil
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
