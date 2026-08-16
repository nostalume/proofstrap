package pack

import (
	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func openStore(root string) (int, error) {
	fd, err := linux.OpenDir(root)
	if err != nil {
		return -1, err
	}
	sha, err := linux.OpenDirAt(fd, "sha256")
	_ = unix.Close(fd)
	return sha, err
}
