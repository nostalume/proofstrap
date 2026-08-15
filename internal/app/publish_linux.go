package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

type PublishReceipt struct {
	path   string
	digest pack.Digest
}

func (receipt PublishReceipt) Path() string        { return receipt.path }
func (receipt PublishReceipt) Digest() pack.Digest { return receipt.digest }

func PublishPlan(path string, plan Plan) (PublishReceipt, error) {
	canonical, err := DecodePlan(plan.bytes)
	if err != nil || canonical.digest != plan.digest {
		return PublishReceipt{}, fmt.Errorf("valid sealed plan is required")
	}
	if err := publishOutput(path, "plan", canonical.bytes); err != nil {
		return PublishReceipt{}, err
	}
	return PublishReceipt{path: path, digest: canonical.digest}, nil
}

func publishReceipt(path string, data []byte) error {
	return publishOutput(path, "receipt", data)
}

func publishOutput(path, kind string, data []byte) (err error) {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return fmt.Errorf("%s output must be a clean absolute non-root path", kind)
	}
	parent, err := openOutputParent(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	stage, fd, err := createOutputStage(parent)
	if err != nil {
		return err
	}
	defer func() {
		cleanupErr := unix.Unlinkat(parent, stage, 0)
		if errors.Is(cleanupErr, unix.ENOENT) {
			cleanupErr = nil
		}
		err = errors.Join(err, cleanupErr)
	}()
	file := os.NewFile(uintptr(fd), stage)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open %s stage", kind)
	}
	if err = writeAll(file, data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat2(parent, stage, parent, filepath.Base(path), unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s output exists", os.ErrExist, kind)
		}
		return err
	}
	return unix.Fsync(parent)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func openOutputParent(path string) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if path != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return -1, openErr
			}
			fd = next
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("output parent ownership or mode is unsafe")
	}
	return fd, nil
}

func createOutputStage(parent int) (string, int, error) {
	for range 8 {
		entropy := make([]byte, 16)
		if _, err := rand.Read(entropy); err != nil {
			return "", -1, err
		}
		name := ".proofstrap-output-" + hex.EncodeToString(entropy)
		fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			if chmodErr := unix.Fchmod(fd, 0o600); chmodErr != nil {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(parent, name, 0)
				return "", -1, chmodErr
			}
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, fmt.Errorf("allocate output staging file")
}
