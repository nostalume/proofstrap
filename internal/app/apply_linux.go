package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type fileJournal struct {
	file   journalFile
	parent int
	first  bool
	offset int64
}

type journalFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Seek(int64, int) (int64, error)
	Close() error
}

func preflightOutputs(journal, receipt string) error {
	for _, path := range []string{journal, receipt} {
		if path == "" {
			continue
		}
		if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
			return fmt.Errorf("output path must be clean, absolute, and non-root")
		}
		parent, err := openOutputParent(filepath.Dir(path))
		if err != nil {
			return err
		}
		if err := unix.Close(parent); err != nil {
			return err
		}
	}
	return nil
}

func openJournal(path string) (journalWriter, error) {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("journal path must be clean, absolute, and non-root")
	}
	parent, err := openOutputParent(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = unix.Close(parent)
		return nil, err
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parent, filepath.Base(path), 0)
		_ = unix.Close(parent)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parent, filepath.Base(path), 0)
		_ = unix.Close(parent)
		return nil, fmt.Errorf("open journal")
	}
	return &fileJournal{file: file, parent: parent, first: true}, nil
}

func (journal *fileJournal) Append(data []byte) error {
	if journal == nil || journal.file == nil || len(data) == 0 {
		return fmt.Errorf("open journal and nonempty frame are required")
	}
	start := journal.offset
	remaining := data
	for len(remaining) != 0 {
		written, err := journal.file.Write(remaining)
		if err != nil {
			return journal.rollback(start, err)
		}
		if written == 0 {
			return journal.rollback(start, io.ErrShortWrite)
		}
		remaining = remaining[written:]
	}
	if err := journal.file.Sync(); err != nil {
		return journal.rollback(start, err)
	}
	journal.offset = start + int64(len(data))
	if journal.first {
		if err := unix.Fsync(journal.parent); err != nil {
			return journal.rollback(start, err)
		}
		journal.first = false
	}
	return nil
}

func (journal *fileJournal) rollback(offset int64, primary error) error {
	truncateErr := journal.file.Truncate(offset)
	_, seekErr := journal.file.Seek(offset, io.SeekStart)
	syncErr := journal.file.Sync()
	journal.offset = offset
	return errors.Join(primary, truncateErr, seekErr, syncErr)
}

func (journal *fileJournal) Close() error {
	if journal == nil {
		return nil
	}
	var fileErr error
	if journal.file != nil {
		fileErr = journal.file.Close()
		journal.file = nil
	}
	var parentErr error
	if journal.parent >= 0 {
		parentErr = unix.Close(journal.parent)
	}
	journal.parent = -1
	return errors.Join(fileErr, parentErr)
}

func readPlanFile(path string) ([]byte, error) {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("Plan path must be clean, absolute, and non-root")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open Plan")
	}
	defer file.Close()
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return nil, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: Plan is not a regular file", ErrInvalidPlan)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPlanBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPlanBytes {
		return nil, fmt.Errorf("%w: Plan exceeds 64 MiB", ErrInvalidPlan)
	}
	return data, nil
}
