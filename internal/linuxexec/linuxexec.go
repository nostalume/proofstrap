package linuxexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const captureLimit = 8 << 20

var (
	ErrIdentityChanged = errors.New("executable identity changed")
	ErrOutputLimit     = errors.New("process output limit exceeded")
)

type Identity struct {
	Path   string
	Digest [sha256.Size]byte
}

type Result struct {
	Started  bool
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

func Identify(candidate string) (Identity, error) {
	if !filepath.IsAbs(candidate) {
		return Identity{}, fmt.Errorf("linuxexec: executable path %q is not absolute", candidate)
	}
	path, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return Identity{}, fmt.Errorf("linuxexec: resolve %q: %w", candidate, err)
	}
	if err := trustedParents(path); err != nil {
		return Identity{}, err
	}

	file, err := os.Open(path)
	if err != nil {
		return Identity{}, fmt.Errorf("linuxexec: open %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Identity{}, fmt.Errorf("linuxexec: inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Identity{}, fmt.Errorf("linuxexec: %q is not a regular executable", path)
	}
	if err := trusted(path, info); err != nil {
		return Identity{}, err
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Identity{}, fmt.Errorf("linuxexec: hash %q: %w", path, err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return Identity{Path: path, Digest: digest}, nil
}

func trustedParents(path string) error {
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("linuxexec: inspect parent %q: %w", directory, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("linuxexec: parent %q is not a directory", directory)
		}
		if err := trusted(directory, info); err != nil {
			return err
		}
		if directory == string(filepath.Separator) {
			return nil
		}
	}
}

func trusted(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("linuxexec: ownership metadata unavailable for %q", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("linuxexec: %q is not owned by root", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("linuxexec: %q is writable by group or others", path)
	}
	return nil
}

func Run(ctx context.Context, expected Identity, args []string, stdin []byte) (Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, errors.New("linuxexec: context deadline required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	actual, err := Identify(expected.Path)
	if err != nil {
		return Result{}, fmt.Errorf("linuxexec: re-identify %q: %w", expected.Path, err)
	}
	if actual != expected {
		return Result{}, ErrIdentityChanged
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	overflow := make(chan struct{}, 1)
	stdout := limitedCapture{overflow: overflow}
	stderr := limitedCapture{overflow: overflow}
	command := exec.Command(expected.Path, args...)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
	}
	command.Stdin = bytes.NewReader(stdin)
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return Result{}, fmt.Errorf("linuxexec: start %q: %w", expected.Path, err)
	}

	result := Result{Started: true}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()

	var runErr error
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-ctx.Done():
		runErr = ctx.Err()
		killProcessGroup(command.Process.Pid)
		waitErr = <-wait
	case <-overflow:
		runErr = ErrOutputLimit
		killProcessGroup(command.Process.Pid)
		waitErr = <-wait
	}
	result.Stdout = stdout.contents
	result.Stderr = stderr.contents
	if (stdout.overflowed || stderr.overflowed) && !errors.Is(runErr, ErrOutputLimit) {
		runErr = errors.Join(runErr, ErrOutputLimit)
	}
	if runErr != nil {
		return result, runErr
	}
	if waitErr == nil {
		result.ExitCode = command.ProcessState.ExitCode()
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) && exit.ExitCode() >= 0 {
		result.ExitCode = exit.ExitCode()
		return result, nil
	}
	return result, fmt.Errorf("linuxexec: wait for %q: %w", expected.Path, waitErr)
}

func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

type limitedCapture struct {
	contents   []byte
	overflow   chan<- struct{}
	overflowed bool
}

func (capture *limitedCapture) Write(data []byte) (int, error) {
	written := len(data)
	remaining := captureLimit - len(capture.contents)
	if remaining < len(data) {
		if remaining > 0 {
			capture.contents = append(capture.contents, data[:remaining]...)
		}
		if !capture.overflowed {
			capture.overflowed = true
			select {
			case capture.overflow <- struct{}{}:
			default:
			}
		}
		return written, nil
	}
	capture.contents = append(capture.contents, data...)
	return written, nil
}
