package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Command struct {
	Name        string
	Args        []string
	stdin       string
	timeout     time.Duration
	stdoutLimit int
	stderrLimit int
}

func (command Command) String() string {
	return strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
}

type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Err      error
}

const maximumCaptureBytes = 64 << 20

type limitedCapture struct {
	contents   []byte
	limit      int
	overflowed bool
}

func newLimitedCapture(limit int) *limitedCapture {
	if limit <= 0 || limit > maximumCaptureBytes {
		limit = maximumCaptureBytes
	}
	return &limitedCapture{limit: limit}
}

func (capture *limitedCapture) Write(contents []byte) (int, error) {
	written := len(contents)
	remaining := capture.limit - len(capture.contents)
	if remaining < len(contents) {
		capture.overflowed = true
	}
	if remaining > 0 {
		if remaining > len(contents) {
			remaining = len(contents)
		}
		capture.contents = append(capture.contents, contents[:remaining]...)
	}
	return written, nil
}

func (capture *limitedCapture) String() string { return string(capture.contents) }

func outputCaptureError(stdout, stderr *limitedCapture) error {
	var exceeded []string
	if stdout.overflowed {
		exceeded = append(exceeded, fmt.Sprintf("stdout exceeded %d-byte capture limit", stdout.limit))
	}
	if stderr.overflowed {
		exceeded = append(exceeded, fmt.Sprintf("stderr exceeded %d-byte capture limit", stderr.limit))
	}
	if len(exceeded) == 0 {
		return nil
	}
	return errors.New(strings.Join(exceeded, "; "))
}

type PathKind uint8

const (
	DirectoryPath PathKind = iota + 1
	RegularPath
	SymlinkPath
	OtherPath
)

type PathInfo struct {
	Kind PathKind
	Mode uint32
	UID  uint32
	GID  uint32
}

type HomeCreation struct {
	Path string
	Mode uint32
	UID  uint32
	GID  uint32
}

type ExecutableIdentity struct {
	Path   string
	Digest string
}

type Runner interface {
	EffectiveUID() (uint32, error)
	ExecutableIdentity() (ExecutableIdentity, error)
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (PathInfo, error)
	Readlink(path string) (string, error)
	EvalSymlinks(path string) (string, error)
	ReadRegularFilePrefixBeneath(root, relative string, size int) ([]byte, error)
	LookPath(name string) (string, error)
	CreateHome(HomeCreation) error

	Run(ctx context.Context, command Command) Result
}

type OSRunner struct{}

func (OSRunner) EffectiveUID() (uint32, error)        { return uint32(os.Geteuid()), nil }
func (OSRunner) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (OSRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (OSRunner) Lstat(path string) (PathInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return PathInfo{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return PathInfo{}, fmt.Errorf("lstat metadata is unavailable for %s", path)
	}
	kind := OtherPath
	switch stat.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		kind = DirectoryPath
	case syscall.S_IFREG:
		kind = RegularPath
	case syscall.S_IFLNK:
		kind = SymlinkPath
	}
	return PathInfo{Kind: kind, Mode: stat.Mode & 0o7777, UID: stat.Uid, GID: stat.Gid}, nil
}

func (OSRunner) Run(ctx context.Context, command Command) Result {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		timeout := command.timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	name, materializeErr := materializeProofstrapSelf(command.Name)
	if materializeErr != nil {
		return Result{ExitCode: -1, Err: materializeErr}
	}
	args := append([]string(nil), command.Args...)
	for index, argument := range args {
		materialized, materializeErr := materializeProofstrapSelf(argument)
		if materializeErr != nil {
			return Result{ExitCode: -1, Err: materializeErr}
		}
		args[index] = materialized
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(command.stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	stdout := newLimitedCapture(command.stdoutLimit)
	stderr := newLimitedCapture(command.stderrLimit)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return Result{ExitCode: 127, Err: err}
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var err error
	timedOut := false
	select {
	case err = <-wait:
	case <-ctx.Done():
		timedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		err = <-wait
	}
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if timedOut {
		result.ExitCode, result.Err = 124, ctx.Err()
	} else if err == nil {
	} else if exit, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exit.ExitCode()
	} else {
		result.ExitCode, result.Err = 127, err
	}
	result.Err = errors.Join(result.Err, outputCaptureError(stdout, stderr))
	return result
}

func resultDetail(result Result) string {
	if detail := strings.TrimSpace(result.Stderr); detail != "" {
		return detail
	}
	if result.Err != nil {
		return result.Err.Error()
	}
	if detail := strings.TrimSpace(result.Stdout); detail != "" {
		return detail
	}
	return fmt.Sprintf("exit %d", result.ExitCode)
}
