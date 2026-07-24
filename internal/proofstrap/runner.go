package proofstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Command struct {
	Name    string
	Args    []string
	stdin   string
	timeout time.Duration
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

type homeFilesystem interface {
	openRoot() (int, error)
	info(int) (PathInfo, error)
	openDirectoryAt(int, string) (int, error)
	mkdirAt(int, string, uint32) error
	chown(int, uint32, uint32) error
	chmod(int, uint32) error
	close(int) error
}

type syscallHomeFilesystem struct{}

func (syscallHomeFilesystem) openRoot() (int, error) {
	return syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
}
func (syscallHomeFilesystem) info(fd int) (PathInfo, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return PathInfo{}, err
	}
	kind := OtherPath
	if stat.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		kind = DirectoryPath
	}
	return PathInfo{Kind: kind, Mode: stat.Mode & 0o7777, UID: stat.Uid, GID: stat.Gid}, nil
}
func (syscallHomeFilesystem) openDirectoryAt(parent int, name string) (int, error) {
	return syscall.Openat(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}
func (syscallHomeFilesystem) mkdirAt(parent int, name string, mode uint32) error {
	return syscall.Mkdirat(parent, name, mode)
}
func (syscallHomeFilesystem) chown(fd int, uid, gid uint32) error {
	return syscall.Fchown(fd, int(uid), int(gid))
}
func (syscallHomeFilesystem) chmod(fd int, mode uint32) error { return syscall.Fchmod(fd, mode) }
func (syscallHomeFilesystem) close(fd int) error              { return syscall.Close(fd) }

type Runner interface {
	EffectiveUID() (uint32, error)
	ExecutableIdentity() (ExecutableIdentity, error)
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (PathInfo, error)
	LookPath(name string) (string, error)
	CreateHome(HomeCreation) error

	Run(ctx context.Context, command Command) Result
}

type OSRunner struct{}

func (OSRunner) EffectiveUID() (uint32, error)        { return uint32(os.Geteuid()), nil }
func (OSRunner) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (OSRunner) Readlink(path string) (string, error) { return os.Readlink(path) }
func (OSRunner) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
func (OSRunner) ReadFilePrefix(path string, size int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents := make([]byte, size)
	if _, err := io.ReadFull(file, contents); err != nil {
		return nil, err
	}
	return contents, nil
}
func (OSRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (OSRunner) ExecutableIdentity() (ExecutableIdentity, error) {
	path, err := os.Executable()
	if err != nil {
		return ExecutableIdentity{}, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	digest, err := runningExecutableDigest()
	if err != nil {
		return ExecutableIdentity{}, err
	}
	return ExecutableIdentity{Path: path, Digest: digest}, nil
}

func runningExecutableDigest() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

const proofstrapSelfPrefix = "@proofstrap-self="

func materializeProofstrapSelf(argument string) (string, error) {
	if !strings.HasPrefix(argument, proofstrapSelfPrefix) {
		return argument, nil
	}
	expected := strings.TrimPrefix(argument, proofstrapSelfPrefix)
	actual, err := runningExecutableDigest()
	if err != nil {
		return "", err
	}
	if actual != expected {
		return "", fmt.Errorf("running executable digest changed")
	}
	return fmt.Sprintf("/proc/%d/exe", os.Getpid()), nil
}

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

func (OSRunner) CreateHome(creation HomeCreation) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("home creation requires root authority")
	}
	return createHome(syscallHomeFilesystem{}, creation)
}

func createHome(filesystem homeFilesystem, creation HomeCreation) error {
	if creation.Path == "/" || !filepath.IsAbs(creation.Path) || filepath.Clean(creation.Path) != creation.Path {
		return fmt.Errorf("home path must be canonical, absolute, and non-root")
	}
	if creation.Mode > 0o777 {
		return fmt.Errorf("home mode must contain only permission bits")
	}
	components := strings.Split(strings.TrimPrefix(creation.Path, "/"), "/")
	parent, err := filesystem.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close(parent) }()
	if info, infoErr := filesystem.info(parent); infoErr != nil {
		return infoErr
	} else if !trustedHomeAncestor(info) {
		return fmt.Errorf("home ancestor / is not a trusted root-owned directory")
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := filesystem.openDirectoryAt(parent, component)
		if openErr != nil {
			return openErr
		}
		if info, infoErr := filesystem.info(next); infoErr != nil {
			_ = filesystem.close(next)
			return infoErr
		} else if !trustedHomeAncestor(info) {
			_ = filesystem.close(next)
			return fmt.Errorf("home ancestor %s is not a trusted root-owned directory", component)
		}
		_ = filesystem.close(parent)
		parent = next
	}
	leaf := components[len(components)-1]
	if err := filesystem.mkdirAt(parent, leaf, creation.Mode); err != nil {
		return err
	}
	home, err := filesystem.openDirectoryAt(parent, leaf)
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close(home) }()
	if err := filesystem.chown(home, creation.UID, creation.GID); err != nil {
		return err
	}
	return filesystem.chmod(home, creation.Mode)
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
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
		return result
	}
	if err == nil {
		return result
	}
	if exit, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exit.ExitCode()
		return result
	}
	result.ExitCode, result.Err = 127, err
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
