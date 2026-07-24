package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireTimezoneFilesystemContract(runner Runner) {
	_, _ = runner.Readlink(localtimePath)
	_, _ = runner.EvalSymlinks(zoneinfoRoot + "/UTC")
	_, _ = runner.ReadRegularFilePrefixBeneath(zoneinfoRoot, "UTC", 4)
}

func TestRunnerDeclaresTimezoneFilesystemEvidence(t *testing.T) {
	requireTimezoneFilesystemContract(&testRunner{})
}

func TestCreateHomeRefusesExistingTargetBeforeOwnershipMutation(t *testing.T) {
	filesystem := &fakeHomeFilesystem{mkdirErr: unix.EEXIST}
	err := createHome(filesystem, HomeCreation{Path: "/home/alice", Mode: 0o700, UID: 1000, GID: 1000})
	if !errors.Is(err, unix.EEXIST) || filesystem.mkdirName != "alice" || filesystem.openedLeaf || filesystem.chowns != 0 || filesystem.chmods != 0 {
		t.Fatalf("err=%v filesystem=%#v", err, filesystem)
	}
}

func TestCreateHomeChangesOnlyNewlyCreatedDirectoryDescriptor(t *testing.T) {
	filesystem := &fakeHomeFilesystem{}
	err := createHome(filesystem, HomeCreation{Path: "/home/alice", Mode: 0o700, UID: 1000, GID: 1000})
	if err != nil || filesystem.opened != "home" || filesystem.mkdirName != "alice" || !filesystem.openedLeaf || filesystem.chowns != 1 || filesystem.chmods != 1 {
		t.Fatalf("err=%v filesystem=%#v", err, filesystem)
	}
}

func TestCreateHomeRejectsUntrustedAncestorBeforeMkdir(t *testing.T) {
	filesystem := &fakeHomeFilesystem{ancestor: PathInfo{Kind: DirectoryPath, Mode: 0o777, UID: 0, GID: 0}}
	err := createHome(filesystem, HomeCreation{Path: "/home/alice", Mode: 0o700, UID: 1000, GID: 1000})
	if err == nil || filesystem.mkdirName != "" || filesystem.chowns != 0 || filesystem.chmods != 0 {
		t.Fatalf("err=%v filesystem=%#v", err, filesystem)
	}
}

type fakeHomeFilesystem struct {
	mkdirErr   error
	opened     string
	mkdirName  string
	openedLeaf bool
	chowns     int
	chmods     int
	nextFD     int
	ancestor   PathInfo
}

func (*fakeHomeFilesystem) openRoot() (int, error) { return 10, nil }
func (filesystem *fakeHomeFilesystem) info(int) (PathInfo, error) {
	if filesystem.ancestor.Kind == 0 {
		return PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}, nil
	}
	return filesystem.ancestor, nil
}
func (filesystem *fakeHomeFilesystem) openDirectoryAt(_ int, name string) (int, error) {
	filesystem.nextFD++
	if name == "alice" {
		filesystem.openedLeaf = true
	} else {
		filesystem.opened = name
	}
	return 10 + filesystem.nextFD, nil
}
func (filesystem *fakeHomeFilesystem) mkdirAt(_ int, name string, _ uint32) error {
	filesystem.mkdirName = name
	return filesystem.mkdirErr
}
func (filesystem *fakeHomeFilesystem) chown(int, uint32, uint32) error {
	filesystem.chowns++
	return nil
}
func (filesystem *fakeHomeFilesystem) chmod(int, uint32) error {
	filesystem.chmods++
	return nil
}
func (*fakeHomeFilesystem) close(int) error { return nil }

func TestOSRunnerKeepsOrdinaryNonzeroExitSeparateFromExecutionError(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "printf disabled; exit 7"}})
	if result.ExitCode != 7 || result.Err != nil || result.Stdout != "disabled" {
		t.Fatalf("result=%#v", result)
	}
}

func TestLimitedCaptureRetainsPrefixWhileReportingFullWrite(t *testing.T) {
	capture := newLimitedCapture(4)
	written, err := capture.Write([]byte("abcdef"))
	if err != nil || written != 6 || capture.String() != "abcd" || !capture.overflowed {
		t.Fatalf("written=%d err=%v capture=%#v", written, err, capture)
	}
}

func TestOSRunnerFailsExplicitlyWhenCapturedOutputExceedsLimit(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "printf abcdef; printf uvwxyz >&2"},
		stdoutLimit: 4, stderrLimit: 5,
	})
	if result.ExitCode != 0 || result.Stdout != "abcd" || result.Stderr != "uvwxy" || result.Err == nil ||
		!strings.Contains(result.Err.Error(), "stdout exceeded 4-byte capture limit") ||
		!strings.Contains(result.Err.Error(), "stderr exceeded 5-byte capture limit") {
		t.Fatalf("result=%#v", result)
	}
}

func TestOSRunnerAcceptsOutputAtExactCaptureLimit(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{
		Name: "sh", Args: []string{"-c", "printf abcd; printf uvwxy >&2"},
		stdoutLimit: 4, stderrLimit: 5,
	})
	if result.ExitCode != 0 || result.Stdout != "abcd" || result.Stderr != "uvwxy" || result.Err != nil {
		t.Fatalf("result=%#v", result)
	}
}

func TestOSRunnerMaterializesDigestBoundRunningExecutable(t *testing.T) {
	digest, err := runningExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	result := (OSRunner{}).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "test -x \"$1\"", "_", proofstrapSelfPrefix + digest}})
	if result.ExitCode != 0 || result.Err != nil {
		t.Fatalf("result=%#v", result)
	}
}

func TestMaterializeDigestBoundRunningExecutableAsDirectCommand(t *testing.T) {
	digest, err := runningExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := materializeProofstrapSelf(proofstrapSelfPrefix + digest)
	want := fmt.Sprintf("/proc/%d/exe", os.Getpid())
	if err != nil || materialized != want {
		t.Fatalf("materialized=%q err=%v want=%q", materialized, err, want)
	}
}

func TestOSRunnerRejectsChangedRunningExecutableDigest(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "exit 0", "_", proofstrapSelfPrefix + "sha256:wrong"}})
	if result.Err == nil || result.ExitCode != -1 {
		t.Fatalf("result=%#v", result)
	}
}

func TestOSRunnerReadsSymlinkTargetWithoutFollowingIt(t *testing.T) {
	path := t.TempDir() + "/localtime"
	if err := os.Symlink("../usr/share/zoneinfo/Etc/UTC", path); err != nil {
		t.Fatal(err)
	}
	target, err := (OSRunner{}).Readlink(path)
	if err != nil || target != "../usr/share/zoneinfo/Etc/UTC" {
		t.Fatalf("target=%q err=%v", target, err)
	}
}

func TestOSRunnerConfinesRegularPrefixReadBeneathRoot(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("TZifpayload"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "zone"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "area")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		relative string
		want     string
		wantErr  bool
	}{
		{name: "regular file", relative: "regular", want: "TZif"},
		{name: "final symlink", relative: "symlink", wantErr: true},
		{name: "FIFO", relative: "fifo", wantErr: true},
		{name: "intermediate symlink", relative: "area/zone", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			contents, err := (OSRunner{}).ReadRegularFilePrefixBeneath(directory, test.relative, 4)
			if test.wantErr {
				if err == nil {
					t.Fatalf("%s was admitted", test.relative)
				}
				return
			}
			if err != nil || string(contents) != test.want {
				t.Fatalf("contents=%q err=%v", contents, err)
			}
		})
	}
}

func TestOSRunnerRejectsNegativeRegularFilePrefixSize(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "zone"), []byte("TZif"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSRunner{}).ReadRegularFilePrefixBeneath(directory, "zone", -1); err == nil {
		t.Fatal("negative prefix size was admitted")
	}
}

func TestOSRunnerSuppliesPrivateCommandInput(t *testing.T) {
	result := (OSRunner{}).Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "read value; printf %s \"$value\""}, stdin: "private\n"})
	if result.ExitCode != 0 || result.Err != nil || result.Stdout != "private" {
		t.Fatalf("result=%#v", result)
	}
}

type testRunner struct {
	uid              uint32
	uids             []uint32
	uidErr           error
	files            map[string][]byte
	fileResults      map[string][]fileResult
	regularPrefixes  map[string][]fileResult
	readlinks        map[string][]linkResult
	evalSymlinks     map[string][]linkResult
	lstats           map[string][]pathResult
	executable       string
	executableDigest string
	executableErr    error
	homeCreations    []HomeCreation
	homeCreationErr  error

	paths           map[string]string
	pathResults     map[string][]string
	results         map[string][]Result
	calls           []string
	pathCalls       []string
	events          []string
	deadlines       []time.Duration
	euidCalls       int
	lstatCalls      []string
	executableCalls int
}

type pathResult struct {
	info PathInfo
	err  error
}

type fileResult struct {
	contents []byte
	err      error
}

type linkResult struct {
	target string
	err    error
}

func (runner *testRunner) EffectiveUID() (uint32, error) {
	runner.euidCalls++
	runner.events = append(runner.events, "euid")
	if len(runner.uids) != 0 {
		uid := runner.uids[0]
		runner.uids = runner.uids[1:]
		return uid, runner.uidErr
	}
	return runner.uid, runner.uidErr
}
func (runner *testRunner) ExecutableIdentity() (ExecutableIdentity, error) {
	runner.executableCalls++
	runner.events = append(runner.events, "executable")
	return ExecutableIdentity{Path: runner.executable, Digest: runner.executableDigest}, runner.executableErr
}
func (runner *testRunner) ReadFile(path string) ([]byte, error) {
	runner.events = append(runner.events, "read:"+path)
	if queue := runner.fileResults[path]; len(queue) != 0 {
		runner.fileResults[path] = queue[1:]
		return queue[0].contents, queue[0].err
	}
	if value, ok := runner.files[path]; ok {
		return value, nil
	}
	return nil, errors.New("missing file")
}
func (runner *testRunner) Readlink(path string) (string, error) {
	runner.events = append(runner.events, "readlink:"+path)
	queue := runner.readlinks[path]
	if len(queue) == 0 {
		return "", errors.New("missing link result")
	}
	runner.readlinks[path] = queue[1:]
	return queue[0].target, queue[0].err
}
func (runner *testRunner) EvalSymlinks(path string) (string, error) {
	runner.events = append(runner.events, "eval:"+path)
	queue := runner.evalSymlinks[path]
	if len(queue) == 0 {
		return "", errors.New("missing symlink result")
	}
	runner.evalSymlinks[path] = queue[1:]
	return queue[0].target, queue[0].err
}

func (runner *testRunner) ReadRegularFilePrefixBeneath(root, relative string, size int) ([]byte, error) {
	path := filepath.Join(root, relative)
	runner.events = append(runner.events, fmt.Sprintf("regular-prefix:%d:%s", size, path))
	if queue := runner.regularPrefixes[path]; len(queue) != 0 {
		runner.regularPrefixes[path] = queue[1:]
		if queue[0].err != nil {
			return nil, queue[0].err
		}
		if len(queue[0].contents) < size {
			return nil, io.ErrUnexpectedEOF
		}
		return append([]byte(nil), queue[0].contents[:size]...), nil
	}
	contents, ok := runner.files[path]
	if !ok {
		return nil, errors.New("missing file")
	}
	if len(contents) < size {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), contents[:size]...), nil
}
func (runner *testRunner) Lstat(path string) (PathInfo, error) {
	runner.lstatCalls = append(runner.lstatCalls, path)
	runner.events = append(runner.events, "lstat:"+path)
	queue := runner.lstats[path]
	if len(queue) == 0 {
		return PathInfo{}, errors.New("missing path result")
	}
	runner.lstats[path] = queue[1:]
	return queue[0].info, queue[0].err
}
func (runner *testRunner) LookPath(name string) (string, error) {
	runner.pathCalls = append(runner.pathCalls, name)
	runner.events = append(runner.events, "path:"+name)
	if queue := runner.pathResults[name]; len(queue) != 0 {
		runner.pathResults[name] = queue[1:]
		return queue[0], nil
	}
	if value, ok := runner.paths[name]; ok {
		return value, nil
	}
	return "", errors.New("missing executable")
}

func (runner *testRunner) CreateHome(creation HomeCreation) error {
	runner.homeCreations = append(runner.homeCreations, creation)
	return runner.homeCreationErr
}

func (runner *testRunner) Run(ctx context.Context, command Command) Result {
	key := command.String()
	runner.calls = append(runner.calls, key)
	runner.events = append(runner.events, "run:"+key)
	if deadline, ok := ctx.Deadline(); ok {
		runner.deadlines = append(runner.deadlines, time.Until(deadline))
	}
	queue := runner.results[key]
	if len(queue) == 0 {
		panic("missing command result: " + key)
	}
	result := queue[0]
	runner.results[key] = queue[1:]
	return result
}
