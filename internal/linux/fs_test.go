package linux_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func TestCleanAbsoluteNonRoot(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "/", "relative", "/tmp/../tmp/file", "/tmp/\x00file"} {
		if linux.CleanAbsoluteNonRoot(path) {
			t.Errorf("CleanAbsoluteNonRoot(%q) = true", path)
		}
	}
	if !linux.CleanAbsoluteNonRoot("/tmp/file") {
		t.Fatal("clean absolute non-root path was rejected")
	}
}

func TestOpenDirDoesNotFollowComponents(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}

	fd, err := linux.OpenDir(directory)
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close directory: %v", err)
	}
	if fd, err := linux.OpenDir(link); err == nil {
		_ = unix.Close(fd)
		t.Fatal("opened a symlinked directory component")
	}
}

func TestOpenDirAtAdmitsOneDirectoryComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("directory", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	parent, err := linux.OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)

	child, err := linux.OpenDirAt(parent, "directory")
	if err != nil {
		t.Fatalf("open child: %v", err)
	}
	_ = unix.Close(child)
	duplicate, err := linux.OpenDirAt(parent, ".")
	if err != nil {
		t.Fatalf("duplicate directory: %v", err)
	}
	_ = unix.Close(duplicate)
	for _, name := range []string{"link", "..", "directory/.."} {
		if fd, err := linux.OpenDirAt(parent, name); err == nil {
			_ = unix.Close(fd)
			t.Errorf("OpenDirAt accepted %q", name)
		}
	}
}

func TestOpenDirClosesDescriptorsOnFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 64 {
		if fd, err := linux.OpenDir(filepath.Join(root, "loop")); err == nil {
			_ = unix.Close(fd)
			t.Fatal("opened a symlinked directory component")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("descriptor count changed from %d to %d", len(before), len(after))
	}
}

func TestOpenRegularAtDoesNotFollowLeaf(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "object")
	if err := os.WriteFile(path, []byte("object"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := linux.OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)

	fd, err := linux.OpenRegularAt(directory, "object")
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close regular file: %v", err)
	}
	for _, name := range []string{"link", "directory", ".", "../object"} {
		if fd, err := linux.OpenRegularAt(directory, name); err == nil {
			_ = unix.Close(fd)
			t.Errorf("OpenRegularAt accepted %q", name)
		}
	}
}

func TestOpenRegularAdmitsOnlyAbsoluteRegularLeaf(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "object")
	if err := os.WriteFile(path, []byte("object"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	fd, err := linux.OpenRegular(path)
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	_ = unix.Close(fd)
	for _, candidate := range []string{filepath.Join(root, "link"), root, "relative"} {
		if fd, err := linux.OpenRegular(candidate); err == nil {
			_ = unix.Close(fd)
			t.Errorf("OpenRegular accepted %q", candidate)
		}
	}
	if _, err := linux.OpenRegular(root); !errors.Is(err, linux.ErrNotRegular) {
		t.Fatalf("directory error = %v", err)
	}
}

func TestCreateStageAtRetriesCollision(t *testing.T) {
	root := t.TempDir()
	directory, err := linux.OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)

	zero := make([]byte, 16)
	first := ".stage-" + string(bytes.Repeat([]byte("00"), 16))
	if err := os.WriteFile(filepath.Join(root, first), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	random := io.MultiReader(bytes.NewReader(zero), bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	fd, name, err := linux.CreateStageAt(directory, random, ".stage-")
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	defer unix.Close(fd)
	if name == first {
		t.Fatal("collision was not retried")
	}
}

func TestCreateStageAtPropagatesEntropyFailure(t *testing.T) {
	root := t.TempDir()
	directory, err := linux.OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)

	want := errors.New("entropy unavailable")
	fd, name, err := linux.CreateStageAt(directory, errorReader{err: want}, ".stage-")
	if fd != -1 || name != "" || !errors.Is(err, want) {
		t.Fatalf("CreateStageAt = %d, %q, %v", fd, name, err)
	}
}

func TestCreateDirsCreatesOnlyBeneathAnchor(t *testing.T) {
	root := t.TempDir()
	if err := linux.CreateDirs(root, []string{"one", "two", "three"}, 0o700); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(root, "one", "two", "three")); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory = %v, %v", info, err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := linux.CreateDirs(root, []string{"link", "escaped"}, 0o700); err == nil {
		t.Fatal("CreateDirs followed symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("created outside anchor: %v", err)
	}
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }
