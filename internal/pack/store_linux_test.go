package pack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func TestImportAndLoadExact(t *testing.T) {
	t.Parallel()
	archive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	source, err := Read(context.Background(), bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	root := newStoreRoot(t)
	sourcePath := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(sourcePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Import(context.Background(), root, sourcePath, source.Digest()); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "sha256", source.Digest().String()[len(digestPrefix):]+".pstrap")
	info, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
		t.Fatalf("final mode = %v", info.Mode())
	}
	stored, err := os.ReadFile(final)
	if err != nil || !bytes.Equal(stored, archive) {
		t.Fatalf("stored bytes differ: %v", err)
	}
	loaded, err := LoadExact(context.Background(), []string{root}, source.Digest())
	if err != nil || loaded.Digest() != source.Digest() || loaded.Kind() != Semantic {
		t.Fatalf("LoadExact = %#v, %v", loaded, err)
	}
}

func TestStoreRejectsMissingOrSymlinkedContentDirectory(t *testing.T) {
	t.Parallel()
	_, digest := semanticArchive(t)
	missing := filepath.Join(t.TempDir(), "missing")
	if source, err := LoadExact(context.Background(), []string{missing}, digest); source != (Source{}) || errorCategory(t, err) != CorruptStore {
		t.Fatalf("missing root = %#v, %v", source, err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	realSHA := filepath.Join(base, "real-sha")
	if err := os.Mkdir(realSHA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realSHA, filepath.Join(root, "sha256")); err != nil {
		t.Fatal(err)
	}
	if source, err := LoadExact(context.Background(), []string{root}, digest); source != (Source{}) || errorCategory(t, err) != CorruptStore {
		t.Fatalf("symlink sha256 = %#v, %v", source, err)
	}
}

func TestLoadExactRejectsNonRegularFinalObject(t *testing.T) {
	t.Parallel()
	_, digest := semanticArchive(t)
	root := newStoreRoot(t)
	path := filepath.Join(root, "sha256", objectName(digest))
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if source, err := LoadExact(context.Background(), []string{root}, digest); source != (Source{}) || errorCategory(t, err) != CorruptStore {
		t.Fatalf("directory final = %#v, %v", source, err)
	}
}

func TestImportDeduplicatesAndLoadRejectsCorruptDuplicate(t *testing.T) {
	t.Parallel()
	archive, digest := semanticArchive(t)
	sourcePath := writeSource(t, archive)
	left, right := newStoreRoot(t), newStoreRoot(t)
	if err := Import(context.Background(), left, sourcePath, digest); err != nil {
		t.Fatal(err)
	}
	if err := Import(context.Background(), left, sourcePath, digest); err != nil {
		t.Fatalf("deduplicated Import failed: %v", err)
	}
	corruptPath := filepath.Join(right, "sha256", objectName(digest))
	if err := os.WriteFile(corruptPath, []byte("corrupt"), 0o444); err != nil {
		t.Fatal(err)
	}
	for _, roots := range [][]string{{left, right}, {right, left}} {
		if source, err := LoadExact(context.Background(), roots, digest); source != (Source{}) || errorCategory(t, err) != CorruptStore {
			t.Fatalf("LoadExact corruption = %#v, %v", source, err)
		}
	}
	before, _ := os.ReadFile(corruptPath)
	if err := Import(context.Background(), right, sourcePath, digest); errorCategory(t, err) != CorruptStore {
		t.Fatalf("Import over corruption = %v", err)
	}
	after, _ := os.ReadFile(corruptPath)
	if !bytes.Equal(before, after) {
		t.Fatal("Import replaced corrupt authoritative object")
	}
}

func TestImportRejectsUnsafeSourcesAndPreservesReadCategory(t *testing.T) {
	t.Parallel()
	root := newStoreRoot(t)
	archive, digest := semanticArchive(t)
	directory := t.TempDir()
	realSource := filepath.Join(directory, "real.pstrap")
	if err := os.WriteFile(realSource, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.pstrap")
	if err := os.Symlink(realSource, symlink); err != nil {
		t.Fatal(err)
	}
	if err := Import(context.Background(), root, symlink, digest); errorCategory(t, err) != IO {
		t.Fatalf("symlink source = %v", err)
	}
	if err := Import(context.Background(), root, directory, digest); errorCategory(t, err) != InvalidValue {
		t.Fatalf("directory source = %v", err)
	}
	bad := []byte("not gzip")
	badPath := writeSource(t, bad)
	badSource, _ := Read(context.Background(), bytes.NewReader(bad))
	_ = badSource
	observed := digestBytes(bad)
	if err := Import(context.Background(), root, badPath, observed); errorCategory(t, err) != Syntax {
		t.Fatalf("invalid archive category = %v", err)
	}
}

func TestImportCancellation(t *testing.T) {
	t.Parallel()
	archive, digest := semanticArchive(t)
	sourcePath := writeSource(t, archive)
	root := newStoreRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Import(ctx, root, sourcePath, digest); !errors.Is(err, context.Canceled) || errorCategory(t, err) != Canceled {
		t.Fatalf("canceled Import = %v", err)
	}
}

func TestImportConcurrentConvergence(t *testing.T) {
	archive, digest := semanticArchive(t)
	sourcePath := writeSource(t, archive)
	root := newStoreRoot(t)
	const workers = 12
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsByWorker <- Import(context.Background(), root, sourcePath, digest)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent Import: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "sha256"))
	if err != nil || len(entries) != 1 || entries[0].Name() != objectName(digest) {
		t.Fatalf("store entries = %v, %v", entries, err)
	}
}

func TestCreateStageCollisionBoundary(t *testing.T) {
	t.Parallel()
	root := newStoreRoot(t)
	directory, err := openStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)
	zeroName := ".import-" + strings.Repeat("0", 32)
	fd, err := unix.Openat(directory, zeroName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	defer unix.Unlinkat(directory, zeroName, 0)
	if fd, name, err := linux.CreateStageAt(directory, bytes.NewReader(make([]byte, 16*16)), ".import-"); fd != -1 || name != "" || err == nil {
		t.Fatalf("collision limit = %d, %q, %v", fd, name, err)
	}
	random := append(make([]byte, 16), append(make([]byte, 15), byte(1))...)
	fd, name, err := linux.CreateStageAt(directory, bytes.NewReader(random), ".import-")
	if err != nil || name != ".import-"+strings.Repeat("0", 31)+"1" {
		t.Fatalf("collision retry = %d, %q, %v", fd, name, err)
	}
	_ = unix.Close(fd)
	_ = unix.Unlinkat(directory, name, 0)
}

func TestStoreContainmentAndAbsence(t *testing.T) {
	t.Parallel()
	digest, _ := ParseDigest("sha256:" + "1111111111111111111111111111111111111111111111111111111111111111")
	for _, root := range []string{"", ".", "/"} {
		if source, err := LoadExact(context.Background(), []string{root}, digest); source != (Source{}) || errorCategory(t, err) != InvalidValue {
			t.Fatalf("LoadExact(%q) = %#v, %v", root, source, err)
		}
	}
	root := newStoreRoot(t)
	if source, err := LoadExact(context.Background(), []string{root, root}, digest); source != (Source{}) || errorCategory(t, err) != InvalidValue {
		t.Fatalf("duplicate-root LoadExact = %#v, %v", source, err)
	}
	if source, err := LoadExact(context.Background(), []string{root}, digest); source != (Source{}) || errorCategory(t, err) != MissingRequirement {
		t.Fatalf("absent LoadExact = %#v, %v", source, err)
	}
	base := t.TempDir()
	realRoot := newStoreRootAt(t, filepath.Join(base, "real"))
	symlink := filepath.Join(base, "link")
	if err := os.Symlink(realRoot, symlink); err != nil {
		t.Fatal(err)
	}
	if source, err := LoadExact(context.Background(), []string{symlink}, digest); source != (Source{}) || errorCategory(t, err) != CorruptStore {
		t.Fatalf("symlink LoadExact = %#v, %v", source, err)
	}
}

func TestLoadExactCancellation(t *testing.T) {
	t.Parallel()
	_, digest := semanticArchive(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if source, err := LoadExact(ctx, []string{newStoreRoot(t)}, digest); source != (Source{}) || !errors.Is(err, context.Canceled) || errorCategory(t, err) != Canceled {
		t.Fatalf("canceled LoadExact = %#v, %v", source, err)
	}
}

func TestImportRejectsDigestMismatchAtomically(t *testing.T) {
	t.Parallel()
	archive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	root := newStoreRoot(t)
	sourcePath := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(sourcePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	expected, _ := ParseDigest("sha256:" + "2222222222222222222222222222222222222222222222222222222222222222")
	if err := Import(context.Background(), root, sourcePath, expected); errorCategory(t, err) != Integrity {
		t.Fatalf("Import mismatch = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "sha256"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed import left entries %v, %v", entries, err)
	}
}

func TestImportCompressedSizeBoundary(t *testing.T) {
	t.Parallel()
	root := newStoreRoot(t)
	data := make([]byte, maxCompressedBytes+1)
	path := writeSource(t, data)
	if err := Import(context.Background(), root, path, digestBytes(data)); errorCategory(t, err) != Limit {
		t.Fatalf("oversized Import = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "sha256"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversized import left entries %v, %v", entries, err)
	}
}

func newStoreRoot(t *testing.T) string {
	t.Helper()
	return newStoreRootAt(t, filepath.Join(t.TempDir(), "store"))
}

func newStoreRootAt(t *testing.T, root string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func semanticArchive(t *testing.T) ([]byte, Digest) {
	t.Helper()
	archive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	source, err := Read(context.Background(), bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	return archive, source.Digest()
}

func writeSource(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestBytes(data []byte) Digest {
	sum := sha256.Sum256(data)
	return Digest{sum: sum}
}
