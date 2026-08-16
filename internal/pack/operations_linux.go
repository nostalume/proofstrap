package pack

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
	"golang.org/x/sys/unix"
)

func Import(ctx context.Context, root, sourcePath string, expected Digest) error {
	if err := storeCanceled(ctx, expected); err != nil {
		return err
	}
	if expected == (Digest{}) {
		return storeDiagnostic(expected, InvalidValue, sourcePath, "expected digest is required", nil)
	}
	if !linux.CleanAbsoluteNonRoot(root) || !linux.CleanAbsoluteNonRoot(sourcePath) {
		return storeDiagnostic(expected, InvalidValue, sourcePath, "store root and source path must be clean absolute non-root paths", nil)
	}
	directory, err := openStore(root)
	if err != nil {
		return storeDiagnostic(expected, CorruptStore, root, "store root is unavailable or unsafe", err)
	}
	defer unix.Close(directory)

	sourceFD, err := linux.OpenRegular(sourcePath)
	if err != nil {
		if errors.Is(err, linux.ErrNotRegular) {
			return storeDiagnostic(expected, InvalidValue, sourcePath, "import source is not a regular file", nil)
		}
		return storeDiagnostic(expected, IO, sourcePath, "open import source", err)
	}
	source := os.NewFile(uintptr(sourceFD), sourcePath)
	defer source.Close()

	stageFD, stageName, err := linux.CreateStageAt(directory, rand.Reader, ".import-")
	if err != nil {
		return storeDiagnostic(expected, IO, root, "create import staging file", err)
	}
	stage := os.NewFile(uintptr(stageFD), stageName)
	cleanup := true
	defer func() {
		_ = stage.Close()
		if cleanup {
			_ = unix.Unlinkat(directory, stageName, 0)
		}
	}()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(stage, hasher), io.LimitReader(&contextReader{ctx: ctx, source: source}, maxCompressedBytes+1))
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return storeCanceled(ctx, expected)
		}
		return storeDiagnostic(expected, IO, sourcePath, "copy import source", err)
	}
	if written > maxCompressedBytes {
		return storeDiagnostic(expected, Limit, sourcePath, "compressed archive exceeds 8 MiB", nil)
	}
	var observed Digest
	copy(observed.sum[:], hasher.Sum(nil))
	if observed != expected {
		return storeDiagnostic(expected, Integrity, sourcePath, "source digest does not match expected digest", nil)
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return storeDiagnostic(expected, IO, sourcePath, "rewind staged archive", err)
	}
	admitted, err := Read(ctx, stage)
	if err != nil {
		return locateImportDiagnostic(expected, err)
	}
	if admitted.Digest() != expected {
		return storeDiagnostic(expected, Integrity, sourcePath, "admitted digest does not match expected digest", nil)
	}
	if err := storeCanceled(ctx, expected); err != nil {
		return err
	}
	if err := stage.Chmod(0o444); err != nil {
		return storeDiagnostic(expected, IO, root, "set staged object mode", err)
	}
	if err := stage.Sync(); err != nil {
		return storeDiagnostic(expected, IO, root, "flush staged object", err)
	}
	if err := storeCanceled(ctx, expected); err != nil {
		return err
	}
	finalName := objectName(expected)
	if err := unix.Linkat(directory, stageName, directory, finalName, 0); err != nil {
		if err != unix.EEXIST {
			return storeDiagnostic(expected, IO, filepath.Join(root, "sha256", finalName), "publish store object", err)
		}
		if _, err := loadCandidate(ctx, directory, filepath.Join(root, "sha256", finalName), finalName, expected); err != nil {
			return err
		}
	}
	if err := unix.Fsync(directory); err != nil {
		return storeDiagnostic(expected, IO, filepath.Join(root, "sha256"), "flush store directory", err)
	}
	_ = unix.Unlinkat(directory, stageName, 0)
	cleanup = false
	return nil
}

func LoadExact(ctx context.Context, roots []string, digest Digest) (Source, error) {
	if err := storeCanceled(ctx, digest); err != nil {
		return Source{}, err
	}
	if digest == (Digest{}) || len(roots) == 0 {
		return Source{}, storeDiagnostic(digest, InvalidValue, "", "digest and at least one store root are required", nil)
	}
	ordered := append([]string(nil), roots...)
	for _, root := range ordered {
		if !linux.CleanAbsoluteNonRoot(root) {
			return Source{}, storeDiagnostic(digest, InvalidValue, root, "store root must be a clean absolute non-root path", nil)
		}
	}
	sort.Strings(ordered)
	for index := 1; index < len(ordered); index++ {
		if ordered[index] == ordered[index-1] {
			return Source{}, storeDiagnostic(digest, InvalidValue, ordered[index], "duplicate store root", nil)
		}
	}
	finalName := objectName(digest)
	var retained Source
	for _, root := range ordered {
		if err := storeCanceled(ctx, digest); err != nil {
			return Source{}, err
		}
		directory, err := openStore(root)
		if err != nil {
			return Source{}, storeDiagnostic(digest, CorruptStore, root, "store root is unavailable or unsafe", err)
		}
		path := filepath.Join(root, "sha256", finalName)
		candidate, err := loadCandidate(ctx, directory, path, finalName, digest)
		_ = unix.Close(directory)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return Source{}, err
		}
		if retained.state == nil {
			retained = candidate
		}
	}
	if retained.state == nil {
		return Source{}, storeDiagnostic(digest, MissingRequirement, "", "exact source is unavailable", nil)
	}
	if err := storeCanceled(ctx, digest); err != nil {
		return Source{}, err
	}
	return retained, nil
}

func loadCandidate(ctx context.Context, directory int, path, name string, digest Digest) (Source, error) {
	fd, err := linux.OpenRegularAt(directory, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Source{}, err
		}
		return Source{}, storeDiagnostic(digest, CorruptStore, path, "stored object is unavailable, unsafe, or non-regular", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	source, err := Read(ctx, file)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return Source{}, storeCanceled(ctx, digest)
		}
		return Source{}, storeDiagnostic(digest, CorruptStore, path, "stored object is invalid", err)
	}
	if source.Digest() != digest {
		return Source{}, storeDiagnostic(digest, CorruptStore, path, "stored object digest does not match its name", nil)
	}
	return source, nil
}

func objectName(digest Digest) string {
	return strings.TrimPrefix(digest.String(), digestPrefix) + ".pstrap"
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if r.ctx == nil {
		return 0, context.Canceled
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(buffer)
}

func storeCanceled(ctx context.Context, digest Digest) error {
	var cause error
	if ctx == nil {
		cause = context.Canceled
	} else {
		cause = ctx.Err()
	}
	if cause == nil {
		return nil
	}
	return storeDiagnostic(digest, Canceled, "", "store operation canceled", cause)
}

func storeDiagnostic(digest Digest, category Category, member, detail string, cause error) *Diagnostic {
	result := diagnostic(category, member, "", detail, cause)
	if digest != (Digest{}) {
		result.Source = digest.String()
	}
	return result
}

func locateImportDiagnostic(digest Digest, err error) error {
	var source *Diagnostic
	if !errors.As(err, &source) {
		return storeDiagnostic(digest, InvalidValue, "", err.Error(), err)
	}
	return &Diagnostic{
		Source: digest.String(), Category: source.Category, Member: source.Member,
		Profile: source.Profile, Field: source.Field, Line: source.Line,
		Column: source.Column, Detail: source.Detail, cause: err,
	}
}
