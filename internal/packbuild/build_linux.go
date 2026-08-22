package packbuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

const (
	maxManifest = 64 << 10
	maxContent  = 1 << 20
	maxMembers  = 256
	maxDecoded  = 32 << 20
	maxOutput   = 8 << 20
)

type Category string

const (
	InvalidInput Category = "InvalidInput"
	InputChanged Category = "InputChanged"
	OutputExists Category = "OutputExists"
	IO           Category = "IO"
	Canceled     Category = "Canceled"
)

type Diagnostic struct {
	Category Category
	Path     string
	Detail   string
	cause    error
}

func (d *Diagnostic) Error() string {
	location := d.Path
	if location != "" {
		location += ": "
	}
	return location + string(d.Category) + ": " + d.Detail
}

func (d *Diagnostic) Unwrap() error { return d.cause }

func diagnostic(category Category, path, detail string, cause error) *Diagnostic {
	if detail == "" && cause != nil {
		detail = cause.Error()
	}
	return &Diagnostic{Category: category, Path: path, Detail: detail, cause: cause}
}

type inputFile struct {
	archivePath string
	directory   int
	name        string
}

func Build(ctx context.Context, inputRoot, outputPath string) (pack.Digest, error) {
	if err := canceled(ctx); err != nil {
		return pack.Digest{}, err
	}
	if !linux.CleanAbsoluteNonRoot(inputRoot) || !linux.CleanAbsoluteNonRoot(outputPath) {
		return pack.Digest{}, diagnostic(InvalidInput, "", "input and output must be clean absolute non-root paths", nil)
	}
	relative, err := filepath.Rel(inputRoot, outputPath)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return pack.Digest{}, diagnostic(InvalidInput, outputPath, "output must be outside input root", nil)
	}
	rootFD, err := linux.OpenDir(inputRoot)
	if err != nil {
		return pack.Digest{}, diagnostic(InvalidInput, inputRoot, "input root is unavailable or unsafe", err)
	}
	defer unix.Close(rootFD)

	rootNames, err := directoryNames(rootFD)
	if err != nil {
		return pack.Digest{}, diagnostic(IO, inputRoot, "enumerate input root", err)
	}
	manifest, err := readInput(rootFD, "manifest.toml", maxManifest)
	if err != nil {
		if errors.Is(err, errInputChanged) {
			return pack.Digest{}, diagnostic(InputChanged, filepath.Join(inputRoot, "manifest.toml"), "manifest changed during read", err)
		}
		return pack.Digest{}, diagnostic(InvalidInput, filepath.Join(inputRoot, "manifest.toml"), "read manifest", err)
	}
	kind, err := pack.ManifestKind(manifest)
	if err != nil {
		return pack.Digest{}, diagnostic(InvalidInput, filepath.Join(inputRoot, "manifest.toml"), "invalid manifest", err)
	}
	contentName := "profiles"
	if kind == pack.Binding {
		contentName = "bindings"
	}
	expectedRootNames := []string{"manifest.toml", contentName}
	sort.Strings(expectedRootNames)
	if !equalStrings(rootNames, expectedRootNames) {
		return pack.Digest{}, diagnostic(InvalidInput, inputRoot, "authoring root has unexpected entries", nil)
	}
	contentFD, err := linux.OpenDirAt(rootFD, contentName)
	if err != nil {
		return pack.Digest{}, diagnostic(InvalidInput, filepath.Join(inputRoot, contentName), "content directory is unavailable or unsafe", err)
	}
	defer unix.Close(contentFD)
	contentNames, err := directoryNames(contentFD)
	if err != nil || len(contentNames) == 0 || len(contentNames) > maxMembers {
		return pack.Digest{}, diagnostic(InvalidInput, filepath.Join(inputRoot, contentName), "content directory must contain 1..256 files", err)
	}
	files := []inputFile{{archivePath: "manifest.toml", directory: rootFD, name: "manifest.toml"}}
	for _, name := range contentNames {
		archivePath := contentName + "/" + name
		files = append(files, inputFile{archivePath: archivePath, directory: contentFD, name: name})
	}

	parentPath, finalName := filepath.Dir(outputPath), filepath.Base(outputPath)
	parentFD, err := linux.OpenDir(parentPath)
	if err != nil {
		return pack.Digest{}, diagnostic(InvalidInput, parentPath, "output parent is unavailable or unsafe", err)
	}
	defer unix.Close(parentFD)
	var finalStat unix.Stat_t
	if err := unix.Fstatat(parentFD, finalName, &finalStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return pack.Digest{}, diagnostic(OutputExists, outputPath, "output already exists", nil)
	} else if err != unix.ENOENT {
		return pack.Digest{}, diagnostic(IO, outputPath, "inspect output", err)
	}
	stageFD, stageName, err := linux.CreateStageAt(parentFD, rand.Reader, ".proofstrap-pack-")
	if err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "create output staging file", err)
	}
	stage := os.NewFile(uintptr(stageFD), stageName)
	defer func() {
		_ = stage.Close()
		_ = unix.Unlinkat(parentFD, stageName, 0)
	}()

	limited := &limitWriter{writer: stage, remaining: maxOutput}
	gzipWriter, err := gzip.NewWriterLevel(limited, gzip.BestCompression)
	if err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "create gzip writer", err)
	}
	gzipWriter.Header = gzip.Header{ModTime: time.Unix(0, 0), OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	decodedBytes := int64(2 * 512)
	for _, item := range files {
		if err := canceled(ctx); err != nil {
			return pack.Digest{}, err
		}
		if err := writeInput(ctx, tarWriter, item, &decodedBytes); err != nil {
			return pack.Digest{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return pack.Digest{}, diagnostic(IO, outputPath, "finish tar archive", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "finish gzip archive", err)
	}
	finalRootNames, err := directoryNames(rootFD)
	if err != nil {
		return pack.Digest{}, diagnostic(IO, inputRoot, "re-enumerate input root", err)
	}
	finalContentNames, err := directoryNames(contentFD)
	if err != nil {
		return pack.Digest{}, diagnostic(IO, filepath.Join(inputRoot, contentName), "re-enumerate content directory", err)
	}
	if !equalStrings(rootNames, finalRootNames) || !equalStrings(contentNames, finalContentNames) {
		return pack.Digest{}, diagnostic(InputChanged, inputRoot, "authoring tree changed during build", nil)
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "rewind staged archive", err)
	}
	source, err := pack.Read(ctx, stage)
	if err != nil {
		return pack.Digest{}, diagnostic(InvalidInput, outputPath, "completed archive rejected", err)
	}
	if err := stage.Chmod(0o644); err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "set output mode", err)
	}
	if err := stage.Sync(); err != nil {
		return pack.Digest{}, diagnostic(IO, outputPath, "flush output", err)
	}
	if err := canceled(ctx); err != nil {
		return pack.Digest{}, err
	}
	if err := unix.Linkat(parentFD, stageName, parentFD, finalName, 0); err != nil {
		if err == unix.EEXIST {
			return pack.Digest{}, diagnostic(OutputExists, outputPath, "output already exists", err)
		}
		return pack.Digest{}, diagnostic(IO, outputPath, "publish output", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return pack.Digest{}, diagnostic(IO, parentPath, "flush output directory", err)
	}
	_ = unix.Unlinkat(parentFD, stageName, 0)
	return source.Digest(), nil
}

func writeInput(ctx context.Context, writer *tar.Writer, item inputFile, decodedBytes *int64) error {
	fd, before, err := openInput(item.directory, item.name)
	if err != nil {
		return diagnostic(InvalidInput, item.archivePath, "open authoring file", err)
	}
	file := os.NewFile(uintptr(fd), item.archivePath)
	defer file.Close()
	maximum := int64(maxContent)
	if item.archivePath == "manifest.toml" {
		maximum = maxManifest
	}
	if before.Size < 0 || before.Size > maximum {
		return diagnostic(InvalidInput, item.archivePath, "authoring file exceeds its limit", nil)
	}
	charge := int64(512) + (before.Size+511)/512*512
	if *decodedBytes > maxDecoded-charge {
		return diagnostic(InvalidInput, item.archivePath, "decoded archive exceeds 32 MiB", nil)
	}
	*decodedBytes += charge
	header := &tar.Header{Name: item.archivePath, Mode: 0o644, Size: before.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
	if err := writer.WriteHeader(header); err != nil {
		return diagnostic(IO, item.archivePath, "write tar header", err)
	}
	if copied, err := copyExact(ctx, writer, file, before.Size); err != nil || copied != before.Size {
		if ctx != nil && ctx.Err() != nil {
			return canceled(ctx)
		}
		return diagnostic(InputChanged, item.archivePath, "authoring file changed during read", err)
	}
	var extra [1]byte
	if n, _ := file.Read(extra[:]); n != 0 {
		return diagnostic(InputChanged, item.archivePath, "authoring file grew during read", nil)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameStat(before, after) {
		return diagnostic(InputChanged, item.archivePath, "authoring file changed during build", err)
	}
	return nil
}

func copyExact(ctx context.Context, destination io.Writer, source io.Reader, size int64) (int64, error) {
	buffer := make([]byte, 32<<10)
	limited := &io.LimitedReader{R: source, N: size}
	var copied int64
	for limited.N > 0 {
		if err := canceled(ctx); err != nil {
			return copied, err
		}
		read, err := limited.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			copied += int64(written)
			if writeErr != nil {
				return copied, writeErr
			}
			if written != read {
				return copied, io.ErrShortWrite
			}
		}
		if err != nil {
			return copied, err
		}
		if read == 0 {
			return copied, io.ErrNoProgress
		}
	}
	return copied, nil
}

func openInput(directory int, name string) (int, unix.Stat_t, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return -1, status, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Nlink != 1 {
		_ = unix.Close(fd)
		return -1, status, errors.New("authoring entry must be a single-link regular file")
	}
	return fd, status, nil
}

func readInput(directory int, name string, maximum int64) ([]byte, error) {
	fd, status, err := openInput(directory, name)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if status.Size < 0 || status.Size > maximum {
		return nil, errors.New("file exceeds limit")
	}
	data := make([]byte, status.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("%w: %v", errInputChanged, err)
	}
	var extra [1]byte
	if n, _ := file.Read(extra[:]); n != 0 {
		return nil, fmt.Errorf("%w: file grew during read", errInputChanged)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameStat(status, after) {
		return nil, fmt.Errorf("%w: file changed during read", errInputChanged)
	}
	return data, nil
}

var errInputChanged = errors.New("input changed")

func directoryNames(fd int) ([]string, error) {
	duplicate, err := linux.OpenDirAt(fd, ".")
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(duplicate), "directory")
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

func equalStrings(left, right []string) bool {
	return bytes.Equal([]byte(strings.Join(left, "\x00")), []byte(strings.Join(right, "\x00")))
}

func sameStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

type limitWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *limitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("compressed archive exceeds 8 MiB")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}

func canceled(ctx context.Context) error {
	if ctx == nil {
		return diagnostic(Canceled, "", "build canceled", context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return diagnostic(Canceled, "", "build canceled", err)
	}
	return nil
}
