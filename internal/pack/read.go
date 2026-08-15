package pack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

const (
	maxCompressedBytes = 8 << 20
	maxDecodedBytes    = 32 << 20
	maxManifestBytes   = 64 << 10
	maxContentBytes    = 1 << 20
	maxContentMembers  = 256
	maxRequirements    = 64
)

var (
	errCompressedLimit = errors.New("compressed archive exceeds 8 MiB")
	errDecodedLimit    = errors.New("decoded archive exceeds 32 MiB")
)

type rawManifest struct {
	Schema   int                `toml:"schema"`
	Kind     string             `toml:"kind"`
	Requires *map[string]string `toml:"requires"`
}

type decodedReader struct {
	ctx   context.Context
	r     io.Reader
	count int64
}

type compressedReader struct {
	ctx     context.Context
	r       io.Reader
	hash    hash.Hash
	count   int64
	failure error
}

type sourceReadError struct {
	err error
}

func (e *sourceReadError) Error() string { return e.err.Error() }
func (e *sourceReadError) Unwrap() error { return e.err }

func newCompressedReader(ctx context.Context, source io.Reader) *compressedReader {
	return &compressedReader{ctx: ctx, r: source, hash: sha256.New()}
}

func (r *compressedReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		r.failure = err
		return 0, err
	}
	remaining := int64(maxCompressedBytes) - r.count
	if remaining < 0 {
		r.failure = errCompressedLimit
		return 0, errCompressedLimit
	}
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	n, err := r.r.Read(buffer)
	if n > 0 {
		admitted := n
		if int64(n) > remaining {
			admitted = int(remaining)
		}
		if admitted > 0 {
			r.count += int64(admitted)
			_, _ = r.hash.Write(buffer[:admitted])
		}
		if admitted != n {
			r.failure = errCompressedLimit
			return admitted, errCompressedLimit
		}
	}
	if err != nil && err != io.EOF {
		r.failure = &sourceReadError{err: err}
		return n, r.failure
	}
	if n == 0 && err == nil {
		r.failure = &sourceReadError{err: io.ErrNoProgress}
		return 0, r.failure
	}
	return n, err
}

func (r *compressedReader) digest() Digest {
	var sum [sha256.Size]byte
	copy(sum[:], r.hash.Sum(nil))
	return Digest{sum: sum}
}

func (r *decodedReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	remaining := int64(maxDecodedBytes) - r.count
	if remaining < 0 {
		return 0, errDecodedLimit
	}
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	n, err := r.r.Read(buffer)
	r.count += int64(n)
	if r.count > maxDecodedBytes {
		return n, errDecodedLimit
	}
	return n, err
}

func Read(ctx context.Context, src io.Reader) (Source, error) {
	if ctx == nil {
		return Source{}, diagnostic(Canceled, "", "", "nil context", context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return Source{}, cancellationDiagnostic(err)
	}
	if src == nil {
		return Source{}, diagnostic(IO, "", "", "nil archive reader", nil)
	}
	compressed := newCompressedReader(ctx, src)
	buffered := bufio.NewReaderSize(compressed, 32<<10)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		if compressed.failure != nil {
			return Source{}, compressedReadDiagnostic(compressed.failure)
		}
		return Source{}, gzipReadDiagnostic(err)
	}
	gzipReader.Multistream(false)
	decoded := &decodedReader{ctx: ctx, r: gzipReader}
	tarReader := tar.NewReader(decoded)

	manifest, kind, requirements, members, err := readMembers(ctx, tarReader)
	if err != nil {
		_ = gzipReader.Close()
		if compressed.failure != nil {
			return Source{}, compressedReadDiagnostic(compressed.failure)
		}
		return Source{}, err
	}
	if err := consumeZeroPadding(decoded); err != nil {
		_ = gzipReader.Close()
		if compressed.failure != nil {
			return Source{}, compressedReadDiagnostic(compressed.failure)
		}
		return Source{}, err
	}
	if err := gzipReader.Close(); err != nil {
		return Source{}, gzipReadDiagnostic(err)
	}
	if _, err := buffered.Peek(1); err == nil {
		return Source{}, diagnostic(Integrity, "", "", "trailing compressed data or second gzip stream", nil)
	} else if err != io.EOF {
		return Source{}, compressedReadDiagnostic(err)
	}
	digest := compressed.digest()
	if err := rejectSelfRequirement(requirements, digest); err != nil {
		return Source{}, diagnostic(InvalidManifest, manifest, "requires", err.Error(), err)
	}
	return Source{state: &sourceState{
		digest: digest, kind: kind, compressed: compressed.count,
		requirements: requirements, members: members,
	}}, nil
}

func rejectSelfRequirement(requirements map[string]Digest, enclosing Digest) error {
	for _, required := range requirements {
		if required == enclosing {
			return fmt.Errorf("pack requires its own digest")
		}
	}
	return nil
}

func readMembers(ctx context.Context, reader *tar.Reader) (string, Kind, map[string]Digest, []contentMember, error) {
	var kind Kind
	var requirements map[string]Digest
	var members []contentMember
	seen := make(map[string]struct{})
	previous := ""
	index := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, nil, nil, cancellationDiagnostic(err)
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, nil, nil, archiveReadDiagnostic(err)
		}
		if header.Format != tar.FormatUSTAR {
			return "", 0, nil, nil, diagnostic(Syntax, header.Name, "", "only USTAR members are admitted", nil)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return "", 0, nil, nil, diagnostic(Syntax, header.Name, "", "only regular files are admitted", nil)
		}
		if _, exists := seen[strings.ToLower(header.Name)]; exists {
			return "", 0, nil, nil, diagnostic(Duplicate, header.Name, "", "duplicate or case-colliding path", nil)
		}
		if index > 1 && header.Name <= previous {
			return "", 0, nil, nil, diagnostic(InvalidPath, header.Name, "", "members are not in canonical path order", nil)
		}
		seen[strings.ToLower(header.Name)] = struct{}{}
		previous = header.Name
		if index == 0 {
			if header.Name != "manifest.toml" {
				return "", 0, nil, nil, diagnostic(InvalidPath, header.Name, "", "manifest.toml must be first", nil)
			}
			data, err := readMember(reader, header.Size, maxManifestBytes, header.Name)
			if err != nil {
				return "", 0, nil, nil, err
			}
			kind, requirements, err = decodeManifest(data)
			if err != nil {
				return "", 0, nil, nil, err
			}
		} else {
			if len(members) >= maxContentMembers {
				return "", 0, nil, nil, diagnostic(Limit, header.Name, "", "content member limit exceeded", nil)
			}
			if err := validateContentPath(kind, header.Name); err != nil {
				return "", 0, nil, nil, err
			}
			data, err := readMember(reader, header.Size, maxContentBytes, header.Name)
			if err != nil {
				return "", 0, nil, nil, err
			}
			members = append(members, contentMember{path: header.Name, data: data})
		}
		index++
	}
	if index == 0 {
		return "", 0, nil, nil, diagnostic(InvalidManifest, "", "", "archive has no manifest", nil)
	}
	if len(members) == 0 {
		return "", 0, nil, nil, diagnostic(KindMismatch, "", "", "pack has no content members", nil)
	}
	return "manifest.toml", kind, requirements, members, nil
}

func readMember(reader io.Reader, size, maximum int64, name string) ([]byte, error) {
	if size < 0 || size > maximum {
		return nil, diagnostic(Limit, name, "", fmt.Sprintf("member payload exceeds %d bytes", maximum), nil)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, archiveReadDiagnostic(err)
	}
	if !utf8.Valid(data) {
		return nil, diagnostic(Syntax, name, "", "member is not valid UTF-8", nil)
	}
	return data, nil
}

func decodeManifest(data []byte) (Kind, map[string]Digest, error) {
	var raw rawManifest
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return 0, nil, diagnostic(InvalidManifest, "manifest.toml", "", "invalid manifest", err)
	}
	if raw.Schema != 1 {
		return 0, nil, diagnostic(UnsupportedSchema, "manifest.toml", "schema", "schema must equal integer 1", nil)
	}
	kind, err := parseKind(raw.Kind)
	if err != nil {
		return 0, nil, diagnostic(InvalidManifest, "manifest.toml", "kind", err.Error(), err)
	}
	if raw.Requires != nil && len(*raw.Requires) == 0 {
		return 0, nil, diagnostic(InvalidManifest, "manifest.toml", "requires", "explicit empty requirements table", nil)
	}
	if raw.Requires != nil && len(*raw.Requires) > maxRequirements {
		return 0, nil, diagnostic(Limit, "manifest.toml", "requires", "requirement limit exceeded", nil)
	}
	requirements := make(map[string]Digest)
	if raw.Requires != nil {
		requirements = make(map[string]Digest, len(*raw.Requires))
	}
	for handle, text := range valueOrEmpty(raw.Requires) {
		if !validSymbol(handle) {
			return 0, nil, diagnostic(InvalidManifest, "manifest.toml", "requires."+handle, "invalid requirement handle", nil)
		}
		digest, err := ParseDigest(text)
		if err != nil {
			return 0, nil, diagnostic(InvalidManifest, "manifest.toml", "requires."+handle, err.Error(), err)
		}
		requirements[handle] = digest
	}
	return kind, requirements, nil
}

func ManifestKind(data []byte) (Kind, error) {
	if len(data) > maxManifestBytes {
		return 0, diagnostic(Limit, "manifest.toml", "", "manifest exceeds 64 KiB", nil)
	}
	if !utf8.Valid(data) {
		return 0, diagnostic(Syntax, "manifest.toml", "", "manifest is not valid UTF-8", nil)
	}
	kind, _, err := decodeManifest(data)
	return kind, err
}

func valueOrEmpty(value *map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	return *value
}

func validateContentPath(kind Kind, path string) error {
	prefix := "profiles/"
	if kind == Binding {
		prefix = "bindings/"
	}
	if !strings.HasPrefix(path, prefix) || strings.Count(path, "/") != 1 {
		return diagnostic(KindMismatch, path, "", "content path does not match pack kind", nil)
	}
	filename := strings.TrimPrefix(path, prefix)
	if !validContentFilename(filename) {
		return diagnostic(InvalidPath, path, "", "invalid content filename", nil)
	}
	return nil
}

func validContentFilename(filename string) bool {
	if len(filename) < len("0.toml") || len(filename) > 99 || !strings.HasSuffix(filename, ".toml") {
		return false
	}
	stem := strings.TrimSuffix(filename, ".toml")
	if len(stem) == 0 || stem[0] == '-' {
		return false
	}
	for _, character := range stem {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validSymbol(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func consumeZeroPadding(reader io.Reader) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := reader.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 {
				return diagnostic(Integrity, "", "", "non-zero trailing tar content", nil)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return archiveReadDiagnostic(err)
		}
	}
}

func archiveReadDiagnostic(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cancellationDiagnostic(err)
	}
	if errors.Is(err, errDecodedLimit) {
		return diagnostic(Limit, "", "", errDecodedLimit.Error(), err)
	}
	if errors.Is(err, errCompressedLimit) {
		return diagnostic(Limit, "", "", errCompressedLimit.Error(), err)
	}
	var sourceError *sourceReadError
	if errors.As(err, &sourceError) {
		return ioDiagnostic(err)
	}
	return diagnostic(Syntax, "", "", "invalid tar stream", err)
}

func compressedReadDiagnostic(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cancellationDiagnostic(err)
	}
	if errors.Is(err, errCompressedLimit) {
		return diagnostic(Limit, "", "", errCompressedLimit.Error(), err)
	}
	return ioDiagnostic(err)
}

func gzipReadDiagnostic(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cancellationDiagnostic(err)
	}
	if errors.Is(err, errCompressedLimit) {
		return diagnostic(Limit, "", "", errCompressedLimit.Error(), err)
	}
	var sourceError *sourceReadError
	if errors.As(err, &sourceError) {
		return ioDiagnostic(err)
	}
	return diagnostic(Syntax, "", "", "invalid gzip stream", err)
}

func ioDiagnostic(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return cancellationDiagnostic(err)
	}
	return diagnostic(IO, "", "", "archive read failed", err)
}

func cancellationDiagnostic(err error) error {
	return diagnostic(Canceled, "", "", "archive read canceled", err)
}
