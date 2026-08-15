package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type archiveMember struct {
	name string
	data string
}

func testArchive(t *testing.T, members ...archiveMember) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := &tar.Header{
			Name:     member.name,
			Mode:     0o644,
			Size:     int64(len(member.data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tarWriter, member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func archiveWith(t *testing.T, configureGzip func(*gzip.Writer), headers []*tar.Header, payloads [][]byte, trailingDecoded int) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if configureGzip != nil {
		configureGzip(gzipWriter)
	}
	tarWriter := tar.NewWriter(gzipWriter)
	for index, header := range headers {
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if index < len(payloads) && payloads[index] != nil {
			if _, err := tarWriter.Write(payloads[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if trailingDecoded > 0 {
		if _, err := gzipWriter.Write(make([]byte, trailingDecoded)); err != nil {
			t.Fatal(err)
		}
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func regularHeader(name string, size int64) *tar.Header {
	return &tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
}

func errorCategory(t *testing.T, err error) Category {
	t.Helper()
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatalf("error type = %T, want *Diagnostic", err)
	}
	return diagnostic.Category
}

func TestManifestKindUsesStrictPackGrammar(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		data     []byte
		kind     Kind
		category Category
	}{
		{name: "semantic", data: []byte("schema=1\nkind='semantic'\n"), kind: Semantic},
		{name: "binding", data: []byte("schema=1\nkind='binding'\n"), kind: Binding},
		{name: "unknown", data: []byte("schema=1\nkind='semantic'\nextra=true\n"), category: InvalidManifest},
		{name: "oversized", data: make([]byte, maxManifestBytes+1), category: Limit},
		{name: "utf8", data: []byte{0xff}, category: Syntax},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, err := ManifestKind(test.data)
			if test.category == "" {
				if err != nil || kind != test.kind {
					t.Fatalf("ManifestKind = %v, %v", kind, err)
				}
				return
			}
			if kind != 0 || errorCategory(t, err) != test.category {
				t.Fatalf("ManifestKind = %v, %v; want %s", kind, err, test.category)
			}
		})
	}
}

func TestSourceDescriptionIsOrderedAndImmutable(t *testing.T) {
	digestText := "sha256:" + strings.Repeat("1", 64)
	source, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n[requires]\nz='" + digestText + "'\na='" + digestText + "'\n"},
		archiveMember{name: "profiles/a.toml", data: "x=1\n"},
		archiveMember{name: "profiles/b.toml", data: "x=1\n"},
	)))
	if err != nil {
		t.Fatal(err)
	}
	left := source.Description()
	if left.Digest != source.Digest() || left.Kind != Semantic || len(left.Requirements) != 2 || left.Requirements[0].Handle != "a" || left.Requirements[1].Handle != "z" || strings.Join(left.Members, ",") != "profiles/a.toml,profiles/b.toml" {
		t.Fatalf("Description = %#v", left)
	}
	left.Requirements[0].Handle = "changed"
	left.Members[0] = "changed"
	right := source.Description()
	if right.Requirements[0].Handle != "a" || right.Members[0] != "profiles/a.toml" {
		t.Fatalf("Description leaked mutable state: %#v", right)
	}
	if zero := (Source{}).Description(); zero.Digest != (Digest{}) || zero.Kind != 0 || zero.Requirements != nil || zero.Members != nil {
		t.Fatalf("zero Description = %#v", zero)
	}
}

func TestReadAdmitsExactSemanticAndBindingSources(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		kind    Kind
		members []archiveMember
	}{
		{
			name: "semantic",
			kind: Semantic,
			members: []archiveMember{
				{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
				{name: "profiles/base.toml", data: "[profiles.base]\npackages=['base']\n"},
			},
		},
		{
			name: "binding",
			kind: Binding,
			members: []archiveMember{
				{name: "manifest.toml", data: "schema=1\nkind='binding'\n"},
				{name: "bindings/base.toml", data: "[package.test]\nbase=['base']\n"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := testArchive(t, test.members...)
			source, err := Read(context.Background(), bytes.NewReader(archive))
			if err != nil {
				t.Fatal(err)
			}
			if source.Kind() != test.kind {
				t.Fatalf("Kind() = %v, want %v", source.Kind(), test.kind)
			}
			wantDigest := Digest{sum: sha256.Sum256(archive)}
			if source.Digest() != wantDigest {
				t.Fatalf("Digest() = %s, want %s", source.Digest(), wantDigest)
			}
		})
	}
}

func TestReadRejectsManifestAndLayoutDefectsAtomically(t *testing.T) {
	t.Parallel()
	tests := map[string][]archiveMember{
		"manifest-not-first": {
			{name: "profiles/base.toml", data: "x=1\n"},
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		},
		"unknown-manifest-field": {
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\nname='forbidden'\n"},
			{name: "profiles/base.toml", data: "x=1\n"},
		},
		"empty-requires": {
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\n[requires]\n"},
			{name: "profiles/base.toml", data: "x=1\n"},
		},
		"wrong-kind-directory": {
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
			{name: "bindings/base.toml", data: "x=1\n"},
		},
		"recursive-path": {
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
			{name: "profiles/sub/base.toml", data: "x=1\n"},
		},
		"invalid-filename": {
			{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
			{name: "profiles/User.toml", data: "x=1\n"},
		},
	}
	for name, members := range tests {
		name, members := name, members
		t.Run(name, func(t *testing.T) {
			source, err := Read(context.Background(), bytes.NewReader(testArchive(t, members...)))
			if err == nil {
				t.Fatal("defective archive admitted")
			}
			if source != (Source{}) {
				t.Fatalf("failed Read returned non-zero Source: %#v", source)
			}
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) {
				t.Fatalf("error type = %T, want *Diagnostic", err)
			}
		})
	}
}

func TestReadRejectsArchiveEnvelopeDefects(t *testing.T) {
	t.Parallel()
	valid := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	)
	second := append(append([]byte(nil), valid...), valid...)
	if _, err := Read(context.Background(), bytes.NewReader(second)); errorCategory(t, err) != Integrity {
		t.Fatalf("second gzip category = %v, want Integrity", errorCategory(t, err))
	}

	rawTrailing := archiveWith(t, nil, []*tar.Header{
		regularHeader("manifest.toml", 25),
		regularHeader("profiles/base.toml", 4),
	}, [][]byte{[]byte("schema=1\nkind='semantic'\n"), []byte("x=1\n")}, 1)
	rawTrailing[len(rawTrailing)-9] ^= 1
	if _, err := Read(context.Background(), bytes.NewReader(rawTrailing)); err == nil {
		t.Fatal("corrupt/non-zero trailing decoded content admitted")
	}

	directory := archiveWith(t, nil, []*tar.Header{
		regularHeader("manifest.toml", 25),
		{Name: "profiles", Mode: 0o755, Typeflag: tar.TypeDir, Format: tar.FormatUSTAR},
	}, [][]byte{[]byte("schema=1\nkind='semantic'\n")}, 0)
	if _, err := Read(context.Background(), bytes.NewReader(directory)); errorCategory(t, err) != Syntax {
		t.Fatalf("directory category = %v, want Syntax", errorCategory(t, err))
	}

	pax := archiveWith(t, nil, []*tar.Header{
		regularHeader("manifest.toml", 25),
		{Name: "profiles/base.toml", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "extension"}},
	}, [][]byte{[]byte("schema=1\nkind='semantic'\n"), []byte("x=1\n")}, 0)
	if _, err := Read(context.Background(), bytes.NewReader(pax)); err == nil {
		t.Fatal("PAX archive admitted")
	}
}

func TestReadRejectsDuplicateAndOutOfOrderMembers(t *testing.T) {
	t.Parallel()
	manifest := archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"}
	for name, members := range map[string][]archiveMember{
		"duplicate":    {manifest, {name: "profiles/base.toml", data: "x=1\n"}, {name: "profiles/base.toml", data: "x=1\n"}},
		"out-of-order": {manifest, {name: "profiles/z.toml", data: "x=1\n"}, {name: "profiles/a.toml", data: "x=1\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(context.Background(), bytes.NewReader(testArchive(t, members...))); err == nil {
				t.Fatal("defective member order admitted")
			}
		})
	}
}

func TestReadManifestRequirementLaws(t *testing.T) {
	t.Parallel()
	digestText := "sha256:" + strings.Repeat("0", 64)
	var requirements strings.Builder
	requirements.WriteString("schema=1\nkind='semantic'\n[requires]\n")
	for index := range maxRequirements {
		fmt.Fprintf(&requirements, "r%d='%s'\n", index, digestText)
	}
	valid := testArchive(t,
		archiveMember{name: "manifest.toml", data: requirements.String()},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	)
	if _, err := Read(context.Background(), bytes.NewReader(valid)); err != nil {
		t.Fatalf("exact requirement limit rejected: %v", err)
	}
	requirements.WriteString("overflow='" + digestText + "'\n")
	overflow := testArchive(t,
		archiveMember{name: "manifest.toml", data: requirements.String()},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	)
	if _, err := Read(context.Background(), bytes.NewReader(overflow)); errorCategory(t, err) != Limit {
		t.Fatalf("requirement overflow category = %v, want Limit", errorCategory(t, err))
	}

	for _, manifest := range []string{
		"kind='semantic'\n",
		"schema=2\nkind='semantic'\n",
		"schema=1.0\nkind='semantic'\n",
		"schema=1\nkind='other'\n",
		"schema=1\nkind='semantic'\n[requires]\nBad='" + digestText + "'\n",
		"schema=1\nkind='semantic'\n[requires]\ncore='sha256:ABC'\n",
	} {
		if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
			archiveMember{name: "manifest.toml", data: manifest},
			archiveMember{name: "profiles/base.toml", data: "x=1\n"},
		))); err == nil {
			t.Fatalf("invalid manifest admitted: %q", manifest)
		}
	}
}

func TestRejectSelfRequirement(t *testing.T) {
	t.Parallel()
	digest, err := ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectSelfRequirement(map[string]Digest{"self": digest}, digest); err == nil {
		t.Fatal("self requirement admitted")
	}
}

func TestReadArchiveBudgetBoundaries(t *testing.T) {
	t.Parallel()

	manifest := "schema=1\nkind='semantic'\n"
	manifestExact := manifest + "#" + strings.Repeat("x", maxManifestBytes-len(manifest)-2) + "\n"
	if len(manifestExact) != maxManifestBytes {
		t.Fatalf("manifest helper length = %d", len(manifestExact))
	}
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: manifestExact},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	))); err != nil {
		t.Fatalf("exact manifest limit rejected: %v", err)
	}
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: manifestExact + "#"},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	))); errorCategory(t, err) != Limit {
		t.Fatalf("manifest overflow category = %v, want Limit", errorCategory(t, err))
	}

	contentExact := strings.Repeat("x", maxContentBytes)
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: manifest},
		archiveMember{name: "profiles/base.toml", data: contentExact},
	))); err != nil {
		t.Fatalf("exact content limit rejected: %v", err)
	}
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: manifest},
		archiveMember{name: "profiles/base.toml", data: contentExact + "x"},
	))); errorCategory(t, err) != Limit {
		t.Fatalf("content overflow category = %v, want Limit", errorCategory(t, err))
	}

	members := []archiveMember{{name: "manifest.toml", data: manifest}}
	for index := range maxContentMembers {
		members = append(members, archiveMember{name: fmt.Sprintf("profiles/p%03d.toml", index), data: "x=1\n"})
	}
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t, members...))); err != nil {
		t.Fatalf("exact member limit rejected: %v", err)
	}
	members = append(members, archiveMember{name: "profiles/z.toml", data: "x=1\n"})
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t, members...))); errorCategory(t, err) != Limit {
		t.Fatalf("member overflow category = %v, want Limit", errorCategory(t, err))
	}

	filename := "a" + strings.Repeat("b", 93) + ".toml"
	if len(filename) != 99 {
		t.Fatalf("filename helper length = %d", len(filename))
	}
	if _, err := Read(context.Background(), bytes.NewReader(testArchive(t,
		archiveMember{name: "manifest.toml", data: manifest},
		archiveMember{name: "profiles/" + filename, data: "x=1\n"},
	))); err != nil {
		t.Fatalf("exact filename limit rejected: %v", err)
	}
	tooLong := "a" + strings.Repeat("b", 94) + ".toml"
	if validContentFilename(tooLong) {
		t.Fatal("100-byte filename admitted")
	}
}

func TestReadCompressedAndDecodedByteBoundaries(t *testing.T) {
	t.Parallel()
	exactCompressed := newCompressedReader(context.Background(), io.LimitReader(zeroReader{}, maxCompressedBytes))
	if n, err := io.Copy(io.Discard, exactCompressed); err != nil || n != maxCompressedBytes {
		t.Fatalf("exact compressed counter failed: bytes=%d err=%v", n, err)
	}
	overflowCompressed := newCompressedReader(context.Background(), io.LimitReader(zeroReader{}, maxCompressedBytes+1))
	if _, err := io.Copy(io.Discard, overflowCompressed); !errors.Is(err, errCompressedLimit) {
		t.Fatalf("compressed overflow error = %v, want limit", err)
	}
	exactDecoded := &decodedReader{ctx: context.Background(), r: io.LimitReader(zeroReader{}, maxDecodedBytes)}
	if n, err := io.Copy(io.Discard, exactDecoded); err != nil || n != maxDecodedBytes {
		t.Fatalf("exact decoded counter failed: bytes=%d err=%v", n, err)
	}
	overflowDecoded := &decodedReader{ctx: context.Background(), r: io.LimitReader(zeroReader{}, maxDecodedBytes+1)}
	if _, err := io.Copy(io.Discard, overflowDecoded); !errors.Is(err, errDecodedLimit) {
		t.Fatalf("decoded overflow error = %v, want limit", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadPreservesUnderlyingIOError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel read failure")
	_, err := Read(context.Background(), failingReader{err: sentinel})
	if !errors.Is(err, sentinel) || errorCategory(t, err) != IO {
		t.Fatalf("error = %v, want wrapped sentinel IO", err)
	}
}

type closeTrackingReader struct {
	*bytes.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

func TestReadHonorsCancellationAndDoesNotCloseReader(t *testing.T) {
	t.Parallel()
	archive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='semantic'\n"},
		archiveMember{name: "profiles/base.toml", data: "x=1\n"},
	)
	reader := &closeTrackingReader{Reader: bytes.NewReader(archive)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, err := Read(ctx, reader)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if source != (Source{}) {
		t.Fatalf("canceled Read returned non-zero Source: %#v", source)
	}
	if reader.closed {
		t.Fatal("Read closed caller-owned reader")
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxCompressedBytes+1 {
			data = data[:maxCompressedBytes+1]
		}
		source, err := Read(context.Background(), bytes.NewReader(data))
		if err != nil && source != (Source{}) {
			t.Fatalf("Read returned partial Source with %v", err)
		}
	})
}

var _ io.Closer = (*closeTrackingReader)(nil)
