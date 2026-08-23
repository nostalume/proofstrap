package packbuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

const maxInput = 1 << 20

type Category string

const (
	InvalidInput Category = "InvalidInput"
	InputChanged Category = "InputChanged"
	OutputExists Category = "OutputExists"
	IO           Category = "IO"
	Canceled     Category = "Canceled"
)

type Diagnostic struct {
	Category     Category
	Path, Detail string
	cause        error
}

func (d *Diagnostic) Error() string {
	p := d.Path
	if p != "" {
		p += ": "
	}
	return p + string(d.Category) + ": " + d.Detail
}
func (d *Diagnostic) Unwrap() error { return d.cause }
func diagnostic(c Category, p, detail string, err error) *Diagnostic {
	if detail == "" && err != nil {
		detail = err.Error()
	}
	return &Diagnostic{c, p, detail, err}
}

type snapshot struct {
	path string
	file *os.File
	stat unix.Stat_t
}

func (s *snapshot) close() { _ = s.file.Close() }
func (s *snapshot) unchanged() bool {
	var now unix.Stat_t
	return unix.Fstat(int(s.file.Fd()), &now) == nil && s.stat.Dev == now.Dev && s.stat.Ino == now.Ino &&
		s.stat.Size == now.Size && s.stat.Mtim == now.Mtim && s.stat.Ctim == now.Ctim
}

func readSnapshot(path string, limit int64) ([]byte, *snapshot, error) {
	fd, err := linux.OpenRegular(path)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Nlink != 1 || st.Size < 0 || st.Size > limit {
		_ = f.Close()
		return nil, nil, errors.New("unsafe or oversized regular file")
	}
	b := make([]byte, st.Size)
	if _, err = io.ReadFull(f, b); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	var extra [1]byte
	if n, _ := f.Read(extra[:]); n != 0 {
		_ = f.Close()
		return nil, nil, errors.New("file grew during read")
	}
	s := &snapshot{path, f, st}
	if !s.unchanged() {
		s.close()
		return nil, nil, errors.New("file changed during read")
	}
	return b, s, nil
}
func closeSnapshots(values []*snapshot) {
	for _, value := range values {
		value.close()
	}
}
func stable(input *snapshot, sources []*snapshot, action string) error {
	if !input.unchanged() {
		return diagnostic(InputChanged, input.path, "input changed during "+action, nil)
	}
	for _, source := range sources {
		if !source.unchanged() {
			return diagnostic(InputChanged, source.path, "source changed during "+action, nil)
		}
	}
	return nil
}

// Check proves that one document's resolved semantics close under explicit backends.
func Check(ctx context.Context, inputPath, packageBackend, serviceBackend string) error {
	if err := canceled(ctx); err != nil {
		return err
	}
	if !linux.CleanAbsoluteNonRoot(inputPath) {
		return diagnostic(InvalidInput, inputPath, "input must be a clean absolute non-root path", nil)
	}
	data, input, err := readSnapshot(inputPath, maxInput)
	if err != nil {
		return diagnostic(InvalidInput, inputPath, "read input document", err)
	}
	defer input.close()
	target, err := document.Decode(inputPath, data)
	if err != nil {
		return diagnostic(InvalidInput, inputPath, "decode input document", err)
	}
	_, sources, snaps, err := loadClosure(ctx, filepath.Join(filepath.Dir(inputPath), "packs"), target.View().Sources)
	if err != nil {
		return err
	}
	defer closeSnapshots(snaps)
	graph, catalogues, err := document.Resolve(ctx, target, sources)
	if err != nil {
		return diagnostic(InvalidInput, inputPath, "resolve input workspace", err)
	}
	packageID, err := binding.NewPackageBackendID(packageBackend)
	if err != nil {
		return diagnostic(InvalidInput, inputPath, "select package backend", err)
	}
	serviceID, err := binding.NewServiceBackendID(serviceBackend)
	if err != nil {
		return diagnostic(InvalidInput, inputPath, "select service backend", err)
	}
	_, projectionErr := binding.Project(ctx, graph, binding.Backends{Package: packageID, Service: serviceID}, catalogues)
	if err := stable(input, snaps, "check"); err != nil {
		return err
	}
	if projectionErr != nil {
		return diagnostic(InvalidInput, inputPath, "check backend binding closure", projectionErr)
	}
	return nil
}

// Build compiles one schema-3 document into an absent, self-contained workspace.
func Build(ctx context.Context, inputPath, outputPath string) (string, error) {
	if err := canceled(ctx); err != nil {
		return "", err
	}
	if !linux.CleanAbsoluteNonRoot(inputPath) || !linux.CleanAbsoluteNonRoot(outputPath) {
		return "", diagnostic(InvalidInput, "", "input and output must be clean absolute non-root paths", nil)
	}
	data, input, err := readSnapshot(inputPath, maxInput)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "read input document", err)
	}
	defer input.close()
	target, err := document.Decode(inputPath, data)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "decode input document", err)
	}
	objects, sources, snaps, err := loadClosure(ctx, filepath.Join(filepath.Dir(inputPath), "packs"), target.View().Sources)
	if err != nil {
		return "", err
	}
	defer closeSnapshots(snaps)
	used := map[string]struct{}{}
	for _, s := range target.View().Sources {
		used[s.Name] = struct{}{}
	}
	semanticAlias := fresh("local", used)
	used[semanticAlias] = struct{}{}
	bindingAlias := fresh("binding", used)
	originalGraph, originalBindings, calls, err := document.ResolvePromotion(ctx, target, sources, semanticAlias)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "resolve input workspace", err)
	}
	promotion, err := document.Promote(target, semanticAlias, calls)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "promote document", err)
	}
	byAlias := map[string]pack.Digest{}
	for _, s := range target.View().Sources {
		byAlias[s.Name] = s.Digest
	}
	var semanticDigest, bindingDigest *pack.Digest
	if promotion.Semantic != nil {
		requires, err := requirements(promotion.SemanticRequires, byAlias)
		if err != nil {
			return "", err
		}
		blob, source, err := makeArchive(ctx, pack.Semantic, "profiles/local.toml", promotion.Semantic, requires)
		if err != nil {
			return "", err
		}
		d := source.Digest()
		semanticDigest = &d
		objects[d] = blob
		sources = append(sources, source)
		byAlias[semanticAlias] = d
	}
	if promotion.Binding != nil {
		requires, err := requirements(promotion.BindingRequires, byAlias)
		if err != nil {
			return "", err
		}
		if promotion.BindingUsesLocal {
			if semanticDigest == nil {
				return "", diagnostic(InvalidInput, inputPath, "local bindings require local profiles", nil)
			}
			requires[semanticAlias] = *semanticDigest
		}
		blob, source, err := makeArchive(ctx, pack.Binding, "bindings/local.toml", promotion.Binding, requires)
		if err != nil {
			return "", err
		}
		d := source.Digest()
		bindingDigest = &d
		objects[d] = blob
		sources = append(sources, source)
	}
	config, err := document.RenderTarget(target, promotion, semanticAlias, semanticDigest, bindingAlias, bindingDigest)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "render target", err)
	}
	generated, err := document.Decode(filepath.Join(outputPath, "proofstrap.toml"), config)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "generated document rejected: "+err.Error(), err)
	}
	generatedGraph, generatedBindings, err := document.Resolve(ctx, generated, sources)
	if err != nil {
		return "", diagnostic(InvalidInput, inputPath, "generated workspace rejected: "+err.Error(), err)
	}
	if !model.Equivalent(originalGraph, generatedGraph) || !binding.Equivalent(originalBindings, generatedBindings) {
		return "", diagnostic(InvalidInput, inputPath, "generated workspace changed resolved meaning", nil)
	}
	if err := stable(input, snaps, "build"); err != nil {
		return "", err
	}
	if err := publish(outputPath, config, objects); err != nil {
		return "", err
	}
	return filepath.Join(outputPath, "proofstrap.toml"), nil
}
func requirements(handles []string, aliases map[string]pack.Digest) (map[string]pack.Digest, error) {
	r := make(map[string]pack.Digest, len(handles))
	for _, h := range handles {
		d, ok := aliases[h]
		if !ok {
			return nil, diagnostic(InvalidInput, "", "missing source alias "+h, nil)
		}
		r[h] = d
	}
	return r, nil
}
func fresh(base string, used map[string]struct{}) string {
	for n := 1; ; n++ {
		v := base
		if n > 1 {
			v = fmt.Sprintf("%s-%d", base, n)
		}
		if _, ok := used[v]; !ok {
			return v
		}
	}
}
func loadClosure(ctx context.Context, store string, roots []document.Source) (map[pack.Digest][]byte, []pack.Source, []*snapshot, error) {
	objects := map[pack.Digest][]byte{}
	if len(roots) == 0 {
		return objects, nil, nil, nil
	}
	var snaps []*snapshot
	var total int64
	digests := make([]pack.Digest, len(roots))
	for i, r := range roots {
		digests[i] = r.Digest
	}
	loader := func(ctx context.Context, d pack.Digest) (pack.Source, error) {
		if len(objects) >= 64 {
			return pack.Source{}, diagnostic(InvalidInput, store, "source closure exceeds 64 packs", nil)
		}
		name := strings.TrimPrefix(d.String(), "sha256:") + ".pstrap"
		path := filepath.Join(store, "sha256", name)
		data, s, err := readSnapshot(path, 8<<20)
		if err != nil {
			return pack.Source{}, diagnostic(InvalidInput, path, "read exact source", err)
		}
		snaps = append(snaps, s)
		total += int64(len(data))
		if total > 128<<20 {
			return pack.Source{}, diagnostic(InvalidInput, store, "source closure exceeds 128 MiB", nil)
		}
		source, err := pack.Read(ctx, bytes.NewReader(data))
		if err != nil || source.Digest() != d {
			return pack.Source{}, diagnostic(InvalidInput, path, "source digest or archive is invalid", err)
		}
		objects[d] = data
		return source, nil
	}
	sources, err := pack.ResolveClosure(ctx, digests, nil, loader)
	if err != nil {
		return nil, nil, snaps, err
	}
	return objects, sources, snaps, nil
}
func makeArchive(ctx context.Context, kind pack.Kind, name string, content []byte, requires map[string]pack.Digest) ([]byte, pack.Source, error) {
	var manifest strings.Builder
	fmt.Fprintf(&manifest, "schema = 1\nkind = %q\n", kind.String())
	if len(requires) > 0 {
		manifest.WriteString("\n[requires]\n")
		keys := make([]string, 0, len(requires))
		for k := range requires {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&manifest, "%s = %q\n", k, requires[k].String())
		}
	}
	var out bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	gz.Header = gzip.Header{ModTime: time.Unix(0, 0), OS: 255}
	tw := tar.NewWriter(gz)
	for _, m := range []struct {
		name string
		data []byte
	}{{"manifest.toml", []byte(manifest.String())}, {name, content}} {
		h := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			return nil, pack.Source{}, err
		}
		if _, err := tw.Write(m.data); err != nil {
			return nil, pack.Source{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, pack.Source{}, err
	}
	if err := gz.Close(); err != nil {
		return nil, pack.Source{}, err
	}
	if out.Len() > 8<<20 {
		return nil, pack.Source{}, diagnostic(InvalidInput, name, "generated pack exceeds 8 MiB", nil)
	}
	blob := append([]byte(nil), out.Bytes()...)
	source, err := pack.Read(ctx, bytes.NewReader(blob))
	return blob, source, err
}
func publish(output string, config []byte, objects map[pack.Digest][]byte) error {
	parent := filepath.Dir(output)
	if _, err := os.Lstat(output); err == nil {
		return diagnostic(OutputExists, output, "output already exists", nil)
	} else if !os.IsNotExist(err) {
		return diagnostic(IO, output, "inspect output", err)
	}
	stage, err := os.MkdirTemp(parent, ".proofstrap-pack-")
	if err != nil {
		return diagnostic(IO, output, "create staging directory", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	if len(objects) > 0 {
		dir := filepath.Join(stage, "packs", "sha256")
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		digests := make([]pack.Digest, 0, len(objects))
		for d := range objects {
			digests = append(digests, d)
		}
		sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
		for _, d := range digests {
			name := strings.TrimPrefix(d.String(), "sha256:") + ".pstrap"
			if err = writeSynced(filepath.Join(dir, name), objects[d]); err != nil {
				return err
			}
		}
	}
	if err = writeSynced(filepath.Join(stage, "proofstrap.toml"), config); err != nil {
		return err
	}
	for _, directory := range []string{filepath.Join(stage, "packs", "sha256"), filepath.Join(stage, "packs"), stage} {
		fd, openErr := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if os.IsNotExist(openErr) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		if syncErr := unix.Fsync(fd); syncErr != nil {
			_ = unix.Close(fd)
			return syncErr
		}
		_ = unix.Close(fd)
	}
	if err = unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		if err == unix.EEXIST {
			return diagnostic(OutputExists, output, "output already exists", err)
		}
		return diagnostic(IO, output, "publish workspace", err)
	}
	published = true
	if fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
	}
	return nil
}
func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}
func canceled(ctx context.Context) error {
	if ctx != nil && ctx.Err() == nil {
		return nil
	}
	cause := context.Canceled
	if ctx != nil {
		cause = ctx.Err()
	}
	return diagnostic(Canceled, "", "operation canceled", cause)
}
