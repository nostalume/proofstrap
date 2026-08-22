package pack_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
)

func TestPackComposition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixtureRoot := filepath.Join("testdata", "composition")
	outputRoot := t.TempDir()

	dependency, dependencyDigest := buildSource(t, ctx, filepath.Join(fixtureRoot, "semantic-dependency"), filepath.Join(outputRoot, "dependency.pstrap"))
	root, rootDigest := buildSource(t, ctx, filepath.Join(fixtureRoot, "semantic-root"), filepath.Join(outputRoot, "root.pstrap"))
	catalogueSource, catalogueDigest := buildSource(t, ctx, filepath.Join(fixtureRoot, "binding-catalogue"), filepath.Join(outputRoot, "binding.pstrap"))

	assertDeterministicBuild(t, ctx, filepath.Join(fixtureRoot, "semantic-dependency"), dependencyDigest, filepath.Join(outputRoot, "dependency-again.pstrap"))
	assertDeterministicBuild(t, ctx, filepath.Join(fixtureRoot, "semantic-root"), rootDigest, filepath.Join(outputRoot, "root-again.pstrap"))
	assertDeterministicBuild(t, ctx, filepath.Join(fixtureRoot, "binding-catalogue"), catalogueDigest, filepath.Join(outputRoot, "binding-again.pstrap"))

	resolved, err := pack.Resolve(ctx, root, []pack.Source{dependency})
	if err != nil {
		t.Fatal(err)
	}
	rootProfile, err := profile.NewRoot("workload")
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := profile.Expand(model.EmptyGraph(), resolved.Library(), []profile.Root{rootProfile})
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := pack.ResolveCatalogue(ctx, catalogueSource, []pack.Source{root, dependency})
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, err := binding.NewPackageBackendID("zypper")
	if err != nil {
		t.Fatal(err)
	}
	serviceBackend, err := binding.NewServiceBackendID("systemd")
	if err != nil {
		t.Fatal(err)
	}
	projected, err := binding.Project(ctx, semantic, binding.Backends{Package: packageBackend, Service: serviceBackend}, []binding.Catalogue{catalogue})
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[string][]string)
	gotProvenance := make(map[string][]string)
	for _, node := range projected.Nodes() {
		dependencies := node.Dependencies()
		keys := make([]string, len(dependencies))
		for index, dependency := range dependencies {
			keys[index] = dependency.Canonical()
		}
		got[node.Key().Canonical()] = keys
		gotProvenance[node.Key().Canonical()] = node.Provenance()
	}
	want := map[string][]string{
		"package:6:zypper12:agent-native":                          {},
		"service:7:systemd13:agent.service20:service:agent:system": {"package:6:zypper12:agent-native"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected graph = %#v, want %#v", got, want)
	}
	bindingSource := catalogueDigest.String() + ":bindings/linux.toml"
	wantProvenance := map[string][]string{
		"package:6:zypper12:agent-native": {
			"profile:" + dependencyDigest.String() + "#base|",
			"profile:" + rootDigest.String() + "#workload|",
			bindingSource,
		},
		"service:7:systemd13:agent.service20:service:agent:system": {
			"profile:" + rootDigest.String() + "#workload|",
			bindingSource,
		},
	}
	if !reflect.DeepEqual(gotProvenance, wantProvenance) {
		t.Fatalf("projected provenance = %#v, want %#v", gotProvenance, wantProvenance)
	}
}

func buildSource(t *testing.T, ctx context.Context, input, output string) (pack.Source, pack.Digest) {
	t.Helper()
	absoluteInput, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	data := archiveFixture(t, absoluteInput)
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := pack.Read(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return source, source.Digest()
}

func assertDeterministicBuild(t *testing.T, ctx context.Context, input string, want pack.Digest, output string) {
	t.Helper()
	absoluteInput, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	data := archiveFixture(t, absoluteInput)
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatal(err)
	}
	gotSource, err := pack.Read(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	got := gotSource.Digest()
	if got != want {
		t.Fatalf("rebuilt digest = %s, want %s", got, want)
	}
}

func archiveFixture(t *testing.T, root string) []byte {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(root, "manifest.toml"))
	if err != nil {
		t.Fatal(err)
	}
	directory := "profiles"
	if _, err := os.Stat(filepath.Join(root, directory)); err != nil {
		directory = "bindings"
	}
	entries, err := os.ReadDir(filepath.Join(root, directory))
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	gzipWriter.Header = gzip.Header{ModTime: time.Unix(0, 0), OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	members := []struct {
		name string
		data []byte
	}{{"manifest.toml", manifest}}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(root, directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, struct {
			name string
			data []byte
		}{directory + "/" + entry.Name(), data})
	}
	for _, member := range members {
		header := &tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
