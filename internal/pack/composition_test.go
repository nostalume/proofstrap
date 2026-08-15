package pack_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
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
	digest, err := packbuild.Build(ctx, absoluteInput, output)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	source, err := pack.Read(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	if source.Digest() != digest {
		t.Fatalf("built digest = %s, admitted digest = %s", digest, source.Digest())
	}
	return source, digest
}

func assertDeterministicBuild(t *testing.T, ctx context.Context, input string, want pack.Digest, output string) {
	t.Helper()
	absoluteInput, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := packbuild.Build(ctx, absoluteInput, output)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("rebuilt digest = %s, want %s", got, want)
	}
}
