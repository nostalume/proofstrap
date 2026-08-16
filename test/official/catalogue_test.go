package official

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
	"github.com/nostalume/proofstrap/internal/profile"
)

func TestCatalogue(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join("..", "..", "profiles")
	output := t.TempDir()
	semantic := buildSource(t, ctx, filepath.Join(root, "core"), filepath.Join(output, "core.pstrap"))
	catalogueSource := buildSource(t, ctx, filepath.Join(root, "linux"), filepath.Join(output, "linux.pstrap"))

	resolved, err := pack.Resolve(ctx, semantic, nil)
	if err != nil {
		t.Fatal(err)
	}
	profiles := resolved.Library().ProfileIDs()
	wantProfiles := []string{"bootstrap-cli", "ca-certificates", "curl", "git", "gzip", "ssh-server", "tar", "vim"}
	if !reflect.DeepEqual(profiles, wantProfiles) {
		t.Fatalf("official profiles = %v, want %v", profiles, wantProfiles)
	}

	roots := make([]profile.Root, 0, len(profiles))
	for _, id := range profiles {
		selected, err := profile.NewRoot(id)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, selected)
	}
	semanticGraph, err := profile.Expand(model.EmptyGraph(), resolved.Library(), roots)
	if err != nil {
		t.Fatal(err)
	}
	assertGraph(t, semanticGraph, map[string][]string{
		"package:ca-certificates":   {},
		"package:curl":              {},
		"package:git":               {},
		"package:gzip":              {},
		"package:ssh-server":        {},
		"package:tar":               {},
		"package:vim":               {},
		"service:ssh-server:system": {"package:ssh-server"},
	})

	catalogue, err := pack.ResolveCatalogue(ctx, catalogueSource, []pack.Source{semantic})
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, _ := binding.NewPackageBackendID("zypper")
	serviceBackend, _ := binding.NewServiceBackendID("systemd")
	projected, err := binding.Project(ctx, semanticGraph, binding.Backends{Package: packageBackend, Service: serviceBackend}, []binding.Catalogue{catalogue})
	if err != nil {
		t.Fatal(err)
	}
	assertProjectedGraph(t, projected, map[string][]string{
		"package:6:zypper15:ca-certificates":                           {},
		"package:6:zypper4:curl":                                       {},
		"package:6:zypper3:git":                                        {},
		"package:6:zypper4:gzip":                                       {},
		"package:6:zypper3:tar":                                        {},
		"package:6:zypper3:vim":                                        {},
		"package:6:zypper14:openssh-server":                            {},
		"service:7:systemd12:sshd.service25:service:ssh-server:system": {"package:6:zypper14:openssh-server"},
	})

	openRC, _ := binding.NewServiceBackendID("openrc")
	apk, _ := binding.NewPackageBackendID("apk")
	projected, err = binding.Project(ctx, semanticGraph, binding.Backends{Package: apk, Service: openRC}, []binding.Catalogue{catalogue})
	if err != nil {
		t.Fatal(err)
	}
	assertProjectedGraph(t, projected, map[string][]string{
		"package:3:apk15:ca-certificates":                    {},
		"package:3:apk4:curl":                                {},
		"package:3:apk3:git":                                 {},
		"package:3:apk4:gzip":                                {},
		"package:3:apk3:tar":                                 {},
		"package:3:apk3:vim":                                 {},
		"package:3:apk14:openssh-server":                     {},
		"service:6:openrc4:sshd25:service:ssh-server:system": {"package:3:apk14:openssh-server"},
	})

	exampleBytes, err := os.ReadFile(filepath.Join("..", "..", "examples", "alpine.toml"))
	if err != nil {
		t.Fatal(err)
	}
	example, err := config.Decode("examples/alpine.toml", exampleBytes)
	if err != nil {
		t.Fatal(err)
	}
	wantSources := map[string]string{"core": semantic.Digest().String(), "linux": catalogueSource.Digest().String()}
	for _, source := range example.Sources() {
		if source.Digest.String() != wantSources[source.Alias] {
			t.Fatalf("example source %q = %s, want %s", source.Alias, source.Digest, wantSources[source.Alias])
		}
		delete(wantSources, source.Alias)
	}
	if len(wantSources) != 0 {
		t.Fatalf("example lacks sources %v", wantSources)
	}
}

func buildSource(t *testing.T, ctx context.Context, input, output string) pack.Source {
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
	return source
}

func assertGraph(t *testing.T, graph model.Graph, want map[string][]string) {
	t.Helper()
	got := make(map[string][]string)
	for _, node := range graph.Nodes() {
		dependencies := node.Dependencies()
		keys := make([]string, len(dependencies))
		for index, dependency := range dependencies {
			keys[index] = dependency.Canonical()
		}
		got[node.Key().Canonical()] = keys
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("graph = %#v, want %#v", got, want)
	}
}

func assertProjectedGraph(t *testing.T, graph binding.Graph, want map[string][]string) {
	t.Helper()
	got := make(map[string][]string)
	for _, node := range graph.Nodes() {
		dependencies := node.Dependencies()
		keys := make([]string, len(dependencies))
		for index, dependency := range dependencies {
			keys[index] = dependency.Canonical()
		}
		got[node.Key().Canonical()] = keys
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected graph = %#v, want %#v", got, want)
	}
}
