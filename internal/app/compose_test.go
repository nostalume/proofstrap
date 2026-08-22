package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestComposeProjectsExactSourceClosureOnce(t *testing.T) {
	root := filepath.Join("..", "pack", "testdata", "composition")
	output := t.TempDir()
	dependency := buildAppSource(t, filepath.Join(root, "semantic-dependency"), filepath.Join(output, "dependency.pstrap"))
	semantic := buildAppSource(t, filepath.Join(root, "semantic-root"), filepath.Join(output, "semantic.pstrap"))
	catalogue := buildAppSource(t, filepath.Join(root, "binding-catalogue"), filepath.Join(output, "binding.pstrap"))
	data := []byte(fmt.Sprintf(`schema = 3
bindings = ["linux"]
include = [{ profile = "core:workload" }]

[sources]
core = %q
linux = %q
`, semantic.Digest().String(), catalogue.Digest().String()))
	target, err := document.Decode("test", data)
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, _ := binding.NewPackageBackendID("zypper")
	serviceBackend, _ := binding.NewServiceBackendID("systemd")
	graph, err := compose(context.Background(), target, []pack.Source{catalogue, semantic, dependency}, binding.Backends{Package: packageBackend, Service: serviceBackend})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("projected nodes = %#v", nodes)
	}
	if id, ok := binding.PackageIDOf(nodes[0]); !ok || id.Backend() != packageBackend || id.Name() != "agent-native" {
		t.Fatalf("package node = %#v", nodes[0])
	}
	if id, ok := binding.ServiceIDOf(nodes[1]); !ok || id.Backend() != serviceBackend || id.Name() != "agent.service" || len(nodes[1].Dependencies()) != 1 {
		t.Fatalf("service node = %#v", nodes[1])
	}
}

func TestComposeProjectsLocalProfileThroughLocalBinding(t *testing.T) {
	target, err := document.Decode("target.toml", []byte(`schema = 3
include = [{ profile = "workstation" }]

[profiles.workstation]
packages = ["agent"]

[profiles.workstation.services.agent]
target = "system"
packages = ["agent"]
running = true

[[bind]]
package = ["zypper"]
to = { agent = ["agent-native"] }

[[bind]]
service = ["systemd"]
to = { agent = ["agent.service"] }
`))
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, _ := binding.NewPackageBackendID("zypper")
	serviceBackend, _ := binding.NewServiceBackendID("systemd")
	graph, err := compose(context.Background(), target, nil, binding.Backends{Package: packageBackend, Service: serviceBackend})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("projected nodes = %#v", nodes)
	}
	id, ok := binding.PackageIDOf(nodes[0])
	if !ok || id.Backend() != packageBackend || id.Name() != "agent-native" {
		t.Fatalf("package node = %#v", nodes[0])
	}
	service, ok := binding.ServiceIDOf(nodes[1])
	if !ok || service.Backend() != serviceBackend || service.Name() != "agent.service" || len(nodes[1].Dependencies()) != 1 {
		t.Fatalf("service node = %#v", nodes[1])
	}
}

func TestResolveCompositionBindsProfileReferenceAcrossSources(t *testing.T) {
	root := t.TempDir()
	core := buildInlineSemantic(t, filepath.Join(root, "core"), `[profiles.workstation]
parameters = { desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
`)
	extra := buildInlineSemantic(t, filepath.Join(root, "extra"), `[profiles.sway]
packages = ["sway"]
`)
	data := []byte(fmt.Sprintf(`schema = 3
include = [{ profile = "core:workstation", arguments = { desktop = "extra:sway" } }]
[sources]
core = %q
extra = %q
`, core.Digest(), extra.Digest()))
	target, err := document.Decode("test", data)
	if err != nil {
		t.Fatal(err)
	}
	graph, _, err := resolveComposition(context.Background(), target, []pack.Source{core, extra})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 1 || nodes[0].Key().Canonical() != "package:sway" {
		t.Fatalf("nodes = %#v", nodes)
	}
	renamed := []byte(fmt.Sprintf(`schema=3
include=[{profile="core:workstation",arguments={desktop="choice:sway"}}]
[sources]
core=%q
choice=%q
`, core.Digest(), extra.Digest()))
	target, err = document.Decode("renamed", renamed)
	if err != nil {
		t.Fatal(err)
	}
	same, _, err := resolveComposition(context.Background(), target, []pack.Source{extra, core})
	if err != nil || !reflect.DeepEqual(graph.Nodes(), same.Nodes()) {
		t.Fatalf("alias changed graph truth: %v", err)
	}
}

func TestResolveCompositionRejectsUnusedSourceAfterBinding(t *testing.T) {
	root := t.TempDir()
	core := buildInlineSemantic(t, filepath.Join(root, "core"), "[profiles.base]\npackages=['base']\n")
	unused := buildInlineSemantic(t, filepath.Join(root, "unused"), "[profiles.other]\npackages=['other']\n")
	data := []byte(fmt.Sprintf("schema=3\ninclude=[{profile='core:base'}]\n[sources]\ncore=%q\nunused=%q\n", core.Digest(), unused.Digest()))
	target, err := document.Decode("test", data)
	if err != nil {
		t.Fatal(err)
	}
	if graph, _, err := resolveComposition(context.Background(), target, []pack.Source{core, unused}); err == nil || len(graph.Nodes()) != 0 {
		t.Fatalf("resolveComposition = %#v, %v", graph, err)
	}
}

func buildInlineSemantic(t testing.TB, input, profileData string) pack.Source {
	return buildInlineSemanticAt(t, input, filepath.Join(t.TempDir(), "source.pstrap"), profileData)
}

func buildInlineSemanticAt(t testing.TB, input, output, profileData string) pack.Source {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(input, "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "manifest.toml"), []byte("schema=1\nkind=\"semantic\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "profiles", "profiles.toml"), []byte(profileData), 0o644); err != nil {
		t.Fatal(err)
	}
	return buildAppSource(t, input, output)
}

func buildAppSource(t testing.TB, input, output string) pack.Source {
	t.Helper()
	absolute, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packbuild.Build(context.Background(), absolute, output); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	source, err := pack.Read(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
