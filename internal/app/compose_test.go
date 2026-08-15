package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestComposeProjectsExactSourceClosureOnce(t *testing.T) {
	root := filepath.Join("..", "pack", "testdata", "composition")
	output := t.TempDir()
	dependency := buildAppSource(t, filepath.Join(root, "semantic-dependency"), filepath.Join(output, "dependency.pstrap"))
	semantic := buildAppSource(t, filepath.Join(root, "semantic-root"), filepath.Join(output, "semantic.pstrap"))
	catalogue := buildAppSource(t, filepath.Join(root, "binding-catalogue"), filepath.Join(output, "binding.pstrap"))
	data := []byte(fmt.Sprintf(`schema = 1
bindings = ["linux"]
profiles = [{ profile = "core:workload" }]

[sources]
core = %q
linux = %q
`, semantic.Digest().String(), catalogue.Digest().String()))
	target, err := config.Decode("test", data)
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

func buildAppSource(t *testing.T, input, output string) pack.Source {
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
