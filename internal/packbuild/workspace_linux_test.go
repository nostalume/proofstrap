package packbuild_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestBuildDirectOnlyAndAbsentOnly(t *testing.T) {
	root := t.TempDir()
	input, output := filepath.Join(root, "input.toml"), filepath.Join(root, "dist")
	if err := os.WriteFile(input, []byte("schema=3\nhostname='host'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := packbuild.Build(context.Background(), input, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "packs")); !os.IsNotExist(err) {
		t.Fatalf("direct-only packs: %v", err)
	}
	before, _ := os.ReadFile(config)
	if _, err := packbuild.Build(context.Background(), input, output); err == nil {
		t.Fatal("existing output accepted")
	}
	after, _ := os.ReadFile(config)
	if !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
}

func TestBuildIsDeterministicAndRejectsDirectoryInput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input.toml")
	data := []byte("schema=3\ninclude=[{profile='base'}]\n[profiles.base]\npackages=['base']\n")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	left, right := filepath.Join(root, "left"), filepath.Join(root, "right")
	if _, err := packbuild.Build(context.Background(), input, left); err != nil {
		t.Fatal(err)
	}
	if _, err := packbuild.Build(context.Background(), input, right); err != nil {
		t.Fatal(err)
	}
	leftConfig, _ := os.ReadFile(filepath.Join(left, "proofstrap.toml"))
	rightConfig, _ := os.ReadFile(filepath.Join(right, "proofstrap.toml"))
	if !bytes.Equal(leftConfig, rightConfig) {
		t.Fatal("generated configs differ")
	}
	leftEntries, _ := os.ReadDir(filepath.Join(left, "packs", "sha256"))
	rightEntries, _ := os.ReadDir(filepath.Join(right, "packs", "sha256"))
	if len(leftEntries) != 1 || len(rightEntries) != 1 || leftEntries[0].Name() != rightEntries[0].Name() {
		t.Fatal("generated identities differ")
	}
	if _, err := packbuild.Build(context.Background(), root, filepath.Join(root, "bad")); err == nil {
		t.Fatal("directory input accepted")
	}
}

func TestBuildQualifiesProfileReferenceArgumentsOnly(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input.toml")
	output := filepath.Join(root, "dist")
	data := []byte(`schema=3
include=[{profile="choice",arguments={session="sway"}}]
[profiles.sway]
packages=["sway"]
[profiles.choice]
parameters={session="profile_ref"}
include=[{profile={parameter="session"}}]
`)
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := packbuild.Build(context.Background(), input, output)
	if err != nil {
		t.Fatal(err)
	}
	generated, _ := os.ReadFile(config)
	if !bytes.Contains(generated, []byte(`session = 'local:sway'`)) && !bytes.Contains(generated, []byte(`session = "local:sway"`)) {
		t.Fatalf("profile argument was not qualified:\n%s", generated)
	}
}

func TestBuildPromotesBindingAgainstImportedSemanticSource(t *testing.T) {
	root := t.TempDir()
	seed := filepath.Join(root, "seed.toml")
	if err := os.WriteFile(seed, []byte("schema=3\ninclude=[{profile='base'}]\n[profiles.base]\npackages=['base']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedConfig, err := packbuild.Build(context.Background(), seed, filepath.Join(root, "seed-dist"))
	if err != nil {
		t.Fatal(err)
	}
	seedBytes, _ := os.ReadFile(seedConfig)
	seedDocument, err := document.Decode(seedConfig, seedBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := seedDocument.View().Sources[0].Digest
	author := filepath.Join(root, "author")
	store := filepath.Join(author, "packs", "sha256")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	name := digest.String()[len("sha256:"):] + ".pstrap"
	object, _ := os.ReadFile(filepath.Join(root, "seed-dist", "packs", "sha256", name))
	if err := os.WriteFile(filepath.Join(store, name), object, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(author, "proofstrap.toml")
	data := []byte("schema=3\ninclude=[{profile='core:base'}]\n[sources]\ncore='" + digest.String() + "'\n[package.zypper]\n'core:base'=['base-native']\n")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := packbuild.Build(context.Background(), input, filepath.Join(root, "dist"))
	if err != nil {
		t.Fatal(err)
	}
	generatedBytes, _ := os.ReadFile(config)
	generated, err := document.Decode(config, generatedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if view := generated.View(); len(view.Sources) != 2 || len(view.Bindings) != 1 || view.Profiles.Present() || view.Mappings.Present() {
		t.Fatalf("generated view = %#v", view)
	}
}

func TestBuildMissingImportLeavesNoOutput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "proofstrap.toml")
	output := filepath.Join(root, "dist")
	data := []byte("schema=3\ninclude=[{profile='core:base'}]\n[sources]\ncore='sha256:" + strings.Repeat("1", 64) + "'\n")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packbuild.Build(context.Background(), input, output); err == nil {
		t.Fatal("missing import accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed build published output: %v", err)
	}
}

func TestBuildQualifiesLocalProfileArgumentForImportedRoot(t *testing.T) {
	root := t.TempDir()
	seed := filepath.Join(root, "seed.toml")
	seedData := []byte(`schema=3
include=[{profile="choice",arguments={session="fallback"}}]
[profiles.choice]
parameters={session="profile_ref"}
include=[{profile={parameter="session"}}]
[profiles.fallback]
packages=["fallback"]
`)
	if err := os.WriteFile(seed, seedData, 0o600); err != nil {
		t.Fatal(err)
	}
	seedConfig, err := packbuild.Build(context.Background(), seed, filepath.Join(root, "seed-dist"))
	if err != nil {
		t.Fatal(err)
	}
	seedBytes, _ := os.ReadFile(seedConfig)
	seedDocument, err := document.Decode(seedConfig, seedBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := seedDocument.View().Sources[0].Digest
	author := filepath.Join(root, "author")
	store := filepath.Join(author, "packs", "sha256")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	name := digest.String()[len("sha256:"):] + ".pstrap"
	object, _ := os.ReadFile(filepath.Join(root, "seed-dist", "packs", "sha256", name))
	if err := os.WriteFile(filepath.Join(store, name), object, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(author, "proofstrap.toml")
	data := []byte("schema=3\ninclude=[{profile='core:choice',arguments={session='sway'}}]\n[sources]\ncore='" + digest.String() + "'\n[profiles.sway]\npackages=['sway']\n")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := packbuild.Build(context.Background(), input, filepath.Join(root, "dist"))
	if err != nil {
		t.Fatal(err)
	}
	generated, _ := os.ReadFile(config)
	if !bytes.Contains(generated, []byte("local:sway")) {
		t.Fatalf("local profile argument was not qualified:\n%s", generated)
	}
}

func TestBuildPromotesOneDocumentIntoEquivalentWorkspace(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "proofstrap.toml")
	output := filepath.Join(root, "dist")
	data := []byte(`schema = 3
include = [{ profile = "workstation" }]

[profiles.workstation]
packages = ["agent"]

[package.zypper]
agent = ["agent-native"]
`)
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := packbuild.Build(context.Background(), input, output)
	wantConfig := filepath.Join(output, "proofstrap.toml")
	if err != nil || config != wantConfig {
		t.Fatalf("Build = %q, %v; want %q", config, err, wantConfig)
	}
	generated, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	target, err := document.Decode(config, generated)
	if err != nil {
		t.Fatal(err)
	}
	view := target.View()
	if len(view.Sources) != 2 || len(view.Bindings) != 1 || view.Profiles.Present() || view.Mappings.Present() {
		t.Fatalf("generated view = %#v", view)
	}
	roots := make([]pack.Digest, len(view.Sources))
	for index, source := range view.Sources {
		roots[index] = source.Digest
	}
	sources, err := pack.ResolveClosure(context.Background(), roots, nil, func(ctx context.Context, digest pack.Digest) (pack.Source, error) {
		return pack.LoadExact(ctx, []string{filepath.Join(output, "packs")}, digest)
	})
	if err != nil {
		t.Fatal(err)
	}
	semantic, catalogues, err := document.Resolve(context.Background(), target, sources)
	if err != nil {
		t.Fatal(err)
	}
	backend, _ := binding.NewPackageBackendID("zypper")
	projected, err := binding.Project(context.Background(), semantic, binding.Backends{Package: backend}, catalogues)
	if err != nil {
		t.Fatal(err)
	}
	nodes := projected.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("projected nodes = %#v", nodes)
	}
	id, ok := binding.PackageIDOf(nodes[0])
	if !ok || id.Backend() != backend || id.Name() != "agent-native" {
		t.Fatalf("projected package = %#v", nodes[0])
	}
}
