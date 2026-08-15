package pack

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

func semanticSource(t *testing.T, manifest string, members ...archiveMember) Source {
	t.Helper()
	all := append([]archiveMember{{name: "manifest.toml", data: manifest}}, members...)
	source, err := Read(context.Background(), bytes.NewReader(testArchive(t, all...)))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestResolveCatalogueAdmitsBindingRoot(t *testing.T) {
	semantic := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['agent']\n"},
	)
	bindingArchive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='binding'\n[requires]\ncore='" + semantic.Digest().String() + "'\n"},
		archiveMember{name: "bindings/base.toml", data: "[package.zypper]\n'core:agent'=['agent']\n"},
	)
	root, err := Read(context.Background(), bytes.NewReader(bindingArchive))
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := ResolveCatalogue(context.Background(), root, []Source{semantic})
	if err != nil {
		t.Fatal(err)
	}
	backend, _ := binding.NewPackageBackendID("zypper")
	semanticPack, err := Resolve(context.Background(), semantic, nil)
	if err != nil {
		t.Fatal(err)
	}
	profileRoot, _ := profile.NewRoot("base")
	graph, _ := profile.Expand(model.EmptyGraph(), semanticPack.Library(), []profile.Root{profileRoot})
	projected, err := binding.Project(context.Background(), graph, binding.Backends{Package: backend}, []binding.Catalogue{catalogue})
	if err != nil || len(projected.Nodes()) != 1 {
		t.Fatalf("projection = %#v, %v", projected, err)
	}
}

func TestResolveLinksDirectQualifiedReferencesWithoutReexport(t *testing.T) {
	t.Parallel()
	core := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/core.toml", data: "[profiles.base]\npackages=['shared']\n"},
	)
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\ncore='"+core.Digest().String()+"'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\ninclude=[{profile='core:base'}]\npackages=['core:shared']\n"},
	)
	resolved, err := Resolve(context.Background(), root, []Source{core})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(resolved.Library().ProfileIDs(), ","); got != "root" {
		t.Fatalf("root ProfileIDs() = %q, want root", got)
	}
	rootProfile, _ := profile.NewRoot("root")
	graph, err := profile.Expand(model.Graph{}, resolved.Library(), []profile.Root{rootProfile})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 1 || nodes[0].Key().Canonical() != "package:shared" {
		t.Fatalf("expanded nodes = %#v, want one global shared package", nodes)
	}
	if len(nodes[0].Provenance()) != 2 {
		t.Fatalf("global package provenance = %v, want two profile origins", nodes[0].Provenance())
	}
}

func TestResolveDistinguishesReferenceFailures(t *testing.T) {
	t.Parallel()
	core := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/core.toml", data: "[profiles.base.services.agent]\ntarget='system'\nrunning=true\n"},
	)
	for _, test := range []struct {
		name, reference string
		category        Category
	}{
		{name: "missing", reference: "absent", category: MissingReference},
		{name: "wrong-domain", reference: "agent", category: WrongDomain},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\ncore='"+core.Digest().String()+"'\n",
				archiveMember{name: "profiles/root.toml", data: "[profiles.root]\npackages=['core:" + test.reference + "']\n"},
			)
			resolved, err := Resolve(context.Background(), root, []Source{core})
			if resolved != (Pack{}) || errorCategory(t, err) != test.category {
				t.Fatalf("Resolve = %#v, %v; want zero %s", resolved, err, test.category)
			}
		})
	}
}

func TestResolveRejectsUnusedRequirement(t *testing.T) {
	t.Parallel()
	core := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/core.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\ncore='"+core.Digest().String()+"'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\npackages=['local']\n"},
	)
	_, err := Resolve(context.Background(), root, []Source{core})
	if errorCategory(t, err) != UnusedRequirement {
		t.Fatalf("category = %v, want UnusedRequirement", errorCategory(t, err))
	}
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) || diagnostic.Source != root.Digest().String() || diagnostic.Field != "requires.core" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestResolveIsInventoryOrderInvariantAndIgnoresUnreachableSources(t *testing.T) {
	t.Parallel()
	core := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/core.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\ncore='"+core.Digest().String()+"'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\ninclude=[{profile='core:base'}]\n"},
	)
	unreachable := Source{state: &sourceState{digest: Digest{sum: [32]byte{9}}, kind: Binding, compressed: maxClosureBytes + 1}}
	left, err := Resolve(context.Background(), root, []Source{unreachable, core})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Resolve(context.Background(), root, []Source{core, unreachable})
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest() != right.Digest() || strings.Join(left.Library().ProfileIDs(), ",") != strings.Join(right.Library().ProfileIDs(), ",") {
		t.Fatalf("inventory order changed visible Pack")
	}
}

func TestResolveClosureBoundariesAndCancellation(t *testing.T) {
	t.Parallel()
	root := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\npackages=['root']\n"},
	)
	root.state.compressed = maxClosureBytes
	if _, err := Resolve(context.Background(), root, nil); err != nil {
		t.Fatalf("exact byte limit rejected: %v", err)
	}
	root.state.compressed++
	if resolved, err := Resolve(context.Background(), root, nil); resolved != (Pack{}) || errorCategory(t, err) != Limit {
		t.Fatalf("byte overflow = %#v, %v", resolved, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if resolved, err := Resolve(ctx, root, nil); resolved != (Pack{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Resolve = %#v, %v", resolved, err)
	}
}

func TestResolveRejectsRequiredBindingAndRequirementCycle(t *testing.T) {
	t.Parallel()
	bindingArchive := testArchive(t,
		archiveMember{name: "manifest.toml", data: "schema=1\nkind='binding'\n"},
		archiveMember{name: "bindings/base.toml", data: "[package.test]\nbase=['base']\n"},
	)
	binding, err := Read(context.Background(), bytes.NewReader(bindingArchive))
	if err != nil {
		t.Fatal(err)
	}
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\nimpl='"+binding.Digest().String()+"'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\npackages=['impl:base']\n"},
	)
	if resolved, err := Resolve(context.Background(), root, []Source{binding}); resolved != (Pack{}) || errorCategory(t, err) != KindMismatch {
		t.Fatalf("required binding = %#v, %v", resolved, err)
	}

	a := syntheticSource(1)
	b := syntheticSource(2)
	a.state.requirements = map[string]Digest{"b": b.Digest()}
	b.state.requirements = map[string]Digest{"a": a.Digest()}
	if resolved, err := Resolve(context.Background(), a, []Source{b}); resolved != (Pack{}) || errorCategory(t, err) != Cycle {
		t.Fatalf("cycle = %#v, %v", resolved, err)
	}
}

func TestResolveUniqueSourceCountBoundary(t *testing.T) {
	t.Parallel()
	sources := make([]Source, maxClosureSources)
	for index := range sources {
		sources[index] = syntheticSource(byte(index + 1))
		if index > 0 {
			sources[index-1].state.requirements = map[string]Digest{"next": sources[index].Digest()}
			sources[index-1].state.members[0].data = []byte("[profiles.p]\ninclude=[{profile='next:p'}]\n")
		}
	}
	if _, err := Resolve(context.Background(), sources[0], sources[1:]); err != nil {
		t.Fatalf("exact source limit rejected: %v", err)
	}
	overflow := syntheticSource(65)
	sources[len(sources)-1].state.requirements = map[string]Digest{"next": overflow.Digest()}
	sources[len(sources)-1].state.members[0].data = []byte("[profiles.p]\ninclude=[{profile='next:p'}]\n")
	if resolved, err := Resolve(context.Background(), sources[0], append(sources[1:], overflow)); resolved != (Pack{}) || errorCategory(t, err) != Limit {
		t.Fatalf("source overflow = %#v, %v", resolved, err)
	}
}

func TestResolveDoesNotExposeTransitiveHandles(t *testing.T) {
	t.Parallel()
	leaf := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/leaf.toml", data: "[profiles.leaf]\npackages=['leaf']\n"},
	)
	middle := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\nleaf='"+leaf.Digest().String()+"'\n",
		archiveMember{name: "profiles/middle.toml", data: "[profiles.middle]\ninclude=[{profile='leaf:leaf'}]\n"},
	)
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\nmiddle='"+middle.Digest().String()+"'\n",
		archiveMember{name: "profiles/root.toml", data: "[profiles.root]\npackages=['middle:leaf']\n"},
	)
	if resolved, err := Resolve(context.Background(), root, []Source{leaf, middle}); resolved != (Pack{}) || errorCategory(t, err) != MissingReference {
		t.Fatalf("transitive re-export = %#v, %v", resolved, err)
	}
}

func syntheticSource(identity byte) Source {
	var sum [32]byte
	sum[0] = identity
	return Source{state: &sourceState{
		digest: Digest{sum: sum}, kind: Semantic, compressed: 1,
		requirements: map[string]Digest{},
		members:      []contentMember{{path: "profiles/p.toml", data: []byte("[profiles.p]\npackages=['p']\n")}},
	}}
}

func TestResolveAdmitsSemanticRootAtomically(t *testing.T) {
	t.Parallel()
	root := semanticSource(t, "schema=1\nkind='semantic'\n",
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['base']\n"},
	)
	resolved, err := Resolve(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Digest() != root.Digest() {
		t.Fatalf("Digest() = %s, want %s", resolved.Digest(), root.Digest())
	}
	if got := strings.Join(resolved.Library().ProfileIDs(), ","); got != "base" {
		t.Fatalf("ProfileIDs() = %q, want base", got)
	}
}

func TestResolveReportsMissingExactRequirementWithoutPack(t *testing.T) {
	t.Parallel()
	missing := "sha256:" + strings.Repeat("1", 64)
	root := semanticSource(t, "schema=1\nkind='semantic'\n[requires]\ncore='"+missing+"'\n",
		archiveMember{name: "profiles/base.toml", data: "[profiles.base]\npackages=['core:base']\n"},
	)
	resolved, err := Resolve(context.Background(), root, nil)
	if resolved != (Pack{}) {
		t.Fatalf("failed Resolve returned non-zero Pack: %#v", resolved)
	}
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) || diagnostic.Category != MissingRequirement {
		t.Fatalf("error = %v, want MissingRequirement Diagnostic", err)
	}
	if diagnostic.Source != root.Digest().String() || diagnostic.Field != "requires.core" {
		t.Fatalf("diagnostic location = source %q field %q", diagnostic.Source, diagnostic.Field)
	}
}
