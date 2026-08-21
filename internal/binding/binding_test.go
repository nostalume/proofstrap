package binding

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

func TestDecodeAndProjectTypedCatalogue(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{
		Path: "profiles/base.toml",
		Data: []byte("[profiles.base]\npackages=['agent']\n[profiles.base.services.agent]\ntarget='system'\nrunning=true\npackages=['agent']\n"),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := Decode(context.Background(), "binding", []Member{{
		Path: "bindings/base.toml",
		Data: []byte("[package.zypper]\n'core:agent'=['agent-native','agent-tools']\n[service.systemd]\n'core:agent'=['agent.service','agent-helper.service']\n"),
	}}, map[string]profile.Library{"core": library})
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, _ := NewPackageBackendID("zypper")
	serviceBackend, _ := NewServiceBackendID("systemd")
	semantic := semanticGraph(t, library)
	projected, err := Project(context.Background(), semantic, Backends{
		Package: packageBackend, Service: serviceBackend,
	}, []Catalogue{catalogue})
	if err != nil {
		t.Fatal(err)
	}
	nodes := projected.Nodes()
	if len(nodes) != 4 {
		t.Fatalf("projected node count = %d, want 4", len(nodes))
	}
	services := 0
	for _, node := range nodes {
		if _, ok := model.ServiceIDOf(node.Semantic()); ok {
			services++
			if len(node.Dependencies()) != 2 {
				t.Fatalf("projected service dependency count = %d, want Cartesian 2", len(node.Dependencies()))
			}
		}
	}
	if services != 2 {
		t.Fatalf("projected service count = %d, want 2", services)
	}
}

func TestDecodeFactoredClausesMatchExpandedCatalogue(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{
		Path: "profiles/base.toml",
		Data: []byte("[profiles.base]\npackages=['agent','archive']\n[profiles.base.services.daemon]\ntarget='system'\nrunning=true\n"),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]profile.Library{"core": library}
	clause := "[[bind]]\npackage=['apt','zypper']\nfrom='core'\nsame=['agent']\nto={archive=['zip','unzip']}\n" +
		"[[bind]]\nservice=['systemd']\nfrom='core'\nsame=['daemon']\n"
	expanded := "[package.apt]\n'core:agent'=['agent']\n'core:archive'=['zip','unzip']\n" +
		"[package.zypper]\n'core:agent'=['agent']\n'core:archive'=['zip','unzip']\n" +
		"[service.systemd]\n'core:daemon'=['daemon']\n"
	decode := func(body string) Catalogue {
		t.Helper()
		catalogue, err := Decode(context.Background(), "binding", []Member{{Path: "bindings/base.toml", Data: []byte(body)}}, required)
		if err != nil {
			t.Fatal(err)
		}
		return catalogue
	}
	clauseCatalogue, expandedCatalogue := decode(clause), decode(expanded)
	if got, want := clauseCatalogue, expandedCatalogue; !reflect.DeepEqual(got, want) {
		t.Fatalf("clause catalogue = %#v, want %#v", got, want)
	}
	reordered := strings.Replace(clause, "['apt','zypper']", "['zypper','apt']", 1)
	if got, want := decode(reordered), decode(clause); !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered clause catalogue = %#v, want %#v", got, want)
	}
	packageBackend, _ := NewPackageBackendID("apt")
	serviceBackend, _ := NewServiceBackendID("systemd")
	backends := Backends{Package: packageBackend, Service: serviceBackend}
	semantic := semanticGraph(t, library)
	got, gotErr := Project(context.Background(), semantic, backends, []Catalogue{clauseCatalogue})
	want, wantErr := Project(context.Background(), semantic, backends, []Catalogue{expandedCatalogue})
	if gotErr != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("clause projection = %#v, %v; want %#v, %v", got, gotErr, want, wantErr)
	}
}

func TestDecodeRejectsFactoredClauseDefectsAtomically(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(
		"[profiles.base]\npackages=['agent','other']\n[profiles.base.services.daemon]\ntarget='system'\nrunning=true\n")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, body, category string }{
		{"neither-domain", "[[bind]]\nfrom='core'\nsame=['agent']\n", "InvalidValue"},
		{"both-domains", "[[bind]]\npackage=['apt']\nservice=['systemd']\nfrom='core'\nsame=['agent']\n", "InvalidValue"},
		{"empty-backends", "[[bind]]\npackage=[]\nfrom='core'\nsame=['agent']\n", "InvalidValue"},
		{"missing-handle", "[[bind]]\npackage=['apt']\nfrom='missing'\nsame=['agent']\n", "MissingReference"},
		{"missing-symbol", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['absent']\n", "MissingReference"},
		{"invalid-symbol", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['Agent']\n", "MissingReference"},
		{"wrong-domain", "[[bind]]\nservice=['systemd']\nfrom='core'\nsame=['agent']\n", "WrongDomain"},
		{"invalid-backend", "[[bind]]\npackage=['APT']\nfrom='core'\nsame=['agent']\n", "InvalidValue"},
		{"duplicate-backend", "[[bind]]\npackage=['apt','apt']\nfrom='core'\nsame=['agent']\n", "Duplicate"},
		{"empty-mapping", "[[bind]]\npackage=['apt']\nfrom='core'\n", "InvalidValue"},
		{"duplicate-same", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent','agent']\n", "Duplicate"},
		{"overlap", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\nto={agent=['native']}\n", "Duplicate"},
		{"empty-output", "[[bind]]\npackage=['apt']\nfrom='core'\nto={agent=[]}\n", "InvalidValue"},
		{"clause-duplicate", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\n[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\n", "Duplicate"},
		{"legacy-duplicate", "[package.apt]\n'core:agent'=['agent']\n[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\n", "Duplicate"},
		{"native-collision", "[[bind]]\npackage=['apt']\nfrom='core'\nto={agent=['native'],other=['native']}\n", "Conflict"},
		{"unknown-field", "[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\nfallback=true\n", "Syntax"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalogue, err := Decode(context.Background(), "binding", []Member{{Path: "bindings/base.toml", Data: []byte(test.body)}}, map[string]profile.Library{"core": library})
			var diagnostic *Diagnostic
			if catalogue != (Catalogue{}) || !errors.As(err, &diagnostic) || diagnostic.Category != test.category {
				t.Fatalf("Decode = %#v, %v; want zero %s", catalogue, err, test.category)
			}
		})
	}
	legacy := []byte("[package.apt]\n'core:agent'=['agent']\n")
	members := []Member{{Path: "bindings/a.toml", Data: legacy}, {Path: "bindings/b.toml", Data: legacy}}
	if _, err := Decode(context.Background(), "binding", members, map[string]profile.Library{"core": library}); err != nil {
		t.Fatalf("legacy duplicate compatibility: %v", err)
	}
	members[0].Data = []byte("[[bind]]\npackage=['apt']\nfrom='core'\nsame=['agent']\n")
	if catalogue, err := Decode(context.Background(), "binding", members, map[string]profile.Library{"core": library}); catalogue != (Catalogue{}) || diagnosticCategory(err) != "Duplicate" {
		t.Fatalf("clause-first legacy duplicate = %#v, %v", catalogue, err)
	}
}

func TestFactoredClauseExpandedKeyLimitAndCancellation(t *testing.T) {
	var semanticBody strings.Builder
	semanticBody.WriteString("[profiles.base]\npackages=[")
	same := make([]string, 1024)
	for index := range same {
		same[index] = fmt.Sprintf("p%d", index)
		fmt.Fprintf(&semanticBody, "'%s',", same[index])
	}
	semanticBody.WriteString("]\n")
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(semanticBody.String())}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bindingBody strings.Builder
	bindingBody.WriteString("[[bind]]\npackage=['b0','b1','b2','b3','b4','b5','b6','b7']\nfrom='core'\nsame=[")
	for index, symbol := range same {
		if index > 0 {
			bindingBody.WriteByte(',')
		}
		fmt.Fprintf(&bindingBody, "'%s'", symbol)
	}
	bindingBody.WriteString("]\n")
	members := []Member{{Path: "bindings/base.toml", Data: []byte(bindingBody.String())}}
	required := map[string]profile.Library{"core": library}
	if _, err := Decode(context.Background(), "binding", members, required); err != nil {
		t.Fatalf("exact expanded key maximum rejected: %v", err)
	}
	members[0].Data = append(members[0].Data, []byte("[[bind]]\npackage=['overflow']\nfrom='core'\nsame=['p0']\n")...)
	if catalogue, err := Decode(context.Background(), "binding", members, required); catalogue != (Catalogue{}) || diagnosticCategory(err) != "Limit" {
		t.Fatalf("expanded maximum plus one = %#v, %v", catalogue, err)
	}
	if catalogue, err := Decode(&countingContext{remaining: 5}, "binding", members[:1], required); catalogue != (Catalogue{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-clause cancellation = %#v, %v", catalogue, err)
	}
}

func diagnosticCategory(err error) string {
	var diagnostic *Diagnostic
	if errors.As(err, &diagnostic) {
		return diagnostic.Category
	}
	return ""
}

func TestBackendAndNativeIdentityBoundaries(t *testing.T) {
	valid63 := "a" + strings.Repeat("1", 62)
	for _, value := range []string{"a", "a-1", valid63} {
		if _, err := NewPackageBackendID(value); err != nil {
			t.Fatalf("valid package backend %q rejected: %v", value, err)
		}
		if _, err := NewServiceBackendID(value); err != nil {
			t.Fatalf("valid service backend %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "A", "a-", "a--b", valid63 + "1"} {
		if _, err := NewPackageBackendID(value); err == nil {
			t.Fatalf("invalid backend %q admitted", value)
		}
	}
	if !validNativeName(strings.Repeat("x", 255)) || validNativeName(strings.Repeat("x", 256)) || validNativeName(string([]byte{0xff})) {
		t.Fatal("native identity boundary is not exact")
	}
}

func TestDecodeRejectsReferenceAndCollisionDefectsAtomically(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(
		"[profiles.base]\npackages=['agent','other']\n[profiles.base.services.daemon]\ntarget='system'\nrunning=true\n")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, body, category string
	}{
		{"unqualified", "[package.test]\nagent=['native']\n", "InvalidValue"},
		{"missing-handle", "[package.test]\n'other:agent'=['native']\n", "MissingReference"},
		{"wrong-domain", "[package.test]\n'core:daemon'=['native']\n", "WrongDomain"},
		{"duplicate-output", "[package.test]\n'core:agent'=['native','native']\n", "InvalidValue"},
		{"native-collision", "[package.test]\n'core:agent'=['native']\n'core:other'=['native']\n", "Conflict"},
		{"unused-handle", "[package.test]\n'core:agent'=['native']\n", "UnusedRequirement"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required := map[string]profile.Library{"core": library}
			if test.name == "unused-handle" {
				required["unused"] = library
			}
			catalogue, err := Decode(context.Background(), "binding", []Member{{Path: "bindings/base.toml", Data: []byte(test.body)}}, required)
			var diagnostic *Diagnostic
			if catalogue != (Catalogue{}) || !errors.As(err, &diagnostic) || diagnostic.Category != test.category {
				t.Fatalf("Decode = %#v, %v; want zero %s", catalogue, err, test.category)
			}
		})
	}
}

func TestDecodeClosedShapeRejectsNestedOutputAsSyntax(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(
		"[profiles.base]\npackages=['agent']\n")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := Decode(context.Background(), "binding", []Member{{
		Path: "bindings/nested.toml", Data: []byte("[package.test]\n'core:agent'={nested=['native']}\n"),
	}}, map[string]profile.Library{"core": library})
	var diagnostic *Diagnostic
	if catalogue != (Catalogue{}) || !errors.As(err, &diagnostic) || diagnostic.Category != "Syntax" {
		t.Fatalf("closed-shape decode = %#v, %v; want zero Syntax", catalogue, err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("[package.zypper]\n'core:agent'=['agent-native']\n"))
	f.Add([]byte("[service.systemd]\n'core:daemon'=['agent.service']\n"))
	f.Add([]byte("[[bind]]\npackage=['zypper']\nfrom='core'\nsame=['agent']\n"))
	f.Add([]byte{0xff, 0xfe})
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(
		"[profiles.base]\npackages=['agent']\n[profiles.base.services.daemon]\ntarget='system'\nrunning=true\n")}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMemberBytes+1 {
			data = data[:maxMemberBytes+1]
		}
		catalogue, err := Decode(context.Background(), "binding", []Member{{Path: "bindings/fuzz.toml", Data: data}}, map[string]profile.Library{"core": library})
		if err != nil && catalogue != (Catalogue{}) {
			t.Fatalf("Decode returned partial Catalogue with %v", err)
		}
		if err == nil {
			_, _ = Project(context.Background(), model.EmptyGraph(), Backends{}, []Catalogue{catalogue})
		}
	})
}

func TestProjectConflictPrecedesUnsupportedAndUnusedMappingsAreInert(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(
		"[profiles.base]\npackages=['wanted']\n[profiles.spare]\npackages=['unused-a','unused-b']\n")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	backend, _ := NewPackageBackendID("test")
	wanted := mappingKey{domain: Package, backend: "test", semantic: "wanted"}
	left := Catalogue{state: &catalogueState{mappings: map[mappingKey]mapping{
		wanted: {outputs: []string{"one"}, sources: []string{"left"}},
		{domain: Package, backend: "test", semantic: "unused-a"}: {outputs: []string{"collision"}, sources: []string{"left"}},
	}}}
	right := Catalogue{state: &catalogueState{mappings: map[mappingKey]mapping{
		wanted: {outputs: []string{"two"}, sources: []string{"right"}},
		{domain: Package, backend: "test", semantic: "unused-b"}: {outputs: []string{"collision"}, sources: []string{"right"}},
	}}}
	graph, err := Project(context.Background(), semanticGraph(t, library), Backends{Package: backend}, []Catalogue{right, left})
	var blocked *Blocked
	if graph != (Graph{}) || !errors.As(err, &blocked) {
		t.Fatalf("Project = %#v, %v; want atomic Blocked", graph, err)
	}
	blockers := blocked.Blockers()
	if len(blockers) != 1 || blockers[0].Kind != Conflict || blockers[0].Semantic != "wanted" {
		t.Fatalf("blockers = %#v, want only wanted Conflict", blockers)
	}
	blockers[0].Sources[0] = "mutated"
	if blocked.Blockers()[0].Sources[0] == "mutated" {
		t.Fatal("Blocked exposed mutable provenance")
	}
}

type countingContext struct{ remaining int }

func (c *countingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *countingContext) Done() <-chan struct{}       { return nil }
func (c *countingContext) Value(any) any               { return nil }
func (c *countingContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestCancellationAndCheckedEdgeArithmetic(t *testing.T) {
	if got, ok := addProduct(maxProjectedEdges, 1, 1, maxProjectedEdges); ok || got != maxProjectedEdges+1 {
		t.Fatalf("overflow result = %d, %v", got, ok)
	}
	if got, ok := addProduct(maxProjectedEdges-1, 1, 1, maxProjectedEdges); !ok || got != maxProjectedEdges {
		t.Fatalf("exact result = %d, %v", got, ok)
	}
	ctx := &countingContext{remaining: 3}
	graph, err := Project(ctx, model.EmptyGraph(), Backends{}, []Catalogue{{state: &catalogueState{mappings: map[mappingKey]mapping{}}}})
	if graph != (Graph{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-projection cancellation = %#v, %v", graph, err)
	}
	if _, ok := err.(*Canceled); !ok {
		t.Fatalf("cancellation type = %T", err)
	}
}

func TestOutputSetBoundaries(t *testing.T) {
	values := make([]string, maxNativeOutputs)
	for index := range values {
		values[index] = "native-" + strings.Repeat("x", index+1)
	}
	if _, err := admitOutputs(values); err != nil {
		t.Fatalf("exact output maximum rejected: %v", err)
	}
	if _, err := admitOutputs(append(values, "overflow")); err == nil {
		t.Fatal("output maximum plus one admitted")
	}
}

func TestCatalogueKeyBoundary(t *testing.T) {
	var semanticBody strings.Builder
	semanticBody.WriteString("[profiles.base]\npackages=[")
	for index := 0; index < 1024; index++ {
		if index > 0 {
			semanticBody.WriteByte(',')
		}
		fmt.Fprintf(&semanticBody, "'p%d'", index)
	}
	semanticBody.WriteString("]\n")
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte(semanticBody.String())}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bindingBody strings.Builder
	for backend := 0; backend < 8; backend++ {
		fmt.Fprintf(&bindingBody, "[package.b%d]\n", backend)
		for index := 0; index < 1024; index++ {
			fmt.Fprintf(&bindingBody, "'core:p%d'=['n%d-%d']\n", index, backend, index)
		}
	}
	members := []Member{{Path: "bindings/base.toml", Data: []byte(bindingBody.String())}}
	if _, err := Decode(context.Background(), "binding", members, map[string]profile.Library{"core": library}); err != nil {
		t.Fatalf("exact catalogue-key maximum rejected: %v", err)
	}
	bindingBody.WriteString("[package.overflow]\n'core:p0'=['overflow']\n")
	members[0].Data = []byte(bindingBody.String())
	catalogue, err := Decode(context.Background(), "binding", members, map[string]profile.Library{"core": library})
	var diagnostic *Diagnostic
	if catalogue != (Catalogue{}) || !errors.As(err, &diagnostic) || diagnostic.Category != "Limit" {
		t.Fatalf("catalogue maximum plus one = %#v, %v", catalogue, err)
	}
}

func TestProjectionNodeAndProvenanceBoundaries(t *testing.T) {
	semantic, packageIDs := packageGraph(t, 1024)
	backend, _ := NewPackageBackendID("test")
	mappings := make(map[mappingKey]mapping, len(packageIDs))
	for _, id := range packageIDs {
		outputs := make([]string, maxNativeOutputs)
		for output := range outputs {
			outputs[output] = fmt.Sprintf("%s-n%d", id, output)
		}
		mappings[mappingKey{domain: Package, backend: "test", semantic: id}] = mapping{
			outputs: outputs,
			sources: []string{"b1", "b2", "b3", "b4", "b5", "b6", "b7"},
		}
	}
	catalogue := Catalogue{state: &catalogueState{mappings: mappings}}
	projected, err := Project(context.Background(), semantic, Backends{Package: backend}, []Catalogue{catalogue})
	if err != nil || len(projected.Nodes()) != maxProjectedNodes {
		t.Fatalf("exact node/provenance maximum = %d nodes, %v", len(projected.Nodes()), err)
	}
	first := mappingKey{domain: Package, backend: "test", semantic: packageIDs[0]}
	value := mappings[first]
	value.sources = append(value.sources, "overflow")
	mappings[first] = value
	if graph, err := Project(context.Background(), semantic, Backends{Package: backend}, []Catalogue{catalogue}); graph != (Graph{}) || blockerKind(t, err) != Limit {
		t.Fatalf("provenance maximum plus one = %#v, %v", graph, err)
	}
	value.sources = value.sources[:7]
	mappings[first] = value
	hostname, _ := model.NewHostname("extra")
	source, _ := model.NewProvenance("extra")
	contribution, _ := model.Contribute(hostname, source)
	semantic, err = semantic.Add([]model.Contribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	if graph, err := Project(context.Background(), semantic, Backends{Package: backend}, []Catalogue{catalogue}); graph != (Graph{}) || blockerKind(t, err) != Limit {
		t.Fatalf("node maximum plus one = %#v, %v", graph, err)
	}
}

func TestProjectionEdgeBoundary(t *testing.T) {
	const packages = maxProjectedEdges / maxNativeOutputs
	semantic, packageIDs := packageGraph(t, packages)
	packageKeys := make([]model.PackageKey, 0, len(packageIDs))
	for _, name := range packageIDs {
		id, _ := model.NewPackageID(name)
		key, _ := model.NewPackageKey(id)
		packageKeys = append(packageKeys, key)
	}
	serviceID, _ := model.NewServiceID("daemon")
	service, _ := model.NewService(serviceID, model.SystemServiceTarget(), model.UnmanagedEnableIntent(), model.RunningIntent(), packageKeys)
	source, _ := model.NewProvenance("service")
	contribution, _ := model.Contribute(service, source)
	semantic, err := semantic.Add([]model.Contribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	packageBackend, _ := NewPackageBackendID("test")
	serviceBackend, _ := NewServiceBackendID("test")
	mappings := make(map[mappingKey]mapping, len(packageIDs)+1)
	for _, name := range packageIDs {
		mappings[mappingKey{domain: Package, backend: "test", semantic: name}] = mapping{outputs: []string{name}, sources: []string{"binding"}}
	}
	serviceOutputs := make([]string, maxNativeOutputs)
	for index := range serviceOutputs {
		serviceOutputs[index] = fmt.Sprintf("daemon-%d", index)
	}
	mappings[mappingKey{domain: Service, backend: "test", semantic: "daemon"}] = mapping{outputs: serviceOutputs, sources: []string{"binding"}}
	catalogue := Catalogue{state: &catalogueState{mappings: mappings}}
	backends := Backends{Package: packageBackend, Service: serviceBackend}
	if _, err := Project(context.Background(), semantic, backends, []Catalogue{catalogue}); err != nil {
		t.Fatalf("exact edge maximum rejected: %v", err)
	}
	extraID, _ := model.NewPackageID("overflow")
	extraKey, _ := model.NewPackageKey(extraID)
	extra, _ := model.NewPackage(extraID)
	extraContribution, _ := model.Contribute(extra, source)
	semantic, _ = semantic.Add([]model.Contribution{extraContribution})
	packageKeys = append(packageKeys, extraKey)
	service, _ = model.NewService(serviceID, model.SystemServiceTarget(), model.UnmanagedEnableIntent(), model.RunningIntent(), packageKeys)
	contribution, _ = model.Contribute(service, source)
	withoutService, _ := packageGraphFromNames(t, append(packageIDs, "overflow"))
	semantic, _ = withoutService.Add([]model.Contribution{contribution})
	mappings[mappingKey{domain: Package, backend: "test", semantic: "overflow"}] = mapping{outputs: []string{"overflow"}, sources: []string{"binding"}}
	if graph, err := Project(context.Background(), semantic, backends, []Catalogue{catalogue}); graph != (Graph{}) || blockerKind(t, err) != Limit {
		t.Fatalf("edge maximum plus one = %#v, %v", graph, err)
	}
}

func packageGraph(t *testing.T, count int) (model.Graph, []string) {
	t.Helper()
	names := make([]string, count)
	for index := range names {
		names[index] = fmt.Sprintf("p%d", index)
	}
	graph, err := packageGraphFromNames(t, names)
	if err != nil {
		t.Fatal(err)
	}
	return graph, names
}

func packageGraphFromNames(t *testing.T, names []string) (model.Graph, error) {
	t.Helper()
	source, _ := model.NewProvenance("semantic")
	contributions := make([]model.Contribution, 0, len(names))
	for _, name := range names {
		id, _ := model.NewPackageID(name)
		resource, _ := model.NewPackage(id)
		contribution, _ := model.Contribute(resource, source)
		contributions = append(contributions, contribution)
	}
	return model.EmptyGraph().Add(contributions)
}

func blockerKind(t *testing.T, err error) BlockerKind {
	t.Helper()
	var blocked *Blocked
	if !errors.As(err, &blocked) || len(blocked.Blockers()) == 0 {
		t.Fatalf("error = %v, want Blocked", err)
	}
	return blocked.Blockers()[0].Kind
}

func semanticGraph(t *testing.T, library profile.Library) model.Graph {
	t.Helper()
	root, _ := profile.NewRoot("base")
	graph, err := profile.Expand(model.EmptyGraph(), library, []profile.Root{root})
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func TestProjectReturnsCompleteUnsupportedBlockersAtomically(t *testing.T) {
	library, err := profile.Decode("semantic", []profile.Member{{
		Path: "profiles/base.toml",
		Data: []byte("[profiles.base]\npackages=['one','two']\n"),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := Project(context.Background(), semanticGraph(t, library), Backends{}, nil)
	if projected != (Graph{}) {
		t.Fatalf("blocked projection returned non-zero Graph: %#v", projected)
	}
	blocked, ok := err.(*Blocked)
	if !ok || len(blocked.Blockers()) != 2 {
		t.Fatalf("error = %#v, want two blockers", err)
	}
}
