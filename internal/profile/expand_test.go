package profile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

func TestExpandBindsIncludesAndEmitsDeterministicGraph(t *testing.T) {
	t.Parallel()
	library := decodeComplete(t)
	base, account, group := identityBase(t, "alice", "audio")
	root := rootFor(t, "desktop",
		accountArgument(t, "account", account),
		groupArgument(t, "group", group),
	)
	graph, err := Expand(base, library, []Root{root})
	if err != nil {
		t.Fatal(err)
	}
	got := graphKeys(graph)
	want := []string{
		"account-lock:alice",
		"account:alice",
		"group:audio",
		"home-mode:alice",
		"home:alice",
		"hostname",
		"membership:alice:audio",
		"package:network-manager",
		"package:pipewire",
		"service:network-manager:system",
		"service:pipewire:user:alice",
		"timezone",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for _, node := range graph.Nodes() {
		if node.Key().Canonical() == "service:network-manager:system" {
			dependencies := node.Dependencies()
			if len(dependencies) != 1 || dependencies[0].Canonical() != "package:network-manager" {
				t.Fatalf("service dependencies = %v", dependencies)
			}
		}
	}
}

func TestBindRootDerivesScalarKindsFromExactLibrary(t *testing.T) {
	library := decodeComplete(t)
	base, account, group := identityBase(t, "alice", "audio")
	identities := map[string]model.Key{account.Canonical(): account, group.Canonical(): group}
	root, err := BindRoot(library, "desktop", map[string]string{"account": "alice", "group": "audio"}, identities, nil)
	if err != nil {
		t.Fatal(err)
	}
	if graph, err := Expand(base, library, []Root{root}); err != nil || len(graph.Nodes()) == 0 {
		t.Fatalf("Expand = %#v, %v", graph, err)
	}
	for name, values := range map[string]map[string]string{
		"missing":    {"account": "missing", "group": "audio"},
		"incomplete": {"account": "alice"},
	} {
		t.Run(name, func(t *testing.T) {
			if root, err := BindRoot(library, "desktop", values, identities, nil); err == nil || root != nil {
				t.Fatalf("BindRoot = %#v, %v", root, err)
			}
		})
	}
}

func TestExpandSelectsExactProfileFromProfileReference(t *testing.T) {
	caller, err := admitInputs("caller", []Member{{Path: "profiles/caller.toml", Data: []byte(`[profiles.workstation]
parameters = { desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := admitInputs("selected", []Member{{Path: "profiles/selected.toml", Data: []byte(`[profiles.sway]
packages = ["sway"]
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, definition := range selected.profiles {
		caller.profiles[key] = definition
	}
	root := root{profile: "workstation", arguments: map[string]reference{
		"desktop": {profile: selected.localProfiles["sway"], kind: profileReference},
	}}
	graph, err := Expand(model.EmptyGraph(), caller, []Root{root})
	if err != nil {
		t.Fatal(err)
	}
	if got := graphKeys(graph); !reflect.DeepEqual(got, []string{"package:sway"}) {
		t.Fatalf("keys = %v", got)
	}
}

func TestBindRootResolvesProfileReferenceWithoutAliasLeakage(t *testing.T) {
	caller, err := admitInputs("caller", []Member{{Path: "profiles/caller.toml", Data: []byte(`[profiles.workstation]
parameters = { desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := admitInputs("selected", []Member{{Path: "profiles/selected.toml", Data: []byte(`[profiles.sway]
packages = ["sway"]
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := BindRoot(caller, "workstation", map[string]string{"desktop": "extra:sway"}, nil,
		func(value string) (Library, string, error) { return selected, "sway", nil })
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Expand(model.EmptyGraph(), caller, []Root{root})
	if err != nil || !reflect.DeepEqual(graphKeys(graph), []string{"package:sway"}) {
		t.Fatalf("Expand = %v, %v", graphKeys(graph), err)
	}
}

func TestExpandChecksDynamicSignatureAndCycleAtomically(t *testing.T) {
	selected, err := admitInputs("selected", []Member{{Path: "profiles/selected.toml", Data: []byte(`[profiles.home]
parameters = { account = "account_ref" }
homes = [{ account = { parameter = "account" } }]
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := admitInputs("caller", []Member{{Path: "profiles/caller.toml", Data: []byte(`[profiles.good]
parameters = { account = "account_ref", choice = "profile_ref" }
[[profiles.good.include]]
profile = { parameter = "choice" }
[profiles.good.include.arguments]
account = { parameter = "account" }

[profiles.bad]
parameters = { choice = "profile_ref" }
[[profiles.bad.include]]
profile = { parameter = "choice" }
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, account, _ := identityBase(t, "alice", "users")
	for key, definition := range selected.profiles {
		caller.profiles[key] = definition
	}
	choice := reference{profile: selected.localProfiles["home"], kind: profileReference}
	good := root{profile: "good", arguments: map[string]reference{
		"account": {literal: account, kind: accountReference}, "choice": choice,
	}}
	if graph, err := Expand(base, caller, []Root{good}); err != nil || !contains(graphKeys(graph), "home:alice") {
		t.Fatalf("good expansion = %v, %v", graphKeys(graph), err)
	}
	bad := root{profile: "bad", arguments: map[string]reference{"choice": choice}}
	if graph, err := Expand(base, caller, []Root{bad}); err == nil || !reflect.DeepEqual(graphProjection(graph), graphProjection(base)) {
		t.Fatalf("signature failure = %#v, %v", graph, err)
	}

	cycle, err := admitInputs("cycle", []Member{{Path: "profiles/cycle.toml", Data: []byte(`[profiles.loop]
parameters = { next = "profile_ref" }
[[profiles.loop.include]]
profile = { parameter = "next" }
[profiles.loop.include.arguments]
next = { parameter = "next" }
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	loop := cycle.localProfiles["loop"]
	cyclicRoot := root{profile: "loop", arguments: map[string]reference{"next": {profile: loop, kind: profileReference}}}
	if graph, err := Expand(base, cycle, []Root{cyclicRoot}); err == nil || !reflect.DeepEqual(graphProjection(graph), graphProjection(base)) {
		t.Fatalf("cycle failure = %#v, %v", graph, err)
	}
	multi, err := admitInputs("multi", []Member{{Path: "profiles/multi.toml", Data: []byte(`[profiles.left]
parameters = { left = "profile_ref", right = "profile_ref" }
[[profiles.left.include]]
profile = { parameter = "right" }
[profiles.left.include.arguments]
left = { parameter = "left" }
right = { parameter = "right" }
[profiles.right]
parameters = { left = "profile_ref", right = "profile_ref" }
[[profiles.right.include]]
profile = { parameter = "left" }
[profiles.right.include.arguments]
left = { parameter = "left" }
right = { parameter = "right" }
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	left, right := multi.localProfiles["left"], multi.localProfiles["right"]
	multiRoot := root{profile: "left", arguments: map[string]reference{
		"left": {profile: left, kind: profileReference}, "right": {profile: right, kind: profileReference},
	}}
	if graph, err := Expand(base, multi, []Root{multiRoot}); err == nil || !reflect.DeepEqual(graphProjection(graph), graphProjection(base)) {
		t.Fatalf("multi-cycle failure = %#v, %v", graph, err)
	}
}

func TestExpandDeduplicatesInstancesAndUnionsProvenance(t *testing.T) {
	t.Parallel()
	library := decodeComplete(t)
	base, account, group := identityBase(t, "alice", "audio")
	root := rootFor(t, "desktop", accountArgument(t, "account", account), groupArgument(t, "group", group))
	one, err := Expand(base, library, []Root{root})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Expand(base, library, []Root{root, root})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(graphProjection(one), graphProjection(two)) {
		t.Fatal("duplicate root changed graph")
	}
}

func TestExpandDistinctBindingsAndRootOrderAreDeterministic(t *testing.T) {
	t.Parallel()
	library := decodeComplete(t)
	base, alice, audio := identityBase(t, "alice", "audio")
	bob, _ := model.NewAccountKey("bob")
	bobResource, _ := model.NewExternalAccount(bob)
	base = addResource(t, base, bobResource, "config:bob")
	aliceRoot := rootFor(t, "desktop", accountArgument(t, "account", alice), groupArgument(t, "group", audio))
	bobRoot := rootFor(t, "desktop", accountArgument(t, "account", bob), groupArgument(t, "group", audio))
	left, err := Expand(base, library, []Root{aliceRoot, bobRoot})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Expand(base, library, []Root{bobRoot, aliceRoot})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(graphProjection(left), graphProjection(right)) {
		t.Fatal("root order changed graph")
	}
	keys := graphKeys(left)
	if !contains(keys, "service:pipewire:user:alice") ||
		!contains(keys, "service:pipewire:user:bob") {
		t.Fatalf("distinct bindings missing: %v", keys)
	}
}

func TestExpandRejectsRootMismatchAndMissingIdentityAtomically(t *testing.T) {
	t.Parallel()
	library := decodeComplete(t)
	base := model.EmptyGraph()
	account, _ := model.NewAccountKey("alice")
	group, _ := model.NewGroupKey("audio")
	cases := []Root{
		rootFor(t, "missing"),
		rootFor(t, "desktop", accountArgument(t, "account", account)),
		rootFor(t, "desktop", accountArgument(t, "account", account), groupArgument(t, "group", group)),
	}
	for _, root := range cases {
		graph, err := Expand(base, library, []Root{root})
		if err == nil {
			t.Fatal("invalid expansion admitted")
		}
		if len(graph.Nodes()) != 0 || len(base.Nodes()) != 0 {
			t.Fatal("failed expansion mutated graph")
		}
	}
}

func TestExpandLimitsAreAtomicAtPlusOne(t *testing.T) {
	t.Parallel()
	library, err := admitTest([]Member{{
		Path: "profiles/limit.toml",
		Data: []byte("[profiles.a]\npackages=[\"a\",\"b\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	root := rootFor(t, "a")
	if _, err := expandWithLimits(model.EmptyGraph(), library, []Root{root}, expansionLimits{
		instances: 1, nodes: 2, edges: 0, provenance: 2,
	}); err != nil {
		t.Fatalf("exact limits rejected: %v", err)
	}
	graph, err := expandWithLimits(model.EmptyGraph(), library, []Root{root}, expansionLimits{
		instances: 1, nodes: 1, edges: 0, provenance: 2,
	})
	if err == nil || len(graph.Nodes()) != 0 {
		t.Fatalf("limit plus one was not atomic: graph=%v err=%v", graphKeys(graph), err)
	}
}

func TestExpandUnifiesProvenanceAcrossDistinctProfiles(t *testing.T) {
	t.Parallel()
	library, err := admitTest([]Member{{
		Path: "profiles/shared.toml",
		Data: []byte("[profiles.a]\npackages=[\"shared\"]\n[profiles.b]\npackages=[\"shared\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Expand(model.EmptyGraph(), library, []Root{rootFor(t, "b"), rootFor(t, "a")})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 1 || len(nodes[0].Provenance()) != 2 {
		t.Fatalf("shared resource did not union provenance: %v", graphProjection(graph))
	}
}

func TestExpandUnifiesTypedResourcesAcrossIndependentLibraries(t *testing.T) {
	t.Parallel()
	first, err := admitTest([]Member{{
		Path: "profiles/first.toml",
		Data: []byte("[profiles.first]\npackages=[\"shared\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := admitTest([]Member{{
		Path: "profiles/second.toml",
		Data: []byte("[profiles.second]\npackages=[\"shared\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Expand(model.EmptyGraph(), first, []Root{rootFor(t, "first")})
	if err != nil {
		t.Fatal(err)
	}
	graph, err = Expand(graph, second, []Root{rootFor(t, "second")})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 1 || nodes[0].Key().Canonical() != "package:shared" {
		t.Fatalf("independent libraries did not unify: %v", graphProjection(graph))
	}
	if got := nodes[0].Provenance(); !reflect.DeepEqual(got, []string{"profile:test-origin#first|", "profile:test-origin#second|"}) {
		t.Fatalf("provenance = %v", got)
	}
}

func TestExpandConflictIsAtomic(t *testing.T) {
	t.Parallel()
	library, err := admitTest([]Member{{
		Path: "profiles/conflict.toml",
		Data: []byte("[profiles.a]\nhostname=\"one\"\n[profiles.b]\nhostname=\"two\"\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := model.EmptyGraph()
	graph, err := Expand(base, library, []Root{rootFor(t, "a"), rootFor(t, "b")})
	if err == nil || len(graph.Nodes()) != 0 || len(base.Nodes()) != 0 {
		t.Fatalf("conflict was not atomic: graph=%v err=%v", graphKeys(graph), err)
	}
}

func TestExpandEachBudgetAxis(t *testing.T) {
	t.Parallel()
	library, err := admitTest([]Member{{
		Path: "profiles/budgets.toml",
		Data: []byte("[profiles.a]\npackages=[\"p\"]\n[profiles.a.services.s]\ntarget=\"system\"\npackages=[\"p\"]\nrunning=true\n[profiles.b]\npackages=[\"q\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	roots := []Root{rootFor(t, "a"), rootFor(t, "b")}
	cases := []expansionLimits{
		{instances: 1, nodes: 10, edges: 10, provenance: 10},
		{instances: 10, nodes: 2, edges: 10, provenance: 10},
		{instances: 10, nodes: 10, edges: 0, provenance: 10},
		{instances: 10, nodes: 10, edges: 10, provenance: 2},
	}
	for _, limits := range cases {
		graph, err := expandWithLimits(model.EmptyGraph(), library, roots, limits)
		if err == nil || len(graph.Nodes()) != 0 {
			t.Fatalf("budget failure not atomic: limits=%+v graph=%v err=%v", limits, graphKeys(graph), err)
		}
	}
}

func decodeComplete(t *testing.T) Library {
	t.Helper()
	library, err := admitTest([]Member{{
		Path: "profiles/complete.toml",
		Data: readFixture(t, "valid", "complete.toml"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return library
}

func rootFor(t *testing.T, profile string, arguments ...Argument) Root {
	t.Helper()
	root, err := NewRoot(profile, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func accountArgument(t *testing.T, name string, key model.AccountKey) Argument {
	t.Helper()
	argument, err := NewAccountArgument(name, key)
	if err != nil {
		t.Fatal(err)
	}
	return argument
}

func groupArgument(t *testing.T, name string, key model.GroupKey) Argument {
	t.Helper()
	argument, err := NewGroupArgument(name, key)
	if err != nil {
		t.Fatal(err)
	}
	return argument
}

func identityBase(t *testing.T, accountName, groupName string) (model.Graph, model.AccountKey, model.GroupKey) {
	t.Helper()
	account, _ := model.NewAccountKey(accountName)
	group, _ := model.NewGroupKey(groupName)
	accountResource, _ := model.NewExternalAccount(account)
	groupResource, _ := model.NewExternalGroup(group)
	graph := addResource(t, model.EmptyGraph(), groupResource, "config:group")
	graph = addResource(t, graph, accountResource, "config:account")
	return graph, account, group
}

func addResource(t *testing.T, graph model.Graph, resource model.Resource, source string) model.Graph {
	t.Helper()
	provenance, _ := model.NewProvenance(source)
	contribution, _ := model.Contribute(resource, provenance)
	next, err := graph.Add([]model.Contribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func graphKeys(graph model.Graph) []string {
	nodes := graph.Nodes()
	keys := make([]string, len(nodes))
	for index, node := range nodes {
		keys[index] = node.Key().Canonical()
	}
	return keys
}

func graphProjection(graph model.Graph) []string {
	var projection []string
	for _, node := range graph.Nodes() {
		projection = append(projection, node.Key().Canonical()+"|"+strings.Join(node.Provenance(), ","))
	}
	return projection
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
