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
	root, err := BindRoot(library, "desktop", map[string]string{"account": "alice", "group": "audio"}, identities)
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
			if root, err := BindRoot(library, "desktop", values, identities); err == nil || root != nil {
				t.Fatalf("BindRoot = %#v, %v", root, err)
			}
		})
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
	library, err := decodeTest([]Member{{
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
	library, err := decodeTest([]Member{{
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
	first, err := decodeTest([]Member{{
		Path: "profiles/first.toml",
		Data: []byte("[profiles.first]\npackages=[\"shared\"]\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := decodeTest([]Member{{
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
	library, err := decodeTest([]Member{{
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
	library, err := decodeTest([]Member{{
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
	library, err := decodeTest([]Member{{
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
