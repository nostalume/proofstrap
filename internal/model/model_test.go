package model_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

func mustAccount(t *testing.T, name string) model.AccountKey {
	t.Helper()
	key, err := model.NewAccountKey(name)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGroup(t *testing.T, name string) model.GroupKey {
	t.Helper()
	key, err := model.NewGroupKey(name)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustPackageKey(t *testing.T, id model.PackageID) model.PackageKey {
	t.Helper()
	key, err := model.NewPackageKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func provenance(t *testing.T, source string) model.Provenance {
	t.Helper()
	p, err := model.NewProvenance(source)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func contribution(t *testing.T, resource model.Resource, source string) model.Contribution {
	t.Helper()
	value, err := model.Contribute(resource, provenance(t, source))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestConstructorsRejectInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := model.NewPackageID(""); err == nil {
		t.Fatal("empty package ID admitted")
	}
	if _, err := model.NewAccountKey("bad:name"); err == nil {
		t.Fatal("invalid account admitted")
	}
	if _, err := model.NewGroupKey(""); err == nil {
		t.Fatal("empty group admitted")
	}

	account := mustAccount(t, "alice")
	group := mustGroup(t, "users")
	if _, err := model.NewManagedAccount(account, 1000, group, "relative"); err == nil {
		t.Fatal("relative account home admitted")
	}
	if _, err := model.NewHomeMode(account, 0o1000); err == nil {
		t.Fatal("out-of-range mode admitted")
	}
	if _, err := model.NewAccountShell(account, "bash"); err == nil {
		t.Fatal("relative shell admitted")
	}
	if _, err := model.NewHostname("Bad_Host"); err == nil {
		t.Fatal("invalid hostname admitted")
	}
	if _, err := model.NewHostname("good.-bad"); err == nil {
		t.Fatal("hostname with noncanonical label admitted")
	}
	if _, err := model.NewTimezone("../UTC"); err == nil {
		t.Fatal("traversing timezone admitted")
	}
	if _, err := model.NewTimezone("Area/Bad.Zone"); err == nil {
		t.Fatal("timezone with unsupported component syntax admitted")
	}
}

func TestServiceRequiresOwnedLifecycleAxis(t *testing.T) {
	t.Parallel()

	id, err := model.NewServiceID("pipewire")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewService(
		id,
		model.SystemServiceTarget(),
		model.UnmanagedEnableIntent(),
		model.UnmanagedRunIntent(),
		nil,
	); err == nil {
		t.Fatal("service with no owned lifecycle axis admitted")
	}
	if _, err := model.NewService(
		id,
		nil,
		model.EnabledIntent(),
		model.UnmanagedRunIntent(),
		nil,
	); err == nil {
		t.Fatal("service with no target admitted")
	}
	if _, err := model.NewService(
		id,
		model.SystemServiceTarget(),
		nil,
		model.UnmanagedRunIntent(),
		nil,
	); err == nil {
		t.Fatal("service with no enable intent admitted")
	}
}

func TestIdentityAndServiceDependenciesAreClosed(t *testing.T) {
	t.Parallel()

	account := mustAccount(t, "alice")
	group := mustGroup(t, "users")
	packageID, _ := model.NewPackageID("pipewire")
	serviceID, _ := model.NewServiceID("pipewire")
	packageResource, _ := model.NewPackage(packageID)
	groupResource, _ := model.NewManagedGroup(group, 1000)
	accountResource, _ := model.NewManagedAccount(account, 1000, group, "/home/alice")
	home, _ := model.NewHome(account)
	homeMode, _ := model.NewHomeMode(account, 0o700)
	lock, _ := model.NewAccountLock(account)
	membership, _ := model.NewMembership(account, group, true)
	target, err := model.UserServiceTarget(account)
	if err != nil {
		t.Fatal(err)
	}
	service, err := model.NewService(
		serviceID,
		target,
		model.UnmanagedEnableIntent(),
		model.RunningIntent(),
		[]model.PackageKey{mustPackageKey(t, packageID)},
	)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := model.EmptyGraph().Add([]model.Contribution{
		contribution(t, packageResource, "profile:package"),
		contribution(t, groupResource, "config:group"),
		contribution(t, accountResource, "config:account"),
		contribution(t, home, "profile:home"),
		contribution(t, homeMode, "profile:home-mode"),
		contribution(t, lock, "profile:lock"),
		contribution(t, membership, "profile:membership"),
		contribution(t, service, "profile:service"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"account:alice":               {"group:users"},
		"account-lock:alice":          {"account:alice"},
		"home-mode:alice":             {"home:alice"},
		"home:alice":                  {"account:alice"},
		"membership:alice:users":      {"account:alice", "group:users"},
		"service:pipewire:user:alice": {"account:alice", "package:pipewire"},
	}
	for _, node := range graph.Nodes() {
		dependencies := node.Dependencies()
		got := make([]string, len(dependencies))
		for index, dependency := range dependencies {
			got[index] = dependency.Canonical()
		}
		if expected, ok := want[node.Key().Canonical()]; ok && !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s dependencies = %v, want %v", node.Key().Canonical(), got, expected)
		}
	}
}

func TestPackageAndServiceKeysRemainDifferentDomains(t *testing.T) {
	t.Parallel()

	pkgID, err := model.NewPackageID("agent")
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := model.NewServiceID("agent")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := model.NewPackage(pkgID)
	if err != nil {
		t.Fatal(err)
	}
	service, err := model.NewService(
		serviceID,
		model.SystemServiceTarget(),
		model.EnabledIntent(),
		model.UnmanagedRunIntent(),
		[]model.PackageKey{mustPackageKey(t, pkgID)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Key().Canonical() == service.Key().Canonical() {
		t.Fatal("cross-domain keys collided")
	}
}

func TestGraphDeltaIsAtomicOnMissingDependency(t *testing.T) {
	t.Parallel()

	account := mustAccount(t, "alice")
	home, err := model.NewHome(account)
	if err != nil {
		t.Fatal(err)
	}
	original := model.EmptyGraph()
	_, err = original.Add([]model.Contribution{
		contribution(t, home, "profile:home"),
	})
	if err == nil || !strings.Contains(err.Error(), "missing dependency") {
		t.Fatalf("got %v, want missing dependency", err)
	}
	if got := original.Nodes(); len(got) != 0 {
		t.Fatalf("failed delta mutated original graph: %v", got)
	}
}

func TestGraphRejectsConflictsAndCoordinateCollisions(t *testing.T) {
	t.Parallel()

	group := mustGroup(t, "users")
	accountA := mustAccount(t, "alice")
	accountB := mustAccount(t, "bob")
	groupResource, _ := model.NewManagedGroup(group, 1000)
	alice, _ := model.NewManagedAccount(accountA, 1000, group, "/home/alice")
	bobSameUID, _ := model.NewManagedAccount(accountB, 1000, group, "/home/bob")
	base, err := model.EmptyGraph().Add([]model.Contribution{
		contribution(t, groupResource, "config:group"),
		contribution(t, alice, "config:alice"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.Add([]model.Contribution{
		contribution(t, bobSameUID, "config:bob"),
	}); err == nil || !strings.Contains(err.Error(), "UID") {
		t.Fatalf("got %v, want UID collision", err)
	}

	groupOther := mustGroup(t, "staff")
	groupSameGID, _ := model.NewManagedGroup(groupOther, 1000)
	if _, err := base.Add([]model.Contribution{
		contribution(t, groupSameGID, "config:staff"),
	}); err == nil || !strings.Contains(err.Error(), "GID") {
		t.Fatalf("got %v, want GID collision", err)
	}

	bobSameHome, _ := model.NewManagedAccount(accountB, 1001, group, "/home/alice")
	if _, err := base.Add([]model.Contribution{
		contribution(t, bobSameHome, "config:bob"),
	}); err == nil || !strings.Contains(err.Error(), "home") {
		t.Fatalf("got %v, want home collision", err)
	}

	externalAlice, _ := model.NewExternalAccount(accountA)
	if _, err := base.Add([]model.Contribution{
		contribution(t, externalAlice, "config:other"),
	}); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("got %v, want resource conflict", err)
	}
}

func TestGraphRejectsDependencyTopologyConflict(t *testing.T) {
	t.Parallel()

	serviceID, _ := model.NewServiceID("agent")
	packageAID, _ := model.NewPackageID("agent-a")
	packageBID, _ := model.NewPackageID("agent-b")
	packageA, _ := model.NewPackage(packageAID)
	packageB, _ := model.NewPackage(packageBID)
	serviceA, _ := model.NewService(
		serviceID,
		model.SystemServiceTarget(),
		model.EnabledIntent(),
		model.UnmanagedRunIntent(),
		[]model.PackageKey{mustPackageKey(t, packageAID)},
	)
	serviceB, _ := model.NewService(
		serviceID,
		model.SystemServiceTarget(),
		model.EnabledIntent(),
		model.UnmanagedRunIntent(),
		[]model.PackageKey{mustPackageKey(t, packageBID)},
	)
	graph, err := model.EmptyGraph().Add([]model.Contribution{
		contribution(t, packageA, "profile:a-package"),
		contribution(t, packageB, "profile:b-package"),
		contribution(t, serviceA, "profile:a-service"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.Add([]model.Contribution{
		contribution(t, serviceB, "profile:b-service"),
	}); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("got %v, want topology conflict", err)
	}
}

func TestGraphUnifiesProvenanceAndProjectsCanonically(t *testing.T) {
	t.Parallel()

	idA, _ := model.NewPackageID("a")
	idB, _ := model.NewPackageID("b")
	a, _ := model.NewPackage(idA)
	b, _ := model.NewPackage(idB)
	graph, err := model.EmptyGraph().Add([]model.Contribution{
		contribution(t, b, "profile:z"),
		contribution(t, a, "profile:y"),
		contribution(t, a, "profile:x"),
		contribution(t, a, "profile:x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graph.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	gotKeys := []string{nodes[0].Key().Canonical(), nodes[1].Key().Canonical()}
	wantKeys := []string{"package:a", "package:b"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("keys = %v, want %v", gotKeys, wantKeys)
	}
	gotProvenance := nodes[0].Provenance()
	wantProvenance := []string{"profile:x", "profile:y"}
	if !reflect.DeepEqual(gotProvenance, wantProvenance) {
		t.Fatalf("provenance = %v, want %v", gotProvenance, wantProvenance)
	}
}
