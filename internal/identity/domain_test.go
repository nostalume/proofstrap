package identity

import (
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

func TestReconcileGroupMatrix(t *testing.T) {
	managed := projectedGroup(t, "wheel", true, 1000)
	external := projectedGroup(t, "video", false, 0)
	exact := groupRecord{name: "wheel", gid: 1000}
	other := groupRecord{name: "other", gid: 1000}

	cases := []struct {
		name     string
		desired  model.Group
		observed groupObservation
		want     DecisionKind
	}{
		{"managed absent", managed, missingGroupObservation(), Change},
		{"managed exact", managed, foundGroupObservation(exact), Exact},
		{"managed gid collision", managed, groupObservation{nameGlobal: missingGroup(), nameLocal: missingGroup(), numberGlobal: foundGroup(other), numberLocal: foundGroup(other)}, Blocked},
		{"external present", external, foundGroupObservation(groupRecord{name: "video", gid: 44}), Exact},
		{"external missing", external, missingGroupObservation(), Blocked},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			decision := reconcileGroup(test.desired, test.observed)
			if decision.Kind() != test.want {
				t.Fatalf("decision = %v (%s), want %v", decision.Kind(), decision.Detail(), test.want)
			}
		})
	}
}

func TestReconcileGroupRejectsNSSDisagreementFailureAndRoot(t *testing.T) {
	desired := projectedGroup(t, "wheel", true, 1000)
	exact := groupRecord{name: "wheel", gid: 1000}
	drift := groupRecord{name: "wheel", gid: 1001}
	for name, observed := range map[string]groupObservation{
		"global local disagreement": {nameGlobal: foundGroup(exact), nameLocal: foundGroup(drift), numberGlobal: foundGroup(exact), numberLocal: foundGroup(exact)},
		"lookup failure":            {nameGlobal: failedGroup("NSS failed"), nameLocal: missingGroup(), numberGlobal: missingGroup(), numberLocal: missingGroup()},
	} {
		t.Run(name, func(t *testing.T) {
			if decision := reconcileGroup(desired, observed); decision.Kind() != Blocked {
				t.Fatalf("decision = %v", decision.Kind())
			}
		})
	}
	root := projectedGroup(t, "root", true, 0)
	if decision := reconcileGroup(root, foundGroupObservation(groupRecord{name: "root", gid: 0})); decision.Kind() != Blocked {
		t.Fatalf("root decision = %v", decision.Kind())
	}
}

func TestReconcileAccountMatrix(t *testing.T) {
	managed := projectedAccount(t, "alice", true, 1000, "wheel", "/home/alice")
	primary := projectedGroup(t, "wheel", true, 1000)
	external := projectedAccount(t, "bob", false, 0, "", "")
	exact := passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}
	cases := []struct {
		name     string
		desired  model.Account
		observed accountObservation
		want     DecisionKind
	}{
		{"managed absent", managed, missingAccountObservation(), Change},
		{"managed exact", managed, foundAccountObservation(exact), Exact},
		{"managed mismatch", managed, foundAccountObservation(passwdRecord{name: "alice", uid: 1000, gid: 1001, home: "/home/alice", shell: "/bin/sh"}), Blocked},
		{"external present", external, foundAccountObservation(passwdRecord{name: "bob", uid: 1001, gid: 1001, home: "/home/bob", shell: "/bin/sh"}), Exact},
		{"external missing", external, missingAccountObservation(), Blocked},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			group := model.Group{}
			if test.desired.Managed() {
				group = primary
			}
			decision := reconcileAccount(test.desired, group, test.observed)
			if decision.Kind() != test.want {
				t.Fatalf("decision = %v (%s), want %v", decision.Kind(), decision.Detail(), test.want)
			}
		})
	}
}

func TestNSSRecordParsingIsStrict(t *testing.T) {
	group, err := parseGroupRecord("wheel:x:1000:alice,bob")
	if err != nil || group.name != "wheel" || group.gid != 1000 || strings.Join(group.members, ",") != "alice,bob" {
		t.Fatalf("group = %#v, %v", group, err)
	}
	account, err := parsePasswdRecord("alice:x:1000:1000:Alice:/home/alice:/bin/sh")
	if err != nil || account.name != "alice" || account.uid != 1000 || account.gid != 1000 || account.home != "/home/alice" || account.shell != "/bin/sh" {
		t.Fatalf("account = %#v, %v", account, err)
	}
	for _, record := range []string{"wheel::1000:", "wheel:x:not-a-number:", "wheel:x:1000:alice,,bob", "wheel:x:1000"} {
		if _, err := parseGroupRecord(record); err == nil {
			t.Fatalf("accepted group record %q", record)
		}
	}
	for _, record := range []string{"alice::1000:1000::/home/alice:/bin/sh", "alice:x:bad:1000::/home/alice:/bin/sh", "alice:x:1000:1000:::/bin/sh"} {
		if _, err := parsePasswdRecord(record); err == nil {
			t.Fatalf("accepted passwd record %q", record)
		}
	}
}

func projectedGroup(t *testing.T, name string, managed bool, gid uint32) model.Group {
	t.Helper()
	key, _ := model.NewGroupKey(name)
	var resource model.Resource
	if managed {
		resource, _ = model.NewManagedGroup(key, gid)
	} else {
		resource, _ = model.NewExternalGroup(key)
	}
	return projectResource(t, resource, model.GroupOf)
}

func projectedAccount(t *testing.T, name string, managed bool, uid uint32, group, home string) model.Account {
	t.Helper()
	accountKey, _ := model.NewAccountKey(name)
	var resources []model.Resource
	if managed {
		groupKey, _ := model.NewGroupKey(group)
		groupResource, _ := model.NewManagedGroup(groupKey, 1000)
		accountResource, _ := model.NewManagedAccount(accountKey, uid, groupKey, home)
		resources = []model.Resource{groupResource, accountResource}
	} else {
		accountResource, _ := model.NewExternalAccount(accountKey)
		resources = []model.Resource{accountResource}
	}
	provenance, _ := model.NewProvenance("identity-test")
	contributions := make([]model.Contribution, 0, len(resources))
	for _, resource := range resources {
		contribution, _ := model.Contribute(resource, provenance)
		contributions = append(contributions, contribution)
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range graph.Nodes() {
		if value, ok := model.AccountOf(node); ok {
			return value
		}
	}
	t.Fatal("account projection missing")
	return model.Account{}
}

func projectResource[T any](t *testing.T, resource model.Resource, query func(model.Node) (T, bool)) T {
	t.Helper()
	provenance, _ := model.NewProvenance("identity-test")
	contribution, _ := model.Contribute(resource, provenance)
	graph, err := model.EmptyGraph().Add([]model.Contribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := query(graph.Nodes()[0])
	if !ok {
		t.Fatal("projection failed")
	}
	return value
}
