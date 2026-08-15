package model_test

import (
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

func TestResourceProjections(t *testing.T) {
	groupKey, _ := model.NewGroupKey("wheel")
	accountKey, _ := model.NewAccountKey("alice")
	packageID, _ := model.NewPackageID("desktop")
	packageKey, _ := model.NewPackageKey(packageID)
	serviceID, _ := model.NewServiceID("session")
	userTarget, _ := model.UserServiceTarget(accountKey)

	managedGroup, _ := model.NewManagedGroup(groupKey, 1000)
	managedAccount, _ := model.NewManagedAccount(accountKey, 1000, groupKey, "/home/alice")
	home, _ := model.NewHome(accountKey)
	homeMode, _ := model.NewHomeMode(accountKey, 0o750)
	lock, _ := model.NewAccountLock(accountKey)
	shell, _ := model.NewAccountShell(accountKey, "/bin/sh")
	membership, _ := model.NewMembership(accountKey, groupKey, true)
	pkg, _ := model.NewPackage(packageID)
	service, _ := model.NewService(serviceID, userTarget, model.EnabledIntent(), model.RunningIntent(), []model.PackageKey{packageKey})
	hostname, _ := model.NewHostname("workstation")
	timezone, _ := model.NewTimezone("Asia/Shanghai")

	nodes := graphNodes(t, managedGroup, managedAccount, home, homeMode, lock, shell, membership, pkg, service, hostname, timezone)

	group, ok := model.GroupOf(nodes["group:wheel"])
	if !ok || !group.Valid() || group.Name() != "wheel" || !group.Managed() || group.GID() != 1000 {
		t.Fatalf("GroupOf = %#v, %v", group, ok)
	}
	account, ok := model.AccountOf(nodes["account:alice"])
	if !ok || !account.Valid() || account.Name() != "alice" || !account.Managed() || account.UID() != 1000 || account.PrimaryGroup() != "wheel" || account.Home() != "/home/alice" {
		t.Fatalf("AccountOf = %#v, %v", account, ok)
	}
	homeView, ok := model.HomeOf(nodes["home:alice"])
	if !ok || !homeView.Valid() || homeView.Account() != "alice" {
		t.Fatalf("HomeOf = %#v, %v", homeView, ok)
	}
	mode, ok := model.HomeModeOf(nodes["home-mode:alice"])
	if !ok || !mode.Valid() || mode.Account() != "alice" || mode.Mode() != 0o750 {
		t.Fatalf("HomeModeOf = %#v, %v", mode, ok)
	}
	lockView, ok := model.AccountLockOf(nodes["account-lock:alice"])
	if !ok || !lockView.Valid() || lockView.Account() != "alice" {
		t.Fatalf("AccountLockOf = %#v, %v", lockView, ok)
	}
	shellView, ok := model.AccountShellOf(nodes["account-shell:alice"])
	if !ok || !shellView.Valid() || shellView.Account() != "alice" || shellView.Shell() != "/bin/sh" {
		t.Fatalf("AccountShellOf = %#v, %v", shellView, ok)
	}
	membershipView, ok := model.MembershipOf(nodes["membership:alice:wheel"])
	if !ok || !membershipView.Valid() || membershipView.Account() != "alice" || membershipView.Group() != "wheel" || !membershipView.Present() {
		t.Fatalf("MembershipOf = %#v, %v", membershipView, ok)
	}
	serviceView, ok := model.ServiceOf(nodes["service:session:user:alice"])
	user, userScoped := serviceView.User()
	packages := serviceView.Packages()
	if !ok || !serviceView.Valid() || serviceView.ID().String() != "session" || !userScoped || user != "alice" || serviceView.Enable() != model.EnabledIntent() || serviceView.Run() != model.RunningIntent() || len(packages) != 1 || packages[0].Canonical() != "package:desktop" {
		t.Fatalf("ServiceOf = %#v, %v", serviceView, ok)
	}
	hostnameView, ok := model.HostnameOf(nodes["hostname"])
	if !ok || !hostnameView.Valid() || hostnameView.Value() != "workstation" {
		t.Fatalf("HostnameOf = %#v, %v", hostnameView, ok)
	}
	timezoneView, ok := model.TimezoneOf(nodes["timezone"])
	if !ok || !timezoneView.Valid() || timezoneView.Value() != "Asia/Shanghai" {
		t.Fatalf("TimezoneOf = %#v, %v", timezoneView, ok)
	}

	if _, ok := model.GroupOf(nodes["account:alice"]); ok {
		t.Fatal("account identified as group")
	}
	wrong := nodes["hostname"]
	wrongKind := map[string]func() bool{
		"account":       func() bool { _, ok := model.AccountOf(wrong); return ok },
		"service":       func() bool { _, ok := model.ServiceOf(wrong); return ok },
		"home":          func() bool { _, ok := model.HomeOf(wrong); return ok },
		"home mode":     func() bool { _, ok := model.HomeModeOf(wrong); return ok },
		"account lock":  func() bool { _, ok := model.AccountLockOf(wrong); return ok },
		"account shell": func() bool { _, ok := model.AccountShellOf(wrong); return ok },
		"membership":    func() bool { _, ok := model.MembershipOf(wrong); return ok },
		"timezone":      func() bool { _, ok := model.TimezoneOf(wrong); return ok },
	}
	for name, query := range wrongKind {
		if query() {
			t.Errorf("hostname identified as %s", name)
		}
	}
	if _, ok := model.HostnameOf(nodes["timezone"]); ok {
		t.Fatal("timezone identified as hostname")
	}
	if _, ok := model.ServiceOf(nil); ok {
		t.Fatal("nil identified as service")
	}

	packages[0] = nil
	again, ok := model.ServiceOf(nodes["service:session:user:alice"])
	if !ok || len(again.Packages()) != 1 || again.Packages()[0] == nil {
		t.Fatal("mutating returned package dependencies changed graph projection")
	}
}

func TestSystemServiceProjection(t *testing.T) {
	serviceID, _ := model.NewServiceID("sshd")
	resource, _ := model.NewService(serviceID, model.SystemServiceTarget(), model.DisabledIntent(), model.StoppedIntent(), nil)
	node := graphNodes(t, resource)["service:sshd:system"]

	service, ok := model.ServiceOf(node)
	user, userScoped := service.User()
	if !ok || !service.Valid() || service.ID().String() != "sshd" || userScoped || user != "" || service.Enable() != model.DisabledIntent() || service.Run() != model.StoppedIntent() || service.Packages() != nil {
		t.Fatalf("ServiceOf(system) = %#v, %v", service, ok)
	}
}

func TestExternalIdentityProjections(t *testing.T) {
	groupKey, _ := model.NewGroupKey("video")
	accountKey, _ := model.NewAccountKey("bob")
	groupResource, _ := model.NewExternalGroup(groupKey)
	accountResource, _ := model.NewExternalAccount(accountKey)
	nodes := graphNodes(t, groupResource, accountResource)

	group, ok := model.GroupOf(nodes["group:video"])
	if !ok || group.Name() != "video" || group.Managed() || group.GID() != 0 {
		t.Fatalf("external GroupOf = %#v, %v", group, ok)
	}
	account, ok := model.AccountOf(nodes["account:bob"])
	if !ok || account.Name() != "bob" || account.Managed() || account.UID() != 0 || account.PrimaryGroup() != "" || account.Home() != "" {
		t.Fatalf("external AccountOf = %#v, %v", account, ok)
	}
}

func graphNodes(t *testing.T, resources ...model.Resource) map[string]model.Node {
	t.Helper()
	provenance, _ := model.NewProvenance("projection-test")
	contributions := make([]model.Contribution, 0, len(resources))
	for _, resource := range resources {
		contribution, err := model.Contribute(resource, provenance)
		if err != nil {
			t.Fatal(err)
		}
		contributions = append(contributions, contribution)
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]model.Node)
	for _, node := range graph.Nodes() {
		result[node.Key().Canonical()] = node
	}
	return result
}
