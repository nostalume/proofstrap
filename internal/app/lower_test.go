package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/identity"
)

func TestIdentityCapabilitiesAreDerivedOnceFromDesiredKinds(t *testing.T) {
	target, err := document.Decode("test", []byte(`schema = 3
[groups.users]
gid = 1000
[groups.audio]

[accounts.alice]
uid = 1000
group = "users"
home = "/home/alice"
shell = "/bin/sh"
locked = true
supplementary = { audio = true }
`))
	if err != nil {
		t.Fatal(err)
	}
	projected, err := binding.Project(context.Background(), target.View().Direct, binding.Backends{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := identityCapabilities(projected)
	want := []identity.Capability{identity.ObserveIdentity, identity.CreateGroup, identity.CreateAccount, identity.ObserveLock, identity.ModifyAccount, identity.ModifyMembership}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestPackageLoweringPlansViaProvidersBeforeDependentBarrier(t *testing.T) {
	zypper, _ := binding.NewPackageBackendID("zypper")
	flatpak, _ := binding.NewPackageBackendID("flatpak")
	groups := []packageGroup{
		{backend: flatpak, names: []string{"app"}, dependencies: []string{"package:zypper"}},
		{backend: zypper, names: []string{"flatpak"}},
	}
	var calls []string
	result := lowerPackageGroups(groups, func(group packageGroup) (operation, bool, *blocker) {
		calls = append(calls, group.backend.String())
		return operation{id: "package:" + group.backend.String(), kind: "package", review: []byte(`{"test":true}`)}, true, nil
	})
	if !reflect.DeepEqual(calls, []string{"zypper"}) {
		t.Fatalf("planned backends = %#v", calls)
	}
	if len(result.operations) != 2 || result.operations[0].id != "package:zypper" || result.operations[1].kind != "barrier" || !reflect.DeepEqual(result.operations[1].dependencies, []string{"package:zypper"}) {
		t.Fatalf("lowered operations = %#v", result.operations)
	}
}

func TestServiceOperationIdentityIncludesBackendAndPrincipal(t *testing.T) {
	systemd := serviceOperationBase("systemd", "agent", "")
	openrc := serviceOperationBase("openrc", "agent", "")
	user := serviceOperationBase("systemd", "agent", "alice")
	if systemd != "service:systemd:system:agent" || openrc != "service:openrc:system:agent" || user != "service:systemd:user:alice:agent" {
		t.Fatalf("service identities = %q, %q, %q", systemd, openrc, user)
	}
	if systemd == openrc {
		t.Fatal("same-name services collided across backends")
	}
}
