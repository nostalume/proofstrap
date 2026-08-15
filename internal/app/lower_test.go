package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/identity"
)

func TestGroupPackagesCanonicalizesHostExactAndViaDependencies(t *testing.T) {
	target, err := config.Decode("test", []byte(`schema = 1
packages = ["curl", "flatpak:org.example.App"]

[via]
flatpak = ["flatpak"]
`))
	if err != nil {
		t.Fatal(err)
	}
	hostBackend, _ := binding.NewPackageBackendID("zypper")
	groups, err := groupPackages(target, binding.Graph{}, hostBackend)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %#v", groups)
	}
	if groups[0].backend.String() != "flatpak" || len(groups[0].names) != 1 || groups[0].names[0] != "org.example.App" || len(groups[0].dependencies) != 1 || groups[0].dependencies[0] != "package:zypper" {
		t.Fatalf("flatpak group = %#v", groups[0])
	}
	if groups[1].backend.String() != "zypper" || len(groups[1].names) != 2 || groups[1].names[0] != "curl" || groups[1].names[1] != "flatpak" || len(groups[1].dependencies) != 0 {
		t.Fatalf("host group = %#v", groups[1])
	}
}

func TestIdentityCapabilitiesAreDerivedOnceFromDesiredKinds(t *testing.T) {
	target, err := config.Decode("test", []byte(`schema = 1
memberships = [{ account = "alice", group = "audio", present = true }]

[groups.users]
gid = 1000
[groups.audio]

[accounts.alice]
uid = 1000
group = "users"
home = "/home/alice"
shell = "/bin/sh"
locked = true
`))
	if err != nil {
		t.Fatal(err)
	}
	projected, err := binding.Project(context.Background(), target.Direct(), binding.Backends{}, nil)
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
