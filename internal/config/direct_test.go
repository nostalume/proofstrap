package config_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/config"
)

func TestDecodeDirectPortableAndNativeTruth(t *testing.T) {
	data := []byte(`schema = 1
packages = ["curl", "flatpak:org.example.App", "zypper:libfoo:amd64"]
hostname = "workstation"
timezone = "Asia/Shanghai"
memberships = [{ account = "alice", group = "audio", present = true }]

[via]
flatpak = ["flatpak"]

[groups.users]
gid = 1000
[groups.audio]

[accounts.alice]
uid = 1000
group = "users"
home = "/home/alice"
mode = "0700"
shell = "/bin/bash"
locked = true
[accounts.operator]

[services.dbus]
target = "system"
packages = ["dbus"]
running = true

[services."systemd:pipewire"]
target = "user:alice"
packages = ["pipewire"]
enabled = true
running = false
`)

	target, err := config.Decode("direct.toml", data)
	if err != nil {
		t.Fatal(err)
	}

	packages := target.Packages()
	if len(packages) != 6 {
		t.Fatalf("packages = %#v", packages)
	}
	wantPackages := []struct {
		name, backend string
	}{
		{"curl", ""}, {"dbus", ""}, {"flatpak", ""},
		{"libfoo:amd64", "zypper"}, {"org.example.App", "flatpak"}, {"pipewire", ""},
	}
	for index, want := range wantPackages {
		if packages[index].Name() != want.name {
			t.Fatalf("package %d name = %q", index, packages[index].Name())
		}
		exact, ok := packages[index].Exact()
		if ok != (want.backend != "") || ok && exact.Backend().String() != want.backend {
			t.Fatalf("package %d exact = %#v, %v", index, exact, ok)
		}
	}

	services := target.Services()
	if len(services) != 2 || services[0].ID().Name() != "dbus" || services[1].ID().Name() != "pipewire" {
		t.Fatalf("services = %#v", services)
	}
	if exact, ok := services[1].ID().Exact(); !ok || exact.Backend().String() != "systemd" {
		t.Fatalf("exact service = %#v, %v", exact, ok)
	}
	if services[0].Target() == nil || services[0].Run() == nil || services[1].Enable() == nil || len(services[1].Packages()) != 1 {
		t.Fatal("service desired truth was not retained")
	}

	via := target.Via()
	if len(via) != 1 || via[0].Backend().String() != "flatpak" || len(via[0].Packages()) != 1 {
		t.Fatalf("via = %#v", via)
	}

	wantKeys := []string{
		"account-lock:alice", "account-shell:alice", "account:alice", "account:operator",
		"group:audio", "group:users", "home-mode:alice", "home:alice", "hostname",
		"membership:alice:audio", "timezone",
	}
	nodes := target.Direct().Nodes()
	gotKeys := make([]string, len(nodes))
	for index, node := range nodes {
		gotKeys[index] = node.Key().Canonical()
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("direct keys = %v, want %v", gotKeys, wantKeys)
	}

	packages[0] = packages[1]
	services[0] = services[1]
	via[0] = config.Via{}
	if target.Packages()[0].Name() != "curl" || target.Services()[0].ID().Name() != "dbus" || len(target.Via()) != 1 {
		t.Fatal("native accessors exposed mutable collection state")
	}
}

func TestDecodeRejectsInvalidDirectTruthAtomically(t *testing.T) {
	tests := []struct {
		name, body, category string
	}{
		{"empty-packages", "packages=[]", "InvalidValue"},
		{"duplicate-package", "packages=['curl','curl']", "Duplicate"},
		{"invalid-exact-package", "packages=['Bad:curl']", "InvalidValue"},
		{"partial-account", "[accounts.alice]\nuid=1000", "InvalidValue"},
		{"missing-primary-group", "[accounts.alice]\nuid=1000\ngroup='users'\nhome='/home/alice'", "MissingReference"},
		{"unlock", "[accounts.alice]\nlocked=false", "InvalidValue"},
		{"short-mode", "[accounts.alice]\nmode='700'", "InvalidValue"},
		{"missing-membership-account", "memberships=[{account='alice',group='users',present=true}]\n[groups.users]", "MissingReference"},
		{"membership-conflict", "memberships=[{account='alice',group='users',present=true},{account='alice',group='users',present=false}]\n[groups.users]\n[accounts.alice]", "Conflict"},
		{"missing-profile-argument", "profiles=[{profile='core:desktop',arguments={owner={account='alice'}}}]\n[sources]\ncore='" + digest + "'", "MissingReference"},
		{"service-missing-target", "[services.dbus]\nrunning=true", "InvalidValue"},
		{"service-bad-target", "[services.dbus]\ntarget='user:alice:extra'\nrunning=true\n[accounts.alice]", "InvalidValue"},
		{"service-missing-account", "[services.dbus]\ntarget='user:alice'\nrunning=true", "MissingReference"},
		{"service-no-lifecycle", "[services.dbus]\ntarget='system'", "InvalidValue"},
		{"empty-service-packages", "[services.dbus]\ntarget='system'\nrunning=true\npackages=[]", "InvalidValue"},
		{"unused-via", "packages=['curl']\n[via]\nflatpak=['flatpak']", "InvalidValue"},
		{"via-cycle", "packages=['flatpak:app']\n[via]\nflatpak=['snap:provider']\nsnap=['flatpak:provider']", "Cycle"},
		{"uid-collision", "[groups.users]\n[accounts.alice]\nuid=1000\ngroup='users'\nhome='/home/alice'\n[accounts.bob]\nuid=1000\ngroup='users'\nhome='/home/bob'", "Conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := config.Decode("invalid.toml", []byte("schema=1\n"+test.body+"\n"))
			var diagnostic *config.Diagnostic
			if target != (config.Target{}) || !errors.As(err, &diagnostic) || diagnostic.Category != test.category {
				t.Fatalf("Decode = %#v, %#v; want zero Target and %s", target, err, test.category)
			}
		})
	}
}

func TestDecodeDirectOrderDoesNotChangeMeaning(t *testing.T) {
	left, err := config.Decode("left.toml", []byte("schema=1\npackages=['zypper:curl','curl']\n"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := config.Decode("right.toml", []byte("schema=1\npackages=['curl','zypper:curl']\n"))
	if err != nil {
		t.Fatal(err)
	}
	keys := func(target config.Target) []string {
		result := make([]string, 0, len(target.Packages()))
		for _, ref := range target.Packages() {
			backend := "host"
			if exact, ok := ref.Exact(); ok {
				backend = exact.Backend().String()
			}
			result = append(result, backend+":"+ref.Name())
		}
		return result
	}
	if !reflect.DeepEqual(keys(left), keys(right)) {
		t.Fatalf("order changed meaning: %v != %v", keys(left), keys(right))
	}
}

func TestDecodeCompleteFixtureIsDeterministic(t *testing.T) {
	first, err := config.Decode("complete.toml", completeFixture)
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.Decode("complete.toml", completeFixture)
	if err != nil {
		t.Fatal(err)
	}
	keys := func(target config.Target) []string {
		result := make([]string, 0)
		for _, source := range target.Sources() {
			result = append(result, "source:"+source.Alias+":"+source.Digest.String())
		}
		for _, ref := range target.Packages() {
			backend := "host"
			if exact, ok := ref.Exact(); ok {
				backend = exact.Backend().String()
			}
			result = append(result, "package:"+backend+":"+ref.Name())
		}
		for _, node := range target.Direct().Nodes() {
			result = append(result, node.Key().Canonical())
		}
		return result
	}
	if !reflect.DeepEqual(keys(first), keys(second)) {
		t.Fatalf("repeated decode differs: %v != %v", keys(first), keys(second))
	}
}

func TestDecodeBoundsCombinedDirectResources(t *testing.T) {
	var data strings.Builder
	data.WriteString("schema=1\npackages=[")
	for index := 0; index < 32768; index++ {
		if index != 0 {
			data.WriteByte(',')
		}
		fmt.Fprintf(&data, "'p%05d'", index)
	}
	data.WriteString("]\nhostname='host'\n")
	target, err := config.Decode("limit.toml", []byte(data.String()))
	var diagnostic *config.Diagnostic
	if target != (config.Target{}) || !errors.As(err, &diagnostic) || diagnostic.Category != "Limit" {
		t.Fatalf("Decode = %#v, %#v; want combined resource Limit", target, err)
	}
}
