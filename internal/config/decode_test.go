package config_test

import (
	"embed"
	"errors"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/config"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

//go:embed testdata/roots.toml
var rootsFixture []byte

//go:embed testdata/unused-source.toml
var unusedSourceFixture []byte

//go:embed testdata/complete.toml
var completeFixture []byte

//go:embed testdata/invalid/*.toml
var invalidFixtures embed.FS

func TestDecodeFixtures(t *testing.T) {
	if _, err := config.Decode("roots.toml", rootsFixture); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	if _, err := config.Decode("unused-source.toml", unusedSourceFixture); err != nil {
		t.Fatalf("deferred source use: %v", err)
	}
}

func TestDecodeRequiresSchemaTwoWithoutSchemaOneCompatibility(t *testing.T) {
	if _, err := config.Decode("two.toml", []byte("schema=2\npackages=['curl']\n")); err != nil {
		t.Fatalf("schema 2: %v", err)
	}
	target, err := config.Decode("one.toml", []byte("schema=1\npackages=['curl']\n"))
	var diagnostic *config.Diagnostic
	if target != (config.Target{}) || !errors.As(err, &diagnostic) || diagnostic.Category != "UnsupportedSchema" {
		t.Fatalf("schema 1 = %#v, %#v; want zero Target and UnsupportedSchema", target, err)
	}
	target, err = config.Decode("one-nested.toml", []byte("schema=1\nprofiles=[{profile='core:old',arguments={owner={account='alice'}}}]\n"))
	if target != (config.Target{}) || !errors.As(err, &diagnostic) || diagnostic.Category != "UnsupportedSchema" {
		t.Fatalf("nested schema 1 = %#v, %#v; want zero Target and UnsupportedSchema", target, err)
	}
}

func TestDecodeCompleteFixture(t *testing.T) {
	target, err := config.Decode("complete.toml", completeFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Sources()) != 2 || len(target.Bindings()) != 1 || len(target.Profiles()) != 2 {
		t.Fatalf("source selections = %d/%d/%d", len(target.Sources()), len(target.Bindings()), len(target.Profiles()))
	}
	if len(target.Packages()) != 6 || len(target.Services()) != 2 || len(target.Via()) != 1 {
		t.Fatalf("native truth = %d/%d/%d", len(target.Packages()), len(target.Services()), len(target.Via()))
	}
	if len(target.Direct().Nodes()) != 11 {
		t.Fatalf("portable nodes = %d", len(target.Direct().Nodes()))
	}
}

func TestDecodeInvalidFixturesAtomically(t *testing.T) {
	want := map[string]string{
		"account-partial.toml":   "InvalidValue",
		"duplicate-package.toml": "Duplicate",
		"missing-reference.toml": "MissingReference",
		"via-cycle.toml":         "Cycle",
	}
	entries, err := invalidFixtures.ReadDir("testdata/invalid")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("invalid fixtures = %d, want %d", len(entries), len(want))
	}
	for _, entry := range entries {
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			data, err := invalidFixtures.ReadFile("testdata/invalid/" + name)
			if err != nil {
				t.Fatal(err)
			}
			target, err := config.Decode(name, data)
			var diagnostic *config.Diagnostic
			if target != (config.Target{}) || !errors.As(err, &diagnostic) || diagnostic.Category != want[name] {
				t.Fatalf("Decode = %#v, %#v; want zero Target and %s", target, err, want[name])
			}
		})
	}
}

func TestDecodeSourcesBindingsAndTypedProfileRoots(t *testing.T) {
	data := []byte(`schema = 2
bindings = ["linux"]
profiles = [
  { profile = "core:desktop", arguments = { account = "alice", group = "users" } },
  { profile = "core:server" }
]

[sources]
core = "` + digest + `"
linux = "` + digest + `"

[groups.users]
[accounts.alice]
`)

	target, err := config.Decode("target.toml", data)
	if err != nil {
		t.Fatal(err)
	}
	sources := target.Sources()
	if len(sources) != 2 || sources[0].Alias != "core" || sources[1].Alias != "linux" || sources[0].Digest.String() != digest {
		t.Fatalf("sources = %#v", sources)
	}
	bindings := target.Bindings()
	if len(bindings) != 1 || bindings[0].Source != "linux" {
		t.Fatalf("bindings = %#v", bindings)
	}
	profiles := target.Profiles()
	if len(profiles) != 2 || profiles[0].Source != "core" || profiles[0].Name == "" || profiles[1].Name == "" {
		t.Fatalf("profiles = %#v", profiles)
	}

	sources[0].Alias = "changed"
	bindings[0].Source = "changed"
	profiles[0].Source = "changed"
	profiles[0].Arguments["account"] = "changed"
	if target.Sources()[0].Alias != "core" || target.Bindings()[0].Source != "linux" || target.Profiles()[0].Source != "core" || target.Profiles()[0].Arguments["account"] != "alice" {
		t.Fatal("Target accessors exposed mutable slice state")
	}
}

func TestDecodeDefersProfileReferenceArgumentsAndSourceUse(t *testing.T) {
	data := []byte(`schema = 2
profiles = [{ profile = "core:workstation", arguments = { desktop = "extra:sway" } }]
[sources]
core = "` + digest + `"
extra = "` + digest + `"
`)
	target, err := config.Decode("target.toml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := target.Profiles()[0].Arguments["desktop"]; got != "extra:sway" {
		t.Fatalf("desktop = %q", got)
	}
}

func TestDecodeDeduplicatesEqualSelectionsCanonically(t *testing.T) {
	data := []byte(`schema=2
bindings=["linux", "linux"]
profiles=[{profile="core:server"}, {profile="core:server"}]
[sources]
linux="` + digest + `"
core="` + digest + `"
`)
	target, err := config.Decode("target.toml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Bindings()) != 1 || len(target.Profiles()) != 1 || target.Sources()[0].Alias != "core" {
		t.Fatalf("noncanonical target: sources=%#v bindings=%#v profiles=%#v", target.Sources(), target.Bindings(), target.Profiles())
	}
}

func TestDecodeRejectsInvalidRootAdmissionAtomically(t *testing.T) {
	tests := []struct {
		name, data, category string
	}{
		{"missing-schema", `bindings=["core"]
[sources]
core="` + digest + `"`, "InvalidValue"},
		{"unknown-field", "schema=2\nunknown=true\n", "Syntax"},
		{"empty-sources", "schema=2\n[sources]\n", "InvalidValue"},
		{"empty-bindings", "schema=2\nbindings=[]\n", "InvalidValue"},
		{"empty-profiles", "schema=2\nprofiles=[]\n", "InvalidValue"},
		{"missing-source", "schema=2\nbindings=['core']\n", "MissingReference"},
		{"bad-profile-reference", "schema=2\nprofiles=[{profile='server'}]\n", "InvalidValue"},
		{"nested-argument", "schema=2\nprofiles=[{profile='core:server',arguments={owner={account='alice'}}}]\n[sources]\ncore='" + digest + "'\n", "Syntax"},
		{"empty-argument", "schema=2\nprofiles=[{profile='core:server',arguments={}}]\n[sources]\ncore='" + digest + "'\n", "InvalidValue"},
		{"bad-source-symbol", "schema=2\nbindings=['Bad']\n[sources]\nBad='" + digest + "'\n", "InvalidValue"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := config.Decode("target.toml", []byte(test.data))
			if err == nil || target != (config.Target{}) {
				t.Fatalf("Decode = %#v, %v; want zero Target and error", target, err)
			}
			var diagnostic *config.Diagnostic
			if !errors.As(err, &diagnostic) || diagnostic.Category != test.category {
				t.Fatalf("error = %#v; want %s Diagnostic", err, test.category)
			}
		})
	}
}

func TestDecodeBoundsBytes(t *testing.T) {
	data := []byte("schema=1\n#" + strings.Repeat("x", 1<<20))
	if target, err := config.Decode("target.toml", data); err == nil || target != (config.Target{}) {
		t.Fatalf("oversized Decode = %#v, %v", target, err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("schema=2\nbindings=['core']\n[sources]\ncore='" + digest + "'\n"))
	f.Add([]byte("schema=2\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20+1 {
			data = data[:1<<20+1]
		}
		target, err := config.Decode("fuzz.toml", data)
		if err != nil {
			if target != (config.Target{}) {
				t.Fatal("failed decode returned a nonzero Target")
			}
			return
		}
		_ = target.Sources()
		_ = target.Bindings()
		_ = target.Profiles()
	})
}
