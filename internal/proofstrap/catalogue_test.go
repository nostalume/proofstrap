package proofstrap

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestModulesReturnsSortedIndependentCatalogueIDs(t *testing.T) {
	first := Modules()
	want := []string{"audio", "dbus", "hyprland", "network", "pavucontrol", "qpwgraph", "sway", "wayland", "wl-paste", "xclip", "xsel"}
	if !reflect.DeepEqual(first, want) || !sort.StringsAreSorted(first) {
		t.Fatalf("modules=%#v want=%#v", first, want)
	}
	first[0] = "changed"
	if reflect.DeepEqual(first, Modules()) {
		t.Fatalf("caller mutated catalogue listing: %#v", Modules())
	}
}

func TestSelectionBindsPackagesAndServicesIndependently(t *testing.T) {
	selected, blockers := production.selectFor(DesiredState{Modules: []string{"network"}})
	if len(blockers) != 0 {
		t.Fatal(blockers)
	}
	packages, packageBlockers := (packageBehavior{manager: zypper, names: zypperPackageNames()}).bind(selected)
	services, serviceBlockers := (services{manager: systemd}).bind(selected)
	if len(packageBlockers) != 0 || len(serviceBlockers) != 0 || len(packages.required) != 1 || len(services.needs) != 2 {
		t.Fatalf("packages=%#v services=%#v packageBlockers=%#v serviceBlockers=%#v", packages, services, packageBlockers, serviceBlockers)
	}
}

func TestPackageBackedServiceCapabilitiesAreExact(t *testing.T) {
	tests := map[moduleID]moduleDefinition{
		"network": {requirements: []requirement{
			serviceRequirement{packageKey: "networkmanager", serviceKey: "networkmanager", scope: SystemService},
		}},
		"audio": {requirements: []requirement{
			serviceRequirement{packageKey: "pipewire", serviceKey: "pipewire", scope: UserService},
			serviceRequirement{packageKey: "wireplumber", serviceKey: "wireplumber", scope: UserService},
			packageRequirement{packageKey: "pipewire-pulse"},
			packageRequirement{packageKey: "alsa-utils"},
		}},
	}
	raw := rawCatalogue()
	var serviceBacked []string
	for id, definition := range raw.modules {
		for _, declared := range definition.requirements {
			if _, ok := declared.(serviceRequirement); ok {
				serviceBacked = append(serviceBacked, string(id))
				break
			}
		}
	}
	sort.Strings(serviceBacked)
	if want := []string{"audio", "network"}; !reflect.DeepEqual(serviceBacked, want) {
		t.Fatalf("service-backed modules=%#v want=%#v", serviceBacked, want)
	}
	for id, want := range tests {
		if got := raw.modules[id]; !reflect.DeepEqual(got, want) {
			t.Errorf("module=%s definition=%#v want=%#v", id, got, want)
		}
		selected, blockers := production.selectFor(DesiredState{Modules: []string{string(id)}})
		if len(blockers) != 0 || len(selected.conflicts) != 0 {
			t.Errorf("module=%s selection=%#v blockers=%#v", id, selected, blockers)
		}
	}
}

func TestCapabilitiesHaveCompleteFiveManagerPackageBindings(t *testing.T) {
	paths := map[string]string{}
	behaviors := []packageBehavior{
		constructAPTBehavior(paths, "2.9.0"), constructPacmanBehavior(paths, "7.0.0"),
		constructZypperBehavior(paths, "1.14.87"), constructDNF5Behavior(paths, "5.2.0"), constructDNF4Behavior(paths, "4.21.0"),
	}
	want := map[moduleID]map[packageManager]map[PackageKey]string{
		"network": {
			apt: {"networkmanager": "network-manager"}, pacman: {"networkmanager": "networkmanager"},
			zypper: {"networkmanager": "NetworkManager"}, dnf5: {"networkmanager": "NetworkManager"}, dnf4: {"networkmanager": "NetworkManager"},
		},
		"audio": {
			apt:    {"alsa-utils": "alsa-utils", "pipewire": "pipewire", "pipewire-pulse": "pipewire-pulse", "wireplumber": "wireplumber"},
			pacman: {"alsa-utils": "alsa-utils", "pipewire": "pipewire", "pipewire-pulse": "pipewire-pulse", "wireplumber": "wireplumber"},
			zypper: {"alsa-utils": "alsa-utils", "pipewire": "pipewire", "pipewire-pulse": "pipewire-pulseaudio", "wireplumber": "wireplumber"},
			dnf5:   {"alsa-utils": "alsa-utils", "pipewire": "pipewire", "pipewire-pulse": "pipewire-pulseaudio", "wireplumber": "wireplumber"},
			dnf4:   {"alsa-utils": "alsa-utils", "pipewire": "pipewire", "pipewire-pulse": "pipewire-pulseaudio", "wireplumber": "wireplumber"},
		},
	}
	for module, managerBindings := range want {
		selected, selectionBlockers := production.selectFor(DesiredState{Modules: []string{string(module)}})
		if len(selectionBlockers) != 0 {
			t.Fatal(selectionBlockers)
		}
		for _, behavior := range behaviors {
			demand, blockers := behavior.bind(selected)
			got := make(map[PackageKey]string, len(demand.required))
			for _, item := range demand.required {
				got[item.key] = item.name
			}
			if len(blockers) != 0 || !reflect.DeepEqual(got, managerBindings[behavior.manager]) {
				t.Errorf("module=%s manager=%s bindings=%#v blockers=%#v want=%#v", module, behavior.manager, got, blockers, managerBindings[behavior.manager])
			}
		}
	}
}

func TestPackageOnlyMigrationWaveDefersWhenManagerBindingsAreIncomplete(t *testing.T) {
	state := DesiredState{Modules: []string{"qpwgraph", "pavucontrol", "wl-paste", "xclip", "xsel"}}
	selected, blockers := production.selectFor(state)
	if len(blockers) != 0 {
		t.Fatal(blockers)
	}
	want := map[PackageKey]bool{
		"qpwgraph": true, "pavucontrol": true, "wl-clipboard": true, "xclip": true, "xsel": true,
	}
	got := make(map[PackageKey]bool)
	for _, key := range selected.packageKeys() {
		got[key] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys=%#v want=%#v", got, want)
	}
	paths := map[string]string{}
	for _, behavior := range []packageBehavior{
		constructAPTBehavior(paths, "2.9.0"),
		constructPacmanBehavior(paths, "7.0.0"),
		constructZypperBehavior(paths, "1.14.87"),
		constructDNF5Behavior(paths, "5.2.0"),
		constructDNF4Behavior(paths, "4.21.0"),
	} {
		demand, bindingBlockers := behavior.bind(selected)
		wantBlockers := 0
		if behavior.manager == dnf4 {
			wantBlockers = 4
		}
		if len(bindingBlockers) != wantBlockers || len(demand.required)+len(bindingBlockers) != len(want) {
			t.Fatalf("manager=%s demand=%#v blockers=%#v", behavior.manager, demand, bindingBlockers)
		}
	}
}

func TestCandidatesRemainDeferredWithoutFiveManagerBindings(t *testing.T) {
	for _, id := range []string{"clipman", "dunst", "foot", "kitty", "mako", "polybar", "waybar", "wofi"} {
		if _, ok := production.modules[moduleID(id)]; ok {
			t.Errorf("incomplete candidate %q was admitted", id)
		}
		if _, blockers := production.selectFor(DesiredState{Modules: []string{id}}); len(blockers) != 1 || blockers[0].Subject != "module:"+id {
			t.Errorf("module=%q blockers=%#v", id, blockers)
		}
	}
}

func TestCurrentPackageBindingsAreExact(t *testing.T) {
	base := map[PackageKey]string{
		"dbus": "dbus", "wayland": "wayland", "sway": "sway", "swayidle": "swayidle", "swaylock": "swaylock",
		"grim": "grim", "slurp": "slurp", "hyprland": "hyprland", "networkmanager": "NetworkManager",
		"pipewire": "pipewire", "wireplumber": "wireplumber", "pipewire-pulse": "pipewire-pulseaudio",
		"alsa-utils": "alsa-utils", "qpwgraph": "qpwgraph", "pavucontrol": "pavucontrol",
		"wl-clipboard": "wl-clipboard", "xclip": "xclip", "xsel": "xsel",
	}
	with := func(changes map[PackageKey]string) map[PackageKey]string {
		got := make(map[PackageKey]string, len(base))
		for key, name := range base {
			got[key] = name
		}
		for key, name := range changes {
			got[key] = name
		}
		return got
	}
	without := func(source map[PackageKey]string, keys ...PackageKey) map[PackageKey]string {
		got := make(map[PackageKey]string, len(source))
		for key, name := range source {
			got[key] = name
		}
		for _, key := range keys {
			delete(got, key)
		}
		return got
	}
	paths := map[string]string{}
	tests := []struct {
		manager packageManager
		got     map[PackageKey]string
		want    map[PackageKey]string
	}{
		{manager: apt, got: aptPackageNames(), want: without(with(map[PackageKey]string{"networkmanager": "network-manager", "wayland": "libwayland-client0", "pipewire-pulse": "pipewire-pulse"}), "hyprland")},
		{manager: pacman, got: pacmanPackageNames(), want: with(map[PackageKey]string{"networkmanager": "networkmanager", "pipewire-pulse": "pipewire-pulse"})},
		{manager: zypper, got: zypperPackageNames(), want: with(map[PackageKey]string{"dbus": "dbus-1", "wayland": "libwayland-client0"})},
		{manager: dnf5, got: constructDNF5Behavior(paths, "5.2.0").names, want: without(with(map[PackageKey]string{"wayland": "libwayland-client"}), "hyprland")},
		{manager: dnf4, got: constructDNF4Behavior(paths, "4.21.0").names, want: without(with(map[PackageKey]string{"wayland": "libwayland-client"}), "sway", "swayidle", "swaylock", "grim", "slurp", "hyprland", "qpwgraph", "wl-clipboard", "xclip", "xsel")},
	}
	for _, test := range tests {
		t.Run(test.manager.String(), func(t *testing.T) {
			if !reflect.DeepEqual(test.got, test.want) {
				t.Fatalf("bindings=%#v want=%#v", test.got, test.want)
			}
		})
	}
}

func TestCompileCatalogueValidatesWholeGraph(t *testing.T) {
	tests := []struct {
		name string
		raw  catalogue
		want string
	}{
		{
			name: "unknown dependency in unselected module",
			raw: catalogue{
				modules: map[moduleID]moduleDefinition{"unused": {requires: []moduleID{"missing"}}},
			},
			want: `module "unused" requires unknown module "missing"`,
		},
		{
			name: "cycle in unselected modules",
			raw: catalogue{
				modules: map[moduleID]moduleDefinition{
					"a": {requires: []moduleID{"b"}},
					"b": {requires: []moduleID{"a"}},
				},
			},
			want: "dependency cycle: a -> b -> a",
		},
		{
			name: "unknown exclusion",
			raw: catalogue{modules: map[moduleID]moduleDefinition{
				"a": {excludes: []moduleID{"missing"}},
			}},
			want: `module "a" excludes unknown module "missing"`,
		},
		{
			name: "unknown requirement key",
			raw: catalogue{
				modules:  map[moduleID]moduleDefinition{"a": {requirements: []requirement{packageRequirement{packageKey: "missing"}}}},
				packages: map[PackageKey]struct{}{},
			},
			want: `unknown package key "missing"`,
		},
		{
			name: "empty package key",
			raw:  catalogue{packages: map[PackageKey]struct{}{PackageKey(""): {}}},
			want: "empty package key",
		},
		{
			name: "empty service key",
			raw:  catalogue{services: map[ServiceKey]struct{}{ServiceKey(""): {}}},
			want: "empty service key",
		},

		{
			name: "duplicate dependency",
			raw: catalogue{modules: map[moduleID]moduleDefinition{
				"a": {requires: []moduleID{"b", "b"}}, "b": {},
			}},
			want: "requires module \"b\" more than once",
		},
		{
			name: "duplicate conflict",
			raw: catalogue{modules: map[moduleID]moduleDefinition{
				"a": {excludes: []moduleID{"b", "b"}}, "b": {},
			}},
			want: "excludes module \"b\" more than once",
		},
		{
			name: "duplicate requirement",
			raw: catalogue{
				modules:  map[moduleID]moduleDefinition{"a": {requirements: []requirement{packageRequirement{packageKey: "p"}, packageRequirement{packageKey: "p"}}}},
				packages: map[PackageKey]struct{}{"p": {}},
			},
			want: "declares requirement",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := compileCatalogue(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want containing %q", err, test.want)
			}
		})
	}
}

func TestCompiledCatalogueIsImmutableAndSelectsDependencyClosure(t *testing.T) {
	raw := catalogue{
		modules: map[moduleID]moduleDefinition{
			"base": {},
			"app":  {requires: []moduleID{"base"}},
		},
	}
	compiled, err := compileCatalogue(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw.modules["app"] = moduleDefinition{}
	delete(raw.modules, "base")

	selected, blockers := compiled.selectFor(DesiredState{Modules: []string{"app"}})
	if len(blockers) != 0 || !reflect.DeepEqual(selected.moduleStrings(), []string{"base", "app"}) {
		t.Fatalf("selected=%#v blockers=%#v", selected, blockers)
	}
}

func TestSelectionRejectsExcludedModulesBeforeHostInspection(t *testing.T) {
	compiled := mustCompileCatalogue(catalogue{
		modules: map[moduleID]moduleDefinition{
			"sway":     {excludes: []moduleID{"hyprland"}},
			"hyprland": {},
		},
	})
	selected, blockers := compiled.selectFor(DesiredState{Modules: []string{"sway", "hyprland"}})
	if len(blockers) != 1 || blockers[0].Subject != "modules:exclusion" {
		t.Fatalf("selected=%#v blockers=%#v", selected, blockers)
	}
	if !reflect.DeepEqual(selected.moduleStrings(), []string{"sway", "hyprland"}) {
		t.Fatalf("modules=%#v", selected.moduleStrings())
	}
}

func TestSelectionExclusionIsUndirectedAndUnrelatedModulesCoexist(t *testing.T) {
	compiled := mustCompileCatalogue(catalogue{modules: map[moduleID]moduleDefinition{
		"a": {excludes: []moduleID{"b"}},
		"b": {},
		"c": {},
	}})
	for _, requested := range [][]string{{"a", "b"}, {"b", "a"}} {
		_, blockers := compiled.selectFor(DesiredState{Modules: requested})
		if len(blockers) != 1 || !strings.Contains(blockers[0].Detail, "cannot both be selected") {
			t.Fatalf("requested=%#v blockers=%#v", requested, blockers)
		}
	}
	_, blockers := compiled.selectFor(DesiredState{Modules: []string{"a", "c"}})
	if len(blockers) != 0 {
		t.Fatalf("unrelated modules blocked: %#v", blockers)
	}
}

func TestProductionCatalogueUsesSelectionExclusionWithoutPackageConflict(t *testing.T) {
	compiled := production
	selected, blockers := compiled.selectFor(DesiredState{Modules: []string{"sway"}})
	if len(blockers) != 0 {
		t.Fatal(blockers)
	}
	if !reflect.DeepEqual(selected.moduleStrings(), []string{"dbus", "wayland", "sway"}) {
		t.Fatalf("modules=%#v", selected.moduleStrings())
	}
	if !reflect.DeepEqual(compiled.modules["sway"].excludes, []moduleID{"hyprland"}) {
		t.Fatalf("sway exclusions=%#v", compiled.modules["sway"].excludes)
	}
}

func TestCompileAndSelectAbortServiceConflict(t *testing.T) {
	compiled, err := compileCatalogue(catalogue{
		modules: map[moduleID]moduleDefinition{
			"wanted": {requirements: []requirement{serviceRequirement{packageKey: "wanted-package", serviceKey: "wanted", scope: SystemService}}},
			"other":  {requirements: []requirement{serviceRequirement{packageKey: "other-package", serviceKey: "other", scope: SystemService}}},
		},
		packages:         map[PackageKey]struct{}{"wanted-package": {}, "other-package": {}},
		services:         map[ServiceKey]struct{}{"wanted": {}, "other": {}},
		serviceConflicts: []serviceConflict{{wanted: "wanted", other: "other", scope: SystemService}},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, blockers := compiled.selectFor(DesiredState{Modules: []string{"wanted"}})
	if len(blockers) != 0 || len(selected.conflicts) != 1 {
		t.Fatalf("selected=%#v blockers=%#v", selected, blockers)
	}
	_, blockers = compiled.selectFor(DesiredState{Modules: []string{"wanted", "other"}})
	if len(blockers) != 1 || blockers[0].Subject != "services:conflict" {
		t.Fatalf("blockers=%#v", blockers)
	}
}

func TestCompileRejectsMalformedServiceConflict(t *testing.T) {
	_, err := compileCatalogue(catalogue{
		services:         map[ServiceKey]struct{}{"wanted": {}},
		serviceConflicts: []serviceConflict{{wanted: "wanted", other: "missing", scope: SystemService}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("err=%v", err)
	}
}

func TestServiceConflictSelectionIncludesScope(t *testing.T) {
	compiled := mustCompileCatalogue(catalogue{
		modules: map[moduleID]moduleDefinition{
			"wanted-user":  {requirements: []requirement{serviceRequirement{packageKey: "wanted-package", serviceKey: "wanted", scope: UserService}}},
			"other-system": {requirements: []requirement{serviceRequirement{packageKey: "other-package", serviceKey: "other", scope: SystemService}}},
		},
		packages:         map[PackageKey]struct{}{"wanted-package": {}, "other-package": {}},
		services:         map[ServiceKey]struct{}{"wanted": {}, "other": {}},
		serviceConflicts: []serviceConflict{{wanted: "wanted", other: "other", scope: UserService}},
	})
	selected, blockers := compiled.selectFor(DesiredState{Modules: []string{"wanted-user", "other-system"}})
	if len(blockers) != 0 || len(selected.conflicts) != 1 {
		t.Fatalf("selected=%#v blockers=%#v", selected, blockers)
	}
}
