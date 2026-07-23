package proofstrap

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPackageBehaviorRequiresInstalledAndRootedNames(t *testing.T) {
	demand := packageDemand{required: []resolvedPackage{{key: "sway", name: "sway"}}}
	for _, test := range []struct {
		name     string
		evidence packageEvidence
		want     string
	}{
		{name: "done", evidence: packageEvidence{installed: packageSet{"sway": {}}, rooted: packageSet{"sway": {}}}, want: "done"},
		{name: "root", evidence: packageEvidence{installed: packageSet{"sway": {}}}, want: "root"},
		{name: "missing installs", evidence: packageEvidence{}, want: "install"},
	} {
		t.Run(test.name, func(t *testing.T) {
			behavior := packageBehavior{
				inventory: func(context.Context, Runner) (packageEvidence, error) { return test.evidence, nil },
				rootCommand: func(names []string) Command {
					return Command{Name: "/test/root", Args: names}
				},
				installCommand: func(names []string) Command {
					return Command{Name: "/test/install", Args: names}
				},
			}
			switch state := behavior.inspect(context.Background(), &testRunner{}, demand).(type) {
			case packageDone:
				if test.want != "done" {
					t.Fatalf("state=%T want=%s", state, test.want)
				}
			case packageRootChange:
				if test.want != "root" {
					t.Fatalf("state=%T want=%s", state, test.want)
				}
			case packageInstallChange:
				if test.want != "install" || state.command.String() != "/test/install sway" {
					t.Fatalf("state=%#v want=%s", state, test.want)
				}
			case packageBlocked:
				if test.want != "blocked" {
					t.Fatalf("state=%#v want=%s", state, test.want)
				}
			default:
				t.Fatalf("state=%#v", state)
			}
		})
	}
}

func TestPackageBehaviorBlocksUnknownRootEvidence(t *testing.T) {
	behavior := packageBehavior{inventory: func(context.Context, Runner) (packageEvidence, error) {
		return packageEvidence{}, context.DeadlineExceeded
	}}
	state := behavior.inspect(context.Background(), &testRunner{}, packageDemand{required: []resolvedPackage{{key: "sway", name: "sway"}}})
	blocked, ok := state.(packageBlocked)
	if !ok || !strings.Contains(blocked.reason, "package evidence") {
		t.Fatalf("state=%#v", state)
	}
}

func TestIndependentPackageConstructorsOwnManagerIdentityAndNames(t *testing.T) {
	paths := map[string]string{
		"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query",
		"pacman": "/usr/bin/pacman", "zypper": "/usr/bin/zypper", "rpm": "/usr/bin/rpm",
		"dnf": "/usr/bin/dnf", "dnf5": "/usr/bin/dnf5",
	}
	for _, test := range []struct {
		name    string
		value   packageBehavior
		manager packageManager
		want    string
		root    bool
		install string
	}{
		{name: "apt", value: constructAPTBehavior(paths, "2.9.0"), manager: apt, want: "network-manager", root: true, install: "/usr/bin/apt-get install --yes --no-remove --no-install-recommends dbus"},
		{name: "pacman", value: constructPacmanBehavior(paths, "7.0.0"), manager: pacman, want: "networkmanager", root: true, install: "/usr/bin/pacman -S --needed --noconfirm dbus"},
		{name: "zypper", value: constructZypperBehavior(paths, "1.14.87"), manager: zypper, want: "NetworkManager", install: "/usr/bin/zypper --non-interactive install --no-recommends dbus"},
		{name: "dnf5", value: constructDNF5Behavior(paths, "5.2.0"), manager: dnf5, want: "NetworkManager", install: "/usr/bin/dnf5 install -y dbus"},
		{name: "dnf4", value: constructDNF4Behavior(paths, "4.21.0"), manager: dnf4, want: "NetworkManager", install: "/usr/bin/dnf install -y dbus"},
	} {
		t.Run(test.name, func(t *testing.T) {
			install := test.value.installCommand([]string{"dbus"})
			if test.value.manager != test.manager || test.value.names["networkmanager"] != test.want || (test.value.rootCommand != nil) != test.root || install.String() != test.install || install.timeout != 10*time.Minute {
				t.Fatalf("behavior=%#v", test.value)
			}
		})
	}
}

func TestDNF5ConstructorKeepsCompatibleDNFAliasPath(t *testing.T) {
	behavior := constructDNF5Behavior(map[string]string{"dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"}, "5.4.2")
	if command := behavior.installCommand([]string{"dbus"}); command.Name != "/usr/bin/dnf" {
		t.Fatalf("command=%#v", command)
	}
}

func TestAptBehaviorObservesInstalledAndManualRootsIndependently(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query"},
		results: map[string][]Result{
			"/usr/bin/dpkg-query -W -f=${binary:Package}\\t${db:Status-Abbrev}\\n": {{Stdout: "dbus:amd64	ii \nlibc6:amd64	ii \n"}},
			"/usr/bin/apt-mark showmanual":                                         {{Stdout: "dbus:amd64\n"}},
		},
	}
	evidence, err := constructAPTBehavior(runner.paths, "2.9.0").inventory(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	want := packageEvidence{installed: packageSet{"dbus": {}, "libc6": {}}, rooted: packageSet{"dbus": {}}}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("evidence=%#v want=%#v", evidence, want)
	}
}

func TestPackageBehaviorRejectsRootEvidenceOutsideInstalledInventory(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query"},
		results: map[string][]Result{
			"/usr/bin/dpkg-query -W -f=${binary:Package}\\t${db:Status-Abbrev}\\n": {{Stdout: "dbus:amd64\tii \n"}},
			"/usr/bin/apt-mark showmanual":                                         {{Stdout: "ghost\n"}},
		},
	}
	_, err := constructAPTBehavior(runner.paths, "2.9.0").inventory(context.Background(), runner)
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("err=%v", err)
	}
}

func TestPacmanBehaviorBuildsExplicitRootChange(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"pacman": "/usr/bin/pacman"},
		results: map[string][]Result{
			"/usr/bin/pacman -Qq":  {{Stdout: "dbus\n"}},
			"/usr/bin/pacman -Qqe": {{Stdout: ""}},
		},
	}
	behavior := constructPacmanBehavior(runner.paths, "7.0.0")
	state := behavior.inspect(context.Background(), runner, packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}})
	change, ok := state.(packageRootChange)
	if !ok || change.command.String() != "/usr/bin/pacman -D --asexplicit dbus" {
		t.Fatalf("state=%#v", state)
	}
}

func TestDNFBehaviorObservesUserInstalledRoots(t *testing.T) {
	for _, manager := range []packageManager{dnf4, dnf5} {
		rootCommand := "/usr/bin/dnf repoquery --userinstalled --qf %{name}"
		if manager == dnf5 {
			rootCommand = "/usr/bin/dnf5 repoquery --userinstalled --qf %{name}\\n"
		}
		runner := &testRunner{
			paths: map[string]string{"dnf": "/usr/bin/dnf", "dnf5": "/usr/bin/dnf5", "rpm": "/usr/bin/rpm"},
			results: map[string][]Result{
				"/usr/bin/rpm -qa --qf %{NAME}\\n": {{Stdout: "dbus\n"}},
				rootCommand:                        {{Stdout: "dbus\n"}},
			},
		}
		var behavior packageBehavior
		if manager == dnf4 {
			behavior = constructDNF4Behavior(runner.paths, "4.21.0")
		} else {
			behavior = constructDNF5Behavior(runner.paths, "5.2.0")
		}
		state := behavior.inspect(context.Background(), runner, packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}})
		_, ok := state.(packageDone)
		if !ok || len(runner.calls) != 2 {
			t.Fatalf("manager=%s state=%#v calls=%#v", manager, state, runner.calls)
		}
	}
}

func TestZypperBehaviorDerivesRootsBySubtractingAutoInstalled(t *testing.T) {
	runner := &testRunner{
		files:   map[string][]byte{"/var/lib/zypp/AutoInstalled": []byte("dependency\n")},
		paths:   map[string]string{"rpm": "/usr/bin/rpm"},
		results: map[string][]Result{"/usr/bin/rpm -qa --qf %{NAME}\\n": {{Stdout: "dbus-1\ndependency\n"}}},
	}
	evidence, err := constructZypperBehavior(runner.paths, "1.14.87").inventory(context.Background(), runner)
	if err != nil || !reflect.DeepEqual(evidence.rooted, packageSet{"dbus-1": {}}) {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
}

func TestZypperBehaviorBuildsInstallChange(t *testing.T) {
	runner := &testRunner{
		files:   map[string][]byte{"/var/lib/zypp/AutoInstalled": {}},
		paths:   map[string]string{"rpm": "/usr/bin/rpm", "zypper": "/usr/bin/zypper"},
		results: map[string][]Result{"/usr/bin/rpm -qa --qf %{NAME}\\n": {{Stdout: ""}}},
	}
	state := constructZypperBehavior(runner.paths, "1.14.87").inspect(
		context.Background(), runner, packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus-1"}}},
	)
	change, ok := state.(packageInstallChange)
	if !ok || change.command.String() != "/usr/bin/zypper --non-interactive install --no-recommends dbus-1" {
		t.Fatalf("state=%#v", state)
	}
}

func TestPackageInstallChangeAllowsDependenciesAndVerifiesRoots(t *testing.T) {
	before := packageEvidence{installed: packageSet{"base": {}}, rooted: packageSet{"base": {}}}
	after := packageEvidence{
		installed: packageSet{"base": {}, "dbus": {}, "dependency": {}},
		rooted:    packageSet{"base": {}, "dbus": {}},
	}
	calls, postHasDeadline := 0, false
	behavior := packageBehavior{manager: apt, inventory: func(ctx context.Context, _ Runner) (packageEvidence, error) {
		calls++
		if calls == 2 {
			_, postHasDeadline = ctx.Deadline()
			return after, nil
		}
		return before, nil
	}}
	change := packageInstallChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   before,
		install:  packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-get", Args: []string{"install", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-get install dbus": {{}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err != nil || !result.attempted || calls != 2 || !postHasDeadline {
		t.Fatalf("result=%#v calls=%d postHasDeadline=%t", result, calls, postHasDeadline)
	}
}

func TestPackageInstallChangeGuardsAfterInventoryBeforeMutation(t *testing.T) {
	evidence := packageEvidence{installed: packageSet{"base": {}}, rooted: packageSet{"base": {}}}
	inventories, guarded := 0, false
	change := packageInstallChange{
		behavior: packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
			inventories++
			return evidence, nil
		}},
		demand: packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before: evidence, install: packageSet{"dbus": {}}, command: Command{Name: "/usr/bin/apt-get", Args: []string{"install", "dbus"}},
	}
	result := change.apply(context.Background(), &testRunner{}, change.command, func() error {
		guarded = true
		return stalePrecondition{detail: "account changed during package inventory"}
	})
	if result.err == nil || result.attempted || !guarded || inventories != 1 {
		t.Fatalf("result=%#v guarded=%v inventories=%d", result, guarded, inventories)
	}
}

func TestPackageInstallChangeRequiresMutationGuard(t *testing.T) {
	result := (packageInstallChange{}).apply(context.Background(), &testRunner{}, Command{}, nil)
	if result.err == nil || result.attempted || !strings.Contains(result.err.Error(), "guard is required") {
		t.Fatalf("result=%#v", result)
	}
}

func TestPackageRootChangeGuardsAfterInventoryBeforeMutation(t *testing.T) {
	evidence := packageEvidence{installed: packageSet{"base": {}, "dbus": {}}, rooted: packageSet{"base": {}}}
	inventories, guarded := 0, false
	change := packageRootChange{
		behavior: packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
			inventories++
			return evidence, nil
		}},
		demand: packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before: evidence, root: packageSet{"dbus": {}}, command: Command{Name: "/usr/bin/apt-mark", Args: []string{"manual", "dbus"}},
	}
	result := change.apply(context.Background(), &testRunner{}, change.command, func() error {
		guarded = true
		return stalePrecondition{detail: "account changed during package inventory"}
	})
	if result.err == nil || result.attempted || !guarded || inventories != 1 {
		t.Fatalf("result=%#v guarded=%v inventories=%d", result, guarded, inventories)
	}
}

func allowPackageMutation() error { return nil }

func TestPackageInstallFailureStillObservesPostAttemptEvidence(t *testing.T) {
	evidence := packageEvidence{installed: packageSet{"base": {}}, rooted: packageSet{"base": {}}}
	calls := 0
	behavior := packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
		calls++
		return evidence, nil
	}}
	change := packageInstallChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   evidence,
		install:  packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-get", Args: []string{"install", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-get install dbus": {{ExitCode: 1, Stderr: "failed"}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err == nil || !result.attempted || calls != 2 || !strings.Contains(result.err.Error(), "native package installation failed") {
		t.Fatalf("result=%#v calls=%d", result, calls)
	}
}

func TestPackageInstallChangeRejectsRemovalAndCollateralRoot(t *testing.T) {
	before := packageEvidence{installed: packageSet{"base": {}}, rooted: packageSet{"base": {}}}
	after := packageEvidence{
		installed: packageSet{"dbus": {}, "dependency": {}},
		rooted:    packageSet{"dbus": {}, "dependency": {}},
	}
	calls := 0
	behavior := packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
		calls++
		if calls == 2 {
			return after, nil
		}
		return before, nil
	}}
	change := packageInstallChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   before,
		install:  packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-get", Args: []string{"install", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-get install dbus": {{}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err == nil || !strings.Contains(result.err.Error(), "removed previously installed") || !strings.Contains(result.err.Error(), "roots differ") {
		t.Fatalf("result=%#v", result)
	}
}

func TestPackageRootChangeBoundsIndependentPostAttemptObservation(t *testing.T) {
	before := packageEvidence{installed: packageSet{"dbus": {}}, rooted: packageSet{}}
	after := packageEvidence{installed: packageSet{"dbus": {}}, rooted: packageSet{"dbus": {}}}
	calls, postHasDeadline := 0, false
	behavior := packageBehavior{manager: apt, inventory: func(ctx context.Context, _ Runner) (packageEvidence, error) {
		calls++
		if calls == 2 {
			_, postHasDeadline = ctx.Deadline()
			return after, nil
		}
		return before, nil
	}}
	change := packageRootChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   before,
		root:     packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-mark", Args: []string{"manual", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-mark manual dbus": {{}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err != nil || !result.attempted || !postHasDeadline {
		t.Fatalf("result=%#v calls=%d postHasDeadline=%v", result, calls, postHasDeadline)
	}
}

func TestPackageRootChangeRejectsUnreviewedRootPromotion(t *testing.T) {
	before := packageEvidence{
		installed: packageSet{"dbus": {}, "dependency": {}},
		rooted:    packageSet{},
	}
	after := packageEvidence{
		installed: packageSet{"dbus": {}, "dependency": {}},
		rooted:    packageSet{"dbus": {}, "dependency": {}},
	}
	calls := 0
	behavior := packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
		calls++
		if calls == 2 {
			return after, nil
		}
		return before, nil
	}}
	change := packageRootChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   before,
		root:     packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-mark", Args: []string{"manual", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-mark manual dbus": {{}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err == nil || !strings.Contains(result.err.Error(), "package roots differ") {
		t.Fatalf("result=%#v", result)
	}
}

func TestPackageRootChangeReportsCollateralAfterFailedCommand(t *testing.T) {
	before := packageEvidence{installed: packageSet{"dbus": {}}, rooted: packageSet{}}
	after := packageEvidence{installed: packageSet{"dbus": {}, "unexpected": {}}, rooted: packageSet{}}
	calls := 0
	behavior := packageBehavior{manager: apt, inventory: func(context.Context, Runner) (packageEvidence, error) {
		calls++
		if calls == 2 {
			return after, nil
		}
		return before, nil
	}}
	change := packageRootChange{
		behavior: behavior,
		demand:   packageDemand{required: []resolvedPackage{{key: "dbus", name: "dbus"}}},
		before:   before,
		root:     packageSet{"dbus": {}},
		command:  Command{Name: "/usr/bin/apt-mark", Args: []string{"manual", "dbus"}},
	}
	runner := &testRunner{results: map[string][]Result{"/usr/bin/apt-mark manual dbus": {{ExitCode: 1, Stderr: "failed"}}}}
	result := change.apply(context.Background(), runner, change.command, allowPackageMutation)
	if result.err == nil || !strings.Contains(result.err.Error(), "mutation failed") || !strings.Contains(result.err.Error(), "changed installed packages") {
		t.Fatalf("result=%#v", result)
	}
}

func TestAptPackageSetIgnoresResidualConfigAndNormalizesArchitecture(t *testing.T) {
	installed, err := parseAPTInstalledSet("sway:amd64	ii\nold-package	rc\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(installed, packageSet{"sway": {}}) {
		t.Fatalf("installed=%#v", installed)
	}
}

func TestObservedPackageSetsDeduplicateNamesAfterProjection(t *testing.T) {
	installed, err := parseAPTInstalledSet("libc6:amd64	ii\nlibc6:i386	ii\n")
	if err != nil || !reflect.DeepEqual(installed, packageSet{"libc6": {}}) {
		t.Fatalf("installed=%#v err=%v", installed, err)
	}
	rpmNames, err := parsePlainPackageSet("gpg-pubkey\ngpg-pubkey\n")
	if err != nil || !reflect.DeepEqual(rpmNames, packageSet{"gpg-pubkey": {}}) {
		t.Fatalf("rpmNames=%#v err=%v", rpmNames, err)
	}
}

func TestAptPackageSetRejectsMalformedInventoryRow(t *testing.T) {
	if _, err := parseAPTInstalledSet("sway:amd64	ii\nmalformed\n"); err == nil {
		t.Fatal("malformed apt inventory was accepted")
	}
}

func TestPackagesForUsesBehaviorEvidenceNotOSIdentity(t *testing.T) {
	runner := &testRunner{
		paths:   map[string]string{"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query"},
		results: map[string][]Result{"/usr/bin/apt-get --version": {{Stdout: "apt 2.9.8 (amd64)\n"}}},
	}
	behavior, err := recognizePackageBehavior(runner)
	if err != nil || behavior.manager != apt || behavior.version != "2.9.8" {
		t.Fatalf("behavior=%#v err=%v", behavior, err)
	}
	runner.paths["pacman"] = "/usr/bin/pacman"
	runner.results["/usr/bin/apt-get --version"] = []Result{{Stdout: "apt 2.9.8 (amd64)\n"}}
	runner.results["/usr/bin/pacman --version"] = []Result{{Stdout: "Pacman v7.0.0\n"}}
	if _, err := recognizePackageBehavior(runner); err == nil {
		t.Fatal("multiple native package behaviors were not rejected")
	}
}

func TestPackagesForRecognizesEveryIncludedManager(t *testing.T) {
	for _, test := range []struct {
		name    string
		paths   map[string]string
		version Result
		manager packageManager
	}{
		{name: "zypper", paths: map[string]string{"zypper": "/usr/bin/zypper", "rpm": "/usr/bin/rpm"}, version: Result{Stdout: "zypper 1.14.87\n"}, manager: zypper},
		{name: "apt", paths: map[string]string{"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query"}, version: Result{Stdout: "apt 2.9.8\n"}, manager: apt},
		{name: "dnf5", paths: map[string]string{"dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"}, version: Result{Stdout: "dnf5 version 5.2.12.0\n"}, manager: dnf5},
		{name: "pacman", paths: map[string]string{"pacman": "/usr/bin/pacman"}, version: Result{Stdout: "Pacman v7.0.0\n"}, manager: pacman},
		{name: "dnf4", paths: map[string]string{"dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"}, version: Result{Stdout: "4.21.1\n"}, manager: dnf4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var executable string
			for _, name := range []string{"zypper", "apt-get", "dnf", "pacman"} {
				if path := test.paths[name]; path != "" {
					executable = path
					break
				}
			}
			runner := &testRunner{paths: test.paths, results: map[string][]Result{executable + " --version": {test.version}}}
			behavior, err := recognizePackageBehavior(runner)
			if err != nil || behavior.manager != test.manager || behavior.version == "" {
				t.Fatalf("behavior=%#v err=%v", behavior, err)
			}
		})
	}
}

func TestPackagesForRejectsMalformedManagerVersion(t *testing.T) {
	runner := &testRunner{
		paths:   map[string]string{"dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"},
		results: map[string][]Result{"/usr/bin/dnf --version": {{Stdout: "unknown\n"}}},
	}
	if _, err := recognizePackageBehavior(runner); err == nil {
		t.Fatal("manager with malformed version evidence was admitted")
	}
}

func TestRecognizePackageBehaviorRejectsDNF5ExecutableReportingDNF4(t *testing.T) {
	runner := &testRunner{
		paths:   map[string]string{"dnf5": "/usr/bin/dnf5", "rpm": "/usr/bin/rpm"},
		results: map[string][]Result{"/usr/bin/dnf5 --version": {{Stdout: "4.21.1\n"}}},
	}
	if _, err := recognizePackageBehavior(runner); err == nil || !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecognizePackageBehaviorDeduplicatesDNF5Aliases(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"dnf5": "/usr/bin/dnf5", "dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"},
		results: map[string][]Result{
			"/usr/bin/dnf5 --version":        {{Stdout: "dnf5 version 5.2.12.0\n"}},
			"/usr/bin/dnf --version":         {{Stdout: "dnf5 version 5.2.12.0\n"}},
			"/usr/bin/rpm --eval %{_dbpath}": {{Stdout: "/var/lib/rpm\n"}},
		},
	}
	behavior, err := recognizePackageBehavior(runner)
	if err != nil || behavior.manager != dnf5 || behavior.version != "5.2.12.0" {
		t.Fatalf("behavior=%#v err=%v", behavior, err)
	}
	if countString(runner.calls, "/usr/bin/rpm --eval %{_dbpath}") != 1 {
		t.Fatalf("native RPM database was not proven: calls=%#v", runner.calls)
	}
}

func TestRecognizePackageBehaviorRejectsDNF5AliasesWithDifferentRPMPaths(t *testing.T) {
	runner := &testRunner{
		paths:       map[string]string{"dnf5": "/usr/bin/dnf5", "dnf": "/usr/bin/dnf"},
		pathResults: map[string][]string{"rpm": {"/usr/bin/rpm", "/opt/rpm/bin/rpm"}},
		results: map[string][]Result{
			"/usr/bin/dnf5 --version": {{Stdout: "dnf5 version 5.2.12.0\n"}},
			"/usr/bin/dnf --version":  {{Stdout: "dnf5 version 5.2.12.0\n"}},
		},
	}
	if _, err := recognizePackageBehavior(runner); err == nil || !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecognizePackageBehaviorRejectsIndependentDNF4AndDNF5(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"dnf5": "/usr/bin/dnf5", "dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm"},
		results: map[string][]Result{
			"/usr/bin/dnf5 --version": {{Stdout: "dnf5 version 5.2.12.0\n"}},
			"/usr/bin/dnf --version":  {{Stdout: "4.21.1\n"}},
		},
	}
	if _, err := recognizePackageBehavior(runner); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecognizePackageBehaviorBlocksPresentIndeterminateCandidate(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{
			"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query",
			"pacman": "/usr/bin/pacman",
		},
		results: map[string][]Result{
			"/usr/bin/apt-get --version": {{Stdout: "apt 2.9.8\n"}},
			"/usr/bin/pacman --version":  {{Stdout: "unknown\n"}},
		},
	}
	if _, err := recognizePackageBehavior(runner); err == nil || !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("err=%v", err)
	}
}

func TestRecognizedPackageBehaviorBindsItsOwnNativeNames(t *testing.T) {
	selected, blockers := production.selectFor(DesiredState{Modules: []string{"network"}})
	if len(blockers) != 0 {
		t.Fatal(blockers)
	}
	runner := &testRunner{
		paths:   map[string]string{"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query"},
		results: map[string][]Result{"/usr/bin/apt-get --version": {{Stdout: "apt 2.9.8\n"}}},
	}
	behavior, err := recognizePackageBehavior(runner)
	if err != nil {
		t.Fatal(err)
	}
	demand, blockers := behavior.bind(selected)
	if len(blockers) != 0 || len(demand.required) != 1 || demand.required[0].name != "network-manager" {
		t.Fatalf("demand=%#v blockers=%#v", demand, blockers)
	}
}

func TestPackageBehaviorBindingFailsClosed(t *testing.T) {
	selected, blockers := production.selectFor(DesiredState{Modules: []string{"network"}})
	if len(blockers) != 0 {
		t.Fatal(blockers)
	}
	_, blockers = (packageBehavior{manager: apt, names: map[PackageKey]string{}}).bind(selected)
	if len(blockers) != 1 || blockers[0].Subject != "binding:package:networkmanager" {
		t.Fatalf("blockers=%#v", blockers)
	}
}
