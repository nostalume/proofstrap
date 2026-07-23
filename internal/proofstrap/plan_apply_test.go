package proofstrap

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEquivalentIndependentPlansHaveCanonicalDigest(t *testing.T) {
	plan := func(modules []string) ReviewPlan {
		runner := baseRunner()
		runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "xclip\nxsel\n"}}
		return Plan(DesiredState{Modules: modules}, runner)
	}
	first := plan([]string{"xsel", "xclip"})
	second := plan([]string{"xclip", "xsel"})
	if first.Blocked() || second.Blocked() || !reflect.DeepEqual(first, second) || first.Digest() != second.Digest() {
		t.Fatalf("first=%#v digest=%s second=%#v digest=%s", first, first.Digest(), second, second.Digest())
	}
}

func TestPackagePlansNeverObserveOrProjectServiceMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		modules []string
		runner  *testRunner
	}{
		{name: "network install", modules: []string{"network"}, runner: missingPackageRunner()},
		{name: "network root", modules: []string{"network"}, runner: networkRootPlanRunner()},
		{name: "audio install", modules: []string{"audio"}, runner: missingPackageRunner()},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := DesiredState{Modules: test.modules}
			if test.name == "audio install" {
				addAccountResults(test.runner, "alice", 1000, 4)
				state = audioDesiredState()
			}
			review := Plan(state, test.runner)
			if review.Blocked() || len(review.Changes) != 1 || !strings.HasPrefix(review.Changes[0].ID, "package-") {
				t.Fatalf("review=%#v calls=%#v", review, test.runner.calls)
			}
			for _, call := range test.runner.calls {
				if strings.Contains(call, "systemctl") {
					t.Fatalf("package plan observed services: %#v", test.runner.calls)
				}
			}
			if containsString(test.runner.pathCalls, "systemctl") || containsFact(review.Facts, "service-manager", "") {
				t.Fatalf("package plan admitted service authority: paths=%#v facts=%#v", test.runner.pathCalls, review.Facts)
			}
		})
	}
}

func TestPackageBackedCapabilityRejectsUnsupportedPID1BeforePackagePlan(t *testing.T) {
	runner := missingPackageRunner()
	runner.files["/proc/1/comm"] = []byte("openrc\n")
	addAccountResults(runner, "alice", 1000, 4)
	review := Plan(audioDesiredState(), runner)
	if !review.Blocked() || len(review.Changes) != 0 || len(review.Blockers) != 1 || review.Blockers[0].Subject != "service-manager" {
		t.Fatalf("review=%#v", review)
	}
	if containsString(runner.pathCalls, "systemctl") || containsString(runner.calls, "/usr/bin/zypper --non-interactive install --no-recommends alsa-utils pipewire pipewire-pulseaudio wireplumber") {
		t.Fatalf("unsupported service manager crossed admission: paths=%#v calls=%#v", runner.pathCalls, runner.calls)
	}
}

func TestPackageApplyLeavesDeadlinesToBehaviorCommands(t *testing.T) {
	runner := packageRootChangeRunner(false)
	command := Command{Name: "/usr/bin/apt-get", Args: []string{"install", "dbus"}, timeout: 10 * time.Minute}
	projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
	change := Change{ID: "package-install:apt", Command: &projected}
	plan := packagePlan{
		plan: ReviewPlan{Changes: []Change{change}}, host: observeHost(runner).facts,
		projection: change, command: command,
	}
	receipt := plan.apply(runner, ApplyReceipt{}, func(ctx context.Context, _ Runner, effective Command, _ packageMutationGuard) packageResult {
		if _, ok := ctx.Deadline(); ok {
			return packageResult{err: errors.New("package orchestration overrode command timeout")}
		}
		if effective.timeout != 10*time.Minute {
			return packageResult{err: errors.New("install timeout was not retained")}
		}
		return packageResult{attempted: true}
	})
	if receipt.Status != ReplanRequired {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestAuthorityFailsClosedWhenKernelPrincipalIsUnknown(t *testing.T) {
	runner := &testRunner{uidErr: errors.New("uid unavailable"), paths: map[string]string{"sudo": "/usr/bin/sudo"}}
	_, _, blockers := admitAuthority(runner, []step{{access: rootStep}})
	if len(blockers) != 1 || blockers[0].Subject != "authority:principal" || len(runner.calls) != 0 || len(runner.pathCalls) != 0 {
		t.Fatalf("blockers=%#v calls=%#v paths=%#v", blockers, runner.calls, runner.pathCalls)
	}
}

func TestPlanBlocksDesiredSelectionExclusionBeforeHostInspection(t *testing.T) {
	runner := &testRunner{}
	plan := Plan(DesiredState{Modules: []string{"sway", "hyprland"}}, runner)
	if !plan.Blocked() || len(plan.Blockers) != 1 || len(runner.calls) != 0 || len(runner.pathCalls) != 0 {
		t.Fatalf("plan=%#v calls=%#v paths=%#v", plan, runner.calls, runner.pathCalls)
	}
}

func TestPlanBlocksEmptyDesiredStateBeforeHostInspection(t *testing.T) {
	plan := Plan(DesiredState{}, &testRunner{})
	if !plan.Blocked() || len(plan.Blockers) != 1 || plan.Blockers[0].Subject != "desired-state" {
		t.Fatalf("plan=%#v", plan)
	}
}

func TestPlanTreatsInstalledCompositorsAsPackagesOnly(t *testing.T) {
	runner := swayRunner()
	plan := Plan(DesiredState{Modules: []string{"sway"}}, runner)
	if plan.Blocked() || len(plan.Changes) != 0 {
		t.Fatalf("plan=%#v", plan)
	}
	for _, fact := range plan.Facts {
		if strings.Contains(fact.Subject, "role:") || strings.Contains(fact.Subject, "compositor") {
			t.Fatalf("runtime occupancy fact=%#v", fact)
		}
	}
}

func TestPackageOnlySelectionDoesNotRequireSystemd(t *testing.T) {
	compiled := mustCompileCatalogue(catalogue{
		modules:  map[moduleID]moduleDefinition{"tool": {requirements: []requirement{packageRequirement{packageKey: "dbus"}}}},
		packages: map[PackageKey]struct{}{"dbus": {}},
	})
	runner := &testRunner{
		files: map[string][]byte{
			"/etc/os-release":             []byte("ID=custom\n"),
			"/proc/1/comm":                []byte("openrc\n"),
			"/var/lib/zypp/AutoInstalled": {},
		},
		paths: map[string]string{"zypper": "/usr/bin/zypper", "rpm": "/usr/bin/rpm"},
		results: map[string][]Result{
			"/usr/bin/zypper --version": {{Stdout: "zypper 1.14.87\n"}},
			rpmInventoryCommand():       {{Stdout: "dbus-1\n"}},
		},
	}
	review := planFor(DesiredState{Modules: []string{"tool"}}, runner, compiled).review()
	if review.Blocked() || containsFact(review.Facts, "service-manager", "") {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestReadyPackageGuardUsesInventoryWithoutPlanningMutation(t *testing.T) {
	evidence := packageEvidence{installed: packageSet{"dbus": {}}, rooted: packageSet{"dbus": {}}}
	rootCalls := 0
	behavior := packageBehavior{
		inventory: func(context.Context, Runner) (packageEvidence, error) { return evidence, nil },
		rootCommand: func([]string) Command {
			rootCalls++
			return Command{Name: "/test/root"}
		},
	}
	plan := readyPlan{packageBehavior: behavior, packageEvidence: evidence}
	stale, err := plan.guardPackages(context.Background(), &testRunner{})
	if stale || err != nil || rootCalls != 0 {
		t.Fatalf("stale=%t err=%v rootCalls=%d", stale, err, rootCalls)
	}
}

func TestPackageRootChangeApplyReturnsReplanRequired(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	reviewRunner := packageRootChangeRunner(false)
	review := Plan(state, reviewRunner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/usr/bin/apt-mark manual dbus" {
		t.Fatalf("review=%#v calls=%#v", review, reviewRunner.calls)
	}
	applyRunner := packageRootChangeRunner(true)
	receipt := Apply(state, applyRunner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, applyRunner.calls)
	}
	for _, call := range applyRunner.calls {
		if strings.Contains(call, "systemctl") {
			t.Fatalf("service command crossed package barrier: %#v", applyRunner.calls)
		}
	}
}

func TestPackageRootReviewProjectsResolvedPrivilegeExecutable(t *testing.T) {
	runner := packageRootChangeRunner(false)
	runner.uid = 1000
	runner.paths["sudo"] = "/opt/proofstrap/bin/sudo"
	runner.results["/opt/proofstrap/bin/sudo -N -n -v"] = []Result{{ExitCode: 0}}

	review := Plan(DesiredState{Modules: []string{"dbus"}}, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/opt/proofstrap/bin/sudo -N -n /usr/bin/apt-mark manual dbus" {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestPackageRootFailureStillObservesPostAttemptEvidence(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	review := Plan(state, packageRootChangeRunner(false))
	runner := packageRootChangeRunner(true)
	runner.results["/usr/bin/apt-mark manual dbus"] = []Result{{ExitCode: 1, Stderr: "failed"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, "/usr/bin/apt-mark showmanual") != 3 {
		t.Fatalf("post-attempt observation missing: calls=%#v", runner.calls)
	}
}

func TestPackageEffectPreconditionDriftIsStaleAndUnattempted(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	review := Plan(state, packageRootChangeRunner(false))
	runner := packageRootChangeRunner(true)
	runner.results["/usr/bin/apt-mark showmanual"] = []Result{{Stdout: ""}, {Stdout: "dbus\n"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/bin/apt-mark manual dbus") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestPackageRootPlanDigestBindsCompleteEvidence(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	first := Plan(state, packageRootChangeRunner(false))
	secondRunner := packageRootChangeRunner(false)
	secondRunner.results["/usr/bin/dpkg-query -W -f=${binary:Package}\\t${db:Status-Abbrev}\\n"] = []Result{{Stdout: "dbus:amd64	ii \nlibc6:amd64	ii \n"}}
	second := Plan(state, secondRunner)
	if first.Blocked() || second.Blocked() || first.Digest() == second.Digest() {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
}

func TestPackageRootPlanDigestBindsResolvedMutationPath(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	first := Plan(state, packageRootChangeRunner(false))
	secondRunner := packageRootChangeRunner(false)
	secondRunner.paths["apt-mark"] = "/opt/apt/bin/apt-mark"
	secondRunner.results["/opt/apt/bin/apt-mark showmanual"] = secondRunner.results["/usr/bin/apt-mark showmanual"]
	delete(secondRunner.results, "/usr/bin/apt-mark showmanual")
	second := Plan(state, secondRunner)
	if first.Blocked() || second.Blocked() || first.Digest() == second.Digest() {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
}

func TestMissingPackagePlansDirectInstall(t *testing.T) {
	review := Plan(DesiredState{Modules: []string{"dbus"}}, missingPackageRunner())
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/usr/bin/zypper --non-interactive install --no-recommends dbus-1" {
		t.Fatalf("review=%#v", review)
	}
}

func TestPackageInstallApplyReturnsReplanRequired(t *testing.T) {
	state := DesiredState{Modules: []string{"dbus"}}
	review := Plan(state, missingPackageRunner())
	if review.Blocked() || len(review.Changes) != 1 {
		t.Fatalf("review=%#v", review)
	}
	runner := missingPackageRunner()
	runner.results[rpmInventoryCommand()] = []Result{
		{Stdout: ""},
		{Stdout: ""},
		{Stdout: "dbus-1\n"},
	}
	runner.results["/usr/bin/zypper --non-interactive install --no-recommends dbus-1"] = []Result{{}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "systemctl") {
			t.Fatalf("service command crossed package barrier: %#v", runner.calls)
		}
	}
}

func TestAudioPackageProgressRequiresFreshServicePlan(t *testing.T) {
	state := audioDesiredState()
	planRunner := missingPackageRunner()
	addAccountResults(planRunner, "alice", 1000, 4)
	review := Plan(state, planRunner)
	wantCommand := "/usr/bin/zypper --non-interactive install --no-recommends alsa-utils pipewire pipewire-pulseaudio wireplumber"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != wantCommand {
		t.Fatalf("review=%#v", review)
	}
	runner := missingPackageRunner()
	addAccountResults(runner, "alice", 1000, 4)
	installed := "alsa-utils\npipewire\npipewire-pulseaudio\nwireplumber\n"
	runner.results[rpmInventoryCommand()] = []Result{{Stdout: ""}, {Stdout: ""}, {Stdout: installed}}
	runner.results[wantCommand] = []Result{{}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	for _, call := range append(append([]string(nil), runner.calls...), runner.pathCalls...) {
		if strings.Contains(call, "systemctl") {
			t.Fatalf("service authority crossed audio package barrier: calls=%#v paths=%#v", runner.calls, runner.pathCalls)
		}
	}
}

func TestPlanAbortConflictBlocksWithoutExecutableStep(t *testing.T) {
	compiled := mustCompileCatalogue(catalogue{
		modules: map[moduleID]moduleDefinition{
			"wanted": {requirements: []requirement{serviceRequirement{packageKey: "networkmanager", serviceKey: "networkmanager", scope: SystemService}}},
		},
		packages:         map[PackageKey]struct{}{"networkmanager": {}},
		services:         map[ServiceKey]struct{}{"networkmanager": {}, "pipewire": {}},
		serviceConflicts: []serviceConflict{{wanted: "networkmanager", other: "pipewire", scope: SystemService}},
	})
	runner := baseRunner()
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "NetworkManager\n"}}
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{{ExitCode: 0, Stdout: "enabled\n"}}
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []Result{{ExitCode: 0, Stdout: "active\n"}}
	runner.results["/usr/bin/systemctl is-active pipewire.service"] = []Result{{ExitCode: 0, Stdout: "active\n"}}
	review := planFor(DesiredState{Modules: []string{"wanted"}}, runner, compiled).review()
	if !review.Blocked() || len(review.Changes) != 0 || len(review.Blockers) != 1 || review.Blockers[0].Subject != "service-conflict:networkmanager:pipewire" {
		t.Fatalf("review=%#v", review)
	}
}

func TestConflictGuardFailsClosedBeforeMutation(t *testing.T) {
	behavior := services{manager: systemd, path: "/usr/bin/systemctl"}
	conflict := resolvedServiceConflict{
		conflict: serviceConflict{wanted: "networkmanager", other: "pipewire", scope: SystemService},
		wanted:   "NetworkManager.service",
		other:    "pipewire.service",
	}
	plan := readyPlan{bound: boundSelection{services: behavior, conflicts: []resolvedServiceConflict{conflict}}}
	for _, test := range []struct {
		name  string
		state Result
		stale bool
		err   bool
	}{
		{name: "became active", state: Result{ExitCode: 0, Stdout: "active\n"}, stale: true},
		{name: "became indeterminate", state: Result{ExitCode: 1, Stdout: "mystery\n"}, err: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
				"/usr/bin/systemctl is-active pipewire.service": {test.state},
			}}
			stale, err := plan.guardConflicts(context.Background(), runner)
			if stale != test.stale || (err != nil) != test.err {
				t.Fatalf("stale=%t err=%v", stale, err)
			}
		})
	}
}

func TestServiceGuardCoversRequirementsWithoutSteps(t *testing.T) {
	behavior := services{manager: systemd, path: "/usr/bin/systemctl"}
	need := serviceNeed{key: "networkmanager", scope: SystemService, target: serviceEnabled}
	resolved := resolvedServiceNeed{need: need, unit: "NetworkManager.service"}
	plan := readyPlan{
		bound:    boundSelection{services: behavior, serviceNeeds: []resolvedServiceNeed{resolved}},
		services: serviceObservations{need: serviceSatisfied{need: need, unit: resolved.unit, detail: "enabled"}},
	}
	for _, test := range []struct {
		name  string
		state Result
		stale bool
		err   bool
	}{
		{name: "satisfied service drifted", state: Result{ExitCode: 1, Stdout: "disabled\n"}, stale: true},
		{name: "service became indeterminate", state: Result{ExitCode: 1, Stdout: "mystery\n"}, err: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
				"/usr/bin/systemctl is-enabled NetworkManager.service": {test.state},
			}}
			stale, err := plan.guardServices(context.Background(), runner)
			if stale != test.stale || (err != nil) != test.err {
				t.Fatalf("stale=%t err=%v", stale, err)
			}
		})
	}
}

func TestMissingPackagePlansBeforeServiceObservation(t *testing.T) {
	runner := baseRunner()
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "base\n"}}
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{ExitCode: 0}}
	plan := Plan(DesiredState{Modules: []string{"network"}}, runner)
	if plan.Blocked() || len(plan.Changes) != 1 || !containsString(runner.calls, rpmInventoryCommand()) || containsString(runner.calls, "/usr/bin/systemctl is-enabled NetworkManager.service") {
		t.Fatalf("plan=%#v calls=%#v", plan, runner.calls)
	}
}

func TestApplyFreshPlanExecutesCanonicalServiceSteps(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	if review.Blocked() || len(review.Changes) != 2 {
		t.Fatalf("review=%#v", review)
	}
	runner := networkApplyRunner()
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Succeeded || receipt.AcceptedDigest != review.Digest() || receipt.PlanDigest != review.Digest() || len(receipt.Outcomes) != 2 {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	wantMutations := []string{
		"/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service",
		"/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service",
	}
	for _, want := range wantMutations {
		if !containsString(runner.calls, want) {
			t.Fatalf("calls=%#v missing=%q", runner.calls, want)
		}
	}
}

func TestApplyUsesOneGlobalAndOneImmediateServiceGuard(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Succeeded {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, rpmInventoryCommand()) != 3 {
		t.Fatalf("package inventory was not rechecked: %#v", runner.calls)
	}
	if countString(runner.calls, "/usr/bin/systemctl is-enabled NetworkManager.service") != 5 || countString(runner.calls, "/usr/bin/systemctl is-active NetworkManager.service") != 5 {
		t.Fatalf("service guards or final verification were duplicated or skipped: %#v", runner.calls)
	}
}

func TestApplyPreparesAuthorityBeforeGlobalGuards(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Succeeded {
		t.Fatalf("receipt=%#v events=%#v", receipt, runner.events)
	}
	lastPath, secondInventory, inventories := -1, -1, 0
	for index, event := range runner.events {
		if strings.HasPrefix(event, "path:") {
			lastPath = index
		}
		if event == "run:"+rpmInventoryCommand() {
			inventories++
			if inventories == 2 {
				secondInventory = index
			}
		}
	}
	if lastPath < 0 || secondInventory < 0 || lastPath >= secondInventory {
		t.Fatalf("authority was not prepared before global guards: %#v", runner.events)
	}
}

func TestApplyPackageGuardDistinguishesDriftFromUnknown(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	for _, test := range []struct {
		name   string
		guard  Result
		status RunStatus
	}{
		{name: "package disappeared", guard: Result{ExitCode: 0, Stdout: "other\n"}, status: Stale},
		{name: "inventory failed", guard: Result{ExitCode: 1, Stderr: "rpm failed"}, status: Failed},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := networkApplyRunner()
			runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "NetworkManager\n"}, test.guard}
			receipt := Apply(state, runner, review.Digest())
			if receipt.Status != test.status || hasMutation(runner.calls) {
				t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
			}
		})
	}
}

func TestApplyFailsOnIndeterminateGlobalServiceEvidence(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "mystery\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 0 || hasMutation(runner.calls) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyFailsWhenFinalAggregatePackageEvidenceRegresses(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results[rpmInventoryCommand()] = []Result{
		{ExitCode: 0, Stdout: "NetworkManager\n"},
		{ExitCode: 0, Stdout: "NetworkManager\n"},
		{ExitCode: 0, Stdout: "other\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != Applied || receipt.Outcomes[1].Status != Applied || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "final:packages" {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyFailsWhenFinalAggregateServiceRegresses(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{
		{ExitCode: 1, Stdout: "disabled\n"}, {ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 0, Stdout: "enabled\n"}, {ExitCode: 1, Stdout: "disabled\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Blockers) == 0 || receipt.Blockers[0].Subject != "final:service:networkmanager" || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != Applied || receipt.Outcomes[1].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyDistinguishesStaleAndBlockedReceipts(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	staleRunner := networkPlanRunner()
	stale := Apply(state, staleRunner, "sha256:wrong")
	if stale.Status != Stale || stale.AcceptedDigest != "sha256:wrong" || stale.PlanDigest == "" || hasMutation(staleRunner.calls) {
		t.Fatalf("stale=%#v calls=%#v", stale, staleRunner.calls)
	}

	blockedState := DesiredState{Modules: []string{"unknown"}}
	blockedRunner := baseRunner()
	blockedReview := Plan(blockedState, blockedRunner)
	blockedApply := baseRunner()
	blocked := Apply(blockedState, blockedApply, blockedReview.Digest())
	if blocked.Status != Blocked || len(blocked.Blockers) == 0 || len(blocked.Outcomes) != 0 {
		t.Fatalf("blocked=%#v", blocked)
	}
}

func TestApplyRunsAllPreconditionsBeforeFirstMutation(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []Result{
		{ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 0, Stdout: "active\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || hasMutation(runner.calls) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyRetainsVerifiedOutcomeOnInterstepDrift(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []Result{
		{ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 0, Stdout: "active\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != Applied || receipt.Outcomes[1].Status != Unattempted {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if !containsString(runner.calls, "/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service") || containsString(runner.calls, "/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service") {
		t.Fatalf("calls=%#v", runner.calls)
	}
}

func TestApplyStopsAfterCommandFailure(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service"] = []Result{{ExitCode: 1, Stderr: "denied"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != FailedAction || receipt.Outcomes[1].Status != Unattempted {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if containsString(runner.calls, "/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service") {
		t.Fatalf("calls=%#v", runner.calls)
	}
	if !strings.Contains(receipt.Outcomes[0].Detail, "post-state") {
		t.Fatalf("outcome=%#v", receipt.Outcomes[0])
	}
}

func TestApplyStopsAfterPostStateVerificationFailure(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "enabled\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != FailedAction || receipt.Outcomes[1].Status != Unattempted {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if containsString(runner.calls, "/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service") {
		t.Fatalf("calls=%#v", runner.calls)
	}
}

func TestPlanDoesNotProbeUserManagerForEnableOnlyWork(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 4)
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "pipewire\nwireplumber\npipewire-pulseaudio\nalsa-utils\n"}}
	runner.results["/usr/bin/systemctl --user is-enabled pipewire.service wireplumber.service"] = []Result{{ExitCode: 1, Stdout: "disabled\ndisabled\n"}}
	runner.results["/usr/bin/systemctl --user is-active pipewire.service wireplumber.service"] = []Result{{ExitCode: 0, Stdout: "active\nactive\n"}}
	plan := Plan(audioDesiredState(), runner)
	if plan.Blocked() || len(plan.Changes) != 1 || containsString(runner.calls, "/usr/bin/systemctl --user show-environment") {
		t.Fatalf("plan=%#v calls=%#v", plan, runner.calls)
	}
}

func TestApplyRejectsChangedPrivilegeAdapterAsStale(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	review := Plan(state, networkPlanRunner())
	runner := networkApplyRunner()
	useDoas(runner)
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || hasMutation(runner.calls) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestPlanAndApplyPreserveExactDoasCommands(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	reviewRunner := networkPlanRunner()
	useDoas(reviewRunner)
	review := Plan(state, reviewRunner)
	if review.Blocked() || len(review.Changes) != 2 {
		t.Fatalf("review=%#v calls=%#v", review, reviewRunner.calls)
	}
	for _, change := range review.Changes {
		if change.Command == nil || !strings.HasPrefix(change.Command.String(), "/usr/bin/doas -n /usr/bin/systemctl ") {
			t.Fatalf("change=%#v", change)
		}
	}

	applyRunner := networkApplyRunner()
	useDoas(applyRunner)
	receipt := Apply(state, applyRunner, review.Digest())
	if receipt.Status != Succeeded {
		t.Fatalf("receipt=%#v calls=%#v", receipt, applyRunner.calls)
	}
	for _, action := range []string{"enable", "start"} {
		want := "/usr/bin/doas -n /usr/bin/systemctl " + action + " NetworkManager.service"
		if !containsString(applyRunner.calls, want) {
			t.Fatalf("missing %q: calls=%#v", want, applyRunner.calls)
		}
	}
}

func TestServiceBehaviorBindsResolvedSystemctlPath(t *testing.T) {
	runner := networkPlanRunner()
	runner.paths["systemctl"] = "/opt/proofstrap/bin/systemctl"
	for _, suffix := range []string{
		"is-enabled NetworkManager.service",
		"is-active NetworkManager.service",
	} {
		resolved := "/opt/proofstrap/bin/systemctl " + suffix
		runner.results[resolved] = runner.results["/usr/bin/systemctl "+suffix]
		delete(runner.results, "/usr/bin/systemctl "+suffix)
	}
	review := Plan(DesiredState{Modules: []string{"network"}}, runner)
	if review.Blocked() || len(review.Changes) != 2 {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
	for _, change := range review.Changes {
		if change.Command == nil || !strings.Contains(change.Command.String(), "/opt/proofstrap/bin/systemctl") {
			t.Fatalf("change=%#v", change)
		}
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "systemctl ") {
			t.Fatalf("bare service lookup reached execution: calls=%#v", runner.calls)
		}
	}
	if countString(runner.pathCalls, "systemctl") != 1 {
		t.Fatalf("systemctl was resolved more than once: pathCalls=%#v", runner.pathCalls)
	}
}

func TestPlanAndApplyUseResolvedPrivilegeExecutable(t *testing.T) {
	state := DesiredState{Modules: []string{"network"}}
	reviewRunner := networkPlanRunner()
	reviewRunner.paths["sudo"] = "/opt/proofstrap/bin/sudo"
	reviewRunner.results["/opt/proofstrap/bin/sudo -N -n -v"] = reviewRunner.results["/usr/bin/sudo -N -n -v"]
	delete(reviewRunner.results, "/usr/bin/sudo -N -n -v")

	review := Plan(state, reviewRunner)
	if review.Blocked() || len(review.Changes) != 2 || review.Changes[0].Command == nil || review.Changes[0].Command.Name != "/opt/proofstrap/bin/sudo" {
		t.Fatalf("review=%#v calls=%#v", review, reviewRunner.calls)
	}

	applyRunner := networkApplyRunner()
	applyRunner.paths["sudo"] = "/opt/proofstrap/bin/sudo"
	applyRunner.results["/opt/proofstrap/bin/sudo -N -n -v"] = applyRunner.results["/usr/bin/sudo -N -n -v"]
	delete(applyRunner.results, "/usr/bin/sudo -N -n -v")
	for _, action := range []string{"enable", "start"} {
		bare := "/usr/bin/sudo -N -n /usr/bin/systemctl " + action + " NetworkManager.service"
		resolved := "/opt/proofstrap/bin/sudo -N -n /usr/bin/systemctl " + action + " NetworkManager.service"
		applyRunner.results[resolved] = applyRunner.results[bare]
		delete(applyRunner.results, bare)
	}

	receipt := Apply(state, applyRunner, review.Digest())
	if receipt.Status != Succeeded {
		t.Fatalf("receipt=%#v calls=%#v", receipt, applyRunner.calls)
	}
	for _, call := range applyRunner.calls {
		if strings.HasPrefix(call, "sudo ") {
			t.Fatalf("bare privilege lookup reached execution: calls=%#v", applyRunner.calls)
		}
	}
	if countString(applyRunner.pathCalls, "systemctl") != 1 {
		t.Fatalf("systemctl was resolved after command preparation: pathCalls=%#v", applyRunner.pathCalls)
	}
}

func containsFact(facts []Fact, subject, detail string) bool {
	for _, fact := range facts {
		if fact.Subject == subject && strings.Contains(fact.Detail, detail) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func hasMutation(calls []string) bool {
	for _, call := range calls {
		if strings.Contains(call, "/usr/bin/systemctl enable") || strings.Contains(call, "/usr/bin/systemctl start") {
			return true
		}
	}
	return false
}

func rpmInventoryCommand() string { return "/usr/bin/rpm -qa --qf %{NAME}\\n" }

func baseRunner() *testRunner {
	return &testRunner{
		uid:              1000,
		executable:       "/usr/bin/proofstrap",
		executableDigest: "sha256:proofstrap-test",
		files: map[string][]byte{
			"/etc/os-release":             []byte("ID=opensuse-tumbleweed\n"),
			"/proc/1/comm":                []byte("systemd\n"),
			"/var/lib/zypp/AutoInstalled": {},
		},
		paths:   map[string]string{"zypper": "/usr/bin/zypper", "rpm": "/usr/bin/rpm", "systemctl": "/usr/bin/systemctl", "sudo": "/usr/bin/sudo"},
		results: map[string][]Result{"/usr/bin/zypper --version": {{ExitCode: 0, Stdout: "zypper 1.14.87\n"}}},
	}
}

func audioDesiredState() DesiredState {
	state, err := newDesiredState([]string{"audio"}, existingAccountIntent{name: "alice"})
	if err != nil {
		panic(err)
	}
	return state
}

func swayRunner() *testRunner {
	runner := baseRunner()
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "dbus-1\nlibwayland-client0\nsway\nswayidle\nswaylock\ngrim\nslurp\nhyprland\n"}}
	return runner
}

func networkPlanRunner() *testRunner {
	runner := baseRunner()
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "NetworkManager\n"}}
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{{ExitCode: 1, Stdout: "disabled\n"}}
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []Result{{ExitCode: 3, Stdout: "inactive\n"}}
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{ExitCode: 0}}
	return runner
}

func networkApplyRunner() *testRunner {
	runner := baseRunner()
	runner.results[rpmInventoryCommand()] = []Result{{ExitCode: 0, Stdout: "NetworkManager\n"}, {ExitCode: 0, Stdout: "NetworkManager\n"}, {ExitCode: 0, Stdout: "NetworkManager\n"}}
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []Result{
		{ExitCode: 1, Stdout: "disabled\n"}, {ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 0, Stdout: "enabled\n"}, {ExitCode: 0, Stdout: "enabled\n"},
	}
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []Result{
		{ExitCode: 3, Stdout: "inactive\n"}, {ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 0, Stdout: "active\n"}, {ExitCode: 0, Stdout: "active\n"},
	}
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{ExitCode: 0}}
	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service"] = []Result{{ExitCode: 0}}
	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service"] = []Result{{ExitCode: 0}}
	return runner
}

func useDoas(runner *testRunner) {
	delete(runner.paths, "sudo")
	runner.paths["doas"] = "/usr/bin/doas"
	delete(runner.results, "/usr/bin/sudo -N -n -v")
	runner.results["/usr/bin/doas -n /usr/bin/true"] = []Result{{ExitCode: 0}}
	for _, action := range []string{"enable", "start"} {
		sudo := "/usr/bin/sudo -N -n /usr/bin/systemctl " + action + " NetworkManager.service"
		if results, ok := runner.results[sudo]; ok {
			runner.results["/usr/bin/doas -n /usr/bin/systemctl "+action+" NetworkManager.service"] = results
			delete(runner.results, sudo)
		}
	}
}

func packageRootChangeRunner(apply bool) *testRunner {
	runner := &testRunner{
		uid: 0,
		files: map[string][]byte{
			"/etc/os-release": []byte("ID=debian\n"),
			"/proc/1/comm":    []byte("openrc\n"),
		},
		paths: map[string]string{
			"apt-get": "/usr/bin/apt-get", "apt-mark": "/usr/bin/apt-mark", "dpkg-query": "/usr/bin/dpkg-query",
		},
		results: map[string][]Result{
			"/usr/bin/apt-get --version": {{Stdout: "apt 2.9.0\n"}},
			"/usr/bin/dpkg-query -W -f=${binary:Package}\\t${db:Status-Abbrev}\\n": {{Stdout: "dbus:amd64\tii \n"}},
			"/usr/bin/apt-mark showmanual":                                         {{Stdout: ""}},
		},
	}
	if apply {
		runner.results["/usr/bin/dpkg-query -W -f=${binary:Package}\\t${db:Status-Abbrev}\\n"] = []Result{
			{Stdout: "dbus:amd64	ii \n"}, {Stdout: "dbus:amd64	ii \n"}, {Stdout: "dbus:amd64	ii \n"},
		}
		runner.results["/usr/bin/apt-mark showmanual"] = []Result{{Stdout: ""}, {Stdout: ""}, {Stdout: "dbus\n"}}
		runner.results["/usr/bin/apt-mark manual dbus"] = []Result{{}}
	}
	return runner
}

func networkRootPlanRunner() *testRunner {
	runner := packageRootChangeRunner(false)
	runner.files["/proc/1/comm"] = []byte("systemd\n")
	runner.paths["systemctl"] = "/usr/bin/systemctl"
	for command := range runner.results {
		if strings.HasPrefix(command, "/usr/bin/dpkg-query ") {
			runner.results[command] = []Result{{Stdout: "network-manager:amd64	ii \n"}}
		}
	}
	return runner
}

func missingPackageRunner() *testRunner {
	runner := baseRunner()
	runner.uid = 0
	runner.results[rpmInventoryCommand()] = []Result{{Stdout: ""}}
	return runner
}
