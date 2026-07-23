package proofstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHostnameIntentAcceptsOnlyCanonicalLinuxNames(t *testing.T) {
	for _, valid := range []string{"node-1", "build-01.example", strings.Repeat("a", 62) + ".b"} {
		intent, err := newHostnameIntent(valid)
		if err != nil || intent.value != valid {
			t.Errorf("value=%q intent=%#v err=%v", valid, intent, err)
		}
	}
	for _, invalid := range []string{
		"", "Node-1", "node_1", "-node", "node-", ".node", "node.", "node..one",
		"node/{{name}}", "node 1", strings.Repeat("a", 65), strings.Repeat("a", 64) + ".b",
	} {
		if _, err := newHostnameIntent(invalid); err == nil {
			t.Errorf("invalid hostname %q was accepted", invalid)
		}
	}
}

func TestHostnameReconciliationDistinguishesExactChangeAndBlocked(t *testing.T) {
	intent, err := newHostnameIntent("node-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reconcileHostname(intent, hostnameObserved{persistent: "node-1", runtime: "node-1"}).(hostnameExact); !ok {
		t.Fatal("exact state did not reconcile as exact")
	}
	if change, ok := reconcileHostname(intent, hostnameObserved{persistent: "old", runtime: "other"}).(hostnameChange); !ok || change.before.persistent != "old" || change.before.runtime != "other" {
		t.Fatalf("change=%#v", change)
	}
	blocked := reconcileHostname(intent, hostnameObservationBlocked{blockerList: []Blocker{{Subject: "hostname:persistent", Detail: "unreadable"}}})
	if decision, ok := blocked.(hostnameBlocked); !ok || len(decision.blockers) != 1 {
		t.Fatalf("blocked=%#v", blocked)
	}
}

func TestHostnameObservationRequiresExactSingleRecords(t *testing.T) {
	for name, runner := range map[string]*testRunner{
		"missing persistent": {files: map[string][]byte{"/proc/sys/kernel/hostname": []byte("node-1\n")}},
		"multiple persistent records": {files: map[string][]byte{
			"/etc/hostname": []byte("node-1\nother\n"), "/proc/sys/kernel/hostname": []byte("node-1\n"),
		}},
		"empty runtime": {files: map[string][]byte{"/etc/hostname": []byte("node-1\n"), "/proc/sys/kernel/hostname": {}}},
	} {
		t.Run(name, func(t *testing.T) {
			if observed := observeHostname(runner); len(observed.blockers()) == 0 {
				t.Fatalf("observation=%#v", observed)
			}
		})
	}
}

func TestExactHostnameNeedsNoMutatorOrAuthority(t *testing.T) {
	state := hostnameState("node-1")
	runner := hostnameRunner(hostnameRead("node-1"))
	runner.files["/proc/1/comm"] = []byte("openrc\n")
	review := Plan(state, runner)
	if review.Blocked() || len(review.Changes) != 0 || review.HostSettings == nil || review.HostSettings.Hostname != "node-1" {
		t.Fatalf("review=%#v", review)
	}
	if containsString(runner.pathCalls, "hostnamectl") || runner.euidCalls != 0 {
		t.Fatalf("paths=%#v euidCalls=%d", runner.pathCalls, runner.euidCalls)
	}
}

func TestHostnameChangePlansOneNoninteractiveStaticAndTransientCommand(t *testing.T) {
	state := hostnameState("node-1")
	state.Modules = []string{"curl"}
	runner := hostnameRunner(hostnameRead("old"))
	review := Plan(state, runner)
	want := "/usr/bin/hostnamectl --no-ask-password --static --transient set-hostname node-1"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "hostname" || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v paths=%#v calls=%#v", review, runner.pathCalls, runner.calls)
	}
	if containsString(runner.pathCalls, "zypper") || containsString(runner.pathCalls, "systemctl") {
		t.Fatalf("unrelated behavior admitted: %#v", runner.pathCalls)
	}
}

func TestHostnameChangeCannotBypassMissingAccountPrerequisite(t *testing.T) {
	runner := hostnameRunner(hostnameRead("old"))
	state := hostnameState("node-1")
	state.Modules = []string{"audio"}
	review := Plan(state, runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "user-service demand requires an explicit account") || len(review.Changes) != 0 || len(runner.fileResults[persistentHostnamePath]) != 1 || containsString(runner.pathCalls, "hostnamectl") {
		t.Fatalf("review=%#v pathCalls=%#v hostnameReads=%#v", review, runner.pathCalls, runner.fileResults[persistentHostnamePath])
	}
}

func TestHostnameChangeUsesExistingNoninteractiveRootAuthority(t *testing.T) {
	state := hostnameState("node-1")
	runner := hostnameRunner(hostnameRead("old"))
	runner.uid = 1000
	runner.paths["sudo"] = "/usr/bin/sudo"
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{ExitCode: 0}}
	review := Plan(state, runner)
	want := "/usr/bin/sudo -N -n /usr/bin/hostnamectl --no-ask-password --static --transient set-hostname node-1"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestDesiredHostnameChangesReviewDigest(t *testing.T) {
	first := Plan(hostnameState("node-1"), hostnameRunner(hostnameRead("old")))
	second := Plan(hostnameState("node-2"), hostnameRunner(hostnameRead("old")))
	if first.Digest() == second.Digest() {
		t.Fatalf("hostname intent is not digest-bound: %s", first.Digest())
	}
}

func TestExactHostnameBindingPropagatesToPackagePlan(t *testing.T) {
	runner := missingPackageRunner()
	runner.files[persistentHostnamePath] = []byte("node-1\n")
	runner.files[runtimeHostnamePath] = []byte("node-1\n")
	state := hostnameState("node-1")
	state.Modules = []string{"curl"}
	planned := planFor(state, runner, production)
	install, ok := planned.(installPlan)
	if !ok || install.host.hostname == nil || install.host.hostname.intent.value != "node-1" {
		t.Fatalf("planned=%#v", planned)
	}
}

func TestHostnameChangeRequiresSystemdAndHostnamectl(t *testing.T) {
	for name, configure := range map[string]func(*testRunner){
		"unsupported pid1":    func(runner *testRunner) { runner.files["/proc/1/comm"] = []byte("openrc\n") },
		"missing hostnamectl": func(runner *testRunner) { delete(runner.paths, "hostnamectl") },
	} {
		t.Run(name, func(t *testing.T) {
			runner := hostnameRunner(hostnameRead("old"))
			configure(runner)
			review := Plan(hostnameState("node-1"), runner)
			if !review.Blocked() || len(review.Changes) != 0 || len(review.Blockers) == 0 || !strings.HasPrefix(review.Blockers[0].Subject, "hostname") {
				t.Fatalf("review=%#v", review)
			}
		})
	}
}

func TestHostnameApplyVerifiesBothStatesAndRequiresReplan(t *testing.T) {
	state := hostnameState("node-1")
	review := Plan(state, hostnameRunner(hostnameRead("old")))
	runner := hostnameRunner(hostnameRead("old"), hostnameRead("old"), hostnameRead("node-1"))
	runner.results[hostnameCommand("node-1")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v events=%#v", receipt, runner.calls, runner.events)
	}
}

func TestHostnameApplyRejectsImmediateDriftWithoutMutation(t *testing.T) {
	state := hostnameState("node-1")
	review := Plan(state, hostnameRunner(hostnameRead("old")))
	runner := hostnameRunner(hostnameRead("old"), hostnameRead("drifted"))
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, hostnameCommand("node-1")) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestExactHostnameDriftStopsUnrelatedAction(t *testing.T) {
	runner := hostnameRunner(hostnameRead("node-1"), hostnameRead("drifted"))
	plannedStep := step{
		id: "service:start", detail: "start", access: rootStep,
		command: Command{Name: "/usr/bin/start"},
		before:  func(context.Context, Runner) error { return nil },
		verify:  func(context.Context, Runner) (bool, string) { return true, "active" },
	}
	projection := plannedStep.projection()
	plan := readyPlan{
		plan: ReviewPlan{Changes: []Change{projection}},
		host: hostBinding{
			facts:    observeHost(runner).facts,
			hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
		},
		steps: []step{plannedStep}, commands: []Command{plannedStep.command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/bin/start") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestExactHostnameDriftAfterAppliedActionFailsRemainingActions(t *testing.T) {
	runner := hostnameRunner(hostnameRead("node-1"), hostnameRead("node-1"), hostnameRead("drifted"))
	steps := []step{
		{id: "service:first", detail: "first", access: rootStep, command: Command{Name: "/usr/bin/first"}, before: func(context.Context, Runner) error { return nil }, verify: func(context.Context, Runner) (bool, string) { return true, "active" }},
		{id: "service:second", detail: "second", access: rootStep, command: Command{Name: "/usr/bin/second"}, before: func(context.Context, Runner) error { return nil }, verify: func(context.Context, Runner) (bool, string) { return true, "active" }},
	}
	runner.results["/usr/bin/first"] = []Result{{}}
	plan := readyPlan{
		plan: ReviewPlan{Changes: []Change{steps[0].projection(), steps[1].projection()}},
		host: hostBinding{
			facts:    observeHost(runner).facts,
			hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
		},
		steps: steps, commands: []Command{steps[0].command, steps[1].command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != Applied || receipt.Outcomes[1].Status != Unattempted || containsString(runner.calls, "/usr/bin/second") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestUnreadableExactHostnameGuardFailsInsteadOfReportingStale(t *testing.T) {
	read := hostnameRead("node-1")
	read[0].err = errors.New("persistent unavailable")
	runner := hostnameRunner(read)
	plan := readyPlan{host: hostBinding{
		facts:    observeHost(runner).facts,
		hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
	}}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:host" {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestUnreadableExactHostnameImmediatelyBeforeActionFailsUnattempted(t *testing.T) {
	unreadable := hostnameRead("node-1")
	unreadable[1].err = errors.New("runtime unavailable")
	runner := hostnameRunner(hostnameRead("node-1"), unreadable)
	plannedStep := step{
		id: "service:start", detail: "start", access: rootStep,
		command: Command{Name: "/usr/bin/start"},
		before:  func(context.Context, Runner) error { return nil },
		verify:  func(context.Context, Runner) (bool, string) { return true, "active" },
	}
	projection := plannedStep.projection()
	plan := readyPlan{
		plan: ReviewPlan{Changes: []Change{projection}},
		host: hostBinding{
			facts:    observeHost(runner).facts,
			hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
		},
		steps: []step{plannedStep}, commands: []Command{plannedStep.command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:host" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/bin/start") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestUnreadableExactHostnameImmediatelyBeforePackageMutationFailsUnattempted(t *testing.T) {
	unreadable := hostnameRead("node-1")
	unreadable[0].err = errors.New("persistent unavailable")
	runner := hostnameRunner(hostnameRead("node-1"), unreadable)
	command := Command{Name: "/usr/bin/zypper", Args: []string{"install", "curl"}}
	projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
	change := Change{ID: "package-install:zypper", Command: &projected}
	plan := packagePlan{
		plan: ReviewPlan{Changes: []Change{change}},
		host: hostBinding{
			facts:    observeHost(runner).facts,
			hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
		},
		projection: change, command: command,
	}
	receipt := plan.apply(runner, ApplyReceipt{}, func(_ context.Context, _ Runner, _ Command, guard packageMutationGuard) packageResult {
		return packageResult{err: guard()}
	})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:host" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestHostnameOnlyApplyRejectsFinalDrift(t *testing.T) {
	runner := hostnameRunner(hostnameRead("node-1"), hostnameRead("drifted"))
	plan := readyPlan{host: hostBinding{
		facts:    observeHost(runner).facts,
		hostname: &hostnameBinding{intent: hostnameIntent{value: "node-1"}},
	}}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "final:host" {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestHostnameApplyReportsAppliedWhenFailedCommandReachedExactPostState(t *testing.T) {
	state := hostnameState("node-1")
	review := Plan(state, hostnameRunner(hostnameRead("old")))
	runner := hostnameRunner(hostnameRead("old"), hostnameRead("old"), hostnameRead("node-1"))
	runner.results[hostnameCommand("node-1")] = []Result{{ExitCode: 1, Stderr: "late failure"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied || !strings.Contains(receipt.Outcomes[0].Detail, "late failure") || !strings.Contains(receipt.Outcomes[0].Detail, "persistent=node-1; runtime=node-1") {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestHostnameApplyReportsFailedCommandWithPartialPostState(t *testing.T) {
	state := hostnameState("node-1")
	review := Plan(state, hostnameRunner(hostnameRead("old")))
	runner := hostnameRunner(hostnameRead("old"), hostnameRead("old"), hostnameReadPair("node-1", "old"))
	runner.results[hostnameCommand("node-1")] = []Result{{ExitCode: 1, Stderr: "denied"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction || !strings.Contains(receipt.Outcomes[0].Detail, "persistent=node-1") || !strings.Contains(receipt.Outcomes[0].Detail, "runtime=old") {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestHostnameApplyFailsWhenPostObservationIsIndeterminate(t *testing.T) {
	state := hostnameState("node-1")
	review := Plan(state, hostnameRunner(hostnameRead("old")))
	post := hostnameRead("node-1")
	post[0].err = errors.New("persistent unavailable")
	runner := hostnameRunner(hostnameRead("old"), hostnameRead("old"), post)
	runner.results[hostnameCommand("node-1")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func hostnameState(value string) DesiredState {
	intent, err := newHostnameIntent(value)
	if err != nil {
		panic(err)
	}
	return DesiredState{machine: &machineIntent{hostname: &intent}}
}

func hostnameRunner(reads ...[]fileResult) *testRunner {
	runner := &testRunner{
		files: map[string][]byte{
			"/etc/os-release": []byte("ID=opensuse-tumbleweed\n"),
			"/proc/1/comm":    []byte("systemd\n"),
		},
		fileResults: map[string][]fileResult{},
		paths:       map[string]string{"hostnamectl": "/usr/bin/hostnamectl"},
		results:     map[string][]Result{},
	}
	for _, read := range reads {
		runner.fileResults["/etc/hostname"] = append(runner.fileResults["/etc/hostname"], read[0])
		runner.fileResults["/proc/sys/kernel/hostname"] = append(runner.fileResults["/proc/sys/kernel/hostname"], read[1])
	}
	return runner
}

func hostnameRead(value string) []fileResult { return hostnameReadPair(value, value) }

func hostnameReadPair(persistent, runtime string) []fileResult {
	return []fileResult{{contents: []byte(persistent + "\n")}, {contents: []byte(runtime + "\n")}}
}

func hostnameCommand(value string) string {
	return "/usr/bin/hostnamectl --no-ask-password --static --transient set-hostname " + value
}
