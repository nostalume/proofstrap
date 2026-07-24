package proofstrap

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestTimezoneIntentRejectsNoncanonicalZoneinfoPaths(t *testing.T) {
	for _, value := range []string{"", "/UTC", "../UTC", "Europe//Berlin", "Europe/../UTC", "Europe/Berlin!", "Vendor/Foo.Bar"} {
		if _, err := newTimezoneIntent(value); err == nil {
			t.Fatalf("timezone %q was accepted", value)
		}
	}
}

func TestExactTimezoneNeedsNoMutatorAuthorityOrRTCInspection(t *testing.T) {
	runner := timezoneRunner("Europe/Berlin")
	review := Plan(timezoneState("Europe/Berlin"), runner)
	if review.Blocked() || len(review.Changes) != 0 || review.HostSettings == nil || review.HostSettings.Timezone != "Europe/Berlin" || !containsFact(review.Facts, "timezone", "Europe/Berlin") {
		t.Fatalf("review=%#v", review)
	}
	if containsString(runner.pathCalls, "timedatectl") || runner.euidCalls != 0 || containsString(runner.calls, timezoneRTCCommand()) {
		t.Fatalf("paths=%#v events=%#v euid=%d", runner.pathCalls, runner.events, runner.euidCalls)
	}
}

func TestTimezoneChangePlansOneNoninteractiveCommand(t *testing.T) {
	runner := timezoneRunner("Etc/UTC")
	review := Plan(timezoneState("Europe/Berlin"), runner)
	want := "/usr/bin/timedatectl --no-ask-password set-timezone Europe/Berlin"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "timezone" || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestTimezoneChangeBlocksWhenRTCUsesLocalTime(t *testing.T) {
	runner := timezoneRunner("Etc/UTC")
	runner.results[timezoneRTCCommand()] = []Result{{ExitCode: 0, Stdout: "yes\n"}}
	review := Plan(timezoneState("Europe/Berlin"), runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "RTC uses local time") || len(review.Changes) != 0 || runner.euidCalls != 0 {
		t.Fatalf("review=%#v", review)
	}
}

func TestTimezoneApplyVerifiesExactPostStateAndRequiresReplan(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC", "Europe/Berlin")
	runner.results[timezoneCommand("Europe/Berlin")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied || !strings.Contains(receipt.Outcomes[0].Detail, "Europe/Berlin") {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestTimezoneChangeCannotBypassMissingAccountPrerequisite(t *testing.T) {
	runner := timezoneRunner("Etc/UTC")
	state := timezoneState("Europe/Berlin")
	state.Modules = []string{"audio"}
	review := Plan(state, runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "user-service demand requires an explicit account") || len(runner.lstats[localtimePath]) != 1 || containsString(runner.pathCalls, "timedatectl") {
		t.Fatalf("review=%#v events=%#v", review, runner.events)
	}
}

func TestExactTimezoneBindingPropagatesToPackagePlan(t *testing.T) {
	runner := missingPackageRunner()
	timezone := timezoneRunner("Europe/Berlin")
	runner.readlinks, runner.evalSymlinks, runner.lstats = timezone.readlinks, timezone.evalSymlinks, timezone.lstats
	runner.files[zoneinfoRoot+"/Europe/Berlin"] = timezone.files[zoneinfoRoot+"/Europe/Berlin"]
	state := timezoneState("Europe/Berlin")
	state.Modules = []string{"curl"}
	planned := planFor(state, runner, production)
	install, ok := planned.(installPlan)
	if !ok || install.host.timezone == nil || install.host.timezone.intent.value != "Europe/Berlin" {
		t.Fatalf("planned=%#v", planned)
	}
}

func TestExactTimezoneDriftStopsUnrelatedAction(t *testing.T) {
	runner := timezoneRunner("Europe/Berlin", "Etc/UTC")
	plannedStep := step{id: "service:start", detail: "start", access: rootStep, command: Command{Name: "/usr/bin/start"}, before: func(context.Context, Runner) error { return nil }, verify: func(context.Context, Runner) (bool, string) { return true, "active" }}
	projection := plannedStep.projection()
	plan := readyPlan{
		plan:  ReviewPlan{Changes: []Change{projection}},
		host:  hostBinding{facts: observeHost(runner).facts, timezone: &timezoneBinding{intent: mustTimezone("Europe/Berlin")}},
		steps: []step{plannedStep}, commands: []Command{plannedStep.command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/bin/start") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestTimezoneFailedCommandWithExactPostStateReportsApplied(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC", "Europe/Berlin")
	runner.results[timezoneCommand("Europe/Berlin")] = []Result{{ExitCode: 1, Stderr: "late failure"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied || !strings.Contains(receipt.Outcomes[0].Detail, "late failure") {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestTimezoneFailedCommandAndFinalHostDriftPreserveBothEvidence(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC", "Europe/Berlin")
	runner.fileResults["/proc/1/comm"] = []fileResult{
		{contents: []byte("systemd\n")},
		{contents: []byte("systemd\n")},
		{contents: []byte("systemd\n")},
		{contents: []byte("openrc\n")},
	}
	runner.results[timezoneCommand("Europe/Berlin")] = []Result{{ExitCode: 1, Stderr: "late failure"}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "final:host" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied || !strings.Contains(receipt.Outcomes[0].Detail, "late failure") || !strings.Contains(receipt.Outcomes[0].Detail, "host evidence changed") {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestTimezoneObservationRejectsNonSymlinkAndOutsideTarget(t *testing.T) {
	nonlink := timezoneRunner()
	nonlink.lstats[localtimePath] = []pathResult{{info: PathInfo{Kind: RegularPath}}}
	outside := timezoneRunner()
	outside.lstats[localtimePath] = []pathResult{{info: PathInfo{Kind: SymlinkPath}}}
	outside.readlinks[localtimePath] = []linkResult{{target: "/tmp/UTC"}}
	for _, runner := range []*testRunner{nonlink, outside} {
		if _, ok := reconcileTimezone(mustTimezone("UTC"), observeTimezone(runner)).(timezoneBlocked); !ok {
			t.Fatalf("timezone observation was admitted")
		}
	}
}

func TestMissingLocaltimeIsExactUTCDefault(t *testing.T) {
	runner := timezoneRunner()
	runner.lstats[localtimePath] = []pathResult{{err: os.ErrNotExist}}
	if _, ok := reconcileTimezone(mustTimezone("UTC"), observeTimezone(runner)).(timezoneExact); !ok {
		t.Fatal("missing /etc/localtime was not treated as UTC")
	}
}

func TestTimezoneObservationAcceptsUTCSymlinkWithoutInstalledZonefile(t *testing.T) {
	runner := timezoneRunner()
	runner.lstats[localtimePath] = []pathResult{{info: PathInfo{Kind: SymlinkPath}}}
	runner.readlinks[localtimePath] = []linkResult{{target: "/usr/share/zoneinfo/UTC"}}
	if _, ok := reconcileTimezone(mustTimezone("UTC"), observeTimezone(runner)).(timezoneExact); !ok {
		t.Fatal("UTC symlink without installed zonefile was not admitted")
	}
}

func TestTimezoneChangeToUTCDoesNotRequireInstalledZonefile(t *testing.T) {
	state := timezoneState("UTC")
	review := Plan(state, timezoneRunner("Europe/Berlin"))
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != timezoneCommand("UTC") {
		t.Fatalf("review=%#v", review)
	}
	runner := timezoneRunner("Europe/Berlin", "Europe/Berlin")
	runner.lstats[localtimePath] = append(runner.lstats[localtimePath], pathResult{err: os.ErrNotExist})
	runner.results[timezoneCommand("UTC")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestTimezoneBecomingExactBeforeMutationIsStaleWithUnattemptedOutcome(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Europe/Berlin")
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || !strings.Contains(receipt.Outcomes[0].Detail, "already exact") || containsString(runner.calls, timezoneCommand("Europe/Berlin")) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestTimezoneObservationAcceptsAbsoluteZoneinfoSymlink(t *testing.T) {
	runner := timezoneRunner()
	runner.lstats[localtimePath] = []pathResult{{info: PathInfo{Kind: SymlinkPath}}}
	runner.readlinks[localtimePath] = []linkResult{{target: "/usr/share/zoneinfo/Etc/UTC"}}
	runner.evalSymlinks[zoneinfoRoot+"/Etc/UTC"] = []linkResult{{target: zoneinfoRoot + "/Etc/UTC"}}
	runner.lstats[zoneinfoRoot+"/Etc/UTC"] = []pathResult{{info: PathInfo{Kind: RegularPath}}}
	runner.files[zoneinfoRoot+"/Etc/UTC"] = []byte("TZif")
	if _, ok := reconcileTimezone(mustTimezone("Etc/UTC"), observeTimezone(runner)).(timezoneExact); !ok {
		t.Fatal("absolute zoneinfo symlink was not admitted")
	}
}

func TestTimezoneObservationAcceptsZoneinfoAliasThatResolvesToTZif(t *testing.T) {
	runner := timezoneRunner("Europe/Berlin")
	runner.lstats[zoneinfoRoot+"/Europe/Berlin"][0] = pathResult{info: PathInfo{Kind: SymlinkPath}}
	runner.evalSymlinks[zoneinfoRoot+"/Europe/Berlin"][0] = linkResult{target: zoneinfoRoot + "/Etc/UTC"}
	runner.lstats[zoneinfoRoot+"/Etc/UTC"] = []pathResult{{info: PathInfo{Kind: RegularPath}}}
	runner.files[zoneinfoRoot+"/Etc/UTC"] = []byte("TZif")
	if _, ok := reconcileTimezone(mustTimezone("Europe/Berlin"), observeTimezone(runner)).(timezoneExact); !ok {
		t.Fatal("zoneinfo alias resolving to TZif was not admitted")
	}
	if !containsString(runner.events, "prefix:4:"+zoneinfoRoot+"/Etc/UTC") || containsString(runner.events, "read:"+zoneinfoRoot+"/Etc/UTC") {
		t.Fatalf("events=%#v", runner.events)
	}
}

func TestTimezoneObservationRejectsZoneinfoAliasEscapingRoot(t *testing.T) {
	runner := timezoneRunner("Europe/Berlin")
	runner.evalSymlinks[zoneinfoRoot+"/Europe/Berlin"][0] = linkResult{target: "/tmp/forged-zone"}
	runner.files["/tmp/forged-zone"] = []byte("TZif")
	if _, ok := reconcileTimezone(mustTimezone("Europe/Berlin"), observeTimezone(runner)).(timezoneBlocked); !ok || containsString(runner.events, "read:/tmp/forged-zone") {
		t.Fatalf("events=%#v", runner.events)
	}
}

func TestTimezoneObservationRejectsNonregularCanonicalTargetBeforeRead(t *testing.T) {
	runner := timezoneRunner("Europe/Berlin")
	runner.lstats[zoneinfoRoot+"/Europe/Berlin"][0] = pathResult{info: PathInfo{Kind: OtherPath}}
	if _, ok := reconcileTimezone(mustTimezone("Europe/Berlin"), observeTimezone(runner)).(timezoneBlocked); !ok || containsString(runner.events, "prefix:4:") {
		t.Fatalf("events=%#v", runner.events)
	}
}

func TestTimezonePostObservationFailureIsFailedAction(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC")
	runner.lstats[localtimePath] = append(runner.lstats[localtimePath], pathResult{err: errors.New("unavailable")})
	runner.results[timezoneCommand("Europe/Berlin")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "timezone" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestTimezoneApplyRevalidatesRTCModeImmediatelyBeforeMutation(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC")
	runner.results[timezoneRTCCommand()] = []Result{
		{ExitCode: 0, Stdout: "no\n"},
		{ExitCode: 0, Stdout: "yes\n"},
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:timezone:rtc" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, timezoneCommand("Europe/Berlin")) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestTimezoneApplyRevalidatesHostAfterPrerequisitesImmediatelyBeforeMutation(t *testing.T) {
	state := timezoneState("Europe/Berlin")
	review := Plan(state, timezoneRunner("Etc/UTC"))
	runner := timezoneRunner("Etc/UTC", "Etc/UTC", "Europe/Berlin")
	runner.fileResults["/proc/1/comm"] = []fileResult{
		{contents: []byte("systemd\n")},
		{contents: []byte("systemd\n")},
		{contents: []byte("openrc\n")},
	}
	runner.results[timezoneCommand("Europe/Berlin")] = []Result{{ExitCode: 0}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, timezoneCommand("Europe/Berlin")) {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func timezoneState(value string) DesiredState {
	intent := mustTimezone(value)
	return DesiredState{machine: &machineIntent{timezone: &intent}}
}

func mustTimezone(value string) timezoneIntent {
	intent, err := newTimezoneIntent(value)
	if err != nil {
		panic(err)
	}
	return intent
}

func timezoneRunner(zones ...string) *testRunner {
	runner := hostnameRunner()
	runner.paths["timedatectl"] = "/usr/bin/timedatectl"
	runner.results[timezoneRTCCommand()] = []Result{
		{ExitCode: 0, Stdout: "no\n"},
		{ExitCode: 0, Stdout: "no\n"},
		{ExitCode: 0, Stdout: "no\n"},
		{ExitCode: 0, Stdout: "no\n"},
	}
	runner.readlinks = map[string][]linkResult{}
	runner.evalSymlinks = map[string][]linkResult{
		zoneinfoRoot + "/Europe/Berlin": {{target: zoneinfoRoot + "/Europe/Berlin"}, {target: zoneinfoRoot + "/Europe/Berlin"}},
	}
	runner.lstats = map[string][]pathResult{
		zoneinfoRoot + "/Europe/Berlin": {{info: PathInfo{Kind: RegularPath}}, {info: PathInfo{Kind: RegularPath}}},
	}
	runner.files[zoneinfoRoot+"/Europe/Berlin"] = []byte("TZif")
	for _, zone := range zones {
		runner.lstats[localtimePath] = append(runner.lstats[localtimePath], pathResult{info: PathInfo{Kind: SymlinkPath}})
		runner.readlinks[localtimePath] = append(runner.readlinks[localtimePath], linkResult{target: "../usr/share/zoneinfo/" + zone})
		zonePath := zoneinfoRoot + "/" + zone
		runner.evalSymlinks[zonePath] = append(runner.evalSymlinks[zonePath], linkResult{target: zonePath})
		runner.files[zonePath] = []byte("TZif")
		runner.lstats[zonePath] = append(runner.lstats[zonePath], pathResult{info: PathInfo{Kind: RegularPath}})
	}
	return runner
}

func timezoneCommand(value string) string {
	return "/usr/bin/timedatectl --no-ask-password set-timezone " + value
}

func timezoneRTCCommand() string {
	return "/usr/bin/timedatectl --no-pager --property=LocalRTC --value show"
}
