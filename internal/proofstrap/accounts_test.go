package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestObserveAccountUsesExactGlobalAndLocalNSSQueries(t *testing.T) {
	entry := "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	runner := &testRunner{
		paths: map[string]string{"getent": "/usr/bin/getent"},
		results: map[string][]Result{
			"/usr/bin/getent passwd alice":          {{Stdout: entry}},
			"/usr/bin/getent -s files passwd alice": {{Stdout: entry}},
			"/usr/bin/getent passwd 1000":           {{Stdout: entry}},
			"/usr/bin/getent -s files passwd 1000":  {{Stdout: entry}},
		},
	}
	observed := observeAccount(context.Background(), runner, existingAccountIntent{name: "alice"})
	snapshot, ok := observed.(accountSnapshot)
	if !ok {
		t.Fatalf("observation=%#v", observed)
	}
	for _, lookup := range []accountLookup{snapshot.globalName, snapshot.localName, snapshot.globalUID, snapshot.localUID} {
		found, ok := lookup.(passwdFound)
		if !ok || found.entry.name != "alice" || found.entry.uid != 1000 || found.entry.primaryGID != 1000 || found.entry.home != "/home/alice" || found.entry.shell != "/bin/bash" {
			t.Fatalf("lookup=%#v", lookup)
		}
	}
	if strings.Join(runner.calls, "|") != "/usr/bin/getent passwd alice|/usr/bin/getent -s files passwd alice|/usr/bin/getent passwd 1000|/usr/bin/getent -s files passwd 1000" {
		t.Fatalf("calls=%#v", runner.calls)
	}
}

func TestParsePasswdEntryPreservesNoncredentialFieldsAndRejectsExtraFraming(t *testing.T) {
	entry, err := parsePasswdEntry("alice:x:1000:1000:Alice Example:/home/alice:/bin/bash \n")
	if err != nil {
		t.Fatal(err)
	}
	if entry.gecos != "Alice Example" || entry.shell != "/bin/bash " {
		t.Fatalf("entry=%#v", entry)
	}
	for _, malformed := range []string{
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\n",
		"\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
	} {
		if _, err := parsePasswdEntry(malformed); err == nil {
			t.Fatalf("accepted malformed framing %q", malformed)
		}
	}
}

func TestParsePasswdEntryRejectsCredentialMaterial(t *testing.T) {
	for _, marker := range []string{"", "!", "*", "$6$hash"} {
		if _, err := parsePasswdEntry("alice:" + marker + ":1000:1000:Alice:/home/alice:/bin/bash\n"); err == nil {
			t.Fatalf("accepted passwd credential field %q", marker)
		}
	}
}

func TestApplyReportsIndeterminateAccountGuard(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*testRunner, accountBinding) ApplyReceipt
	}{
		{
			name: "package plan",
			apply: func(runner *testRunner, account accountBinding) ApplyReceipt {
				command := Command{Name: "/usr/bin/zypper", Args: []string{"install", "example"}}
				projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
				change := Change{ID: "package-install:zypper", Command: &projected}
				plan := packagePlan{
					plan: ReviewPlan{Changes: []Change{change}}, host: hostBinding{facts: observeHost(runner).facts},
					account: account, projection: change, command: command,
				}
				return plan.apply(runner, ApplyReceipt{}, func(context.Context, Runner, Command, packageMutationGuard) packageResult {
					t.Fatal("indeterminate account guard admitted package effect")
					return packageResult{}
				})
			},
		},
		{
			name: "ready plan",
			apply: func(runner *testRunner, account accountBinding) ApplyReceipt {
				plan := readyPlan{plan: ReviewPlan{}, host: hostBinding{facts: observeHost(runner).facts}, account: account}
				return plan.apply(runner, ApplyReceipt{})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := baseRunner()
			runner.paths["getent"] = "/usr/bin/getent"
			failure := Result{Err: errors.New("NSS unavailable")}
			entryResult := Result{Stdout: "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"}
			runner.results["/usr/bin/getent passwd alice"] = []Result{failure}
			runner.results["/usr/bin/getent -s files passwd alice"] = []Result{entryResult}
			runner.results["/usr/bin/getent passwd 1000"] = []Result{entryResult}
			runner.results["/usr/bin/getent -s files passwd 1000"] = []Result{entryResult}
			entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, gecos: "Alice", home: "/home/alice", shell: "/bin/bash"}
			receipt := test.apply(runner, accountBinding{intent: existingAccountIntent{name: "alice"}, observed: exactAccountSnapshot(entry)})
			if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:account" || !strings.Contains(receipt.Blockers[0].Detail, "NSS unavailable") {
				t.Fatalf("receipt=%#v", receipt)
			}
		})
	}
}

func TestReconcileAccountIdentifiesExactLocalAccount(t *testing.T) {
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}
	decision := reconcileAccount(existingAccountIntent{name: "alice"}, exactAccountSnapshot(entry))
	identified, ok := decision.(accountIdentified)
	if !ok || len(identified.facts) == 0 {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcileAccountBlocksNSSOnlyCollision(t *testing.T) {
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}
	snapshot := exactAccountSnapshot(entry)
	snapshot.localName = passwdMissing{}
	decision := reconcileAccount(presentAccountForTest(), snapshot)
	blocked, ok := decision.(accountIdentificationBlocked)
	if !ok || !blockerContains(blocked.blockers, "NSS identity exists without a matching local account") {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcileAccountBlocksConflictsAndIndeterminateEvidence(t *testing.T) {
	t.Run("local NSS disagreement", func(t *testing.T) {
		global := passwdFound{entry: passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}}
		local := passwdFound{entry: passwdEntry{name: "alice", uid: 1001, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}}
		decision := reconcileAccount(existingAccountIntent{name: "alice"}, accountSnapshot{globalName: global, localName: local, globalUID: global, localUID: local})
		blocked, ok := decision.(accountIdentificationBlocked)
		if !ok || !blockerContains(blocked.blockers, "local and NSS passwd records disagree") {
			t.Fatalf("decision=%#v", decision)
		}
	})
	t.Run("name lookup returns another account", func(t *testing.T) {
		entry := passwdEntry{name: "bob", uid: 1000, primaryGID: 1000, home: "/home/bob", shell: "/bin/bash"}
		decision := reconcileAccount(existingAccountIntent{name: "alice"}, exactAccountSnapshot(entry))
		blocked, ok := decision.(accountIdentificationBlocked)
		if !ok || !blockerContains(blocked.blockers, "name lookup returned") {
			t.Fatalf("decision=%#v", decision)
		}
	})
	t.Run("reverse UID collision", func(t *testing.T) {
		missing := passwdMissing{}
		owner := passwdFound{entry: passwdEntry{name: "bob", uid: 1000, primaryGID: 1000, home: "/home/bob", shell: "/bin/bash"}}
		decision := reconcileAccount(presentAccountForTest(), accountSnapshot{globalName: missing, localName: missing, globalUID: owner, localUID: missing})
		blocked, ok := decision.(accountIdentificationBlocked)
		if !ok || !blockerContains(blocked.blockers, "requested UID is already owned through NSS") {
			t.Fatalf("decision=%#v", decision)
		}
	})
	t.Run("lookup failure", func(t *testing.T) {
		skipped := passwdLookupSkipped{}
		decision := reconcileAccount(existingAccountIntent{name: "alice"}, accountSnapshot{globalName: passwdLookupFailed{detail: "NSS unavailable"}, localName: skipped, globalUID: skipped, localUID: skipped})
		blocked, ok := decision.(accountIdentificationBlocked)
		if !ok || !blockerContains(blocked.blockers, "NSS unavailable") {
			t.Fatalf("decision=%#v", decision)
		}
	})
	t.Run("present mismatch", func(t *testing.T) {
		entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/zsh"}
		decision := reconcileAccount(presentAccountForTest(), exactAccountSnapshot(entry))
		blocked, ok := decision.(accountIdentificationBlocked)
		if !ok || !blockerContains(blocked.blockers, "account shell is") {
			t.Fatalf("decision=%#v", decision)
		}
	})
}

func TestReconcileAccountMarksAbsentPresentIntentEligible(t *testing.T) {
	missing := passwdMissing{}
	decision := reconcileAccount(presentAccountForTest(), accountSnapshot{globalName: missing, localName: missing, globalUID: missing, localUID: missing})
	eligible, ok := decision.(accountAbsentEligible)
	if !ok || len(eligible.facts) != 1 {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestPlanAccountCreationPrecedesPackageInspection(t *testing.T) {
	runner := baseRunner()
	runner.uid = 0
	runner.paths["getent"] = "/usr/bin/getent"
	runner.paths["useradd"] = "/usr/sbin/useradd"
	runner.paths["passwd"] = "/usr/bin/passwd"
	for _, command := range []string{
		"/usr/bin/getent passwd alice",
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []Result{{ExitCode: 2}}
	}
	setGroupResults(runner, []Result{{Stdout: "alice:x:1000:\n"}})
	state, err := newDesiredState([]string{"sway"}, presentAccountForTest())
	if err != nil {
		t.Fatal(err)
	}
	review := Plan(state, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "account-create:alice" || containsString(runner.pathCalls, "zypper") {
		t.Fatalf("review=%#v pathCalls=%#v", review, runner.pathCalls)
	}
}

func TestUserServiceDemandRequiresExplicitAccountBeforePackageInspection(t *testing.T) {
	runner := missingPackageRunner()
	review := Plan(DesiredState{Modules: []string{"audio"}}, runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "user-service demand requires an explicit account") || containsString(runner.pathCalls, "zypper") {
		t.Fatalf("review=%#v pathCalls=%#v", review, runner.pathCalls)
	}
}

func TestUserServiceTargetMustMatchEffectiveUID(t *testing.T) {
	runner := baseRunner()
	runner.uid = 1001
	runner.results[rpmInventoryCommand()] = []Result{{Stdout: "alsa-utils\npipewire\npipewire-pulseaudio\nwireplumber\n"}}
	addAccountResults(runner, "alice", 1000, 4)
	state, err := newDesiredState([]string{"audio"}, existingAccountIntent{name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	review := Plan(state, runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "effective uid is 1001, target account uid is 1000") || containsString(runner.pathCalls, "systemctl") {
		t.Fatalf("review=%#v pathCalls=%#v", review, runner.pathCalls)
	}
}

func TestUserServiceAuthorityMustRetainTargetUID(t *testing.T) {
	runner := baseRunner()
	runner.uids = []uint32{1000, 1001}
	addAccountResults(runner, "alice", 1000, 4)
	runner.results[rpmInventoryCommand()] = []Result{{Stdout: "alsa-utils\npipewire\npipewire-pulseaudio\nwireplumber\n"}}
	runner.results["/usr/bin/systemctl --user is-enabled pipewire.service wireplumber.service"] = []Result{{ExitCode: 1, Stdout: "disabled\ndisabled\n"}}
	runner.results["/usr/bin/systemctl --user is-active pipewire.service wireplumber.service"] = []Result{{ExitCode: 3, Stdout: "inactive\ninactive\n"}}
	runner.results["/usr/bin/systemctl --user show-environment"] = []Result{{}}
	review := Plan(audioDesiredState(), runner)
	if !review.Blocked() || !blockerContains(review.Blockers, "authority effective uid is 1001, target account uid is 1000") || len(review.Changes) != 0 {
		t.Fatalf("review=%#v", review)
	}
}

func TestApplyRevalidatesAccountBeforeMutation(t *testing.T) {
	runner := baseRunner()
	runner.paths["getent"] = "/usr/bin/getent"
	entry := Result{Stdout: "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"}
	missing := Result{ExitCode: 2}
	runner.results["/usr/bin/getent passwd alice"] = []Result{entry, entry, missing}
	runner.results["/usr/bin/getent -s files passwd alice"] = []Result{entry, entry, entry}
	runner.results["/usr/bin/getent passwd 1000"] = []Result{entry, entry, entry}
	runner.results["/usr/bin/getent -s files passwd 1000"] = []Result{entry, entry, entry}
	state, err := newDesiredState(nil, existingAccountIntent{name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	review := Plan(state, runner)
	if review.Blocked() || review.Account == nil || len(review.Changes) != 0 {
		t.Fatalf("review=%#v", review)
	}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestAccountGuardReusesReviewedGetentPath(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 2)
	intent := existingAccountIntent{name: "alice"}
	observed := observeAccount(context.Background(), runner, intent)
	runner.paths["getent"] = "/tmp/getent"
	entry := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
	runner.results["/tmp/getent passwd alice"] = []Result{entry}
	runner.results["/tmp/getent -s files passwd alice"] = []Result{entry}
	runner.results["/tmp/getent passwd 1000"] = []Result{entry}
	runner.results["/tmp/getent -s files passwd 1000"] = []Result{entry}
	stale, err := (accountBinding{intent: intent, observed: observed}).guard(context.Background(), runner)
	if err != nil || stale || countString(runner.pathCalls, "getent") != 1 || containsString(runner.calls, "/tmp/getent passwd alice") {
		t.Fatalf("stale=%v err=%v paths=%#v calls=%#v", stale, err, runner.pathCalls, runner.calls)
	}
}

func TestAccountObserverPathIsReviewVisibleAndDigestBound(t *testing.T) {
	state, err := newDesiredState(nil, existingAccountIntent{name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	planWith := func(path string) ReviewPlan {
		runner := baseRunner()
		runner.paths["getent"] = path
		entry := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
		for _, args := range []string{"passwd alice", "-s files passwd alice", "passwd 1000", "-s files passwd 1000"} {
			runner.results[path+" "+args] = []Result{entry}
		}
		return Plan(state, runner)
	}
	reviewed := planWith("/usr/bin/getent")
	replaced := planWith("/tmp/getent")
	if !containsFact(reviewed.Facts, "account-observer", "getent=/usr/bin/getent") || reviewed.Digest() == replaced.Digest() {
		t.Fatalf("reviewed=%#v replaced=%#v", reviewed, replaced)
	}
}

func TestReadyApplyGuardsFullAccountBeforeEveryMutation(t *testing.T) {
	runner := baseRunner()
	runner.uid = 1000
	addAccountResults(runner, "alice", 1000, 1)
	intent := existingAccountIntent{name: "alice"}
	observed := observeAccount(context.Background(), runner, intent)
	exact := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
	changed := Result{Stdout: "alice:x:1000:1000:Changed:/home/alice:/bin/bash\n"}
	runner.results["/usr/bin/getent passwd alice"] = []Result{exact, exact, changed}
	runner.results["/usr/bin/getent -s files passwd alice"] = []Result{exact, exact, exact}
	runner.results["/usr/bin/getent passwd 1000"] = []Result{exact, exact, exact}
	runner.results["/usr/bin/getent -s files passwd 1000"] = []Result{exact, exact, exact}
	steps := []step{
		{id: "service:first", detail: "first", access: directStep, command: Command{Name: "/usr/bin/first"}, timeout: time.Second, before: func(context.Context, Runner) error { return nil }, verify: func(context.Context, Runner) (bool, string) { return true, "ready" }},
		{id: "service:second", detail: "second", access: directStep, command: Command{Name: "/usr/bin/second"}, timeout: time.Second, before: func(context.Context, Runner) error { return nil }, verify: func(context.Context, Runner) (bool, string) { return true, "ready" }},
	}
	runner.results["/usr/bin/first"] = []Result{{}}
	plan := readyPlan{
		plan:       ReviewPlan{Changes: []Change{steps[0].projection(), steps[1].projection()}},
		host:       hostBinding{facts: observeHost(runner).facts},
		account:    accountBinding{intent: intent, observed: observed},
		targetUser: true,
		steps:      steps,
		commands:   []Command{steps[0].command, steps[1].command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Failed || len(receipt.Outcomes) != 2 || receipt.Outcomes[0].Status != Applied || receipt.Outcomes[1].Status != Unattempted || containsString(runner.calls, "/usr/bin/second") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestReadyApplyGuardsAccountAfterStepPreconditions(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 4)
	intent := existingAccountIntent{name: "alice"}
	observed := observeAccount(context.Background(), runner, intent)
	changed := Result{Stdout: "alice:x:1000:1000:Changed:/home/alice:/bin/bash\n"}
	plannedStep := step{
		id: "service:start", detail: "start", access: directStep,
		command: Command{Name: "/usr/bin/start"}, timeout: time.Second,
		before: func(context.Context, Runner) error {
			runner.results["/usr/bin/getent passwd alice"] = []Result{changed}
			return nil
		},
		verify: func(context.Context, Runner) (bool, string) { return true, "ready" },
	}
	runner.results["/usr/bin/start"] = []Result{{}}
	plan := readyPlan{
		plan: ReviewPlan{Changes: []Change{plannedStep.projection()}}, host: hostBinding{facts: observeHost(runner).facts},
		account: accountBinding{intent: intent, observed: observed}, steps: []step{plannedStep}, commands: []Command{plannedStep.command},
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/bin/start") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestAccountOnlyApplyIsReadOnlyAndSucceedsAfterFreshIdentification(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 4)
	state, err := newDesiredState(nil, existingAccountIntent{name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	review := Plan(state, runner)
	receipt := Apply(state, runner, review.Digest())
	if review.Blocked() || receipt.Status != Succeeded || len(receipt.Outcomes) != 0 {
		t.Fatalf("review=%#v receipt=%#v", review, receipt)
	}
	for _, call := range runner.calls {
		if !strings.HasPrefix(call, "/usr/bin/getent ") {
			t.Fatalf("account-only apply executed non-observation command: %q", call)
		}
	}
}

func TestReadyApplyRejectsTargetUIDDriftBeforeActions(t *testing.T) {
	runner := baseRunner()
	runner.uid = 1001
	addAccountResults(runner, "alice", 1000, 1)
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}
	plan := readyPlan{
		plan: ReviewPlan{}, host: hostBinding{facts: observeHost(runner).facts},
		account:    accountBinding{intent: existingAccountIntent{name: "alice"}, observed: exactAccountSnapshot(entry)},
		targetUser: true,
	}
	receipt := plan.apply(runner, ApplyReceipt{})
	if receipt.Status != Stale || len(runner.calls) != 4 {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestPackageApplyReportsPostMutationAccountDrift(t *testing.T) {
	runner := baseRunner()
	runner.paths["getent"] = "/usr/bin/getent"
	entryResult := Result{Stdout: "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"}
	missing := Result{ExitCode: 2}
	runner.results["/usr/bin/getent passwd alice"] = []Result{entryResult, missing}
	for _, command := range []string{
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []Result{entryResult, entryResult}
	}
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, gecos: "Alice", home: "/home/alice", shell: "/bin/bash"}
	command := Command{Name: "/usr/bin/zypper", Args: []string{"install", "example"}}
	projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
	change := Change{ID: "package-install:zypper", Command: &projected}
	plan := packagePlan{
		plan: ReviewPlan{Changes: []Change{change}}, host: hostBinding{facts: observeHost(runner).facts},
		account:    accountBinding{intent: existingAccountIntent{name: "alice"}, observed: exactAccountSnapshot(entry)},
		projection: change, command: command,
	}
	receipt := plan.apply(runner, ApplyReceipt{}, func(context.Context, Runner, Command, packageMutationGuard) packageResult {
		return packageResult{}
	})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "final:account" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestPackageApplyReportsIndeterminateImmediateAccountGuard(t *testing.T) {
	runner := baseRunner()
	runner.paths["getent"] = "/usr/bin/getent"
	exact := Result{Stdout: "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"}
	failure := Result{Err: errors.New("NSS unavailable")}
	runner.results["/usr/bin/getent passwd alice"] = []Result{exact, failure}
	for _, command := range []string{
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []Result{exact, exact}
	}
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, gecos: "Alice", home: "/home/alice", shell: "/bin/bash"}
	command := Command{Name: "/usr/bin/zypper", Args: []string{"install", "example"}}
	projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
	change := Change{ID: "package-install:zypper", Command: &projected}
	plan := packagePlan{
		plan: ReviewPlan{Changes: []Change{change}}, host: hostBinding{facts: observeHost(runner).facts},
		account:    accountBinding{intent: existingAccountIntent{name: "alice"}, observed: exactAccountSnapshot(entry)},
		projection: change, command: command,
	}
	receipt := plan.apply(runner, ApplyReceipt{}, func(_ context.Context, _ Runner, _ Command, guard packageMutationGuard) packageResult {
		return packageResult{err: guard()}
	})
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:account" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestAccountReviewIsDigestBound(t *testing.T) {
	review := canonicalReview(ReviewPlan{Account: PresentAccountReview{State: "present", Name: "alice", UID: 1000, Shell: "/bin/bash", PrimaryGroup: "alice", PrimaryGID: 1000, Home: "/home/alice", HomeMode: "0700"}})
	digest := review.Digest()
	changed := review
	value := changed.Account.(PresentAccountReview)
	value.UID++
	changed.Account = value
	if changed.Digest() == digest {
		t.Fatal("account intent was not digest-bound")
	}
}

func exactAccountSnapshot(entry passwdEntry) accountSnapshot {
	found := passwdFound{entry: entry}
	return accountSnapshot{getentPath: "/usr/bin/getent", globalName: found, localName: found, globalUID: found, localUID: found}
}

func presentAccountForTest() presentAccountIntent {
	return presentAccountIntent{
		name: "alice", uid: 1000, shell: "/bin/bash",
		primaryGroup: primaryGroupIntent{name: "alice", gid: 1000},
		home:         homeIntent{path: "/home/alice", mode: 0o700},
	}
}

func blockerContains(blockers []Blocker, fragment string) bool {
	for _, blocker := range blockers {
		if strings.Contains(blocker.Detail, fragment) {
			return true
		}
	}
	return false
}

func addAccountResults(runner *testRunner, name string, uid uint32, count int) {
	runner.paths["getent"] = "/usr/bin/getent"
	runner.paths["passwd"] = "/usr/bin/passwd"
	entry := Result{Stdout: fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash\n", name, uid, uid, name)}
	keys := []string{
		"/usr/bin/getent passwd " + name,
		"/usr/bin/getent -s files passwd " + name,
		fmt.Sprintf("/usr/bin/getent passwd %d", uid),
		fmt.Sprintf("/usr/bin/getent -s files passwd %d", uid),
	}
	for _, key := range keys {
		queue := make([]Result, count)
		for i := range queue {
			queue[i] = entry
		}
		runner.results[key] = queue
	}
	locked := Result{Stdout: fmt.Sprintf("%s L 2026-07-23 0 99999 7 -1\n", name)}
	queue := make([]Result, count)
	for i := range queue {
		queue[i] = locked
	}
	runner.results["/usr/bin/passwd -S "+name] = queue
	group := Result{Stdout: fmt.Sprintf("%s:x:%d:\n", name, uid)}
	for _, key := range []string{
		"/usr/bin/getent group " + name,
		"/usr/bin/getent -s files group " + name,
		fmt.Sprintf("/usr/bin/getent group %d", uid),
		fmt.Sprintf("/usr/bin/getent -s files group %d", uid),
	} {
		queue := make([]Result, count)
		for i := range queue {
			queue[i] = group
		}
		runner.results[key] = queue
	}
	if runner.lstats == nil {
		runner.lstats = map[string][]pathResult{}
	}
	for path, info := range map[string]PathInfo{
		"/":             {Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0},
		"/home":         {Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0},
		"/home/" + name: {Kind: DirectoryPath, Mode: 0o700, UID: uid, GID: uid},
	} {
		queue := make([]pathResult, count)
		for i := range queue {
			queue[i] = pathResult{info: info}
		}
		runner.lstats[path] = queue
	}
}
