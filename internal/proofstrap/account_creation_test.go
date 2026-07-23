package proofstrap

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPlanCreatesOnlyAbsentLockedAccount(t *testing.T) {
	runner := absentAccountExactGroupRunner()
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	want := "/usr/sbin/useradd --uid 1000 --gid 1000 --shell /bin/bash --home-dir /home/alice --no-create-home --no-user-group --password ! alice"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "account-create:alice" || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v calls=%#v paths=%#v", review, runner.calls, runner.pathCalls)
	}
	if containsCallFragment(runner.calls, "passwd -S") || containsCallFragment(runner.calls, "usermod") || containsCallFragment(runner.calls, " --groups ") {
		t.Fatalf("unexpected account behavior: calls=%#v", runner.calls)
	}
}

func TestPlanRequiresExactExistingAccountToBeLocked(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	runner.paths["passwd"] = "/usr/bin/passwd"
	runner.results["/usr/bin/passwd -S alice"] = []Result{{Stdout: "alice L 2026-07-23 0 99999 7 -1\n"}}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 0 || !containsString(runner.calls, "/usr/bin/passwd -S alice") {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestApplyCreatesLockedAccountThenRequiresReplan(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentAccountExactGroupRunner())
	runner := accountCreateApplyRunner(Result{}, Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}, Result{Stdout: "alice L 2026-07-23 0 99999 7 -1\n"})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, accountCreateCommand()) != 1 || countString(runner.pathCalls, "useradd") != 1 || countString(runner.pathCalls, "passwd") != 1 {
		t.Fatalf("paths=%#v calls=%#v", runner.pathCalls, runner.calls)
	}
}

func TestApplyAccountCreationFailureStillObservesAccountAndGroup(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentAccountExactGroupRunner())
	runner := accountCreateApplyRunner(Result{ExitCode: 1, Stderr: "denied"}, Result{ExitCode: 2}, Result{})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, "/usr/bin/getent passwd alice") != 3 || countString(runner.calls, "/usr/bin/getent group alice") != 3 {
		t.Fatalf("post-attempt observation missing: calls=%#v", runner.calls)
	}
}

func TestObserveAccountLockStatusUsesPreparedBoundedCommand(t *testing.T) {
	runner := &testRunner{results: map[string][]Result{
		"/usr/bin/passwd -S alice": {{Stdout: "alice L 2026-07-23 0 99999 7 -1\n"}},
	}}
	command := Command{Name: "/usr/bin/passwd", Args: []string{"-S", "alice"}, timeout: 5 * time.Second}
	observed := observeAccountLockStatus(context.Background(), runner, command, "alice")
	if _, ok := observed.(accountLocked); !ok || len(runner.calls) != 1 || runner.calls[0] != "/usr/bin/passwd -S alice" {
		t.Fatalf("observed=%#v calls=%#v", observed, runner.calls)
	}
}

func TestObserveAccountLockStatusTreatsCommandFailureAsIndeterminate(t *testing.T) {
	runner := &testRunner{results: map[string][]Result{
		"/usr/bin/passwd -S alice": {{Err: errors.New("timeout")}},
	}}
	observed := observeAccountLockStatus(context.Background(), runner, Command{Name: "/usr/bin/passwd", Args: []string{"-S", "alice"}}, "alice")
	if _, ok := observed.(accountLockIndeterminate); !ok {
		t.Fatalf("observed=%#v", observed)
	}
}

func TestAccountBindingGuardDetectsLockStatusDrift(t *testing.T) {
	entry := passwdEntry{name: "alice", uid: 1000, primaryGID: 1000, home: "/home/alice", shell: "/bin/bash"}
	runner := &testRunner{results: map[string][]Result{}}
	setAccountResults(runner, []Result{{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}})
	runner.results["/usr/bin/passwd -S alice"] = []Result{{Stdout: "alice P 2026-07-23 0 99999 7 -1\n"}}
	binding := accountBinding{
		intent:   presentAccountForTest(),
		observed: exactAccountSnapshot(entry),
		lock: accountLockBinding{
			name: "alice", command: Command{Name: "/usr/bin/passwd", Args: []string{"-S", "alice"}}, observed: accountLocked{name: "alice"},
		},
	}
	stale, err := binding.guard(context.Background(), runner)
	if err != nil || !stale {
		t.Fatalf("stale=%v err=%v calls=%#v", stale, err, runner.calls)
	}
}

func TestRootAuthorityPreservesAccountCommandTimeout(t *testing.T) {
	for _, authority := range []authority{
		{principal: rootPrincipal{}, access: rootAccess{}},
		{principal: userPrincipal{uid: 1000}, access: sudoAccess{path: "/usr/bin/sudo"}},
	} {
		prepared, err := authority.rootCommand(Command{Name: "/usr/bin/passwd", Args: []string{"-S", "alice"}, timeout: 5 * time.Second})
		if err != nil || prepared.timeout != 5*time.Second {
			t.Fatalf("authority=%#v command=%#v err=%v", authority, prepared, err)
		}
	}
}

func TestParseAccountLockStatusIdentifiesLockedAccount(t *testing.T) {
	observed := parseAccountLockStatus("alice", "alice L 2026-07-23 0 99999 7 -1\n")
	if locked, ok := observed.(accountLocked); !ok || locked.name != "alice" {
		t.Fatalf("observed=%#v", observed)
	}
}

func TestParseAccountLockStatusRejectsMalformedRecords(t *testing.T) {
	for _, record := range []string{
		"alice L 2026-07-23 0 99999 7 -1",
		"alice L 2026-07-23 0 99999 7 -1\nextra L 2026-07-23 0 99999 7 -1\n",
		"bob L 2026-07-23 0 99999 7 -1\n",
		"alice unknown 2026-07-23 0 99999 7 -1\n",
		"alice L 2026-07-23 0 99999 7\n",
	} {
		if _, ok := parseAccountLockStatus("alice", record).(accountLockIndeterminate); !ok {
			t.Fatalf("accepted malformed status record %q", record)
		}
	}
}

func TestParseAccountLockStatusRequiresSingleASCIISpaces(t *testing.T) {
	for _, record := range []string{
		" alice L 2026-07-23 0 99999 7 -1\n",
		"alice  L 2026-07-23 0 99999 7 -1\n",
		"alice L 2026-07-23  99999 7 -1\n",
		"alice L 2026-07-23 0 99999 7 -1 \n",
		"alice	L 2026-07-23 0 99999 7 -1\n",
		"alice L 2026-07-23	junk 0 99999 7 -1\n",
		"alice L 2026-07-23\x0bjunk 0 99999 7 -1\n",
		"alice L 2026-07-23\x0cjunk 0 99999 7 -1\n",
		"alice L 2026-07-23\u00a0junk 0 99999 7 -1\n",
		"alice L 2026-07-23 0 99999 7 -1\r\n",
	} {
		if _, ok := parseAccountLockStatus("alice", record).(accountLockIndeterminate); !ok {
			t.Fatalf("accepted non-exact status record %q", record)
		}
	}
}

func TestReconcileAccountCreationAdmitsOnlyAbsentAccountWithExactGroup(t *testing.T) {
	decision := reconcileAccountCreation(
		"alice",
		accountAbsentEligible{},
		primaryGroupIdentified{},
		accountLockUnobserved{},
	)
	if _, ok := decision.(accountCreateEligible); !ok {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcileAccountCreationRequiresExistingAccountToBeLocked(t *testing.T) {
	for _, test := range []struct {
		lock          accountLockObservation
		wantSatisfied bool
	}{
		{lock: accountLocked{name: "alice"}, wantSatisfied: true},
		{lock: accountUnlocked{name: "alice", status: "P"}},
		{lock: accountUnlocked{name: "alice", status: "NP"}},
		{lock: accountLockIndeterminate{detail: "status unavailable"}},
	} {
		decision := reconcileAccountCreation("alice", accountIdentified{}, primaryGroupIdentified{}, test.lock)
		_, satisfied := decision.(accountCreationSatisfied)
		if satisfied != test.wantSatisfied {
			t.Fatalf("lock=%#v decision=%#v", test.lock, decision)
		}
	}
}

func absentAccountExactGroupRunner() *testRunner {
	runner := absentPrimaryGroupRunner()
	runner.paths["useradd"] = "/usr/sbin/useradd"
	runner.paths["passwd"] = "/usr/bin/passwd"
	setGroupResults(runner, []Result{{Stdout: "alice:x:1000:\n"}})
	return runner
}

func accountCreateApplyRunner(execution, postAccount, lock Result) *testRunner {
	runner := absentAccountExactGroupRunner()
	missing := Result{ExitCode: 2}
	setAccountResults(runner, []Result{missing, missing, postAccount})
	exactGroup := Result{Stdout: "alice:x:1000:\n"}
	setGroupResults(runner, []Result{exactGroup, exactGroup, exactGroup})
	runner.results[accountCreateCommand()] = []Result{execution}
	if postAccount.ExitCode == 0 && postAccount.Err == nil {
		runner.results["/usr/bin/passwd -S alice"] = []Result{lock}
	}
	return runner
}

func setAccountResults(runner *testRunner, results []Result) {
	for _, command := range []string{
		"/usr/bin/getent passwd alice",
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = append([]Result(nil), results...)
	}
}

func accountCreateCommand() string {
	return "/usr/sbin/useradd --uid 1000 --gid 1000 --shell /bin/bash --home-dir /home/alice --no-create-home --no-user-group --password ! alice"
}

func TestPlanBlocksUnlockedExistingAccountWithoutRepair(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	runner.results["/usr/bin/passwd -S alice"] = []Result{{Stdout: "alice P 2026-07-23 0 99999 7 -1\n"}}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if !review.Blocked() || !hasBlockerSubject(review.Blockers, "account-lock:alice") || containsCallFragment(runner.calls, "passwd -l") || containsCallFragment(runner.calls, "usermod") {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestPlanWrapsAccountCreationWithExactNoninteractiveSudo(t *testing.T) {
	runner := absentAccountExactGroupRunner()
	runner.uid = 2000
	runner.paths["sudo"] = "/opt/proofstrap/bin/sudo"
	runner.results["/opt/proofstrap/bin/sudo -N -n -v"] = []Result{{}}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	want := "/opt/proofstrap/bin/sudo -N -n " + accountCreateCommand()
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestApplyRequiresFreshAccountAndPrimaryGroup(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentAccountExactGroupRunner())
	exactAccount := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
	exactGroup := Result{Stdout: "alice:x:1000:\n"}
	missing := Result{ExitCode: 2}
	for _, test := range []struct {
		name   string
		change func(*testRunner)
	}{
		{name: "account", change: func(runner *testRunner) { setAccountResults(runner, []Result{missing, exactAccount}) }},
		{name: "primary group", change: func(runner *testRunner) { setGroupResults(runner, []Result{exactGroup, missing}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := accountCreateApplyRunner(Result{}, exactAccount, Result{Stdout: "alice L 2026-07-23 0 99999 7 -1\n"})
			test.change(runner)
			receipt := Apply(state, runner, review.Digest())
			if receipt.Status != Stale || containsString(runner.calls, accountCreateCommand()) {
				t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
			}
		})
	}
}

func TestApplyRejectsUnlockedCreatedAccountWithoutRepair(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentAccountExactGroupRunner())
	runner := accountCreateApplyRunner(Result{}, Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}, Result{Stdout: "alice P 2026-07-23 0 99999 7 -1\n"})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction || containsCallFragment(runner.calls, "passwd -l") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestAccountCreationDigestBindsMutationAndLockObserverPaths(t *testing.T) {
	baseline := absentAccountExactGroupRunner()
	baselineReview := Plan(DesiredState{account: presentAccountForTest()}, baseline)
	for _, change := range []func(*testRunner){
		func(runner *testRunner) { runner.paths["useradd"] = "/opt/proofstrap/useradd" },
		func(runner *testRunner) { runner.paths["passwd"] = "/opt/proofstrap/passwd" },
	} {
		runner := absentAccountExactGroupRunner()
		change(runner)
		if review := Plan(DesiredState{account: presentAccountForTest()}, runner); review.Digest() == baselineReview.Digest() {
			t.Fatalf("path change did not change digest: baseline=%#v changed=%#v", baselineReview, review)
		}
	}
}
