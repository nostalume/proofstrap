package proofstrap

import (
	"io/fs"
	"reflect"
	"testing"
)

func TestObserveHomeUsesLstatFromRootThroughTarget(t *testing.T) {
	runner := &testRunner{lstats: map[string][]pathResult{
		"/":           {{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
		"/home":       {{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
		"/home/alice": {{err: fs.ErrNotExist}},
	}}
	snapshot := observeHome(runner, homeIntent{path: "/home/alice", mode: 0o700})
	if !reflect.DeepEqual(runner.lstatCalls, []string{"/", "/home", "/home/alice"}) {
		t.Fatalf("calls=%#v", runner.lstatCalls)
	}
	if _, ok := snapshot.target.state.(pathMissing); !ok {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestPlanCreatesOnlyAbsentHome(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	runner.paths["install"] = "/usr/bin/install"
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(runner, []pathResult{{err: fs.ErrNotExist}})
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	want := "/usr/bin/sudo -N -n @proofstrap-self=sha256:proofstrap-test _create-home --uid 1000 --gid 1000 --mode 0700 -- /home/alice"
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "home-create:/home/alice" || review.Changes[0].Command == nil || review.Changes[0].Command.String() != want {
		t.Fatalf("review=%#v calls=%#v paths=%#v", review, runner.calls, runner.pathCalls)
	}
	for _, prohibited := range []string{"install", "mkdir", "chown", "chmod", "usermod", "groupmod"} {
		if containsCallFragment(runner.calls, prohibited) {
			t.Fatalf("prohibited %s call: %#v", prohibited, runner.calls)
		}
	}
	if containsString(runner.calls, rpmInventoryCommand()) {
		t.Fatalf("home creation did not precede package inspection: %#v", runner.calls)
	}
}

func TestApplyCreatesExactHomeThenRequiresReplan(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	planner := baseRunner()
	addAccountResults(planner, "alice", 1000, 1)
	planner.paths["install"] = "/usr/bin/install"
	planner.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(planner, []pathResult{{err: fs.ErrNotExist}})
	review := Plan(state, planner)

	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 3)
	runner.paths["install"] = "/usr/bin/install"
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	exactAncestor := pathResult{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}
	runner.lstats = map[string][]pathResult{
		"/":           {exactAncestor, exactAncestor, exactAncestor},
		"/home":       {exactAncestor, exactAncestor, exactAncestor},
		"/home/alice": {{err: fs.ErrNotExist}, {err: fs.ErrNotExist}, {info: PathInfo{Kind: DirectoryPath, Mode: 0o700, UID: 1000, GID: 1000}}},
	}
	runner.results[homeCreateCommand()] = []Result{{}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v lstat=%#v", receipt, runner.calls, runner.lstatCalls)
	}
	if !containsString(runner.calls, homeCreateCommand()) || len(runner.lstatCalls) != 9 {
		t.Fatalf("calls=%#v lstat=%#v", runner.calls, runner.lstatCalls)
	}
}

func TestPlanAcceptsExactExistingHomeWithoutFoundationalChange(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 0 || runner.executableCalls != 0 {
		t.Fatalf("review=%#v paths=%#v", review, runner.pathCalls)
	}
}

func TestPlanBlocksUnsafeHomeBeforeAuthorityAndPackageInspection(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	runner.lstats["/home/alice"] = []pathResult{{info: PathInfo{Kind: SymlinkPath, Mode: 0o777, UID: 1000, GID: 1000}}}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if !review.Blocked() || len(review.Changes) != 0 || runner.executableCalls != 0 || containsString(runner.calls, "/usr/bin/sudo -N -n -v") || containsString(runner.calls, rpmInventoryCommand()) {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestApplyObservesHomeAfterFailedCreation(t *testing.T) {
	state, review := absentHomePlan(t)
	runner := homeApplyRunner(Result{ExitCode: 7}, pathResult{err: fs.ErrNotExist})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction || len(runner.lstatCalls) != 9 {
		t.Fatalf("receipt=%#v calls=%#v lstat=%#v", receipt, runner.calls, runner.lstatCalls)
	}
}

func TestApplyObservesLockWhenPostAttemptAccountIsMissing(t *testing.T) {
	state, review := absentHomePlan(t)
	runner := homeApplyRunner(Result{ExitCode: 7}, pathResult{err: fs.ErrNotExist})
	exact := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
	missing := Result{ExitCode: 2}
	setAccountResults(runner, []Result{exact, exact, missing})
	receipt := Apply(state, runner, review.Digest())
	lockCalls := 0
	for _, call := range runner.calls {
		if call == "/usr/bin/passwd -S alice" {
			lockCalls++
		}
	}
	if receipt.Status != Failed || lockCalls != 3 {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyPreservesAppliedHomeWhenPostAttemptDependencyVerificationFails(t *testing.T) {
	state, review := absentHomePlan(t)
	runner := homeApplyRunner(Result{}, pathResult{info: PathInfo{Kind: DirectoryPath, Mode: 0o700, UID: 1000, GID: 1000}})
	exact := Result{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}
	setAccountResults(runner, []Result{exact, exact, {ExitCode: 2}})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "final:home-dependencies" {
		t.Fatalf("receipt=%#v", receipt)
	}
}

func TestApplyRejectsHomeDriftBeforeCreation(t *testing.T) {
	state, review := absentHomePlan(t)
	runner := homeApplyRunner(Result{}, pathResult{info: PathInfo{Kind: DirectoryPath, Mode: 0o700, UID: 1000, GID: 1000}})
	runner.lstats["/home/alice"][1] = pathResult{info: PathInfo{Kind: SymlinkPath, Mode: 0o777, UID: 1000, GID: 1000}}
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || containsString(runner.calls, homeCreateCommand()) {
		t.Fatalf("receipt=%#v calls=%#v lstat=%#v", receipt, runner.calls, runner.lstatCalls)
	}
}

func TestHomeCreationDigestBindsExecutableIdentityAndAncestry(t *testing.T) {
	_, baseline := absentHomePlan(t)
	changedPath := baseRunner()
	addAccountResults(changedPath, "alice", 1000, 1)
	changedPath.executable = "/opt/proofstrap/proofstrap"
	changedPath.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(changedPath, []pathResult{{err: fs.ErrNotExist}})
	if Plan(DesiredState{account: presentAccountForTest()}, changedPath).Digest() == baseline.Digest() {
		t.Fatal("proofstrap executable path was not digest-bound")
	}
	changedDigest := baseRunner()
	addAccountResults(changedDigest, "alice", 1000, 1)
	changedDigest.executableDigest = "sha256:changed-proofstrap"
	changedDigest.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(changedDigest, []pathResult{{err: fs.ErrNotExist}})
	if Plan(DesiredState{account: presentAccountForTest()}, changedDigest).Digest() == baseline.Digest() {
		t.Fatal("proofstrap executable content digest was not digest-bound")
	}
	changedAncestry := baseRunner()
	addAccountResults(changedAncestry, "alice", 1000, 1)
	changedAncestry.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(changedAncestry, []pathResult{{err: fs.ErrNotExist}})
	changedAncestry.lstats["/home"][0].info.Mode = 0o750
	if Plan(DesiredState{account: presentAccountForTest()}, changedAncestry).Digest() == baseline.Digest() {
		t.Fatal("home ancestry was not digest-bound")
	}
}

func TestHomeAncestorPathsRunFromRootToParent(t *testing.T) {
	want := []string{"/", "/srv", "/srv/users"}
	if got := homeAncestorPaths("/srv/users/alice"); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths=%#v want=%#v", got, want)
	}
}

func TestReconcileHomeCreationAdmitsAbsentTargetUnderRealDirectoryAncestry(t *testing.T) {
	snapshot := homeSnapshot{
		ancestors: []pathEvidence{
			{path: "/", state: pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
			{path: "/home", state: pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
		},
		target: pathEvidence{path: "/home/alice", state: pathMissing{}},
	}
	decision := reconcileHomeCreation(homeIntent{path: "/home/alice", mode: 0o700}, 1000, 1000, snapshot)
	if _, ok := decision.(homeCreateEligible); !ok {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcileHomeCreationAcceptsOnlyExactExistingDirectory(t *testing.T) {
	exact := exactHomeSnapshot(PathInfo{Kind: DirectoryPath, Mode: 0o700, UID: 1000, GID: 1000})
	if _, ok := reconcileHomeCreation(homeIntent{path: "/home/alice", mode: 0o700}, 1000, 1000, exact).(homeSatisfied); !ok {
		t.Fatalf("exact home was not satisfied")
	}
	for _, info := range []PathInfo{
		{Kind: SymlinkPath, Mode: 0o700, UID: 1000, GID: 1000},
		{Kind: RegularPath, Mode: 0o700, UID: 1000, GID: 1000},
		{Kind: DirectoryPath, Mode: 0o755, UID: 1000, GID: 1000},
		{Kind: DirectoryPath, Mode: 0o700, UID: 1001, GID: 1000},
		{Kind: DirectoryPath, Mode: 0o700, UID: 1000, GID: 1001},
	} {
		if _, ok := reconcileHomeCreation(homeIntent{path: "/home/alice", mode: 0o700}, 1000, 1000, exactHomeSnapshot(info)).(homeBlocked); !ok {
			t.Fatalf("nonexact home admitted: %#v", info)
		}
	}
}

func TestReconcileHomeCreationBlocksUnsafeAncestry(t *testing.T) {
	for _, state := range []pathState{
		pathFound{info: PathInfo{Kind: SymlinkPath, Mode: 0o777, UID: 0, GID: 0}},
		pathFound{info: PathInfo{Kind: RegularPath, Mode: 0o755, UID: 0, GID: 0}},
		pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o777, UID: 0, GID: 0}},
		pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 1000, GID: 1000}},
		pathMissing{},
		pathObservationFailed{detail: "permission denied"},
	} {
		snapshot := homeSnapshot{
			ancestors: []pathEvidence{{path: "/", state: pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755}}}, {path: "/home", state: state}},
			target:    pathEvidence{path: "/home/alice", state: pathMissing{}},
		}
		if _, ok := reconcileHomeCreation(homeIntent{path: "/home/alice", mode: 0o700}, 1000, 1000, snapshot).(homeBlocked); !ok {
			t.Fatalf("unsafe ancestry admitted: %#v", state)
		}
	}
}

func exactHomeSnapshot(info PathInfo) homeSnapshot {
	return homeSnapshot{
		ancestors: []pathEvidence{
			{path: "/", state: pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
			{path: "/home", state: pathFound{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}},
		},
		target: pathEvidence{path: "/home/alice", state: pathFound{info: info}},
	}
}

func setExactHomeAncestry(runner *testRunner, target []pathResult) {
	if runner.lstats == nil {
		runner.lstats = map[string][]pathResult{}
	}
	runner.lstats["/"] = []pathResult{{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}}
	runner.lstats["/home"] = []pathResult{{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}}
	runner.lstats["/home/alice"] = append([]pathResult(nil), target...)
}

func homeCreateCommand() string {
	return "/usr/bin/sudo -N -n @proofstrap-self=sha256:proofstrap-test _create-home --uid 1000 --gid 1000 --mode 0700 -- /home/alice"
}

func absentHomePlan(t *testing.T) (DesiredState, ReviewPlan) {
	t.Helper()
	state := DesiredState{account: presentAccountForTest()}
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	runner.paths["install"] = "/usr/bin/install"
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	setExactHomeAncestry(runner, []pathResult{{err: fs.ErrNotExist}})
	return state, Plan(state, runner)
}

func homeApplyRunner(execution Result, postTarget pathResult) *testRunner {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 3)
	runner.paths["install"] = "/usr/bin/install"
	runner.results["/usr/bin/sudo -N -n -v"] = []Result{{}}
	exactAncestor := pathResult{info: PathInfo{Kind: DirectoryPath, Mode: 0o755, UID: 0, GID: 0}}
	runner.lstats = map[string][]pathResult{
		"/":           {exactAncestor, exactAncestor, exactAncestor},
		"/home":       {exactAncestor, exactAncestor, exactAncestor},
		"/home/alice": {{err: fs.ErrNotExist}, {err: fs.ErrNotExist}, postTarget},
	}
	runner.results[homeCreateCommand()] = []Result{execution}
	return runner
}
