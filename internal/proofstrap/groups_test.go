package proofstrap

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestObservePrimaryGroupUsesReviewedGetentForGlobalAndLocalNameAndGID(t *testing.T) {
	entry := Result{Stdout: "alice:x:1000:alice\n"}
	runner := &testRunner{results: map[string][]Result{
		"/usr/bin/getent group alice":          {entry},
		"/usr/bin/getent -s files group alice": {entry},
		"/usr/bin/getent group 1000":           {entry},
		"/usr/bin/getent -s files group 1000":  {entry},
	}}
	snapshot := observePrimaryGroup(context.Background(), runner, "/usr/bin/getent", primaryGroupIntent{name: "alice", gid: 1000})
	want := []string{
		"/usr/bin/getent group alice",
		"/usr/bin/getent -s files group alice",
		"/usr/bin/getent group 1000",
		"/usr/bin/getent -s files group 1000",
	}
	if !reflect.DeepEqual(runner.calls, want) || len(runner.pathCalls) != 0 || snapshot.getentPath != "/usr/bin/getent" {
		t.Fatalf("calls=%#v paths=%#v snapshot=%#v", runner.calls, runner.pathCalls, snapshot)
	}
}

func TestParseGroupEntryPreservesNoncredentialFieldsAndRequiresExactFraming(t *testing.T) {
	entry, err := parseGroupEntry("alice:x:1000:alice,bob\n")
	if err != nil || entry.name != "alice" || entry.gid != 1000 || !reflect.DeepEqual(entry.members, []string{"alice", "bob"}) {
		t.Fatalf("entry=%#v err=%v", entry, err)
	}
	for _, malformed := range []string{
		"alice:x:1000:alice",
		"alice:x:1000:alice\n\n",
		"alice:x:not-a-gid:alice\n",
		"alice:x:1000\n",
	} {
		if _, err := parseGroupEntry(malformed); err == nil {
			t.Fatalf("accepted malformed group record %q", malformed)
		}
	}
}

func TestParseGroupEntryRejectsCredentialMaterial(t *testing.T) {
	for _, marker := range []string{"", "!", "*", "$6$hash"} {
		if _, err := parseGroupEntry("alice:" + marker + ":1000:alice\n"); err == nil {
			t.Fatalf("accepted group credential field %q", marker)
		}
	}
}

func TestReconcilePrimaryGroupIdentifiesExactGroup(t *testing.T) {
	entry := groupEntry{name: "alice", gid: 1000, members: []string{"alice"}}
	decision := reconcilePrimaryGroup(primaryGroupIntent{name: "alice", gid: 1000}, exactPrimaryGroupSnapshot("/usr/bin/getent", entry))
	identified, ok := decision.(primaryGroupIdentified)
	if !ok || len(identified.facts) == 0 || !strings.Contains(identified.facts[0].Detail, "gid=1000") {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcilePrimaryGroupMarksCleanAbsenceCreateEligible(t *testing.T) {
	missing := groupMissing{}
	decision := reconcilePrimaryGroup(primaryGroupIntent{name: "alice", gid: 1000}, primaryGroupSnapshot{
		getentPath: "/usr/bin/getent", globalName: missing, localName: missing, globalGID: missing, localGID: missing,
	})
	if _, ok := decision.(primaryGroupAbsentEligible); !ok {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestReconcilePrimaryGroupBlocksNSSOnlyCollisionAndReverseGIDCollision(t *testing.T) {
	alice := groupFound{entry: groupEntry{name: "alice", gid: 1000}}
	other := groupFound{entry: groupEntry{name: "other", gid: 1000}}
	missing := groupMissing{}
	for _, snapshot := range []primaryGroupSnapshot{
		{getentPath: "/usr/bin/getent", globalName: alice, localName: missing, globalGID: alice, localGID: missing},
		{getentPath: "/usr/bin/getent", globalName: missing, localName: missing, globalGID: other, localGID: other},
	} {
		decision := reconcilePrimaryGroup(primaryGroupIntent{name: "alice", gid: 1000}, snapshot)
		if blocked, ok := decision.(primaryGroupBlocked); !ok || len(blocked.blockers) == 0 {
			t.Fatalf("decision=%#v", decision)
		}
	}
}

func exactPrimaryGroupSnapshot(getent string, entry groupEntry) primaryGroupSnapshot {
	found := groupFound{entry: entry}
	return primaryGroupSnapshot{getentPath: getent, globalName: found, localName: found, globalGID: found, localGID: found}
}

func TestPlanCreatesOnlyAbsentPrimaryGroup(t *testing.T) {
	runner := absentPrimaryGroupRunner()
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "primary-group-create:alice" || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/usr/sbin/groupadd --gid 1000 alice" {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
	if containsCallFragment(runner.calls, "useradd") || containsCallFragment(runner.calls, "usermod") {
		t.Fatalf("primary-group planning crossed into account mutation: calls=%#v", runner.calls)
	}
}

func TestPlanKeepsPrimaryGIDIndependentFromAccountUID(t *testing.T) {
	intent := presentAccountForTest()
	intent.primaryGroup.gid = 2000
	runner := absentPrimaryGroupRunner()
	delete(runner.results, "/usr/bin/getent group 1000")
	delete(runner.results, "/usr/bin/getent -s files group 1000")
	missing := Result{ExitCode: 2}
	runner.results["/usr/bin/getent group 2000"] = []Result{missing}
	runner.results["/usr/bin/getent -s files group 2000"] = []Result{missing}
	review := Plan(DesiredState{account: intent}, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/usr/sbin/groupadd --gid 2000 alice" {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestPlanExistingAccountIntentDoesNotObserveOrMutatePrimaryGroup(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	review := Plan(DesiredState{account: existingAccountIntent{name: "alice"}}, runner)
	if review.Blocked() || containsCallFragment(runner.calls, " group ") || containsString(runner.pathCalls, "groupadd") {
		t.Fatalf("review=%#v calls=%#v paths=%#v", review, runner.calls, runner.pathCalls)
	}
}

func TestPlanPresentExactAccountAndGroupNeedsNoFoundationalChange(t *testing.T) {
	runner := baseRunner()
	addAccountResults(runner, "alice", 1000, 1)
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 0 || !containsString(runner.calls, "/usr/bin/getent group alice") {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestPlanCreatesAccountOnlyAfterPrimaryGroupIsExact(t *testing.T) {
	runner := absentPrimaryGroupRunner()
	runner.paths["useradd"] = "/usr/sbin/useradd"
	runner.paths["passwd"] = "/usr/bin/passwd"
	group := Result{Stdout: "alice:x:1000:\n"}
	setGroupResults(runner, []Result{group})
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].ID != "account-create:alice" {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestPlanBlocksPrimaryGroupCollisionWithoutResolvingGroupadd(t *testing.T) {
	runner := absentPrimaryGroupRunner()
	other := Result{Stdout: "other:x:1000:\n"}
	runner.results["/usr/bin/getent group 1000"] = []Result{other}
	runner.results["/usr/bin/getent -s files group 1000"] = []Result{other}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if !review.Blocked() || !hasBlockerSubject(review.Blockers, "primary-group:alice") || containsString(runner.pathCalls, "groupadd") {
		t.Fatalf("review=%#v paths=%#v", review, runner.pathCalls)
	}
}

func TestPlanWrapsPrimaryGroupCreationWithExactNoninteractiveSudo(t *testing.T) {
	runner := absentPrimaryGroupRunner()
	runner.uid = 1000
	runner.paths["sudo"] = "/opt/proofstrap/bin/sudo"
	runner.results["/opt/proofstrap/bin/sudo -N -n -v"] = []Result{{}}
	review := Plan(DesiredState{account: presentAccountForTest()}, runner)
	if review.Blocked() || len(review.Changes) != 1 || review.Changes[0].Command == nil || review.Changes[0].Command.String() != "/opt/proofstrap/bin/sudo -N -n /usr/sbin/groupadd --gid 1000 alice" {
		t.Fatalf("review=%#v calls=%#v", review, runner.calls)
	}
}

func TestApplyCreatesPrimaryGroupThenRequiresReplan(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentPrimaryGroupRunner())
	runner := primaryGroupApplyRunner(Result{})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != ReplanRequired || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Applied {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, "/usr/sbin/groupadd --gid 1000 alice") != 1 || containsCallFragment(runner.calls, "useradd") || containsCallFragment(runner.calls, "usermod") {
		t.Fatalf("calls=%#v", runner.calls)
	}
	if countString(runner.pathCalls, "groupadd") != 1 {
		t.Fatalf("groupadd path was not frozen: paths=%#v", runner.pathCalls)
	}
}

func TestApplyPrimaryGroupDriftPreventsGroupadd(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentPrimaryGroupRunner())
	runner := primaryGroupApplyRunner(Result{})
	exact := Result{Stdout: "alice:x:1000:\n"}
	setGroupResults(runner, []Result{{ExitCode: 2}, exact})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Stale || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/sbin/groupadd --gid 1000 alice") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyIndeterminatePrimaryGroupGuardFailsWithoutGroupadd(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentPrimaryGroupRunner())
	runner := primaryGroupApplyRunner(Result{})
	setGroupResults(runner, []Result{{ExitCode: 2}, {Err: errors.New("NSS unavailable")}})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Blockers) != 1 || receipt.Blockers[0].Subject != "guard:primary-group" || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != Unattempted || containsString(runner.calls, "/usr/sbin/groupadd --gid 1000 alice") {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
}

func TestApplyPrimaryGroupFailureStillObservesPostAttemptState(t *testing.T) {
	state := DesiredState{account: presentAccountForTest()}
	review := Plan(state, absentPrimaryGroupRunner())
	runner := primaryGroupApplyRunner(Result{ExitCode: 1, Stderr: "denied"})
	receipt := Apply(state, runner, review.Digest())
	if receipt.Status != Failed || len(receipt.Outcomes) != 1 || receipt.Outcomes[0].Status != FailedAction {
		t.Fatalf("receipt=%#v calls=%#v", receipt, runner.calls)
	}
	if countString(runner.calls, "/usr/bin/getent group alice") != 3 {
		t.Fatalf("post-attempt group observation missing: calls=%#v", runner.calls)
	}
}

func absentPrimaryGroupRunner() *testRunner {
	runner := baseRunner()
	runner.uid = 0
	runner.paths["getent"] = "/usr/bin/getent"
	runner.paths["groupadd"] = "/usr/sbin/groupadd"
	missing := Result{ExitCode: 2}
	for _, command := range []string{
		"/usr/bin/getent passwd alice",
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []Result{missing}
	}
	setGroupResults(runner, []Result{missing})
	return runner
}

func primaryGroupApplyRunner(groupadd Result) *testRunner {
	runner := baseRunner()
	runner.uid = 0
	runner.paths["getent"] = "/usr/bin/getent"
	runner.paths["groupadd"] = "/usr/sbin/groupadd"
	missing := Result{ExitCode: 2}
	for _, command := range []string{
		"/usr/bin/getent passwd alice",
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []Result{missing, missing, missing}
	}
	exact := Result{Stdout: "alice:x:1000:\n"}
	setGroupResults(runner, []Result{missing, missing, exact})
	runner.results["/usr/sbin/groupadd --gid 1000 alice"] = []Result{groupadd}
	return runner
}

func setGroupResults(runner *testRunner, results []Result) {
	for _, command := range []string{
		"/usr/bin/getent group alice",
		"/usr/bin/getent -s files group alice",
		"/usr/bin/getent group 1000",
		"/usr/bin/getent -s files group 1000",
	} {
		runner.results[command] = append([]Result(nil), results...)
	}
}

func containsCallFragment(calls []string, fragment string) bool {
	for _, call := range calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

func hasBlockerSubject(blockers []Blocker, subject string) bool {
	for _, blocker := range blockers {
		if blocker.Subject == subject {
			return true
		}
	}
	return false
}
