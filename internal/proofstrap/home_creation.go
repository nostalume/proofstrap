package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"time"
)

//sumtype:decl
type pathState interface{ pathState() }

type pathFound struct{ info PathInfo }
type pathMissing struct{}
type pathObservationFailed struct{ detail string }

func (pathFound) pathState()             {}
func (pathMissing) pathState()           {}
func (pathObservationFailed) pathState() {}

type pathEvidence struct {
	path  string
	state pathState
}

type homeSnapshot struct {
	ancestors []pathEvidence
	target    pathEvidence
}

type homeBinding struct {
	intent   homeIntent
	uid      uint32
	gid      uint32
	observed homeSnapshot
}

//sumtype:decl
type homeCreationDecision interface{ homeCreationDecision() }

type homeSatisfied struct{ facts []Fact }
type homeCreateEligible struct{ facts []Fact }
type homeBlocked struct{ blockers []Blocker }

func (homeSatisfied) homeCreationDecision()      {}
func (homeCreateEligible) homeCreationDecision() {}
func (homeBlocked) homeCreationDecision()        {}

func homeAncestorPaths(path string) []string {
	path = filepath.Clean(path)
	if path == "/" {
		return nil
	}
	var reversed []string
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		reversed = append(reversed, current)
		if current == "/" {
			break
		}
	}
	ancestors := make([]string, len(reversed))
	for index := range reversed {
		ancestors[len(reversed)-1-index] = reversed[index]
	}
	return ancestors
}

func observeHome(runner Runner, intent homeIntent) homeSnapshot {
	paths := homeAncestorPaths(intent.path)
	ancestors := make([]pathEvidence, len(paths))
	for index, path := range paths {
		ancestors[index] = observePath(runner, path)
	}
	return homeSnapshot{ancestors: ancestors, target: observePath(runner, intent.path)}
}

func observePath(runner Runner, path string) pathEvidence {
	info, err := runner.Lstat(path)
	if err == nil {
		return pathEvidence{path: path, state: pathFound{info: info}}
	}
	if errors.Is(err, fs.ErrNotExist) {
		return pathEvidence{path: path, state: pathMissing{}}
	}
	return pathEvidence{path: path, state: pathObservationFailed{detail: err.Error()}}
}

func (binding homeBinding) guard(_ context.Context, runner Runner) (bool, error) {
	if binding.intent.path == "" {
		return false, nil
	}
	fresh := observeHome(runner, binding.intent)
	if detail := homeObservationFailure(fresh); detail != "" {
		return false, fmt.Errorf("home cannot be revalidated: %s", detail)
	}
	return !reflect.DeepEqual(fresh, binding.observed), nil
}

func homeObservationFailure(snapshot homeSnapshot) string {
	evidence := append(append([]pathEvidence(nil), snapshot.ancestors...), snapshot.target)
	for _, value := range evidence {
		if failed, ok := value.state.(pathObservationFailed); ok {
			return value.path + ": " + failed.detail
		}
	}
	return ""
}

func homeSnapshotFacts(snapshot homeSnapshot) []Fact {
	evidence := append(append([]pathEvidence(nil), snapshot.ancestors...), snapshot.target)
	facts := make([]Fact, 0, len(evidence))
	for _, value := range evidence {
		detail := "missing"
		if found, ok := value.state.(pathFound); ok {
			detail = fmt.Sprintf("kind=%s mode=%04o uid=%d gid=%d", pathKindName(found.info.Kind), found.info.Mode, found.info.UID, found.info.GID)
		} else if failed, ok := value.state.(pathObservationFailed); ok {
			detail = "indeterminate: " + failed.detail
		}
		facts = append(facts, Fact{Subject: "home-path:" + value.path, Detail: detail})
	}
	return facts
}

func pathKindName(kind PathKind) string {
	switch kind {
	case DirectoryPath:
		return "directory"
	case RegularPath:
		return "regular"
	case SymlinkPath:
		return "symlink"
	default:
		return "other"
	}
}

func reconcileHomeCreation(intent homeIntent, uid, gid uint32, snapshot homeSnapshot) homeCreationDecision {
	subject := "home:" + intent.path
	if intent.path == "/" || snapshot.target.path != intent.path {
		return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: "home target is not safely observable"}}}
	}
	wantAncestors := homeAncestorPaths(intent.path)
	if len(snapshot.ancestors) != len(wantAncestors) {
		return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: "home ancestry evidence is incomplete"}}}
	}
	for index, evidence := range snapshot.ancestors {
		if evidence.path != wantAncestors[index] {
			return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: "home ancestry evidence is out of order"}}}
		}
		found, ok := evidence.state.(pathFound)
		if !ok || !trustedHomeAncestor(found.info) {
			return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: fmt.Sprintf("ancestor %s is not a trusted root-owned directory", evidence.path)}}}
		}
	}
	switch target := snapshot.target.state.(type) {
	case pathMissing:
		return homeCreateEligible{facts: []Fact{{Subject: subject, Detail: "absent under real-directory ancestry"}}}
	case pathFound:
		if target.info.Kind != DirectoryPath || target.info.Mode != intent.mode || target.info.UID != uid || target.info.GID != gid {
			return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: "existing home type, mode, owner, or group is not exact"}}}
		}
		return homeSatisfied{facts: []Fact{{Subject: subject, Detail: fmt.Sprintf("exact directory uid=%d gid=%d mode=%04o", uid, gid, intent.mode)}}}
	case pathObservationFailed:
		return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: target.detail}}}
	default:
		return homeBlocked{blockers: []Blocker{{Subject: subject, Detail: "home target observation is invalid"}}}
	}
}

func trustedHomeAncestor(info PathInfo) bool {
	return info.Kind == DirectoryPath && info.UID == 0 && info.Mode&0o022 == 0
}

func verifyHomeCreation(intent homeIntent, uid, gid uint32, snapshot homeSnapshot) (bool, string) {
	switch decision := reconcileHomeCreation(intent, uid, gid, snapshot).(type) {
	case homeSatisfied:
		return true, decision.facts[0].Detail
	case homeCreateEligible:
		return false, "home remains absent"
	case homeBlocked:
		if len(decision.blockers) != 0 {
			return false, decision.blockers[0].Detail
		}
		return false, "home verification blocked"
	default:
		return false, "home verification is indeterminate"
	}
}

func planHomeCreation(review ReviewPlan, host hostBinding, account accountBinding, group primaryGroupBinding, intent presentAccountIntent, runner Runner) planned {
	executable, err := runner.ExecutableIdentity()
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "home:" + intent.home.path, Detail: "proofstrap executable is unavailable: " + err.Error()})
		return blocked(review)
	}
	review.Facts = append(review.Facts, Fact{Subject: "home-executable:" + intent.home.path, Detail: "path=" + executable.Path + "; digest=" + executable.Digest})
	authority, facts, blockers := admitAuthority(runner, []step{{access: rootStep}})
	review.Facts = append(review.Facts, facts...)
	review.Blockers = append(review.Blockers, blockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	bare := Command{Name: proofstrapSelfPrefix + executable.Digest, Args: []string{
		"_create-home",
		"--uid", strconv.FormatUint(uint64(intent.uid), 10),
		"--gid", strconv.FormatUint(uint64(intent.primaryGroup.gid), 10),
		"--mode", fmt.Sprintf("%04o", intent.home.mode),
		"--", intent.home.path,
	}, timeout: 30 * time.Second}
	effective, err := authority.rootCommand(bare)
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "home command preparation: " + err.Error()})
		return blocked(review)
	}
	projected := Command{Name: effective.Name, Args: append([]string(nil), effective.Args...)}
	projection := Change{ID: "home-create:" + intent.home.path, Detail: "create home " + intent.home.path, Command: &projected}
	review.Changes = append(review.Changes, projection)
	review = canonicalReview(review)
	return homeCreatePlan{plan: review, host: host, account: account, group: group, projection: projection, command: effective}
}
