package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
)

const (
	getentPath   = "/usr/bin/getent"
	groupaddPath = "/usr/sbin/groupadd"
	useraddPath  = "/usr/sbin/useradd"
	usermodPath  = "/usr/sbin/usermod"
	passwdPath   = "/usr/bin/passwd"
	gpasswdPath  = "/usr/bin/gpasswd"
)

var (
	ErrStale       = errors.New("identity operation is stale")
	ErrUnsupported = errors.New("identity capability is unsupported")
)

type Capability uint8

const (
	ObserveIdentity Capability = iota + 1
	CreateGroup
	CreateAccount
	ObserveLock
	ModifyAccount
	ModifyMembership
)

type shadowEffects struct {
	identify func(string) (linux.Identity, error)
	run      func(context.Context, linux.Identity, []string, []byte) (linux.Result, error)
	home     homeEffects
}

type toolEvidence struct {
	name     string
	identity linux.Identity
}

type selectionEvidence struct {
	capabilities []Capability
	tools        []toolEvidence
	rootGroup    groupRecord
	rootAccount  passwdRecord
}

type Selected struct {
	evidence selectionEvidence
	effects  shadowEffects
}

func Select(ctx context.Context, capabilities []Capability) (*Selected, error) {
	return selectShadow(ctx, shadowEffects{identify: linux.Identify, run: linux.Run, home: systemHomeEffects()}, capabilities)
}

func selectShadow(ctx context.Context, effects shadowEffects, capabilities []Capability) (*Selected, error) {
	if !linux.FutureContext(ctx) || effects.identify == nil || effects.run == nil {
		return nil, fmt.Errorf("bounded context and complete shadow effects are required")
	}
	caps := append([]Capability(nil), capabilities...)
	slices.Sort(caps)
	caps = slices.Compact(caps)
	if len(caps) == 0 || caps[0] != ObserveIdentity {
		return nil, fmt.Errorf("identity observation capability is required")
	}
	for _, capability := range caps {
		if capability < ObserveIdentity || capability > ModifyMembership {
			return nil, fmt.Errorf("invalid identity capability")
		}
	}
	paths := []struct {
		capability Capability
		name, path string
	}{
		{ObserveIdentity, "getent", getentPath},
		{CreateGroup, "groupadd", groupaddPath},
		{CreateAccount, "useradd", useraddPath},
		{ObserveLock, "passwd", passwdPath},
		{ModifyAccount, "usermod", usermodPath},
		{ModifyMembership, "gpasswd", gpasswdPath},
	}
	tools := make([]toolEvidence, 0, len(caps))
	for _, candidate := range paths {
		if !slices.Contains(caps, candidate.capability) {
			continue
		}
		identity, err := effects.identify(candidate.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w: %s", ErrUnsupported, candidate.name)
			}
			return nil, fmt.Errorf("identify %s: %w", candidate.name, err)
		}
		tools = append(tools, toolEvidence{name: candidate.name, identity: identity})
	}
	selected := &Selected{evidence: selectionEvidence{capabilities: caps, tools: tools}, effects: effects}
	globalGroup, err := selected.lookupGroup(ctx, false, "0")
	if err != nil {
		return nil, fmt.Errorf("prove global group NSS: %w", err)
	}
	localGroup, err := selected.lookupGroup(ctx, true, "0")
	if err != nil {
		return nil, fmt.Errorf("prove files group NSS: %w", err)
	}
	globalAccount, err := selected.lookupAccount(ctx, false, "0")
	if err != nil {
		return nil, fmt.Errorf("prove global passwd NSS: %w", err)
	}
	localAccount, err := selected.lookupAccount(ctx, true, "0")
	if err != nil {
		return nil, fmt.Errorf("prove files passwd NSS: %w", err)
	}
	group, groupOK := groupFound(globalGroup)
	localGroupValue, localGroupOK := groupFound(localGroup)
	account, accountOK := accountFound(globalAccount)
	localAccountValue, localAccountOK := accountFound(localAccount)
	if !groupOK || !localGroupOK || !sameGroup(group, localGroupValue) || group.gid != 0 ||
		!accountOK || !localAccountOK || account != localAccountValue || account.uid != 0 {
		return nil, fmt.Errorf("global and files-only root NSS baselines disagree")
	}
	selected.evidence.rootGroup, selected.evidence.rootAccount = group, account
	return selected, nil
}

func (selected *Selected) valid() bool {
	return selected != nil && selected.effects.identify != nil && selected.effects.run != nil &&
		len(selected.evidence.capabilities) != 0 && len(selected.evidence.tools) != 0
}

func (selected *Selected) tool(name string) (linux.Identity, bool) {
	if selected == nil {
		return linux.Identity{}, false
	}
	for _, tool := range selected.evidence.tools {
		if tool.name == name {
			return tool.identity, true
		}
	}
	return linux.Identity{}, false
}

func (selected *Selected) lookupGroup(ctx context.Context, local bool, key string) (groupLookup, error) {
	getent, ok := selected.tool("getent")
	if !ok {
		return groupLookup{}, fmt.Errorf("getent is not admitted")
	}
	args := []string{"group", key}
	if local {
		args = []string{"-s", "files", "group", key}
	}
	result, err := selected.effects.run(ctx, getent, args, nil)
	if missingResult(result, err) {
		return missingGroup(), nil
	}
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return groupLookup{}, nativeFailure("getent group", result, err)
	}
	record, err := oneRecord(result.Stdout)
	if err != nil {
		return groupLookup{}, err
	}
	parsed, err := parseGroupRecord(record)
	if err != nil {
		return groupLookup{}, err
	}
	return foundGroup(parsed), nil
}

func (selected *Selected) lookupAccount(ctx context.Context, local bool, key string) (accountLookup, error) {
	getent, ok := selected.tool("getent")
	if !ok {
		return accountLookup{}, fmt.Errorf("getent is not admitted")
	}
	args := []string{"passwd", key}
	if local {
		args = []string{"-s", "files", "passwd", key}
	}
	result, err := selected.effects.run(ctx, getent, args, nil)
	if missingResult(result, err) {
		return missingAccount(), nil
	}
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return accountLookup{}, nativeFailure("getent passwd", result, err)
	}
	record, err := oneRecord(result.Stdout)
	if err != nil {
		return accountLookup{}, err
	}
	parsed, err := parsePasswdRecord(record)
	if err != nil {
		return accountLookup{}, err
	}
	return foundAccount(parsed), nil
}

func (selected *Selected) observeGroup(ctx context.Context, desired model.Group) (groupObservation, error) {
	return selected.observeGroupIntent(ctx, groupIntentOf(desired))
}

func (selected *Selected) observeGroupIntent(ctx context.Context, desired groupIntent) (groupObservation, error) {
	globalName, err := selected.lookupGroup(ctx, false, desired.name)
	if err != nil {
		return groupObservation{}, err
	}
	localName, err := selected.lookupGroup(ctx, true, desired.name)
	if err != nil {
		return groupObservation{}, err
	}
	gid, haveGID := desired.gid, desired.managed
	if !haveGID {
		if found, ok := groupFound(globalName); ok {
			gid, haveGID = found.gid, true
		} else if found, ok := groupFound(localName); ok {
			gid, haveGID = found.gid, true
		}
	}
	if !haveGID {
		return groupObservation{nameGlobal: globalName, nameLocal: localName, numberGlobal: missingGroup(), numberLocal: missingGroup()}, nil
	}
	globalNumber, err := selected.lookupGroup(ctx, false, strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return groupObservation{}, err
	}
	localNumber, err := selected.lookupGroup(ctx, true, strconv.FormatUint(uint64(gid), 10))
	return groupObservation{nameGlobal: globalName, nameLocal: localName, numberGlobal: globalNumber, numberLocal: localNumber}, err
}

func (selected *Selected) observeAccount(ctx context.Context, desired model.Account) (accountObservation, error) {
	return selected.observeAccountIntent(ctx, accountIntentOf(desired))
}

func (selected *Selected) observeAccountIntent(ctx context.Context, desired accountIntent) (accountObservation, error) {
	globalName, err := selected.lookupAccount(ctx, false, desired.name)
	if err != nil {
		return accountObservation{}, err
	}
	localName, err := selected.lookupAccount(ctx, true, desired.name)
	if err != nil {
		return accountObservation{}, err
	}
	uid, haveUID := desired.uid, desired.managed
	if !haveUID {
		if found, ok := accountFound(globalName); ok {
			uid, haveUID = found.uid, true
		} else if found, ok := accountFound(localName); ok {
			uid, haveUID = found.uid, true
		}
	}
	if !haveUID {
		return accountObservation{nameGlobal: globalName, nameLocal: localName, numberGlobal: missingAccount(), numberLocal: missingAccount()}, nil
	}
	globalNumber, err := selected.lookupAccount(ctx, false, strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return accountObservation{}, err
	}
	localNumber, err := selected.lookupAccount(ctx, true, strconv.FormatUint(uint64(uid), 10))
	return accountObservation{nameGlobal: globalName, nameLocal: localName, numberGlobal: globalNumber, numberLocal: localNumber}, err
}

type operationKind uint8

const (
	createGroupOperation operationKind = iota + 1
	createAccountOperation
	lockAccountOperation
	setShellOperation
	setMembershipOperation
	createHomeOperation
	setHomeModeOperation
)

type Planned struct {
	decision    Decision
	operation   *Operation
	groupFact   GroupFact
	accountFact *AccountFact
}

type GroupFact struct {
	Name string
	GID  uint32
}

func (fact GroupFact) valid() bool { return fact.Name != "" && fact.Name != "root" && fact.GID != 0 }

type AccountFact struct {
	name, home string
	uid, gid   uint32
}

func (fact AccountFact) Name() string { return fact.name }
func (fact AccountFact) UID() uint32  { return fact.uid }
func (fact AccountFact) GID() uint32  { return fact.gid }
func (fact AccountFact) Home() string { return fact.home }

func (planned Planned) Decision() Decision { return planned.decision }
func (planned Planned) GroupFact() (GroupFact, bool) {
	return planned.groupFact, planned.groupFact.valid()
}
func (planned Planned) Operation() (Operation, bool) {
	if planned.operation == nil {
		return Operation{}, false
	}
	return *planned.operation, true
}
func (planned Planned) AccountFact() (AccountFact, bool) {
	if planned.accountFact == nil {
		return AccountFact{}, false
	}
	return *planned.accountFact, true
}

type Operation struct {
	kind              operationKind
	evidence          selectionEvidence
	group             groupIntent
	account           accountIntent
	primary           GroupFact
	groupBefore       groupObservation
	accountBefore     accountObservation
	lockAccount       string
	lockBefore        bool
	shellAccount      string
	shellValue        string
	shellBefore       passwdRecord
	membershipAccount string
	membershipGroup   string
	membershipPresent bool
	membershipBefore  groupRecord
	homeMode          uint16
	homeIntent        homeIntent
	homeBefore        homeState
}

func (selected *Selected) PlanGroup(ctx context.Context, desired model.Group) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, group, and bounded context are required")
	}
	observed, err := selected.observeGroup(ctx, desired)
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	decision := reconcileGroup(desired, observed)
	planned := Planned{decision: decision}
	if decision.kind == Exact {
		if record, ok := groupFound(observed.nameGlobal); ok {
			planned.groupFact = GroupFact{Name: record.name, GID: record.gid}
		}
	}
	if decision.kind == Change {
		if _, ok := selected.tool("groupadd"); !ok {
			return Planned{decision: blocked("groupadd is not admitted")}, nil
		}
		planned.operation = &Operation{kind: createGroupOperation, evidence: selected.evidence, group: groupIntentOf(desired), groupBefore: observed}
	}
	return planned, nil
}

func (selected *Selected) PlanAccount(ctx context.Context, desired model.Account, primary model.Group, primaryFact GroupFact) (Planned, error) {
	if !selected.valid() || !desired.Valid() || desired.Managed() && !primary.Valid() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, account, managed primary group when owned, and bounded context are required")
	}
	observed, err := selected.observeAccount(ctx, desired)
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if primary.Valid() && primary.Managed() {
		primaryFact = GroupFact{Name: primary.Name(), GID: primary.GID()}
	}
	decision := reconcileAccount(desired, primary, primaryFact, observed)
	planned := Planned{decision: decision}
	if decision.kind == Exact {
		if record, ok := accountFound(observed.nameGlobal); ok {
			planned.accountFact = &AccountFact{name: record.name, uid: record.uid, gid: record.gid, home: record.home}
		}
	}
	if decision.kind == Change {
		if _, ok := selected.tool("useradd"); !ok {
			return Planned{decision: blocked("useradd is not admitted")}, nil
		}
		if _, ok := selected.tool("passwd"); !ok {
			return Planned{decision: blocked("passwd status is not admitted")}, nil
		}
		planned.operation = &Operation{kind: createAccountOperation, evidence: selected.evidence, account: accountIntentOf(desired), primary: primaryFact, accountBefore: observed}
	}
	return planned, nil
}

func (selected *Selected) PlanLock(ctx context.Context, desired model.AccountLock) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, lock, and bounded context are required")
	}
	locked, err := selected.observeLock(ctx, desired.Account())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if locked {
		return Planned{decision: Decision{kind: Exact, detail: "account is locked"}}, nil
	}
	if _, ok := selected.tool("passwd"); !ok {
		return Planned{decision: blocked("passwd is not admitted")}, nil
	}
	return Planned{decision: Decision{kind: Change, detail: "account requires lock"}, operation: &Operation{kind: lockAccountOperation, evidence: selected.evidence, lockAccount: desired.Account(), lockBefore: false}}, nil
}

func (selected *Selected) PlanShell(ctx context.Context, desired model.AccountShell) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, shell, and bounded context are required")
	}
	before, err := selected.observeNamedAccount(ctx, desired.Account())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if before.shell == desired.Shell() {
		return Planned{decision: Decision{kind: Exact, detail: "account shell is exact"}}, nil
	}
	if _, ok := selected.tool("usermod"); !ok {
		return Planned{decision: blocked("usermod is not admitted")}, nil
	}
	return Planned{decision: Decision{kind: Change, detail: "account shell differs"}, operation: &Operation{kind: setShellOperation, evidence: selected.evidence, shellAccount: desired.Account(), shellValue: desired.Shell(), shellBefore: before}}, nil
}

func (selected *Selected) PlanMembership(ctx context.Context, desired model.Membership) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, membership, and bounded context are required")
	}
	account, err := selected.observeNamedAccount(ctx, desired.Account())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	before, err := selected.observeNamedGroup(ctx, desired.Group())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if account.gid == before.gid {
		return Planned{decision: blocked("primary group cannot be supplementary")}, nil
	}
	present := slices.Contains(before.members, desired.Account())
	if present == desired.Present() {
		return Planned{decision: Decision{kind: Exact, detail: "membership is exact"}}, nil
	}
	if _, ok := selected.tool("gpasswd"); !ok {
		return Planned{decision: blocked("gpasswd is not admitted")}, nil
	}
	return Planned{decision: Decision{kind: Change, detail: "membership differs"}, operation: &Operation{kind: setMembershipOperation, evidence: selected.evidence, membershipAccount: desired.Account(), membershipGroup: desired.Group(), membershipPresent: desired.Present(), membershipBefore: before}}, nil
}

type ApplyResult struct {
	started  bool
	decision Decision
}

func (result ApplyResult) Started() bool      { return result.started }
func (result ApplyResult) Decision() Decision { return result.decision }

func (operation Operation) Apply(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	if !linux.FutureContext(effectCtx) || freshPost == nil || !fresh.valid() {
		return ApplyResult{}, fmt.Errorf("fresh selection, bounded effect context, and fresh post-observation context are required")
	}
	if !sameSelectionEvidence(operation.evidence, fresh.evidence) {
		return ApplyResult{}, fmt.Errorf("%w: shadow evidence changed", ErrStale)
	}
	switch operation.kind {
	case createGroupOperation:
		return operation.applyGroup(effectCtx, freshPost, fresh)
	case createAccountOperation:
		return operation.applyAccount(effectCtx, freshPost, fresh)
	case lockAccountOperation:
		return operation.applyLock(effectCtx, freshPost, fresh)
	case setShellOperation:
		return operation.applyShell(effectCtx, freshPost, fresh)
	case setMembershipOperation:
		return operation.applyMembership(effectCtx, freshPost, fresh)
	case createHomeOperation:
		return operation.applyHome(effectCtx, freshPost, fresh)
	case setHomeModeOperation:
		return operation.applyHomeMode(effectCtx, freshPost, fresh)
	default:
		return ApplyResult{}, fmt.Errorf("invalid identity operation")
	}
}

func (operation Operation) applyLock(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	before, err := fresh.observeLock(effectCtx, operation.lockAccount)
	if err != nil {
		return ApplyResult{}, err
	}
	if before != operation.lockBefore {
		return ApplyResult{}, fmt.Errorf("%w: lock observation changed", ErrStale)
	}
	tool, _ := fresh.tool("passwd")
	result, runErr := fresh.effects.run(effectCtx, tool, []string{"-l", operation.lockAccount}, nil)
	runErr = linux.CommandFailure("lock account", result, runErr)
	return finishIdentity(result.Started, runErr, freshPost, "lock postcondition is not exact", func(ctx context.Context) (Decision, bool, error) {
		after, err := fresh.observeLock(ctx, operation.lockAccount)
		return exactIdentity(after, "account is locked"), after, err
	})
}

func (operation Operation) applyShell(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	before, err := fresh.observeNamedAccount(effectCtx, operation.shellAccount)
	if err != nil {
		return ApplyResult{}, err
	}
	if before != operation.shellBefore {
		return ApplyResult{}, fmt.Errorf("%w: shell account observation changed", ErrStale)
	}
	tool, _ := fresh.tool("usermod")
	result, runErr := fresh.effects.run(effectCtx, tool, []string{"--shell", operation.shellValue, "--", operation.shellAccount}, nil)
	runErr = linux.CommandFailure("set account shell", result, runErr)
	return finishIdentity(result.Started, runErr, freshPost, "shell postcondition is not exact", func(ctx context.Context) (Decision, bool, error) {
		after, err := fresh.observeNamedAccount(ctx, operation.shellAccount)
		exact := after.shell == operation.shellValue
		return exactIdentity(exact, "account shell is exact"), exact, err
	})
}

func (operation Operation) applyMembership(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	before, err := fresh.observeNamedGroup(effectCtx, operation.membershipGroup)
	if err != nil {
		return ApplyResult{}, err
	}
	if !sameGroup(before, operation.membershipBefore) {
		return ApplyResult{}, fmt.Errorf("%w: membership group observation changed", ErrStale)
	}
	verb := "--add"
	if !operation.membershipPresent {
		verb = "--delete"
	}
	tool, _ := fresh.tool("gpasswd")
	result, runErr := fresh.effects.run(effectCtx, tool, []string{verb, operation.membershipAccount, operation.membershipGroup}, nil)
	runErr = linux.CommandFailure("set group membership", result, runErr)
	return finishIdentity(result.Started, runErr, freshPost, "membership postcondition is not exact", func(ctx context.Context) (Decision, bool, error) {
		after, err := fresh.observeNamedGroup(ctx, operation.membershipGroup)
		exact := operation.membershipPresent == slices.Contains(after.members, operation.membershipAccount) && slices.Equal(withoutMember(before.members, operation.membershipAccount), withoutMember(after.members, operation.membershipAccount))
		return exactIdentity(exact, "membership is exact"), exact, err
	})
}

func (selected *Selected) observeNamedAccount(ctx context.Context, name string) (passwdRecord, error) {
	global, err := selected.lookupAccount(ctx, false, name)
	if err != nil {
		return passwdRecord{}, err
	}
	local, err := selected.lookupAccount(ctx, true, name)
	if err != nil {
		return passwdRecord{}, err
	}
	globalValue, globalOK := accountFound(global)
	localValue, localOK := accountFound(local)
	if !globalOK || !localOK || globalValue != localValue || globalValue.name != name {
		return passwdRecord{}, fmt.Errorf("global and files-only account records are not exact")
	}
	return globalValue, nil
}

func (selected *Selected) observeNamedGroup(ctx context.Context, name string) (groupRecord, error) {
	global, err := selected.lookupGroup(ctx, false, name)
	if err != nil {
		return groupRecord{}, err
	}
	local, err := selected.lookupGroup(ctx, true, name)
	if err != nil {
		return groupRecord{}, err
	}
	globalValue, globalOK := groupFound(global)
	localValue, localOK := groupFound(local)
	if !globalOK || !localOK || !sameGroup(globalValue, localValue) || globalValue.name != name {
		return groupRecord{}, fmt.Errorf("global and files-only group records are not exact")
	}
	return globalValue, nil
}

func withoutMember(values []string, account string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != account {
			result = append(result, value)
		}
	}
	return result
}

func (operation Operation) applyGroup(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	before, err := fresh.observeGroupIntent(effectCtx, operation.group)
	if err != nil {
		return ApplyResult{}, err
	}
	if !reflect.DeepEqual(before, operation.groupBefore) {
		return ApplyResult{}, fmt.Errorf("%w: group observation changed", ErrStale)
	}
	tool, _ := fresh.tool("groupadd")
	result, runErr := fresh.effects.run(effectCtx, tool, []string{"--gid", strconv.FormatUint(uint64(operation.group.gid), 10), "--", operation.group.name}, nil)
	runErr = linux.CommandFailure("create group", result, runErr)
	return finishIdentity(result.Started, runErr, freshPost, "group postcondition is not exact", func(ctx context.Context) (Decision, bool, error) {
		after, err := fresh.observeGroupIntent(ctx, operation.group)
		decision := Decision{}
		if err == nil {
			decision = reconcileGroupIntent(operation.group, after)
		}
		return decision, decision.kind == Exact, err
	})
}

func (operation Operation) applyAccount(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	primary := groupIntent{name: operation.primary.Name, managed: true, gid: operation.primary.GID}
	primaryBefore, err := fresh.observeGroupIntent(effectCtx, primary)
	if err != nil || reconcileGroupIntent(primary, primaryBefore).kind != Exact {
		return ApplyResult{}, errors.Join(fmt.Errorf("%w: primary group evidence changed", ErrStale), err)
	}
	before, err := fresh.observeAccountIntent(effectCtx, operation.account)
	if err != nil {
		return ApplyResult{}, err
	}
	if !reflect.DeepEqual(before, operation.accountBefore) {
		return ApplyResult{}, fmt.Errorf("%w: account observation changed", ErrStale)
	}
	tool, _ := fresh.tool("useradd")
	args := []string{"--uid", strconv.FormatUint(uint64(operation.account.uid), 10), "--gid", strconv.FormatUint(uint64(operation.primary.GID), 10), "--home-dir", operation.account.home, "--no-create-home", "--no-user-group", "--", operation.account.name}
	result, runErr := fresh.effects.run(effectCtx, tool, args, nil)
	runErr = linux.CommandFailure("create account", result, runErr)
	return finishIdentity(result.Started, runErr, freshPost, "account or lock postcondition is not exact", func(ctx context.Context) (Decision, bool, error) {
		after, observeErr := fresh.observeAccountIntent(ctx, operation.account)
		decision := Decision{}
		if observeErr == nil {
			decision = reconcileAccountIntent(operation.account, operation.primary, after)
		}
		locked, lockErr := fresh.observeLock(ctx, operation.account.name)
		return decision, decision.kind == Exact && locked, errors.Join(observeErr, lockErr)
	})
}

func exactIdentity(exact bool, detail string) Decision {
	if exact {
		return Decision{kind: Exact, detail: detail}
	}
	return Decision{}
}

func finishIdentity(started bool, effectErr error, freshPost func() (context.Context, context.CancelFunc), failure string, observe func(context.Context) (Decision, bool, error)) (ApplyResult, error) {
	result := ApplyResult{started: started}
	ctx, cancel, err := beginPost(freshPost)
	if err != nil {
		return result, errors.Join(effectErr, err)
	}
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, errors.Join(effectErr, err)
	}
	decision, exact, observeErr := observe(ctx)
	result.decision = decision
	if observeErr == nil && exact {
		return result, nil
	}
	return result, errors.Join(effectErr, observeErr, fmt.Errorf("%s", failure))
}

func beginPost(freshPost func() (context.Context, context.CancelFunc)) (context.Context, context.CancelFunc, error) {
	if freshPost == nil {
		return nil, nil, fmt.Errorf("fresh bounded post-observation context is required")
	}
	ctx, cancel := freshPost()
	if cancel == nil || !linux.FutureContext(ctx) {
		if cancel != nil {
			cancel()
		}
		return nil, nil, fmt.Errorf("fresh bounded post-observation context is required")
	}
	return ctx, cancel, nil
}

func (selected *Selected) observeLock(ctx context.Context, account string) (bool, error) {
	passwd, ok := selected.tool("passwd")
	if !ok {
		return false, fmt.Errorf("passwd status is not admitted")
	}
	result, err := selected.effects.run(ctx, passwd, []string{"-S", account}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return false, nativeFailure("passwd status", result, err)
	}
	fields := strings.Fields(strings.TrimSuffix(string(result.Stdout), "\n"))
	if len(fields) < 2 || fields[0] != account || !strings.HasSuffix(string(result.Stdout), "\n") {
		return false, fmt.Errorf("malformed passwd status")
	}
	return fields[1] == "L", nil
}

func sameSelectionEvidence(left, right selectionEvidence) bool {
	return reflect.DeepEqual(left, right)
}

func missingResult(result linux.Result, err error) bool {
	return err == nil && result.Started && result.ExitCode == 2 && len(result.Stdout) == 0 && len(result.Stderr) == 0
}

func oneRecord(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || strings.Count(string(data), "\n") != 1 {
		return "", fmt.Errorf("NSS lookup did not return one newline-terminated record")
	}
	return string(data[:len(data)-1]), nil
}

func nativeFailure(action string, result linux.Result, err error) error {
	detail := fmt.Errorf("%s failed: started=%t exit=%d stderr=%q", action, result.Started, result.ExitCode, result.Stderr)
	return errors.Join(detail, err)
}
