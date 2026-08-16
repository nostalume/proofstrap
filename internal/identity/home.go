package identity

import (
	"context"
	"fmt"
	"reflect"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
)

type homeState struct {
	exists, trusted, directory bool
	uid, gid                   uint32
	mode                       uint16
}

type homeEffects struct {
	observe func(string) (homeState, error)
	create  func(string, uint32, uint32) (bool, error)
	chmod   func(string, uint16) (bool, error)
}

func (effects homeEffects) valid() bool {
	return effects.observe != nil && effects.create != nil && effects.chmod != nil
}

type homeIntent struct {
	path     string
	uid, gid uint32
}

func (selected *Selected) PlanHome(ctx context.Context, desired model.Home, account model.Account) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !account.Valid() || desired.Account() != account.Name() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, home/account pair, and bounded context are required")
	}
	if !selected.effects.home.valid() {
		return Planned{decision: blocked("home filesystem effects are unavailable")}, nil
	}
	record, err := selected.observeNamedAccount(ctx, account.Name())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if record.uid == 0 || record.gid == 0 || record.home == "/" {
		return Planned{decision: blocked("root home is outside identity authority")}, nil
	}
	intent := homeIntent{path: record.home, uid: record.uid, gid: record.gid}
	before, err := selected.effects.home.observe(intent.path)
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	decision := reconcileHome(intent, before)
	planned := Planned{decision: decision}
	if decision.kind == Change {
		planned.operation = &Operation{kind: createHomeOperation, evidence: selected.evidence, account: accountIntent{name: account.Name()}, homeIntent: intent, homeBefore: before}
	}
	return planned, nil
}

func (selected *Selected) PlanHomeMode(ctx context.Context, desired model.HomeMode, account model.Account) (Planned, error) {
	if !selected.valid() || !desired.Valid() || !account.Valid() || desired.Account() != account.Name() || !linux.FutureContext(ctx) {
		return Planned{}, fmt.Errorf("valid selection, home mode/account pair, and bounded context are required")
	}
	if !selected.effects.home.valid() {
		return Planned{decision: blocked("home filesystem effects are unavailable")}, nil
	}
	record, err := selected.observeNamedAccount(ctx, account.Name())
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if record.uid == 0 || record.gid == 0 || record.home == "/" {
		return Planned{decision: blocked("root home is outside identity authority")}, nil
	}
	intent := homeIntent{path: record.home, uid: record.uid, gid: record.gid}
	before, err := selected.effects.home.observe(intent.path)
	if err != nil {
		return Planned{decision: blocked(err.Error())}, nil
	}
	if reconcileHome(intent, before).kind != Exact {
		return Planned{decision: blocked("home identity is not exact")}, nil
	}
	if before.mode == desired.Mode() {
		return Planned{decision: Decision{kind: Exact, detail: "home mode is exact"}}, nil
	}
	return Planned{decision: Decision{kind: Change, detail: "home mode differs"}, operation: &Operation{kind: setHomeModeOperation, evidence: selected.evidence, account: accountIntent{name: account.Name()}, homeMode: desired.Mode(), homeIntent: intent, homeBefore: before}}, nil
}

func reconcileHome(intent homeIntent, observed homeState) Decision {
	if !observed.trusted {
		return blocked("home ancestry is not trusted")
	}
	if !observed.exists {
		return Decision{kind: Change, detail: "home is absent under trusted ancestry"}
	}
	if !observed.directory || observed.uid != intent.uid || observed.gid != intent.gid {
		return blocked("existing home type or ownership differs")
	}
	return Decision{kind: Exact, detail: "home directory and ownership are exact"}
}

func (operation Operation) applyHome(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	if !fresh.effects.home.valid() {
		return ApplyResult{}, fmt.Errorf("home filesystem effects are unavailable")
	}
	record, err := fresh.observeNamedAccount(effectCtx, operation.account.name)
	if err != nil || record.uid != operation.homeIntent.uid || record.gid != operation.homeIntent.gid || record.home != operation.homeIntent.path {
		return ApplyResult{}, fmt.Errorf("%w: home account evidence changed", ErrStale)
	}
	before, err := fresh.effects.home.observe(operation.homeIntent.path)
	if err != nil {
		return ApplyResult{}, err
	}
	if !reflect.DeepEqual(before, operation.homeBefore) {
		return ApplyResult{}, fmt.Errorf("%w: home observation changed", ErrStale)
	}
	started, effectErr := fresh.effects.home.create(operation.homeIntent.path, operation.homeIntent.uid, operation.homeIntent.gid)
	return finishIdentity(started, effectErr, freshPost, "home postcondition is not exact", func(context.Context) (Decision, bool, error) {
		after, err := fresh.effects.home.observe(operation.homeIntent.path)
		decision := reconcileHome(operation.homeIntent, after)
		return decision, decision.kind == Exact, err
	})
}

func (operation Operation) applyHomeMode(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	if !fresh.effects.home.valid() {
		return ApplyResult{}, fmt.Errorf("home filesystem effects are unavailable")
	}
	record, err := fresh.observeNamedAccount(effectCtx, operation.account.name)
	if err != nil || record.uid != operation.homeIntent.uid || record.gid != operation.homeIntent.gid || record.home != operation.homeIntent.path {
		return ApplyResult{}, fmt.Errorf("%w: home mode account evidence changed", ErrStale)
	}
	before, err := fresh.effects.home.observe(operation.homeIntent.path)
	if err != nil {
		return ApplyResult{}, err
	}
	if !reflect.DeepEqual(before, operation.homeBefore) {
		return ApplyResult{}, fmt.Errorf("%w: home mode observation changed", ErrStale)
	}
	started, effectErr := fresh.effects.home.chmod(operation.homeIntent.path, operation.homeMode)
	return finishIdentity(started, effectErr, freshPost, "home mode postcondition is not exact", func(context.Context) (Decision, bool, error) {
		after, err := fresh.effects.home.observe(operation.homeIntent.path)
		exact := reconcileHome(operation.homeIntent, after).kind == Exact && after.mode == operation.homeMode
		return exactIdentity(exact, "home mode is exact"), exact, err
	})
}
