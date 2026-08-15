package services

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

type ApplyResult struct {
	started  bool
	decision Decision
}

func (result ApplyResult) Started() bool      { return result.started }
func (result ApplyResult) Decision() Decision { return result.decision }

func (operation Operation) valid() bool {
	if !validSelectionEvidence(operation.evidence) || !validDemand(operation.demand) || operation.before.id != operation.demand.unit || operation.before.load != "loaded" {
		return false
	}
	if operation.evidence.scope == systemScope && operation.demand.user != "" || operation.evidence.scope == userScope && operation.demand.user != operation.evidence.principal.name {
		return false
	}
	switch operation.kind {
	case enableOperation:
		return operation.demand.persistence == wantOn && operation.before.value == "disabled" && operation.before.sub == ""
	case disableOperation:
		return operation.demand.persistence == wantOff && operation.before.value == "enabled" && operation.before.sub == ""
	case startOperation:
		return operation.demand.runtime == wantOn && operation.before.value == "inactive" && validText(operation.before.sub, 255)
	case stopOperation:
		return operation.demand.runtime == wantOff && operation.before.value == "active" && validText(operation.before.sub, 255)
	default:
		return false
	}
}

func (operation Operation) Apply(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	if !operation.valid() || !fresh.valid() || !futureContext(effectCtx) || freshPost == nil {
		return ApplyResult{}, fmt.Errorf("valid service operation, fresh selection, bounded effect context, and fresh post-observation context are required")
	}
	if operation.evidence != fresh.evidence {
		return ApplyResult{}, fmt.Errorf("%w: service selection evidence changed", ErrStale)
	}
	before, err := fresh.Observe(effectCtx, []Demand{{value: operation.demand}})
	if err != nil {
		return ApplyResult{}, err
	}
	record, _ := before.record(Demand{value: operation.demand})
	if operation.axisState(record) != operation.before {
		return ApplyResult{}, fmt.Errorf("%w: service axis observation changed", ErrStale)
	}
	args := append(fresh.prefix(), operation.verb(), "--", operation.demand.unit)
	result, runErr := fresh.effects.run(effectCtx, fresh.evidence.tool, args, nil)
	runErr = commandFailure(operation.verb()+" service", result, runErr)
	postCtx, cancelPost := freshPost()
	if cancelPost == nil || !futureContext(postCtx) {
		if cancelPost != nil {
			cancelPost()
		}
		return ApplyResult{started: result.Started}, errors.Join(runErr, fmt.Errorf("fresh bounded service post-observation context is required"))
	}
	defer cancelPost()
	after, observeErr := fresh.Observe(postCtx, []Demand{{value: operation.demand}})
	apply := ApplyResult{started: result.Started}
	if observeErr == nil {
		record, _ = after.record(Demand{value: operation.demand})
		apply.decision = operation.postDecision(record)
	}
	if apply.decision.kind == Exact {
		return apply, nil
	}
	return apply, errors.Join(runErr, observeErr, fmt.Errorf("service axis postcondition is not exact"))
}

func (operation Operation) axisState(record unitRecord) axisState {
	if operation.kind == enableOperation || operation.kind == disableOperation {
		return persistenceState(record)
	}
	return runtimeState(record)
}

func (operation Operation) postDecision(record unitRecord) Decision {
	if operation.kind == enableOperation || operation.kind == disableOperation {
		return reconcilePersistence(operation.demand.persistence, record)
	}
	return reconcileRuntime(operation.demand.runtime, record)
}

func (operation Operation) verb() string {
	switch operation.kind {
	case enableOperation:
		return "enable"
	case disableOperation:
		return "disable"
	case startOperation:
		return "start"
	case stopOperation:
		return "stop"
	default:
		return ""
	}
}

func validSelectionEvidence(value selectionEvidence) bool {
	if value.scope < systemScope || value.scope > userScope || !filepath.IsAbs(value.tool.Path) || filepath.Clean(value.tool.Path) != value.tool.Path || !validText(value.version, 255) || value.euid != 0 || value.pid1 != "systemd" {
		return false
	}
	if value.scope == systemScope {
		return !value.principal.admitted && value.home == (homeEvidence{})
	}
	return value.principal.valid() && value.home.directory && value.home.path == value.principal.home && value.home.uid == value.principal.uid && value.home.mode <= 0o777
}
