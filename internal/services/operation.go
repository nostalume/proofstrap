package services

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/nostalume/proofstrap/internal/linux"
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
	if !operation.valid() || !fresh.valid() || !linux.FutureContext(effectCtx) || freshPost == nil {
		return ApplyResult{}, fmt.Errorf("valid service operation, fresh selection, bounded effect context, and fresh post-observation context are required")
	}
	if operation.evidence != fresh.evidence {
		return ApplyResult{}, fmt.Errorf("%w: service selection evidence changed", ErrStale)
	}
	desired := Demand{backend: operation.evidence.backend, value: operation.demand}
	before, err := fresh.Observe(effectCtx, []Demand{desired})
	if err != nil {
		return ApplyResult{}, err
	}
	record, _ := before.record(desired)
	if operation.axisState(record) != operation.before {
		return ApplyResult{}, fmt.Errorf("%w: service axis observation changed", ErrStale)
	}
	tool, args := fresh.effectCommand(operation)
	result, runErr := fresh.effects.run(effectCtx, tool, args, nil)
	runErr = commandFailure(operation.verb()+" service", result, runErr)
	postCtx, cancelPost := freshPost()
	if cancelPost == nil || !linux.FutureContext(postCtx) {
		if cancelPost != nil {
			cancelPost()
		}
		return ApplyResult{started: result.Started}, errors.Join(runErr, fmt.Errorf("fresh bounded service post-observation context is required"))
	}
	defer cancelPost()
	apply := ApplyResult{started: result.Started}
	decision, observeErr := operation.observePost(postCtx, fresh, desired, result.Started)
	apply.decision = decision
	if apply.decision.kind == Exact {
		return apply, nil
	}
	return apply, errors.Join(runErr, observeErr, fmt.Errorf("service axis postcondition is not exact: %s", apply.decision.detail))
}

func (operation Operation) observePost(ctx context.Context, fresh *Selected, desired Demand, settle bool) (Decision, error) {
	delay := 10 * time.Millisecond
	for attempt := 0; attempt < 8; attempt++ {
		after, err := fresh.Observe(ctx, []Demand{desired})
		if err != nil {
			return Decision{}, err
		}
		record, _ := after.record(desired)
		decision := operation.postDecision(record)
		if decision.kind == Exact || !settle || !operation.openRCMaySettle(record) || attempt == 7 {
			return decision, nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return decision, ctx.Err()
		case <-timer.C:
		}
		if delay < 200*time.Millisecond {
			delay *= 2
			if delay > 200*time.Millisecond {
				delay = 200 * time.Millisecond
			}
		}
	}
	return Decision{}, fmt.Errorf("service post-observation attempts exhausted")
}

func (operation Operation) openRCMaySettle(record unitRecord) bool {
	if operation.evidence.backend != "openrc" {
		return false
	}
	if operation.kind == startOperation {
		return record.active == "inactive" || record.active == "activating" || record.active == "failed"
	}
	if operation.kind == stopOperation {
		return record.active == "active" || record.active == "deactivating"
	}
	return false
}

func (selected *Selected) effectCommand(operation Operation) (linux.Identity, []string) {
	if selected.evidence.backend == "openrc" {
		if operation.kind == enableOperation {
			return selected.evidence.update, []string{"add", operation.demand.unit, "default"}
		}
		if operation.kind == disableOperation {
			return selected.evidence.update, []string{"delete", operation.demand.unit, "default"}
		}
		return selected.evidence.tool, []string{operation.demand.unit, operation.verb()}
	}
	return selected.evidence.tool, append(selected.prefix(), operation.verb(), "--", operation.demand.unit)
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
	if value.scope < systemScope || value.scope > userScope || !filepath.IsAbs(value.tool.Path) || filepath.Clean(value.tool.Path) != value.tool.Path || !validText(value.version, 255) || value.euid != 0 {
		return false
	}
	if value.backend == "openrc" {
		return value.scope == systemScope && filepath.IsAbs(value.status.Path) && filepath.Clean(value.status.Path) == value.status.Path && filepath.IsAbs(value.update.Path) && filepath.Clean(value.update.Path) == value.update.Path && validText(value.control, 63) && value.pid1 == "" && !value.principal.admitted && value.home == (homeEvidence{})
	}
	if value.backend != "systemd" || value.pid1 != "systemd" || value.status != (linux.Identity{}) || value.update != (linux.Identity{}) || value.control != "" {
		return false
	}
	if value.scope == systemScope {
		return !value.principal.admitted && value.home == (homeEvidence{})
	}
	return value.principal.valid() && value.home.directory && value.home.path == value.principal.home && value.home.uid == value.principal.uid && value.home.mode <= 0o777
}
