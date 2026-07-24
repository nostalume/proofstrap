package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func Apply(state DesiredState, runner Runner, acceptedDigest string) ApplyReceipt {
	current := planFor(state, runner, production)
	review := current.review()
	digest := review.Digest()
	base := ApplyReceipt{AcceptedDigest: acceptedDigest, PlanDigest: digest}
	if acceptedDigest != digest {
		base.Status = Stale
		return base
	}
	return current.apply(runner, base)
}

func matchesSingleProjectedCommand(review ReviewPlan, projection Change, command Command) bool {
	projected := Command{Name: command.Name, Args: append([]string(nil), command.Args...)}
	return len(review.Changes) == 1 && reflect.DeepEqual(review.Changes[0], projection) &&
		projection.Command != nil && reflect.DeepEqual(*projection.Command, projected)
}

func (plan blockedPlan) apply(_ Runner, receipt ApplyReceipt) ApplyReceipt {
	receipt.Status, receipt.Blockers = Blocked, append([]Blocker(nil), plan.plan.Blockers...)
	return receipt
}

func failedAccountGuard(receipt ApplyReceipt, action, subject, detail string) ApplyReceipt {
	status, _ := receipt.transition(receiptTransition{failed: true})
	receipt.Blockers = []Blocker{{Subject: subject, Detail: detail}}
	receipt.Outcomes = []ActionOutcome{{Action: action, Status: status, Detail: detail}}
	return receipt
}

func initialHostGuard(receipt ApplyReceipt, host hostBinding, runner Runner) (ApplyReceipt, bool) {
	stale, err := host.guard(runner)
	if err != nil {
		receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = []Blocker{{Subject: "guard:host", Detail: err.Error()}}
		return receipt, true
	}
	if stale {
		receipt.transition(receiptTransition{stale: true})
		return receipt, true
	}
	return receipt, false
}

func immediateHostGuard(receipt ApplyReceipt, host hostBinding, runner Runner, action, driftDetail string) (ApplyReceipt, bool, string) {
	stale, err := host.guard(runner)
	if err != nil {
		status, _ := receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = append(receipt.Blockers, Blocker{Subject: "guard:host", Detail: err.Error()})
		receipt.Outcomes = append(receipt.Outcomes, ActionOutcome{Action: action, Status: status, Detail: err.Error()})
		return receipt, true, err.Error()
	}
	if stale {
		transition := receiptTransition{failed: true}
		if len(receipt.Outcomes) == 0 {
			transition = receiptTransition{stale: true}
		}
		status, _ := receipt.transition(transition)
		receipt.Outcomes = append(receipt.Outcomes, ActionOutcome{Action: action, Status: status, Detail: driftDetail})
		return receipt, true, driftDetail
	}
	return receipt, false, ""
}

func finalHostGuard(host hostBinding, runner Runner) (string, bool) {
	stale, err := host.guard(runner)
	if err != nil {
		return err.Error(), true
	}
	if stale {
		return "host evidence changed during apply", true
	}
	return "", false
}

func (plan readyPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	if err := plan.validateProjections(); err != nil {
		receipt.transition(receiptTransition{failed: true})
		return receipt
	}
	ctx := context.Background()
	if guarded, stop := plan.initialGuards(ctx, runner, receipt); stop {
		return guarded
	}
	for i, prepared := range plan.steps {
		step := prepared.step
		if guarded, stop := plan.guardStep(ctx, runner, receipt, i); stop {
			return guarded
		}
		stepContext, cancel := context.WithTimeout(ctx, step.timeout)
		result := runner.Run(stepContext, prepared.command)
		cancel()
		if result.Err != nil || result.ExitCode != 0 {
			receipt.transition(receiptTransition{attempted: true, failed: true})
			detail := commandFailure(prepared.command, result)
			if step.verify != nil {
				_, postState := step.verify(ctx, runner)
				detail += "; post-state: " + postState
			}
			receipt.Outcomes = append(receipt.Outcomes, failureOutcomes(plan.steps, i, detail)...)
			return receipt
		}
		if satisfied, detail := step.verify(ctx, runner); !satisfied {
			receipt.transition(receiptTransition{attempted: true, failed: true})
			receipt.Outcomes = append(receipt.Outcomes, failureOutcomes(plan.steps, i, "verification: post-state not satisfied: "+detail)...)
			return receipt
		}
		status, _ := receipt.transition(receiptTransition{attempted: true, verified: true})
		receipt.Outcomes = append(receipt.Outcomes, ActionOutcome{Action: step.id, Status: status, Detail: "verified"})
	}
	if blockers := plan.finalState(ctx, runner); len(blockers) != 0 {
		transition := receiptTransition{failed: true}
		if len(receipt.Outcomes) != 0 {
			transition = receiptTransition{attempted: true, verified: true, failed: true}
		}
		receipt.transition(transition)
		receipt.Blockers = blockers
		return receipt
	}
	transition := receiptTransition{}
	if len(receipt.Outcomes) != 0 {
		transition = receiptTransition{attempted: true, verified: true}
	}
	receipt.transition(transition)
	return receipt
}

func (plan readyPlan) initialGuards(ctx context.Context, runner Runner, receipt ApplyReceipt) (ApplyReceipt, bool) {
	if guarded, stop := initialHostGuard(receipt, plan.host, runner); stop {
		return guarded, true
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt, true
	} else if stale {
		receipt.transition(receiptTransition{stale: true})
		return receipt, true
	}
	if plan.targetUser {
		if stale, err := plan.account.guardUID(runner); err != nil {
			receipt.transition(receiptTransition{failed: true})
			receipt.Blockers = []Blocker{{Subject: "guard:account-target", Detail: err.Error()}}
			return receipt, true
		} else if stale {
			receipt.transition(receiptTransition{stale: true})
			return receipt, true
		}
	}
	if len(plan.bound.packageNeeds) != 0 {
		stale, err := plan.guardPackages(ctx, runner)
		if err != nil {
			receipt.transition(receiptTransition{failed: true})
			return receipt, true
		}
		if stale {
			receipt.transition(receiptTransition{stale: true})
			return receipt, true
		}
	}
	if stale, err := plan.guardServices(ctx, runner); err != nil {
		receipt.transition(receiptTransition{failed: true})
		return receipt, true
	} else if stale {
		receipt.transition(receiptTransition{stale: true})
		return receipt, true
	}
	if stale, err := plan.guardConflicts(ctx, runner); err != nil {
		receipt.transition(receiptTransition{failed: true})
		return receipt, true
	} else if stale {
		receipt.transition(receiptTransition{stale: true})
		return receipt, true
	}
	return receipt, false
}

func (plan readyPlan) guardStep(ctx context.Context, runner Runner, receipt ApplyReceipt, index int) (ApplyReceipt, bool) {
	step := plan.steps[index].step
	if err := step.before(ctx, runner); err != nil {
		transition := receiptTransition{failed: true}
		var stale stalePrecondition
		if errors.As(err, &stale) && len(receipt.Outcomes) == 0 {
			transition = receiptTransition{stale: true}
		}
		receipt.transition(transition)
		receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, index, err.Error())...)
		return receipt, true
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil || stale {
		detail := "account evidence changed immediately before action"
		transition := receiptTransition{failed: true}
		if err != nil {
			detail = err.Error()
			receipt.Blockers = append(receipt.Blockers, Blocker{Subject: "guard:account", Detail: detail})
		} else if len(receipt.Outcomes) == 0 {
			transition = receiptTransition{stale: true}
		}
		receipt.transition(transition)
		receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, index, detail)...)
		return receipt, true
	}
	if guarded, stop := plan.guardDirectStep(runner, receipt, index); stop {
		return guarded, true
	}
	if guarded, stop, detail := immediateHostGuard(receipt, plan.host, runner, step.id, "host evidence changed immediately before action"); stop {
		receipt = guarded
		receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, index+1, detail)...)
		return receipt, true
	}
	return receipt, false
}

func (plan readyPlan) guardDirectStep(runner Runner, receipt ApplyReceipt, index int) (ApplyReceipt, bool) {
	if !plan.targetUser || plan.steps[index].step.access != directStep {
		return receipt, false
	}
	stale, err := plan.account.guardUID(runner)
	if err == nil && !stale {
		return receipt, false
	}
	transition := receiptTransition{failed: true}
	if len(receipt.Outcomes) == 0 && stale {
		transition = receiptTransition{stale: true}
	}
	detail := "target account uid changed immediately before user-service action"
	if err != nil {
		detail = err.Error()
	}
	receipt.transition(transition)
	receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, index, detail)...)
	return receipt, true
}

func (plan readyPlan) guardPackages(ctx context.Context, runner Runner) (bool, error) {
	current, err := plan.packageBehavior.inventory(ctx, runner)
	if err != nil {
		return false, err
	}
	return !reflect.DeepEqual(current, plan.packageEvidence), nil
}

func (plan readyPlan) guardServices(ctx context.Context, runner Runner) (bool, error) {
	current := plan.bound.services.observe(ctx, runner, plan.bound.serviceNeeds)
	for _, item := range plan.bound.serviceNeeds {
		before := serviceObservationAt(plan.services, item)
		after := serviceObservationAt(current, item)
		switch before.(type) {
		case serviceSatisfied:
			switch state := after.(type) {
			case serviceSatisfied:
			case serviceUnsatisfied:
				return true, nil
			case serviceIndeterminate:
				return false, fmt.Errorf("service %s cannot be revalidated: %s", item.unit, state.detail)
			case serviceMissing:
				return false, fmt.Errorf("service %s observation is missing", item.unit)
			}
		case serviceUnsatisfied:
			switch state := after.(type) {
			case serviceUnsatisfied:
			case serviceSatisfied:
				return true, nil
			case serviceIndeterminate:
				return false, fmt.Errorf("service %s cannot be revalidated: %s", item.unit, state.detail)
			case serviceMissing:
				return false, fmt.Errorf("service %s observation is missing", item.unit)
			}
		case serviceIndeterminate, serviceMissing:
			return false, fmt.Errorf("reviewed service %s observation is missing", item.unit)
		}
	}
	return false, nil
}

func (plan readyPlan) guardConflicts(ctx context.Context, runner Runner) (bool, error) {
	for _, observed := range plan.bound.services.observeConflicts(ctx, runner, plan.bound.conflicts) {
		state := observed.state
		if state == nil {
			state = serviceMissing{}
		}
		switch state := state.(type) {
		case serviceUnsatisfied:
			continue
		case serviceSatisfied:
			return true, nil
		case serviceIndeterminate:
			return false, fmt.Errorf("conflicting service cannot be revalidated: %s", state.detail)
		case serviceMissing:
			return false, fmt.Errorf("conflicting service observation is missing")
		}
	}
	return false, nil
}

func (plan readyPlan) finalState(ctx context.Context, runner Runner) []Blocker {
	if detail, failed := finalHostGuard(plan.host, runner); failed {
		return []Blocker{{Subject: "final:host", Detail: detail}}
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		return []Blocker{{Subject: "final:account", Detail: err.Error()}}
	} else if stale {
		return []Blocker{{Subject: "final:account", Detail: "account evidence changed during apply"}}
	}
	if plan.targetUser {
		if stale, err := plan.account.guardUID(runner); err != nil {
			return []Blocker{{Subject: "final:account-target", Detail: err.Error()}}
		} else if stale {
			return []Blocker{{Subject: "final:account-target", Detail: "effective uid no longer matches the target account"}}
		}
	}
	if len(plan.bound.packageNeeds) != 0 {
		current, err := plan.packageBehavior.inventory(ctx, runner)
		if err != nil {
			return []Blocker{{Subject: "final:packages", Detail: err.Error()}}
		}
		if !reflect.DeepEqual(current, plan.packageEvidence) {
			return []Blocker{{Subject: "final:packages", Detail: "package evidence changed during apply"}}
		}
	}
	observed := plan.bound.services.observe(ctx, runner, plan.bound.serviceNeeds)
	var blockers []Blocker
	for _, item := range plan.bound.serviceNeeds {
		subject := "final:service:" + string(item.need.key)
		switch state := serviceObservationAt(observed, item).(type) {
		case serviceSatisfied:
		case serviceUnsatisfied:
			blockers = append(blockers, Blocker{Subject: subject, Detail: item.unit + " regressed to " + state.detail})
		case serviceIndeterminate:
			blockers = append(blockers, Blocker{Subject: subject, Detail: item.unit + " is indeterminate: " + state.detail})
		case serviceMissing:
			blockers = append(blockers, Blocker{Subject: subject, Detail: item.unit + " observation is missing"})
		}
	}
	conflicts := plan.bound.services.observeConflicts(ctx, runner, plan.bound.conflicts)
	_, conflictBlockers := plan.bound.services.reconcileConflicts(conflicts)
	for _, blocker := range conflictBlockers {
		blocker.Subject = "final:" + blocker.Subject
		blockers = append(blockers, blocker)
	}
	return blockers
}

func (plan readyPlan) validateProjections() error {
	reviewed := make(map[string]Change, len(plan.steps))
	for _, change := range plan.plan.Changes {
		if change.Command != nil {
			reviewed[change.ID] = change
		}
	}
	if len(reviewed) != len(plan.steps) {
		return fmt.Errorf("reviewed executable changes do not match private steps")
	}
	for _, prepared := range plan.steps {
		if reviewedProjection, ok := reviewed[prepared.step.id]; !ok || !reflect.DeepEqual(reviewedProjection, prepared.projection) {
			return fmt.Errorf("reviewed projection for %s does not match private step", prepared.step.id)
		}
	}
	return nil
}

func failureOutcomes(steps []preparedStep, index int, detail string) []ActionOutcome {
	result := []ActionOutcome{{Action: steps[index].step.id, Status: FailedAction, Detail: detail}}
	for _, prepared := range steps[index+1:] {
		result = append(result, ActionOutcome{Action: prepared.step.id, Status: Unattempted})
	}
	return result
}

func unattemptedOutcomes(steps []preparedStep, index int, detail string) []ActionOutcome {
	result := make([]ActionOutcome, 0, len(steps)-index)
	for i := index; i < len(steps); i++ {
		itemDetail := "stopped before execution"
		if i == index {
			itemDetail = detail
		}
		result = append(result, ActionOutcome{Action: steps[i].step.id, Status: Unattempted, Detail: itemDetail})
	}
	return result
}

func commandFailure(command Command, result Result) string {
	detail := nonempty(result.Stderr, result.Err)
	if detail == "unknown" && strings.TrimSpace(result.Stdout) != "" {
		detail = strings.TrimSpace(result.Stdout)
	}
	return fmt.Sprintf("%s exited %d: %s", command.String(), result.ExitCode, detail)
}
