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

func (plan blockedPlan) apply(_ Runner, receipt ApplyReceipt) ApplyReceipt {
	receipt.Status, receipt.Blockers = Blocked, append([]Blocker(nil), plan.plan.Blockers...)
	return receipt
}

func (plan rootPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	return plan.packagePlan.apply(runner, receipt, func(ctx context.Context, runner Runner, command Command, guard packageMutationGuard) packageResult {
		return plan.change.apply(ctx, runner, command, guard)
	})
}

func (plan installPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	return plan.packagePlan.apply(runner, receipt, func(ctx context.Context, runner Runner, command Command, guard packageMutationGuard) packageResult {
		return plan.change.apply(ctx, runner, command, guard)
	})
}

func (plan primaryGroupPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	preparedProjection := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) ||
		plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, preparedProjection) {
		receipt.Status = Failed
		return receipt
	}
	ctx := context.Background()
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.group.guard(ctx, runner); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:primary-group", Detail: err.Error()}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "primary group evidence changed immediately before mutation"}}
		return receipt
	}
	execution := runner.Run(ctx, plan.command)
	freshGroup := observePrimaryGroup(ctx, runner, plan.group.observed.getentPath, plan.group.intent)
	verified, verificationDetail := verifyPrimaryGroup(plan.group.intent, freshGroup)
	if stale, err := plan.account.guard(ctx, runner); err != nil || stale {
		detail := "account evidence changed after primary group mutation"
		if err != nil {
			detail = err.Error()
		}
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "final:account", Detail: detail}}
		status := FailedAction
		if verified {
			status = Applied
		}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: verificationDetail + "; " + detail}}
		return receipt
	}
	if execution.Err != nil || execution.ExitCode != 0 || !verified {
		detail := verificationDetail
		if execution.Err != nil || execution.ExitCode != 0 {
			detail = "groupadd failed: " + resultDetail(execution) + "; " + verificationDetail
		}
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: detail}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: "verified primary group creation; replan required"}}
	return receipt
}

func (plan accountCreatePlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	preparedProjection := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) ||
		plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, preparedProjection) {
		receipt.Status = Failed
		return receipt
	}
	ctx := context.Background()
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.group.guard(ctx, runner); err != nil {
		return failedAccountGuard(receipt, plan.projection.ID, "guard:primary-group", err.Error())
	} else if stale {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "primary group evidence changed immediately before account creation"}}
		return receipt
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		return failedAccountGuard(receipt, plan.projection.ID, "guard:account", err.Error())
	} else if stale {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "account evidence changed immediately before account creation"}}
		return receipt
	}
	execution := runner.Run(ctx, plan.command)
	reviewedAccount := plan.account.observed.(accountSnapshot)
	intent := plan.account.intent.(presentAccountIntent)
	freshAccount := observeAccountWithGetent(ctx, runner, intent, reviewedAccount.getentPath)
	lock := accountLockObservation(accountLockUnobserved{})
	if _, identified := reconcileAccount(intent, freshAccount).(accountIdentified); identified {
		lock = observeAccountLockStatus(ctx, runner, plan.lockStatusCommand, intent.name)
	}
	accountVerified, accountDetail := verifyAccountCreation(intent, freshAccount, lock)
	freshGroup := observePrimaryGroup(ctx, runner, plan.group.observed.getentPath, plan.group.intent)
	groupVerified, groupDetail := verifyPrimaryGroup(plan.group.intent, freshGroup)
	if execution.Err != nil || execution.ExitCode != 0 {
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: "useradd failed: " + resultDetail(execution) + "; " + accountDetail + "; " + groupDetail}}
		return receipt
	}
	if !accountVerified {
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: accountDetail}}
		return receipt
	}
	if !groupVerified {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "final:primary-group", Detail: groupDetail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: accountDetail + "; " + groupDetail}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: "verified locked account creation; replan required"}}
	return receipt
}

func (plan homeCreatePlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	preparedProjection := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) ||
		plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, preparedProjection) {
		receipt.Status = Failed
		return receipt
	}
	ctx := context.Background()
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.group.guard(ctx, runner); err != nil {
		return failedAccountGuard(receipt, plan.projection.ID, "guard:primary-group", err.Error())
	} else if stale {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "primary group evidence changed immediately before home creation"}}
		return receipt
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		return failedAccountGuard(receipt, plan.projection.ID, "guard:account", err.Error())
	} else if stale {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "account, lock, or home evidence changed immediately before home creation"}}
		return receipt
	}
	execution := runner.Run(ctx, plan.command)
	intent := plan.account.intent.(presentAccountIntent)
	freshHome := observeHome(runner, intent.home)
	homeVerified, homeDetail := verifyHomeCreation(intent.home, intent.uid, intent.primaryGroup.gid, freshHome)
	reviewedAccount := plan.account.observed.(accountSnapshot)
	freshAccount := observeAccountWithGetent(ctx, runner, intent, reviewedAccount.getentPath)
	lock := observeAccountLockStatus(ctx, runner, plan.account.lock.command, intent.name)
	accountVerified, accountDetail := verifyAccountCreation(intent, freshAccount, lock)
	freshGroup := observePrimaryGroup(ctx, runner, plan.group.observed.getentPath, plan.group.intent)
	groupVerified, groupDetail := verifyPrimaryGroup(plan.group.intent, freshGroup)
	verification := homeDetail + "; " + accountDetail + "; " + groupDetail
	if execution.Err != nil || execution.ExitCode != 0 {
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: "home creation failed: " + resultDetail(execution) + "; " + verification}}
		return receipt
	}
	if !homeVerified {
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: verification}}
		return receipt
	}
	if !accountVerified || !groupVerified {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "final:home-dependencies", Detail: accountDetail + "; " + groupDetail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: verification}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: "verified home creation; replan required"}}
	return receipt
}

func failedAccountGuard(receipt ApplyReceipt, action, subject, detail string) ApplyReceipt {
	receipt.Status = Failed
	receipt.Blockers = []Blocker{{Subject: subject, Detail: detail}}
	receipt.Outcomes = []ActionOutcome{{Action: action, Status: Unattempted, Detail: detail}}
	return receipt
}

func (plan packagePlan) apply(runner Runner, receipt ApplyReceipt, effect func(context.Context, Runner, Command, packageMutationGuard) packageResult) ApplyReceipt {
	preparedProjection := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) ||
		plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, preparedProjection) {
		receipt.Status = Failed
		return receipt
	}
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.account.guard(context.Background(), runner); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.Status = Stale
		return receipt
	}
	guard := func() error {
		stale, err := plan.account.guard(context.Background(), runner)
		if err != nil {
			return accountMutationGuardFailed{detail: err.Error()}
		}
		if stale {
			return stalePrecondition{detail: "account evidence changed immediately before package mutation"}
		}
		return nil
	}
	result := effect(context.Background(), runner, plan.command, guard)
	if result.err != nil {
		var stale stalePrecondition
		if !result.attempted && errors.As(result.err, &stale) {
			receipt.Status = Stale
			receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: Unattempted, Detail: result.err.Error()}}
			return receipt
		}
		var accountFailure accountMutationGuardFailed
		if !result.attempted && errors.As(result.err, &accountFailure) {
			receipt.Status = Failed
			receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: accountFailure.Error()}}
			receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: Unattempted, Detail: accountFailure.Error()}}
			return receipt
		}
		receipt.Status = Failed
		status := Unattempted
		if result.attempted {
			status = FailedAction
		}
		receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: result.err.Error()}}
		return receipt
	}
	if stale, err := plan.account.guard(context.Background(), runner); err != nil || stale {
		detail := "account evidence changed after verified package mutation"
		if err != nil {
			detail = err.Error()
		}
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "final:account", Detail: detail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: Applied, Detail: "verified; " + detail}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: Applied, Detail: "verified; replan required"}}
	return receipt
}

func (plan readyPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	if err := plan.validateProjections(); err != nil {
		receipt.Status = Failed
		return receipt
	}
	if len(plan.commands) != len(plan.steps) {
		receipt.Status = Failed
		return receipt
	}
	ctx := context.Background()
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.Status = Stale
		return receipt
	}
	if plan.targetUser {
		if stale, err := plan.account.guardUID(runner); err != nil {
			receipt.Status = Failed
			receipt.Blockers = []Blocker{{Subject: "guard:account-target", Detail: err.Error()}}
			return receipt
		} else if stale {
			receipt.Status = Stale
			return receipt
		}
	}
	if len(plan.bound.packageNeeds) != 0 {
		stale, err := plan.guardPackages(ctx, runner)
		if err != nil {
			receipt.Status = Failed
			return receipt
		}
		if stale {
			receipt.Status = Stale
			return receipt
		}
	}
	if stale, err := plan.guardServices(ctx, runner); err != nil {
		receipt.Status = Failed
		return receipt
	} else if stale {
		receipt.Status = Stale
		return receipt
	}
	if stale, err := plan.guardConflicts(ctx, runner); err != nil {
		receipt.Status = Failed
		return receipt
	} else if stale {
		receipt.Status = Stale
		return receipt
	}

	for i, step := range plan.steps {
		if err := step.before(ctx, runner); err != nil {
			var stale stalePrecondition
			if errors.As(err, &stale) {
				if len(receipt.Outcomes) == 0 {
					receipt.Status = Stale
				} else {
					receipt.Status = Failed
				}
			} else {
				receipt.Status = Failed
			}
			receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, i, err.Error())...)
			return receipt
		}
		if stale, err := plan.account.guard(ctx, runner); err != nil || stale {
			detail := "account evidence changed immediately before action"
			receipt.Status = Failed
			if err != nil {
				detail = err.Error()
				receipt.Blockers = append(receipt.Blockers, Blocker{Subject: "guard:account", Detail: detail})
			} else if len(receipt.Outcomes) == 0 {
				receipt.Status = Stale
			}
			receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, i, detail)...)
			return receipt
		}
		if plan.targetUser && step.access == directStep {
			if stale, err := plan.account.guardUID(runner); err != nil || stale {
				receipt.Status = Failed
				if len(receipt.Outcomes) == 0 && stale {
					receipt.Status = Stale
				}
				detail := "target account uid changed immediately before user-service action"
				if err != nil {
					detail = err.Error()
				}
				receipt.Outcomes = append(receipt.Outcomes, unattemptedOutcomes(plan.steps, i, detail)...)
				return receipt
			}
		}
		stepContext, cancel := context.WithTimeout(ctx, step.timeout)
		result := runner.Run(stepContext, plan.commands[i])
		cancel()
		if result.Err != nil || result.ExitCode != 0 {
			receipt.Status = Failed
			detail := commandFailure(plan.commands[i], result)
			if step.verify != nil {
				_, postState := step.verify(ctx, runner)
				detail += "; post-state: " + postState
			}
			receipt.Outcomes = append(receipt.Outcomes, failureOutcomes(plan.steps, i, detail)...)
			return receipt
		}
		if satisfied, detail := step.verify(ctx, runner); !satisfied {
			receipt.Status = Failed
			receipt.Outcomes = append(receipt.Outcomes, failureOutcomes(plan.steps, i, "verification: post-state not satisfied: "+detail)...)
			return receipt
		}
		receipt.Outcomes = append(receipt.Outcomes, ActionOutcome{Action: step.id, Status: Applied, Detail: "verified"})
	}
	if blockers := plan.finalState(ctx, runner); len(blockers) != 0 {
		receipt.Status = Failed
		receipt.Blockers = blockers
		return receipt
	}
	receipt.Status = Succeeded
	return receipt
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
		before := plan.services[item.need]
		after := current[item.need]
		switch before.(type) {
		case serviceSatisfied:
			switch state := after.(type) {
			case serviceSatisfied:
			case serviceUnsatisfied:
				return true, nil
			case serviceIndeterminate:
				return false, fmt.Errorf("service %s cannot be revalidated: %s", item.unit, state.detail)
			default:
				return false, fmt.Errorf("service %s observation is missing", item.unit)
			}
		case serviceUnsatisfied:
			switch state := after.(type) {
			case serviceUnsatisfied:
			case serviceSatisfied:
				return true, nil
			case serviceIndeterminate:
				return false, fmt.Errorf("service %s cannot be revalidated: %s", item.unit, state.detail)
			default:
				return false, fmt.Errorf("service %s observation is missing", item.unit)
			}
		default:
			return false, fmt.Errorf("reviewed service %s observation is missing", item.unit)
		}
	}
	return false, nil
}

func (plan readyPlan) guardConflicts(ctx context.Context, runner Runner) (bool, error) {
	for _, observed := range plan.bound.services.observeConflicts(ctx, runner, plan.bound.conflicts) {
		switch state := observed.state.(type) {
		case serviceUnsatisfied:
			continue
		case serviceSatisfied:
			return true, nil
		case serviceIndeterminate:
			return false, fmt.Errorf("conflicting service cannot be revalidated: %s", state.detail)
		default:
			return false, fmt.Errorf("conflicting service observation is missing")
		}
	}
	return false, nil
}

func (plan readyPlan) finalState(ctx context.Context, runner Runner) []Blocker {
	host := observeHost(runner)
	if len(host.blockers) != 0 || !reflect.DeepEqual(host.facts, plan.host) {
		return []Blocker{{Subject: "final:host", Detail: "host evidence changed during apply"}}
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
		switch state := observed[item.need].(type) {
		case serviceSatisfied:
		case serviceUnsatisfied:
			blockers = append(blockers, Blocker{Subject: subject, Detail: item.unit + " regressed to " + state.detail})
		case serviceIndeterminate:
			blockers = append(blockers, Blocker{Subject: subject, Detail: item.unit + " is indeterminate: " + state.detail})
		default:
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
	if len(plan.commands) != len(plan.steps) {
		return fmt.Errorf("prepared commands do not match private steps")
	}
	for i, step := range plan.steps {
		projection := step.projectionFor(plan.commands[i])
		if reviewedProjection, ok := reviewed[step.id]; !ok || !reflect.DeepEqual(reviewedProjection, projection) {
			return fmt.Errorf("reviewed projection for %s does not match private step", step.id)
		}
	}
	return nil
}

func failureOutcomes(steps []step, index int, detail string) []ActionOutcome {
	result := []ActionOutcome{{Action: steps[index].id, Status: FailedAction, Detail: detail}}
	for _, step := range steps[index+1:] {
		result = append(result, ActionOutcome{Action: step.id, Status: Unattempted})
	}
	return result
}

func unattemptedOutcomes(steps []step, index int, detail string) []ActionOutcome {
	result := make([]ActionOutcome, 0, len(steps)-index)
	for i := index; i < len(steps); i++ {
		itemDetail := "stopped before execution"
		if i == index {
			itemDetail = detail
		}
		result = append(result, ActionOutcome{Action: steps[i].id, Status: Unattempted, Detail: itemDetail})
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
