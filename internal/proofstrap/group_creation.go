package proofstrap

import "context"

func (plan primaryGroupPlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	if !matchesSingleProjectedCommand(plan.plan, plan.projection, plan.command) {
		receipt.transition(receiptTransition{failed: true})
		return receipt
	}
	ctx := context.Background()
	if guarded, stop := initialHostGuard(receipt, plan.host, runner); stop {
		return guarded
	}
	if stale, err := plan.account.guard(ctx, runner); err != nil {
		receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.transition(receiptTransition{stale: true})
		return receipt
	}
	if stale, err := plan.group.guard(ctx, runner); err != nil {
		status, _ := receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = []Blocker{{Subject: "guard:primary-group", Detail: err.Error()}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: err.Error()}}
		return receipt
	} else if stale {
		status, _ := receipt.transition(receiptTransition{stale: true})
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: "primary group evidence changed immediately before mutation"}}
		return receipt
	}
	if guarded, stop, _ := immediateHostGuard(receipt, plan.host, runner, plan.projection.ID, "host evidence changed immediately before mutation"); stop {
		return guarded
	}
	execution := runner.Run(ctx, plan.command)
	freshGroup := observePrimaryGroup(ctx, runner, plan.group.observed.getentPath, plan.group.intent)
	verified, verificationDetail := verifyPrimaryGroup(plan.group.intent, freshGroup)
	if stale, err := plan.account.guard(ctx, runner); err != nil || stale {
		detail := "account evidence changed after primary group mutation"
		if err != nil {
			detail = err.Error()
		}
		status, _ := receipt.transition(receiptTransition{attempted: true, verified: verified, failed: true})
		receipt.Blockers = []Blocker{{Subject: "final:account", Detail: detail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: verificationDetail + "; " + detail}}
		return receipt
	}
	if execution.Err != nil || execution.ExitCode != 0 || !verified {
		detail := verificationDetail
		if execution.Err != nil || execution.ExitCode != 0 {
			detail = "groupadd failed: " + resultDetail(execution) + "; " + verificationDetail
		}
		status, _ := receipt.transition(receiptTransition{attempted: true, failed: true})
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: detail}}
		return receipt
	}
	if detail, failed := finalHostGuard(plan.host, runner); failed {
		status, _ := receipt.transition(receiptTransition{attempted: true, verified: true, failed: true})
		receipt.Blockers = []Blocker{{Subject: "final:host", Detail: detail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: verificationDetail + "; " + detail}}
		return receipt
	}
	status, _ := receipt.transition(receiptTransition{attempted: true, verified: true, progress: true})
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: "verified primary group creation; replan required"}}
	return receipt
}
