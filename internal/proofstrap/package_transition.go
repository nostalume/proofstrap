package proofstrap

import (
	"context"
	"errors"
)

func (plan packagePlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	if plan.change == nil || !matchesSingleProjectedCommand(plan.plan, plan.projection, plan.command) {
		receipt.transition(receiptTransition{failed: true})
		return receipt
	}
	if guarded, stop := initialHostGuard(receipt, plan.host, runner); stop {
		return guarded
	}
	if stale, err := plan.account.guard(context.Background(), runner); err != nil {
		receipt.transition(receiptTransition{failed: true})
		receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: err.Error()}}
		return receipt
	} else if stale {
		receipt.transition(receiptTransition{stale: true})
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
		if stale, err := plan.host.guard(runner); err != nil {
			return hostMutationGuardFailed{detail: err.Error()}
		} else if stale {
			return stalePrecondition{detail: "host evidence changed immediately before package mutation"}
		}
		return nil
	}
	result := plan.change.apply(context.Background(), runner, plan.command, guard)
	if result.err != nil {
		var stale stalePrecondition
		if !result.attempted && errors.As(result.err, &stale) {
			status, _ := receipt.transition(receiptTransition{stale: true})
			receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: result.err.Error()}}
			return receipt
		}
		var accountFailure accountMutationGuardFailed
		if !result.attempted && errors.As(result.err, &accountFailure) {
			status, _ := receipt.transition(receiptTransition{failed: true})
			receipt.Blockers = []Blocker{{Subject: "guard:account", Detail: accountFailure.Error()}}
			receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: accountFailure.Error()}}
			return receipt
		}
		var hostFailure hostMutationGuardFailed
		if !result.attempted && errors.As(result.err, &hostFailure) {
			status, _ := receipt.transition(receiptTransition{failed: true})
			receipt.Blockers = []Blocker{{Subject: "guard:host", Detail: hostFailure.Error()}}
			receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: hostFailure.Error()}}
			return receipt
		}
		status, _ := receipt.transition(receiptTransition{attempted: result.attempted, failed: true})
		receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: result.err.Error()}}
		return receipt
	}
	if stale, err := plan.account.guard(context.Background(), runner); err != nil || stale {
		detail := "account evidence changed after verified package mutation"
		if err != nil {
			detail = err.Error()
		}
		status, _ := receipt.transition(receiptTransition{attempted: true, verified: true, failed: true})
		receipt.Blockers = []Blocker{{Subject: "final:account", Detail: detail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: "verified; " + detail}}
		return receipt
	}
	if detail, failed := finalHostGuard(plan.host, runner); failed {
		status, _ := receipt.transition(receiptTransition{attempted: true, verified: true, failed: true})
		receipt.Blockers = []Blocker{{Subject: "final:host", Detail: detail}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: "verified; " + detail}}
		return receipt
	}
	status, _ := receipt.transition(receiptTransition{attempted: true, verified: true, progress: true})
	receipt.Outcomes = []ActionOutcome{{Action: plan.plan.Changes[0].ID, Status: status, Detail: "verified; replan required"}}
	return receipt
}
