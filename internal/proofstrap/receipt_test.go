package proofstrap

import "testing"

func TestReceiptTransitionLaw(t *testing.T) {
	for _, test := range []struct {
		name       string
		transition receiptTransition
		run        RunStatus
		action     ActionStatus
		hasAction  bool
	}{
		{name: "no work", run: Succeeded},
		{name: "preparation failure", transition: receiptTransition{failed: true}, run: Failed, action: Unattempted, hasAction: true},
		{name: "stale before run", transition: receiptTransition{stale: true}, run: Stale, action: Unattempted, hasAction: true},
		{name: "failed attempt", transition: receiptTransition{attempted: true, failed: true}, run: Failed, action: FailedAction, hasAction: true},
		{name: "unverified attempt", transition: receiptTransition{attempted: true}, run: Failed, action: FailedAction, hasAction: true},
		{name: "verified action", transition: receiptTransition{attempted: true, verified: true}, run: Succeeded, action: Applied, hasAction: true},
		{name: "verified progress", transition: receiptTransition{attempted: true, verified: true, progress: true}, run: ReplanRequired, action: Applied, hasAction: true},
		{name: "verified but final regression", transition: receiptTransition{attempted: true, verified: true, failed: true}, run: Failed, action: Applied, hasAction: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.transition.runStatus(); got != test.run {
				t.Fatalf("run status=%q want %q", got, test.run)
			}
			got, ok := test.transition.actionStatus()
			if ok != test.hasAction || ok && got != test.action {
				t.Fatalf("action status=%q ok=%v want %q ok=%v", got, ok, test.action, test.hasAction)
			}
		})
	}
}

func TestReceiptTransitionRejectsStaleAttempt(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("stale attempted transition did not panic")
		}
	}()
	_ = (receiptTransition{stale: true, attempted: true}).runStatus()
}
