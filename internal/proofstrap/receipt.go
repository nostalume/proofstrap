package proofstrap

type receiptTransition struct {
	attempted bool
	verified  bool
	progress  bool
	failed    bool
	stale     bool
}

func (transition receiptTransition) validate() {
	if transition.stale && transition.attempted {
		panic("attempted transition cannot be stale")
	}
	if transition.verified && !transition.attempted {
		panic("unattempted transition cannot be verified")
	}
	if transition.progress && !transition.verified {
		panic("unverified transition cannot report progress")
	}
}

func (transition receiptTransition) runStatus() RunStatus {
	transition.validate()
	switch {
	case transition.stale:
		return Stale
	case transition.failed || transition.attempted && !transition.verified:
		return Failed
	case transition.progress:
		return ReplanRequired
	default:
		return Succeeded
	}
}

func (transition receiptTransition) actionStatus() (ActionStatus, bool) {
	transition.validate()
	switch {
	case transition.attempted && transition.verified:
		return Applied, true
	case transition.attempted:
		return FailedAction, true
	case transition.failed || transition.stale:
		return Unattempted, true
	default:
		return "", false
	}
}

func (receipt *ApplyReceipt) transition(transition receiptTransition) (ActionStatus, bool) {
	receipt.Status = transition.runStatus()
	return transition.actionStatus()
}
