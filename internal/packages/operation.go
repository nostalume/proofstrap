package packages

import (
	"context"
	"errors"
	"fmt"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

var ErrStale = errors.New("package operation is stale")

type Operation struct {
	evidence candidateEvidence
	before   Observation
	offer    Offer
}

func NewOperation(selected Selected, before Observation, decision Decision) (Operation, error) {
	if !selected.valid() {
		return Operation{}, fmt.Errorf("selected package behavior is required")
	}
	if !before.valid() {
		return Operation{}, fmt.Errorf("complete package observation is required")
	}
	if !decision.Allowed() {
		return Operation{}, fmt.Errorf("package offer is not permitted")
	}
	if len(decision.state.offer.state.deltas) == 0 {
		return Operation{}, fmt.Errorf("empty package offer requires no operation")
	}
	return Operation{evidence: selected.evidence, before: before, offer: decision.state.offer}, nil
}

func (operation Operation) valid() bool {
	return validExpectedEvidence(operation.evidence) && operation.before.valid() && operation.offer.valid()
}

func (operation Operation) Deltas() []Delta                   { return operation.offer.Deltas() }
func (operation Operation) Backend() binding.PackageBackendID { return operation.evidence.backend }

type ApplyResult struct {
	started bool
	after   Observation
}

func (result ApplyResult) Started() bool { return result.started }
func (result ApplyResult) After() (Observation, bool) {
	return result.after, result.after.valid()
}

func (operation Operation) Apply(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh Selected) (ApplyResult, error) {
	if !operation.valid() || !fresh.valid() {
		return ApplyResult{}, fmt.Errorf("valid package operation and fresh selection are required")
	}
	if !linux.FutureContext(effectCtx) || freshPost == nil {
		return ApplyResult{}, fmt.Errorf("bounded package effect and fresh post-observation context are required")
	}
	if !operation.evidence.equal(fresh.evidence) {
		return ApplyResult{}, fmt.Errorf("%w: selected package evidence changed", ErrStale)
	}
	desired := desiredFrom(operation.before)
	current, err := fresh.Observe(effectCtx, desired)
	if err != nil {
		return ApplyResult{}, err
	}
	if !current.valid() {
		return ApplyResult{}, fmt.Errorf("fresh package observation is incomplete")
	}
	if !current.equal(operation.before) {
		return ApplyResult{}, fmt.Errorf("%w: package observation changed", ErrStale)
	}
	commit, commitErr := fresh.commit(effectCtx, current, operation.offer)
	if !commit.Started {
		if commitErr == nil {
			return ApplyResult{}, fmt.Errorf("package behavior reported success without starting mutation")
		}
		return ApplyResult{}, commitErr
	}
	result := ApplyResult{started: true}
	postCtx, cancelPost := freshPost()
	if cancelPost == nil {
		return result, errors.Join(commitErr, fmt.Errorf("fresh bounded package post-observation context is required"))
	}
	defer cancelPost()
	if !linux.FutureContext(postCtx) {
		return result, errors.Join(commitErr, fmt.Errorf("fresh bounded package post-observation context is required"))
	}
	after, observeErr := fresh.Observe(postCtx, desired)
	var verifyErr error
	if observeErr == nil {
		if !after.valid() {
			observeErr = fmt.Errorf("post-package observation is incomplete")
		} else {
			result.after = after
			verifyErr = fresh.behavior.Verify(operation.before, operation.offer, after)
		}
	}
	if errors.Is(commitErr, ErrStale) {
		commitErr = fmt.Errorf("package behavior reported stale after starting mutation: %v", commitErr)
	}
	return result, errors.Join(commitErr, observeErr, verifyErr)
}
