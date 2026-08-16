package packages

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type operationBehavior struct {
	observations []Observation
	observeErrs  []error
	commit       commitResult
	commitErr    error
	verifyErr    error
	cancelCommit context.CancelFunc
	calls        []string
	contexts     []context.Context
	observeIndex int
}

func (behavior *operationBehavior) Observe(ctx context.Context, _ proof, _ []string) (Observation, error) {
	behavior.calls = append(behavior.calls, "observe")
	behavior.contexts = append(behavior.contexts, ctx)
	index := behavior.observeIndex
	behavior.observeIndex++
	var observation Observation
	if index < len(behavior.observations) {
		observation = behavior.observations[index]
	}
	var err error
	if index < len(behavior.observeErrs) {
		err = behavior.observeErrs[index]
	}
	return observation, err
}

func (*operationBehavior) Preview(context.Context, proof, Observation) (Offer, error) {
	return Offer{}, errors.New("unexpected preview")
}

func (behavior *operationBehavior) Commit(ctx context.Context, _ proof, _ Observation, _ Offer) (commitResult, error) {
	behavior.calls = append(behavior.calls, "commit")
	behavior.contexts = append(behavior.contexts, ctx)
	if behavior.cancelCommit != nil {
		behavior.cancelCommit()
	}
	return behavior.commit, behavior.commitErr
}

func (behavior *operationBehavior) Verify(_ Observation, _ Offer, _ Observation) error {
	behavior.calls = append(behavior.calls, "verify")
	return behavior.verifyErr
}

func operationFixture(t *testing.T, fresh behavior, proofValue string) (Operation, Selected, Observation) {
	t.Helper()
	backend := backend(t, "test")
	planned := selectExact(backend, []candidate{admittedCandidate(backend, SystemCandidate, "proof", fakeBehavior{})}).(Selected)
	current := selectExact(backend, []candidate{admittedCandidate(backend, SystemCandidate, proofValue, fresh)}).(Selected)
	before := verificationObservation(t, []string{"pkg"}, nil, nil, []demand{{Name: "pkg", State: demandMissing}})
	after := verificationObservation(t, []string{"pkg"}, []record{{Key: "pkg", State: "installed"}}, []string{"pkg"}, []demand{{Name: "pkg", State: demandDirect}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Add, "pkg", "", "installed"),
		mustDelta(t, RootAdd, "pkg", "", "direct"),
	})
	decision, _ := Decide(offer)
	operation, err := NewOperation(planned, before, decision)
	if err != nil {
		t.Fatal(err)
	}
	return operation, current, after
}

func boundedContexts(t *testing.T) (context.Context, context.CancelFunc, context.Context, context.CancelFunc) {
	t.Helper()
	effect, cancelEffect := context.WithTimeout(context.Background(), time.Minute)
	post, cancelPost := context.WithTimeout(context.Background(), time.Minute)
	return effect, cancelEffect, post, cancelPost
}

func postContext(ctx context.Context) func() (context.Context, context.CancelFunc) {
	return func() (context.Context, context.CancelFunc) { return ctx, func() {} }
}

func TestOperationApplyRequiresFreshEvidenceAndVerifiesPostState(t *testing.T) {
	behavior := &operationBehavior{commit: commitResult{Started: true}}
	operation, selected, after := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before, after}
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()

	result, err := operation.Apply(effect, postContext(post), selected)
	if err != nil || !result.Started() {
		t.Fatalf("Apply = %#v, %v", result, err)
	}
	observed, ok := result.After()
	if !ok || !observed.equal(after) {
		t.Fatalf("After = %#v, %v", observed, ok)
	}
	if !reflect.DeepEqual(behavior.calls, []string{"observe", "commit", "observe", "verify"}) {
		t.Fatalf("calls = %#v", behavior.calls)
	}
	if behavior.contexts[0] != effect || behavior.contexts[1] != effect || behavior.contexts[2] != post {
		t.Fatal("Apply used the wrong effect or post-observation context")
	}
}

func TestOperationApplyClassifiesPreMutationDriftAsStale(t *testing.T) {
	behavior := &operationBehavior{}
	operation, driftedProof, _ := operationFixture(t, behavior, "other-proof")
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	if result, err := operation.Apply(effect, postContext(post), driftedProof); !errors.Is(err, ErrStale) || result.Started() || len(behavior.calls) != 0 {
		t.Fatalf("proof drift = %#v, %v, calls=%v", result, err, behavior.calls)
	}

	behavior = &operationBehavior{}
	operation, selected, _ := operationFixture(t, behavior, "proof")
	changed := verificationObservation(t, []string{"pkg"}, []record{{Key: "other"}}, nil, []demand{{Name: "pkg", State: demandMissing}})
	behavior.observations = []Observation{changed}
	if result, err := operation.Apply(effect, postContext(post), selected); !errors.Is(err, ErrStale) || result.Started() || !reflect.DeepEqual(behavior.calls, []string{"observe"}) {
		t.Fatalf("state drift = %#v, %v, calls=%v", result, err, behavior.calls)
	}

	behavior = &operationBehavior{commitErr: ErrStale}
	operation, selected, _ = operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before}
	if result, err := operation.Apply(effect, postContext(post), selected); !errors.Is(err, ErrStale) || result.Started() || !reflect.DeepEqual(behavior.calls, []string{"observe", "commit"}) {
		t.Fatalf("offer drift = %#v, %v, calls=%v", result, err, behavior.calls)
	}
}

func TestOperationApplyPreservesStartedPostEvidenceAndJoinedFailures(t *testing.T) {
	commitFailure := errors.New("commit failed")
	verifyFailure := errors.New("verify failed")
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	behavior := &operationBehavior{commit: commitResult{Started: true}, commitErr: commitFailure, verifyErr: verifyFailure}
	operation, selected, after := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before, after}
	result, err := operation.Apply(effect, postContext(post), selected)
	observed, ok := result.After()
	if !result.Started() || !ok || !observed.equal(after) || !errors.Is(err, commitFailure) || !errors.Is(err, verifyFailure) {
		t.Fatalf("partial Apply = %#v, %v", result, err)
	}
	if !reflect.DeepEqual(behavior.calls, []string{"observe", "commit", "observe", "verify"}) {
		t.Fatalf("calls = %#v", behavior.calls)
	}
}

func TestOperationApplyDoesNotPostObserveGuaranteedPreStartFailure(t *testing.T) {
	failure := errors.New("did not start")
	behavior := &operationBehavior{commitErr: failure}
	operation, selected, _ := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before}
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	result, err := operation.Apply(effect, postContext(post), selected)
	if result.Started() || !errors.Is(err, failure) || !reflect.DeepEqual(behavior.calls, []string{"observe", "commit"}) {
		t.Fatalf("pre-start failure = %#v, %v, calls=%v", result, err, behavior.calls)
	}

	behavior = &operationBehavior{}
	operation, selected, _ = operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before}
	if _, err := operation.Apply(effect, postContext(post), selected); err == nil {
		t.Fatal("accepted nil Commit error with Started false")
	}

	observeFailure := errors.New("pre-observation failed")
	behavior = &operationBehavior{observeErrs: []error{observeFailure}}
	operation, selected, _ = operationFixture(t, behavior, "proof")
	if result, err := operation.Apply(effect, postContext(post), selected); !errors.Is(err, observeFailure) || result.Started() || !reflect.DeepEqual(behavior.calls, []string{"observe"}) {
		t.Fatalf("pre-observation failure = %#v, %v, calls=%v", result, err, behavior.calls)
	}
}

func TestOperationApplyPreservesPostObservationFailure(t *testing.T) {
	postFailure := errors.New("post observation failed")
	behavior := &operationBehavior{commit: commitResult{Started: true}, observeErrs: []error{nil, postFailure}}
	operation, selected, _ := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before}
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	result, err := operation.Apply(effect, postContext(post), selected)
	if !result.Started() || !errors.Is(err, postFailure) {
		t.Fatalf("post failure = %#v, %v", result, err)
	}
	if _, ok := result.After(); ok || !reflect.DeepEqual(behavior.calls, []string{"observe", "commit", "observe"}) {
		t.Fatalf("post failure evidence/calls = %#v/%v", result, behavior.calls)
	}
}

func TestOperationApplyUsesIndependentBoundedPostContext(t *testing.T) {
	effect, cancelEffect := context.WithTimeout(context.Background(), time.Minute)
	post, cancelPost := context.WithTimeout(context.Background(), time.Minute)
	defer cancelPost()
	behavior := &operationBehavior{commit: commitResult{Started: true}, cancelCommit: cancelEffect}
	operation, selected, after := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before, after}
	if result, err := operation.Apply(effect, postContext(post), selected); err != nil || !result.Started() {
		t.Fatalf("canceled effect Apply = %#v, %v", result, err)
	}

	behavior = &operationBehavior{commit: commitResult{Started: true}}
	operation, selected, _ = operationFixture(t, behavior, "proof")
	if result, err := operation.Apply(context.Background(), postContext(post), selected); err == nil || result.Started() || len(behavior.calls) != 0 {
		t.Fatalf("unbounded effect context = %#v, %v, calls=%v", result, err, behavior.calls)
	}
	if result, err := operation.Apply(post, nil, selected); err == nil || result.Started() || len(behavior.calls) != 0 {
		t.Fatalf("missing post factory = %#v, %v, calls=%v", result, err, behavior.calls)
	}

	behavior.observations = []Observation{operation.before}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if result, err := operation.Apply(post, postContext(expired), selected); err == nil || !result.Started() || !reflect.DeepEqual(behavior.calls, []string{"observe", "commit"}) {
		t.Fatalf("expired post context = %#v, %v, calls=%v", result, err, behavior.calls)
	}
}

func TestOperationApplyRejectsStartedStaleAsBehaviorFailure(t *testing.T) {
	behavior := &operationBehavior{commit: commitResult{Started: true}, commitErr: ErrStale}
	operation, selected, after := operationFixture(t, behavior, "proof")
	behavior.observations = []Observation{operation.before, after}
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	result, err := operation.Apply(effect, postContext(post), selected)
	if !result.Started() || err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("started stale = %#v, %v", result, err)
	}
}
