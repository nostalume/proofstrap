package packages

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

func TestDNFInventoryQueryFormatsHonorNativeRecordBoundaries(t *testing.T) {
	row := "--queryformat=%{name}\t%{epoch}\t%{version}\t%{release}\t%{arch}\t%{vendor}\t%{reason}"
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"dnf4": {dnf4InventoryArgs(), row},
		"dnf5": {dnf5InventoryArgs(), row + "\n"},
	} {
		if got := test.args[len(test.args)-1]; got != test.want {
			t.Errorf("%s query format = %q, want %q", name, got, test.want)
		}
	}
}

func verificationObservation(t *testing.T, desired []string, installed []record, roots []string, demands []demand) Observation {
	t.Helper()
	inventory, err := newInventory(installed, roots)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := newObservation(desired, inventory, demands)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

type transitionVerifier interface {
	Verify(Observation, Offer, Observation) error
}

func exerciseRPMVerification(t *testing.T, verifier transitionVerifier, root string) {
	t.Helper()
	before := verificationObservation(t, []string{"new"},
		[]record{{Key: "keep\t0:1-1\tnoarch", State: "vendor"}}, []string{"keep-root"},
		[]demand{{Name: "new", State: demandMissing}})
	after := verificationObservation(t, []string{"new"},
		[]record{{Key: "keep\t0:1-1\tnoarch", State: "vendor"}, {Key: "new\t0:2-1\tx86_64", State: "vendor"}},
		[]string{"keep-root", root}, []demand{{Name: "new", State: demandDirect}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Add, "new\tx86_64", "", "0:2-1"),
		mustDelta(t, RootAdd, "new", "", "direct"),
	})
	if err := verifier.Verify(before, offer, after); err != nil {
		t.Fatalf("verify Add: %v", err)
	}
	cases := []struct {
		name  string
		after Observation
	}{
		{"unresolved", verificationObservation(t, []string{"new"}, after.inventory().installed(), after.inventory().roots(), []demand{{Name: "new", State: demandDependency}})},
		{"missing-record", verificationObservation(t, []string{"new"}, before.inventory().installed(), after.inventory().roots(), after.demands())},
		{"wrong-version", verificationObservation(t, []string{"new"}, []record{{Key: "keep\t0:1-1\tnoarch", State: "vendor"}, {Key: "new\t0:3-1\tx86_64", State: "vendor"}}, after.inventory().roots(), after.demands())},
		{"removed-root", verificationObservation(t, []string{"new"}, after.inventory().installed(), []string{root}, after.demands())},
		{"excess-roots", verificationObservation(t, []string{"new"}, after.inventory().installed(), []string{"extra-root", "keep-root", root}, after.demands())},
	}
	for _, test := range cases {
		if err := verifier.Verify(before, offer, test.after); err == nil {
			t.Fatalf("Verify accepted %s post-state", test.name)
		}
	}
}

func TestVerificationEnvelopeRejectsUnreviewedRootAndLifecycleEvidence(t *testing.T) {
	direct := verificationObservation(t, []string{"pkg"}, nil, []string{"pkg"}, []demand{{Name: "pkg", State: demandDirect}})
	extraRoot := verificationObservation(t, []string{"pkg"}, nil, []string{"other", "pkg"}, []demand{{Name: "pkg", State: demandDirect}})
	empty, _ := newOffer(nil)
	if _, err := verifyObservationTransition(direct, empty, extraRoot); err == nil {
		t.Fatal("accepted root growth without RootAdd")
	}
	removed, _ := newOffer([]Delta{mustDelta(t, Remove, "pkg\tx86_64", "1", "")})
	if _, err := verifyObservationTransition(direct, removed, direct); err == nil {
		t.Fatal("accepted forbidden lifecycle evidence")
	}
	changedDemand := verificationObservation(t, []string{"other"}, nil, []string{"pkg"}, []demand{{Name: "other", State: demandDirect}})
	if _, err := verifyObservationTransition(direct, empty, changedDemand); err == nil {
		t.Fatal("accepted changed desired set")
	}
}

func TestDomainInventoryAndObservationAreCanonicalAndImmutable(t *testing.T) {
	records := []record{{Key: "z", State: "2"}, {Key: "a", State: "1"}}
	roots := []string{"virtual", "a"}
	inventory, err := newInventory(records, roots)
	if err != nil {
		t.Fatal(err)
	}
	records[0].Key = "mutated"
	roots[0] = "mutated"
	if got := inventory.installed(); !reflect.DeepEqual(got, []record{{Key: "a", State: "1"}, {Key: "z", State: "2"}}) {
		t.Fatalf("Installed = %#v", got)
	}
	if got := inventory.roots(); !reflect.DeepEqual(got, []string{"a", "virtual"}) {
		t.Fatalf("Roots = %#v", got)
	}
	desired := []string{"virtual", "a"}
	observation, err := newObservation(desired, inventory, []demand{
		{Name: "virtual", State: demandDependency},
		{Name: "a", State: demandDirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := observation.demands(); !reflect.DeepEqual(got, []demand{{Name: "a", State: demandDirect}, {Name: "virtual", State: demandDependency}}) {
		t.Fatalf("Demands = %#v", got)
	}
	if !observation.inventory().equal(inventory) {
		t.Fatal("Observation lost inventory")
	}
}

func TestDomainConstructorsRejectIncompleteOrContradictoryEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		records []record
		roots   []string
	}{
		{"empty-key", []record{{State: "v"}}, nil},
		{"duplicate-key", []record{{Key: "a", State: "1"}, {Key: "a", State: "2"}}, nil},
		{"empty-root", nil, []string{""}},
		{"duplicate-root", nil, []string{"a", "a"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if value, err := newInventory(test.records, test.roots); err == nil || value.valid() {
				t.Fatalf("newInventory = %#v, %v; want invalid error", value, err)
			}
		})
	}
	baseInventory, _ := newInventory(nil, nil)
	for _, test := range []struct {
		name    string
		desired []string
		states  []demand
	}{
		{"zero-inventory", []string{"a"}, []demand{{Name: "a", State: demandDirect}}},
		{"missing-result", []string{"a", "b"}, []demand{{Name: "a", State: demandDirect}}},
		{"extra-result", []string{"a"}, []demand{{Name: "a", State: demandDirect}, {Name: "b", State: demandMissing}}},
		{"duplicate-result", []string{"a"}, []demand{{Name: "a", State: demandDirect}, {Name: "a", State: demandDirect}}},
		{"invalid-state", []string{"a"}, []demand{{Name: "a", State: demandState(99)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := baseInventory
			if test.name == "zero-inventory" {
				candidate = inventory{}
			}
			if value, err := newObservation(test.desired, candidate, test.states); err == nil || value.valid() {
				t.Fatalf("newObservation = %#v, %v; want invalid error", value, err)
			}
		})
	}
	for _, desired := range [][]string{{"a", "a"}, {""}} {
		if value, err := newObservation(desired, baseInventory, nil); err == nil || value.valid() {
			t.Fatalf("invalid desired set admitted: %#v, %v", value, err)
		}
	}
}

func TestDomainLifecycleBlocksForbiddenAndUnclassifiedOffers(t *testing.T) {
	zypper := backend(t, "zypper")
	selected := selectExact(zypper, []candidate{
		admittedCandidate(zypper, SystemCandidate, "zypper-proof", fakeBehavior{}),
	}).(Selected)
	inventory, _ := newInventory(nil, nil)
	observation, _ := newObservation([]string{"new"}, inventory, []demand{{Name: "new", State: demandMissing}})
	allowed := []Delta{
		mustDelta(t, Add, "new", "", "1"),
		mustDelta(t, Upgrade, "old", "1", "2"),
		mustDelta(t, RootAdd, "new", "", "direct"),
	}
	offer, err := newOffer(allowed)
	if err != nil {
		t.Fatal(err)
	}
	allowedDecision, err := Decide(offer)
	if err != nil || !allowedDecision.Allowed() {
		t.Fatalf("Decide = %#v, %v; want allowed", allowedDecision, err)
	}
	operation, err := NewOperation(selected, observation, allowedDecision)
	if err != nil || operation.Backend() != zypper || !reflect.DeepEqual(operation.Deltas(), allowed) {
		t.Fatalf("NewOperation = %#v, %v", operation, err)
	}

	for _, kind := range []DeltaKind{Downgrade, Remove, Replace, RootRemove, VendorChange, ArchitectureChange, Unclassified} {
		delta := forbiddenDelta(t, kind)
		offer, err := newOffer([]Delta{delta})
		if err != nil {
			t.Fatalf("%s offer: %v", kind, err)
		}
		decision, err := Decide(offer)
		if err != nil || decision.Allowed() || len(decision.Blockers()) != 1 {
			t.Fatalf("%s decision = %#v, %v", kind, decision, err)
		}
		if operation, err := NewOperation(selected, observation, decision); err == nil || operation.valid() {
			t.Fatalf("%s constructed operation: %#v, %v", kind, operation, err)
		}
	}
	if offer, err := newOffer([]Delta{allowed[0], allowed[0]}); err == nil || offer.valid() {
		t.Fatalf("duplicate delta admitted: %#v, %v", offer, err)
	}
	if offer, err := newOffer([]Delta{allowed[0], mustDelta(t, Remove, "new", "1", "")}); err == nil || offer.valid() {
		t.Fatalf("contradictory package-state deltas admitted: %#v, %v", offer, err)
	}
	if operation, err := NewOperation(selected, Observation{}, allowedDecision); err == nil || operation.valid() {
		t.Fatalf("incomplete pre-observation constructed operation: %#v, %v", operation, err)
	}
	if operation, err := NewOperation(Selected{}, observation, allowedDecision); err == nil || operation.valid() {
		t.Fatalf("invalid selected behavior constructed operation: %#v, %v", operation, err)
	}
	second, _ := newOffer([]Delta{allowed[2], allowed[0], allowed[1]})
	if !offer.equal(second) {
		t.Fatal("semantic offer equality depends on input order")
	}
	exposed := offer.Deltas()
	exposed[0] = Delta{}
	if !offer.equal(second) {
		t.Fatal("Offer exposed mutable deltas")
	}
	empty, _ := newOffer(nil)
	emptyDecision, _ := Decide(empty)
	if operation, err := NewOperation(selected, observation, emptyDecision); err == nil || operation.valid() {
		t.Fatalf("empty offer constructed operation: %#v, %v", operation, err)
	}
}

func TestDecisionAllowsOnlyExactReinstallForMatchingRootPromotion(t *testing.T) {
	reinstall := mustDelta(t, Replace, "pkg\tx86_64", "0:1-1", "0:1-1 (reinstall)")
	root := mustDelta(t, RootAdd, "pkg", "", "direct")
	offer, _ := newOffer([]Delta{reinstall, root})
	decision, err := Decide(offer)
	if err != nil || !decision.Allowed() {
		t.Fatalf("matching promotion = %#v, %v", decision, err)
	}
	for name, deltas := range map[string][]Delta{
		"no-root":        {reinstall},
		"unmatched-root": {reinstall, mustDelta(t, RootAdd, "other", "", "direct")},
		"changed-state":  {mustDelta(t, Replace, "pkg\tx86_64", "0:1-1", "0:2-1"), root},
	} {
		t.Run(name, func(t *testing.T) {
			offer, _ := newOffer(deltas)
			decision, err := Decide(offer)
			if err != nil || decision.Allowed() {
				t.Fatalf("decision = %#v, %v; want blocked", decision, err)
			}
		})
	}
}

func TestDomainHostAndExactSelectionReduceCandidateEvidence(t *testing.T) {
	zypper := backend(t, "zypper")
	apt := backend(t, "apt")
	flatpak := backend(t, "flatpak")
	zypperBehavior := fakeBehavior{}
	aptBehavior := fakeBehavior{}
	auxBehavior := fakeBehavior{}

	selected := selectHost([]candidate{
		admittedCandidate(zypper, SystemCandidate, "zypper-proof", zypperBehavior),
		admittedCandidate(flatpak, AuxiliaryCandidate, "flatpak-proof", auxBehavior),
	})
	chosen, ok := selected.(Selected)
	if !ok || chosen.Backend() != zypper {
		t.Fatalf("host selection = %#v, want zypper", selected)
	}
	desired := []string{"editor"}
	observation, err := chosen.Observe(context.Background(), desired)
	if err != nil || observation.demands()[0].Name != "zypper-proof:editor" {
		t.Fatalf("selected behavior mismatch: %#v, %v", observation, err)
	}
	if desired[0] != "editor" {
		t.Fatal("Selected.Observe exposed caller-owned desired slice")
	}
	if !chosen.evidence.equal(admittedCandidate(zypper, SystemCandidate, "zypper-proof", zypperBehavior).evidence) ||
		chosen.evidence.equal(admittedCandidate(zypper, SystemCandidate, "other-proof", zypperBehavior).evidence) {
		t.Fatal("candidate proof equality is not exact")
	}
	expected, _ := newOffer(nil)
	commit, err := chosen.commit(context.Background(), observation, expected)
	if err != nil || !commit.Started {
		t.Fatalf("Commit = %#v, %v; want started", commit, err)
	}

	if _, ok := selectHost(nil).(Unsupported); !ok {
		t.Fatalf("zero host candidates = %#v, want Unsupported", selectHost(nil))
	}
	if _, ok := selectHost([]candidate{
		admittedCandidate(zypper, SystemCandidate, "z", zypperBehavior),
		admittedCandidate(apt, SystemCandidate, "a", aptBehavior),
	}).(Ambiguous); !ok {
		t.Fatal("multiple admitted system candidates did not produce Ambiguous")
	}
	if _, ok := selectHost([]candidate{
		admittedCandidate(zypper, SystemCandidate, "z", zypperBehavior),
		indeterminateCandidate(apt, SystemCandidate, "probe failed"),
	}).(Indeterminate); !ok {
		t.Fatal("competing indeterminate system candidate did not fail closed")
	}
	if exact := selectExact(flatpak, []candidate{
		admittedCandidate(zypper, SystemCandidate, "z", zypperBehavior),
		admittedCandidate(flatpak, AuxiliaryCandidate, "f", auxBehavior),
	}); exact.(Selected).Backend() != flatpak {
		t.Fatalf("exact selection = %#v, want flatpak", exact)
	}
	if _, ok := selectExact(zypper, []candidate{
		admittedCandidate(zypper, SystemCandidate, "one", zypperBehavior),
		admittedCandidate(zypper, SystemCandidate, "two", zypperBehavior),
	}).(Indeterminate); !ok {
		t.Fatal("conflicting identities for one backend did not produce Indeterminate")
	}
	duplicate := selectHost([]candidate{
		admittedCandidate(zypper, SystemCandidate, "same", zypperBehavior),
		admittedCandidate(zypper, SystemCandidate, "same", zypperBehavior),
		indeterminateCandidate(flatpak, AuxiliaryCandidate, "irrelevant"),
	})
	if _, ok := duplicate.(Indeterminate); !ok {
		t.Fatalf("duplicate backend candidates did not fail closed: %#v", duplicate)
	}
	if selected := selectExact(zypper, []candidate{
		admittedCandidate(zypper, SystemCandidate, "z", zypperBehavior),
		indeterminateCandidate(apt, SystemCandidate, "unrelated"),
	}); selected.(Selected).Backend() != zypper {
		t.Fatalf("unrelated exact evidence competed: %#v", selected)
	}
	malformed := []candidate{
		{evidence: candidateEvidence{backend: zypper, role: SystemCandidate, state: candidateAdmitted}},
		{evidence: candidateEvidence{backend: zypper, role: SystemCandidate, state: candidateAbsent, detail: "unexpected"}},
		{evidence: candidateEvidence{backend: zypper, role: SystemCandidate, state: candidateUnsupported}},
		{evidence: candidateEvidence{backend: zypper, role: SystemCandidate, state: candidateIndeterminate}},
		{evidence: candidateEvidence{backend: zypper, role: SystemCandidate, state: candidateUnsupported,
			proof: fakeProof{value: "unexpected"}, detail: "unsupported"}},
	}
	for index, value := range malformed {
		result := selectExact(zypper, []candidate{value})
		if _, ok := result.(Indeterminate); !ok {
			t.Fatalf("malformed candidate %d did not fail closed: %#v", index, result)
		}
	}
	ambiguous := selectHost([]candidate{
		admittedCandidate(zypper, SystemCandidate, "z", zypperBehavior),
		admittedCandidate(apt, SystemCandidate, "a", aptBehavior),
	}).(Ambiguous)
	backends := ambiguous.Backends()
	backends[0] = flatpak
	if ambiguous.Backends()[0] != apt {
		t.Fatal("Ambiguous exposed mutable backend evidence")
	}
}

func TestDomainEffectsKeepTheLinuxBoundaryExplicit(t *testing.T) {
	production := linuxEffects()
	if production.identify == nil || production.run == nil {
		t.Fatal("production Linux effects are incomplete")
	}
	wantIdentity := linux.Identity{Path: "/usr/bin/manager"}
	wantResult := linux.Result{Started: true, ExitCode: 7, Stdout: []byte("native")}
	boundary := effects{
		identify: func(path string) (linux.Identity, error) {
			if path != wantIdentity.Path {
				t.Fatalf("identify path = %q", path)
			}
			return wantIdentity, nil
		},
		run: func(ctx context.Context, identity linux.Identity, args []string, stdin []byte) (linux.Result, error) {
			if _, ok := ctx.Deadline(); !ok || identity != wantIdentity ||
				!reflect.DeepEqual(args, []string{"preview", "pkg"}) || string(stdin) != "input\n" {
				t.Fatalf("run boundary = %#v, %#v, %q", identity, args, stdin)
			}
			return wantResult, nil
		},
	}
	if identity, err := boundary.identify(wantIdentity.Path); err != nil || identity != wantIdentity {
		t.Fatalf("identify = %#v, %v", identity, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result, err := boundary.run(ctx, wantIdentity, []string{"preview", "pkg"}, []byte("input\n")); err != nil || !reflect.DeepEqual(result, wantResult) {
		t.Fatalf("run = %#v, %v", result, err)
	}
}

func TestProductionSelectionRejectsUnknownExactBackendWithoutProbe(t *testing.T) {
	backend, err := binding.NewPackageBackendID("flatpak")
	if err != nil {
		t.Fatal(err)
	}
	selection := SelectExact(context.Background(), backend)
	unsupported, ok := selection.(Unsupported)
	if !ok || unsupported.Backend() != backend {
		t.Fatalf("unknown exact selection = %#v", selection)
	}
}

func mustDelta(t *testing.T, kind DeltaKind, key, before, after string) Delta {
	t.Helper()
	value, err := newDelta(kind, key, before, after)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func forbiddenDelta(t *testing.T, kind DeltaKind) Delta {
	t.Helper()
	switch kind {
	case Remove, RootRemove:
		return mustDelta(t, kind, "pkg", "old", "")
	case Unclassified:
		return mustDelta(t, kind, "pkg", "native", "unknown")
	default:
		return mustDelta(t, kind, "pkg", "old", "new")
	}
}

func backend(t *testing.T, name string) binding.PackageBackendID {
	t.Helper()
	id, err := binding.NewPackageBackendID(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type fakeProof struct{ value string }

func (fakeProof) proof() {}
func (value fakeProof) equal(other proof) bool {
	candidate, ok := other.(fakeProof)
	return ok && value == candidate
}

type fakeBehavior struct{}

func admittedCandidate(id binding.PackageBackendID, role CandidateRole, value string, behavior behavior) candidate {
	return candidate{evidence: candidateEvidence{
		backend: id, role: role, state: candidateAdmitted, proof: fakeProof{value: value},
	}, behavior: behavior}
}

func indeterminateCandidate(id binding.PackageBackendID, role CandidateRole, detail string) candidate {
	return candidate{evidence: candidateEvidence{
		backend: id, role: role, state: candidateIndeterminate, detail: detail,
	}}
}

func (fakeBehavior) Observe(_ context.Context, evidence proof, desired []string) (Observation, error) {
	value := evidence.(fakeProof)
	inventory, _ := newInventory(nil, nil)
	states := make([]demand, len(desired))
	for index, name := range desired {
		states[index] = demand{Name: name, State: demandDirect}
		states[index].Name = value.value + ":" + states[index].Name
		desired[index] = states[index].Name
	}
	return newObservation(desired, inventory, states)
}

func (fakeBehavior) Preview(context.Context, proof, Observation) (Offer, error) {
	return newOffer(nil)
}

func (fakeBehavior) Commit(context.Context, proof, Observation, Offer) (commitResult, error) {
	return commitResult{Started: true}, nil
}
func (fakeBehavior) Verify(Observation, Offer, Observation) error { return nil }
