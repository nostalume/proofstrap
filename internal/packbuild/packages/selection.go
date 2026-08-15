package packages

import (
	"context"
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
)

type CandidateRole uint8

const (
	SystemCandidate CandidateRole = iota + 1
	AuxiliaryCandidate
)

type candidateState uint8

const (
	candidateAbsent candidateState = iota + 1
	candidateUnsupported
	candidateIndeterminate
	candidateAdmitted
)

type candidateEvidence struct {
	backend binding.PackageBackendID
	role    CandidateRole
	state   candidateState
	proof   proof
	detail  string
}

func (evidence candidateEvidence) equal(other candidateEvidence) bool {
	if evidence.backend != other.backend || evidence.role != other.role || evidence.state != other.state ||
		evidence.detail != other.detail {
		return false
	}
	if evidence.proof == nil || other.proof == nil {
		return evidence.proof == nil && other.proof == nil
	}
	return evidence.proof.equal(other.proof) && other.proof.equal(evidence.proof)
}

type proof interface {
	proof()
	equal(proof) bool
}

type behavior interface {
	Observe(context.Context, proof, []string) (Observation, error)
	Preview(context.Context, proof, Observation) (Offer, error)
	Commit(context.Context, proof, Observation, Offer) (commitResult, error)
	Verify(Observation, Offer, Observation) error
}

type commitResult struct{ Started bool }

type candidate struct {
	evidence candidateEvidence
	behavior behavior
}

//sumtype:decl
type Selection interface{ selection() }

type Selected struct {
	evidence candidateEvidence
	behavior behavior
}

type Unsupported struct{ backend binding.PackageBackendID }
type Ambiguous struct{ backends []binding.PackageBackendID }
type Indeterminate struct {
	backend binding.PackageBackendID
	detail  string
}

// SelectHost probes the fixed built-in system package managers and reduces
// their evidence to one host backend without distro-name dispatch.
func SelectHost(ctx context.Context) Selection {
	effect := linuxEffects()
	return selectHost([]candidate{
		probeZypper(ctx, effect),
		probeApt(ctx, effect),
		probeDNF4(ctx, effect),
		probeDNF5(ctx, effect, systemDNF5Files()),
	})
}

// SelectExact probes only the requested fixed built-in backend.
func SelectExact(ctx context.Context, backend binding.PackageBackendID) Selection {
	effect := linuxEffects()
	var value candidate
	switch backend.String() {
	case "zypper":
		value = probeZypper(ctx, effect)
	case "apt":
		value = probeApt(ctx, effect)
	case "dnf4":
		value = probeDNF4(ctx, effect)
	case "dnf5":
		value = probeDNF5(ctx, effect, systemDNF5Files())
	default:
		return Unsupported{backend: backend}
	}
	return selectExact(backend, []candidate{value})
}

func (Selected) selection()      {}
func (Unsupported) selection()   {}
func (Ambiguous) selection()     {}
func (Indeterminate) selection() {}

func (selected Selected) Backend() binding.PackageBackendID { return selected.evidence.backend }
func (selected Selected) valid() bool {
	return validCandidate(candidate{evidence: selected.evidence, behavior: selected.behavior}) &&
		selected.evidence.state == candidateAdmitted
}
func (selected Selected) Observe(ctx context.Context, desired []string) (Observation, error) {
	if !selected.valid() {
		return Observation{}, fmt.Errorf("invalid selected package behavior")
	}
	return selected.behavior.Observe(ctx, selected.evidence.proof, append([]string(nil), desired...))
}
func (selected Selected) Preview(ctx context.Context, observation Observation) (Offer, error) {
	if !selected.valid() || !observation.valid() {
		return Offer{}, fmt.Errorf("selected behavior and complete observation are required")
	}
	return selected.behavior.Preview(ctx, selected.evidence.proof, observation)
}
func (selected Selected) commit(ctx context.Context, observation Observation, expected Offer) (commitResult, error) {
	if !selected.valid() || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("selected behavior, complete observation, and reviewed offer are required")
	}
	return selected.behavior.Commit(ctx, selected.evidence.proof, observation, expected)
}

func (selection Unsupported) Backend() binding.PackageBackendID { return selection.backend }
func (selection Ambiguous) Backends() []binding.PackageBackendID {
	return append([]binding.PackageBackendID(nil), selection.backends...)
}
func (selection Indeterminate) Backend() binding.PackageBackendID { return selection.backend }
func (selection Indeterminate) Detail() string                    { return selection.detail }

func selectHost(candidates []candidate) Selection {
	system := make([]candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.evidence.role == SystemCandidate {
			system = append(system, candidate)
		}
	}
	return reduceCandidates(binding.PackageBackendID{}, system)
}

func selectExact(backend binding.PackageBackendID, candidates []candidate) Selection {
	exact := make([]candidate, 0, 1)
	for _, candidate := range candidates {
		if candidate.evidence.backend == backend {
			exact = append(exact, candidate)
		}
	}
	return reduceCandidates(backend, exact)
}

func reduceCandidates(demanded binding.PackageBackendID, candidates []candidate) Selection {
	admitted := make(map[string]candidate)
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		evidence := candidate.evidence
		if !validCandidate(candidate) {
			return Indeterminate{backend: evidence.backend, detail: "invalid candidate evidence"}
		}
		key := evidence.backend.String()
		if _, exists := seen[key]; exists {
			return Indeterminate{backend: evidence.backend, detail: "duplicate backend candidate"}
		}
		seen[key] = struct{}{}
		if evidence.state == candidateIndeterminate {
			return Indeterminate{backend: evidence.backend, detail: evidence.detail}
		}
		if evidence.state != candidateAdmitted {
			continue
		}
		admitted[key] = candidate
	}
	if len(admitted) == 0 {
		return Unsupported{backend: demanded}
	}
	if len(admitted) > 1 {
		backends := make([]binding.PackageBackendID, 0, len(admitted))
		for _, candidate := range admitted {
			backends = append(backends, candidate.evidence.backend)
		}
		sort.Slice(backends, func(i, j int) bool { return backends[i].String() < backends[j].String() })
		return Ambiguous{backends: backends}
	}
	for _, candidate := range admitted {
		return Selected{evidence: candidate.evidence, behavior: candidate.behavior}
	}
	panic("unreachable")
}

func validCandidate(candidate candidate) bool {
	evidence := candidate.evidence
	if evidence.backend.String() == "" || evidence.role < SystemCandidate || evidence.role > AuxiliaryCandidate ||
		evidence.state < candidateAbsent || evidence.state > candidateAdmitted {
		return false
	}
	if evidence.state == candidateAdmitted {
		return evidence.proof != nil && evidence.detail == "" && candidate.behavior != nil
	}
	if evidence.proof != nil || candidate.behavior != nil {
		return false
	}
	if evidence.state == candidateAbsent {
		return evidence.detail == ""
	}
	return evidence.detail != ""
}
