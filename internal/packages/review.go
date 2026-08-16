package packages

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
	reviewjson "github.com/nostalume/proofstrap/internal/review"
)

const maxReviewBytes = 64 << 20

type Review struct{ state *reviewState }

type reviewState struct {
	evidence candidateEvidence
	before   Observation
	offer    Offer
}

func (review Review) valid() bool {
	return review.state != nil && validExpectedEvidence(review.state.evidence) &&
		review.state.before.valid() && review.state.offer.valid() && len(review.state.offer.state.deltas) != 0
}

func (review Review) Backend() binding.PackageBackendID {
	if review.state == nil {
		return binding.PackageBackendID{}
	}
	return review.state.evidence.backend
}

func (review Review) Role() CandidateRole {
	if review.state == nil {
		return 0
	}
	return review.state.evidence.role
}

func (review Review) Deltas() []Delta {
	if review.state == nil {
		return nil
	}
	return review.state.offer.Deltas()
}

func EncodeReview(operation Operation) ([]byte, error) {
	if !operation.valid() || len(operation.offer.state.deltas) == 0 {
		return nil, fmt.Errorf("valid nonempty package operation is required")
	}
	wire, err := reviewToWire(reviewState{evidence: operation.evidence, before: operation.before, offer: operation.offer})
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode package review: %w", err)
	}
	if len(encoded) > maxReviewBytes {
		return nil, fmt.Errorf("package review exceeds %d bytes", maxReviewBytes)
	}
	return encoded, nil
}

func DecodeReview(data []byte) (Review, error) {
	if len(data) == 0 || len(data) > maxReviewBytes {
		return Review{}, fmt.Errorf("package review must contain 1..%d bytes", maxReviewBytes)
	}
	var wire reviewWire
	err := reviewjson.DecodeStrict(data, &wire)
	if errors.Is(err, reviewjson.ErrMultiple) {
		return Review{}, fmt.Errorf("package review contains multiple JSON values")
	}
	var trailing reviewjson.TrailingError
	if errors.As(err, &trailing) {
		return Review{}, fmt.Errorf("decode package review trailing data: %w", trailing.Err)
	}
	if err != nil {
		return Review{}, fmt.Errorf("decode package review: %w", err)
	}
	state, err := reviewFromWire(wire)
	if err != nil {
		return Review{}, err
	}
	canonical, err := reviewToWire(state)
	if err != nil {
		return Review{}, err
	}
	encoded, _ := json.Marshal(canonical)
	if !bytes.Equal(data, encoded) {
		return Review{}, fmt.Errorf("package review is not canonical JSON")
	}
	return Review{state: &state}, nil
}

func Reconstruct(review Review, fresh Selected) (Operation, error) {
	if !review.valid() || !fresh.valid() {
		return Operation{}, fmt.Errorf("valid package review and fresh selection are required")
	}
	if !review.state.evidence.equal(fresh.evidence) {
		return Operation{}, fmt.Errorf("%w: selected package evidence changed", ErrStale)
	}
	return Operation{evidence: review.state.evidence, before: review.state.before, offer: review.state.offer}, nil
}

func validExpectedEvidence(evidence candidateEvidence) bool {
	return evidence.backend.String() != "" &&
		evidence.role >= SystemCandidate && evidence.role <= AuxiliaryCandidate &&
		evidence.state == candidateAdmitted && evidence.proof != nil && evidence.detail == ""
}

type reviewWire struct {
	Backend      string       `json:"backend"`
	Role         string       `json:"role"`
	Tools        []toolWire   `json:"tools"`
	Architecture string       `json:"architecture,omitempty"`
	Installed    []recordWire `json:"installed"`
	Roots        []string     `json:"roots"`
	Demands      []demandWire `json:"demands"`
	Deltas       []deltaWire  `json:"deltas"`
}

type toolWire struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

type recordWire struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

type demandWire struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type deltaWire struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func reviewToWire(state reviewState) (reviewWire, error) {
	if !validExpectedEvidence(state.evidence) || !state.before.valid() || !state.offer.valid() {
		return reviewWire{}, fmt.Errorf("complete package review evidence is required")
	}
	tools, architecture, err := encodeProof(state.evidence.proof)
	if err != nil {
		return reviewWire{}, err
	}
	decoded, err := decodeProof(state.evidence.backend.String(), tools, architecture)
	if err != nil || !state.evidence.proof.equal(decoded) || !decoded.equal(state.evidence.proof) {
		if err == nil {
			err = fmt.Errorf("proof does not match backend")
		}
		return reviewWire{}, fmt.Errorf("invalid package review proof: %w", err)
	}
	wire := reviewWire{
		Backend:      state.evidence.backend.String(),
		Role:         roleName(state.evidence.role),
		Tools:        tools,
		Architecture: architecture,
		Installed:    make([]recordWire, 0),
		Roots:        append([]string{}, state.before.inventory().roots()...),
		Demands:      make([]demandWire, 0),
		Deltas:       make([]deltaWire, 0),
	}
	for _, record := range state.before.inventory().installed() {
		wire.Installed = append(wire.Installed, recordWire{Key: record.Key, State: record.State})
	}
	for _, demand := range state.before.demands() {
		wire.Demands = append(wire.Demands, demandWire{Name: demand.Name, State: demandStateName(demand.State)})
	}
	for _, delta := range state.offer.deltas() {
		wire.Deltas = append(wire.Deltas, deltaWire{Kind: delta.Kind().String(), Key: delta.Key(), Before: delta.Before(), After: delta.After()})
	}
	return wire, nil
}

func reviewFromWire(wire reviewWire) (reviewState, error) {
	backend, err := binding.NewPackageBackendID(wire.Backend)
	if err != nil {
		return reviewState{}, err
	}
	role, err := parseRole(wire.Role)
	if err != nil {
		return reviewState{}, err
	}
	native, err := decodeProof(wire.Backend, wire.Tools, wire.Architecture)
	if err != nil {
		return reviewState{}, err
	}
	installed := make([]record, 0, len(wire.Installed))
	for _, item := range wire.Installed {
		installed = append(installed, record{Key: item.Key, State: item.State})
	}
	inventory, err := newInventory(installed, wire.Roots)
	if err != nil {
		return reviewState{}, err
	}
	desired := make([]string, 0, len(wire.Demands))
	demands := make([]demand, 0, len(wire.Demands))
	for _, item := range wire.Demands {
		state, stateErr := parseDemandState(item.State)
		if stateErr != nil {
			return reviewState{}, stateErr
		}
		desired = append(desired, item.Name)
		demands = append(demands, demand{Name: item.Name, State: state})
	}
	before, err := newObservation(desired, inventory, demands)
	if err != nil {
		return reviewState{}, err
	}
	deltas := make([]Delta, 0, len(wire.Deltas))
	for _, item := range wire.Deltas {
		kind, kindErr := parseDeltaKind(item.Kind)
		if kindErr != nil {
			return reviewState{}, kindErr
		}
		delta, deltaErr := newDelta(kind, item.Key, item.Before, item.After)
		if deltaErr != nil {
			return reviewState{}, deltaErr
		}
		deltas = append(deltas, delta)
	}
	offer, err := newOffer(deltas)
	if err != nil {
		return reviewState{}, err
	}
	decision, err := Decide(offer)
	if err != nil || !decision.Allowed() || len(deltas) == 0 {
		return reviewState{}, fmt.Errorf("package review requires a nonempty permitted offer")
	}
	return reviewState{
		evidence: candidateEvidence{backend: backend, role: role, state: candidateAdmitted, proof: native},
		before:   before,
		offer:    offer,
	}, nil
}

func encodeProof(native proof) ([]toolWire, string, error) {
	switch value := native.(type) {
	case zypperProof:
		return []toolWire{
			encodeTool("rpm", value.rpm, value.rpmVersion),
			encodeTool("zypper", value.zypper, value.zypperVersion),
		}, "", nil
	case aptProof:
		return []toolWire{
			encodeTool("apt-get", value.get, value.getVersion),
			encodeTool("apt-mark", value.mark, value.markVersion),
			encodeTool("dpkg", value.dpkg, value.dpkgVersion),
			encodeTool("dpkg-query", value.query, value.queryVersion),
		}, value.nativeArch, nil
	case dnf5Proof:
		return []toolWire{encodeTool("dnf5", value.executable, value.version)}, "", nil
	case dnf4Proof:
		return []toolWire{encodeTool("dnf", value.executable, value.version)}, "", nil
	case apkProof:
		return []toolWire{encodeTool("apk", value.executable, value.version)}, value.architecture, nil
	default:
		return nil, "", fmt.Errorf("unsupported package proof %T", native)
	}
}

func decodeProof(backend string, tools []toolWire, architecture string) (proof, error) {
	switch backend {
	case "zypper":
		values, err := decodeTools(tools, []string{"rpm", "zypper"})
		if err != nil || architecture != "" {
			return nil, proofShapeError(backend, err)
		}
		return zypperProof{rpm: values[0].identity, rpmVersion: values[0].version, zypper: values[1].identity, zypperVersion: values[1].version}, nil
	case "apt":
		values, err := decodeTools(tools, []string{"apt-get", "apt-mark", "dpkg", "dpkg-query"})
		if err != nil || !validReviewText(architecture, 255) {
			return nil, proofShapeError(backend, err)
		}
		return aptProof{get: values[0].identity, getVersion: values[0].version, mark: values[1].identity, markVersion: values[1].version, dpkg: values[2].identity, dpkgVersion: values[2].version, query: values[3].identity, queryVersion: values[3].version, nativeArch: architecture}, nil
	case "dnf5":
		values, err := decodeTools(tools, []string{"dnf5"})
		if err != nil || architecture != "" {
			return nil, proofShapeError(backend, err)
		}
		return dnf5Proof{executable: values[0].identity, version: values[0].version}, nil
	case "dnf4":
		values, err := decodeTools(tools, []string{"dnf"})
		if err != nil || architecture != "" {
			return nil, proofShapeError(backend, err)
		}
		return dnf4Proof{executable: values[0].identity, version: values[0].version}, nil
	case "apk":
		values, err := decodeTools(tools, []string{"apk"})
		if err != nil || !validAPKArchitecture(architecture) {
			return nil, proofShapeError(backend, err)
		}
		return apkProof{executable: values[0].identity, version: values[0].version, architecture: architecture}, nil
	default:
		return nil, fmt.Errorf("unsupported package review backend %q", backend)
	}
}

type decodedTool struct {
	identity linux.Identity
	version  string
}

func encodeTool(name string, identity linux.Identity, version string) toolWire {
	return toolWire{Name: name, Path: identity.Path, SHA256: hex.EncodeToString(identity.Digest[:]), Version: version}
}

func decodeTools(tools []toolWire, names []string) ([]decodedTool, error) {
	if len(tools) != len(names) {
		return nil, fmt.Errorf("expected %d tools", len(names))
	}
	result := make([]decodedTool, len(tools))
	for index, tool := range tools {
		if tool.Name != names[index] || !validReviewText(tool.Version, 255) || len(tool.Path) > 4095 ||
			!filepath.IsAbs(tool.Path) || filepath.Clean(tool.Path) != tool.Path || strings.ContainsRune(tool.Path, 0) {
			return nil, fmt.Errorf("invalid tool %d", index)
		}
		digest, err := hex.DecodeString(tool.SHA256)
		if err != nil || len(digest) != len(result[index].identity.Digest) || hex.EncodeToString(digest) != tool.SHA256 {
			return nil, fmt.Errorf("invalid tool digest %d", index)
		}
		result[index].identity.Path = tool.Path
		copy(result[index].identity.Digest[:], digest)
		result[index].version = tool.Version
	}
	return result, nil
}

func proofShapeError(backend string, err error) error {
	if err == nil {
		err = fmt.Errorf("invalid architecture")
	}
	return fmt.Errorf("invalid %s proof: %w", backend, err)
}

func validReviewText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func roleName(role CandidateRole) string {
	if role == SystemCandidate {
		return "system"
	}
	if role == AuxiliaryCandidate {
		return "auxiliary"
	}
	return "invalid"
}

func parseRole(value string) (CandidateRole, error) {
	switch value {
	case "system":
		return SystemCandidate, nil
	case "auxiliary":
		return AuxiliaryCandidate, nil
	default:
		return 0, fmt.Errorf("invalid package candidate role %q", value)
	}
}

func demandStateName(state demandState) string {
	switch state {
	case demandMissing:
		return "missing"
	case demandDependency:
		return "dependency"
	case demandDirect:
		return "direct"
	default:
		return "invalid"
	}
}

func parseDemandState(value string) (demandState, error) {
	switch value {
	case "missing":
		return demandMissing, nil
	case "dependency":
		return demandDependency, nil
	case "direct":
		return demandDirect, nil
	default:
		return 0, fmt.Errorf("invalid package demand state %q", value)
	}
}

func parseDeltaKind(value string) (DeltaKind, error) {
	for kind := Add; kind <= Unclassified; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("invalid package delta kind %q", value)
}
