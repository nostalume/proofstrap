package services

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
)

const maxReviewBytes = 1 << 20

type Review struct{ operation *Operation }

func (review Review) valid() bool { return review.operation != nil && review.operation.valid() }

func (review Review) Principal() (Principal, bool) {
	if !review.valid() || review.operation.evidence.scope != userScope {
		return Principal{}, false
	}
	return review.operation.evidence.principal, true
}

func EncodeReview(operation Operation) ([]byte, error) {
	if !operation.valid() {
		return nil, fmt.Errorf("valid service operation is required")
	}
	wire := operationToWire(operation)
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode service review: %w", err)
	}
	if len(encoded) > maxReviewBytes {
		return nil, fmt.Errorf("service review exceeds %d bytes", maxReviewBytes)
	}
	return encoded, nil
}

func DecodeReview(data []byte) (Review, error) {
	if len(data) == 0 || len(data) > maxReviewBytes {
		return Review{}, fmt.Errorf("service review must contain 1..%d bytes", maxReviewBytes)
	}
	var wire reviewWire
	if err := decodeStrict(data, &wire); err != nil {
		return Review{}, fmt.Errorf("decode service review: %w", err)
	}
	operation, err := operationFromWire(wire)
	if err != nil {
		return Review{}, err
	}
	canonical, _ := EncodeReview(operation)
	if !bytes.Equal(data, canonical) {
		return Review{}, fmt.Errorf("service review is not canonical JSON")
	}
	return Review{operation: &operation}, nil
}

func Reconstruct(review Review, fresh *Selected) (Operation, error) {
	if !review.valid() || !fresh.valid() {
		return Operation{}, fmt.Errorf("valid service review and fresh selection are required")
	}
	if review.operation.evidence != fresh.evidence {
		return Operation{}, fmt.Errorf("%w: service selection evidence changed", ErrStale)
	}
	return *review.operation, nil
}

type reviewWire struct {
	Kind     string        `json:"kind"`
	Evidence evidenceWire  `json:"evidence"`
	Unit     string        `json:"unit"`
	User     string        `json:"user,omitempty"`
	Before   axisStateWire `json:"before"`
}
type evidenceWire struct {
	Scope   string            `json:"scope"`
	Tool    toolWire          `json:"tool"`
	Version string            `json:"version"`
	EUID    uint32            `json:"euid"`
	PID1    string            `json:"pid1"`
	User    *userEvidenceWire `json:"user,omitempty"`
}
type toolWire struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type userEvidenceWire struct {
	Name string   `json:"name"`
	UID  uint32   `json:"uid"`
	Home homeWire `json:"home"`
}
type homeWire struct {
	Path      string `json:"path"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mode      uint16 `json:"mode"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	Directory bool   `json:"directory"`
}
type axisStateWire struct {
	ID    string `json:"id"`
	Load  string `json:"load"`
	Value string `json:"value"`
	Sub   string `json:"sub"`
}

func operationToWire(operation Operation) reviewWire {
	evidence := evidenceWire{Scope: scopeName(operation.evidence.scope), Tool: toolWire{Path: operation.evidence.tool.Path, SHA256: hex.EncodeToString(operation.evidence.tool.Digest[:])}, Version: operation.evidence.version, EUID: operation.evidence.euid, PID1: operation.evidence.pid1}
	if operation.evidence.scope == userScope {
		principal, home := operation.evidence.principal, operation.evidence.home
		evidence.User = &userEvidenceWire{Name: principal.name, UID: principal.uid, Home: homeWire{Path: home.path, UID: home.uid, GID: home.gid, Mode: home.mode, Device: home.device, Inode: home.inode, Directory: home.directory}}
	}
	return reviewWire{Kind: operationName(operation.kind), Evidence: evidence, Unit: operation.demand.unit, User: operation.demand.user, Before: axisStateWire{operation.before.id, operation.before.load, operation.before.value, operation.before.sub}}
}

func operationFromWire(wire reviewWire) (Operation, error) {
	kind, err := parseOperation(wire.Kind)
	if err != nil {
		return Operation{}, err
	}
	evidence, err := evidenceFromWire(wire.Evidence)
	if err != nil {
		return Operation{}, err
	}
	desired := demand{unit: wire.Unit, user: wire.User}
	switch kind {
	case enableOperation:
		desired.persistence = wantOn
	case disableOperation:
		desired.persistence = wantOff
	case startOperation:
		desired.runtime = wantOn
	case stopOperation:
		desired.runtime = wantOff
	}
	operation := Operation{kind: kind, evidence: evidence, demand: desired, before: axisState{wire.Before.ID, wire.Before.Load, wire.Before.Value, wire.Before.Sub}}
	if !operation.valid() {
		return Operation{}, fmt.Errorf("service review operation is invalid")
	}
	if evidence.scope == systemScope && desired.user != "" || evidence.scope == userScope && desired.user != evidence.principal.name {
		return Operation{}, fmt.Errorf("service review principal does not match scope")
	}
	return operation, nil
}

func evidenceFromWire(wire evidenceWire) (selectionEvidence, error) {
	var result selectionEvidence
	scope, err := parseScope(wire.Scope)
	if err != nil {
		return result, err
	}
	if !filepath.IsAbs(wire.Tool.Path) || filepath.Clean(wire.Tool.Path) != wire.Tool.Path {
		return result, fmt.Errorf("invalid reviewed systemctl path")
	}
	digest, err := hex.DecodeString(wire.Tool.SHA256)
	if err != nil || len(digest) != len(result.tool.Digest) || hex.EncodeToString(digest) != wire.Tool.SHA256 {
		return result, fmt.Errorf("invalid reviewed systemctl digest")
	}
	result.scope, result.tool.Path, result.version, result.euid, result.pid1 = scope, wire.Tool.Path, wire.Version, wire.EUID, wire.PID1
	copy(result.tool.Digest[:], digest)
	if scope == systemScope {
		if wire.User != nil {
			return result, fmt.Errorf("system service review contains user evidence")
		}
	}
	if scope == userScope {
		if wire.User == nil {
			return result, fmt.Errorf("user service review lacks user evidence")
		}
		principal, principalErr := NewPrincipal(wire.User.Name, wire.User.UID, wire.User.Home.Path)
		if principalErr != nil {
			return result, principalErr
		}
		home := wire.User.Home
		result.principal = principal
		result.home = homeEvidence{path: home.Path, uid: home.UID, gid: home.GID, mode: home.Mode, device: home.Device, inode: home.Inode, directory: home.Directory}
	}
	if !validSelectionEvidence(result) {
		return result, fmt.Errorf("service review selection evidence is invalid")
	}
	return result, nil
}

func scopeName(value scope) string {
	if value == systemScope {
		return "system"
	}
	if value == userScope {
		return "user"
	}
	return "invalid"
}
func parseScope(value string) (scope, error) {
	switch value {
	case "system":
		return systemScope, nil
	case "user":
		return userScope, nil
	default:
		return 0, fmt.Errorf("invalid service scope %q", value)
	}
}
func operationName(value operationKind) string {
	switch value {
	case enableOperation:
		return "enable"
	case disableOperation:
		return "disable"
	case startOperation:
		return "start"
	case stopOperation:
		return "stop"
	default:
		return "invalid"
	}
}
func parseOperation(value string) (operationKind, error) {
	for kind := enableOperation; kind <= stopOperation; kind++ {
		if operationName(kind) == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("invalid service operation %q", value)
}
func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
