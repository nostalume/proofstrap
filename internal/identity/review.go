package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/linuxexec"
)

const maxReviewBytes = 1 << 20

type Review struct{ operation *Operation }

func (review Review) valid() bool {
	return review.operation != nil && validOperation(*review.operation)
}

func (review Review) Capabilities() []Capability {
	if !review.valid() {
		return nil
	}
	return append([]Capability(nil), review.operation.evidence.capabilities...)
}

func EncodeReview(operation Operation) ([]byte, error) {
	if !validOperation(operation) {
		return nil, fmt.Errorf("valid identity operation is required")
	}
	wire, err := operationToWire(operation)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode identity review: %w", err)
	}
	if len(encoded) > maxReviewBytes {
		return nil, fmt.Errorf("identity review exceeds %d bytes", maxReviewBytes)
	}
	return encoded, nil
}

func DecodeReview(data []byte) (Review, error) {
	if len(data) == 0 || len(data) > maxReviewBytes {
		return Review{}, fmt.Errorf("identity review must contain 1..%d bytes", maxReviewBytes)
	}
	var wire reviewWire
	if err := decodeStrict(data, &wire); err != nil {
		return Review{}, fmt.Errorf("decode identity review: %w", err)
	}
	operation, err := operationFromWire(wire)
	if err != nil {
		return Review{}, err
	}
	canonical, _ := EncodeReview(operation)
	if !bytes.Equal(data, canonical) {
		return Review{}, fmt.Errorf("identity review is not canonical JSON")
	}
	return Review{operation: &operation}, nil
}

func Reconstruct(review Review, fresh *Selected) (Operation, error) {
	if !review.valid() || !fresh.valid() {
		return Operation{}, fmt.Errorf("valid identity review and fresh selection are required")
	}
	if !sameSelectionEvidence(review.operation.evidence, fresh.evidence) {
		return Operation{}, fmt.Errorf("%w: shadow evidence changed", ErrStale)
	}
	return *review.operation, nil
}

type reviewWire struct {
	Kind         string          `json:"kind"`
	Capabilities []string        `json:"capabilities"`
	Tools        []toolWire      `json:"tools"`
	RootGroup    groupRecordWire `json:"root_group"`
	RootAccount  passwdWire      `json:"root_account"`
	Payload      json.RawMessage `json:"payload"`
}

type toolWire struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type groupIntentWire struct {
	Name    string `json:"name"`
	GID     uint32 `json:"gid"`
	Managed bool   `json:"managed"`
}
type accountIntentWire struct {
	Name         string `json:"name"`
	UID          uint32 `json:"uid"`
	PrimaryGroup string `json:"primary_group"`
	Home         string `json:"home"`
	Managed      bool   `json:"managed"`
}
type groupRecordWire struct {
	Name    string   `json:"name"`
	GID     uint32   `json:"gid"`
	Members []string `json:"members"`
}
type passwdWire struct {
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Gecos string `json:"gecos"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}
type groupLookupWire struct {
	State  string          `json:"state"`
	Record groupRecordWire `json:"record"`
	Detail string          `json:"detail"`
}
type accountLookupWire struct {
	State  string     `json:"state"`
	Record passwdWire `json:"record"`
	Detail string     `json:"detail"`
}
type groupObservationWire struct {
	NameGlobal   groupLookupWire `json:"name_global"`
	NameLocal    groupLookupWire `json:"name_local"`
	NumberGlobal groupLookupWire `json:"number_global"`
	NumberLocal  groupLookupWire `json:"number_local"`
}
type accountObservationWire struct {
	NameGlobal   accountLookupWire `json:"name_global"`
	NameLocal    accountLookupWire `json:"name_local"`
	NumberGlobal accountLookupWire `json:"number_global"`
	NumberLocal  accountLookupWire `json:"number_local"`
}
type homeIntentWire struct {
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}
type homeStateWire struct {
	Exists    bool   `json:"exists"`
	Trusted   bool   `json:"trusted"`
	Directory bool   `json:"directory"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mode      uint16 `json:"mode"`
}

type groupPayload struct {
	Desired groupIntentWire      `json:"desired"`
	Before  groupObservationWire `json:"before"`
}
type accountPayload struct {
	Desired accountIntentWire      `json:"desired"`
	Primary groupIntentWire        `json:"primary"`
	Before  accountObservationWire `json:"before"`
}
type lockPayload struct {
	Account string `json:"account"`
	Before  bool   `json:"before"`
}
type shellPayload struct {
	Account string     `json:"account"`
	Shell   string     `json:"shell"`
	Before  passwdWire `json:"before"`
}
type membershipPayload struct {
	Account string          `json:"account"`
	Group   string          `json:"group"`
	Present bool            `json:"present"`
	Before  groupRecordWire `json:"before"`
}
type homePayload struct {
	Account string         `json:"account"`
	Intent  homeIntentWire `json:"intent"`
	Before  homeStateWire  `json:"before"`
}
type homeModePayload struct {
	Account string         `json:"account"`
	Intent  homeIntentWire `json:"intent"`
	Mode    uint16         `json:"mode"`
	Before  homeStateWire  `json:"before"`
}

func operationToWire(operation Operation) (reviewWire, error) {
	payload, err := encodePayload(operation)
	if err != nil {
		return reviewWire{}, err
	}
	wire := reviewWire{Kind: kindName(operation.kind), RootGroup: groupRecordToWire(operation.evidence.rootGroup), RootAccount: passwdToWire(operation.evidence.rootAccount), Payload: payload}
	for _, capability := range operation.evidence.capabilities {
		wire.Capabilities = append(wire.Capabilities, capabilityName(capability))
	}
	for _, tool := range operation.evidence.tools {
		wire.Tools = append(wire.Tools, toolWire{Name: tool.name, Path: tool.identity.Path, SHA256: hex.EncodeToString(tool.identity.Digest[:])})
	}
	return wire, nil
}

func encodePayload(operation Operation) (json.RawMessage, error) {
	var value any
	switch operation.kind {
	case createGroupOperation:
		value = groupPayload{groupIntentToWire(operation.group), groupObservationToWire(operation.groupBefore)}
	case createAccountOperation:
		value = accountPayload{accountIntentToWire(operation.account), groupIntentToWire(operation.primary), accountObservationToWire(operation.accountBefore)}
	case lockAccountOperation:
		value = lockPayload{operation.lockAccount, operation.lockBefore}
	case setShellOperation:
		value = shellPayload{operation.shellAccount, operation.shellValue, passwdToWire(operation.shellBefore)}
	case setMembershipOperation:
		value = membershipPayload{operation.membershipAccount, operation.membershipGroup, operation.membershipPresent, groupRecordToWire(operation.membershipBefore)}
	case createHomeOperation:
		value = homePayload{operation.account.name, homeIntentToWire(operation.homeIntent), homeStateToWire(operation.homeBefore)}
	case setHomeModeOperation:
		value = homeModePayload{operation.account.name, homeIntentToWire(operation.homeIntent), operation.homeMode, homeStateToWire(operation.homeBefore)}
	default:
		return nil, fmt.Errorf("invalid identity operation kind")
	}
	return json.Marshal(value)
}

func operationFromWire(wire reviewWire) (Operation, error) {
	kind, err := parseKind(wire.Kind)
	if err != nil {
		return Operation{}, err
	}
	evidence, err := evidenceFromWire(wire)
	if err != nil {
		return Operation{}, err
	}
	operation := Operation{kind: kind, evidence: evidence}
	switch kind {
	case createGroupOperation:
		var value groupPayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.group, operation.groupBefore = groupIntentFromWire(value.Desired), groupObservationFromWire(value.Before)
	case createAccountOperation:
		var value accountPayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.account, operation.primary, operation.accountBefore = accountIntentFromWire(value.Desired), groupIntentFromWire(value.Primary), accountObservationFromWire(value.Before)
	case lockAccountOperation:
		var value lockPayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.lockAccount, operation.lockBefore = value.Account, value.Before
	case setShellOperation:
		var value shellPayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.shellAccount, operation.shellValue, operation.shellBefore = value.Account, value.Shell, passwdFromWire(value.Before)
	case setMembershipOperation:
		var value membershipPayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.membershipAccount, operation.membershipGroup, operation.membershipPresent, operation.membershipBefore = value.Account, value.Group, value.Present, groupRecordFromWire(value.Before)
	case createHomeOperation:
		var value homePayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.account, operation.homeIntent, operation.homeBefore = accountIntent{name: value.Account}, homeIntentFromWire(value.Intent), homeStateFromWire(value.Before)
	case setHomeModeOperation:
		var value homeModePayload
		if err := decodeStrict(wire.Payload, &value); err != nil {
			return Operation{}, err
		}
		operation.account, operation.homeIntent, operation.homeMode, operation.homeBefore = accountIntent{name: value.Account}, homeIntentFromWire(value.Intent), value.Mode, homeStateFromWire(value.Before)
	}
	if !validOperation(operation) {
		return Operation{}, fmt.Errorf("identity review operation is invalid")
	}
	return operation, nil
}

func evidenceFromWire(wire reviewWire) (selectionEvidence, error) {
	var result selectionEvidence
	for _, name := range wire.Capabilities {
		capability, err := parseCapability(name)
		if err != nil {
			return result, err
		}
		result.capabilities = append(result.capabilities, capability)
	}
	for _, value := range wire.Tools {
		if !validText(value.Name) || !filepath.IsAbs(value.Path) || filepath.Clean(value.Path) != value.Path {
			return result, fmt.Errorf("invalid identity review tool")
		}
		digest, err := hex.DecodeString(value.SHA256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != value.SHA256 {
			return result, fmt.Errorf("invalid identity review tool digest")
		}
		identity := linuxexec.Identity{Path: value.Path}
		copy(identity.Digest[:], digest)
		result.tools = append(result.tools, toolEvidence{name: value.Name, identity: identity})
	}
	result.rootGroup, result.rootAccount = groupRecordFromWire(wire.RootGroup), passwdFromWire(wire.RootAccount)
	if !validEvidence(result) {
		return result, fmt.Errorf("invalid identity selection evidence")
	}
	return result, nil
}

func validEvidence(value selectionEvidence) bool {
	if len(value.capabilities) == 0 || value.capabilities[0] != ObserveIdentity || !slices.IsSorted(value.capabilities) || len(value.tools) != len(value.capabilities) || value.rootGroup.gid != 0 || value.rootAccount.uid != 0 {
		return false
	}
	expected := map[Capability]string{ObserveIdentity: "getent", CreateGroup: "groupadd", CreateAccount: "useradd", ObserveLock: "passwd", ModifyAccount: "usermod", ModifyMembership: "gpasswd"}
	for index, capability := range value.capabilities {
		name, known := expected[capability]
		tool := value.tools[index]
		if !known || index > 0 && value.capabilities[index-1] == capability || name != tool.name || !filepath.IsAbs(tool.identity.Path) || filepath.Clean(tool.identity.Path) != tool.identity.Path {
			return false
		}
	}
	return validGroupRecord(value.rootGroup) && validPasswd(value.rootAccount)
}

func validOperation(value Operation) bool {
	if !validEvidence(value.evidence) {
		return false
	}
	switch value.kind {
	case createGroupOperation:
		return admitted(value.evidence, CreateGroup) && validText(value.group.name) && value.group.managed && value.group.gid != 0 && reconcileGroupIntent(value.group, value.groupBefore).kind == Change
	case createAccountOperation:
		return admitted(value.evidence, CreateAccount) && admitted(value.evidence, ObserveLock) && validText(value.account.name) && value.account.managed && value.account.uid != 0 && validText(value.account.home) && validText(value.primary.name) && value.primary.managed && value.primary.gid != 0 && reconcileAccountIntent(value.account, value.primary, value.accountBefore).kind == Change
	case lockAccountOperation:
		return admitted(value.evidence, ObserveLock) && validText(value.lockAccount) && !value.lockBefore
	case setShellOperation:
		return admitted(value.evidence, ModifyAccount) && validText(value.shellAccount) && validText(value.shellValue) && validPasswd(value.shellBefore) && value.shellBefore.name == value.shellAccount && value.shellBefore.shell != value.shellValue
	case setMembershipOperation:
		return admitted(value.evidence, ModifyMembership) && validText(value.membershipAccount) && validText(value.membershipGroup) && validGroupRecord(value.membershipBefore) && value.membershipBefore.name == value.membershipGroup && slices.Contains(value.membershipBefore.members, value.membershipAccount) != value.membershipPresent
	case createHomeOperation:
		return validText(value.account.name) && validHome(value.homeIntent) && reconcileHome(value.homeIntent, value.homeBefore).kind == Change
	case setHomeModeOperation:
		return validText(value.account.name) && validHome(value.homeIntent) && value.homeMode <= 0o777 && reconcileHome(value.homeIntent, value.homeBefore).kind == Exact && value.homeBefore.mode != value.homeMode
	default:
		return false
	}
}

func admitted(evidence selectionEvidence, capability Capability) bool {
	return slices.Contains(evidence.capabilities, capability)
}

func validGroupRecord(value groupRecord) bool {
	return validText(value.name) && slices.IsSorted(value.members) && !hasDuplicates(value.members)
}

func validPasswd(value passwdRecord) bool {
	return validText(value.name) && validText(value.home) && validText(value.shell)
}

func hasDuplicates(values []string) bool {
	for index, value := range values {
		if !validText(value) || index > 0 && values[index-1] == value {
			return true
		}
	}
	return false
}

func validHome(value homeIntent) bool {
	return filepath.IsAbs(value.path) && filepath.Clean(value.path) == value.path && value.path != "/" && value.uid != 0 && value.gid != 0
}
func validText(value string) bool {
	return value != "" && len(value) <= 4095 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
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

func kindName(value operationKind) string {
	return [...]string{"", "group-create", "account-create", "account-lock", "shell-set", "membership-set", "home-create", "home-mode-set"}[value]
}
func parseKind(value string) (operationKind, error) {
	for kind := createGroupOperation; kind <= setHomeModeOperation; kind++ {
		if kindName(kind) == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("invalid identity operation kind %q", value)
}
func capabilityName(value Capability) string {
	return [...]string{"", "observe-identity", "create-group", "create-account", "observe-lock", "modify-account", "modify-membership"}[value]
}
func parseCapability(value string) (Capability, error) {
	for capability := ObserveIdentity; capability <= ModifyMembership; capability++ {
		if capabilityName(capability) == value {
			return capability, nil
		}
	}
	return 0, fmt.Errorf("invalid identity capability %q", value)
}

func groupIntentToWire(v groupIntent) groupIntentWire {
	return groupIntentWire{v.name, v.gid, v.managed}
}
func groupIntentFromWire(v groupIntentWire) groupIntent { return groupIntent{v.Name, v.Managed, v.GID} }
func accountIntentToWire(v accountIntent) accountIntentWire {
	return accountIntentWire{v.name, v.uid, v.primaryGroup, v.home, v.managed}
}
func accountIntentFromWire(v accountIntentWire) accountIntent {
	return accountIntent{v.Name, v.PrimaryGroup, v.Home, v.UID, v.Managed}
}
func groupRecordToWire(v groupRecord) groupRecordWire {
	return groupRecordWire{v.name, v.gid, append([]string(nil), v.members...)}
}
func groupRecordFromWire(v groupRecordWire) groupRecord {
	return groupRecord{v.Name, v.GID, append([]string(nil), v.Members...)}
}
func passwdToWire(v passwdRecord) passwdWire {
	return passwdWire{v.name, v.uid, v.gid, v.gecos, v.home, v.shell}
}
func passwdFromWire(v passwdWire) passwdRecord {
	return passwdRecord{v.Name, v.Gecos, v.Home, v.Shell, v.UID, v.GID}
}
func lookupName(v lookupState) string { return [...]string{"", "missing", "found", "failed"}[v] }
func parseLookup(v string) lookupState {
	for state := lookupMissing; state <= lookupFailed; state++ {
		if lookupName(state) == v {
			return state
		}
	}
	return 0
}
func groupLookupToWire(v groupLookup) groupLookupWire {
	return groupLookupWire{lookupName(v.state), groupRecordToWire(v.record), v.detail}
}
func groupLookupFromWire(v groupLookupWire) groupLookup {
	return groupLookup{parseLookup(v.State), groupRecordFromWire(v.Record), v.Detail}
}
func accountLookupToWire(v accountLookup) accountLookupWire {
	return accountLookupWire{lookupName(v.state), passwdToWire(v.record), v.detail}
}
func accountLookupFromWire(v accountLookupWire) accountLookup {
	return accountLookup{parseLookup(v.State), passwdFromWire(v.Record), v.Detail}
}
func groupObservationToWire(v groupObservation) groupObservationWire {
	return groupObservationWire{groupLookupToWire(v.nameGlobal), groupLookupToWire(v.nameLocal), groupLookupToWire(v.numberGlobal), groupLookupToWire(v.numberLocal)}
}
func groupObservationFromWire(v groupObservationWire) groupObservation {
	return groupObservation{groupLookupFromWire(v.NameGlobal), groupLookupFromWire(v.NameLocal), groupLookupFromWire(v.NumberGlobal), groupLookupFromWire(v.NumberLocal)}
}
func accountObservationToWire(v accountObservation) accountObservationWire {
	return accountObservationWire{accountLookupToWire(v.nameGlobal), accountLookupToWire(v.nameLocal), accountLookupToWire(v.numberGlobal), accountLookupToWire(v.numberLocal)}
}
func accountObservationFromWire(v accountObservationWire) accountObservation {
	return accountObservation{accountLookupFromWire(v.NameGlobal), accountLookupFromWire(v.NameLocal), accountLookupFromWire(v.NumberGlobal), accountLookupFromWire(v.NumberLocal)}
}
func homeIntentToWire(v homeIntent) homeIntentWire   { return homeIntentWire{v.path, v.uid, v.gid} }
func homeIntentFromWire(v homeIntentWire) homeIntent { return homeIntent{v.Path, v.UID, v.GID} }
func homeStateToWire(v homeState) homeStateWire {
	return homeStateWire{v.exists, v.trusted, v.directory, v.uid, v.gid, v.mode}
}
func homeStateFromWire(v homeStateWire) homeState {
	return homeState{v.Exists, v.Trusted, v.Directory, v.UID, v.GID, v.Mode}
}
