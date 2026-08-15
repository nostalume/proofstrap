package host

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maxReviewBytes = 1 << 20

type Review struct{ operation *Operation }

func (review Review) valid() bool {
	return review.operation != nil && review.operation.valid()
}

func (review Review) Axis() Axis {
	if !review.valid() {
		return 0
	}
	switch review.operation.kind {
	case writeHostnameOperation:
		return HostnamePersistence
	case setHostnameOperation:
		return HostnameRuntime
	case writeTimezoneOperation:
		return TimezonePersistence
	default:
		return 0
	}
}

func EncodeReview(operation Operation) ([]byte, error) {
	if !operation.valid() {
		return nil, fmt.Errorf("valid host operation is required")
	}
	encoded, err := json.Marshal(operationToWire(operation))
	if err != nil {
		return nil, fmt.Errorf("encode host review: %w", err)
	}
	if len(encoded) > maxReviewBytes {
		return nil, fmt.Errorf("host review exceeds %d bytes", maxReviewBytes)
	}
	return encoded, nil
}

func DecodeReview(data []byte) (Review, error) {
	if len(data) == 0 || len(data) > maxReviewBytes {
		return Review{}, fmt.Errorf("host review must contain 1..%d bytes", maxReviewBytes)
	}
	var wire reviewWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Review{}, fmt.Errorf("decode host review: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Review{}, fmt.Errorf("host review contains multiple JSON values")
		}
		return Review{}, fmt.Errorf("decode host review trailing data: %w", err)
	}
	operation, err := operationFromWire(wire)
	if err != nil {
		return Review{}, err
	}
	canonical, _ := EncodeReview(operation)
	if !bytes.Equal(data, canonical) {
		return Review{}, fmt.Errorf("host review is not canonical JSON")
	}
	return Review{operation: &operation}, nil
}

func Reconstruct(review Review, fresh *Selected) (Operation, error) {
	if !review.valid() || !fresh.valid() {
		return Operation{}, fmt.Errorf("valid host review and fresh selection are required")
	}
	if review.operation.evidence != fresh.evidence {
		return Operation{}, fmt.Errorf("%w: host representation evidence changed", ErrStale)
	}
	return *review.operation, nil
}

type reviewWire struct {
	Kind     string        `json:"kind"`
	Evidence evidenceWire  `json:"evidence"`
	Desired  string        `json:"desired"`
	Hostname *hostnameWire `json:"hostname,omitempty"`
	Timezone *timezoneWire `json:"timezone,omitempty"`
	Zone     *zoneWire     `json:"zone,omitempty"`
}

type evidenceWire struct {
	Kind      string         `json:"kind"`
	EUID      uint32         `json:"euid"`
	Etc       directoryWire  `json:"etc"`
	Zoneinfo  *directoryWire `json:"zoneinfo,omitempty"`
	Secondary bool           `json:"secondary_absent,omitempty"`
}

type directoryWire struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type hostnameWire struct {
	File    *hostnameFileWire `json:"file,omitempty"`
	Runtime string            `json:"runtime,omitempty"`
}

type hostnameFileWire struct {
	Present  bool   `json:"present"`
	Regular  bool   `json:"regular,omitempty"`
	Contents string `json:"contents,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	GID      uint32 `json:"gid,omitempty"`
	Device   uint64 `json:"device,omitempty"`
	Inode    uint64 `json:"inode,omitempty"`
}

type timezoneWire struct {
	Present bool      `json:"present"`
	Zone    string    `json:"zone,omitempty"`
	Target  string    `json:"target,omitempty"`
	File    *zoneWire `json:"file,omitempty"`
	Device  uint64    `json:"device,omitempty"`
	Inode   uint64    `json:"inode,omitempty"`
}

type zoneWire struct {
	Regular bool   `json:"regular"`
	TZif    bool   `json:"tzif"`
	Mode    uint32 `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
}

func operationToWire(operation Operation) reviewWire {
	wire := reviewWire{Kind: operationName(operation.kind), Evidence: evidenceToWire(operation.evidence), Desired: operation.desired}
	switch operation.kind {
	case writeHostnameOperation:
		value := hostnameFileToWire(operation.hostnameBefore.persistent)
		wire.Hostname = &hostnameWire{File: &value}
	case setHostnameOperation:
		wire.Hostname = &hostnameWire{Runtime: operation.hostnameBefore.runtime}
	case writeTimezoneOperation:
		value := timezoneToWire(operation.timezoneBefore)
		zone := zoneToWire(operation.zone)
		wire.Timezone, wire.Zone = &value, &zone
	}
	return wire
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
	operation := Operation{kind: kind, desired: wire.Desired, evidence: evidence}
	switch kind {
	case writeHostnameOperation:
		if wire.Hostname == nil || wire.Hostname.File == nil || wire.Hostname.Runtime != "" || wire.Timezone != nil || wire.Zone != nil {
			return Operation{}, fmt.Errorf("persistent hostname review shape is invalid")
		}
		operation.hostnameBefore.persistent = hostnameFileFromWire(*wire.Hostname.File)
	case setHostnameOperation:
		if wire.Hostname == nil || wire.Hostname.File != nil || wire.Hostname.Runtime == "" || wire.Timezone != nil || wire.Zone != nil {
			return Operation{}, fmt.Errorf("runtime hostname review shape is invalid")
		}
		operation.hostnameBefore.runtime = wire.Hostname.Runtime
	case writeTimezoneOperation:
		if wire.Hostname != nil || wire.Timezone == nil || wire.Zone == nil {
			return Operation{}, fmt.Errorf("timezone review shape is invalid")
		}
		operation.timezoneBefore = timezoneFromWire(*wire.Timezone)
		operation.zone = zoneFromWire(*wire.Zone)
	}
	if !operation.valid() {
		return Operation{}, fmt.Errorf("host review operation is invalid")
	}
	return operation, nil
}

func evidenceToWire(value selectionEvidence) evidenceWire {
	wire := evidenceWire{Kind: mechanismName(value.kind), EUID: value.euid, Etc: directoryToWire(value.etc)}
	if value.kind == timezoneMechanism {
		zoneinfo := directoryToWire(value.zoneinfo)
		wire.Zoneinfo, wire.Secondary = &zoneinfo, value.secondaryAbsent
	}
	return wire
}

func evidenceFromWire(wire evidenceWire) (selectionEvidence, error) {
	kind, err := parseMechanism(wire.Kind)
	if err != nil {
		return selectionEvidence{}, err
	}
	value := selectionEvidence{kind: kind, euid: wire.EUID, etc: directoryFromWire(wire.Etc)}
	if kind == hostnameMechanism {
		if wire.Zoneinfo != nil || wire.Secondary {
			return selectionEvidence{}, fmt.Errorf("hostname evidence contains timezone fields")
		}
	}
	if kind == timezoneMechanism {
		if wire.Zoneinfo == nil || !wire.Secondary {
			return selectionEvidence{}, fmt.Errorf("timezone evidence is incomplete")
		}
		value.zoneinfo, value.secondaryAbsent = directoryFromWire(*wire.Zoneinfo), true
	}
	if !validSelectionEvidence(value) {
		return selectionEvidence{}, fmt.Errorf("host selection evidence is invalid")
	}
	return value, nil
}

func directoryToWire(value directoryEvidence) directoryWire {
	return directoryWire{Path: value.path, Mode: value.mode, UID: value.uid, GID: value.gid, Device: value.device, Inode: value.inode}
}

func directoryFromWire(wire directoryWire) directoryEvidence {
	return directoryEvidence{path: wire.Path, directory: true, mode: wire.Mode, uid: wire.UID, gid: wire.GID, device: wire.Device, inode: wire.Inode}
}

func hostnameFileToWire(value hostnameFile) hostnameFileWire {
	return hostnameFileWire{Present: value.present, Regular: value.regular, Contents: value.contents, Mode: value.mode, UID: value.uid, GID: value.gid, Device: value.device, Inode: value.inode}
}

func hostnameFileFromWire(wire hostnameFileWire) hostnameFile {
	return hostnameFile{present: wire.Present, regular: wire.Regular, contents: wire.Contents, mode: wire.Mode, uid: wire.UID, gid: wire.GID, device: wire.Device, inode: wire.Inode}
}

func timezoneToWire(value timezoneObservation) timezoneWire {
	wire := timezoneWire{Present: value.present, Zone: value.zone, Target: value.target, Device: value.device, Inode: value.inode}
	if value.present {
		zone := zoneToWire(value.zoneFile)
		wire.File = &zone
	}
	return wire
}

func timezoneFromWire(wire timezoneWire) timezoneObservation {
	value := timezoneObservation{present: wire.Present, zone: wire.Zone, target: wire.Target, device: wire.Device, inode: wire.Inode}
	if wire.File != nil {
		value.zoneFile = zoneFromWire(*wire.File)
	}
	return value
}

func zoneToWire(value zoneFile) zoneWire {
	return zoneWire{Regular: value.regular, TZif: value.tzif, Mode: value.mode, UID: value.uid, GID: value.gid, Device: value.device, Inode: value.inode}
}

func zoneFromWire(wire zoneWire) zoneFile {
	return zoneFile{regular: wire.Regular, tzif: wire.TZif, mode: wire.Mode, uid: wire.UID, gid: wire.GID, device: wire.Device, inode: wire.Inode}
}

func operationName(value operationKind) string {
	switch value {
	case writeHostnameOperation:
		return "hostname-persistence"
	case setHostnameOperation:
		return "hostname-runtime"
	case writeTimezoneOperation:
		return "timezone-persistence"
	default:
		return "invalid"
	}
}

func parseOperation(value string) (operationKind, error) {
	for kind := writeHostnameOperation; kind <= writeTimezoneOperation; kind++ {
		if operationName(kind) == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("invalid host operation %q", value)
}

func mechanismName(value mechanism) string {
	if value == hostnameMechanism {
		return "hostname"
	}
	if value == timezoneMechanism {
		return "timezone"
	}
	return "invalid"
}

func parseMechanism(value string) (mechanism, error) {
	switch value {
	case "hostname":
		return hostnameMechanism, nil
	case "timezone":
		return timezoneMechanism, nil
	default:
		return 0, fmt.Errorf("invalid host mechanism %q", value)
	}
}
