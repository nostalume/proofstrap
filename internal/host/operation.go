package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/nostalume/proofstrap/internal/model"
)

var (
	ErrUnsupported  = errors.New("host representation is unsupported")
	ErrUnauthorized = errors.New("host representation is unauthorized")
	ErrStale        = errors.New("host operation is stale")
)

type mechanism uint8

const (
	hostnameMechanism mechanism = iota + 1
	timezoneMechanism
)

type directoryEvidence struct {
	path          string
	directory     bool
	mode          uint32
	uid, gid      uint32
	device, inode uint64
}

type selectionEvidence struct {
	kind            mechanism
	euid            uint32
	etc, zoneinfo   directoryEvidence
	secondaryAbsent bool
}

type effects struct {
	observeHostname func() (hostnameObservation, error)
	writeHostname   func(hostnameFile, string) (bool, error)
	setHostname     func(string) (bool, error)
	zone            func(string) (zoneFile, error)
	observeTimezone func() (timezoneObservation, error)
	writeTimezone   func(timezoneObservation, string, zoneFile) (bool, error)
}

type Selected struct {
	evidence selectionEvidence
	effects  effects
}

func (selected *Selected) valid() bool {
	if selected == nil || !validSelectionEvidence(selected.evidence) {
		return false
	}
	switch selected.evidence.kind {
	case hostnameMechanism:
		return selected.effects.observeHostname != nil && selected.effects.writeHostname != nil && selected.effects.setHostname != nil
	case timezoneMechanism:
		return selected.effects.zone != nil && selected.effects.observeTimezone != nil && selected.effects.writeTimezone != nil
	default:
		return false
	}
}

func validSelectionEvidence(value selectionEvidence) bool {
	if value.euid != 0 || !validDirectory(value.etc, "/etc") {
		return false
	}
	switch value.kind {
	case hostnameMechanism:
		return value.zoneinfo == (directoryEvidence{}) && !value.secondaryAbsent
	case timezoneMechanism:
		return validDirectory(value.zoneinfo, "/usr/share/zoneinfo") && value.secondaryAbsent
	default:
		return false
	}
}

func validDirectory(value directoryEvidence, path string) bool {
	return value.path == path && filepath.IsAbs(value.path) && value.directory && value.uid == 0 && value.gid == 0 && value.mode&0o022 == 0 && value.device != 0 && value.inode != 0
}

func (selected *Selected) PlanHostname(ctx context.Context, desired model.Hostname) (Plan, error) {
	if !selected.valid() || selected.evidence.kind != hostnameMechanism || !desired.Valid() || !futureContext(ctx) {
		return Plan{}, fmt.Errorf("valid hostname selection, desired value, and bounded context are required")
	}
	before, err := selected.effects.observeHostname()
	if err != nil {
		return hostnameBlockedPlan(err.Error()), nil
	}
	plan := reconcileHostname(desired.Value(), before)
	sealOperations(&plan, selected.evidence)
	return plan, nil
}

func (selected *Selected) PlanTimezone(ctx context.Context, desired model.Timezone) (Plan, error) {
	if !selected.valid() || selected.evidence.kind != timezoneMechanism || !desired.Valid() || !futureContext(ctx) {
		return Plan{}, fmt.Errorf("valid timezone selection, desired value, and bounded context are required")
	}
	zone, err := selected.effects.zone(desired.Value())
	if err != nil {
		plan := Plan{}
		plan.set(TimezonePersistence, Decision{kind: Blocked, detail: err.Error()})
		return plan, nil
	}
	before, err := selected.effects.observeTimezone()
	if err != nil {
		plan := Plan{}
		plan.set(TimezonePersistence, Decision{kind: Blocked, detail: err.Error()})
		return plan, nil
	}
	plan := reconcileTimezone(desired.Value(), zone, before)
	sealOperations(&plan, selected.evidence)
	return plan, nil
}

func hostnameBlockedPlan(detail string) Plan {
	plan := Plan{}
	plan.set(HostnamePersistence, Decision{kind: Blocked, detail: detail})
	plan.set(HostnameRuntime, Decision{kind: Blocked, detail: detail})
	return plan
}

func sealOperations(plan *Plan, evidence selectionEvidence) {
	for index := range plan.operations {
		plan.operations[index].evidence = evidence
	}
}

type ApplyResult struct {
	started  bool
	decision Decision
}

func (result ApplyResult) Started() bool      { return result.started }
func (result ApplyResult) Decision() Decision { return result.decision }

func (operation Operation) valid() bool {
	if !validSelectionEvidence(operation.evidence) || operation.desired == "" {
		return false
	}
	switch operation.kind {
	case writeHostnameOperation:
		return operation.evidence.kind == hostnameMechanism && validHostname(operation.desired) && validHostnameFile(operation.hostnameBefore.persistent) && operation.hostnameBefore.runtime == "" && operation.hostnameBefore.runtimeBlocked == ""
	case setHostnameOperation:
		return operation.evidence.kind == hostnameMechanism && validHostname(operation.desired) && validHostname(operation.hostnameBefore.runtime) && operation.hostnameBefore.persistent == (hostnameFile{}) && operation.hostnameBefore.runtimeBlocked == ""
	case writeTimezoneOperation:
		return operation.evidence.kind == timezoneMechanism && validTimezone(operation.desired) && validZoneFile(operation.zone) && validTimezoneBefore(operation.timezoneBefore)
	default:
		return false
	}
}

func validHostnameFile(value hostnameFile) bool {
	if !value.present {
		return value == (hostnameFile{})
	}
	if !value.regular || value.blocked != "" || value.uid != 0 || value.gid != 0 || value.mode&0o022 != 0 || value.device == 0 || value.inode == 0 {
		return false
	}
	return len(value.contents) >= 2 && strings.HasSuffix(value.contents, "\n") && !strings.ContainsAny(strings.TrimSuffix(value.contents, "\n"), "\r\n") && validHostname(strings.TrimSuffix(value.contents, "\n"))
}

func validZoneFile(value zoneFile) bool {
	return value.regular && value.tzif && value.blocked == "" && value.uid == 0 && value.gid == 0 && value.mode&0o022 == 0 && value.device != 0 && value.inode != 0
}

func validTimezoneBefore(value timezoneObservation) bool {
	if !value.present {
		return value == (timezoneObservation{})
	}
	zone, ok := timezoneTarget(value.target)
	return value.blocked == "" && value.device != 0 && value.inode != 0 && ok && zone == value.zone && validTimezone(value.zone) && validZoneFile(value.zoneFile)
}

func (operation Operation) Apply(effectCtx context.Context, freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	if !operation.valid() || !fresh.valid() || !futureContext(effectCtx) || freshPost == nil {
		return ApplyResult{}, fmt.Errorf("valid host operation, fresh selection, bounded effect context, and fresh post-observation context are required")
	}
	if operation.evidence != fresh.evidence {
		return ApplyResult{}, fmt.Errorf("%w: host representation evidence changed", ErrStale)
	}
	switch operation.kind {
	case writeHostnameOperation:
		return operation.applyHostnameFile(freshPost, fresh)
	case setHostnameOperation:
		return operation.applyHostnameRuntime(freshPost, fresh)
	case writeTimezoneOperation:
		return operation.applyTimezone(freshPost, fresh)
	default:
		return ApplyResult{}, fmt.Errorf("unknown host operation")
	}
}

func (operation Operation) applyHostnameFile(freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	current, err := fresh.effects.observeHostname()
	if err != nil {
		return ApplyResult{}, err
	}
	if current.persistent != operation.hostnameBefore.persistent {
		return ApplyResult{}, fmt.Errorf("%w: persistent hostname changed", ErrStale)
	}
	started, effectErr := fresh.effects.writeHostname(current.persistent, operation.desired)
	return operation.finishHostname(freshPost, fresh, HostnamePersistence, started, effectErr)
}

func (operation Operation) applyHostnameRuntime(freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	current, err := fresh.effects.observeHostname()
	if err != nil {
		return ApplyResult{}, err
	}
	if current.runtime != operation.hostnameBefore.runtime || current.runtimeBlocked != operation.hostnameBefore.runtimeBlocked {
		return ApplyResult{}, fmt.Errorf("%w: runtime hostname changed", ErrStale)
	}
	started, effectErr := fresh.effects.setHostname(operation.desired)
	return operation.finishHostname(freshPost, fresh, HostnameRuntime, started, effectErr)
}

func (operation Operation) finishHostname(freshPost func() (context.Context, context.CancelFunc), fresh *Selected, axis Axis, started bool, effectErr error) (ApplyResult, error) {
	if !started && effectErr == nil {
		return ApplyResult{}, fmt.Errorf("host effect reported success without starting mutation")
	}
	postCtx, cancelPost := freshPost()
	if cancelPost == nil || !futureContext(postCtx) {
		if cancelPost != nil {
			cancelPost()
		}
		return ApplyResult{started: started}, errors.Join(effectErr, fmt.Errorf("fresh bounded host post-observation context is required"))
	}
	defer cancelPost()
	post, postErr := fresh.effects.observeHostname()
	result := ApplyResult{started: started}
	if postErr == nil {
		plan := reconcileHostname(operation.desired, post)
		result.decision, _ = plan.Decision(axis)
	}
	if result.decision.kind == Exact && effectErr == nil {
		return result, nil
	}
	return result, errors.Join(effectErr, postErr, fmt.Errorf("host postcondition is not exact"))
}

func (operation Operation) applyTimezone(freshPost func() (context.Context, context.CancelFunc), fresh *Selected) (ApplyResult, error) {
	current, err := fresh.effects.observeTimezone()
	if err != nil {
		return ApplyResult{}, err
	}
	if current != operation.timezoneBefore {
		return ApplyResult{}, fmt.Errorf("%w: timezone representation changed", ErrStale)
	}
	started, effectErr := fresh.effects.writeTimezone(current, operation.desired, operation.zone)
	if !started && effectErr == nil {
		return ApplyResult{}, fmt.Errorf("timezone effect reported success without starting mutation")
	}
	postCtx, cancelPost := freshPost()
	if cancelPost == nil || !futureContext(postCtx) {
		if cancelPost != nil {
			cancelPost()
		}
		return ApplyResult{started: started}, errors.Join(effectErr, fmt.Errorf("fresh bounded host post-observation context is required"))
	}
	defer cancelPost()
	post, postErr := fresh.effects.observeTimezone()
	result := ApplyResult{started: started}
	if postErr == nil {
		plan := reconcileTimezone(operation.desired, operation.zone, post)
		result.decision, _ = plan.Decision(TimezonePersistence)
	}
	if result.decision.kind == Exact && effectErr == nil {
		return result, nil
	}
	return result, errors.Join(effectErr, postErr, fmt.Errorf("timezone postcondition is not exact"))
}

func futureContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) > 0
}

func validHostname(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validTimezone(value string) bool {
	if value == "" || len(value) > 4095 || strings.HasPrefix(value, "/") || filepath.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return false
		}
		for _, character := range component {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '+' && character != '-' {
				return false
			}
		}
	}
	return true
}
