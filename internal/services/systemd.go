package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
)

const (
	maxObservationUnits   = 128
	maxObservationBytes   = 1 << 20
	maxObservationDemands = 32768
)

var (
	ErrUnsupported   = errors.New("service control plane is unsupported")
	ErrIndeterminate = errors.New("service control plane is indeterminate")
	ErrUnauthorized  = errors.New("service control plane is unauthorized")
	ErrAmbiguous     = errors.New("service control plane is ambiguous")
	ErrStale         = errors.New("service operation is stale")
)

type scope uint8

const (
	systemScope scope = iota + 1
	userScope
)

type Principal struct {
	name, home string
	uid        uint32
	admitted   bool
}

func NewPrincipal(name string, uid uint32, home string) (Principal, error) {
	if !validText(name, 255) || uid == 0 || !validAbsolutePath(home) {
		return Principal{}, fmt.Errorf("valid non-root principal name, UID, and home are required")
	}
	return Principal{name: name, uid: uid, home: home, admitted: true}, nil
}

func ManagedPrincipal(account model.Account) (Principal, error) {
	if !account.Valid() || !account.Managed() {
		return Principal{}, fmt.Errorf("managed account projection is required")
	}
	return NewPrincipal(account.Name(), account.UID(), account.Home())
}

func (principal Principal) valid() bool { return principal.admitted }

type homeEvidence struct {
	path      string
	uid, gid  uint32
	mode      uint16
	device    uint64
	inode     uint64
	directory bool
}

type selectionEvidence struct {
	scope     scope
	backend   string
	tool      linux.Identity
	status    linux.Identity
	update    linux.Identity
	version   string
	euid      uint32
	pid1      string
	control   string
	principal Principal
	home      homeEvidence
}

type Selected struct {
	evidence selectionEvidence
	effects  systemEffects
	openrc   openRCEffects
}

func SelectSystem(ctx context.Context) (*Selected, error) {
	return selectSystem(ctx, productionEffects())
}

func SelectUser(ctx context.Context, principal Principal) (*Selected, error) {
	return selectUser(ctx, productionEffects(), principal)
}

func SelectSystemBackend(ctx context.Context, backend string) (*Selected, error) {
	switch backend {
	case "systemd":
		return SelectSystem(ctx)
	case "openrc":
		return SelectOpenRCSystem(ctx)
	default:
		return nil, fmt.Errorf("%w: service backend %q", ErrUnsupported, backend)
	}
}

func SelectUserBackend(ctx context.Context, backend string, principal Principal) (*Selected, error) {
	if backend != "systemd" {
		return nil, fmt.Errorf("%w: service backend %q has no user control plane", ErrUnsupported, backend)
	}
	return SelectUser(ctx, principal)
}

func SelectHostSystem(ctx context.Context) (*Selected, error) {
	return selectHostSystem(ctx, SelectOpenRCSystem, SelectSystem)
}

func selectHostSystem(ctx context.Context, selectors ...func(context.Context) (*Selected, error)) (*Selected, error) {
	var selected []*Selected
	var failures []error
	for _, selectBackend := range selectors {
		candidate, err := selectBackend(ctx)
		if err == nil {
			selected = append(selected, candidate)
		} else {
			failures = append(failures, err)
		}
	}
	if len(selected) == 1 {
		return selected[0], nil
	}
	if len(selected) > 1 {
		return nil, fmt.Errorf("%w: multiple service control planes are usable", ErrAmbiguous)
	}
	return nil, errors.Join(append([]error{ErrUnsupported}, failures...)...)
}

func (selected *Selected) Backend() string {
	if !selected.valid() {
		return ""
	}
	return selected.evidence.backend
}

func selectSystem(ctx context.Context, effects systemEffects) (*Selected, error) {
	base, err := selectBase(ctx, effects)
	if err != nil {
		return nil, err
	}
	base.evidence.scope = systemScope
	version, err := probeManager(ctx, effects, base.evidence.tool, nil)
	if err != nil {
		return nil, err
	}
	base.evidence.version = version
	return base, nil
}

func selectUser(ctx context.Context, effects systemEffects, principal Principal) (*Selected, error) {
	if !principal.valid() {
		return nil, fmt.Errorf("valid exact user principal is required")
	}
	base, err := selectBase(ctx, effects)
	if err != nil {
		return nil, err
	}
	home, err := effects.home(principal.home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: principal home is absent", ErrUnsupported)
		}
		return nil, fmt.Errorf("%w: inspect principal home: %v", ErrIndeterminate, err)
	}
	if !home.directory || home.path != principal.home || home.uid != principal.uid {
		return nil, fmt.Errorf("%w: principal home identity differs", ErrUnsupported)
	}
	base.evidence.scope, base.evidence.principal, base.evidence.home = userScope, principal, home
	prefix := []string{"--user", "--machine=" + strconv.FormatUint(uint64(principal.uid), 10) + "@.host"}
	version, err := probeManager(ctx, effects, base.evidence.tool, prefix)
	if err != nil {
		return nil, err
	}
	base.evidence.version = version
	return base, nil
}

func selectBase(ctx context.Context, effects systemEffects) (*Selected, error) {
	if !linux.FutureContext(ctx) || effects.identify == nil || effects.run == nil || effects.euid == nil || effects.pid1 == nil || effects.home == nil {
		return nil, fmt.Errorf("bounded context and complete system effects are required")
	}
	euid, err := admitRoot(effects.euid)
	if err != nil {
		return nil, err
	}
	pid1, err := effects.pid1()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect PID 1: %v", ErrIndeterminate, err)
	}
	if pid1 != "systemd" {
		return nil, fmt.Errorf("%w: PID 1 is %q", ErrUnsupported, pid1)
	}
	tool, err := identifyUnique(effects, "systemctl", []string{"/usr/bin/systemctl", "/bin/systemctl"})
	if err != nil {
		return nil, err
	}
	return &Selected{evidence: selectionEvidence{backend: "systemd", tool: tool, euid: euid, pid1: pid1}, effects: effects}, nil
}

func probeManager(ctx context.Context, effects systemEffects, tool linux.Identity, prefix []string) (string, error) {
	args := append(append([]string(nil), prefix...), "show", "--property=Version", "--value")
	result, err := effects.run(ctx, tool, args, nil)
	if err != nil || !result.Started {
		return "", fmt.Errorf("%w: %v", ErrIndeterminate, commandFailure("manager probe", result, err))
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("%w: manager endpoint is unreachable", ErrUnsupported)
	}
	version := strings.TrimSuffix(string(result.Stdout), "\n")
	if len(result.Stderr) != 0 || !validText(version, 255) || strings.Contains(version, "\n") {
		return "", fmt.Errorf("%w: malformed manager version", ErrIndeterminate)
	}
	return version, nil
}

func (selected *Selected) valid() bool {
	if selected == nil || selected.effects.identify == nil || selected.effects.run == nil || selected.effects.euid == nil || !validSelectionEvidence(selected.evidence) {
		return false
	}
	if selected.evidence.backend == "openrc" {
		return selected.openrc.inspect != nil && selected.openrc.control != nil
	}
	return selected.effects.pid1 != nil && selected.effects.home != nil
}

type Demand struct {
	backend string
	value   demand
}

func (value Demand) valid() bool {
	return (value.backend == "systemd" || value.backend == "openrc") && validDemand(value.value) && (value.backend == "systemd" || value.value.user == "")
}

func NewDemand(id binding.ServiceID, target model.ServiceTarget, enable model.EnableIntent, run model.RunIntent) (Demand, error) {
	backend := id.Backend().String()
	if (backend != "systemd" && backend != "openrc") || !validUnit(id.Name()) || target == nil {
		return Demand{}, fmt.Errorf("supported exact service identity and typed target are required")
	}
	value := demand{unit: id.Name(), persistence: enableIntent(enable), runtime: runIntent(run)}
	if user, ok := model.ServiceTargetUser(target); ok {
		if backend == "openrc" {
			return Demand{}, fmt.Errorf("OpenRC user services are unsupported")
		}
		value.user = user
	}
	if !validDemand(value) {
		return Demand{}, fmt.Errorf("service demand is invalid")
	}
	return Demand{backend: backend, value: value}, nil
}

func DemandOf(node binding.Node) (Demand, error) {
	if node == nil {
		return Demand{}, fmt.Errorf("service binding node is required")
	}
	id, ok := binding.ServiceIDOf(node)
	service, serviceOK := model.ServiceOf(node.Semantic())
	backend := id.Backend().String()
	if !ok || !serviceOK || (backend != "systemd" && backend != "openrc") || !validUnit(id.Name()) {
		return Demand{}, fmt.Errorf("supported exact service binding is required")
	}
	desired := demand{unit: id.Name(), persistence: enableIntent(service.Enable()), runtime: runIntent(service.Run())}
	if user, ok := service.User(); ok {
		if backend == "openrc" {
			return Demand{}, fmt.Errorf("OpenRC user services are unsupported")
		}
		desired.user = user
	}
	if !validDemand(desired) {
		return Demand{}, fmt.Errorf("service demand is invalid")
	}
	return Demand{backend: backend, value: desired}, nil
}

func enableIntent(value model.EnableIntent) intent {
	switch value {
	case model.EnabledIntent():
		return wantOn
	case model.DisabledIntent():
		return wantOff
	default:
		return unmanaged
	}
}

func runIntent(value model.RunIntent) intent {
	switch value {
	case model.RunningIntent():
		return wantOn
	case model.StoppedIntent():
		return wantOff
	default:
		return unmanaged
	}
}

func validDemand(value demand) bool {
	return validUnit(value.unit) && (value.persistence >= unmanaged && value.persistence <= wantOff) && (value.runtime >= unmanaged && value.runtime <= wantOff) && (value.persistence != unmanaged || value.runtime != unmanaged) && (value.user == "" || validText(value.user, 255))
}

type observationState struct{ records map[string]unitRecord }
type Observation struct{ state *observationState }

func (observation Observation) record(desired Demand) (unitRecord, bool) {
	if observation.state == nil {
		return unitRecord{}, false
	}
	value, ok := observation.state.records[desired.value.unit]
	return value, ok
}

func (selected *Selected) Observe(ctx context.Context, desired []Demand) (Observation, error) {
	if !selected.valid() || !linux.FutureContext(ctx) {
		return Observation{}, fmt.Errorf("valid selection and bounded context are required")
	}
	if len(desired) > maxObservationDemands {
		return Observation{}, fmt.Errorf("service observation exceeds %d demands", maxObservationDemands)
	}
	values := append([]Demand(nil), desired...)
	for _, value := range values {
		if !value.valid() || !selected.matches(value) {
			return Observation{}, fmt.Errorf("demand does not match selected service scope")
		}
	}
	slices.SortFunc(values, func(left, right Demand) int { return strings.Compare(left.value.unit, right.value.unit) })
	for index := 1; index < len(values); index++ {
		if values[index-1].value.unit == values[index].value.unit {
			return Observation{}, fmt.Errorf("duplicate service demand %q", values[index].value.unit)
		}
	}
	records := make(map[string]unitRecord, len(values))
	for start := 0; start < len(values); start += maxObservationUnits {
		end := min(start+maxObservationUnits, len(values))
		chunk, err := selected.observeChunk(ctx, values[start:end])
		if err != nil {
			return Observation{}, err
		}
		for key, record := range chunk {
			records[key] = record
		}
	}
	return Observation{state: &observationState{records: records}}, nil
}

func (selected *Selected) observeChunk(ctx context.Context, desired []Demand) (map[string]unitRecord, error) {
	if selected.evidence.backend == "openrc" {
		return selected.observeOpenRC(ctx, desired)
	}
	args := selected.prefix()
	args = append(args, "show", "--property=Id,LoadState,UnitFileState,ActiveState,SubState", "--")
	requested := make(map[string]struct{}, len(desired))
	for _, value := range desired {
		args = append(args, value.value.unit)
		requested[value.value.unit] = struct{}{}
	}
	result, err := selected.effects.run(ctx, selected.evidence.tool, args, nil)
	if err != nil || !result.Started {
		return nil, commandFailure("observe services", result, err)
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > maxObservationBytes {
		return nil, fmt.Errorf("service property output is empty or exceeds %d bytes", maxObservationBytes)
	}
	records, err := parsePropertyRecords(result.Stdout)
	if err != nil {
		return nil, err
	}
	if len(records) != len(requested) {
		return nil, fmt.Errorf("service property record count differs")
	}
	for unit := range requested {
		if _, ok := records[unit]; !ok {
			return nil, fmt.Errorf("service property record %q is omitted or noncanonical", unit)
		}
	}
	return records, nil
}

func parsePropertyRecords(data []byte) (map[string]unitRecord, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("service property output is not newline terminated")
	}
	records := make(map[string]unitRecord)
	fields := make(map[string]string, 5)
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		for _, key := range []string{"Id", "LoadState", "UnitFileState", "ActiveState", "SubState"} {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("service property %s is missing", key)
			}
		}
		value := unitRecord{id: fields["Id"], load: fields["LoadState"], unitFile: fields["UnitFileState"], active: fields["ActiveState"], sub: fields["SubState"]}
		if !validUnit(value.id) {
			return fmt.Errorf("service property Id is invalid")
		}
		if _, exists := records[value.id]; exists {
			return fmt.Errorf("duplicate service property record %q", value.id)
		}
		records[value.id] = value
		fields = make(map[string]string, 5)
		return nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !slices.Contains([]string{"Id", "LoadState", "UnitFileState", "ActiveState", "SubState"}, key) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid service property line")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate service property %s", key)
		}
		fields[key] = value
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return records, nil
}

func (selected *Selected) Plan(ctx context.Context, desired Demand) (Plan, error) {
	observed, err := selected.Observe(ctx, []Demand{desired})
	if err != nil {
		return Plan{}, err
	}
	return selected.Reconcile(desired, observed)
}

func (selected *Selected) Reconcile(desired Demand, observed Observation) (Plan, error) {
	if !selected.valid() || !desired.valid() || !selected.matches(desired) {
		return Plan{}, fmt.Errorf("valid matching selection and demand are required")
	}
	record, ok := observed.record(desired)
	if !ok {
		return Plan{}, fmt.Errorf("service observation is missing")
	}
	plan := reconcile(desired.value, record)
	for index := range plan.operations {
		plan.operations[index].evidence = selected.evidence
	}
	return plan, nil
}

func (selected *Selected) matches(desired Demand) bool {
	if desired.backend != selected.evidence.backend {
		return false
	}
	value := desired.value
	if selected.evidence.scope == systemScope {
		return value.user == ""
	}
	return value.user == selected.evidence.principal.name
}

func (selected *Selected) prefix() []string {
	if selected.evidence.scope == systemScope {
		return nil
	}
	return []string{"--user", "--machine=" + strconv.FormatUint(uint64(selected.evidence.principal.uid), 10) + "@.host"}
}

func validUnit(value string) bool {
	return validText(value, 255) && value[0] != '-' && !strings.ContainsAny(value, "/ ")
}
func validAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}
func validText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}
