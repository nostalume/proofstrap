package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type resolvedServiceNeed struct {
	need serviceNeed
	unit string
}

type resolvedServiceConflict struct {
	wantedKey  ServiceKey
	otherKey   ServiceKey
	scope      ServiceScope
	wantedUnit string
	otherUnit  string
}

type serviceDemand struct {
	needs     []resolvedServiceNeed
	conflicts []resolvedServiceConflict
}

//sumtype:decl
type serviceObservationKind interface{ serviceObservationKind() }

type serviceSatisfied struct {
	need         serviceNeed
	unit, detail string
}
type serviceUnsatisfied struct {
	need         serviceNeed
	unit, detail string
}
type serviceIndeterminate struct {
	need         serviceNeed
	unit, detail string
}
type serviceMissing struct {
	need serviceNeed
	unit string
}

func (serviceSatisfied) serviceObservationKind()     {}
func (serviceUnsatisfied) serviceObservationKind()   {}
func (serviceIndeterminate) serviceObservationKind() {}
func (serviceMissing) serviceObservationKind()       {}

type serviceObservations map[serviceNeed]serviceObservationKind

func serviceObservationAt(observations serviceObservations, item resolvedServiceNeed) serviceObservationKind {
	if observed, ok := observations[item.need]; ok && observed != nil {
		return observed
	}
	return serviceMissing{need: item.need, unit: item.unit}
}

func serviceObservationDetail(observation serviceObservationKind) string {
	switch state := observation.(type) {
	case serviceSatisfied:
		return state.detail
	case serviceUnsatisfied:
		return state.detail
	case serviceIndeterminate:
		return state.detail
	case serviceMissing:
		return "observation is missing"
	}
	panic("unknown service observation kind")
}

type conflictObservation struct {
	conflict resolvedServiceConflict
	state    serviceObservationKind
}
type serviceInspectionGroup struct {
	scope  ServiceScope
	target serviceTarget
}

type services struct {
	path string
}

func (behavior services) bind(selected selection) (serviceDemand, []Blocker) {
	var demand serviceDemand
	if len(selected.serviceNeeds()) == 0 && len(selected.conflicts) == 0 {
		return demand, nil
	}
	names := map[ServiceKey]string{
		"networkmanager": "NetworkManager.service",
		"pipewire":       "pipewire.service",
		"wireplumber":    "wireplumber.service",
	}
	var blockers []Blocker
	for _, need := range selected.serviceNeeds() {
		unit := names[need.key]
		if unit == "" {
			blockers = append(blockers, Blocker{Subject: "binding:service:" + string(need.key), Detail: "no concrete service name"})
			continue
		}
		demand.needs = append(demand.needs, resolvedServiceNeed{need: need, unit: unit})
	}
	for _, conflict := range selected.conflicts {
		wanted, other := names[conflict.wanted], names[conflict.other]
		if wanted == "" || other == "" {
			blockers = append(blockers, Blocker{Subject: "binding:service-conflict", Detail: fmt.Sprintf("missing unit binding for %s -> %s", conflict.wanted, conflict.other)})
			continue
		}
		demand.conflicts = append(demand.conflicts, resolvedServiceConflict{
			wantedKey: conflict.wanted, otherKey: conflict.other, scope: conflict.scope,
			wantedUnit: wanted, otherUnit: other,
		})
	}
	return demand, blockers
}

func requireSystemd(pid1 string) error {
	if pid1 != "systemd" {
		return fmt.Errorf("unsupported service manager %q", pid1)
	}
	return nil
}

func servicesFor(pid1 string, runner Runner) (services, error) {
	if err := requireSystemd(pid1); err != nil {
		return services{}, err
	}
	path, err := runner.LookPath("systemctl")
	if err != nil {
		return services{}, errors.New("required executable systemctl is unavailable")
	}
	return services{path: path}, nil
}

func (behavior services) observe(ctx context.Context, runner Runner, resolved []resolvedServiceNeed) serviceObservations {
	observations := make(serviceObservations, len(resolved))
	if len(resolved) == 0 {
		return observations
	}
	if behavior.path == "" {
		for _, item := range resolved {
			observations[item.need] = serviceIndeterminate{need: item.need, unit: item.unit, detail: "required executable systemctl is unavailable"}
		}
		return observations
	}
	groups := make(map[serviceInspectionGroup][]resolvedServiceNeed)
	for _, item := range resolved {
		key := serviceInspectionGroup{scope: item.need.scope, target: item.need.target}
		groups[key] = append(groups[key], item)
	}
	keys := make([]serviceInspectionGroup, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scope == keys[j].scope {
			return serviceTargetPrecedence(keys[i].target) < serviceTargetPrecedence(keys[j].target)
		}
		return keys[i].scope < keys[j].scope
	})
	for _, key := range keys {
		items := groups[key]
		sort.Slice(items, func(i, j int) bool { return items[i].unit < items[j].unit })
		command := serviceInspectCommand(behavior.path, key, items)
		result := runner.Run(ctx, command)
		rows := nonemptyLines(result.Stdout)
		if result.Err != nil || len(rows) != len(items) {
			detail := resultDetail(result)
			if len(rows) != len(items) {
				detail = fmt.Sprintf("expected %d status rows, received %d", len(items), len(rows))
			}
			for _, item := range items {
				observations[item.need] = serviceIndeterminate{need: item.need, unit: item.unit, detail: detail}
			}
			continue
		}
		for i, item := range items {
			rowResult := result
			rowResult.Stdout = rows[i]
			if len(items) > 1 {
				if exitCode, recognized := serviceRowExitCode(key.target, rows[i]); recognized {
					rowResult.ExitCode = exitCode
				}
			}
			observations[item.need] = classifyService(item.need, item.unit, rowResult)
		}
	}
	return observations
}

func serviceRowExitCode(target serviceTarget, row string) (int, bool) {
	state := strings.ToLower(strings.TrimSpace(row))
	if target == serviceEnabled {
		switch state {
		case "enabled":
			return 0, true
		case "disabled":
			return 1, true
		}
	} else {
		switch state {
		case "active":
			return 0, true
		case "inactive", "failed":
			return 3, true
		}
	}
	return 0, false
}

func serviceInspectCommand(path string, group serviceInspectionGroup, items []resolvedServiceNeed) Command {
	args := make([]string, 0, len(items)+2)
	if group.scope == UserService {
		args = append(args, "--user")
	}
	if group.target == serviceEnabled {
		args = append(args, "is-enabled")
	} else {
		args = append(args, "is-active")
	}
	for _, item := range items {
		args = append(args, item.unit)
	}
	return Command{Name: path, Args: args}
}

func nonemptyLines(output string) []string {
	var rows []string
	for _, row := range strings.Split(output, "\n") {
		if row = strings.TrimSpace(row); row != "" {
			rows = append(rows, row)
		}
	}
	return rows
}

func (behavior services) observeConflicts(ctx context.Context, runner Runner, conflicts []resolvedServiceConflict) []conflictObservation {
	observed := make([]conflictObservation, 0, len(conflicts))
	for _, conflict := range conflicts {
		need := serviceNeed{key: conflict.otherKey, scope: conflict.scope, target: serviceActive}
		item := resolvedServiceNeed{need: need, unit: conflict.otherUnit}
		states := behavior.observe(ctx, runner, []resolvedServiceNeed{item})
		observed = append(observed, conflictObservation{conflict: conflict, state: serviceObservationAt(states, item)})
	}
	return observed
}

func (services) reconcileConflicts(observed []conflictObservation) ([]Fact, []Blocker) {
	var facts []Fact
	var blockers []Blocker
	for _, item := range observed {
		subject := fmt.Sprintf("service-conflict:%s:%s", item.conflict.wantedKey, item.conflict.otherKey)
		state := item.state
		if state == nil {
			state = serviceMissing{}
		}
		switch state := state.(type) {
		case serviceUnsatisfied:
			facts = append(facts, Fact{Subject: subject, Detail: item.conflict.otherUnit + " inactive (" + state.detail + ")"})
		case serviceSatisfied:
			blockers = append(blockers, Blocker{Subject: subject, Detail: fmt.Sprintf("%s is active and conflicts with desired %s", item.conflict.otherUnit, item.conflict.wantedUnit)})
		case serviceIndeterminate:
			blockers = append(blockers, Blocker{Subject: subject, Detail: "conflicting service state is indeterminate: " + state.detail})
		case serviceMissing:
			blockers = append(blockers, Blocker{Subject: subject, Detail: "conflicting service state is missing"})
		}
	}
	return facts, blockers
}

func classifyService(need serviceNeed, unit string, result Result) serviceObservationKind {
	state := strings.ToLower(strings.TrimSpace(result.Stdout))
	if result.Err != nil {
		return serviceIndeterminate{need: need, unit: unit, detail: result.Err.Error()}
	}
	if need.target == serviceEnabled {
		switch state {
		case "enabled":
			if result.ExitCode == 0 {
				return serviceSatisfied{need: need, unit: unit, detail: state}
			}
		case "disabled":
			if result.ExitCode != 0 {
				return serviceUnsatisfied{need: need, unit: unit, detail: state}
			}
		}
	} else {
		switch state {
		case "active":
			if result.ExitCode == 0 {
				return serviceSatisfied{need: need, unit: unit, detail: state}
			}
		case "inactive", "failed":
			if result.ExitCode != 0 {
				return serviceUnsatisfied{need: need, unit: unit, detail: state}
			}
		}
	}
	return serviceIndeterminate{need: need, unit: unit, detail: fmt.Sprintf("unrecognized state %q (exit %d)", state, result.ExitCode)}
}

type serviceChange struct {
	scope  ServiceScope
	target serviceTarget
	needs  []resolvedServiceNeed
}

func (services) reconcile(needs []resolvedServiceNeed, observed serviceObservations) (facts []Fact, changes []serviceChange, blockers []Blocker) {
	groups := make(map[serviceInspectionGroup][]resolvedServiceNeed)
	for _, item := range needs {
		switch state := serviceObservationAt(observed, item).(type) {
		case serviceSatisfied:
			facts = append(facts, Fact{Subject: serviceSubject(item.need), Detail: state.detail})
		case serviceUnsatisfied:
			key := serviceInspectionGroup{scope: item.need.scope, target: item.need.target}
			groups[key] = append(groups[key], item)
		case serviceIndeterminate:
			blockers = append(blockers, Blocker{Subject: serviceSubject(item.need), Detail: state.detail})
		case serviceMissing:
			blockers = append(blockers, Blocker{Subject: serviceSubject(item.need), Detail: "missing service observation"})
		}
	}
	keys := make([]serviceInspectionGroup, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scope == keys[j].scope {
			return serviceTargetPrecedence(keys[i].target) < serviceTargetPrecedence(keys[j].target)
		}
		return keys[i].scope < keys[j].scope
	})
	for _, key := range keys {
		items := groups[key]
		sort.Slice(items, func(i, j int) bool { return items[i].unit < items[j].unit })
		changes = append(changes, serviceChange{scope: key.scope, target: key.target, needs: append([]resolvedServiceNeed(nil), items...)})
	}
	return facts, changes, blockers
}

func (behavior services) step(change serviceChange) (step, error) {
	if len(change.needs) == 0 {
		return step{}, errors.New("empty service change")
	}
	verb, suffix := "", ""
	if change.target == serviceEnabled {
		verb, suffix = "enable", "enable"
	} else {
		verb, suffix = "start", "start"
	}
	args := make([]string, 0, len(change.needs)+2)
	access := rootStep
	if change.scope == UserService {
		args = append(args, "--user")
		access = directStep
	}
	args = append(args, verb)
	units := make([]string, len(change.needs))
	for i, item := range change.needs {
		units[i] = item.unit
	}
	sort.Strings(units)
	args = append(args, units...)
	command := Command{Name: behavior.path, Args: args}
	id := fmt.Sprintf("services:%s:%s", change.scope, suffix)
	before := func(ctx context.Context, runner Runner) error {
		observed := behavior.observe(ctx, runner, change.needs)
		for _, item := range change.needs {
			state := serviceObservationAt(observed, item)
			switch state.(type) {
			case serviceUnsatisfied:
			case serviceSatisfied:
				return stalePrecondition{detail: serviceSubject(item.need) + " changed"}
			case serviceIndeterminate, serviceMissing:
				return fmt.Errorf("%s cannot be revalidated: %T", serviceSubject(item.need), state)
			}
		}
		return nil
	}
	verify := func(ctx context.Context, runner Runner) (bool, string) {
		observed := make(serviceObservations, len(change.needs))
		for _, item := range change.needs {
			for need, state := range behavior.observe(ctx, runner, []resolvedServiceNeed{item}) {
				observed[need] = state
			}
		}
		allSatisfied := true
		details := make([]string, 0, len(change.needs))
		for _, item := range change.needs {
			switch state := serviceObservationAt(observed, item).(type) {
			case serviceSatisfied:
				details = append(details, item.unit+"=satisfied("+state.detail+")")
			case serviceUnsatisfied:
				allSatisfied = false
				details = append(details, item.unit+"=unsatisfied("+state.detail+")")
			case serviceIndeterminate:
				allSatisfied = false
				details = append(details, item.unit+"=indeterminate("+state.detail+")")
			case serviceMissing:
				allSatisfied = false
				details = append(details, item.unit+"=missing")
			}
		}
		return allSatisfied, strings.Join(details, ", ")
	}
	return step{id: id, detail: verb + " " + strings.Join(units, ", "), command: command, timeout: 30 * time.Second, access: access, manager: change.scope == UserService && change.target == serviceActive, before: before, verify: verify}, nil
}

func serviceSubject(need serviceNeed) string {
	target := "active"
	if need.target == serviceEnabled {
		target = "enabled"
	}
	return fmt.Sprintf("service:%s:%s:%s", need.scope, need.key, target)
}
