package host

type Axis uint8

const (
	HostnamePersistence Axis = iota + 1
	HostnameRuntime
	TimezonePersistence
	axisLimit
)

type DecisionKind uint8

const (
	Exact DecisionKind = iota + 1
	Change
	Blocked
)

type Decision struct {
	kind   DecisionKind
	detail string
}

func (decision Decision) Kind() DecisionKind { return decision.kind }
func (decision Decision) Detail() string     { return decision.detail }

type Plan struct {
	decisions  [axisLimit]Decision
	present    [axisLimit]bool
	operations []Operation
}

func (plan Plan) Decision(axis Axis) (Decision, bool) {
	if axis == 0 || axis >= axisLimit || !plan.present[axis] {
		return Decision{}, false
	}
	return plan.decisions[axis], true
}

func (plan Plan) Operations() []Operation {
	return append([]Operation(nil), plan.operations...)
}

type operationKind uint8

const (
	writeHostnameOperation operationKind = iota + 1
	setHostnameOperation
	writeTimezoneOperation
)

type Operation struct {
	kind           operationKind
	desired        string
	hostnameBefore hostnameObservation
	timezoneBefore timezoneObservation
	zone           zoneFile
	evidence       selectionEvidence
}

type hostnameFile struct {
	present, regular bool
	contents         string
	mode             uint32
	uid, gid         uint32
	device, inode    uint64
	blocked          string
}

type hostnameObservation struct {
	persistent     hostnameFile
	runtime        string
	runtimeBlocked string
}

type zoneFile struct {
	regular       bool
	tzif          bool
	mode          uint32
	uid, gid      uint32
	device, inode uint64
	blocked       string
}

type timezoneObservation struct {
	present       bool
	zone, target  string
	zoneFile      zoneFile
	device, inode uint64
	blocked       string
}

func reconcileHostname(desired string, before hostnameObservation) Plan {
	plan := Plan{}
	persistence := Decision{kind: Change, detail: "persistent hostname differs"}
	switch {
	case before.persistent.blocked != "":
		persistence = Decision{kind: Blocked, detail: before.persistent.blocked}
	case before.persistent.present && before.persistent.contents == desired+"\n" && before.persistent.mode == 0o644 && before.persistent.uid == 0 && before.persistent.gid == 0:
		persistence = Decision{kind: Exact, detail: "persistent hostname is exact"}
	case !before.persistent.present:
		persistence.detail = "persistent hostname is missing"
	}
	runtime := Decision{kind: Change, detail: "runtime hostname differs"}
	switch {
	case before.runtimeBlocked != "":
		runtime = Decision{kind: Blocked, detail: before.runtimeBlocked}
	case before.runtime == desired:
		runtime = Decision{kind: Exact, detail: "runtime hostname is exact"}
	}
	plan.set(HostnamePersistence, persistence)
	plan.set(HostnameRuntime, runtime)
	if persistence.kind == Blocked || runtime.kind == Blocked {
		return plan
	}
	if persistence.kind == Change {
		plan.operations = append(plan.operations, Operation{kind: writeHostnameOperation, desired: desired, hostnameBefore: hostnameObservation{persistent: before.persistent}})
	}
	if runtime.kind == Change {
		plan.operations = append(plan.operations, Operation{kind: setHostnameOperation, desired: desired, hostnameBefore: hostnameObservation{runtime: before.runtime, runtimeBlocked: before.runtimeBlocked}})
	}
	return plan
}

func reconcileTimezone(desired string, desiredZone zoneFile, before timezoneObservation) Plan {
	plan := Plan{}
	decision := Decision{kind: Change, detail: "timezone differs"}
	switch {
	case desiredZone.blocked != "":
		decision = Decision{kind: Blocked, detail: desiredZone.blocked}
	case !desiredZone.regular || !desiredZone.tzif:
		decision = Decision{kind: Blocked, detail: "desired timezone is not canonical TZif data"}
	case before.blocked != "":
		decision = Decision{kind: Blocked, detail: before.blocked}
	case before.present && before.zone == desired && before.zoneFile == desiredZone:
		decision = Decision{kind: Exact, detail: "timezone is exact"}
	case !before.present:
		decision.detail = "localtime link is missing"
	}
	plan.set(TimezonePersistence, decision)
	if decision.kind == Change {
		plan.operations = append(plan.operations, Operation{kind: writeTimezoneOperation, desired: desired, timezoneBefore: before, zone: desiredZone})
	}
	return plan
}

func (plan *Plan) set(axis Axis, decision Decision) {
	plan.decisions[axis] = decision
	plan.present[axis] = true
}
