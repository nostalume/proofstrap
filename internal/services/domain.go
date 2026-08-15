package services

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

type axis uint8

const (
	persistenceAxis axis = iota + 1
	runtimeAxis
)

type intent uint8

const (
	unmanaged intent = iota
	wantOn
	wantOff
)

type operationKind uint8

const (
	enableOperation operationKind = iota + 1
	disableOperation
	startOperation
	stopOperation
)

type demand struct {
	unit                 string
	persistence, runtime intent
	user                 string
}

type unitRecord struct {
	id, load, unitFile, active, sub string
}

type Plan struct {
	persistence Decision
	runtime     Decision
	operations  []Operation
}

func (plan Plan) Persistence() Decision { return plan.persistence }
func (plan Plan) Runtime() Decision     { return plan.runtime }
func (plan Plan) Operations() []Operation {
	return append([]Operation(nil), plan.operations...)
}

type Operation struct {
	kind     operationKind
	demand   demand
	before   axisState
	evidence selectionEvidence
}

type axisState struct {
	id, load, value, sub string
}

func reconcile(desired demand, before unitRecord) Plan {
	plan := Plan{
		persistence: reconcilePersistence(desired.persistence, before),
		runtime:     reconcileRuntime(desired.runtime, before),
	}
	if plan.persistence.kind == Blocked || plan.runtime.kind == Blocked {
		return plan
	}
	if plan.runtime.kind == Change && desired.runtime == wantOff {
		plan.operations = append(plan.operations, Operation{kind: stopOperation, demand: runtimeDemand(desired), before: runtimeState(before)})
	}
	if plan.persistence.kind == Change {
		kind := enableOperation
		if desired.persistence == wantOff {
			kind = disableOperation
		}
		plan.operations = append(plan.operations, Operation{kind: kind, demand: persistenceDemand(desired), before: persistenceState(before)})
	}
	if plan.runtime.kind == Change && desired.runtime == wantOn {
		plan.operations = append(plan.operations, Operation{kind: startOperation, demand: runtimeDemand(desired), before: runtimeState(before)})
	}
	return plan
}

func persistenceDemand(value demand) demand {
	value.runtime = unmanaged
	return value
}

func runtimeDemand(value demand) demand {
	value.persistence = unmanaged
	return value
}

func reconcilePersistence(desired intent, before unitRecord) Decision {
	if desired == unmanaged {
		return Decision{kind: Exact, detail: "persistence is unmanaged"}
	}
	if before.id == "" || before.load == "not-found" {
		return Decision{kind: Blocked, detail: "unit is missing"}
	}
	if before.load != "loaded" {
		return Decision{kind: Blocked, detail: "unit load state is unsupported: " + before.load}
	}
	switch before.unitFile {
	case "enabled":
		if desired == wantOn {
			return Decision{kind: Exact, detail: "unit is enabled"}
		}
		return Decision{kind: Change, detail: "unit requires disable"}
	case "disabled":
		if desired == wantOff {
			return Decision{kind: Exact, detail: "unit is disabled"}
		}
		return Decision{kind: Change, detail: "unit requires enable"}
	case "static", "indirect", "generated", "transient", "alias", "linked", "linked-runtime", "enabled-runtime", "masked", "masked-runtime", "bad":
		return Decision{kind: Blocked, detail: "unit-file state is not manageable: " + before.unitFile}
	default:
		return Decision{kind: Blocked, detail: "unit-file state is indeterminate: " + before.unitFile}
	}
}

func reconcileRuntime(desired intent, before unitRecord) Decision {
	if desired == unmanaged {
		return Decision{kind: Exact, detail: "runtime is unmanaged"}
	}
	if before.id == "" || before.load == "not-found" {
		return Decision{kind: Blocked, detail: "unit is missing"}
	}
	if before.load != "loaded" {
		return Decision{kind: Blocked, detail: "unit load state is unsupported: " + before.load}
	}
	switch before.active {
	case "active":
		if desired == wantOn {
			return Decision{kind: Exact, detail: "unit is active"}
		}
		return Decision{kind: Change, detail: "unit requires stop"}
	case "inactive":
		if desired == wantOff {
			return Decision{kind: Exact, detail: "unit is inactive"}
		}
		return Decision{kind: Change, detail: "unit requires start"}
	case "failed":
		return Decision{kind: Blocked, detail: "unit runtime is failed"}
	case "activating", "deactivating", "reloading", "maintenance", "refreshing":
		return Decision{kind: Blocked, detail: "unit runtime is transitional: " + before.active}
	default:
		return Decision{kind: Blocked, detail: "unit runtime is indeterminate: " + before.active}
	}
}

func persistenceState(record unitRecord) axisState {
	return axisState{id: record.id, load: record.load, value: record.unitFile}
}

func runtimeState(record unitRecord) axisState {
	return axisState{id: record.id, load: record.load, value: record.active, sub: record.sub}
}
