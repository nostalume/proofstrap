package services

import "testing"

func TestReconcileServiceAxesAndOrdering(t *testing.T) {
	tests := []struct {
		name                 string
		demand               demand
		before               unitRecord
		persistence, runtime DecisionKind
		operations           []operationKind
	}{
		{"exact", demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}, unitRecord{id: "demo.service", load: "loaded", unitFile: "enabled", active: "active", sub: "running"}, Exact, Exact, nil},
		{"exact off", demand{unit: "demo.service", persistence: wantOff, runtime: wantOff}, unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}, Exact, Exact, nil},
		{"enable then start", demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}, unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}, Change, Change, []operationKind{enableOperation, startOperation}},
		{"stop then disable", demand{unit: "demo.service", persistence: wantOff, runtime: wantOff}, unitRecord{id: "demo.service", load: "loaded", unitFile: "enabled", active: "active", sub: "running"}, Change, Change, []operationKind{stopOperation, disableOperation}},
		{"unmanaged persistence", demand{unit: "demo.service", runtime: wantOn}, unitRecord{id: "demo.service", load: "loaded", unitFile: "static", active: "inactive", sub: "dead"}, Exact, Change, []operationKind{startOperation}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := reconcile(test.demand, test.before)
			if plan.Persistence().Kind() != test.persistence || plan.Runtime().Kind() != test.runtime {
				t.Fatalf("decisions = %v/%v", plan.Persistence().Kind(), plan.Runtime().Kind())
			}
			operations := plan.Operations()
			if len(operations) != len(test.operations) {
				t.Fatalf("operations = %#v", operations)
			}
			for index, want := range test.operations {
				if operations[index].kind != want {
					t.Fatalf("operation %d = %v, want %v", index, operations[index].kind, want)
				}
			}
		})
	}
}

func TestReconcileBlocksUnsupportedStatesWithoutCollapsingThem(t *testing.T) {
	tests := []struct {
		name        string
		before      unitRecord
		blockedAxis axis
	}{
		{"missing", unitRecord{id: "demo.service", load: "not-found", unitFile: "", active: "inactive", sub: "dead"}, persistenceAxis},
		{"static", unitRecord{id: "demo.service", load: "loaded", unitFile: "static", active: "inactive", sub: "dead"}, persistenceAxis},
		{"masked", unitRecord{id: "demo.service", load: "loaded", unitFile: "masked", active: "inactive", sub: "dead"}, persistenceAxis},
		{"failed", unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "failed", sub: "failed"}, runtimeAxis},
		{"activating", unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "activating", sub: "start"}, runtimeAxis},
		{"unknown", unitRecord{id: "demo.service", load: "loaded", unitFile: "mystery", active: "mystery", sub: "mystery"}, persistenceAxis},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := reconcile(demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}, test.before)
			decision := plan.Persistence()
			if test.blockedAxis == runtimeAxis {
				decision = plan.Runtime()
			}
			if decision.Kind() != Blocked || len(plan.Operations()) != 0 {
				t.Fatalf("plan = %#v", plan)
			}
		})
	}
}
