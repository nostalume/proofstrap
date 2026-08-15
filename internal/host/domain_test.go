package host

import "testing"

func TestHostnameReconciliationKeepsAxesIndependentAndOrdered(t *testing.T) {
	tests := []struct {
		name                 string
		before               hostnameObservation
		persistence, runtime DecisionKind
		operations           []operationKind
	}{
		{
			name:        "exact",
			before:      hostnameObservation{persistent: exactHostnameFile("node"), runtime: "node"},
			persistence: Exact,
			runtime:     Exact,
		},
		{
			name:        "persistent then runtime",
			before:      hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"},
			persistence: Change,
			runtime:     Change,
			operations:  []operationKind{writeHostnameOperation, setHostnameOperation},
		},
		{
			name:        "metadata only",
			before:      hostnameObservation{persistent: hostnameFile{present: true, regular: true, contents: "node\n", mode: 0o600, uid: 0, gid: 0}, runtime: "node"},
			persistence: Change,
			runtime:     Exact,
			operations:  []operationKind{writeHostnameOperation},
		},
		{
			name:        "missing persistence",
			before:      hostnameObservation{runtime: "node"},
			persistence: Change,
			runtime:     Exact,
			operations:  []operationKind{writeHostnameOperation},
		},
		{
			name:        "unsafe persistence blocks whole resource",
			before:      hostnameObservation{persistent: hostnameFile{present: true, blocked: "hostname file is not root-owned"}, runtime: "old"},
			persistence: Blocked,
			runtime:     Change,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := reconcileHostname("node", test.before)
			assertDecision(t, plan, HostnamePersistence, test.persistence)
			assertDecision(t, plan, HostnameRuntime, test.runtime)
			operations := plan.Operations()
			if len(operations) != len(test.operations) {
				t.Fatalf("operations = %#v, want %v", operations, test.operations)
			}
			for index, operation := range operations {
				if operation.kind != test.operations[index] {
					t.Fatalf("operation %d = %v, want %v", index, operation.kind, test.operations[index])
				}
			}
		})
	}
}

func TestTimezoneReconciliationRequiresExactCanonicalSymlink(t *testing.T) {
	exact := timezoneObservation{present: true, zone: "Asia/Shanghai", target: "/usr/share/zoneinfo/Asia/Shanghai", zoneFile: zoneFile{regular: true, tzif: true}}
	tests := []struct {
		name       string
		before     timezoneObservation
		decision   DecisionKind
		operations int
	}{
		{"exact", exact, Exact, 0},
		{"different", timezoneObservation{present: true, zone: "UTC", target: "/usr/share/zoneinfo/UTC", zoneFile: zoneFile{regular: true, tzif: true}}, Change, 1},
		{"missing", timezoneObservation{}, Change, 1},
		{"regular localtime", timezoneObservation{present: true, blocked: "localtime is not a symlink"}, Blocked, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := reconcileTimezone("Asia/Shanghai", exact.zoneFile, test.before)
			assertDecision(t, plan, TimezonePersistence, test.decision)
			if got := len(plan.Operations()); got != test.operations {
				t.Fatalf("operations = %d, want %d", got, test.operations)
			}
		})
	}
}

func exactHostnameFile(value string) hostnameFile {
	return hostnameFile{present: true, regular: true, contents: value + "\n", mode: 0o644, uid: 0, gid: 0, device: 1, inode: 2}
}

func assertDecision(t *testing.T, plan Plan, axis Axis, want DecisionKind) {
	t.Helper()
	decision, ok := plan.Decision(axis)
	if !ok || decision.Kind() != want {
		t.Fatalf("decision %v = %#v,%t, want %v", axis, decision, ok, want)
	}
}
