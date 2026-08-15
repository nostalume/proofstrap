package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/model"
)

func TestHostnamePlanAndApplySealEachAxis(t *testing.T) {
	before := hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"}
	afterPersistent := hostnameObservation{persistent: exactHostnameFile("node"), runtime: "old"}
	afterRuntime := hostnameObservation{persistent: exactHostnameFile("node"), runtime: "node"}
	fixture := &effectFixture{hostnames: []hostnameObservation{before, before, afterPersistent, before, afterRuntime}}
	selected := selectedHostname(fixture)
	desired := projectedHostname(t, "node")

	plan, err := selected.PlanHostname(testContext(t), desired)
	if err != nil {
		t.Fatal(err)
	}
	operations := plan.Operations()
	if len(operations) != 2 || operations[0].kind != writeHostnameOperation || operations[1].kind != setHostnameOperation {
		t.Fatalf("operations = %#v", operations)
	}

	result, err := operations[0].Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact || fixture.writes != 1 || fixture.sets != 0 {
		t.Fatalf("persistent Apply = %#v, %v; writes=%d sets=%d", result, err, fixture.writes, fixture.sets)
	}
	result, err = operations[1].Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact || fixture.writes != 1 || fixture.sets != 1 {
		t.Fatalf("runtime Apply = %#v, %v; writes=%d sets=%d", result, err, fixture.writes, fixture.sets)
	}
}

func TestHostOperationRejectsFreshEvidenceAndAxisDriftBeforeStart(t *testing.T) {
	before := hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"}
	fixture := &effectFixture{hostnames: []hostnameObservation{before}}
	selected := selectedHostname(fixture)
	plan, err := selected.PlanHostname(testContext(t), projectedHostname(t, "node"))
	if err != nil {
		t.Fatal(err)
	}
	operation := plan.Operations()[0]

	driftedSelection := *selected
	driftedSelection.evidence.etc.inode++
	if result, err := operation.Apply(testContext(t), postContext(t), &driftedSelection); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("selection drift = %#v, %v", result, err)
	}

	fixture.hostnames = append(fixture.hostnames, hostnameObservation{persistent: exactHostnameFile("other"), runtime: "old"})
	if result, err := operation.Apply(testContext(t), postContext(t), selected); !errors.Is(err, ErrStale) || result.Started() || fixture.writes != 0 {
		t.Fatalf("state drift = %#v, %v, writes=%d", result, err, fixture.writes)
	}
}

func TestTimezonePlanAndApplyUseDesiredTZifEvidence(t *testing.T) {
	desiredZone := zoneFile{regular: true, tzif: true, mode: 0o644, device: 3, inode: 4}
	before := timezoneObservation{present: true, zone: "UTC", target: "/usr/share/zoneinfo/UTC", zoneFile: zoneFile{regular: true, tzif: true, mode: 0o644, device: 3, inode: 2}, device: 1, inode: 8}
	after := timezoneObservation{present: true, zone: "Asia/Shanghai", target: "/usr/share/zoneinfo/Asia/Shanghai", zoneFile: desiredZone, device: 1, inode: 9}
	fixture := &effectFixture{zones: map[string]zoneFile{"Asia/Shanghai": desiredZone}, timezones: []timezoneObservation{before, before, after}}
	selected := selectedTimezone(fixture)
	plan, err := selected.PlanTimezone(testContext(t), projectedTimezone(t, "Asia/Shanghai"))
	if err != nil || len(plan.Operations()) != 1 {
		t.Fatalf("PlanTimezone = %#v, %v", plan, err)
	}
	result, err := plan.Operations()[0].Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact || fixture.timezoneWrites != 1 {
		t.Fatalf("timezone Apply = %#v, %v; writes=%d", result, err, fixture.timezoneWrites)
	}
}

func TestHostApplyReportsStartedAndIndependentPostcondition(t *testing.T) {
	before := hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"}
	after := hostnameObservation{persistent: exactHostnameFile("node"), runtime: "old"}
	effectErr := errors.New("directory sync failed")
	fixture := &effectFixture{
		hostnames: []hostnameObservation{before, before, after},
		writeErr:  effectErr,
	}
	selected := selectedHostname(fixture)
	plan, err := selected.PlanHostname(testContext(t), projectedHostname(t, "node"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := plan.Operations()[0].Apply(testContext(t), postContext(t), selected)
	if !errors.Is(err, effectErr) || !result.Started() || result.Decision().Kind() != Exact {
		t.Fatalf("Apply after effect error = %#v, %v", result, err)
	}
}

func TestHostApplyPreservesStartedWhenPostObservationFails(t *testing.T) {
	before := hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"}
	postErr := errors.New("post observation failed")
	fixture := &effectFixture{
		hostnames:           []hostnameObservation{before, before},
		hostnameObserveErrs: []error{nil, nil, postErr},
	}
	selected := selectedHostname(fixture)
	plan, err := selected.PlanHostname(testContext(t), projectedHostname(t, "node"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := plan.Operations()[0].Apply(testContext(t), postContext(t), selected)
	if !errors.Is(err, postErr) || !result.Started() || result.Decision().Kind() != 0 {
		t.Fatalf("Apply after post observation error = %#v, %v", result, err)
	}
}

func TestHostPlanningConvertsObservationFailuresToBlockedDecisions(t *testing.T) {
	hostnameFixture := &effectFixture{hostnameObserveErrs: []error{errors.New("hostname unavailable")}}
	hostnamePlan, err := selectedHostname(hostnameFixture).PlanHostname(testContext(t), projectedHostname(t, "node"))
	if err != nil || len(hostnamePlan.Operations()) != 0 {
		t.Fatalf("hostname blocked plan = %#v, %v", hostnamePlan, err)
	}
	for _, axis := range []Axis{HostnamePersistence, HostnameRuntime} {
		decision, ok := hostnamePlan.Decision(axis)
		if !ok || decision.Kind() != Blocked {
			t.Fatalf("hostname decision %v = %#v, %t", axis, decision, ok)
		}
	}

	timezoneFixture := &effectFixture{zones: map[string]zoneFile{}}
	timezonePlan, err := selectedTimezone(timezoneFixture).PlanTimezone(testContext(t), projectedTimezone(t, "UTC"))
	decision, ok := timezonePlan.Decision(TimezonePersistence)
	if err != nil || !ok || decision.Kind() != Blocked || len(timezonePlan.Operations()) != 0 {
		t.Fatalf("timezone blocked plan = %#v, %v", timezonePlan, err)
	}
}

type effectFixture struct {
	hostnames           []hostnameObservation
	hostnameObserveErrs []error
	timezones           []timezoneObservation
	zones               map[string]zoneFile
	writes, sets        int
	timezoneWrites      int
	writeErr            error
}

func selectedHostname(fixture *effectFixture) *Selected {
	return &Selected{evidence: selectionEvidence{kind: hostnameMechanism, euid: 0, etc: directoryEvidence{path: "/etc", directory: true, uid: 0, gid: 0, mode: 0o755, device: 1, inode: 2}}, effects: fixture.effects()}
}

func selectedTimezone(fixture *effectFixture) *Selected {
	return &Selected{evidence: selectionEvidence{kind: timezoneMechanism, euid: 0, etc: directoryEvidence{path: "/etc", directory: true, uid: 0, gid: 0, mode: 0o755, device: 1, inode: 2}, zoneinfo: directoryEvidence{path: "/usr/share/zoneinfo", directory: true, uid: 0, gid: 0, mode: 0o755, device: 1, inode: 3}, secondaryAbsent: true}, effects: fixture.effects()}
}

func (fixture *effectFixture) effects() effects {
	return effects{
		observeHostname: func() (hostnameObservation, error) {
			if len(fixture.hostnameObserveErrs) > 0 {
				err := fixture.hostnameObserveErrs[0]
				fixture.hostnameObserveErrs = fixture.hostnameObserveErrs[1:]
				if err != nil {
					return hostnameObservation{}, err
				}
			}
			if len(fixture.hostnames) == 0 {
				return hostnameObservation{}, errors.New("no hostname observation")
			}
			value := fixture.hostnames[0]
			fixture.hostnames = fixture.hostnames[1:]
			return value, nil
		},
		writeHostname: func(hostnameFile, string) (bool, error) { fixture.writes++; return true, fixture.writeErr },
		setHostname:   func(string) (bool, error) { fixture.sets++; return true, nil },
		zone: func(name string) (zoneFile, error) {
			value, ok := fixture.zones[name]
			if !ok {
				return zoneFile{}, errors.New("zone absent")
			}
			return value, nil
		},
		observeTimezone: func() (timezoneObservation, error) {
			if len(fixture.timezones) == 0 {
				return timezoneObservation{}, errors.New("no timezone observation")
			}
			value := fixture.timezones[0]
			fixture.timezones = fixture.timezones[1:]
			return value, nil
		},
		writeTimezone: func(timezoneObservation, string, zoneFile) (bool, error) { fixture.timezoneWrites++; return true, nil },
	}
}

func projectedHostname(t *testing.T, value string) model.Hostname {
	t.Helper()
	resource, err := model.NewHostname(value)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := graphWith(t, resource)
	if err != nil {
		t.Fatal(err)
	}
	valueView, ok := model.HostnameOf(graph.Nodes()[0])
	if !ok {
		t.Fatal("hostname projection failed")
	}
	return valueView
}

func projectedTimezone(t *testing.T, value string) model.Timezone {
	t.Helper()
	resource, err := model.NewTimezone(value)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := graphWith(t, resource)
	if err != nil {
		t.Fatal(err)
	}
	valueView, ok := model.TimezoneOf(graph.Nodes()[0])
	if !ok {
		t.Fatal("timezone projection failed")
	}
	return valueView
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func postContext(t *testing.T) func() (context.Context, context.CancelFunc) {
	t.Helper()
	return func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), time.Minute)
	}
}

func graphWith(t *testing.T, resource model.Resource) (model.Graph, error) {
	t.Helper()
	provenance, err := model.NewProvenance("test")
	if err != nil {
		return model.Graph{}, err
	}
	contribution, err := model.Contribute(resource, provenance)
	if err != nil {
		return model.Graph{}, err
	}
	return model.EmptyGraph().Add([]model.Contribution{contribution})
}
