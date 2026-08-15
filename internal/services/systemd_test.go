package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linuxexec"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

type systemdFixture struct {
	identities      map[string]linuxexec.Identity
	euid            uint32
	pid1            string
	home            homeEvidence
	records         map[string]unitRecord
	calls           [][]string
	malformed       string
	mutationFailure bool
	mutationChanges bool
	probeFailure    bool
	probeMalformed  string
}

func newSystemdFixture() *systemdFixture {
	identity := serviceIdentity("/usr/bin/systemctl", 1)
	return &systemdFixture{
		identities: map[string]linuxexec.Identity{"/usr/bin/systemctl": identity, "/bin/systemctl": identity},
		euid:       0, pid1: "systemd",
		home:            homeEvidence{path: "/home/alice", uid: 1000, gid: 1000, mode: 0o750, device: 1, inode: 2, directory: true},
		records:         make(map[string]unitRecord),
		mutationChanges: true,
	}
}

func (fixture *systemdFixture) effects() systemEffects {
	return systemEffects{
		identify: func(path string) (linuxexec.Identity, error) {
			value, ok := fixture.identities[path]
			if !ok {
				return linuxexec.Identity{}, os.ErrNotExist
			}
			return value, nil
		},
		run:  fixture.run,
		euid: func() (uint32, error) { return fixture.euid, nil },
		pid1: func() (string, error) { return fixture.pid1, nil },
		home: func(string) (homeEvidence, error) { return fixture.home, nil },
	}
}

func (fixture *systemdFixture) run(_ context.Context, _ linuxexec.Identity, args []string, _ []byte) (linuxexec.Result, error) {
	fixture.calls = append(fixture.calls, append([]string(nil), args...))
	if slices.Contains(args, "--property=Version") {
		if fixture.probeFailure {
			return linuxexec.Result{Started: true, ExitCode: 1}, nil
		}
		if fixture.probeMalformed != "" {
			return linuxexec.Result{Started: true, Stdout: []byte(fixture.probeMalformed)}, nil
		}
		return linuxexec.Result{Started: true, Stdout: []byte("256.7\n")}, nil
	}
	for _, verb := range []string{"enable", "disable", "start", "stop"} {
		if slices.Contains(args, verb) {
			unit := args[len(args)-1]
			if fixture.mutationChanges {
				record := fixture.records[unit]
				switch verb {
				case "enable":
					record.unitFile = "enabled"
				case "disable":
					record.unitFile = "disabled"
				case "start":
					record.active, record.sub = "active", "running"
				case "stop":
					record.active, record.sub = "inactive", "dead"
				}
				fixture.records[unit] = record
			}
			if fixture.mutationFailure {
				return linuxexec.Result{Started: true, ExitCode: 7, Stderr: []byte("native failure")}, nil
			}
			return linuxexec.Result{Started: true}, nil
		}
	}
	if fixture.malformed != "" {
		return linuxexec.Result{Started: true, Stdout: []byte(fixture.malformed)}, nil
	}
	separator := slices.Index(args, "--")
	var output strings.Builder
	for index := len(args) - 1; index > separator; index-- {
		record, ok := fixture.records[args[index]]
		if !ok {
			record = unitRecord{id: args[index], load: "not-found", unitFile: "", active: "inactive", sub: "dead"}
		}
		fmt.Fprintf(&output, "SubState=%s\nId=%s\nActiveState=%s\nLoadState=%s\nUnitFileState=%s\n\n", record.sub, record.id, record.active, record.load, record.unitFile)
	}
	return linuxexec.Result{Started: true, Stdout: []byte(output.String())}, nil
}

func TestSystemAndExactUserAdmissionAreIndependent(t *testing.T) {
	fixture := newSystemdFixture()
	system, err := selectSystem(testContext(t), fixture.effects())
	if err != nil || !system.valid() || system.evidence.scope != systemScope {
		t.Fatalf("system = %#v, %v", system, err)
	}
	principal := Principal{name: "alice", uid: 1000, home: "/home/alice", admitted: true}
	user, err := selectUser(testContext(t), fixture.effects(), principal)
	if err != nil || !user.valid() || user.evidence.scope != userScope || user.evidence.principal != principal || user.evidence.home != fixture.home {
		t.Fatalf("user = %#v, %v", user, err)
	}
	wantUserProbe := []string{"--user", "--machine=1000@.host", "show", "--property=Version", "--value"}
	if !containsArgs(fixture.calls, wantUserProbe) {
		t.Fatalf("calls = %#v", fixture.calls)
	}

	fixture.euid = 1000
	if _, err := selectUser(testContext(t), fixture.effects(), principal); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-root user admission = %v", err)
	}
	fixture.euid = 0
	fixture.pid1 = "openrc"
	if _, err := selectSystem(testContext(t), fixture.effects()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("non-systemd PID1 = %v", err)
	}
	fixture.pid1 = "systemd"
	fixture.identities["/bin/systemctl"] = serviceIdentity("/opt/systemctl", 9)
	if _, err := selectSystem(testContext(t), fixture.effects()); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("competing systemctl = %v", err)
	}
	delete(fixture.identities, "/bin/systemctl")
	delete(fixture.identities, "/usr/bin/systemctl")
	if _, err := selectSystem(testContext(t), fixture.effects()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing systemctl = %v", err)
	}
	fixture = newSystemdFixture()
	fixture.home.uid = 1001
	if _, err := selectUser(testContext(t), fixture.effects(), principal); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("wrong home owner = %v", err)
	}
	fixture = newSystemdFixture()
	fixture.probeFailure = true
	if _, err := selectSystem(testContext(t), fixture.effects()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unreachable manager = %v", err)
	}
	fixture = newSystemdFixture()
	fixture.probeMalformed = "256\nextra\n"
	if _, err := selectSystem(testContext(t), fixture.effects()); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("malformed manager proof = %v", err)
	}
}

func TestPropertyObservationIsKeyedStrictAndChunked(t *testing.T) {
	fixture := newSystemdFixture()
	selected, err := selectSystem(testContext(t), fixture.effects())
	if err != nil {
		t.Fatal(err)
	}
	fixture.calls = nil
	demands := make([]Demand, 129)
	for index := range demands {
		unit := fmt.Sprintf("unit-%03d.service", index)
		fixture.records[unit] = unitRecord{id: unit, load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}
		demands[index] = Demand{value: demand{unit: unit, persistence: wantOn, runtime: wantOn}}
	}
	observed, err := selected.Observe(testContext(t), demands)
	if err != nil || len(observed.state.records) != 129 {
		t.Fatalf("observe = %#v, %v", observed, err)
	}
	if len(fixture.calls) != 2 {
		t.Fatalf("chunk calls = %d", len(fixture.calls))
	}
	for _, desired := range demands {
		record, ok := observed.record(desired)
		if !ok || record.id != desired.value.unit {
			t.Fatalf("record %q = %#v,%t", desired.value.unit, record, ok)
		}
	}

	fixture.malformed = "Id=a.service\nLoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\n\nId=a.service\nLoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\n\n"
	if _, err := selected.Observe(testContext(t), []Demand{{value: demand{unit: "a.service", runtime: wantOn}}}); err == nil {
		t.Fatal("accepted duplicate record")
	}
	fixture.malformed = "Id=a.service\nLoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n\n"
	if _, err := selected.Observe(testContext(t), []Demand{{value: demand{unit: "a.service", runtime: wantOn}}}); err == nil {
		t.Fatal("accepted incomplete record")
	}
	fixture.malformed = "Id=a.service\nLoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\nDescription=unexpected\n\n"
	if _, err := selected.Observe(testContext(t), []Demand{{value: demand{unit: "a.service", runtime: wantOn}}}); err == nil {
		t.Fatal("accepted unrequested property")
	}
	fixture.malformed = strings.Repeat("x", maxObservationBytes+1)
	if _, err := selected.Observe(testContext(t), []Demand{{value: demand{unit: "a.service", runtime: wantOn}}}); err == nil {
		t.Fatal("accepted oversized property output")
	}
	if _, err := selected.Observe(testContext(t), make([]Demand, maxObservationDemands+1)); err == nil {
		t.Fatal("accepted excessive demand count")
	}
}

func TestPlanUsesBindingDemandAndAttachesSelectionEvidence(t *testing.T) {
	fixture := newSystemdFixture()
	fixture.records["demo.service"] = unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}
	selected, err := selectSystem(testContext(t), fixture.effects())
	if err != nil {
		t.Fatal(err)
	}
	desired := Demand{value: demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}}
	planned, err := selected.Plan(testContext(t), desired)
	if err != nil {
		t.Fatal(err)
	}
	operations := planned.Operations()
	if len(operations) != 2 || !reflect.DeepEqual(operations[0].evidence, selected.evidence) || !reflect.DeepEqual(operations[1].evidence, selected.evidence) {
		t.Fatalf("operations=%#v", operations)
	}
}

func TestDemandComesFromConcreteBindingAndSemanticTarget(t *testing.T) {
	for _, user := range []bool{false, true} {
		t.Run(fmt.Sprintf("user=%t", user), func(t *testing.T) {
			node := projectedServiceNode(t, user, "demo.service")
			desired, err := DemandOf(node)
			if err != nil {
				t.Fatal(err)
			}
			wantUser := ""
			if user {
				wantUser = "alice"
			}
			if desired.value.unit != "demo.service" || desired.value.user != wantUser || desired.value.persistence != wantOn || desired.value.runtime != wantOn {
				t.Fatalf("demand=%#v", desired)
			}
		})
	}
	if _, err := DemandOf(projectedServiceNode(t, false, "-option.service")); err == nil {
		t.Fatal("accepted option-like unit")
	}
}

func TestNativeDemandUsesTheSameTypedContractAsBindingDemand(t *testing.T) {
	backend, _ := binding.NewServiceBackendID("systemd")
	id, _ := binding.NewServiceID(backend, "agent.service")
	account, _ := model.NewAccountKey("alice")
	target, _ := model.UserServiceTarget(account)
	demand, err := NewDemand(id, target, model.EnabledIntent(), model.RunningIntent())
	if err != nil {
		t.Fatal(err)
	}
	if !demand.valid() || demand.value.unit != "agent.service" || demand.value.user != "alice" || demand.value.persistence != wantOn || demand.value.runtime != wantOn {
		t.Fatalf("native demand = %#v", demand)
	}
}

func projectedServiceNode(t *testing.T, user bool, unit string) binding.Node {
	t.Helper()
	library, err := profile.Decode("semantic", []profile.Member{{Path: "profiles/base.toml", Data: []byte("[profiles.base.services.demo]\ntarget='system'\nenabled=true\nrunning=true\n")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := binding.Decode(context.Background(), "binding", []binding.Member{{Path: "bindings/base.toml", Data: []byte("[service.systemd]\n'core:demo'=['" + unit + "']\n")}}, map[string]profile.Library{"core": library})
	if err != nil {
		t.Fatal(err)
	}
	serviceID, _ := model.NewServiceID("demo")
	target := model.SystemServiceTarget()
	resources := []model.Resource{}
	if user {
		account, _ := model.NewAccountKey("alice")
		accountResource, _ := model.NewExternalAccount(account)
		resources = append(resources, accountResource)
		target, _ = model.UserServiceTarget(account)
	}
	service, _ := model.NewService(serviceID, target, model.EnabledIntent(), model.RunningIntent(), nil)
	resources = append(resources, service)
	provenance, _ := model.NewProvenance("service-test")
	var contributions []model.Contribution
	for _, resource := range resources {
		contribution, _ := model.Contribute(resource, provenance)
		contributions = append(contributions, contribution)
	}
	semantic, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	backend, _ := binding.NewServiceBackendID("systemd")
	projected, err := binding.Project(context.Background(), semantic, binding.Backends{Service: backend}, []binding.Catalogue{catalogue})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range projected.Nodes() {
		if _, ok := binding.ServiceIDOf(node); ok {
			return node
		}
	}
	t.Fatal("projected service missing")
	return nil
}

func TestOperationsMutateOneAxisInOrderAndGuardOnlyTheirAxis(t *testing.T) {
	for _, test := range []struct {
		name    string
		before  unitRecord
		desired demand
		want    [][]string
	}{
		{"enable-start", unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}, demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}, [][]string{{"enable", "--", "demo.service"}, {"start", "--", "demo.service"}}},
		{"stop-disable", unitRecord{id: "demo.service", load: "loaded", unitFile: "enabled", active: "active", sub: "running"}, demand{unit: "demo.service", persistence: wantOff, runtime: wantOff}, [][]string{{"stop", "--", "demo.service"}, {"disable", "--", "demo.service"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSystemdFixture()
			fixture.records["demo.service"] = test.before
			selected, err := selectSystem(testContext(t), fixture.effects())
			if err != nil {
				t.Fatal(err)
			}
			fixture.calls = nil
			planned, err := selected.Plan(testContext(t), Demand{value: test.desired})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range planned.Operations() {
				result, err := operation.Apply(testContext(t), postContext(t), selected)
				if err != nil || !result.Started() || result.Decision().Kind() != Exact {
					t.Fatalf("apply=%#v,%v", result, err)
				}
			}
			var mutations [][]string
			for _, call := range fixture.calls {
				for _, verb := range []string{"enable", "disable", "start", "stop"} {
					if slices.Contains(call, verb) {
						mutations = append(mutations, call)
					}
				}
			}
			if !reflect.DeepEqual(mutations, test.want) {
				t.Fatalf("mutations=%#v", mutations)
			}
		})
	}
}

func TestOperationStaleAndCommandFailurePostStateLaw(t *testing.T) {
	for _, changes := range []bool{false, true} {
		t.Run(fmt.Sprintf("desired=%t", changes), func(t *testing.T) {
			fixture := newSystemdFixture()
			fixture.records["demo.service"] = unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}
			selected, _ := selectSystem(testContext(t), fixture.effects())
			planned, _ := selected.Plan(testContext(t), Demand{value: demand{unit: "demo.service", persistence: wantOn}})
			operation := planned.Operations()[0]
			fixture.mutationFailure = true
			fixture.mutationChanges = changes
			result, err := operation.Apply(testContext(t), postContext(t), selected)
			if changes && (err != nil || result.Decision().Kind() != Exact) {
				t.Fatalf("exact post-state=%#v,%v", result, err)
			}
			if !changes && (err == nil || !result.Started()) {
				t.Fatalf("failed post-state=%#v,%v", result, err)
			}
		})
	}
	fixture := newSystemdFixture()
	fixture.records["demo.service"] = unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}
	selected, _ := selectSystem(testContext(t), fixture.effects())
	planned, _ := selected.Plan(testContext(t), Demand{value: demand{unit: "demo.service", runtime: wantOn}})
	operation := planned.Operations()[0]
	fixture.records["demo.service"] = unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "active", sub: "running"}
	fixture.calls = nil
	if result, err := operation.Apply(testContext(t), postContext(t), selected); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("stale=%#v,%v", result, err)
	}
	for _, call := range fixture.calls {
		if slices.Contains(call, "start") {
			t.Fatalf("stale operation mutated: %#v", fixture.calls)
		}
	}
}

func TestExactUserOperationKeepsMachineEndpoint(t *testing.T) {
	fixture := newSystemdFixture()
	fixture.records["pipewire.service"] = unitRecord{id: "pipewire.service", load: "loaded", unitFile: "enabled", active: "inactive", sub: "dead"}
	principal, _ := NewPrincipal("alice", 1000, "/home/alice")
	selected, err := selectUser(testContext(t), fixture.effects(), principal)
	if err != nil {
		t.Fatal(err)
	}
	fixture.calls = nil
	planned, err := selected.Plan(testContext(t), Demand{value: demand{unit: "pipewire.service", runtime: wantOn, user: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	operation := planned.Operations()[0]
	driftedFixture := newSystemdFixture()
	driftedFixture.home.inode = 99
	drifted, err := selectUser(testContext(t), driftedFixture.effects(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := operation.Apply(testContext(t), postContext(t), drifted); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("home drift=%#v,%v", result, err)
	}
	if _, err := operation.Apply(testContext(t), postContext(t), selected); err != nil {
		t.Fatal(err)
	}
	if !containsArgs(fixture.calls, []string{"--user", "--machine=1000@.host", "start", "--", "pipewire.service"}) {
		t.Fatalf("calls=%#v", fixture.calls)
	}
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
func serviceIdentity(path string, marker byte) linuxexec.Identity {
	value := linuxexec.Identity{Path: path}
	value.Digest[0] = marker
	return value
}
func containsArgs(calls [][]string, want []string) bool {
	for _, call := range calls {
		if reflect.DeepEqual(call, want) {
			return true
		}
	}
	return false
}
