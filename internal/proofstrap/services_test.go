package proofstrap

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestServiceObservationKindMakesMissingExplicit(t *testing.T) {
	need := serviceNeed{key: "networkmanager", scope: SystemService, target: serviceActive}
	state := serviceObservationAt(serviceObservations{}, resolvedServiceNeed{need: need, unit: "NetworkManager.service"})
	missing, ok := state.(serviceMissing)
	if !ok || missing.need != need || missing.unit != "NetworkManager.service" || serviceObservationDetail(state) != "observation is missing" {
		t.Fatalf("state=%#v detail=%q", state, serviceObservationDetail(state))
	}
}

func TestSystemdAdmissionIsExact(t *testing.T) {
	if err := requireSystemd("systemd"); err != nil {
		t.Fatal(err)
	}
	if err := requireSystemd("openrc"); err == nil || err.Error() != `unsupported service manager "openrc"` {
		t.Fatalf("err=%v", err)
	}
}

func TestServiceTargetPrecedenceNamesEnableBeforeActive(t *testing.T) {
	if serviceTargetPrecedence(serviceEnabled) >= serviceTargetPrecedence(serviceActive) {
		t.Fatal("service enable must precede service start")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown service target was assigned an execution precedence")
		}
	}()
	serviceTargetPrecedence(0)
}

func TestServiceBehaviorBindsExactProductionUnits(t *testing.T) {
	for _, test := range []struct {
		module string
		want   map[serviceNeed]string
	}{
		{
			module: "network",
			want: map[serviceNeed]string{
				{key: "networkmanager", scope: SystemService, target: serviceEnabled}: "NetworkManager.service",
				{key: "networkmanager", scope: SystemService, target: serviceActive}:  "NetworkManager.service",
			},
		},
		{
			module: "audio",
			want: map[serviceNeed]string{
				{key: "pipewire", scope: UserService, target: serviceEnabled}:    "pipewire.service",
				{key: "pipewire", scope: UserService, target: serviceActive}:     "pipewire.service",
				{key: "wireplumber", scope: UserService, target: serviceEnabled}: "wireplumber.service",
				{key: "wireplumber", scope: UserService, target: serviceActive}:  "wireplumber.service",
			},
		},
	} {
		t.Run(test.module, func(t *testing.T) {
			selected, blockers := production.selectFor(DesiredState{Modules: []string{test.module}})
			if len(blockers) != 0 {
				t.Fatal(blockers)
			}
			demand, blockers := (services{}).bind(selected)
			if len(blockers) != 0 || len(demand.needs) != len(test.want) {
				t.Fatalf("demand=%#v blockers=%#v", demand, blockers)
			}
			for _, need := range demand.needs {
				if unit := test.want[need.need]; unit != need.unit {
					t.Fatalf("need=%#v want unit=%q", need, unit)
				}
			}
		})
	}
}

func TestServicesForUsesPID1NotOSIdentity(t *testing.T) {
	runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}}
	behavior, err := servicesFor("systemd", runner)
	if err != nil || behavior.path != "/usr/bin/systemctl" {
		t.Fatalf("behavior=%#v err=%v", behavior, err)
	}
	if _, err := servicesFor("openrc", runner); err == nil {
		t.Fatal("unsupported service manager was admitted")
	}
}

func TestServiceBehaviorProvesExecutableOnlyWhenObserved(t *testing.T) {
	runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
		"/usr/bin/systemctl is-active NetworkManager.service": {{ExitCode: 0, Stdout: "active\n"}},
	}}
	behavior, err := servicesFor("systemd", runner)
	if err != nil {
		t.Fatal(err)
	}
	need := resolvedServiceNeed{need: serviceNeed{key: "networkmanager", scope: SystemService, target: serviceActive}, unit: "NetworkManager.service"}
	observed := behavior.observe(context.Background(), runner, []resolvedServiceNeed{need})
	if _, ok := observed[need.need].(serviceSatisfied); !ok {
		t.Fatalf("observed=%#v", observed)
	}
	if !reflect.DeepEqual(runner.pathCalls, []string{"systemctl"}) {
		t.Fatalf("LookPath=%#v", runner.pathCalls)
	}
}

func TestServiceClassificationRequiresExactState(t *testing.T) {
	need := serviceNeed{key: "pipewire", scope: UserService, target: serviceActive}
	for _, test := range []struct {
		name   string
		result Result
		kind   string
	}{
		{"active", Result{ExitCode: 0, Stdout: "active\n"}, "satisfied"},
		{"inactive", Result{ExitCode: 3, Stdout: "inactive\n"}, "unsatisfied"},
		{"nonzero active contradiction", Result{ExitCode: 3, Stdout: "active\n"}, "indeterminate"},
		{"zero inactive contradiction", Result{ExitCode: 0, Stdout: "inactive\n"}, "indeterminate"},
		{"exit zero malformed", Result{ExitCode: 0, Stdout: "mystery\n"}, "indeterminate"},
		{"not found", Result{ExitCode: 4, Stdout: "not-found\n"}, "indeterminate"},
		{"masked", Result{ExitCode: 1, Stdout: "masked\n"}, "indeterminate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := classifyService(need, "pipewire.service", test.result)
			switch test.kind {
			case "satisfied":
				if _, ok := observed.(serviceSatisfied); !ok {
					t.Fatalf("observed=%#v", observed)
				}
			case "unsatisfied":
				if _, ok := observed.(serviceUnsatisfied); !ok {
					t.Fatalf("observed=%#v", observed)
				}
			case "indeterminate":
				if _, ok := observed.(serviceIndeterminate); !ok {
					t.Fatalf("observed=%#v", observed)
				}
			}
		})
	}
}

func TestEnabledClassificationRequiresCompatibleExitStatus(t *testing.T) {
	need := serviceNeed{key: "networkmanager", scope: SystemService, target: serviceEnabled}
	for _, result := range []Result{
		{ExitCode: 1, Stdout: "enabled\n"},
		{ExitCode: 0, Stdout: "disabled\n"},
	} {
		observed := classifyService(need, "NetworkManager.service", result)
		if _, ok := observed.(serviceIndeterminate); !ok {
			t.Fatalf("result=%#v observed=%#v", result, observed)
		}
	}
}

func TestServiceInspectionRejectsMissingAndExtraRows(t *testing.T) {
	behavior := services{path: "/usr/bin/systemctl"}
	first := resolvedServiceNeed{need: serviceNeed{key: "pipewire", scope: UserService, target: serviceEnabled}, unit: "pipewire.service"}
	second := resolvedServiceNeed{need: serviceNeed{key: "wireplumber", scope: UserService, target: serviceEnabled}, unit: "wireplumber.service"}
	for _, output := range []string{"enabled\n", "enabled\nenabled\nenabled\n"} {
		runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
			"/usr/bin/systemctl --user is-enabled pipewire.service wireplumber.service": {{ExitCode: 1, Stdout: output}},
		}}
		observed := behavior.observe(context.Background(), runner, []resolvedServiceNeed{first, second})
		if _, ok := observed[first.need].(serviceIndeterminate); !ok {
			t.Fatalf("output=%q first=%#v", output, observed[first.need])
		}
		if _, ok := observed[second.need].(serviceIndeterminate); !ok {
			t.Fatalf("output=%q second=%#v", output, observed[second.need])
		}
	}
}

func TestServiceInspectionClassifiesEachMixedBatchRowDespiteExistentialExit(t *testing.T) {
	behavior := services{path: "/usr/bin/systemctl"}
	for _, test := range []struct {
		name      string
		target    serviceTarget
		satisfied string
		other     string
	}{
		{name: "active and failed", target: serviceActive, satisfied: "active", other: "failed"},
		{name: "enabled and disabled", target: serviceEnabled, satisfied: "enabled", other: "disabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := resolvedServiceNeed{need: serviceNeed{key: "pipewire", scope: UserService, target: test.target}, unit: "pipewire.service"}
			second := resolvedServiceNeed{need: serviceNeed{key: "wireplumber", scope: UserService, target: test.target}, unit: "wireplumber.service"}
			verb := "is-active"
			if test.target == serviceEnabled {
				verb = "is-enabled"
			}
			runner := &testRunner{results: map[string][]Result{
				"/usr/bin/systemctl --user " + verb + " pipewire.service wireplumber.service": {{ExitCode: 0, Stdout: test.satisfied + "\n" + test.other + "\n"}},
			}}
			observed := behavior.observe(context.Background(), runner, []resolvedServiceNeed{second, first})
			if _, ok := observed[first.need].(serviceSatisfied); !ok {
				t.Fatalf("first=%#v", observed[first.need])
			}
			if _, ok := observed[second.need].(serviceUnsatisfied); !ok {
				t.Fatalf("second=%#v", observed[second.need])
			}
		})
	}
}

func TestServiceReconciliationBuildsCanonicalPrivateStep(t *testing.T) {
	behavior := services{path: "/usr/bin/systemctl"}
	needs := []resolvedServiceNeed{
		{need: serviceNeed{key: "wireplumber", scope: UserService, target: serviceActive}, unit: "wireplumber.service"},
		{need: serviceNeed{key: "pipewire", scope: UserService, target: serviceActive}, unit: "pipewire.service"},
	}
	observed := serviceObservations{
		needs[0].need: serviceUnsatisfied{need: needs[0].need, unit: needs[0].unit, detail: "inactive"},
		needs[1].need: serviceUnsatisfied{need: needs[1].need, unit: needs[1].unit, detail: "inactive"},
	}
	_, changes, blockers := behavior.reconcile(needs, observed)
	if len(blockers) != 0 || len(changes) != 1 {
		t.Fatalf("changes=%#v blockers=%#v", changes, blockers)
	}
	step, err := behavior.step(changes[0])
	if err != nil {
		t.Fatal(err)
	}
	want := Command{Name: "/usr/bin/systemctl", Args: []string{"--user", "start", "pipewire.service", "wireplumber.service"}}
	if !reflect.DeepEqual(step.command, want) || step.id != "services:user:start" || step.access != directStep {
		t.Fatalf("step=%#v", step)
	}
	projection := step.projectionFor(step.command)
	if projection.Command == nil || !reflect.DeepEqual(*projection.Command, want) {
		t.Fatalf("projection=%#v", projection)
	}
}

func TestServicePostStateReportsPartialGroupedMutationPerUnit(t *testing.T) {
	behavior := services{path: "/usr/bin/systemctl"}
	needs := []resolvedServiceNeed{
		{need: serviceNeed{key: "pipewire", scope: UserService, target: serviceActive}, unit: "pipewire.service"},
		{need: serviceNeed{key: "wireplumber", scope: UserService, target: serviceActive}, unit: "wireplumber.service"},
	}
	step, err := behavior.step(serviceChange{scope: UserService, target: serviceActive, needs: needs})
	if err != nil {
		t.Fatal(err)
	}
	runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
		"/usr/bin/systemctl --user is-active pipewire.service":    {{ExitCode: 0, Stdout: "active\n"}},
		"/usr/bin/systemctl --user is-active wireplumber.service": {{ExitCode: 3, Stdout: "inactive\n"}},
	}}
	satisfied, detail := step.verify(context.Background(), runner)
	if satisfied || !strings.Contains(detail, "pipewire.service=satisfied") || !strings.Contains(detail, "wireplumber.service=unsatisfied") {
		t.Fatalf("satisfied=%t detail=%q calls=%#v", satisfied, detail, runner.calls)
	}
}

func TestAbortServiceConflictUsesDecisiveActiveState(t *testing.T) {
	behavior := services{path: "/usr/bin/systemctl"}
	conflict := resolvedServiceConflict{
		wantedKey: "wanted", otherKey: "other", scope: SystemService,
		wantedUnit: "Wanted.service", otherUnit: "Other.service",
	}
	for _, test := range []struct {
		name     string
		result   Result
		blocked  bool
		factPart string
	}{
		{name: "active blocks", result: Result{ExitCode: 0, Stdout: "active\n"}, blocked: true},
		{name: "inactive clears", result: Result{ExitCode: 3, Stdout: "inactive\n"}, factPart: "inactive"},
		{name: "unknown blocks", result: Result{ExitCode: 1, Stdout: "mystery\n"}, blocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{paths: map[string]string{"systemctl": "/usr/bin/systemctl"}, results: map[string][]Result{
				"/usr/bin/systemctl is-active Other.service": {test.result},
			}}
			observed := behavior.observeConflicts(context.Background(), runner, []resolvedServiceConflict{conflict})
			facts, blockers := behavior.reconcileConflicts(observed)
			if (len(blockers) != 0) != test.blocked {
				t.Fatalf("facts=%#v blockers=%#v", facts, blockers)
			}
			if test.factPart != "" && (len(facts) != 1 || !strings.Contains(facts[0].Detail, test.factPart)) {
				t.Fatalf("facts=%#v", facts)
			}
		})
	}
}
