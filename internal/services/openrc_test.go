package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
)

type openRCFixture struct {
	status     map[string]string
	runlevels  map[string][]string
	calls      [][]string
	noChange   bool
	settle     int
	transition string
	commandErr bool
}

func newOpenRCFixture() *openRCFixture {
	return &openRCFixture{status: map[string]string{"sshd": "stopped"}, runlevels: map[string][]string{"sshd": nil}}
}

func (fixture *openRCFixture) system() systemEffects {
	return systemEffects{
		identify: func(path string) (linux.Identity, error) {
			if filepath.Dir(path) != "/sbin" {
				return linux.Identity{}, os.ErrNotExist
			}
			switch filepath.Base(path) {
			case "rc-service", "rc-status", "rc-update":
				return serviceIdentity(path, path[len(path)-1]), nil
			default:
				return linux.Identity{}, os.ErrNotExist
			}
		},
		run:  fixture.run,
		euid: func() (uint32, error) { return 0, nil },
	}
}

func (fixture *openRCFixture) openrc() openRCEffects {
	return openRCEffects{
		control: func() error { return nil },
		inspect: func(units []string) (map[string]openRCFileState, error) {
			result := make(map[string]openRCFileState, len(units))
			for _, unit := range units {
				levels, exists := fixture.runlevels[unit]
				result[unit] = openRCFileState{script: exists, runlevels: append([]string(nil), levels...)}
			}
			return result, nil
		},
	}
}

func (fixture *openRCFixture) run(_ context.Context, tool linux.Identity, args []string, _ []byte) (linux.Result, error) {
	fixture.calls = append(fixture.calls, append([]string{filepath.Base(tool.Path)}, args...))
	if reflect.DeepEqual(args, []string{"--version"}) {
		return linux.Result{Started: true, ExitCode: 0, Stdout: []byte(filepath.Base(tool.Path) + " (OpenRC) 0.63.2\n")}, nil
	}
	if reflect.DeepEqual(args, []string{"--runlevel"}) {
		return linux.Result{Started: true, ExitCode: 0, Stdout: []byte("default\n")}, nil
	}
	if reflect.DeepEqual(args, []string{"--format", "ini", "--servicelist"}) {
		var output strings.Builder
		for _, unit := range []string{"sshd"} {
			output.WriteString(unit + " =  " + fixture.status[unit] + " \n")
			if fixture.status[unit] == fixture.transition && fixture.settle > 0 {
				fixture.settle--
				if fixture.settle == 0 {
					fixture.status[unit] = "started"
				}
			}
		}
		return linux.Result{Started: true, ExitCode: 0, Stdout: []byte(output.String())}, nil
	}
	if filepath.Base(tool.Path) == "rc-update" && len(args) == 3 && args[2] == "default" {
		if !fixture.noChange && args[0] == "add" {
			fixture.runlevels[args[1]] = []string{"default"}
		} else if !fixture.noChange && args[0] == "delete" {
			fixture.runlevels[args[1]] = nil
		}
		return linux.Result{Started: true, ExitCode: 0}, nil
	}
	if filepath.Base(tool.Path) == "rc-service" && len(args) == 2 {
		if !fixture.noChange && args[1] == "start" {
			fixture.status[args[0]] = "started"
			if fixture.settle > 0 {
				fixture.status[args[0]] = fixture.transition
			}
		} else if !fixture.noChange && args[1] == "stop" {
			fixture.status[args[0]] = "stopped"
		}
		result := linux.Result{Started: true}
		if fixture.commandErr {
			result.ExitCode = 1
			result.Stderr = []byte("native diagnostic")
		}
		return result, nil
	}
	return linux.Result{}, errors.New("unexpected OpenRC call")
}

func TestOpenRCRuntimeApplySettlesBoundedTransientState(t *testing.T) {
	for _, transition := range []string{"starting", "crashed"} {
		for _, commandErr := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/command-error=%t", transition, commandErr), func(t *testing.T) {
				fixture := newOpenRCFixture()
				fixture.settle = 1
				fixture.transition = transition
				fixture.commandErr = commandErr
				selected, err := selectOpenRCSystem(testContext(t), fixture.system(), fixture.openrc())
				if err != nil {
					t.Fatal(err)
				}
				backend, _ := binding.NewServiceBackendID("openrc")
				id, _ := binding.NewServiceID(backend, "sshd")
				demand, _ := NewDemand(id, model.SystemServiceTarget(), model.UnmanagedEnableIntent(), model.RunningIntent())
				planned, err := selected.Plan(testContext(t), demand)
				if err != nil || len(planned.Operations()) != 1 {
					t.Fatalf("plan = %#v, %v", planned, err)
				}
				result, err := planned.Operations()[0].Apply(testContext(t), postContext(t), selected)
				if err != nil || !result.Started() || result.Decision().Kind() != Exact {
					t.Fatalf("settled apply = %#v, %v", result, err)
				}
			})
		}
	}
}

func TestOpenRCDemandAdmitsOnlySystemScope(t *testing.T) {
	backend, _ := binding.NewServiceBackendID("openrc")
	id, _ := binding.NewServiceID(backend, "sshd")
	if _, err := NewDemand(id, model.SystemServiceTarget(), model.EnabledIntent(), model.RunningIntent()); err != nil {
		t.Fatalf("system OpenRC demand rejected: %v", err)
	}
	account, _ := model.NewAccountKey("alice")
	user, _ := model.UserServiceTarget(account)
	if _, err := NewDemand(id, user, model.EnabledIntent(), model.RunningIntent()); err == nil {
		t.Fatal("user OpenRC demand admitted")
	}
}

func TestOpenRCSelectionReconcileApplyAndReview(t *testing.T) {
	fixture := newOpenRCFixture()
	selected, err := selectOpenRCSystem(testContext(t), fixture.system(), fixture.openrc())
	if err != nil || selected.Backend() != "openrc" {
		t.Fatalf("select OpenRC = %#v, %v", selected, err)
	}
	backend, _ := binding.NewServiceBackendID("openrc")
	id, _ := binding.NewServiceID(backend, "sshd")
	demand, _ := NewDemand(id, model.SystemServiceTarget(), model.EnabledIntent(), model.RunningIntent())
	planned, err := selected.Plan(testContext(t), demand)
	if err != nil || len(planned.Operations()) != 2 {
		t.Fatalf("OpenRC plan = %#v, %v", planned, err)
	}
	wantCalls := [][]string{{"rc-update", "add", "sshd", "default"}, {"rc-service", "sshd", "start"}}
	start := len(fixture.calls)
	for _, operation := range planned.Operations() {
		encoded, err := EncodeReview(operation)
		if err != nil {
			t.Fatal(err)
		}
		review, err := DecodeReview(encoded)
		if err != nil || review.Backend() != "openrc" {
			t.Fatalf("OpenRC review = %#v, %v", review, err)
		}
		reconstructed, err := Reconstruct(review, selected)
		if err != nil {
			t.Fatal(err)
		}
		applied, err := reconstructed.Apply(testContext(t), postContext(t), selected)
		if err != nil || !applied.Started() || applied.Decision().Kind() != Exact {
			t.Fatalf("OpenRC apply = %#v, %v", applied, err)
		}
	}
	var effects [][]string
	for _, call := range fixture.calls[start:] {
		if call[0] == "rc-update" || call[0] == "rc-service" {
			effects = append(effects, call)
		}
	}
	if !reflect.DeepEqual(effects, wantCalls) {
		t.Fatalf("OpenRC effects = %#v, want %#v", effects, wantCalls)
	}
	off, _ := NewDemand(id, model.SystemServiceTarget(), model.DisabledIntent(), model.StoppedIntent())
	planned, err = selected.Plan(testContext(t), off)
	if err != nil || len(planned.Operations()) != 2 {
		t.Fatalf("OpenRC stop plan = %#v, %v", planned, err)
	}
	start = len(fixture.calls)
	for _, operation := range planned.Operations() {
		if _, err := operation.Apply(testContext(t), postContext(t), selected); err != nil {
			t.Fatal(err)
		}
	}
	effects = effects[:0]
	for _, call := range fixture.calls[start:] {
		if call[0] == "rc-update" || call[0] == "rc-service" {
			effects = append(effects, call)
		}
	}
	wantCalls = [][]string{{"rc-service", "sshd", "stop"}, {"rc-update", "delete", "sshd", "default"}}
	if !reflect.DeepEqual(effects, wantCalls) {
		t.Fatalf("OpenRC stop effects = %#v, want %#v", effects, wantCalls)
	}
}

func TestOpenRCNonDefaultAndMalformedStatusBlock(t *testing.T) {
	if statuses, err := parseOpenRCStatus([]byte("device = hotplugged\n")); err != nil || statuses["device"] != "hotplugged" {
		t.Fatalf("documented OpenRC hotplugged state = %v, %v", statuses, err)
	}
	fixture := newOpenRCFixture()
	fixture.runlevels["sshd"] = []string{"boot"}
	selected, err := selectOpenRCSystem(testContext(t), fixture.system(), fixture.openrc())
	if err != nil {
		t.Fatal(err)
	}
	backend, _ := binding.NewServiceBackendID("openrc")
	id, _ := binding.NewServiceID(backend, "sshd")
	demand, _ := NewDemand(id, model.SystemServiceTarget(), model.EnabledIntent(), model.RunningIntent())
	planned, err := selected.Plan(testContext(t), demand)
	if err != nil || planned.Persistence().Kind() != Blocked || len(planned.Operations()) != 0 {
		t.Fatalf("non-default OpenRC plan = %#v, %v", planned, err)
	}
	for _, data := range []string{"sshd =  started ", "[default]\n", "sshd = \n", "sshd = unknown\n", "sshd = stopped\nsshd = started\n"} {
		if _, err := parseOpenRCStatus([]byte(data)); err == nil {
			t.Fatalf("malformed OpenRC status admitted: %q", data)
		}
	}
}

func TestOpenRCRejectsBackendMismatchAndCommandWithoutPostState(t *testing.T) {
	fixture := newOpenRCFixture()
	selected, err := selectOpenRCSystem(testContext(t), fixture.system(), fixture.openrc())
	if err != nil {
		t.Fatal(err)
	}
	systemdBackend, _ := binding.NewServiceBackendID("systemd")
	systemdID, _ := binding.NewServiceID(systemdBackend, "sshd.service")
	systemdDemand, _ := NewDemand(systemdID, model.SystemServiceTarget(), model.UnmanagedEnableIntent(), model.RunningIntent())
	if _, err := selected.Plan(testContext(t), systemdDemand); err == nil {
		t.Fatal("systemd demand admitted by OpenRC selection")
	}
	openRCBackend, _ := binding.NewServiceBackendID("openrc")
	openRCID, _ := binding.NewServiceID(openRCBackend, "sshd")
	openRCDemand, _ := NewDemand(openRCID, model.SystemServiceTarget(), model.EnabledIntent(), model.UnmanagedRunIntent())
	planned, err := selected.Plan(testContext(t), openRCDemand)
	if err != nil {
		t.Fatal(err)
	}
	fixture.noChange = true
	result, err := planned.Operations()[0].Apply(testContext(t), postContext(t), selected)
	if err == nil || !result.Started() || result.Decision().Kind() == Exact {
		t.Fatalf("unchanged OpenRC post-state = %#v, %v", result, err)
	}
}

func TestSelectionRejectsCompetingSystemControlPlanes(t *testing.T) {
	fixture := newOpenRCFixture()
	selected, err := selectOpenRCSystem(testContext(t), fixture.system(), fixture.openrc())
	if err != nil {
		t.Fatal(err)
	}
	selector := func(context.Context) (*Selected, error) { return selected, nil }
	if _, err := selectHostSystem(testContext(t), selector, selector); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("competing service selection = %v", err)
	}
}
