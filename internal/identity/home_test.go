package identity

import (
	"errors"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

type memoryHomes struct {
	states    map[string]homeState
	calls     []string
	createErr error
	modeErr   error
}

func newMemoryHomes() *memoryHomes { return &memoryHomes{states: make(map[string]homeState)} }

func (homes *memoryHomes) effects() homeEffects {
	return homeEffects{
		observe: func(path string) (homeState, error) {
			homes.calls = append(homes.calls, "observe:"+path)
			state, ok := homes.states[path]
			if !ok {
				return homeState{trusted: true}, nil
			}
			return state, nil
		},
		create: func(path string, uid, gid uint32) (bool, error) {
			homes.calls = append(homes.calls, "create:"+path)
			if homes.createErr != nil {
				return true, homes.createErr
			}
			if homes.states[path].exists {
				return false, errors.New("collision")
			}
			homes.states[path] = homeState{exists: true, trusted: true, directory: true, uid: uid, gid: gid, mode: 0o700}
			return true, nil
		},
		chmod: func(path string, mode uint16) (bool, error) {
			homes.calls = append(homes.calls, "chmod:"+path)
			if homes.modeErr != nil {
				return true, homes.modeErr
			}
			state := homes.states[path]
			state.mode = mode
			homes.states[path] = state
			return true, nil
		},
	}
}

func TestHomeAndModeAreIndependentGuardedOperations(t *testing.T) {
	fixture := newShadowFixture()
	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000}
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity})
	homes := newMemoryHomes()
	selected.effects.home = homes.effects()
	home, mode, account := projectedHome(t)

	planned, err := selected.PlanHome(testContext(t), home, account)
	if err != nil || planned.Decision().Kind() != Change {
		t.Fatalf("PlanHome = %#v, %v", planned, err)
	}
	operation, _ := planned.Operation()
	result, err := operation.Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact {
		t.Fatalf("Apply home = %#v, %v", result, err)
	}
	if state := homes.states["/home/alice"]; state.mode != 0o700 || state.uid != 1000 || state.gid != 1000 {
		t.Fatalf("created state = %#v", state)
	}

	planned, err = selected.PlanHomeMode(testContext(t), mode, account)
	if err != nil || planned.Decision().Kind() != Change {
		t.Fatalf("PlanHomeMode = %#v, %v", planned, err)
	}
	operation, _ = planned.Operation()
	result, err = operation.Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact || homes.states["/home/alice"].mode != 0o750 {
		t.Fatalf("Apply mode = %#v, %v, state=%#v", result, err, homes.states["/home/alice"])
	}
	if !reflect.DeepEqual(homes.calls, []string{"observe:/home/alice", "observe:/home/alice", "create:/home/alice", "observe:/home/alice", "observe:/home/alice", "observe:/home/alice", "chmod:/home/alice", "observe:/home/alice"}) {
		t.Fatalf("home calls = %v", homes.calls)
	}
	if planned, err := selected.PlanHome(testContext(t), home, account); err != nil || planned.Decision().Kind() != Exact {
		t.Fatalf("exact home = %#v, %v", planned, err)
	}
	if planned, err := selected.PlanHomeMode(testContext(t), mode, account); err != nil || planned.Decision().Kind() != Exact {
		t.Fatalf("exact home mode = %#v, %v", planned, err)
	}
}

func TestHomeBlocksUnsafeExistingObjectsAndStaleState(t *testing.T) {
	fixture := newShadowFixture()
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity})
	homes := newMemoryHomes()
	selected.effects.home = homes.effects()
	home, _, account := projectedHome(t)

	homes.states["/home/alice"] = homeState{exists: true, trusted: true, directory: false, uid: 1000, gid: 1000, mode: 0o700}
	if planned, _ := selected.PlanHome(testContext(t), home, account); planned.Decision().Kind() != Blocked {
		t.Fatalf("non-directory = %v", planned.Decision().Kind())
	}
	homes.states["/home/alice"] = homeState{exists: true, trusted: false, directory: true, uid: 1000, gid: 1000, mode: 0o700}
	if planned, _ := selected.PlanHome(testContext(t), home, account); planned.Decision().Kind() != Blocked {
		t.Fatalf("untrusted ancestry = %v", planned.Decision().Kind())
	}

	delete(homes.states, "/home/alice")
	if planned, _ := selected.PlanHomeMode(testContext(t), projectedMode(t), account); planned.Decision().Kind() != Blocked {
		t.Fatalf("mode without exact home = %#v", planned)
	}
	planned, _ := selected.PlanHome(testContext(t), home, account)
	operation, _ := planned.Operation()
	homes.states["/home/alice"] = homeState{exists: true, trusted: true, directory: true, uid: 1000, gid: 1000, mode: 0o700}
	if result, err := operation.Apply(testContext(t), postContext(t), selected); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("stale home = %#v, %v", result, err)
	}
}

func projectedMode(t *testing.T) model.HomeMode {
	_, mode, _ := projectedHome(t)
	return mode
}

func projectedHome(t *testing.T) (model.Home, model.HomeMode, model.Account) {
	t.Helper()
	group, _ := model.NewGroupKey("wheel")
	account, _ := model.NewAccountKey("alice")
	groupResource, _ := model.NewManagedGroup(group, 1000)
	accountResource, _ := model.NewManagedAccount(account, 1000, group, "/home/alice")
	homeResource, _ := model.NewHome(account)
	modeResource, _ := model.NewHomeMode(account, 0o750)
	provenance, _ := model.NewProvenance("home-test")
	resources := []model.Resource{groupResource, accountResource, homeResource, modeResource}
	contributions := make([]model.Contribution, 0, len(resources))
	for _, resource := range resources {
		contribution, _ := model.Contribute(resource, provenance)
		contributions = append(contributions, contribution)
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	var home model.Home
	var mode model.HomeMode
	var accountView model.Account
	for _, node := range graph.Nodes() {
		if value, ok := model.HomeOf(node); ok {
			home = value
		}
		if value, ok := model.HomeModeOf(node); ok {
			mode = value
		}
		if value, ok := model.AccountOf(node); ok {
			accountView = value
		}
	}
	return home, mode, accountView
}
