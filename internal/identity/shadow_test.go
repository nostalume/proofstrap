package identity

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

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/model"
)

type shadowFixture struct {
	identities map[string]linux.Identity
	groups     map[string]groupRecord
	accounts   map[string]passwdRecord
	locked     map[string]bool
	calls      []string
}

func newShadowFixture() *shadowFixture {
	paths := []string{getentPath, groupaddPath, useraddPath, usermodPath, passwdPath, gpasswdPath}
	fixture := &shadowFixture{identities: make(map[string]linux.Identity), groups: make(map[string]groupRecord), accounts: make(map[string]passwdRecord), locked: make(map[string]bool)}
	for index, path := range paths {
		fixture.identities[path] = shadowIdentity(path, byte(index+1))
	}
	fixture.groups["root"] = groupRecord{name: "root", gid: 0}
	fixture.accounts["root"] = passwdRecord{name: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/sh"}
	return fixture
}

func (fixture *shadowFixture) effects() shadowEffects {
	return shadowEffects{
		identify: func(path string) (linux.Identity, error) {
			identity, ok := fixture.identities[path]
			if !ok {
				return linux.Identity{}, os.ErrNotExist
			}
			return identity, nil
		},
		run: fixture.run,
	}
}

func (fixture *shadowFixture) run(_ context.Context, executable linux.Identity, args []string, _ []byte) (linux.Result, error) {
	call := executable.Path + " " + strings.Join(args, " ")
	fixture.calls = append(fixture.calls, call)
	switch executable.Path {
	case getentPath:
		return fixture.getent(args), nil
	case groupaddPath:
		gid := uint32(0)
		fmt.Sscan(args[1], &gid)
		fixture.groups[args[3]] = groupRecord{name: args[3], gid: gid}
		return linux.Result{Started: true, ExitCode: 0}, nil
	case useraddPath:
		uid, gid := uint32(0), uint32(0)
		fmt.Sscan(args[1], &uid)
		fmt.Sscan(args[3], &gid)
		name := args[len(args)-1]
		fixture.accounts[name] = passwdRecord{name: name, uid: uid, gid: gid, home: args[5], shell: "/bin/sh"}
		fixture.locked[name] = true
		return linux.Result{Started: true, ExitCode: 0}, nil
	case passwdPath:
		if args[0] == "-l" {
			fixture.locked[args[1]] = true
			return linux.Result{Started: true, ExitCode: 0}, nil
		}
		name := args[1]
		status := "P"
		if fixture.locked[name] {
			status = "L"
		}
		return linux.Result{Started: true, ExitCode: 0, Stdout: []byte(name + " " + status + " 08/15/2026 0 99999 7 -1\n")}, nil
	case usermodPath:
		if args[0] != "--shell" {
			return linux.Result{}, fmt.Errorf("unexpected usermod args %v", args)
		}
		record := fixture.accounts[args[3]]
		record.shell = args[1]
		fixture.accounts[args[3]] = record
		return linux.Result{Started: true, ExitCode: 0}, nil
	case gpasswdPath:
		account, group := args[1], args[2]
		record := fixture.groups[group]
		if args[0] == "--add" && !slices.Contains(record.members, account) {
			record.members = append(record.members, account)
			slices.Sort(record.members)
		}
		if args[0] == "--delete" {
			record.members = slices.DeleteFunc(record.members, func(value string) bool { return value == account })
		}
		fixture.groups[group] = record
		return linux.Result{Started: true, ExitCode: 0}, nil
	default:
		return linux.Result{}, fmt.Errorf("unexpected call %s", call)
	}
}

func (fixture *shadowFixture) getent(args []string) linux.Result {
	local := len(args) == 4
	database, key := args[len(args)-2], args[len(args)-1]
	_ = local
	if database == "group" {
		for _, record := range fixture.groups {
			if key == record.name || key == fmt.Sprint(record.gid) {
				return linux.Result{Started: true, Stdout: []byte(fmt.Sprintf("%s:x:%d:%s\n", record.name, record.gid, strings.Join(record.members, ",")))}
			}
		}
	} else {
		for _, record := range fixture.accounts {
			if key == record.name || key == fmt.Sprint(record.uid) {
				return linux.Result{Started: true, Stdout: []byte(fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n", record.name, record.uid, record.gid, record.gecos, record.home, record.shell))}
			}
		}
	}
	return linux.Result{Started: true, ExitCode: 2}
}

func TestSelectShadowProvesNSSAndOnlyRequiredTools(t *testing.T) {
	fixture := newShadowFixture()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	selected, err := selectShadow(ctx, fixture.effects(), []Capability{ObserveIdentity, CreateGroup})
	if err != nil {
		t.Fatal(err)
	}
	if !selected.valid() || len(selected.evidence.tools) != 2 || selected.evidence.tools[0].name != "getent" || selected.evidence.tools[1].name != "groupadd" {
		t.Fatalf("selection = %#v", selected)
	}
	for _, forbidden := range []string{useraddPath, usermodPath, passwdPath, gpasswdPath} {
		for _, call := range fixture.calls {
			if strings.HasPrefix(call, forbidden+" ") {
				t.Fatalf("unrequired tool invoked: %s", call)
			}
		}
	}
}

func TestSelectShadowClassifiesMissingRequiredToolAsUnsupported(t *testing.T) {
	fixture := newShadowFixture()
	delete(fixture.identities, groupaddPath)
	if _, err := selectShadow(testContext(t), fixture.effects(), []Capability{ObserveIdentity, CreateGroup}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing groupadd = %v", err)
	}
}

func TestGroupOperationGuardsMutatesAndPostVerifies(t *testing.T) {
	fixture := newShadowFixture()
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, CreateGroup})
	desired := projectedGroup(t, "wheel", true, 1000)
	planned, err := selected.PlanGroup(testContext(t), desired)
	if err != nil || planned.Decision().Kind() != Change {
		t.Fatalf("PlanGroup = %#v, %v", planned, err)
	}
	operation, ok := planned.Operation()
	if !ok {
		t.Fatal("change has no operation")
	}
	result, err := operation.Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact {
		t.Fatalf("Apply = %#v, %v", result, err)
	}
	want := groupaddPath + " --gid 1000 -- wheel"
	if !containsCall(fixture.calls, want) {
		t.Fatalf("calls lack %q: %v", want, fixture.calls)
	}
}

func TestGroupOperationRejectsFreshEvidenceAndObservationDrift(t *testing.T) {
	fixture := newShadowFixture()
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, CreateGroup})
	planned, _ := selected.PlanGroup(testContext(t), projectedGroup(t, "wheel", true, 1000))
	operation, _ := planned.Operation()

	drifted := *selected
	drifted.evidence.tools = append([]toolEvidence(nil), selected.evidence.tools...)
	drifted.evidence.tools[1].identity.Digest[0]++
	if result, err := operation.Apply(testContext(t), postContext(t), &drifted); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("evidence drift = %#v, %v", result, err)
	}

	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1001}
	if result, err := operation.Apply(testContext(t), postContext(t), selected); !errors.Is(err, ErrStale) || result.Started() {
		t.Fatalf("observation drift = %#v, %v", result, err)
	}
}

func TestCommandFailureUsesIndependentPostState(t *testing.T) {
	for _, desiredReached := range []bool{false, true} {
		t.Run(fmt.Sprintf("desired=%t", desiredReached), func(t *testing.T) {
			fixture := newShadowFixture()
			selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, CreateGroup})
			planned, _ := selected.PlanGroup(testContext(t), projectedGroup(t, "wheel", true, 1000))
			operation, _ := planned.Operation()
			original := selected.effects.run
			selected.effects.run = func(ctx context.Context, executable linux.Identity, args []string, stdin []byte) (linux.Result, error) {
				if executable.Path == groupaddPath {
					if desiredReached {
						fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000}
					}
					return linux.Result{Started: true, ExitCode: 7, Stderr: []byte("native failure")}, nil
				}
				return original(ctx, executable, args, stdin)
			}
			result, err := operation.Apply(testContext(t), postContext(t), selected)
			if desiredReached && (err != nil || result.Decision().Kind() != Exact) {
				t.Fatalf("desired post-state did not win: %#v, %v", result, err)
			}
			if !desiredReached && (err == nil || !result.Started()) {
				t.Fatalf("undesired post-state hid failure: %#v, %v", result, err)
			}
		})
	}
}

func TestAccountOperationSuppressesImplicitResourcesAndProvesLock(t *testing.T) {
	fixture := newShadowFixture()
	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000}
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, CreateAccount, ObserveLock})
	desired := projectedAccount(t, "alice", true, 1000, "wheel", "/home/alice")
	primary := projectedGroup(t, "wheel", true, 1000)
	planned, err := selected.PlanAccount(testContext(t), desired, primary)
	if err != nil || planned.Decision().Kind() != Change {
		t.Fatalf("PlanAccount = %#v, %v", planned, err)
	}
	operation, _ := planned.Operation()
	result, err := operation.Apply(testContext(t), postContext(t), selected)
	if err != nil || !result.Started() || result.Decision().Kind() != Exact {
		t.Fatalf("Apply account = %#v, %v", result, err)
	}
	want := useraddPath + " --uid 1000 --gid 1000 --home-dir /home/alice --no-create-home --no-user-group -- alice"
	if !containsCall(fixture.calls, want) || !containsCall(fixture.calls, passwdPath+" -S alice") {
		t.Fatalf("account calls = %v", fixture.calls)
	}
}

func TestExternalAccountNeedsNoPrimaryGroupAndReturnsExactFact(t *testing.T) {
	fixture := newShadowFixture()
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 100, home: "/home/alice", shell: "/bin/sh"}
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity})
	planned, err := selected.PlanAccount(testContext(t), projectedAccount(t, "alice", false, 0, "", ""), model.Group{})
	if err != nil || planned.Decision().Kind() != Exact {
		t.Fatalf("plan=%#v,%v", planned, err)
	}
	fact, ok := planned.AccountFact()
	if !ok || fact.Name() != "alice" || fact.UID() != 1000 || fact.GID() != 100 || fact.Home() != "/home/alice" {
		t.Fatalf("fact=%#v,%t", fact, ok)
	}
	if _, ok := planned.Operation(); ok {
		t.Fatal("external exact account has operation")
	}
}

func TestLockShellAndMembershipOperationsAreIndependent(t *testing.T) {
	fixture := newShadowFixture()
	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000, members: []string{"bob"}}
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}
	fixture.locked["alice"] = false
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, ObserveLock, ModifyAccount, ModifyMembership})

	lockView, shellView, membershipView := projectedEdges(t)
	for name, plan := range map[string]func() (Planned, error){
		"lock":       func() (Planned, error) { return selected.PlanLock(testContext(t), lockView) },
		"shell":      func() (Planned, error) { return selected.PlanShell(testContext(t), shellView) },
		"membership": func() (Planned, error) { return selected.PlanMembership(testContext(t), membershipView) },
	} {
		t.Run(name, func(t *testing.T) {
			planned, err := plan()
			if err != nil || planned.Decision().Kind() != Change {
				t.Fatalf("plan = %#v, %v", planned, err)
			}
			operation, ok := planned.Operation()
			if !ok {
				t.Fatal("change has no operation")
			}
			result, err := operation.Apply(testContext(t), postContext(t), selected)
			if err != nil || !result.Started() || result.Decision().Kind() != Exact {
				t.Fatalf("apply = %#v, %v", result, err)
			}
		})
	}

	if !containsCall(fixture.calls, passwdPath+" -l alice") ||
		!containsCall(fixture.calls, usermodPath+" --shell /bin/zsh -- alice") ||
		!containsCall(fixture.calls, gpasswdPath+" --add alice wheel") {
		t.Fatalf("edge calls = %v", fixture.calls)
	}
	if !reflect.DeepEqual(fixture.groups["wheel"].members, []string{"alice", "bob"}) {
		t.Fatalf("unrelated membership lost: %v", fixture.groups["wheel"].members)
	}
}

func TestIdentityEdgePlansCoverExactAndBlocked(t *testing.T) {
	fixture := newShadowFixture()
	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000, members: []string{"alice"}}
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/zsh"}
	fixture.locked["alice"] = true
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, ObserveLock, ModifyAccount, ModifyMembership})
	lock, shell, membership := projectedEdges(t)
	for name, plan := range map[string]func() (Planned, error){
		"lock":       func() (Planned, error) { return selected.PlanLock(testContext(t), lock) },
		"shell":      func() (Planned, error) { return selected.PlanShell(testContext(t), shell) },
		"membership": func() (Planned, error) { return selected.PlanMembership(testContext(t), membership) },
	} {
		t.Run(name+"-exact", func(t *testing.T) {
			planned, err := plan()
			if err != nil || planned.Decision().Kind() != Exact {
				t.Fatalf("plan = %#v, %v", planned, err)
			}
			if _, ok := planned.Operation(); ok {
				t.Fatal("exact plan has operation")
			}
		})
	}

	delete(fixture.accounts, "alice")
	if planned, _ := selected.PlanShell(testContext(t), shell); planned.Decision().Kind() != Blocked {
		t.Fatalf("missing shell account = %#v", planned)
	}
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/zsh"}
	delete(fixture.groups, "wheel")
	if planned, _ := selected.PlanMembership(testContext(t), membership); planned.Decision().Kind() != Blocked {
		t.Fatalf("missing membership group = %#v", planned)
	}
	withoutLock := mustSelectShadow(t, fixture, []Capability{ObserveIdentity})
	if planned, _ := withoutLock.PlanLock(testContext(t), lock); planned.Decision().Kind() != Blocked {
		t.Fatalf("unavailable lock observer = %#v", planned)
	}
}

func TestMembershipRemovalPreservesUnrelatedMembers(t *testing.T) {
	fixture := newShadowFixture()
	fixture.groups["wheel"] = groupRecord{name: "wheel", gid: 1000, members: []string{"alice", "bob"}}
	fixture.accounts["alice"] = passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}
	selected := mustSelectShadow(t, fixture, []Capability{ObserveIdentity, ModifyMembership})
	desired := projectedMembership(t, false)
	planned, err := selected.PlanMembership(testContext(t), desired)
	if err != nil || planned.Decision().Kind() != Change {
		t.Fatalf("plan = %#v, %v", planned, err)
	}
	operation, _ := planned.Operation()
	result, err := operation.Apply(testContext(t), postContext(t), selected)
	if err != nil || result.Decision().Kind() != Exact || !reflect.DeepEqual(fixture.groups["wheel"].members, []string{"bob"}) {
		t.Fatalf("remove = %#v, %v, members=%v", result, err, fixture.groups["wheel"].members)
	}
}

func projectedMembership(t *testing.T, present bool) model.Membership {
	t.Helper()
	account, _ := model.NewAccountKey("alice")
	group, _ := model.NewGroupKey("wheel")
	resources := []model.Resource{}
	accountResource, _ := model.NewExternalAccount(account)
	groupResource, _ := model.NewExternalGroup(group)
	membershipResource, _ := model.NewMembership(account, group, present)
	resources = append(resources, accountResource, groupResource, membershipResource)
	provenance, _ := model.NewProvenance("membership-test")
	var contributions []model.Contribution
	for _, resource := range resources {
		contribution, _ := model.Contribute(resource, provenance)
		contributions = append(contributions, contribution)
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range graph.Nodes() {
		if value, ok := model.MembershipOf(node); ok {
			return value
		}
	}
	t.Fatal("membership projection missing")
	return model.Membership{}
}

func projectedEdges(t *testing.T) (model.AccountLock, model.AccountShell, model.Membership) {
	t.Helper()
	account, _ := model.NewAccountKey("alice")
	group, _ := model.NewGroupKey("wheel")
	accountResource, _ := model.NewExternalAccount(account)
	groupResource, _ := model.NewExternalGroup(group)
	lockResource, _ := model.NewAccountLock(account)
	shellResource, _ := model.NewAccountShell(account, "/bin/zsh")
	membershipResource, _ := model.NewMembership(account, group, true)
	provenance, _ := model.NewProvenance("identity-edge-test")
	resources := []model.Resource{accountResource, groupResource, lockResource, shellResource, membershipResource}
	contributions := make([]model.Contribution, 0, len(resources))
	for _, resource := range resources {
		contribution, _ := model.Contribute(resource, provenance)
		contributions = append(contributions, contribution)
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		t.Fatal(err)
	}
	var lock model.AccountLock
	var shell model.AccountShell
	var membership model.Membership
	for _, node := range graph.Nodes() {
		if value, ok := model.AccountLockOf(node); ok {
			lock = value
		}
		if value, ok := model.AccountShellOf(node); ok {
			shell = value
		}
		if value, ok := model.MembershipOf(node); ok {
			membership = value
		}
	}
	return lock, shell, membership
}

func mustSelectShadow(t *testing.T, fixture *shadowFixture, capabilities []Capability) *Selected {
	t.Helper()
	selected, err := selectShadow(testContext(t), fixture.effects(), capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return selected
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

func containsCall(calls []string, want string) bool {
	return slices.Contains(calls, want)
}

func shadowIdentity(path string, marker byte) linux.Identity {
	identity := linux.Identity{Path: path}
	identity.Digest[0] = marker
	return identity
}
