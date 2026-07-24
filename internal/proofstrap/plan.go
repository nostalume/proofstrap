package proofstrap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type stepAccess uint8

const (
	directStep stepAccess = iota + 1
	rootStep
)

type step struct {
	id      string
	detail  string
	command Command
	timeout time.Duration
	access  stepAccess
	manager bool
	before  func(context.Context, Runner) error
	verify  func(context.Context, Runner) (bool, string)
}

type preparedStep struct {
	step       step
	command    Command
	projection Change
}

func newPreparedStep(value step, effective Command) (preparedStep, error) {
	if value.id == "" || value.detail == "" {
		return preparedStep{}, fmt.Errorf("step identity and detail are required")
	}
	if value.timeout <= 0 {
		return preparedStep{}, fmt.Errorf("step timeout must be positive")
	}
	if value.access != directStep && value.access != rootStep {
		return preparedStep{}, fmt.Errorf("step access is invalid")
	}
	if value.before == nil || value.verify == nil {
		return preparedStep{}, fmt.Errorf("step guards are required")
	}
	if effective.Name == "" {
		return preparedStep{}, fmt.Errorf("prepared command name is required")
	}
	effective.Args = append([]string(nil), effective.Args...)
	return preparedStep{step: value, command: effective, projection: value.projectionFor(effective)}, nil
}

func (value step) projectionFor(prepared Command) Change {
	command := Command{Name: prepared.Name, Args: append([]string(nil), prepared.Args...)}
	return Change{ID: value.id, Detail: value.detail, Command: &command}
}

//sumtype:decl
type planned interface {
	planned()
	review() ReviewPlan
	apply(Runner, ApplyReceipt) ApplyReceipt
}

type blockedPlan struct{ plan ReviewPlan }
type packageChange interface {
	apply(context.Context, Runner, Command, packageMutationGuard) packageResult
}
type packagePlan struct {
	plan       ReviewPlan
	host       hostBinding
	account    accountBinding
	projection Change
	command    Command
	change     packageChange
}
type primaryGroupPlan struct {
	plan       ReviewPlan
	host       hostBinding
	account    accountBinding
	group      primaryGroupBinding
	projection Change
	command    Command
}
type accountCreatePlan struct {
	plan              ReviewPlan
	host              hostBinding
	account           accountBinding
	group             primaryGroupBinding
	projection        Change
	command           Command
	lockStatusCommand Command
}
type homeCreatePlan struct {
	plan       ReviewPlan
	host       hostBinding
	account    accountBinding
	group      primaryGroupBinding
	projection Change
	command    Command
}

type packageResult struct {
	attempted bool
	err       error
}

type packageMutationGuard func() error

type accountMutationGuardFailed struct{ detail string }

func (failure accountMutationGuardFailed) Error() string { return failure.detail }

type hostMutationGuardFailed struct{ detail string }

func (failure hostMutationGuardFailed) Error() string { return failure.detail }

type boundSelection struct {
	services     services
	packageNeeds []resolvedPackage
	serviceNeeds []resolvedServiceNeed
	conflicts    []resolvedServiceConflict
}
type readyPlan struct {
	plan            ReviewPlan
	host            hostBinding
	account         accountBinding
	targetUser      bool
	bound           boundSelection
	packageBehavior packageBehavior
	packageEvidence packageEvidence
	services        serviceObservations
	steps           []preparedStep
}

func (blockedPlan) planned()                       {}
func (packagePlan) planned()                       {}
func (primaryGroupPlan) planned()                  {}
func (accountCreatePlan) planned()                 {}
func (homeCreatePlan) planned()                    {}
func (readyPlan) planned()                         {}
func (value blockedPlan) review() ReviewPlan       { return value.plan }
func (value packagePlan) review() ReviewPlan       { return value.plan }
func (value primaryGroupPlan) review() ReviewPlan  { return value.plan }
func (value accountCreatePlan) review() ReviewPlan { return value.plan }
func (value homeCreatePlan) review() ReviewPlan    { return value.plan }
func (value readyPlan) review() ReviewPlan         { return value.plan }

func blocked(review ReviewPlan) blockedPlan {
	if len(review.Blockers) == 0 {
		panic("blocked plan without blocker")
	}
	return blockedPlan{plan: canonicalReview(review)}
}

func planFor(state DesiredState, runner Runner, catalogue compiledCatalogue) planned {
	selected, blockers := catalogue.selectFor(state)
	review := ReviewPlan{Modules: selected.moduleStrings(), Account: reviewAccount(state.account), HostSettings: reviewHostSettings(state.machine), Blockers: blockers}
	if len(blockers) != 0 {
		return blocked(review)
	}
	host := observeHost(runner)
	review.Host, review.Facts = host.facts, append(review.Facts, host.factsOut...)
	review.Blockers = append(review.Blockers, host.blockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	needsUserAccount := selected.requiresUserAccount()
	if needsUserAccount && state.account == nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: "user-service demand requires an explicit account"})
		return blocked(review)
	}
	boundHost := hostBinding{facts: host.facts}
	if state.machine != nil && state.machine.hostname != nil {
		observed := observeHostname(runner)
		switch decision := reconcileHostname(*state.machine.hostname, observed).(type) {
		case hostnameExact:
			review.Facts = append(review.Facts, decision.facts...)
			boundHost.hostname = state.machine.hostname
		case hostnameBlocked:
			review.Blockers = append(review.Blockers, decision.blockers...)
			return blocked(review)
		case hostnameChange:
			review.Facts = append(review.Facts, hostnameFacts(decision.before)...)
			return planHostnameChange(review, host.facts, *state.machine.hostname, decision.before, runner)
		}
	}
	if state.machine != nil && state.machine.timezone != nil {
		observed := observeTimezone(runner)
		switch decision := reconcileTimezone(*state.machine.timezone, observed).(type) {
		case timezoneExact:
			review.Facts = append(review.Facts, decision.facts...)
			boundHost.timezone = state.machine.timezone
		case timezoneBlocked:
			review.Blockers = append(review.Blockers, decision.blockers...)
			return blocked(review)
		case timezoneChange:
			review.Facts = append(review.Facts, timezoneFacts(decision.before)...)
			return planTimezoneChange(review, boundHost, *state.machine.timezone, decision.before, runner)
		}
	}
	account := unboundAccount()
	var accountState accountDecision
	accountAbsent := false
	if state.account != nil {
		observed := observeAccount(context.Background(), runner, state.account)
		snapshot, snapshotOK := observed.(accountSnapshot)
		if snapshotOK {
			review.Facts = append(review.Facts, Fact{Subject: "account-observer", Detail: "getent=" + snapshot.getentPath})
		}
		accountState = reconcileAccount(state.account, observed)
		switch decision := accountState.(type) {
		case accountIdentified:
			review.Facts = append(review.Facts, decision.facts...)
			account = identifiedAccount(state.account, snapshot)
		case accountAbsentEligible:
			review.Facts = append(review.Facts, decision.facts...)
			account = absentAccount(state.account.(presentAccountIntent), snapshot)
			accountAbsent = true
		case accountIdentificationBlocked:
			review.Facts = append(review.Facts, decision.facts...)
			review.Blockers = append(review.Blockers, decision.blockers...)
		}
		if len(review.Blockers) != 0 {
			return blocked(review)
		}
	}
	if desired, ok := state.account.(presentAccountIntent); ok {
		_, accountSnapshot, _, err := account.reviewedEvidence()
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:binding", Detail: err.Error()})
			return blocked(review)
		}
		observedGroup := observePrimaryGroup(context.Background(), runner, accountSnapshot.getentPath, desired.primaryGroup)
		groupSnapshot := observedGroup
		review.Facts = append(review.Facts, Fact{Subject: "primary-group-observer", Detail: "getent=" + groupSnapshot.getentPath})
		switch decision := reconcilePrimaryGroup(desired.primaryGroup, observedGroup).(type) {
		case primaryGroupIdentified:
			review.Facts = append(review.Facts, decision.facts...)
			group := primaryGroupBinding{intent: desired.primaryGroup, observed: groupSnapshot}
			if accountAbsent {
				switch creation := reconcileAccountCreation(desired.name, accountState, decision, accountLockUnobserved{}).(type) {
				case accountCreateEligible:
					review.Facts = append(review.Facts, creation.facts...)
					return planAccountCreation(review, boundHost, account, group, desired, runner)
				case accountCreationBlocked:
					review.Blockers = append(review.Blockers, creation.blockers...)
					return blocked(review)
				case accountCreationSatisfied:
					panic("absent account cannot satisfy account creation")
				}
			}
			var lockCommand Command
			var lock accountLockObservation
			review, lockCommand, lock = observeExistingAccountLock(review, desired, runner)
			switch accountCreation := reconcileAccountCreation(desired.name, accountState, decision, lock).(type) {
			case accountCreationSatisfied:
				review.Facts = append(review.Facts, accountCreation.facts...)
				account.lock = accountLockBinding{name: desired.name, command: lockCommand, observed: lock}
				home := observeHome(runner, desired.home)
				review.Facts = append(review.Facts, homeSnapshotFacts(home)...)
				account.home = homeBinding{intent: desired.home, uid: desired.uid, gid: desired.primaryGroup.gid, observed: home}
				switch homeDecision := reconcileHomeCreation(desired.home, desired.uid, desired.primaryGroup.gid, home).(type) {
				case homeSatisfied:
					review.Facts = append(review.Facts, homeDecision.facts...)
				case homeCreateEligible:
					review.Facts = append(review.Facts, homeDecision.facts...)
					return planHomeCreation(review, boundHost, account, group, desired, runner)
				case homeBlocked:
					review.Blockers = append(review.Blockers, homeDecision.blockers...)
					return blocked(review)
				}
			case accountCreationBlocked:
				review.Blockers = append(review.Blockers, accountCreation.blockers...)
				return blocked(review)
			case accountCreateEligible:
				panic("identified account cannot be create-eligible")
			}
		case primaryGroupBlocked:
			review.Blockers = append(review.Blockers, decision.blockers...)
			return blocked(review)
		case primaryGroupAbsentEligible:
			review.Facts = append(review.Facts, decision.facts...)
			groupadd, err := runner.LookPath("groupadd")
			if err != nil {
				review.Blockers = append(review.Blockers, Blocker{Subject: "primary-group:" + desired.primaryGroup.name, Detail: "groupadd executable is unavailable: " + err.Error()})
				return blocked(review)
			}
			authority, authorityFacts, authorityBlockers := admitAuthority(runner, []step{{access: rootStep}})
			review.Facts = append(review.Facts, authorityFacts...)
			review.Blockers = append(review.Blockers, authorityBlockers...)
			if len(review.Blockers) != 0 {
				return blocked(review)
			}
			bare := Command{Name: groupadd, Args: []string{"--gid", strconv.FormatUint(uint64(desired.primaryGroup.gid), 10), desired.primaryGroup.name}, timeout: 30 * time.Second}
			effective, err := authority.rootCommand(bare)
			if err != nil {
				review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "command preparation: " + err.Error()})
				return blocked(review)
			}
			projectedCommand := Command{Name: effective.Name, Args: append([]string(nil), effective.Args...)}
			projection := Change{ID: "primary-group-create:" + desired.primaryGroup.name, Detail: fmt.Sprintf("create primary group %s with gid %d", desired.primaryGroup.name, desired.primaryGroup.gid), Command: &projectedCommand}
			review.Changes = append(review.Changes, projection)
			review = canonicalReview(review)
			return primaryGroupPlan{
				plan: review, host: boundHost, account: account,
				group:      primaryGroupBinding{intent: desired.primaryGroup, observed: groupSnapshot},
				projection: projection, command: effective,
			}
		}
	}
	if len(selected.serviceNeeds()) != 0 || len(selected.conflicts) != 0 {
		pid1, err := observePID1(runner)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "service-manager", Detail: err.Error()})
			return blocked(review)
		}
		if err := requireSystemd(pid1); err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "service-manager", Detail: err.Error()})
			return blocked(review)
		}
		boundHost.pid1 = pid1
		review.Facts = append(review.Facts, Fact{Subject: "service-manager", Detail: pid1})
	}
	var packageBehavior packageBehavior
	var packageNeeds []resolvedPackage
	var err error
	if len(selected.packageKeys()) != 0 {
		packageBehavior, err = recognizePackageBehavior(runner)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "package-manager", Detail: err.Error()})
			return blocked(review)
		}
		review.Facts = append(review.Facts, Fact{Subject: "package-manager", Detail: packageBehavior.manager.String() + " " + packageBehavior.version})
		var packageBlockers []Blocker
		packageNeeds, packageBlockers = packageBehavior.bind(selected)
		review.Blockers = append(review.Blockers, packageBlockers...)
	}
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	bound := boundSelection{packageNeeds: packageNeeds}
	var packageState packageState = packageDone{evidence: packageEvidence{installed: packageSet{}, rooted: packageSet{}}}
	if len(packageNeeds) != 0 {
		packageState = packageBehavior.inspect(context.Background(), runner, packageNeeds)
	}
	var packageEvidence packageEvidence
	var packageMutation packageChange
	var packageCommand Command
	var projectPackageMutation func(Command) Change
	switch state := packageState.(type) {
	case packageDone:
		packageEvidence = state.evidence
		if len(bound.packageNeeds) != 0 {
			review.Facts = append(review.Facts, packageEvidenceFacts(state.evidence)...)
		}
		for _, item := range bound.packageNeeds {
			review.Facts = append(review.Facts, Fact{Subject: "package:" + string(item.key), Detail: item.name + " installed and rooted"})
		}
	case packageBlocked:
		review.Blockers = append(review.Blockers, Blocker{Subject: "package:" + packageBehavior.manager.String(), Detail: state.reason})
		return blocked(review)
	case packageRootChange:
		packageEvidence, packageMutation, packageCommand, projectPackageMutation = state.before, state, state.command, state.projectionFor
	case packageInstallChange:
		packageEvidence, packageMutation, packageCommand, projectPackageMutation = state.before, state, state.command, state.projectionFor
	}
	if packageMutation != nil {
		review.Facts = append(review.Facts, packageEvidenceFacts(packageEvidence)...)
		authority, authorityFacts, authorityBlockers := admitAuthority(runner, []step{{access: rootStep}})
		review.Facts = append(review.Facts, authorityFacts...)
		review.Blockers = append(review.Blockers, authorityBlockers...)
		if len(review.Blockers) != 0 {
			return blocked(review)
		}
		effective, err := authority.rootCommand(packageCommand)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "command preparation: " + err.Error()})
			return blocked(review)
		}
		projection := projectPackageMutation(effective)
		review.Changes = append(review.Changes, projection)
		review = canonicalReview(review)
		return packagePlan{
			plan: review, host: boundHost, account: account, projection: projection, command: effective, change: packageMutation,
		}
	}
	if needsUserAccount {
		effectiveUID, err := runner.EffectiveUID()
		targetUID, identified := account.uid()
		switch {
		case err != nil:
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: "effective uid is unavailable: " + err.Error()})
		case !identified:
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: "target account uid is not identified"})
		case effectiveUID == 0:
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: "user-service target must be non-root"})
		case effectiveUID != targetUID:
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: fmt.Sprintf("effective uid is %d, target account uid is %d", effectiveUID, targetUID)})
		default:
			review.Facts = append(review.Facts, Fact{Subject: "account:target", Detail: fmt.Sprintf("effective uid %d matches %s", effectiveUID, state.account.accountName())})
		}
		if len(review.Blockers) != 0 {
			return blocked(review)
		}
	}
	if len(selected.serviceNeeds()) != 0 || len(selected.conflicts) != 0 {
		serviceBehavior, err := servicesFor(boundHost.pid1, runner)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "service-manager", Detail: err.Error()})
			return blocked(review)
		}
		serviceDemand, serviceBlockers := serviceBehavior.bind(selected)
		review.Blockers = append(review.Blockers, serviceBlockers...)
		if len(review.Blockers) != 0 {
			return blocked(review)
		}
		bound.services = serviceBehavior
		bound.serviceNeeds = serviceDemand.needs
		bound.conflicts = serviceDemand.conflicts
	}
	serviceObservations := bound.services.observe(context.Background(), runner, bound.serviceNeeds)
	serviceFacts, candidates, serviceBlockers := bound.services.reconcile(bound.serviceNeeds, serviceObservations)
	review.Facts = append(review.Facts, serviceFacts...)
	review.Blockers = append(review.Blockers, serviceBlockers...)
	conflictObservations := bound.services.observeConflicts(context.Background(), runner, bound.conflicts)
	conflictFacts, conflictBlockers := bound.services.reconcileConflicts(conflictObservations)
	review.Facts = append(review.Facts, conflictFacts...)
	review.Blockers = append(review.Blockers, conflictBlockers...)

	steps := make([]step, 0, len(candidates))
	for _, candidate := range candidates {
		step, stepErr := bound.services.step(candidate)
		if stepErr != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "workflow:step", Detail: stepErr.Error()})
			continue
		}
		steps = append(steps, step)
	}

	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	authority, authorityFacts, authorityBlockers := admitAuthority(runner, steps)
	review.Facts = append(review.Facts, authorityFacts...)
	review.Blockers = append(review.Blockers, authorityBlockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	if needsUserAccount && len(steps) != 0 {
		targetUID, _ := account.uid()
		principal, ok := authority.principal.(userPrincipal)
		if !ok {
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: "user-service authority is not a non-root user"})
		} else if principal.uid != targetUID {
			review.Blockers = append(review.Blockers, Blocker{Subject: "account:target", Detail: fmt.Sprintf("authority effective uid is %d, target account uid is %d", principal.uid, targetUID)})
		}
		if len(review.Blockers) != 0 {
			return blocked(review)
		}
	}
	prepared := make([]preparedStep, 0, len(steps))
	for _, step := range steps {
		command, err := authority.command(step)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "command preparation: " + err.Error()})
			continue
		}
		preparedStep, err := newPreparedStep(step, command)
		if err != nil {
			review.Blockers = append(review.Blockers, Blocker{Subject: "workflow:step", Detail: err.Error()})
			continue
		}
		prepared = append(prepared, preparedStep)
		review.Changes = append(review.Changes, preparedStep.projection)
	}
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	review = canonicalReview(review)
	return readyPlan{
		plan: review, host: boundHost, account: account, targetUser: needsUserAccount, bound: bound,
		packageBehavior: packageBehavior, packageEvidence: packageEvidence,
		services: serviceObservations, steps: prepared,
	}
}

func packageEvidenceFacts(evidence packageEvidence) []Fact {
	return []Fact{
		{Subject: "package-evidence:installed", Detail: strings.Join(sortedPackageSet(evidence.installed), ",")},
		{Subject: "package-evidence:rooted", Detail: strings.Join(sortedPackageSet(evidence.rooted), ",")},
	}
}

func admitAuthority(runner Runner, steps []step) (authority, []Fact, []Blocker) {
	if len(steps) == 0 {
		return authority{}, nil, nil
	}
	value, facts := inspectAuthority(runner)
	if principal, ok := value.principal.(unknownPrincipal); ok {
		return value, facts, []Blocker{{Subject: "authority:principal", Detail: principal.detail}}
	}
	needsRoot, needsUser, needsManager := false, false, false
	managerPath := ""
	for _, step := range steps {
		needsRoot = needsRoot || step.access == rootStep
		needsUser = needsUser || step.access == directStep
		needsManager = needsManager || step.manager
		if step.manager {
			if managerPath == "" {
				managerPath = step.command.Name
			} else if managerPath != step.command.Name {
				return value, facts, []Blocker{{Subject: "runtime:user-manager", Detail: "multiple service-manager executable authorities"}}
			}
		}
	}
	if needsUser {
		switch admission := value.runtimeAdmission(runner, true, needsManager, managerPath).(type) {
		case runtimeAdmitted:
			if admission.detail != "" {
				facts = append(facts, Fact{Subject: "runtime:user-manager", Detail: admission.detail})
			}
		case runtimeDenied:
			return value, facts, []Blocker{{Subject: "runtime:user-manager", Detail: admission.detail}}
		case runtimeIndeterminate:
			return value, facts, []Blocker{{Subject: "runtime:user-manager", Detail: admission.detail}}
		}
	}
	if needsRoot {
		var accessDetail string
		value.access, accessDetail = inspectAccessFor(value.principal, runner)
		facts = append(facts, Fact{Subject: "authority:system", Detail: accessDetail})
		switch access := value.access.(type) {
		case rootAccess, sudoAccess, doasAccess:
		case sudoAuthenticationUnavailable:
			return value, facts, []Blocker{{Subject: "authority:system", Detail: access.detail}}
		case sudoNoUpdateProbeUnsupported:
			return value, facts, []Blocker{{Subject: "authority:system", Detail: access.detail}}
		case doasNopassUnavailable:
			return value, facts, []Blocker{{Subject: "authority:system", Detail: access.detail}}
		case noPrivilege:
			return value, facts, []Blocker{{Subject: "authority:system", Detail: access.detail}}
		default:
			return value, facts, []Blocker{{Subject: "authority:system", Detail: "access is unknown"}}
		}
	}
	return value, facts, nil
}

func Plan(state DesiredState, runner Runner) ReviewPlan {
	return planFor(state, runner, production).review()
}

type stalePrecondition struct{ detail string }

func (value stalePrecondition) Error() string { return value.detail }
