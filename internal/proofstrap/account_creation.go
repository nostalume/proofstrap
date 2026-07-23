package proofstrap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

//sumtype:decl
type accountLockObservation interface{ accountLockObservation() }

type accountLocked struct{ name string }
type accountUnlocked struct{ name, status string }
type accountLockUnobserved struct{}
type accountLockIndeterminate struct{ detail string }

type accountLockBinding struct {
	name     string
	command  Command
	observed accountLockObservation
}

func (accountLocked) accountLockObservation()            {}
func (accountUnlocked) accountLockObservation()          {}
func (accountLockUnobserved) accountLockObservation()    {}
func (accountLockIndeterminate) accountLockObservation() {}

func (binding accountLockBinding) guard(ctx context.Context, runner Runner) (bool, error) {
	if binding.command.Name == "" {
		return false, nil
	}
	fresh := observeAccountLockStatus(ctx, runner, binding.command, binding.name)
	if indeterminate, ok := fresh.(accountLockIndeterminate); ok {
		return false, fmt.Errorf("account lock status cannot be revalidated: %s", indeterminate.detail)
	}
	return fresh != binding.observed, nil
}

//sumtype:decl
type accountCreationDecision interface{ accountCreationDecision() }

type accountCreationSatisfied struct{ facts []Fact }
type accountCreateEligible struct{ facts []Fact }
type accountCreationBlocked struct{ blockers []Blocker }

func (accountCreationSatisfied) accountCreationDecision() {}
func (accountCreateEligible) accountCreationDecision()    {}
func (accountCreationBlocked) accountCreationDecision()   {}

func parseAccountLockStatus(name, output string) accountLockObservation {
	if !strings.HasSuffix(output, "\n") {
		return accountLockIndeterminate{detail: "account lock status is not newline terminated"}
	}
	record := strings.TrimSuffix(output, "\n")
	if record == "" || strings.ContainsAny(record, "\r\n") {
		return accountLockIndeterminate{detail: "account lock status is not exactly one record"}
	}
	for index := range len(record) {
		if value := record[index]; value != ' ' && (value < '!' || value > '~') {
			return accountLockIndeterminate{detail: "account lock status contains non-ASCII framing"}
		}
	}
	fields := strings.Split(record, " ")
	if len(fields) != 7 {
		return accountLockIndeterminate{detail: fmt.Sprintf("account lock status has %d fields, want 7", len(fields))}
	}
	for _, field := range fields {
		if field == "" {
			return accountLockIndeterminate{detail: "account lock status has an empty field"}
		}
	}
	if fields[0] != name {
		return accountLockIndeterminate{detail: fmt.Sprintf("account lock status names %q, want %q", fields[0], name)}
	}
	switch fields[1] {
	case "L":
		return accountLocked{name: name}
	case "P", "NP":
		return accountUnlocked{name: name, status: fields[1]}
	default:
		return accountLockIndeterminate{detail: fmt.Sprintf("account lock status %q is unknown", fields[1])}
	}
}

func observeAccountLockStatus(ctx context.Context, runner Runner, command Command, name string) accountLockObservation {
	command.timeout = 5 * time.Second
	result := runner.Run(ctx, command)
	if result.Err != nil || result.ExitCode != 0 || result.Stderr != "" {
		return accountLockIndeterminate{detail: resultDetail(result)}
	}
	return parseAccountLockStatus(name, result.Stdout)
}

func reconcileAccountCreation(name string, account accountDecision, group primaryGroupDecision, lock accountLockObservation) accountCreationDecision {
	if _, exact := group.(primaryGroupIdentified); !exact {
		return accountCreationBlocked{blockers: []Blocker{{Subject: "account:" + name, Detail: "primary group is not exact"}}}
	}
	switch account.(type) {
	case accountAbsentEligible:
		if _, ok := lock.(accountLockUnobserved); !ok {
			return accountCreationBlocked{blockers: []Blocker{{Subject: "account:" + name, Detail: "unexpected lock evidence for absent account"}}}
		}
		return accountCreateEligible{facts: []Fact{{Subject: "account:" + name, Detail: "eligible for locked account creation"}}}
	case accountIdentified:
		switch observed := lock.(type) {
		case accountLocked:
			return accountCreationSatisfied{facts: []Fact{{Subject: "account-lock:" + name, Detail: "locked"}}}
		case accountUnlocked:
			return accountCreationBlocked{blockers: []Blocker{{Subject: "account-lock:" + name, Detail: "existing account is not locked: status=" + observed.status}}}
		case accountLockIndeterminate:
			return accountCreationBlocked{blockers: []Blocker{{Subject: "account-lock:" + name, Detail: observed.detail}}}
		default:
			return accountCreationBlocked{blockers: []Blocker{{Subject: "account-lock:" + name, Detail: "lock status was not observed"}}}
		}
	default:
		return accountCreationBlocked{blockers: []Blocker{{Subject: "account:" + name, Detail: "account identity is not eligible for creation"}}}
	}
}

func planAccountCreation(review ReviewPlan, host HostFacts, account accountBinding, group primaryGroupBinding, intent presentAccountIntent, runner Runner) planned {
	useradd, err := runner.LookPath("useradd")
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "account:" + intent.name, Detail: "useradd executable is unavailable: " + err.Error()})
		return blocked(review)
	}
	passwd, err := runner.LookPath("passwd")
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "account-lock:" + intent.name, Detail: "passwd executable is unavailable: " + err.Error()})
		return blocked(review)
	}
	authority, facts, blockers := admitAuthority(runner, []step{{access: rootStep}})
	review.Facts = append(review.Facts, facts...)
	review.Blockers = append(review.Blockers, blockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	bare := Command{Name: useradd, Args: []string{
		"--uid", strconv.FormatUint(uint64(intent.uid), 10),
		"--gid", strconv.FormatUint(uint64(intent.primaryGroup.gid), 10),
		"--shell", intent.shell,
		"--home-dir", intent.home.path,
		"--no-create-home",
		"--no-user-group",
		"--password", "!",
		intent.name,
	}, timeout: 30 * time.Second}
	effective, err := authority.rootCommand(bare)
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "account command preparation: " + err.Error()})
		return blocked(review)
	}
	lockStatus, err := authority.rootCommand(Command{Name: passwd, Args: []string{"-S", intent.name}, timeout: 5 * time.Second})
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "account lock observer preparation: " + err.Error()})
		return blocked(review)
	}
	review.Facts = append(review.Facts, Fact{Subject: "account-lock-observer", Detail: lockStatus.String()})
	projectedCommand := Command{Name: effective.Name, Args: append([]string(nil), effective.Args...)}
	projection := Change{ID: "account-create:" + intent.name, Detail: "create locked account " + intent.name, Command: &projectedCommand}
	review.Changes = append(review.Changes, projection)
	review = canonicalReview(review)
	return accountCreatePlan{
		plan: review, host: host, account: account, group: group,
		projection: projection, command: effective, lockStatusCommand: lockStatus,
	}
}

func observeExistingAccountLock(review ReviewPlan, intent presentAccountIntent, runner Runner) (ReviewPlan, Command, accountLockObservation) {
	passwd, err := runner.LookPath("passwd")
	if err != nil {
		return review, Command{}, accountLockIndeterminate{detail: "passwd executable is unavailable: " + err.Error()}
	}
	command := Command{Name: passwd, Args: []string{"-S", intent.name}, timeout: 5 * time.Second}
	uid, err := runner.EffectiveUID()
	if err != nil {
		return review, Command{}, accountLockIndeterminate{detail: "effective uid is unavailable: " + err.Error()}
	}
	if uid != intent.uid {
		authority, facts, blockers := admitAuthority(runner, []step{{access: rootStep}})
		review.Facts = append(review.Facts, facts...)
		if len(blockers) != 0 {
			return review, Command{}, accountLockIndeterminate{detail: blockers[0].Detail}
		}
		command, err = authority.rootCommand(command)
		if err != nil {
			return review, Command{}, accountLockIndeterminate{detail: err.Error()}
		}
	}
	review.Facts = append(review.Facts, Fact{Subject: "account-lock-observer", Detail: command.String()})
	return review, command, observeAccountLockStatus(context.Background(), runner, command, intent.name)
}

func verifyAccountCreation(intent presentAccountIntent, observed accountObservation, lock accountLockObservation) (bool, string) {
	identity := reconcileAccount(intent, observed)
	switch decision := reconcileAccountCreation(intent.name, identity, primaryGroupIdentified{}, lock).(type) {
	case accountCreationSatisfied:
		return true, "account identity is exact and locked"
	case accountCreationBlocked:
		if len(decision.blockers) != 0 {
			return false, decision.blockers[0].Detail
		}
	case accountCreateEligible:
		return false, "account remains absent"
	}
	return false, "account creation could not be verified"
}
