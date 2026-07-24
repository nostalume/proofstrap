package proofstrap

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	persistentHostnamePath = "/etc/hostname"
	runtimeHostnamePath    = "/proc/sys/kernel/hostname"
)

type hostnameIntent struct{ value string }

func newHostnameIntent(value string) (hostnameIntent, error) {
	if err := validateHostname(value, false); err != nil {
		return hostnameIntent{}, err
	}
	return hostnameIntent{value: value}, nil
}

func validateHostname(value string, uppercase bool) error {
	if value == "" || len(value) > 64 {
		return fmt.Errorf("hostname must contain 1 to 64 ASCII bytes")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname %q is not canonical DNS-style syntax", value)
		}
		for index := range len(label) {
			character := label[index]
			valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-'
			valid = valid || uppercase && character >= 'A' && character <= 'Z'
			if !valid {
				return fmt.Errorf("hostname %q is not canonical DNS-style syntax", value)
			}
		}
	}
	return nil
}

//sumtype:decl
type hostnameObservation interface {
	hostnameObservation()
	blockers() []Blocker
}

type hostnameObserved struct{ persistent, runtime string }
type hostnameObservationBlocked struct{ blockerList []Blocker }

func (hostnameObserved) hostnameObservation()           {}
func (hostnameObservationBlocked) hostnameObservation() {}
func (hostnameObserved) blockers() []Blocker            { return nil }
func (value hostnameObservationBlocked) blockers() []Blocker {
	return append([]Blocker(nil), value.blockerList...)
}

func observeHostname(runner Runner) hostnameObservation {
	persistent, persistentErr := readHostnameRecord(runner, persistentHostnamePath)
	runtime, runtimeErr := readHostnameRecord(runner, runtimeHostnamePath)
	var blockers []Blocker
	if persistentErr != nil {
		blockers = append(blockers, Blocker{Subject: "hostname:persistent", Detail: persistentErr.Error()})
	}
	if runtimeErr != nil {
		blockers = append(blockers, Blocker{Subject: "hostname:runtime", Detail: runtimeErr.Error()})
	}
	if len(blockers) != 0 {
		return hostnameObservationBlocked{blockerList: blockers}
	}
	return hostnameObserved{persistent: persistent, runtime: runtime}
}

func readHostnameRecord(runner Runner, path string) (string, error) {
	contents, err := runner.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	record := string(contents)
	if strings.HasSuffix(record, "\n") {
		record = strings.TrimSuffix(record, "\n")
	}
	if record == "" || strings.ContainsAny(record, "\r\n") {
		return "", fmt.Errorf("%s must contain exactly one hostname record", path)
	}
	if err := validateHostname(record, true); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return record, nil
}

//sumtype:decl
type hostnameDecision interface{ hostnameDecision() }

type hostnameExact struct {
	facts []Fact
}
type hostnameChange struct{ before hostnameObserved }
type hostnameBlocked struct{ blockers []Blocker }

func (hostnameExact) hostnameDecision()   {}
func (hostnameChange) hostnameDecision()  {}
func (hostnameBlocked) hostnameDecision() {}

func reconcileHostname(intent hostnameIntent, observation hostnameObservation) hostnameDecision {
	switch value := observation.(type) {
	case hostnameObservationBlocked:
		return hostnameBlocked{blockers: value.blockers()}
	case hostnameObserved:
		if value.persistent == intent.value && value.runtime == intent.value {
			return hostnameExact{facts: hostnameFacts(value)}
		}
		return hostnameChange{before: value}
	default:
		return hostnameBlocked{blockers: []Blocker{{Subject: "hostname", Detail: "unknown hostname observation"}}}
	}
}

func hostnameFacts(observed hostnameObserved) []Fact {
	return []Fact{
		{Subject: "hostname:persistent", Detail: observed.persistent},
		{Subject: "hostname:runtime", Detail: observed.runtime},
	}
}

type hostnameBinding struct {
	intent hostnameIntent
}

type hostBinding struct {
	facts    HostFacts
	hostname *hostnameBinding
	timezone *timezoneBinding
}

func (binding hostBinding) guard(runner Runner) (bool, error) {
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 {
		return false, fmt.Errorf("host evidence cannot be revalidated: %s", blockersDetail(inspection.blockers))
	}
	if !reflect.DeepEqual(inspection.facts, binding.facts) {
		return true, nil
	}
	if binding.hostname != nil {
		fresh := observeHostname(runner)
		switch decision := reconcileHostname(binding.hostname.intent, fresh).(type) {
		case hostnameExact:
		case hostnameBlocked:
			return false, fmt.Errorf("hostname evidence cannot be revalidated: %s", blockersDetail(decision.blockers))
		case hostnameChange:
			return true, nil
		default:
			return false, fmt.Errorf("hostname evidence cannot be revalidated: unknown decision")
		}
	}
	if binding.timezone != nil {
		switch decision := reconcileTimezone(binding.timezone.intent, observeTimezone(runner)).(type) {
		case timezoneExact:
		case timezoneBlocked:
			return false, fmt.Errorf("timezone evidence cannot be revalidated: %s", blockersDetail(decision.blockers))
		case timezoneChange:
			return true, nil
		default:
			return false, fmt.Errorf("timezone evidence cannot be revalidated: unknown decision")
		}
	}
	return false, nil
}

type hostnamePlan struct {
	plan       ReviewPlan
	host       HostFacts
	intent     hostnameIntent
	before     hostnameObserved
	projection Change
	command    Command
}

func (hostnamePlan) planned()                 {}
func (value hostnamePlan) review() ReviewPlan { return value.plan }

func planHostnameChange(review ReviewPlan, host HostFacts, intent hostnameIntent, before hostnameObserved, runner Runner) planned {
	if host.PID1 != "systemd" {
		review.Blockers = append(review.Blockers, Blocker{Subject: "hostname:mutator", Detail: "hostname changes require systemd PID 1"})
		return blocked(review)
	}
	hostnamectl, err := runner.LookPath("hostnamectl")
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "hostname:mutator", Detail: "hostnamectl executable is unavailable: " + err.Error()})
		return blocked(review)
	}
	authority, facts, blockers := admitAuthority(runner, []step{{access: rootStep}})
	review.Facts = append(review.Facts, facts...)
	review.Blockers = append(review.Blockers, blockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	bare := Command{Name: hostnamectl, Args: []string{"--no-ask-password", "--static", "--transient", "set-hostname", intent.value}, timeout: 30 * time.Second}
	effective, err := authority.rootCommand(bare)
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "hostname command preparation: " + err.Error()})
		return blocked(review)
	}
	projected := Command{Name: effective.Name, Args: append([]string(nil), effective.Args...)}
	projection := Change{ID: "hostname", Detail: "set persistent and runtime hostname to " + intent.value, Command: &projected}
	review.Changes = append(review.Changes, projection)
	return hostnamePlan{
		plan: canonicalReview(review), host: host, intent: intent, before: before,
		projection: projection, command: effective,
	}
}

func (plan hostnamePlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	projected := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) || plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, projected) {
		receipt.Status = Failed
		return receipt
	}
	inspection := observeHost(runner)
	if len(inspection.blockers) != 0 || !reflect.DeepEqual(inspection.facts, plan.host) {
		receipt.Status = Stale
		return receipt
	}
	fresh := observeHostname(runner)
	if blockers := fresh.blockers(); len(blockers) != 0 {
		receipt.Status = Failed
		receipt.Blockers = blockers
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "hostname evidence cannot be revalidated"}}
		return receipt
	}
	if !reflect.DeepEqual(fresh, plan.before) {
		receipt.Status = Stale
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "hostname evidence changed immediately before mutation"}}
		return receipt
	}
	execution := runner.Run(context.Background(), plan.command)
	post := observeHostname(runner)
	verified, detail := verifyHostname(plan.intent, post)
	if execution.Err != nil || execution.ExitCode != 0 {
		outcome := FailedAction
		if verified {
			outcome = Applied
		}
		receipt.Status = Failed
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: outcome, Detail: "hostnamectl failed: " + resultDetail(execution) + "; post-state: " + detail}}
		return receipt
	}
	if !verified {
		receipt.Status = Failed
		receipt.Blockers = post.blockers()
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: FailedAction, Detail: "post-state: " + detail}}
		return receipt
	}
	finalHost := observeHost(runner)
	if len(finalHost.blockers) != 0 || !reflect.DeepEqual(finalHost.facts, plan.host) {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "final:host", Detail: "host identity changed after hostname mutation"}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: detail}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: detail + "; replan required"}}
	return receipt
}

func verifyHostname(intent hostnameIntent, observation hostnameObservation) (bool, string) {
	switch value := observation.(type) {
	case hostnameObserved:
		detail := "persistent=" + value.persistent + "; runtime=" + value.runtime
		return value.persistent == intent.value && value.runtime == intent.value, detail
	case hostnameObservationBlocked:
		return false, blockersDetail(value.blockerList)
	default:
		return false, "unknown hostname observation"
	}
}

func blockersDetail(blockers []Blocker) string {
	parts := make([]string, len(blockers))
	for index, blocker := range blockers {
		parts[index] = blocker.Subject + ": " + blocker.Detail
	}
	return strings.Join(parts, "; ")
}
