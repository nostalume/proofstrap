package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	localtimePath = "/etc/localtime"
	zoneinfoRoot  = "/usr/share/zoneinfo"
)

type timezoneIntent struct{ value string }

type timezoneFilesystem interface {
	Readlink(path string) (string, error)
	EvalSymlinks(path string) (string, error)
	ReadFilePrefix(path string, size int) ([]byte, error)
}

func newTimezoneIntent(value string) (timezoneIntent, error) {
	if err := validateTimezone(value); err != nil {
		return timezoneIntent{}, err
	}
	return timezoneIntent{value: value}, nil
}

func validateTimezone(value string) error {
	if value == "" || len(value) > 4095 || filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("timezone %q must be a normalized relative zoneinfo path", value)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return fmt.Errorf("timezone %q must be a normalized relative zoneinfo path", value)
		}
		for index := range len(component) {
			character := component[index]
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_+-", rune(character)) {
				continue
			}
			return fmt.Errorf("timezone %q contains unsupported syntax", value)
		}
	}
	return nil
}

//sumtype:decl
type timezoneObservation interface {
	timezoneObservation()
	blockers() []Blocker
}

type timezoneObserved struct {
	value  string
	target string
}
type timezoneObservationBlocked struct{ blockerList []Blocker }

func (timezoneObserved) timezoneObservation()           {}
func (timezoneObservationBlocked) timezoneObservation() {}
func (timezoneObserved) blockers() []Blocker            { return nil }
func (value timezoneObservationBlocked) blockers() []Blocker {
	return append([]Blocker(nil), value.blockerList...)
}

func observeTimezone(runner Runner) timezoneObservation {
	info, err := runner.Lstat(localtimePath)
	if errors.Is(err, os.ErrNotExist) {
		return timezoneObserved{value: "UTC", target: "missing; system default"}
	}
	if err != nil {
		return blockedTimezone("lstat " + localtimePath + ": " + err.Error())
	}
	if info.Kind != SymlinkPath {
		return blockedTimezone(localtimePath + " must be a symbolic link into " + zoneinfoRoot)
	}
	filesystem, ok := runner.(timezoneFilesystem)
	if !ok {
		return blockedTimezone("runner does not support timezone filesystem evidence")
	}
	target, err := filesystem.Readlink(localtimePath)
	if err != nil {
		return blockedTimezone("readlink " + localtimePath + ": " + err.Error())
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(localtimePath), resolved)
	}
	resolved = filepath.Clean(resolved)
	prefix := zoneinfoRoot + "/"
	if !strings.HasPrefix(resolved, prefix) {
		return blockedTimezone(localtimePath + " target is outside " + zoneinfoRoot)
	}
	zone := strings.TrimPrefix(resolved, prefix)
	if err := validateTimezone(zone); err != nil {
		return blockedTimezone(err.Error())
	}
	if zone != "UTC" {
		if err := verifyTimezoneData(runner, resolved); err != nil {
			return blockedTimezone(err.Error())
		}
	}
	return timezoneObserved{value: zone, target: target}
}

func blockedTimezone(detail string) timezoneObservation {
	return timezoneObservationBlocked{blockerList: []Blocker{{Subject: "timezone", Detail: detail}}}
}

//sumtype:decl
type timezoneDecision interface{ timezoneDecision() }

type timezoneExact struct{ facts []Fact }
type timezoneChange struct{ before timezoneObserved }
type timezoneBlocked struct{ blockers []Blocker }

func (timezoneExact) timezoneDecision()   {}
func (timezoneChange) timezoneDecision()  {}
func (timezoneBlocked) timezoneDecision() {}

func reconcileTimezone(intent timezoneIntent, observation timezoneObservation) timezoneDecision {
	switch value := observation.(type) {
	case timezoneObservationBlocked:
		return timezoneBlocked{blockers: value.blockers()}
	case timezoneObserved:
		if value.value == intent.value {
			return timezoneExact{facts: timezoneFacts(value)}
		}
		return timezoneChange{before: value}
	default:
		return timezoneBlocked{blockers: []Blocker{{Subject: "timezone", Detail: "unknown timezone observation"}}}
	}
}

func timezoneFacts(observed timezoneObserved) []Fact {
	return []Fact{{Subject: "timezone", Detail: observed.value + " via " + observed.target}}
}

func installedTimezone(runner Runner, intent timezoneIntent) error {
	if intent.value == "UTC" {
		return nil
	}
	path := zoneinfoRoot + "/" + intent.value
	return verifyTimezoneData(runner, path)
}

func verifyTimezoneData(runner Runner, path string) error {
	filesystem, ok := runner.(timezoneFilesystem)
	if !ok {
		return fmt.Errorf("runner does not support timezone filesystem evidence")
	}
	canonical, err := filesystem.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve timezone data %s: %w", path, err)
	}
	canonical = filepath.Clean(canonical)
	if !strings.HasPrefix(canonical, zoneinfoRoot+"/") {
		return fmt.Errorf("timezone data %s resolves outside %s", path, zoneinfoRoot)
	}
	info, err := runner.Lstat(canonical)
	if err != nil {
		return fmt.Errorf("lstat timezone data %s: %w", canonical, err)
	}
	if info.Kind != RegularPath {
		return fmt.Errorf("timezone data %s is not a regular file", canonical)
	}
	contents, err := filesystem.ReadFilePrefix(canonical, 4)
	if err != nil {
		return fmt.Errorf("read timezone data %s: %w", canonical, err)
	}
	if len(contents) < 4 || string(contents[:4]) != "TZif" {
		return fmt.Errorf("%s is not TZif timezone data", canonical)
	}
	return nil
}

func timezoneRTCProbe(timedatectl string) Command {
	return Command{Name: timedatectl, Args: []string{"--no-pager", "--property=LocalRTC", "--value", "show"}, timeout: 10 * time.Second}
}

func admitTimezoneRTC(runner Runner, command Command) (Fact, error) {
	result := runner.Run(context.Background(), command)
	if result.Err != nil || result.ExitCode != 0 {
		return Fact{}, fmt.Errorf("observe timedated LocalRTC: %s", resultDetail(result))
	}
	switch strings.TrimSpace(result.Stdout) {
	case "no":
		return Fact{Subject: "timezone:rtc", Detail: "timedated LocalRTC=false"}, nil
	case "yes":
		return Fact{}, fmt.Errorf("RTC uses local time; timezone mutation would also update the hardware clock")
	default:
		return Fact{}, fmt.Errorf("timedated returned unknown LocalRTC value %q", strings.TrimSpace(result.Stdout))
	}
}

type timezoneBinding struct{ intent timezoneIntent }

type timezonePlan struct {
	plan       ReviewPlan
	host       hostBinding
	intent     timezoneIntent
	before     timezoneObserved
	projection Change
	rtcProbe   Command
	command    Command
}

func (timezonePlan) planned()                 {}
func (value timezonePlan) review() ReviewPlan { return value.plan }

func planTimezoneChange(review ReviewPlan, host hostBinding, intent timezoneIntent, before timezoneObserved, runner Runner) planned {
	if review.Host.PID1 != "systemd" {
		review.Blockers = append(review.Blockers, Blocker{Subject: "timezone:mutator", Detail: "timezone changes require systemd PID 1"})
		return blocked(review)
	}
	if err := installedTimezone(runner, intent); err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "timezone:zoneinfo", Detail: err.Error()})
		return blocked(review)
	}
	timedatectl, err := runner.LookPath("timedatectl")
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "timezone:mutator", Detail: "timedatectl executable is unavailable: " + err.Error()})
		return blocked(review)
	}
	rtcProbe := timezoneRTCProbe(timedatectl)
	rtc, err := admitTimezoneRTC(runner, rtcProbe)
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "timezone:rtc", Detail: err.Error()})
		return blocked(review)
	}
	review.Facts = append(review.Facts, rtc)
	authority, facts, blockers := admitAuthority(runner, []step{{access: rootStep}})
	review.Facts = append(review.Facts, facts...)
	review.Blockers = append(review.Blockers, blockers...)
	if len(review.Blockers) != 0 {
		return blocked(review)
	}
	bare := Command{Name: timedatectl, Args: []string{"--no-ask-password", "set-timezone", intent.value}, timeout: 30 * time.Second}
	effective, err := authority.rootCommand(bare)
	if err != nil {
		review.Blockers = append(review.Blockers, Blocker{Subject: "authority:system", Detail: "timezone command preparation: " + err.Error()})
		return blocked(review)
	}
	projected := Command{Name: effective.Name, Args: append([]string(nil), effective.Args...)}
	projection := Change{ID: "timezone", Detail: "set timezone to " + intent.value, Command: &projected}
	review.Changes = append(review.Changes, projection)
	return timezonePlan{plan: canonicalReview(review), host: host, intent: intent, before: before, projection: projection, rtcProbe: rtcProbe, command: effective}
}

func (plan timezonePlan) apply(runner Runner, receipt ApplyReceipt) ApplyReceipt {
	projected := Command{Name: plan.command.Name, Args: append([]string(nil), plan.command.Args...)}
	if len(plan.plan.Changes) != 1 || !reflect.DeepEqual(plan.plan.Changes[0], plan.projection) || plan.projection.Command == nil || !reflect.DeepEqual(*plan.projection.Command, projected) {
		receipt.Status = Failed
		return receipt
	}
	if guarded, stop := initialHostGuard(receipt, plan.host, runner); stop {
		return guarded
	}
	fresh := observeTimezone(runner)
	switch decision := reconcileTimezone(plan.intent, fresh).(type) {
	case timezoneBlocked:
		receipt.Status = Failed
		receipt.Blockers = decision.blockers
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "timezone evidence cannot be revalidated"}}
		return receipt
	case timezoneExact:
		receipt.Status = Stale
		_, detail := verifyTimezone(plan.intent, fresh)
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "timezone already exact immediately before mutation: " + detail}}
		return receipt
	case timezoneChange:
		if !reflect.DeepEqual(decision.before, plan.before) {
			receipt.Status = Stale
			receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: "timezone evidence changed immediately before mutation"}}
			return receipt
		}
	}
	if err := installedTimezone(runner, plan.intent); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:timezone:zoneinfo", Detail: err.Error()}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: err.Error()}}
		return receipt
	}
	if _, err := admitTimezoneRTC(runner, plan.rtcProbe); err != nil {
		receipt.Status = Failed
		receipt.Blockers = []Blocker{{Subject: "guard:timezone:rtc", Detail: err.Error()}}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Unattempted, Detail: err.Error()}}
		return receipt
	}
	if guarded, stop, _ := immediateHostGuard(receipt, plan.host, runner, plan.projection.ID, "host evidence changed immediately before timezone mutation"); stop {
		return guarded
	}
	execution := runner.Run(context.Background(), plan.command)
	post := observeTimezone(runner)
	verified, detail := verifyTimezone(plan.intent, post)
	if execution.Err != nil || execution.ExitCode != 0 {
		detail = "timedatectl failed: " + resultDetail(execution) + "; " + detail
	}
	if hostDetail, failed := finalHostGuard(plan.host, runner); failed {
		receipt.Status = Failed
		receipt.Blockers = append(post.blockers(), Blocker{Subject: "final:host", Detail: hostDetail})
		status := FailedAction
		if verified {
			status = Applied
		}
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: detail + "; " + hostDetail}}
		return receipt
	}
	if execution.Err != nil || execution.ExitCode != 0 || !verified {
		status := FailedAction
		if verified {
			status = Applied
		}
		receipt.Status = Failed
		receipt.Blockers = post.blockers()
		receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: status, Detail: detail}}
		return receipt
	}
	receipt.Status = ReplanRequired
	receipt.Outcomes = []ActionOutcome{{Action: plan.projection.ID, Status: Applied, Detail: "verified timezone " + plan.intent.value + "; replan required"}}
	return receipt
}

func verifyTimezone(intent timezoneIntent, observation timezoneObservation) (bool, string) {
	switch value := observation.(type) {
	case timezoneObserved:
		return value.value == intent.value, "timezone=" + value.value + " via " + value.target
	case timezoneObservationBlocked:
		return false, blockersDetail(value.blockerList)
	default:
		return false, "unknown timezone observation"
	}
}
