package proofstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type Fact struct {
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

type Blocker struct {
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

type Change struct {
	ID      string   `json:"id"`
	Detail  string   `json:"detail"`
	Command *Command `json:"command,omitempty"`
}

type HostSettingsReview struct {
	Hostname string `json:"hostname"`
}

//sumtype:decl
type AccountReview interface {
	accountReview()
	Summary() string
}

type ExistingAccountReview struct {
	State string `json:"state"`
	Name  string `json:"name"`
}

type PresentAccountReview struct {
	State        string `json:"state"`
	Name         string `json:"name"`
	UID          uint32 `json:"uid"`
	Shell        string `json:"shell"`
	PrimaryGroup string `json:"primary_group"`
	PrimaryGID   uint32 `json:"primary_gid"`
	Home         string `json:"home"`
	HomeMode     string `json:"home_mode"`
}

func (ExistingAccountReview) accountReview() {}
func (PresentAccountReview) accountReview()  {}
func (value ExistingAccountReview) Summary() string {
	return value.State + " name=" + value.Name
}
func (value PresentAccountReview) Summary() string {
	return value.State + " name=" + value.Name + " uid=" + strconv.FormatUint(uint64(value.UID), 10) + " primary_group=" + value.PrimaryGroup + ":" + strconv.FormatUint(uint64(value.PrimaryGID), 10) + " home=" + strconv.Quote(value.Home) + ":" + value.HomeMode + " shell=" + strconv.Quote(value.Shell)
}

type ReviewPlan struct {
	Modules      []string            `json:"modules"`
	Account      AccountReview       `json:"account,omitempty"`
	HostSettings *HostSettingsReview `json:"host_settings,omitempty"`
	Host         HostFacts           `json:"host"`
	Facts        []Fact              `json:"facts"`
	Changes      []Change            `json:"changes"`
	Blockers     []Blocker           `json:"blockers"`
}

func (plan ReviewPlan) Blocked() bool { return len(plan.Blockers) != 0 }

func (plan ReviewPlan) Digest() string {
	canonical := plan
	canonical.Modules = append([]string(nil), plan.Modules...)
	canonical.Account = cloneAccountReview(plan.Account)
	canonical.HostSettings = cloneHostSettingsReview(plan.HostSettings)
	canonical.Facts = append([]Fact(nil), plan.Facts...)
	canonical.Changes = cloneChanges(plan.Changes)
	canonical.Blockers = append([]Blocker(nil), plan.Blockers...)
	sort.Strings(canonical.Modules)
	sort.Slice(canonical.Facts, func(i, j int) bool {
		return canonical.Facts[i].Subject < canonical.Facts[j].Subject || canonical.Facts[i].Subject == canonical.Facts[j].Subject && canonical.Facts[i].Detail < canonical.Facts[j].Detail
	})
	sort.Slice(canonical.Changes, func(i, j int) bool { return canonical.Changes[i].ID < canonical.Changes[j].ID })
	sort.Slice(canonical.Blockers, func(i, j int) bool {
		return canonical.Blockers[i].Subject < canonical.Blockers[j].Subject || canonical.Blockers[i].Subject == canonical.Blockers[j].Subject && canonical.Blockers[i].Detail < canonical.Blockers[j].Detail
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func reviewHostSettings(intent *machineIntent) *HostSettingsReview {
	if intent == nil || intent.hostname == nil {
		return nil
	}
	return &HostSettingsReview{Hostname: intent.hostname.value}
}

func cloneHostSettingsReview(source *HostSettingsReview) *HostSettingsReview {
	if source == nil {
		return nil
	}
	clone := *source
	return &clone
}

func reviewAccount(intent accountIntent) AccountReview {
	switch value := intent.(type) {
	case nil:
		return nil
	case existingAccountIntent:
		return ExistingAccountReview{State: "existing", Name: value.name}
	case presentAccountIntent:
		return PresentAccountReview{
			State: "present", Name: value.name, UID: value.uid, Shell: value.shell,
			PrimaryGroup: value.primaryGroup.name, PrimaryGID: value.primaryGroup.gid,
			Home: value.home.path, HomeMode: fmt.Sprintf("%04o", value.home.mode),
		}
	default:
		panic("unknown account intent")
	}
}

func cloneAccountReview(source AccountReview) AccountReview {
	switch value := source.(type) {
	case nil:
		return nil
	case ExistingAccountReview:
		return value
	case PresentAccountReview:
		return value
	default:
		panic("unknown account review")
	}
}

func cloneChanges(source []Change) []Change {
	result := make([]Change, len(source))
	for i, change := range source {
		result[i] = change
		if change.Command != nil {
			command := Command{Name: change.Command.Name, Args: append([]string(nil), change.Command.Args...)}
			result[i].Command = &command
		}
	}
	return result
}

type RunStatus string
type ActionStatus string

const (
	Succeeded      RunStatus = "succeeded"
	ReplanRequired RunStatus = "replan_required"

	Blocked      RunStatus    = "blocked"
	Stale        RunStatus    = "stale"
	Failed       RunStatus    = "failed"
	Applied      ActionStatus = "applied"
	FailedAction ActionStatus = "failed"
	Unattempted  ActionStatus = "unattempted"
)

type ActionOutcome struct {
	Action string       `json:"action"`
	Status ActionStatus `json:"status"`
	Detail string       `json:"detail,omitempty"`
}

type ApplyReceipt struct {
	AcceptedDigest string          `json:"accepted_digest"`
	PlanDigest     string          `json:"plan_digest"`
	Status         RunStatus       `json:"status"`
	Blockers       []Blocker       `json:"blockers,omitempty"`
	Outcomes       []ActionOutcome `json:"outcomes,omitempty"`
}
