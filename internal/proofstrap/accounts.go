package proofstrap

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type passwdEntry struct {
	name       string
	uid        uint32
	primaryGID uint32
	gecos      string
	home       string
	shell      string
}

//sumtype:decl
type accountLookup interface{ accountLookup() }

type passwdFound struct{ entry passwdEntry }
type passwdMissing struct{}
type passwdLookupFailed struct{ detail string }
type passwdLookupSkipped struct{}

func (passwdFound) accountLookup()         {}
func (passwdMissing) accountLookup()       {}
func (passwdLookupFailed) accountLookup()  {}
func (passwdLookupSkipped) accountLookup() {}

//sumtype:decl
type accountObservation interface{ accountObservation() }

type accountSnapshot struct {
	getentPath string
	globalName accountLookup
	localName  accountLookup
	globalUID  accountLookup
	localUID   accountLookup
}
type accountObservationFailed struct{ detail string }

func (accountSnapshot) accountObservation()          {}
func (accountObservationFailed) accountObservation() {}

//sumtype:decl
type accountDecision interface{ accountDecision() }

type accountIdentified struct{ facts []Fact }
type accountAbsentEligible struct{ facts []Fact }
type accountIdentificationBlocked struct {
	facts    []Fact
	blockers []Blocker
}

type accountBinding struct {
	intent   accountIntent
	observed accountObservation
	lock     accountLockBinding
	home     homeBinding
}

func (accountIdentified) accountDecision()            {}
func (accountAbsentEligible) accountDecision()        {}
func (accountIdentificationBlocked) accountDecision() {}

func observeAccount(ctx context.Context, runner Runner, intent accountIntent) accountObservation {
	getent, err := runner.LookPath("getent")
	if err != nil {
		return accountObservationFailed{detail: "getent executable is unavailable: " + err.Error()}
	}
	return observeAccountWithGetent(ctx, runner, intent, getent)
}

func observeAccountWithGetent(ctx context.Context, runner Runner, intent accountIntent, getent string) accountObservation {
	name := intent.accountName()
	globalName := lookupPasswd(ctx, runner, getent, false, name)
	localName := lookupPasswd(ctx, runner, getent, true, name)
	uid, ok := intendedUID(intent, globalName, localName)
	if !ok {
		skipped := passwdLookupSkipped{}
		return accountSnapshot{getentPath: getent, globalName: globalName, localName: localName, globalUID: skipped, localUID: skipped}
	}
	key := strconv.FormatUint(uint64(uid), 10)
	return accountSnapshot{
		getentPath: getent,
		globalName: globalName,
		localName:  localName,
		globalUID:  lookupPasswd(ctx, runner, getent, false, key),
		localUID:   lookupPasswd(ctx, runner, getent, true, key),
	}
}

func intendedUID(intent accountIntent, globalName, localName accountLookup) (uint32, bool) {
	if present, ok := intent.(presentAccountIntent); ok {
		return present.uid, true
	}
	if found, ok := globalName.(passwdFound); ok {
		return found.entry.uid, true
	}
	if found, ok := localName.(passwdFound); ok {
		return found.entry.uid, true
	}
	return 0, false
}

func lookupPasswd(ctx context.Context, runner Runner, getent string, local bool, key string) accountLookup {
	args := []string{"passwd", key}
	if local {
		args = []string{"-s", "files", "passwd", key}
	}
	result := runner.Run(ctx, Command{Name: getent, Args: args, timeout: 5 * time.Second})
	if result.Err == nil && result.ExitCode == 2 && result.Stdout == "" && result.Stderr == "" {
		return passwdMissing{}
	}
	if result.Err != nil || result.ExitCode != 0 || result.Stderr != "" {
		return passwdLookupFailed{detail: resultDetail(result)}
	}
	entry, err := parsePasswdEntry(result.Stdout)
	if err != nil {
		return passwdLookupFailed{detail: err.Error()}
	}
	return passwdFound{entry: entry}
}

func parsePasswdEntry(output string) (passwdEntry, error) {
	if !strings.HasSuffix(output, "\n") {
		return passwdEntry{}, fmt.Errorf("passwd record is not newline terminated")
	}
	record := strings.TrimSuffix(output, "\n")
	if record == "" || strings.Contains(record, "\n") {
		count := 0
		if record != "" {
			count = strings.Count(record, "\n") + 1
		}
		return passwdEntry{}, fmt.Errorf("passwd lookup returned %d records", count)
	}
	fields := strings.Split(record, ":")
	if len(fields) != 7 {
		return passwdEntry{}, fmt.Errorf("passwd record has %d fields, want 7", len(fields))
	}
	if fields[1] != "x" {
		return passwdEntry{}, fmt.Errorf("passwd credential field is not the shadow placeholder")
	}
	uid, err := parseIdentityNumber("uid", fields[2])
	if err != nil {
		return passwdEntry{}, err
	}
	gid, err := parseIdentityNumber("gid", fields[3])
	if err != nil {
		return passwdEntry{}, err
	}
	if fields[0] == "" || fields[5] == "" || fields[6] == "" {
		return passwdEntry{}, fmt.Errorf("passwd record has an empty name, home, or shell")
	}
	return passwdEntry{
		name: fields[0], uid: uid, primaryGID: gid,
		gecos: fields[4], home: fields[5], shell: fields[6],
	}, nil
}

func parseIdentityNumber(subject, value string) (uint32, error) {
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("passwd %s %q is invalid", subject, value)
	}
	return uint32(number), nil
}

func reconcileAccount(intent accountIntent, observed accountObservation) accountDecision {
	name := intent.accountName()
	snapshot, ok := observed.(accountSnapshot)
	if !ok {
		failure := observed.(accountObservationFailed)
		return blockedAccount(name, nil, failure.detail)
	}
	if blockers := accountLookupBlockers(name, snapshot); len(blockers) != 0 {
		return accountIdentificationBlocked{blockers: blockers}
	}
	global, globalFound := snapshot.globalName.(passwdFound)
	local, localFound := snapshot.localName.(passwdFound)
	if !globalFound || !localFound {
		return reconcileMissingAccount(intent, snapshot, globalFound, localFound)
	}
	if global.entry.name != name || local.entry.name != name {
		return blockedAccount(name, nil, fmt.Sprintf("name lookup returned %q globally and %q locally", global.entry.name, local.entry.name))
	}
	if global.entry != local.entry {
		return blockedAccount(name, nil, "local and NSS passwd records disagree")
	}
	globalUID, globalUIDFound := snapshot.globalUID.(passwdFound)
	localUID, localUIDFound := snapshot.localUID.(passwdFound)
	if !globalUIDFound || !localUIDFound || globalUID.entry != global.entry || localUID.entry != local.entry {
		return blockedAccount(name, nil, "UID lookup does not resolve to the same local and NSS account")
	}
	if desired, ok := intent.(presentAccountIntent); ok {
		if detail := presentAccountMismatch(desired, global.entry); detail != "" {
			return blockedAccount(name, nil, detail)
		}
	}
	fact := Fact{Subject: "account:" + name, Detail: fmt.Sprintf("local and NSS identity agree: uid=%d gid=%d home=%q shell=%q", global.entry.uid, global.entry.primaryGID, global.entry.home, global.entry.shell)}
	return accountIdentified{facts: []Fact{fact}}
}

func accountLookupBlockers(name string, snapshot accountSnapshot) []Blocker {
	lookups := []struct {
		subject string
		value   accountLookup
	}{
		{"global-name", snapshot.globalName}, {"local-name", snapshot.localName},
		{"global-uid", snapshot.globalUID}, {"local-uid", snapshot.localUID},
	}
	var blockers []Blocker
	for _, lookup := range lookups {
		if failed, ok := lookup.value.(passwdLookupFailed); ok {
			blockers = append(blockers, Blocker{Subject: "account:" + name + ":" + lookup.subject, Detail: failed.detail})
		}
	}
	return blockers
}

func reconcileMissingAccount(intent accountIntent, snapshot accountSnapshot, globalFound, localFound bool) accountDecision {
	name := intent.accountName()
	if globalFound && !localFound {
		return blockedAccount(name, nil, "NSS identity exists without a matching local account")
	}
	if localFound && !globalFound {
		return blockedAccount(name, nil, "local passwd identity is not visible through NSS")
	}
	if _, present := intent.(existingAccountIntent); present {
		return blockedAccount(name, nil, "explicit existing account was not found locally or through NSS")
	}
	if _, found := snapshot.globalUID.(passwdFound); found {
		return blockedAccount(name, nil, "requested UID is already owned through NSS")
	}
	if _, found := snapshot.localUID.(passwdFound); found {
		return blockedAccount(name, nil, "requested UID is already owned in the local passwd database")
	}
	fact := Fact{Subject: "account:" + name, Detail: "absent locally and through NSS; requested UID is unclaimed"}
	return accountAbsentEligible{facts: []Fact{fact}}
}

func presentAccountMismatch(intent presentAccountIntent, entry passwdEntry) string {
	switch {
	case entry.name != intent.name:
		return fmt.Sprintf("account name is %q, want %q", entry.name, intent.name)
	case entry.uid != intent.uid:
		return fmt.Sprintf("account uid is %d, want %d", entry.uid, intent.uid)
	case entry.primaryGID != intent.primaryGroup.gid:
		return fmt.Sprintf("account primary gid is %d, want %d", entry.primaryGID, intent.primaryGroup.gid)
	case entry.home != intent.home.path:
		return fmt.Sprintf("account home is %q, want %q", entry.home, intent.home.path)
	case entry.shell != intent.shell:
		return fmt.Sprintf("account shell is %q, want %q", entry.shell, intent.shell)
	default:
		return ""
	}
}

func blockedAccount(name string, facts []Fact, detail string) accountDecision {
	return accountIdentificationBlocked{facts: facts, blockers: []Blocker{{Subject: "account:" + name, Detail: detail}}}
}

func (binding accountBinding) guard(ctx context.Context, runner Runner) (bool, error) {
	if binding.intent == nil {
		return false, nil
	}
	reviewed, ok := binding.observed.(accountSnapshot)
	if !ok || reviewed.getentPath == "" {
		return false, fmt.Errorf("account observer executable is not identified")
	}
	current := observeAccountWithGetent(ctx, runner, binding.intent, reviewed.getentPath)
	if failed, ok := current.(accountObservationFailed); ok {
		return false, fmt.Errorf("account cannot be revalidated: %s", failed.detail)
	}
	snapshot := current.(accountSnapshot)
	if blockers := accountLookupBlockers(binding.intent.accountName(), snapshot); len(blockers) != 0 {
		return false, fmt.Errorf("account cannot be revalidated: %s", blockers[0].Detail)
	}
	if !reflect.DeepEqual(current, binding.observed) {
		return true, nil
	}
	if stale, err := binding.lock.guard(ctx, runner); err != nil || stale {
		return stale, err
	}
	return binding.home.guard(ctx, runner)
}

func (binding accountBinding) uid() (uint32, bool) {
	snapshot, ok := binding.observed.(accountSnapshot)
	if !ok {
		return 0, false
	}
	found, ok := snapshot.globalName.(passwdFound)
	return found.entry.uid, ok
}

func (binding accountBinding) guardUID(runner Runner) (bool, error) {
	targetUID, ok := binding.uid()
	if !ok {
		return false, fmt.Errorf("target account uid is not identified")
	}
	effectiveUID, err := runner.EffectiveUID()
	if err != nil {
		return false, fmt.Errorf("effective uid is unavailable: %w", err)
	}
	return effectiveUID == 0 || effectiveUID != targetUID, nil
}
