package proofstrap

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type groupEntry struct {
	name    string
	gid     uint32
	members []string
}

//sumtype:decl
type groupLookup interface{ groupLookup() }

type groupFound struct{ entry groupEntry }
type groupMissing struct{}
type groupLookupFailed struct{ detail string }

func (groupFound) groupLookup()        {}
func (groupMissing) groupLookup()      {}
func (groupLookupFailed) groupLookup() {}

type primaryGroupSnapshot struct {
	getentPath string
	globalName groupLookup
	localName  groupLookup
	globalGID  groupLookup
	localGID   groupLookup
}

//sumtype:decl
type primaryGroupDecision interface{ primaryGroupDecision() }

type primaryGroupIdentified struct{ facts []Fact }
type primaryGroupAbsentEligible struct{ facts []Fact }
type primaryGroupBlocked struct{ blockers []Blocker }

func (primaryGroupIdentified) primaryGroupDecision()     {}
func (primaryGroupAbsentEligible) primaryGroupDecision() {}
func (primaryGroupBlocked) primaryGroupDecision()        {}

type primaryGroupBinding struct {
	intent   primaryGroupIntent
	observed primaryGroupSnapshot
}

func (binding primaryGroupBinding) guard(ctx context.Context, runner Runner) (bool, error) {
	fresh := observePrimaryGroup(ctx, runner, binding.observed.getentPath, binding.intent)
	if blockers := primaryGroupLookupBlockers(binding.intent.name, fresh); len(blockers) != 0 {
		return false, fmt.Errorf("primary group observation is indeterminate: %s", blockers[0].Detail)
	}
	return !reflect.DeepEqual(binding.observed, fresh), nil
}

func observePrimaryGroup(ctx context.Context, runner Runner, getent string, intent primaryGroupIntent) primaryGroupSnapshot {
	key := strconv.FormatUint(uint64(intent.gid), 10)
	return primaryGroupSnapshot{
		getentPath: getent,
		globalName: lookupGroup(ctx, runner, getent, false, intent.name),
		localName:  lookupGroup(ctx, runner, getent, true, intent.name),
		globalGID:  lookupGroup(ctx, runner, getent, false, key),
		localGID:   lookupGroup(ctx, runner, getent, true, key),
	}
}

func lookupGroup(ctx context.Context, runner Runner, getent string, local bool, key string) groupLookup {
	args := []string{"group", key}
	if local {
		args = []string{"-s", "files", "group", key}
	}
	result := runner.Run(ctx, Command{Name: getent, Args: args, timeout: 5 * time.Second})
	if result.Err == nil && result.ExitCode == 2 && result.Stdout == "" && result.Stderr == "" {
		return groupMissing{}
	}
	if result.Err != nil || result.ExitCode != 0 || result.Stderr != "" {
		return groupLookupFailed{detail: resultDetail(result)}
	}
	entry, err := parseGroupEntry(result.Stdout)
	if err != nil {
		return groupLookupFailed{detail: err.Error()}
	}
	return groupFound{entry: entry}
}

func parseGroupEntry(output string) (groupEntry, error) {
	if !strings.HasSuffix(output, "\n") {
		return groupEntry{}, fmt.Errorf("group record is not newline terminated")
	}
	record := strings.TrimSuffix(output, "\n")
	if record == "" || strings.Contains(record, "\n") {
		count := 0
		if record != "" {
			count = strings.Count(record, "\n") + 1
		}
		return groupEntry{}, fmt.Errorf("group lookup returned %d records", count)
	}
	fields := strings.Split(record, ":")
	if len(fields) != 4 {
		return groupEntry{}, fmt.Errorf("group record has %d fields, want 4", len(fields))
	}
	if fields[1] != "x" {
		return groupEntry{}, fmt.Errorf("group credential field is not the shadow placeholder")
	}
	if fields[0] == "" {
		return groupEntry{}, fmt.Errorf("group record has an empty name")
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return groupEntry{}, fmt.Errorf("group gid %q is invalid", fields[2])
	}
	var members []string
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
		for _, member := range members {
			if member == "" {
				return groupEntry{}, fmt.Errorf("group record has an empty member")
			}
		}
	}
	return groupEntry{name: fields[0], gid: uint32(gid), members: members}, nil
}

func reconcilePrimaryGroup(intent primaryGroupIntent, snapshot primaryGroupSnapshot) primaryGroupDecision {
	if blockers := primaryGroupLookupBlockers(intent.name, snapshot); len(blockers) != 0 {
		return primaryGroupBlocked{blockers: blockers}
	}
	globalName, globalFound := snapshot.globalName.(groupFound)
	localName, localFound := snapshot.localName.(groupFound)
	if !globalFound || !localFound {
		return reconcileMissingPrimaryGroup(intent, snapshot, globalFound, localFound)
	}
	if globalName.entry.name != intent.name || localName.entry.name != intent.name {
		return blockedPrimaryGroup(intent.name, "name lookup returned a different group")
	}
	if !reflect.DeepEqual(globalName.entry, localName.entry) {
		return blockedPrimaryGroup(intent.name, "local and NSS group records disagree")
	}
	if globalName.entry.gid != intent.gid {
		return blockedPrimaryGroup(intent.name, fmt.Sprintf("existing gid is %d, requested %d", globalName.entry.gid, intent.gid))
	}
	globalGID, globalGIDFound := snapshot.globalGID.(groupFound)
	localGID, localGIDFound := snapshot.localGID.(groupFound)
	if !globalGIDFound || !localGIDFound || !reflect.DeepEqual(globalGID.entry, globalName.entry) || !reflect.DeepEqual(localGID.entry, localName.entry) {
		return blockedPrimaryGroup(intent.name, "GID lookup does not resolve to the same local and NSS group")
	}
	fact := Fact{Subject: "primary-group:" + intent.name, Detail: fmt.Sprintf("local and NSS group agree: gid=%d", intent.gid)}
	return primaryGroupIdentified{facts: []Fact{fact}}
}

func primaryGroupLookupBlockers(name string, snapshot primaryGroupSnapshot) []Blocker {
	lookups := []struct {
		subject string
		value   groupLookup
	}{
		{"global-name", snapshot.globalName}, {"local-name", snapshot.localName},
		{"global-gid", snapshot.globalGID}, {"local-gid", snapshot.localGID},
	}
	var blockers []Blocker
	for _, lookup := range lookups {
		if failed, ok := lookup.value.(groupLookupFailed); ok {
			blockers = append(blockers, Blocker{Subject: "primary-group:" + name + ":" + lookup.subject, Detail: failed.detail})
		}
	}
	return blockers
}

func reconcileMissingPrimaryGroup(intent primaryGroupIntent, snapshot primaryGroupSnapshot, globalFound, localFound bool) primaryGroupDecision {
	if globalFound && !localFound {
		return blockedPrimaryGroup(intent.name, "NSS group exists without a matching local group")
	}
	if localFound && !globalFound {
		return blockedPrimaryGroup(intent.name, "local group is absent from NSS resolution")
	}
	globalGID, globalGIDFound := snapshot.globalGID.(groupFound)
	localGID, localGIDFound := snapshot.localGID.(groupFound)
	if globalGIDFound || localGIDFound {
		if globalGIDFound && localGIDFound && reflect.DeepEqual(globalGID.entry, localGID.entry) {
			return blockedPrimaryGroup(intent.name, fmt.Sprintf("gid %d belongs to %q", intent.gid, globalGID.entry.name))
		}
		return blockedPrimaryGroup(intent.name, fmt.Sprintf("gid %d has inconsistent local and NSS ownership", intent.gid))
	}
	fact := Fact{Subject: "primary-group:" + intent.name, Detail: fmt.Sprintf("absent locally and through NSS: gid=%d; eligible for create-only establishment", intent.gid)}
	return primaryGroupAbsentEligible{facts: []Fact{fact}}
}

func blockedPrimaryGroup(name, detail string) primaryGroupBlocked {
	return primaryGroupBlocked{blockers: []Blocker{{Subject: "primary-group:" + name, Detail: detail}}}
}

func verifyPrimaryGroup(intent primaryGroupIntent, observed primaryGroupSnapshot) (bool, string) {
	switch decision := reconcilePrimaryGroup(intent, observed).(type) {
	case primaryGroupIdentified:
		return true, decision.facts[0].Detail
	case primaryGroupAbsentEligible:
		return false, decision.facts[0].Detail
	case primaryGroupBlocked:
		return false, decision.blockers[0].Detail
	default:
		return false, "unknown primary group decision"
	}
}
