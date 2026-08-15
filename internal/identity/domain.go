package identity

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

type DecisionKind uint8

const (
	Exact DecisionKind = iota + 1
	Change
	Blocked
)

type Decision struct {
	kind   DecisionKind
	detail string
}

func (decision Decision) Kind() DecisionKind { return decision.kind }
func (decision Decision) Detail() string     { return decision.detail }

type lookupState uint8

const (
	lookupMissing lookupState = iota + 1
	lookupFound
	lookupFailed
)

type groupRecord struct {
	name    string
	gid     uint32
	members []string
}

type groupIntent struct {
	name    string
	managed bool
	gid     uint32
}

func groupIntentOf(value model.Group) groupIntent {
	return groupIntent{name: value.Name(), managed: value.Managed(), gid: value.GID()}
}

type groupLookup struct {
	state  lookupState
	record groupRecord
	detail string
}

type groupObservation struct {
	nameGlobal, nameLocal, numberGlobal, numberLocal groupLookup
}

func missingGroup() groupLookup                { return groupLookup{state: lookupMissing} }
func foundGroup(value groupRecord) groupLookup { return groupLookup{state: lookupFound, record: value} }
func failedGroup(detail string) groupLookup    { return groupLookup{state: lookupFailed, detail: detail} }
func missingGroupObservation() groupObservation {
	missing := missingGroup()
	return groupObservation{missing, missing, missing, missing}
}
func foundGroupObservation(value groupRecord) groupObservation {
	found := foundGroup(value)
	return groupObservation{found, found, found, found}
}

func reconcileGroup(desired model.Group, observed groupObservation) Decision {
	if !desired.Valid() {
		return blocked("invalid group projection")
	}
	return reconcileGroupIntent(groupIntentOf(desired), observed)
}

func reconcileGroupIntent(desired groupIntent, observed groupObservation) Decision {
	if desired.name == "" {
		return blocked("invalid group intent")
	}
	if desired.name == "root" || desired.managed && desired.gid == 0 {
		return blocked("root group is outside managed identity authority")
	}
	if detail := failedGroupLookup(observed); detail != "" {
		return blocked(detail)
	}
	global, globalFound := groupFound(observed.nameGlobal)
	local, localFound := groupFound(observed.nameLocal)
	if globalFound != localFound {
		return blocked("global and files-only group visibility disagree")
	}
	if !globalFound {
		if !desired.managed {
			return blocked("external group is absent")
		}
		if observed.numberGlobal.state == lookupFound || observed.numberLocal.state == lookupFound {
			return blocked("requested GID is already owned")
		}
		if observed.numberGlobal.state != lookupMissing || observed.numberLocal.state != lookupMissing {
			return blocked("requested GID ownership is indeterminate")
		}
		return Decision{kind: Change, detail: "group is absent and GID is unclaimed"}
	}
	if !sameGroup(global, local) {
		return blocked("global and files-only group records disagree")
	}
	if global.name != desired.name {
		return blocked("group name lookup returned another identity")
	}
	if desired.managed && global.gid != desired.gid {
		return blocked("managed group GID differs")
	}
	numberGlobal, numberGlobalFound := groupFound(observed.numberGlobal)
	numberLocal, numberLocalFound := groupFound(observed.numberLocal)
	if !numberGlobalFound || !numberLocalFound || !sameGroup(global, numberGlobal) || !sameGroup(global, numberLocal) {
		return blocked("numeric GID does not resolve to the same group")
	}
	return Decision{kind: Exact, detail: "global and files-only group records agree"}
}

func failedGroupLookup(observed groupObservation) string {
	for _, lookup := range []groupLookup{observed.nameGlobal, observed.nameLocal, observed.numberGlobal, observed.numberLocal} {
		if lookup.state == lookupFailed {
			if lookup.detail == "" {
				return "group lookup failed"
			}
			return lookup.detail
		}
	}
	return ""
}

func groupFound(lookup groupLookup) (groupRecord, bool) {
	return lookup.record, lookup.state == lookupFound
}

func sameGroup(left, right groupRecord) bool {
	return left.name == right.name && left.gid == right.gid && slices.Equal(left.members, right.members)
}

type passwdRecord struct {
	name, gecos, home, shell string
	uid, gid                 uint32
}

type accountIntent struct {
	name, primaryGroup, home string
	uid                      uint32
	managed                  bool
}

func accountIntentOf(value model.Account) accountIntent {
	return accountIntent{name: value.Name(), primaryGroup: value.PrimaryGroup(), home: value.Home(), uid: value.UID(), managed: value.Managed()}
}

type accountLookup struct {
	state  lookupState
	record passwdRecord
	detail string
}

type accountObservation struct {
	nameGlobal, nameLocal, numberGlobal, numberLocal accountLookup
}

func missingAccount() accountLookup { return accountLookup{state: lookupMissing} }
func foundAccount(value passwdRecord) accountLookup {
	return accountLookup{state: lookupFound, record: value}
}
func failedAccount(detail string) accountLookup {
	return accountLookup{state: lookupFailed, detail: detail}
}
func missingAccountObservation() accountObservation {
	missing := missingAccount()
	return accountObservation{missing, missing, missing, missing}
}
func foundAccountObservation(value passwdRecord) accountObservation {
	found := foundAccount(value)
	return accountObservation{found, found, found, found}
}

func reconcileAccount(desired model.Account, primary model.Group, observed accountObservation) Decision {
	if !desired.Valid() {
		return blocked("invalid account projection")
	}
	return reconcileAccountIntent(accountIntentOf(desired), groupIntentOf(primary), observed)
}

func reconcileAccountIntent(desired accountIntent, primary groupIntent, observed accountObservation) Decision {
	if desired.name == "" {
		return blocked("invalid account intent")
	}
	if desired.name == "root" || desired.managed && desired.uid == 0 {
		return blocked("root account is outside managed identity authority")
	}
	if desired.managed && (!primary.managed || primary.name != desired.primaryGroup || primary.gid == 0) {
		return blocked("managed account primary group evidence is invalid")
	}
	for _, lookup := range []accountLookup{observed.nameGlobal, observed.nameLocal, observed.numberGlobal, observed.numberLocal} {
		if lookup.state == lookupFailed {
			return blocked(lookup.detail)
		}
	}
	global, globalFound := accountFound(observed.nameGlobal)
	local, localFound := accountFound(observed.nameLocal)
	if globalFound != localFound {
		return blocked("global and files-only account visibility disagree")
	}
	if !globalFound {
		if !desired.managed {
			return blocked("external account is absent")
		}
		if observed.numberGlobal.state == lookupFound || observed.numberLocal.state == lookupFound {
			return blocked("requested UID is already owned")
		}
		if observed.numberGlobal.state != lookupMissing || observed.numberLocal.state != lookupMissing {
			return blocked("requested UID ownership is indeterminate")
		}
		return Decision{kind: Change, detail: "account is absent and UID is unclaimed"}
	}
	if global != local {
		return blocked("global and files-only passwd records disagree")
	}
	if global.name != desired.name {
		return blocked("account name lookup returned another identity")
	}
	if desired.managed && (global.uid != desired.uid || global.gid != primary.gid || global.home != desired.home) {
		return blocked("managed account coordinates differ")
	}
	numberGlobal, numberGlobalFound := accountFound(observed.numberGlobal)
	numberLocal, numberLocalFound := accountFound(observed.numberLocal)
	if !numberGlobalFound || !numberLocalFound || numberGlobal != global || numberLocal != global {
		return blocked("numeric UID does not resolve to the same account")
	}
	return Decision{kind: Exact, detail: "global and files-only passwd records agree"}
}

func accountFound(lookup accountLookup) (passwdRecord, bool) {
	return lookup.record, lookup.state == lookupFound
}

func blocked(detail string) Decision { return Decision{kind: Blocked, detail: detail} }

func parseGroupRecord(record string) (groupRecord, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 4 || fields[0] == "" || fields[1] != "x" {
		return groupRecord{}, fmt.Errorf("invalid group record")
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return groupRecord{}, fmt.Errorf("invalid group GID %q", fields[2])
	}
	var members []string
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
		slices.Sort(members)
		for index, member := range members {
			if member == "" || index != 0 && members[index-1] == member {
				return groupRecord{}, fmt.Errorf("invalid group member list")
			}
		}
	}
	return groupRecord{name: fields[0], gid: uint32(gid), members: members}, nil
}

func parsePasswdRecord(record string) (passwdRecord, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 7 || fields[0] == "" || fields[1] != "x" || fields[5] == "" || fields[6] == "" {
		return passwdRecord{}, fmt.Errorf("invalid passwd record")
	}
	uid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return passwdRecord{}, fmt.Errorf("invalid passwd UID %q", fields[2])
	}
	gid, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return passwdRecord{}, fmt.Errorf("invalid passwd GID %q", fields[3])
	}
	return passwdRecord{name: fields[0], uid: uint32(uid), gid: uint32(gid), gecos: fields[4], home: fields[5], shell: fields[6]}, nil
}
