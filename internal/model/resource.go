package model

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

//sumtype:decl
type EnableIntent interface {
	enableIntent() enableIntent
}

type enableIntent uint8

const (
	enableUnmanaged enableIntent = iota
	enableEnabled
	enableDisabled
)

func (intent enableIntent) enableIntent() enableIntent { return intent }
func UnmanagedEnableIntent() EnableIntent              { return enableUnmanaged }
func EnabledIntent() EnableIntent                      { return enableEnabled }
func DisabledIntent() EnableIntent                     { return enableDisabled }

//sumtype:decl
type RunIntent interface {
	runIntent() runIntent
}

type runIntent uint8

const (
	runUnmanaged runIntent = iota
	runRunning
	runStopped
)

func (intent runIntent) runIntent() runIntent { return intent }
func UnmanagedRunIntent() RunIntent           { return runUnmanaged }
func RunningIntent() RunIntent                { return runRunning }
func StoppedIntent() RunIntent                { return runStopped }

type coordinate struct {
	kind  string
	value string
}

//sumtype:decl
type Resource interface {
	Key() Key
	resource()
	desired() string
	dependencies() []Key
	coordinates() []coordinate
}

type packageResource struct{ key packageKey }

func NewPackage(id PackageID) (Resource, error) {
	key, err := NewPackageKey(id)
	if err != nil {
		return nil, err
	}
	return packageResource{key: key.(packageKey)}, nil
}
func (r packageResource) Key() Key                { return r.key }
func (packageResource) resource()                 {}
func (packageResource) desired() string           { return "present" }
func (packageResource) dependencies() []Key       { return nil }
func (packageResource) coordinates() []coordinate { return nil }

type serviceResource struct {
	key      serviceKey
	enable   enableIntent
	run      runIntent
	packages []packageKey
}

func NewService(id ServiceID, target ServiceTarget, enable EnableIntent, run RunIntent, packages []PackageKey) (Resource, error) {
	serviceID, ok := id.(serviceID)
	if !ok {
		return nil, fmt.Errorf("invalid service ID")
	}
	if target == nil {
		return nil, fmt.Errorf("service target is required")
	}
	if enable == nil {
		return nil, fmt.Errorf("enable intent is required")
	}
	if run == nil {
		return nil, fmt.Errorf("run intent is required")
	}
	enableValue := enable.enableIntent()
	runValue := run.runIntent()
	if enableValue == enableUnmanaged && runValue == runUnmanaged {
		return nil, fmt.Errorf("service must own at least one lifecycle axis")
	}
	seen := make(map[string]struct{}, len(packages))
	copied := make([]packageKey, 0, len(packages))
	for _, pkg := range packages {
		value, ok := pkg.(packageKey)
		if !ok {
			return nil, fmt.Errorf("invalid package dependency")
		}
		key := value.Canonical()
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate package dependency %s", key)
		}
		seen[key] = struct{}{}
		copied = append(copied, value)
	}
	return serviceResource{
		key:      serviceKey{id: serviceID, target: target.serviceTarget()},
		enable:   enableValue,
		run:      runValue,
		packages: copied,
	}, nil
}
func (r serviceResource) Key() Key { return r.key }
func (serviceResource) resource()  {}
func (r serviceResource) desired() string {
	return strconv.Itoa(int(r.enable)) + ":" + strconv.Itoa(int(r.run))
}
func (r serviceResource) dependencies() []Key {
	deps := make([]Key, 0, len(r.packages)+1)
	if r.key.target.isUser {
		deps = append(deps, r.key.target.user)
	}
	for _, pkg := range r.packages {
		deps = append(deps, pkg)
	}
	return deps
}
func (serviceResource) coordinates() []coordinate { return nil }

type groupResource struct {
	key     groupKey
	managed bool
	gid     uint32
}

func NewManagedGroup(key GroupKey, gid uint32) (Resource, error) {
	value, ok := key.(groupKey)
	if !ok {
		return nil, fmt.Errorf("invalid group key")
	}
	return groupResource{key: value, managed: true, gid: gid}, nil
}
func NewExternalGroup(key GroupKey) (Resource, error) {
	value, ok := key.(groupKey)
	if !ok {
		return nil, fmt.Errorf("invalid group key")
	}
	return groupResource{key: value}, nil
}
func (r groupResource) Key() Key { return r.key }
func (groupResource) resource()  {}
func (r groupResource) desired() string {
	if !r.managed {
		return "external"
	}
	return "managed:" + strconv.FormatUint(uint64(r.gid), 10)
}
func (groupResource) dependencies() []Key { return nil }
func (r groupResource) coordinates() []coordinate {
	if !r.managed {
		return nil
	}
	return []coordinate{{kind: "GID", value: strconv.FormatUint(uint64(r.gid), 10)}}
}

type accountResource struct {
	key     accountKey
	managed bool
	uid     uint32
	group   groupKey
	home    string
}

func NewManagedAccount(key AccountKey, uid uint32, group GroupKey, home string) (Resource, error) {
	accountValue, accountOK := key.(accountKey)
	groupValue, groupOK := group.(groupKey)
	if !accountOK || !groupOK {
		return nil, fmt.Errorf("valid account and primary group are required")
	}
	if !validAbsolutePath(home) {
		return nil, fmt.Errorf("account home must be a clean absolute path")
	}
	return accountResource{key: accountValue, managed: true, uid: uid, group: groupValue, home: home}, nil
}
func NewExternalAccount(key AccountKey) (Resource, error) {
	value, ok := key.(accountKey)
	if !ok {
		return nil, fmt.Errorf("invalid account key")
	}
	return accountResource{key: value}, nil
}
func (r accountResource) Key() Key { return r.key }
func (accountResource) resource()  {}
func (r accountResource) desired() string {
	if !r.managed {
		return "external"
	}
	return "managed:" + strconv.FormatUint(uint64(r.uid), 10) + ":" + r.group.name + ":" + r.home
}
func (r accountResource) dependencies() []Key {
	if !r.managed {
		return nil
	}
	return []Key{r.group}
}
func (r accountResource) coordinates() []coordinate {
	if !r.managed {
		return nil
	}
	return []coordinate{
		{kind: "UID", value: strconv.FormatUint(uint64(r.uid), 10)},
		{kind: "home", value: r.home},
	}
}

type homeResource struct{ key homeKey }

func NewHome(account AccountKey) (Resource, error) {
	value, ok := account.(accountKey)
	if !ok {
		return nil, fmt.Errorf("invalid account key")
	}
	return homeResource{key: homeKey{account: value}}, nil
}
func (r homeResource) Key() Key                { return r.key }
func (homeResource) resource()                 {}
func (homeResource) desired() string           { return "present" }
func (r homeResource) dependencies() []Key     { return []Key{r.key.account} }
func (homeResource) coordinates() []coordinate { return nil }

type homeModeResource struct {
	key  homeModeKey
	mode uint16
}

func NewHomeMode(account AccountKey, mode uint16) (Resource, error) {
	value, ok := account.(accountKey)
	if !ok {
		return nil, fmt.Errorf("invalid account key")
	}
	if mode > 0o777 {
		return nil, fmt.Errorf("home mode exceeds 0777")
	}
	return homeModeResource{key: homeModeKey{account: value}, mode: mode}, nil
}
func (r homeModeResource) Key() Key                { return r.key }
func (homeModeResource) resource()                 {}
func (r homeModeResource) desired() string         { return fmt.Sprintf("%04o", r.mode) }
func (r homeModeResource) dependencies() []Key     { return []Key{homeKey{account: r.key.account}} }
func (homeModeResource) coordinates() []coordinate { return nil }

type accountLockResource struct{ key accountLockKey }

func NewAccountLock(account AccountKey) (Resource, error) {
	value, ok := account.(accountKey)
	if !ok {
		return nil, fmt.Errorf("invalid account key")
	}
	return accountLockResource{key: accountLockKey{account: value}}, nil
}
func (r accountLockResource) Key() Key                { return r.key }
func (accountLockResource) resource()                 {}
func (accountLockResource) desired() string           { return "locked" }
func (r accountLockResource) dependencies() []Key     { return []Key{r.key.account} }
func (accountLockResource) coordinates() []coordinate { return nil }

type accountShellResource struct {
	key   accountShellKey
	shell string
}

func NewAccountShell(account AccountKey, shell string) (Resource, error) {
	value, ok := account.(accountKey)
	if !ok || !validAbsolutePath(shell) {
		return nil, fmt.Errorf("account shell must be a clean absolute path")
	}
	return accountShellResource{key: accountShellKey{account: value}, shell: shell}, nil
}
func (r accountShellResource) Key() Key                { return r.key }
func (accountShellResource) resource()                 {}
func (r accountShellResource) desired() string         { return r.shell }
func (r accountShellResource) dependencies() []Key     { return []Key{r.key.account} }
func (accountShellResource) coordinates() []coordinate { return nil }

type membershipResource struct {
	key     membershipKey
	present bool
}

func NewMembership(account AccountKey, group GroupKey, present bool) (Resource, error) {
	accountValue, accountOK := account.(accountKey)
	groupValue, groupOK := group.(groupKey)
	if !accountOK || !groupOK {
		return nil, fmt.Errorf("membership account and group are required")
	}
	return membershipResource{key: membershipKey{account: accountValue, group: groupValue}, present: present}, nil
}
func (r membershipResource) Key() Key                { return r.key }
func (membershipResource) resource()                 {}
func (r membershipResource) desired() string         { return strconv.FormatBool(r.present) }
func (r membershipResource) dependencies() []Key     { return []Key{r.key.account, r.key.group} }
func (membershipResource) coordinates() []coordinate { return nil }

type hostnameResource struct{ value string }

func NewHostname(value string) (Resource, error) {
	if !validHostname(value) {
		return nil, fmt.Errorf("invalid hostname %q", value)
	}
	return hostnameResource{value: value}, nil
}
func (hostnameResource) Key() Key                  { return hostnameKey{} }
func (hostnameResource) resource()                 {}
func (r hostnameResource) desired() string         { return r.value }
func (hostnameResource) dependencies() []Key       { return nil }
func (hostnameResource) coordinates() []coordinate { return nil }

type timezoneResource struct{ value string }

func NewTimezone(value string) (Resource, error) {
	if !validTimezone(value) {
		return nil, fmt.Errorf("invalid timezone %q", value)
	}
	return timezoneResource{value: value}, nil
}
func (timezoneResource) Key() Key                  { return timezoneKey{} }
func (timezoneResource) resource()                 {}
func (r timezoneResource) desired() string         { return r.value }
func (timezoneResource) dependencies() []Key       { return nil }
func (timezoneResource) coordinates() []coordinate { return nil }

func validAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && !strings.ContainsRune(value, 0) && path.Clean(value) == value
}

func validHostname(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				character != '-' {
				return false
			}
		}
	}
	return true
}

func validTimezone(value string) bool {
	if value == "" || len(value) > 4095 || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return false
		}
		for _, character := range component {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') &&
				character != '_' && character != '+' && character != '-' {
				return false
			}
		}
	}
	return true
}
