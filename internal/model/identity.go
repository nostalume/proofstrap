package model

import (
	"fmt"
	"unicode/utf8"
)

func validSymbol(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func validAccountName(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == ':' || character == '/' || character == 0 || character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

//sumtype:decl
type PackageID interface {
	packageID()
	canonical() string
	String() string
}

type packageID struct {
	name string
}

func NewPackageID(name string) (PackageID, error) {
	if !validSymbol(name) {
		return nil, fmt.Errorf("invalid package name %q", name)
	}
	return packageID{name: name}, nil
}

func (packageID) packageID() {}
func (id packageID) canonical() string {
	return id.name
}
func (id packageID) String() string { return id.name }

//sumtype:decl
type ServiceID interface {
	serviceID()
	canonical() string
	String() string
}

type serviceID struct {
	name string
}

func NewServiceID(name string) (ServiceID, error) {
	if !validSymbol(name) {
		return nil, fmt.Errorf("invalid service name %q", name)
	}
	return serviceID{name: name}, nil
}

func (serviceID) serviceID() {}
func (id serviceID) canonical() string {
	return id.name
}
func (id serviceID) String() string { return id.name }

//sumtype:decl
type Key interface {
	Canonical() string
	key()
}

//sumtype:decl
type PackageKey interface {
	Key
	packageKey()
}

type packageKey struct{ id packageID }

func NewPackageKey(id PackageID) (PackageKey, error) {
	value, ok := id.(packageID)
	if !ok {
		return nil, fmt.Errorf("invalid package ID")
	}
	return packageKey{id: value}, nil
}
func (k packageKey) Canonical() string { return "package:" + k.id.canonical() }
func (packageKey) key()                {}
func (packageKey) packageKey()         {}

type serviceKey struct {
	id     serviceID
	target serviceTargetKey
}

func (k serviceKey) Canonical() string {
	return "service:" + k.id.canonical() + ":" + k.target.canonical()
}
func (serviceKey) key() {}

//sumtype:decl
type GroupKey interface {
	Key
	groupKey()
}

type groupKey struct{ name string }

func NewGroupKey(name string) (GroupKey, error) {
	if !validAccountName(name) {
		return nil, fmt.Errorf("invalid group name %q", name)
	}
	return groupKey{name: name}, nil
}
func (k groupKey) Canonical() string { return "group:" + k.name }
func (groupKey) key()                {}
func (groupKey) groupKey()           {}

//sumtype:decl
type AccountKey interface {
	Key
	accountKey()
}

type accountKey struct{ name string }

func NewAccountKey(name string) (AccountKey, error) {
	if !validAccountName(name) {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	return accountKey{name: name}, nil
}
func (k accountKey) Canonical() string { return "account:" + k.name }
func (accountKey) key()                {}
func (accountKey) accountKey()         {}

type accountLockKey struct{ account accountKey }

func (k accountLockKey) Canonical() string { return "account-lock:" + k.account.name }
func (accountLockKey) key()                {}

type accountShellKey struct{ account accountKey }

func (k accountShellKey) Canonical() string { return "account-shell:" + k.account.name }
func (accountShellKey) key()                {}

type membershipKey struct {
	account accountKey
	group   groupKey
}

func (k membershipKey) Canonical() string {
	return "membership:" + k.account.name + ":" + k.group.name
}
func (membershipKey) key() {}

type homeKey struct{ account accountKey }

func (k homeKey) Canonical() string { return "home:" + k.account.name }
func (homeKey) key()                {}

type homeModeKey struct{ account accountKey }

func (k homeModeKey) Canonical() string { return "home-mode:" + k.account.name }
func (homeModeKey) key()                {}

type hostnameKey struct{}

func (hostnameKey) Canonical() string { return "hostname" }
func (hostnameKey) key()              {}

type timezoneKey struct{}

func (timezoneKey) Canonical() string { return "timezone" }
func (timezoneKey) key()              {}

type serviceTargetKey struct {
	user   accountKey
	isUser bool
}

func (k serviceTargetKey) canonical() string {
	if k.isUser {
		return "user:" + k.user.name
	}
	return "system"
}

//sumtype:decl
type ServiceTarget interface {
	serviceTarget() serviceTargetKey
}

type systemServiceTarget struct{}

func (systemServiceTarget) serviceTarget() serviceTargetKey { return serviceTargetKey{} }

type userServiceTarget struct{ account accountKey }

func (t userServiceTarget) serviceTarget() serviceTargetKey {
	return serviceTargetKey{user: t.account, isUser: true}
}

func SystemServiceTarget() ServiceTarget { return systemServiceTarget{} }

func ServiceTargetUser(target ServiceTarget) (string, bool) {
	value, ok := target.(userServiceTarget)
	if !ok {
		return "", false
	}
	return value.account.name, true
}

func UserServiceTarget(account AccountKey) (ServiceTarget, error) {
	value, ok := account.(accountKey)
	if !ok {
		return nil, fmt.Errorf("invalid account key")
	}
	return userServiceTarget{account: value}, nil
}
