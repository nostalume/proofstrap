package proofstrap

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/pelletier/go-toml/v2"
)

type desiredStateFile struct {
	Modules []string            `toml:"modules"`
	Account *desiredAccountFile `toml:"account"`
	Host    *desiredHostFile    `toml:"host"`
}

type desiredHostFile struct {
	Hostname *string `toml:"hostname"`
	Timezone *string `toml:"timezone"`
}

type desiredAccountFile struct {
	State        string                   `toml:"state"`
	Name         string                   `toml:"name"`
	UID          *uint32                  `toml:"uid"`
	Shell        *string                  `toml:"shell"`
	PrimaryGroup *desiredPrimaryGroupFile `toml:"primary_group"`
	Home         *desiredHomeFile         `toml:"home"`
}

type desiredPrimaryGroupFile struct {
	Name string  `toml:"name"`
	GID  *uint32 `toml:"gid"`
}

type desiredHomeFile struct {
	Path string `toml:"path"`
	Mode string `toml:"mode"`
}

func ReadDesiredState(path string) (DesiredState, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return DesiredState{}, err
	}
	var desired desiredStateFile
	decoder := toml.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&desired); err != nil {
		return DesiredState{}, fmt.Errorf("read %q: %w", path, err)
	}
	account, err := desired.Account.intent()
	if err != nil {
		return DesiredState{}, fmt.Errorf("read %q: %w", path, err)
	}
	machine, err := desired.Host.intent()
	if err != nil {
		return DesiredState{}, fmt.Errorf("read %q: %w", path, err)
	}
	state, err := newDesiredState(desired.Modules, account)
	if err != nil {
		return DesiredState{}, fmt.Errorf("read %q: %w", path, err)
	}
	state.machine = machine
	return state, nil
}

type machineIntent struct {
	hostname *hostnameIntent
	timezone *timezoneIntent
}

func (raw *desiredHostFile) intent() (*machineIntent, error) {
	if raw == nil {
		return nil, nil
	}
	if raw.Hostname == nil && raw.Timezone == nil {
		return nil, fmt.Errorf("host requires hostname or timezone")
	}
	intent := &machineIntent{}
	if raw.Hostname != nil {
		hostname, err := newHostnameIntent(*raw.Hostname)
		if err != nil {
			return nil, err
		}
		intent.hostname = &hostname
	}
	if raw.Timezone != nil {
		timezone, err := newTimezoneIntent(*raw.Timezone)
		if err != nil {
			return nil, err
		}
		intent.timezone = &timezone
	}
	return intent, nil
}

//sumtype:decl
type accountIntent interface {
	accountIntent()
	accountName() string
}

type existingAccountIntent struct{ name string }
type presentAccountIntent struct {
	name         string
	uid          uint32
	shell        string
	primaryGroup primaryGroupIntent
	home         homeIntent
}
type primaryGroupIntent struct {
	name string
	gid  uint32
}
type homeIntent struct {
	path string
	mode uint32
}

func (existingAccountIntent) accountIntent()            {}
func (presentAccountIntent) accountIntent()             {}
func (value existingAccountIntent) accountName() string { return value.name }
func (value presentAccountIntent) accountName() string  { return value.name }

// DesiredState is the user-owned desired state. It selects module IDs and may
// explicitly identify one target account and exact host settings; it does not
// define module behavior.
type DesiredState struct {
	Modules []string
	account accountIntent
	machine *machineIntent
}

func NewDesiredState(modules []string) (DesiredState, error) {
	return newDesiredState(modules, nil)
}

func newDesiredState(modules []string, account accountIntent) (DesiredState, error) {
	seen := make(map[string]bool, len(modules))
	cleaned := make([]string, 0, len(modules))
	for _, module := range modules {
		if module == "" {
			return DesiredState{}, fmt.Errorf("desired module ID must not be empty")
		}
		if seen[module] {
			continue
		}
		seen[module] = true
		cleaned = append(cleaned, module)
	}
	return DesiredState{Modules: cleaned, account: account}, nil
}

func (state DesiredState) Empty() bool {
	return len(state.Modules) == 0 && state.account == nil && state.machine == nil
}

var accountNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}[a-z0-9_$-]?$`)

func (raw *desiredAccountFile) intent() (accountIntent, error) {
	if raw == nil {
		return nil, nil
	}
	if err := validateAccountName(raw.Name); err != nil {
		return nil, err
	}
	switch raw.State {
	case "existing":
		if raw.UID != nil || raw.Shell != nil || raw.PrimaryGroup != nil || raw.Home != nil {
			return nil, fmt.Errorf("existing account %q accepts only state and name", raw.Name)
		}
		return existingAccountIntent{name: raw.Name}, nil
	case "present":
		return raw.presentIntent()
	default:
		return nil, fmt.Errorf("account state must be existing or present")
	}
}

func (raw desiredAccountFile) presentIntent() (accountIntent, error) {
	if raw.UID == nil || *raw.UID == 0 {
		return nil, fmt.Errorf("present account %q requires a nonzero uid", raw.Name)
	}
	if raw.Shell == nil {
		return nil, fmt.Errorf("present account %q requires shell", raw.Name)
	}
	if err := validateAbsolutePath("shell", *raw.Shell); err != nil {
		return nil, err
	}
	if raw.PrimaryGroup == nil || raw.PrimaryGroup.GID == nil || *raw.PrimaryGroup.GID == 0 {
		return nil, fmt.Errorf("present account %q requires a nonzero primary_group.gid", raw.Name)
	}
	if err := validateAccountName(raw.PrimaryGroup.Name); err != nil {
		return nil, fmt.Errorf("primary group: %w", err)
	}
	if raw.Home == nil {
		return nil, fmt.Errorf("present account %q requires home", raw.Name)
	}
	if err := validateAbsolutePath("home path", raw.Home.Path); err != nil {
		return nil, err
	}
	if len(raw.Home.Mode) != 4 || raw.Home.Mode[0] != '0' {
		return nil, fmt.Errorf("home mode must be four octal digits such as 0700")
	}
	mode, err := strconv.ParseUint(raw.Home.Mode, 8, 12)
	if err != nil || mode > 0o777 {
		return nil, fmt.Errorf("home mode %q is invalid", raw.Home.Mode)
	}
	return presentAccountIntent{
		name: raw.Name, uid: *raw.UID, shell: *raw.Shell,
		primaryGroup: primaryGroupIntent{name: raw.PrimaryGroup.Name, gid: *raw.PrimaryGroup.GID},
		home:         homeIntent{path: raw.Home.Path, mode: uint32(mode)},
	}, nil
}

func validateAccountName(value string) error {
	if !accountNamePattern.MatchString(value) {
		return fmt.Errorf("account or group name %q is invalid", value)
	}
	return nil
}

func validateAbsolutePath(subject, value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("%s %q must be an absolute canonical path", subject, value)
	}
	return nil
}
