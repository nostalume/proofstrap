package profile

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

func Encode(input Input) ([]byte, error) {
	if input.path == "" || input.syntax.Profiles == nil {
		return nil, fmt.Errorf("invalid semantic input")
	}
	return toml.Marshal(input.syntax)
}

type Syntax struct {
	Profiles map[string]rawProfile `toml:"profiles,omitempty"`
}

type Input struct {
	path   string
	syntax Syntax
}

type rawProfile struct {
	Parameters   map[string]string     `toml:"parameters,omitempty"`
	Include      []CallSyntax          `toml:"include,omitempty"`
	Packages     []string              `toml:"packages,omitempty"`
	Services     map[string]rawService `toml:"services,omitempty"`
	Homes        []rawAccount          `toml:"homes,omitempty"`
	HomeModes    []rawHomeMode         `toml:"home_modes,omitempty"`
	AccountLocks []rawAccount          `toml:"account_locks,omitempty"`
	Memberships  []rawMembership       `toml:"memberships,omitempty"`
	Hostname     *string               `toml:"hostname,omitempty"`
	Timezone     *string               `toml:"timezone,omitempty"`
}

type CallSyntax struct {
	Profile   any            `toml:"profile"`
	Arguments map[string]any `toml:"arguments,omitempty"`
}

type rawService struct {
	Target   any      `toml:"target"`
	Packages []string `toml:"packages,omitempty"`
	Enabled  *bool    `toml:"enabled,omitempty"`
	Running  *bool    `toml:"running,omitempty"`
}

type rawAccount struct {
	Account any `toml:"account"`
}

type rawHomeMode struct {
	Account any    `toml:"account"`
	Mode    string `toml:"mode"`
}

type rawMembership struct {
	Account any   `toml:"account"`
	Group   any   `toml:"group"`
	Present *bool `toml:"present"`
}

func Parse(member Member) (Input, error) {
	if len(member.Data) > MaxMemberBytes {
		return Input{}, diagnostic(member.Path, "", "", "Limit", "member exceeds 1 MiB")
	}
	if !utf8.Valid(member.Data) {
		return Input{}, diagnostic(member.Path, "", "", "Syntax", "member is not valid UTF-8")
	}
	var raw Syntax
	decoder := toml.NewDecoder(bytes.NewReader(member.Data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Input{}, decodeDiagnostic(member.Path, err)
	}
	return Embed(member.Path, raw)
}

func Embed(path string, raw Syntax) (Input, error) {
	if path == "" {
		return Input{}, &Diagnostic{Category: "InvalidValue", Detail: "member path provenance is required"}
	}
	if rawValueDepth(raw) > maxDepth {
		return Input{}, diagnostic(path, "", "", "Limit", "structural depth exceeds 16")
	}
	if len(raw.Profiles) == 0 {
		return Input{}, diagnostic(path, "", "profiles", "InvalidValue", "root profiles table must be non-empty")
	}
	return Input{path: path, syntax: raw}, nil
}

func rawValueDepth(raw Syntax) int {
	maximum := 0
	for _, profile := range raw.Profiles {
		for _, include := range profile.Include {
			maximum = max(maximum, valueDepth(include.Profile))
			for _, value := range include.Arguments {
				maximum = max(maximum, valueDepth(value))
			}
		}
		for _, service := range profile.Services {
			maximum = max(maximum, valueDepth(service.Target))
		}
		for _, account := range profile.Homes {
			maximum = max(maximum, valueDepth(account.Account))
		}
		for _, mode := range profile.HomeModes {
			maximum = max(maximum, valueDepth(mode.Account))
		}
		for _, account := range profile.AccountLocks {
			maximum = max(maximum, valueDepth(account.Account))
		}
		for _, membership := range profile.Memberships {
			maximum = max(maximum, valueDepth(membership.Account), valueDepth(membership.Group))
		}
	}
	return maximum
}

func valueDepth(value any) int {
	switch value := value.(type) {
	case map[string]any:
		maximum := 0
		for _, child := range value {
			maximum = max(maximum, valueDepth(child))
		}
		return maximum + 1
	case []any:
		maximum := 0
		for _, child := range value {
			maximum = max(maximum, valueDepth(child))
		}
		return maximum + 1
	default:
		return 0
	}
}

func decodeDiagnostic(member string, err error) error {
	result := diagnostic(member, "", "", "Syntax", err.Error())
	var decodeError *toml.DecodeError
	if errors.As(err, &decodeError) {
		result.Line, result.Column = decodeError.Position()
	}
	return result
}
