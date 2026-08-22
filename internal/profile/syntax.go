package profile

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

// Syntax is the profile-owned TOML surface embedded by larger documents.
// Callers must pass it to Embed; admitted state never retains this mutable form.
type Syntax struct {
	Profiles map[string]rawProfile `toml:"profiles"`
}

// Input is one validated syntax unit with immutable provenance.
type Input struct {
	path   string
	syntax Syntax
}

type rawProfile struct {
	Parameters   map[string]string     `toml:"parameters"`
	Include      []rawInclude          `toml:"include"`
	Packages     []string              `toml:"packages"`
	Services     map[string]rawService `toml:"services"`
	Homes        []rawAccount          `toml:"homes"`
	HomeModes    []rawHomeMode         `toml:"home_modes"`
	AccountLocks []rawAccount          `toml:"account_locks"`
	Memberships  []rawMembership       `toml:"memberships"`
	Hostname     *string               `toml:"hostname"`
	Timezone     *string               `toml:"timezone"`
}

type rawInclude struct {
	Profile   any            `toml:"profile"`
	Arguments map[string]any `toml:"arguments"`
}

type rawService struct {
	Target   any      `toml:"target"`
	Packages []string `toml:"packages"`
	Enabled  *bool    `toml:"enabled"`
	Running  *bool    `toml:"running"`
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

// Parse strictly decodes one standalone profile member.
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

// Embed validates profile syntax decoded as part of a larger strict document.
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
