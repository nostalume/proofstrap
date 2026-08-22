package binding

import (
	"bytes"
	"errors"

	"github.com/pelletier/go-toml/v2"
)

// Syntax is the binding-owned TOML surface embedded by larger documents.
// Callers must pass it to Embed; admitted state never retains this mutable form.
type Syntax struct {
	Package map[string]map[string][]string `toml:"package"`
	Service map[string]map[string][]string `toml:"service"`
	Bind    []Clause                       `toml:"bind"`
}

type Clause struct {
	Package []string            `toml:"package"`
	Service []string            `toml:"service"`
	From    string              `toml:"from"`
	Same    []string            `toml:"same"`
	To      map[string][]string `toml:"to"`
}

// Input is one validated syntax unit with immutable provenance.
type Input struct {
	path   string
	syntax Syntax
}

// Parse strictly decodes one standalone binding member.
func Parse(member Member) (Input, error) {
	if len(member.Data) == 0 || len(member.Data) > maxMemberBytes {
		return Input{}, bindingDiagnostic("Limit", member.Path, "", "binding member must be non-empty and at most 1 MiB", nil)
	}
	var syntax Syntax
	decoder := toml.NewDecoder(bytes.NewReader(member.Data)).DisallowUnknownFields()
	if err := decoder.Decode(&syntax); err != nil {
		result := bindingDiagnostic("Syntax", member.Path, "", "invalid binding TOML", err)
		var decodeError *toml.DecodeError
		if errors.As(err, &decodeError) {
			result.Line, result.Column = decodeError.Position()
		}
		return Input{}, result
	}
	return Embed(member.Path, syntax)
}

// Embed validates binding syntax decoded as part of a larger strict document.
func Embed(path string, syntax Syntax) (Input, error) {
	if path == "" {
		return Input{}, bindingDiagnostic("InvalidValue", "", "", "member path provenance is required", nil)
	}
	if len(syntax.Package) == 0 && len(syntax.Service) == 0 && len(syntax.Bind) == 0 {
		return Input{}, bindingDiagnostic("InvalidValue", path, "", "binding member has no mappings", nil)
	}
	return Input{path: path, syntax: syntax}, nil
}
