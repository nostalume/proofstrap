package binding

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func EncodePromoted(input Input, semanticAlias string) ([]byte, error) {
	if input.path == "" || !validSymbol(semanticAlias) {
		return nil, fmt.Errorf("invalid binding promotion")
	}
	syntax := Syntax{Package: promoteTables(input.syntax.Package, semanticAlias), Service: promoteTables(input.syntax.Service, semanticAlias)}
	if input.syntax.Bind != nil {
		syntax.Bind = make([]Clause, len(input.syntax.Bind))
		for index, clause := range input.syntax.Bind {
			syntax.Bind[index] = Clause{
				Package: append([]string(nil), clause.Package...), Service: append([]string(nil), clause.Service...),
				From: clause.From, Same: append([]string(nil), clause.Same...), To: cloneOutputs(clause.To),
			}
			if syntax.Bind[index].From == "" {
				syntax.Bind[index].From = semanticAlias
			}
		}
	}
	return toml.Marshal(syntax)
}

func promoteTables(input map[string]map[string][]string, alias string) map[string]map[string][]string {
	if input == nil {
		return nil
	}
	result := make(map[string]map[string][]string, len(input))
	for backend, cells := range input {
		result[backend] = make(map[string][]string, len(cells))
		for symbol, outputs := range cells {
			if !strings.Contains(symbol, ":") {
				symbol = alias + ":" + symbol
			}
			result[backend][symbol] = append([]string(nil), outputs...)
		}
	}
	return result
}

func cloneOutputs(input map[string][]string) map[string][]string {
	if input == nil {
		return nil
	}
	result := make(map[string][]string, len(input))
	for symbol, outputs := range input {
		result[symbol] = append([]string(nil), outputs...)
	}
	return result
}

type Syntax struct {
	Package map[string]map[string][]string `toml:"package,omitempty"`
	Service map[string]map[string][]string `toml:"service,omitempty"`
	Bind    []Clause                       `toml:"bind,omitempty"`
}

type Clause struct {
	Package []string            `toml:"package,omitempty"`
	Service []string            `toml:"service,omitempty"`
	From    string              `toml:"from,omitempty"`
	Same    []string            `toml:"same,omitempty"`
	To      map[string][]string `toml:"to,omitempty"`
}

type Input struct {
	path   string
	syntax Syntax
}

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

func Embed(path string, syntax Syntax) (Input, error) {
	if path == "" {
		return Input{}, bindingDiagnostic("InvalidValue", "", "", "member path provenance is required", nil)
	}
	if len(syntax.Package) == 0 && len(syntax.Service) == 0 && len(syntax.Bind) == 0 {
		return Input{}, bindingDiagnostic("InvalidValue", path, "", "binding member has no mappings", nil)
	}
	return Input{path: path, syntax: syntax}, nil
}
