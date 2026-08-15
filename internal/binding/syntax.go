package binding

import (
	"bytes"
	"errors"

	"github.com/pelletier/go-toml/v2"
)

type rawMember struct {
	Package map[string]map[string][]string `toml:"package"`
	Service map[string]map[string][]string `toml:"service"`
}

func decodeMember(member Member) (rawMember, error) {
	if len(member.Data) == 0 || len(member.Data) > maxMemberBytes {
		return rawMember{}, bindingDiagnostic("Limit", member.Path, "", "binding member must be non-empty and at most 1 MiB", nil)
	}
	var raw rawMember
	decoder := toml.NewDecoder(bytes.NewReader(member.Data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		result := bindingDiagnostic("Syntax", member.Path, "", "invalid binding TOML", err)
		var decodeError *toml.DecodeError
		if errors.As(err, &decodeError) {
			result.Line, result.Column = decodeError.Position()
		}
		return rawMember{}, result
	}
	if len(raw.Package) == 0 && len(raw.Service) == 0 {
		return rawMember{}, bindingDiagnostic("InvalidValue", member.Path, "", "binding member has no mappings", nil)
	}
	return raw, nil
}
