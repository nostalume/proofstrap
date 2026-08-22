package binding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
	"github.com/pelletier/go-toml/v2"
)

type rawMember struct {
	Package map[string]map[string][]string `toml:"package"`
	Service map[string]map[string][]string `toml:"service"`
	Bind    []bindClause                   `toml:"bind"`
}

type bindClause struct {
	Package []string            `toml:"package"`
	Service []string            `toml:"service"`
	From    string              `toml:"from"`
	Same    []string            `toml:"same"`
	To      map[string][]string `toml:"to"`
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
	if len(raw.Package) == 0 && len(raw.Service) == 0 && len(raw.Bind) == 0 {
		return rawMember{}, bindingDiagnostic("InvalidValue", member.Path, "", "binding member has no mappings", nil)
	}
	return raw, nil
}

const (
	maxMemberBytes   = 1 << 20
	maxBindingKeys   = 8192
	maxNativeOutputs = 32
)

func Decode(ctx context.Context, origin string, members []Member, required map[string]profile.Library) (Catalogue, error) {
	if err := canceled(ctx); err != nil {
		return Catalogue{}, err
	}
	if origin == "" || len(members) == 0 {
		return Catalogue{}, bindingDiagnostic("InvalidValue", "", "", "origin and members are required", nil)
	}
	ordered := append([]Member(nil), members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	mappings := make(map[mappingKey]mapping)
	nativeOwners := make(map[string]string)
	factored := make(map[mappingKey]bool)
	used := make(map[string]struct{})
	admit := func(member Member, domain Domain, backend, field, symbol string, values []string, clause bool) error {
		outputs, err := admitOutputs(values)
		if err != nil {
			return bindingDiagnostic("InvalidValue", member.Path, field, err.Error(), err)
		}
		key := mappingKey{domain: domain, backend: backend, semantic: symbol}
		if prior, exists := mappings[key]; exists {
			if clause || factored[key] {
				return bindingDiagnostic("Duplicate", member.Path, field, "binding cell is already defined", nil)
			}
			if strings.Join(prior.outputs, "\x00") != strings.Join(outputs, "\x00") {
				return bindingDiagnostic("Conflict", member.Path, field, "different outputs for one binding key", nil)
			}
			prior.sources = unionStrings(prior.sources, []string{origin + ":" + member.Path})
			mappings[key] = prior
			return nil
		}
		if len(mappings) >= maxBindingKeys {
			return bindingDiagnostic("Limit", member.Path, field, "binding key limit exceeded", nil)
		}
		for _, output := range outputs {
			collision := fmt.Sprintf("%d\x00%s\x00%s", domain, backend, output)
			if owner, exists := nativeOwners[collision]; exists && owner != symbol {
				return bindingDiagnostic("Conflict", member.Path, field, "native identity already emitted by "+owner, nil)
			}
			nativeOwners[collision] = symbol
		}
		mappings[key] = mapping{outputs: outputs, sources: []string{origin + ":" + member.Path}}
		factored[key] = clause
		return nil
	}
	previous := ""
	for _, member := range ordered {
		if err := canceled(ctx); err != nil {
			return Catalogue{}, err
		}
		if member.Path == "" || member.Path == previous {
			return Catalogue{}, bindingDiagnostic("Duplicate", member.Path, "", "invalid or duplicate member path", nil)
		}
		previous = member.Path
		raw, err := decodeMember(member)
		if err != nil {
			return Catalogue{}, err
		}
		for _, domain := range []Domain{Package, Service} {
			tables := raw.Package
			if domain == Service {
				tables = raw.Service
			}
			for _, backend := range sortedMapKeys(tables) {
				if err := canceled(ctx); err != nil {
					return Catalogue{}, err
				}
				if !validBackendID(backend) || len(tables[backend]) == 0 {
					return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, domain.String()+"."+backend, "invalid or empty backend table", nil)
				}
				for _, reference := range sortedMapKeys(tables[backend]) {
					if err := canceled(ctx); err != nil {
						return Catalogue{}, err
					}
					handle, symbol, err := parseQualified(reference)
					if err != nil {
						return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, reference, err.Error(), err)
					}
					library, exists := required[handle]
					if !exists {
						return Catalogue{}, bindingDiagnostic("MissingReference", member.Path, reference, "missing requirement handle "+handle, nil)
					}
					used[handle] = struct{}{}
					if category, err := proveDeclaration(domain, library, symbol); err != nil {
						return Catalogue{}, bindingDiagnostic(category, member.Path, reference, err.Error(), err)
					}
					if err := admit(member, domain, backend, reference, symbol, tables[backend][reference], false); err != nil {
						return Catalogue{}, err
					}
				}
			}
		}
		for index, clause := range raw.Bind {
			field := fmt.Sprintf("bind.%d", index)
			domain, backends := Package, clause.Package
			if (len(clause.Package) == 0) == (len(clause.Service) == 0) {
				return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, field, "exactly one non-empty package or service backend list is required", nil)
			}
			if len(clause.Service) > 0 {
				domain, backends = Service, clause.Service
			}
			library, exists := required[clause.From]
			if !validSymbol(clause.From) || !exists {
				return Catalogue{}, bindingDiagnostic("MissingReference", member.Path, field, "missing requirement handle "+clause.From, nil)
			}
			used[clause.From] = struct{}{}
			seen := make(map[string]struct{}, len(backends))
			for _, backend := range backends {
				if !validBackendID(backend) {
					return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, field, "invalid backend", nil)
				}
				if _, exists := seen[backend]; exists {
					return Catalogue{}, bindingDiagnostic("Duplicate", member.Path, field, "duplicate backend", nil)
				}
				seen[backend] = struct{}{}
			}
			if len(clause.Same) == 0 && len(clause.To) == 0 {
				return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, field, "same or to mappings are required", nil)
			}
			values := make(map[string][]string, len(clause.Same)+len(clause.To))
			for _, symbol := range clause.Same {
				if _, exists := values[symbol]; exists {
					return Catalogue{}, bindingDiagnostic("Duplicate", member.Path, field, "duplicate or overlapping symbol", nil)
				}
				values[symbol] = []string{symbol}
			}
			for symbol, outputs := range clause.To {
				if _, exists := values[symbol]; exists {
					return Catalogue{}, bindingDiagnostic("Duplicate", member.Path, field, "duplicate or overlapping symbol", nil)
				}
				values[symbol] = outputs
			}
			for _, symbol := range sortedMapKeys(values) {
				if category, err := proveDeclaration(domain, library, symbol); err != nil {
					return Catalogue{}, bindingDiagnostic(category, member.Path, field, err.Error(), err)
				}
				for _, backend := range backends {
					if err := canceled(ctx); err != nil {
						return Catalogue{}, err
					}
					if err := admit(member, domain, backend, field, symbol, values[symbol], true); err != nil {
						return Catalogue{}, err
					}
				}
			}
		}
	}
	for _, handle := range sortedMapKeys(required) {
		if _, exists := used[handle]; !exists {
			return Catalogue{}, bindingDiagnostic("UnusedRequirement", "", "requires."+handle, "requirement handle is unused", nil)
		}
	}
	return Catalogue{state: &catalogueState{mappings: mappings}}, nil
}

func proveDeclaration(domain Domain, library profile.Library, symbol string) (string, error) {
	packageID, packageErr := model.NewPackageID(symbol)
	serviceID, serviceErr := model.NewServiceID(symbol)
	if packageErr != nil || serviceErr != nil {
		return "MissingReference", fmt.Errorf("invalid semantic Symbol")
	}
	if domain == Package {
		if library.DeclaresPackage(packageID) {
			return "", nil
		}
		if library.DeclaresService(serviceID) {
			return "WrongDomain", fmt.Errorf("wrong domain: declaration is a service")
		}
		return "MissingReference", fmt.Errorf("missing package declaration %s", symbol)
	}
	if library.DeclaresService(serviceID) {
		return "", nil
	}
	if library.DeclaresPackage(packageID) {
		return "WrongDomain", fmt.Errorf("wrong domain: declaration is a package")
	}
	return "MissingReference", fmt.Errorf("missing service declaration %s", symbol)
}

func parseQualified(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || !validSymbol(parts[0]) || !validSymbol(parts[1]) {
		return "", "", fmt.Errorf("binding key must be handle:Symbol")
	}
	return parts[0], parts[1], nil
}

func admitOutputs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maxNativeOutputs {
		return nil, fmt.Errorf("native output list must contain 1..32 values")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validNativeName(value) {
			return nil, fmt.Errorf("invalid native identity")
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate native identity")
		}
		seen[value] = struct{}{}
	}
	return sortedStrings(seen), nil
}

func validSymbol(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func unionStrings(left, right []string) []string {
	values := make(map[string]struct{}, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		values[value] = struct{}{}
	}
	return sortedStrings(values)
}

func bindingDiagnostic(category, member, field, detail string, cause error) *Diagnostic {
	return &Diagnostic{Category: category, Member: member, Field: field, Detail: detail, cause: cause}
}
