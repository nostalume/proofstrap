package binding

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

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
	used := make(map[string]struct{})
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
					if err := proveDeclaration(domain, library, symbol); err != nil {
						category := "MissingReference"
						if strings.HasPrefix(err.Error(), "wrong domain") {
							category = "WrongDomain"
						}
						return Catalogue{}, bindingDiagnostic(category, member.Path, reference, err.Error(), err)
					}
					outputs, err := admitOutputs(tables[backend][reference])
					if err != nil {
						return Catalogue{}, bindingDiagnostic("InvalidValue", member.Path, reference, err.Error(), err)
					}
					key := mappingKey{domain: domain, backend: backend, semantic: symbol}
					source := origin + ":" + member.Path
					if prior, exists := mappings[key]; exists {
						if strings.Join(prior.outputs, "\x00") != strings.Join(outputs, "\x00") {
							return Catalogue{}, bindingDiagnostic("Conflict", member.Path, reference, "different outputs for one binding key", nil)
						}
						prior.sources = unionStrings(prior.sources, []string{source})
						mappings[key] = prior
						continue
					}
					if len(mappings) >= maxBindingKeys {
						return Catalogue{}, bindingDiagnostic("Limit", member.Path, reference, "binding key limit exceeded", nil)
					}
					for _, output := range outputs {
						collision := fmt.Sprintf("%d\x00%s\x00%s", domain, backend, output)
						if owner, exists := nativeOwners[collision]; exists && owner != symbol {
							return Catalogue{}, bindingDiagnostic("Conflict", member.Path, reference, "native identity already emitted by "+owner, nil)
						}
						nativeOwners[collision] = symbol
					}
					mappings[key] = mapping{outputs: outputs, sources: []string{source}}
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

func proveDeclaration(domain Domain, library profile.Library, symbol string) error {
	packageID, packageErr := model.NewPackageID(symbol)
	serviceID, serviceErr := model.NewServiceID(symbol)
	if packageErr != nil || serviceErr != nil {
		return fmt.Errorf("invalid semantic Symbol")
	}
	if domain == Package {
		if library.DeclaresPackage(packageID) {
			return nil
		}
		if library.DeclaresService(serviceID) {
			return fmt.Errorf("wrong domain: declaration is a service")
		}
		return fmt.Errorf("missing package declaration %s", symbol)
	}
	if library.DeclaresService(serviceID) {
		return nil
	}
	if library.DeclaresPackage(packageID) {
		return fmt.Errorf("wrong domain: declaration is a package")
	}
	return fmt.Errorf("missing service declaration %s", symbol)
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
