package binding

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const (
	maxMemberBytes   = 1 << 20
	maxBindingKeys   = 8192
	maxNativeOutputs = 32
)

type declarationReference struct {
	domain Domain
	handle string
	symbol string
	member string
	field  string
	key    bool
}

// Module is an admitted binding module whose semantic references are unlinked.
type Module struct {
	mappings   map[mappingKey]mapping
	references []declarationReference
}

// Admit validates and combines binding-owned syntax units atomically.
func Admit(ctx context.Context, origin string, inputs []Input) (Module, error) {
	if err := canceled(ctx); err != nil {
		return Module{}, err
	}
	if origin == "" || len(inputs) == 0 {
		return Module{}, bindingDiagnostic("InvalidValue", "", "", "origin and inputs are required", nil)
	}
	ordered := append([]Input(nil), inputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })
	mappings := make(map[mappingKey]mapping)
	nativeOwners := make(map[string]string)
	factored := make(map[mappingKey]bool)
	references := make([]declarationReference, 0)
	admit := func(input Input, domain Domain, backend, field, symbol string, values []string, clause bool) error {
		outputs, err := admitOutputs(values)
		if err != nil {
			return bindingDiagnostic("InvalidValue", input.path, field, err.Error(), err)
		}
		key := mappingKey{domain: domain, backend: backend, semantic: symbol}
		if prior, exists := mappings[key]; exists {
			if clause || factored[key] {
				return bindingDiagnostic("Duplicate", input.path, field, "binding cell is already defined", nil)
			}
			if strings.Join(prior.outputs, "\x00") != strings.Join(outputs, "\x00") {
				return bindingDiagnostic("Conflict", input.path, field, "different outputs for one binding key", nil)
			}
			prior.sources = unionStrings(prior.sources, []string{origin + ":" + input.path})
			mappings[key] = prior
			return nil
		}
		if len(mappings) >= maxBindingKeys {
			return bindingDiagnostic("Limit", input.path, field, "binding key limit exceeded", nil)
		}
		for _, output := range outputs {
			collision := fmt.Sprintf("%d\x00%s\x00%s", domain, backend, output)
			if owner, exists := nativeOwners[collision]; exists && owner != symbol {
				return bindingDiagnostic("Conflict", input.path, field, "native identity already emitted by "+owner, nil)
			}
			nativeOwners[collision] = symbol
		}
		mappings[key] = mapping{outputs: outputs, sources: []string{origin + ":" + input.path}}
		factored[key] = clause
		return nil
	}
	previous := ""
	for _, input := range ordered {
		if err := canceled(ctx); err != nil {
			return Module{}, err
		}
		if input.path == "" || input.syntax.Package == nil && input.syntax.Service == nil && input.syntax.Bind == nil || input.path == previous {
			return Module{}, bindingDiagnostic("Duplicate", input.path, "", "invalid or duplicate input", nil)
		}
		previous = input.path
		raw := input.syntax
		for _, domain := range []Domain{Package, Service} {
			tables := raw.Package
			if domain == Service {
				tables = raw.Service
			}
			for _, backend := range sortedMapKeys(tables) {
				if err := canceled(ctx); err != nil {
					return Module{}, err
				}
				if !validBackendID(backend) || len(tables[backend]) == 0 {
					return Module{}, bindingDiagnostic("InvalidValue", input.path, domain.String()+"."+backend, "invalid or empty backend table", nil)
				}
				for _, reference := range sortedMapKeys(tables[backend]) {
					if err := canceled(ctx); err != nil {
						return Module{}, err
					}
					handle, symbol, err := parseReference(reference)
					if err != nil {
						return Module{}, bindingDiagnostic("InvalidValue", input.path, reference, err.Error(), err)
					}
					references = append(references, declarationReference{domain: domain, handle: handle, symbol: symbol, member: input.path, field: reference, key: true})
					if err := admit(input, domain, backend, reference, symbol, tables[backend][reference], false); err != nil {
						return Module{}, err
					}
				}
			}
		}
		for index, clause := range raw.Bind {
			field := fmt.Sprintf("bind.%d", index)
			domain, backends := Package, clause.Package
			if (len(clause.Package) == 0) == (len(clause.Service) == 0) {
				return Module{}, bindingDiagnostic("InvalidValue", input.path, field, "exactly one non-empty package or service backend list is required", nil)
			}
			if len(clause.Service) > 0 {
				domain, backends = Service, clause.Service
			}
			if clause.From != "" && !validSymbol(clause.From) {
				return Module{}, bindingDiagnostic("MissingReference", input.path, field, "missing requirement handle "+clause.From, nil)
			}
			seen := make(map[string]struct{}, len(backends))
			for _, backend := range backends {
				if !validBackendID(backend) {
					return Module{}, bindingDiagnostic("InvalidValue", input.path, field, "invalid backend", nil)
				}
				if _, exists := seen[backend]; exists {
					return Module{}, bindingDiagnostic("Duplicate", input.path, field, "duplicate backend", nil)
				}
				seen[backend] = struct{}{}
			}
			if len(clause.Same) == 0 && len(clause.To) == 0 {
				return Module{}, bindingDiagnostic("InvalidValue", input.path, field, "same or to mappings are required", nil)
			}
			values := make(map[string][]string, len(clause.Same)+len(clause.To))
			for _, symbol := range clause.Same {
				if _, exists := values[symbol]; exists {
					return Module{}, bindingDiagnostic("Duplicate", input.path, field, "duplicate or overlapping symbol", nil)
				}
				values[symbol] = []string{symbol}
			}
			for symbol, outputs := range clause.To {
				if _, exists := values[symbol]; exists {
					return Module{}, bindingDiagnostic("Duplicate", input.path, field, "duplicate or overlapping symbol", nil)
				}
				values[symbol] = outputs
			}
			for _, symbol := range sortedMapKeys(values) {
				references = append(references, declarationReference{domain: domain, handle: clause.From, symbol: symbol, member: input.path, field: field})
				for _, backend := range backends {
					if err := canceled(ctx); err != nil {
						return Module{}, err
					}
					if err := admit(input, domain, backend, field, symbol, values[symbol], true); err != nil {
						return Module{}, err
					}
				}
			}
		}
	}
	return Module{mappings: mappings, references: references}, nil
}

func parseReference(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) == 1 && validSymbol(parts[0]) {
		return "", parts[0], nil
	}
	if len(parts) != 2 || !validSymbol(parts[0]) || !validSymbol(parts[1]) {
		return "", "", fmt.Errorf("binding key must be Symbol or handle:Symbol")
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
