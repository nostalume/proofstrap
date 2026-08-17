package profile

import (
	"fmt"
	"strings"
)

func linkLibrary(origin string, local map[string]profileDefinition, required map[string]Library) (Library, error) {
	result := Library{
		profiles: make(map[string]profileDefinition), localProfiles: make(map[string]string, len(local)),
		packageSymbols: make(map[string]struct{}), serviceSymbols: make(map[string]struct{}),
	}
	for _, id := range sortedKeys(local) {
		key := profileKey(origin, id)
		result.localProfiles[id] = key
		definition := local[id]
		result.profiles[key] = definition
		for _, reference := range definition.packages {
			if reference.alias == "" {
				result.packageSymbols[reference.name] = struct{}{}
			}
		}
		for _, service := range definition.services {
			if service.id.alias == "" {
				result.serviceSymbols[service.id.name] = struct{}{}
			}
			for _, reference := range service.packages {
				if reference.alias == "" {
					result.packageSymbols[reference.name] = struct{}{}
				}
			}
		}
	}
	used := make(map[string]struct{})
	for _, key := range sortedKeys(result.profiles) {
		definition := result.profiles[key]
		for index := range definition.includes {
			include := &definition.includes[index]
			if include.profileParameter != "" {
				continue
			}
			reference, _ := parseSemanticReference(include.profile)
			target, err := resolveProfileReference(reference, result, required, used)
			if err != nil {
				return Library{}, diagnostic(definition.member, definition.id, fmt.Sprintf("include[%d].profile", index), categoryOf(err), err.Error())
			}
			include.profile = target
		}
		for index := range definition.packages {
			if err := resolveResourceReference(&definition.packages[index], required, used, true); err != nil {
				return Library{}, diagnostic(definition.member, definition.id, "packages", categoryOf(err), err.Error())
			}
		}
		for index := range definition.services {
			service := &definition.services[index]
			if err := resolveResourceReference(&service.id, required, used, false); err != nil {
				return Library{}, diagnostic(definition.member, definition.id, "services", categoryOf(err), err.Error())
			}
			for packageIndex := range service.packages {
				if err := resolveResourceReference(&service.packages[packageIndex], required, used, true); err != nil {
					return Library{}, diagnostic(definition.member, definition.id, "services.packages", categoryOf(err), err.Error())
				}
			}
		}
		result.profiles[key] = definition
	}
	for _, handle := range sortedKeys(required) {
		if _, exists := used[handle]; !exists {
			return Library{}, &Diagnostic{Category: "UnusedRequirement", Field: "requires." + handle, Detail: "requirement handle is unused"}
		}
	}
	for _, library := range required {
		for key, definition := range library.profiles {
			result.profiles[key] = definition
		}
	}
	if err := validateLibrary(result.profiles); err != nil {
		return Library{}, err
	}
	return result, nil
}

type referenceError struct {
	category string
	detail   string
}

func (e *referenceError) Error() string { return e.detail }

func categoryOf(err error) string {
	if value, ok := err.(*referenceError); ok {
		return value.category
	}
	return "MissingReference"
}

func resolveProfileReference(reference semanticReference, local Library, required map[string]Library, used map[string]struct{}) (string, error) {
	if reference.alias == "" {
		key, exists := local.localProfiles[reference.name]
		if !exists {
			return "", &referenceError{"MissingReference", "missing profile " + reference.name}
		}
		return key, nil
	}
	library, exists := required[reference.alias]
	if !exists {
		return "", &referenceError{"MissingReference", "missing requirement handle " + reference.alias}
	}
	used[reference.alias] = struct{}{}
	if key, exists := library.localProfiles[reference.name]; exists {
		return key, nil
	}
	if _, exists := library.packageSymbols[reference.name]; exists {
		return "", &referenceError{"WrongDomain", "reference exists as package, not profile"}
	}
	if _, exists := library.serviceSymbols[reference.name]; exists {
		return "", &referenceError{"WrongDomain", "reference exists as service, not profile"}
	}
	return "", &referenceError{"MissingReference", "missing profile " + reference.name}
}

func resolveResourceReference(reference *semanticReference, required map[string]Library, used map[string]struct{}, wantPackage bool) error {
	if reference.alias == "" {
		return nil
	}
	library, exists := required[reference.alias]
	if !exists {
		return &referenceError{"MissingReference", "missing requirement handle " + reference.alias}
	}
	used[reference.alias] = struct{}{}
	wanted, other := library.packageSymbols, library.serviceSymbols
	wantedName, otherName := "package", "service"
	if !wantPackage {
		wanted, other = library.serviceSymbols, library.packageSymbols
		wantedName, otherName = "service", "package"
	}
	if _, exists := wanted[reference.name]; !exists {
		if _, exists := other[reference.name]; exists {
			return &referenceError{"WrongDomain", "reference exists as " + otherName + ", not " + wantedName}
		}
		return &referenceError{"MissingReference", "missing " + wantedName + " " + reference.name}
	}
	reference.alias = ""
	return nil
}

func validateLibrary(profiles map[string]profileDefinition) error {
	for _, id := range sortedKeys(profiles) {
		definition := profiles[id]
		seen := make(map[string]struct{}, len(definition.includes))
		for index := range definition.includes {
			include := &definition.includes[index]
			if include.profileParameter != "" {
				continue
			}
			target, exists := profiles[include.profile]
			if !exists {
				return diagnostic(definition.member, definition.id, fmt.Sprintf("include[%d].profile", index), "MissingReference", "missing profile "+include.profile)
			}
			arguments, err := admitArguments(include.sourceArguments, definition.parameters, target.parameters)
			if err != nil {
				return diagnostic(definition.member, definition.id, fmt.Sprintf("include[%d].arguments", index), "TypeMismatch", err.Error())
			}
			include.arguments = arguments
			key := include.profile + "|" + canonicalArguments(arguments)
			if _, exists := seen[key]; exists {
				return diagnostic(definition.member, definition.id, "include", "Duplicate", "duplicate include instance")
			}
			seen[key] = struct{}{}
		}
	}
	return validateIncludeCycles(profiles)
}

func admitArguments(raw map[string]any, caller, target map[string]parameterKind) (map[string]reference, error) {
	if len(target) == 0 {
		if raw != nil {
			return nil, fmt.Errorf("arguments forbidden for parameterless target")
		}
		return nil, nil
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("arguments required for parameterized target")
	}
	if len(raw) != len(target) || len(raw) > maxParameters {
		return nil, fmt.Errorf("argument keys must exactly match target parameters")
	}
	result := make(map[string]reference, len(raw))
	for _, name := range sortedKeys(target) {
		value, exists := raw[name]
		if !exists {
			return nil, fmt.Errorf("missing argument %q", name)
		}
		reference, err := admitReference(value, target[name]&^parameterUsed, caller)
		if err != nil {
			return nil, err
		}
		result[name] = reference
	}
	return result, nil
}

func validateIncludeCycles(profiles map[string]profileDefinition) error {
	state := make(map[string]uint8, len(profiles))
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return diagnostic(profiles[id].member, profiles[id].id, "include", "Cycle", "profile include cycle")
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, include := range profiles[id].includes {
			if include.profileParameter != "" {
				continue
			}
			if err := visit(include.profile); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, id := range sortedKeys(profiles) {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func canonicalArguments(arguments map[string]reference) string {
	return canonicalBindings("", arguments)
}

func canonicalBindings(prefix string, bindings map[string]reference) string {
	var builder strings.Builder
	builder.WriteString(prefix)
	for _, name := range sortedKeys(bindings) {
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(bindings[name].canonical())
		builder.WriteByte(';')
	}
	return builder.String()
}
