package profile

import (
	"fmt"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

// Call is an admitted concrete root profile call.
type Call struct {
	reference semanticReference
	arguments map[string]string
}

func AdmitCalls(raw []CallSyntax) ([]Call, error) {
	if raw != nil && len(raw) == 0 {
		return nil, fmt.Errorf("explicit empty include")
	}
	if len(raw) > maxProfiles {
		return nil, fmt.Errorf("root include limit exceeded")
	}
	seen := make(map[string]struct{}, len(raw))
	result := make([]Call, 0, len(raw))
	for index, item := range raw {
		value, ok := item.Profile.(string)
		if !ok {
			return nil, fmt.Errorf("include[%d].profile must be a profile reference", index)
		}
		reference, err := parseSemanticReference(value)
		if err != nil {
			return nil, fmt.Errorf("include[%d].profile: %w", index, err)
		}
		var arguments map[string]string
		if item.Arguments != nil && len(item.Arguments) == 0 {
			return nil, fmt.Errorf("include[%d].arguments is explicitly empty", index)
		}
		if item.Arguments != nil {
			arguments = make(map[string]string, len(item.Arguments))
		}
		var key strings.Builder
		key.WriteString(reference.canonical())
		for _, name := range sortedKeys(item.Arguments) {
			value, ok := item.Arguments[name].(string)
			if !validSymbol(name) || !ok || value == "" {
				return nil, fmt.Errorf("include[%d].arguments.%s must be a non-empty concrete string", index, name)
			}
			arguments[name] = value
			key.WriteString("|" + name + "=" + value)
		}
		if _, exists := seen[key.String()]; exists {
			continue
		}
		seen[key.String()] = struct{}{}
		result = append(result, Call{reference: reference, arguments: arguments})
	}
	return result, nil
}

func BindCall(local Library, call Call, identities map[string]model.Key, resolver ResolveProfile) (Root, error) {
	if call.reference.alias == "" {
		return BindRoot(local, call.reference.name, call.arguments, identities, resolver)
	}
	library, name, err := resolver(call.reference.canonical())
	if err != nil {
		return nil, err
	}
	return BindRoot(library, name, call.arguments, identities, resolver)
}

func CallRequirements(calls []Call) []string {
	used := make(map[string]struct{})
	for _, call := range calls {
		if call.reference.alias != "" {
			used[call.reference.alias] = struct{}{}
		}
	}
	return sortedKeys(used)
}

func Requirements(module Module) []string {
	used := make(map[string]struct{})
	for _, definition := range module.profiles {
		for _, include := range definition.includes {
			if reference, err := parseSemanticReference(include.profile); err == nil && reference.alias != "" {
				used[reference.alias] = struct{}{}
			}
		}
		for _, reference := range definition.packages {
			if reference.alias != "" {
				used[reference.alias] = struct{}{}
			}
		}
		for _, service := range definition.services {
			if service.id.alias != "" {
				used[service.id.alias] = struct{}{}
			}
			for _, reference := range service.packages {
				if reference.alias != "" {
					used[reference.alias] = struct{}{}
				}
			}
		}
	}
	return sortedKeys(used)
}

func (m Module) Present() bool { return m.profiles != nil }

func Stats(module Module) (resources, edges int) {
	for _, definition := range module.profiles {
		resources += len(definition.packages) + len(definition.services) + len(definition.homes) + len(definition.homeModes) + len(definition.accountLocks) + len(definition.memberships)
		edges += len(definition.includes)
		for _, service := range definition.services {
			edges += len(service.packages)
		}
		if definition.hostname != nil {
			resources++
		}
		if definition.timezone != nil {
			resources++
		}
	}
	return resources, edges
}
