package proofstrap

import (
	"fmt"
	"sort"
	"strings"
)

type PackageKey string
type ServiceKey string
type ServiceScope string

const (
	SystemService ServiceScope = "system"
	UserService   ServiceScope = "user"
)

type serviceTarget uint8

const (
	serviceEnabled serviceTarget = iota + 1
	serviceActive
)

//sumtype:decl
type requirement interface{ requirement() }

type packageRequirement struct{ packageKey PackageKey }
type serviceRequirement struct {
	packageKey PackageKey
	serviceKey ServiceKey
	scope      ServiceScope
}

func (packageRequirement) requirement() {}
func (serviceRequirement) requirement() {}

type serviceNeed struct {
	key    ServiceKey
	scope  ServiceScope
	target serviceTarget
}

type moduleID string

type moduleDefinition struct {
	requires     []moduleID
	excludes     []moduleID
	requirements []requirement
}

type catalogue struct {
	modules          map[moduleID]moduleDefinition
	packages         map[PackageKey]struct{}
	services         map[ServiceKey]struct{}
	serviceConflicts []serviceConflict
}

type serviceConflict struct {
	wanted ServiceKey
	other  ServiceKey
	scope  ServiceScope
}

type conflictPair struct{ first, second moduleID }

type compiledCatalogue struct {
	modules          map[moduleID]moduleDefinition
	packages         map[PackageKey]struct{}
	services         map[ServiceKey]struct{}
	exclusions       []conflictPair
	serviceConflicts []serviceConflict
}

type selection struct {
	modules      []moduleID
	requirements []requirement
	conflicts    []serviceConflict
}

func compileCatalogue(raw catalogue) (compiledCatalogue, error) {
	compiled := compiledCatalogue{
		modules:          make(map[moduleID]moduleDefinition, len(raw.modules)),
		packages:         copySet(raw.packages),
		services:         copySet(raw.services),
		serviceConflicts: append([]serviceConflict(nil), raw.serviceConflicts...),
	}

	for key := range raw.packages {
		if key == "" {
			return compiledCatalogue{}, fmt.Errorf("empty package key")
		}
	}

	for key := range raw.services {
		if key == "" {
			return compiledCatalogue{}, fmt.Errorf("empty service key")
		}
	}
	seenServiceConflicts := make(map[serviceConflict]bool)
	for _, conflict := range raw.serviceConflicts {
		if conflict.wanted == conflict.other {
			return compiledCatalogue{}, fmt.Errorf("service conflict has identical endpoints %q", conflict.wanted)
		}
		if _, ok := raw.services[conflict.wanted]; !ok {
			return compiledCatalogue{}, fmt.Errorf("service conflict references unknown service %q", conflict.wanted)
		}
		if _, ok := raw.services[conflict.other]; !ok {
			return compiledCatalogue{}, fmt.Errorf("service conflict references unknown service %q", conflict.other)
		}
		if conflict.scope != SystemService && conflict.scope != UserService {
			return compiledCatalogue{}, fmt.Errorf("service conflict %q -> %q has invalid scope", conflict.wanted, conflict.other)
		}
		if seenServiceConflicts[conflict] {
			return compiledCatalogue{}, fmt.Errorf("duplicate service conflict %q -> %q", conflict.wanted, conflict.other)
		}
		seenServiceConflicts[conflict] = true
	}
	sort.Slice(compiled.serviceConflicts, func(i, j int) bool {
		left, right := compiled.serviceConflicts[i], compiled.serviceConflicts[j]
		if left.wanted != right.wanted {
			return left.wanted < right.wanted
		}
		if left.other != right.other {
			return left.other < right.other
		}
		return left.scope < right.scope
	})
	ids := sortedModuleIDs(raw.modules)
	pairs := make(map[conflictPair]struct{})
	for _, id := range ids {
		if id == "" {
			return compiledCatalogue{}, fmt.Errorf("empty module ID")
		}
		definition := cloneModule(raw.modules[id])
		compiled.modules[id] = definition
		seenDependencies := make(map[moduleID]bool)
		for _, dependency := range definition.requires {
			if seenDependencies[dependency] {
				return compiledCatalogue{}, fmt.Errorf("module %q requires module %q more than once", id, dependency)
			}
			seenDependencies[dependency] = true
			if _, ok := raw.modules[dependency]; !ok {
				return compiledCatalogue{}, fmt.Errorf("module %q requires unknown module %q", id, dependency)
			}
		}
		seenExclusions := make(map[moduleID]bool)
		for _, excluded := range definition.excludes {
			if seenExclusions[excluded] {
				return compiledCatalogue{}, fmt.Errorf("module %q excludes module %q more than once", id, excluded)
			}
			seenExclusions[excluded] = true
			if excluded == id {
				return compiledCatalogue{}, fmt.Errorf("module %q excludes itself", id)
			}
			if _, ok := raw.modules[excluded]; !ok {
				return compiledCatalogue{}, fmt.Errorf("module %q excludes unknown module %q", id, excluded)
			}
			pair := conflictPair{first: id, second: excluded}
			if pair.second < pair.first {
				pair.first, pair.second = pair.second, pair.first
			}
			pairs[pair] = struct{}{}
		}

		seenRequirements := make(map[requirement]bool)
		for _, required := range definition.requirements {
			if seenRequirements[required] {
				return compiledCatalogue{}, fmt.Errorf("module %q declares requirement %v more than once", id, required)
			}
			seenRequirements[required] = true
			if err := compiled.validateRequirement(required); err != nil {
				return compiledCatalogue{}, fmt.Errorf("module %q has invalid requirement: %w", id, err)
			}
		}
	}
	if err := compiled.validateCycles(ids); err != nil {
		return compiledCatalogue{}, err
	}
	for pair := range pairs {
		compiled.exclusions = append(compiled.exclusions, pair)
	}
	sort.Slice(compiled.exclusions, func(i, j int) bool {
		if compiled.exclusions[i].first == compiled.exclusions[j].first {
			return compiled.exclusions[i].second < compiled.exclusions[j].second
		}
		return compiled.exclusions[i].first < compiled.exclusions[j].first
	})
	return compiled, nil
}

func mustCompileCatalogue(raw catalogue) compiledCatalogue {
	compiled, err := compileCatalogue(raw)
	if err != nil {
		panic(err)
	}
	return compiled
}

func copySet[K comparable](source map[K]struct{}) map[K]struct{} {
	result := make(map[K]struct{}, len(source))
	for key := range source {
		result[key] = struct{}{}
	}
	return result
}

func cloneModule(source moduleDefinition) moduleDefinition {
	return moduleDefinition{
		requires:     append([]moduleID(nil), source.requires...),
		excludes:     append([]moduleID(nil), source.excludes...),
		requirements: append([]requirement(nil), source.requirements...),
	}
}

func sortedModuleIDs(modules map[moduleID]moduleDefinition) []moduleID {
	ids := make([]moduleID, 0, len(modules))
	for id := range modules {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func Modules() []string {
	ids := sortedModuleIDs(production.modules)
	modules := make([]string, len(ids))
	for index, id := range ids {
		modules[index] = string(id)
	}
	return modules
}

func (compiled compiledCatalogue) validateRequirement(required requirement) error {
	if required == nil {
		return fmt.Errorf("nil requirement")
	}
	switch value := required.(type) {
	case packageRequirement:
		if _, ok := compiled.packages[value.packageKey]; !ok {
			return fmt.Errorf("unknown package key %q", value.packageKey)
		}
	case serviceRequirement:
		if _, ok := compiled.packages[value.packageKey]; !ok {
			return fmt.Errorf("unknown package key %q", value.packageKey)
		}
		if _, ok := compiled.services[value.serviceKey]; !ok {
			return fmt.Errorf("unknown service key %q", value.serviceKey)
		}
		if value.scope != SystemService && value.scope != UserService {
			return fmt.Errorf("invalid service scope %q", value.scope)
		}
	default:
		return fmt.Errorf("unknown requirement %T", required)
	}
	return nil
}

type visitState uint8

const (
	visitUnseen visitState = iota
	visitActive
	visitDone
)

func (compiled compiledCatalogue) validateCycles(ids []moduleID) error {
	states := make(map[moduleID]visitState, len(ids))
	stack := make([]moduleID, 0, len(ids))
	var visit func(moduleID) error
	visit = func(id moduleID) error {
		switch states[id] {
		case visitActive:
			start := 0
			for i, value := range stack {
				if value == id {
					start = i
					break
				}
			}
			cycle := append(append([]moduleID(nil), stack[start:]...), id)
			values := make([]string, len(cycle))
			for i, value := range cycle {
				values[i] = string(value)
			}
			return fmt.Errorf("dependency cycle: %s", strings.Join(values, " -> "))
		case visitDone:
			return nil
		}
		states[id] = visitActive
		stack = append(stack, id)
		for _, dependency := range compiled.modules[id].requires {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		states[id] = visitDone
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (compiled compiledCatalogue) selectFor(state DesiredState) (selection, []Blocker) {
	selected := selection{}
	seen := make(map[moduleID]bool)
	var blockers []Blocker
	if len(state.Modules) == 0 && state.account == nil {
		return selected, []Blocker{{Subject: "desired-state", Detail: "at least one module is required"}}
	}
	var visit func(moduleID)
	visit = func(id moduleID) {
		if seen[id] {
			return
		}
		seen[id] = true
		definition, ok := compiled.modules[id]
		if !ok {
			blockers = append(blockers, Blocker{Subject: "module:" + string(id), Detail: "unknown module"})
			return
		}
		for _, dependency := range definition.requires {
			visit(dependency)
		}
		selected.modules = append(selected.modules, id)
		selected.requirements = append(selected.requirements, definition.requirements...)
	}
	for _, rawID := range state.Modules {
		visit(moduleID(rawID))
	}
	for _, pair := range compiled.exclusions {
		if seen[pair.first] && seen[pair.second] {
			blockers = append(blockers, Blocker{Subject: "modules:exclusion", Detail: fmt.Sprintf("modules %q and %q cannot both be selected", pair.first, pair.second)})
		}
	}
	type scopedService struct {
		key   ServiceKey
		scope ServiceScope
	}
	selectedServices := make(map[scopedService]bool)
	for _, required := range selected.requirements {
		if service, ok := required.(serviceRequirement); ok {
			selectedServices[scopedService{key: service.serviceKey, scope: service.scope}] = true
		}
	}
	for _, conflict := range compiled.serviceConflicts {
		if !selectedServices[scopedService{key: conflict.wanted, scope: conflict.scope}] {
			continue
		}
		if selectedServices[scopedService{key: conflict.other, scope: conflict.scope}] {
			blockers = append(blockers, Blocker{Subject: "services:conflict", Detail: fmt.Sprintf("services %q and %q cannot both be desired", conflict.wanted, conflict.other)})
			continue
		}
		selected.conflicts = append(selected.conflicts, conflict)
	}
	return selected, blockers
}

func (selected selection) moduleStrings() []string {
	result := make([]string, len(selected.modules))
	for i, id := range selected.modules {
		result[i] = string(id)
	}
	return result
}

func (selected selection) packageKeys() []PackageKey {
	seen := make(map[PackageKey]bool)
	var keys []PackageKey
	for _, required := range selected.requirements {
		var key PackageKey
		switch value := required.(type) {
		case packageRequirement:
			key = value.packageKey
		case serviceRequirement:
			key = value.packageKey
		}
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys
}

func (selected selection) serviceNeeds() []serviceNeed {
	seen := make(map[serviceNeed]bool)
	var needs []serviceNeed
	for _, required := range selected.requirements {
		value, ok := required.(serviceRequirement)
		if !ok {
			continue
		}
		for _, target := range []serviceTarget{serviceEnabled, serviceActive} {
			need := serviceNeed{key: value.serviceKey, scope: value.scope, target: target}
			if !seen[need] {
				seen[need] = true
				needs = append(needs, need)
			}
		}
	}
	return needs
}

func (selected selection) requiresUserAccount() bool {
	for _, required := range selected.requirements {
		if service, ok := required.(serviceRequirement); ok && service.scope == UserService {
			return true
		}
	}
	return false
}
