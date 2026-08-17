package profile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

const (
	maxProfiles   = 256
	maxParameters = 16
	maxIncludes   = 64
	maxResources  = 1024
	maxDepth      = 16
)

func Decode(origin string, members []Member, required map[string]Library) (Library, error) {
	if origin == "" {
		return Library{}, &Diagnostic{Category: "InvalidValue", Detail: "source origin is required"}
	}
	if len(members) == 0 {
		return Library{}, &Diagnostic{Category: "InvalidValue", Detail: "at least one semantic member is required"}
	}
	ordered := append([]Member(nil), members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	profiles := make(map[string]profileDefinition)
	previousPath := ""
	for _, member := range ordered {
		if member.Path == "" {
			return Library{}, &Diagnostic{Category: "InvalidValue", Detail: "member path provenance is required"}
		}
		if member.Path == previousPath {
			return Library{}, diagnostic(member.Path, "", "", "Duplicate", "duplicate member path")
		}
		previousPath = member.Path
		raw, err := decodeMember(member)
		if err != nil {
			return Library{}, err
		}
		if len(profiles)+len(raw.Profiles) > maxProfiles {
			return Library{}, diagnostic(member.Path, "", "profiles", "Limit", "profile limit exceeded")
		}
		for _, id := range sortedKeys(raw.Profiles) {
			if _, exists := profiles[id]; exists {
				return Library{}, diagnostic(member.Path, id, "profiles."+id, "Duplicate", "duplicate profile ID")
			}
			definition, err := admitProfile(member.Path, id, raw.Profiles[id])
			if err != nil {
				return Library{}, err
			}
			profiles[id] = definition
		}
	}
	library, err := linkLibrary(origin, profiles, required)
	if err != nil {
		return Library{}, err
	}
	return library, nil
}

func profileKey(origin, id string) string { return origin + "#" + id }

func admitProfile(member, id string, raw rawProfile) (profileDefinition, error) {
	if !validSymbol(id) {
		return profileDefinition{}, diagnostic(member, id, "profiles."+id, "InvalidValue", "invalid profile ID")
	}
	definition := profileDefinition{id: id, member: member}
	if raw.Parameters != nil {
		if len(raw.Parameters) == 0 {
			return profileDefinition{}, diagnostic(member, id, "parameters", "InvalidValue", "explicit empty parameters")
		}
		if len(raw.Parameters) > maxParameters {
			return profileDefinition{}, diagnostic(member, id, "parameters", "Limit", "parameter limit exceeded")
		}
		definition.parameters = make(map[string]parameterKind, len(raw.Parameters)+1)
		definition.parameters[""] = parameterUsed
		for _, name := range sortedKeys(raw.Parameters) {
			if !validSymbol(name) {
				return profileDefinition{}, diagnostic(member, id, "parameters."+name, "InvalidValue", "invalid parameter name")
			}
			kind, ok := parseParameterKind(raw.Parameters[name])
			if !ok {
				return profileDefinition{}, diagnostic(member, id, "parameters."+name, "InvalidValue", "invalid parameter kind")
			}
			definition.parameters[name] = kind
		}
	}
	if raw.Include != nil {
		if len(raw.Include) == 0 {
			return profileDefinition{}, diagnostic(member, id, "include", "InvalidValue", "explicit empty include")
		}
		if len(raw.Include) > maxIncludes {
			return profileDefinition{}, diagnostic(member, id, "include", "Limit", "include limit exceeded")
		}
		definition.includes = make([]includeDefinition, len(raw.Include))
		for index, include := range raw.Include {
			value, err := admitReference(include.Profile, profileReference, definition.parameters)
			if target, ok := include.Profile.(string); ok {
				_, err = parseSemanticReference(target)
				value = reference{profile: target, kind: profileReference}
			}
			if err != nil {
				return profileDefinition{}, diagnostic(member, id, fmt.Sprintf("include[%d].profile", index), "InvalidValue", err.Error())
			}
			definition.includes[index] = includeDefinition{profile: value.profile,
				profileParameter: value.parameter, sourceArguments: include.Arguments}
			for _, argument := range include.Arguments {
				if object, ok := argument.(map[string]any); ok && len(object) == 1 {
					if name, ok := object["parameter"].(string); ok && definition.parameters[name] != 0 {
						definition.parameters[name] |= parameterUsed
					}
				}
			}
		}
	}
	resourceCount := len(raw.Packages) + len(raw.Services) + len(raw.Homes) +
		len(raw.HomeModes) + len(raw.AccountLocks) + len(raw.Memberships)
	if raw.Hostname != nil {
		resourceCount++
	}
	if raw.Timezone != nil {
		resourceCount++
	}
	if resourceCount > maxResources {
		return profileDefinition{}, diagnostic(member, id, "", "Limit", "resource limit exceeded")
	}
	var err error
	if definition.packages, err = admitPackages(member, id, "packages", raw.Packages); err != nil {
		return profileDefinition{}, err
	}
	if definition.services, err = admitServices(member, id, raw.Services, definition.parameters); err != nil {
		return profileDefinition{}, err
	}
	if definition.homes, err = admitAccountSet(member, id, "homes", raw.Homes, definition.parameters); err != nil {
		return profileDefinition{}, err
	}
	if definition.accountLocks, err = admitAccountSet(member, id, "account_locks", raw.AccountLocks, definition.parameters); err != nil {
		return profileDefinition{}, err
	}
	if definition.homeModes, err = admitHomeModes(member, id, raw.HomeModes, definition.parameters); err != nil {
		return profileDefinition{}, err
	}
	if definition.memberships, err = admitMemberships(member, id, raw.Memberships, definition.parameters); err != nil {
		return profileDefinition{}, err
	}
	if raw.Hostname != nil {
		definition.hostname, err = model.NewHostname(*raw.Hostname)
		if err != nil {
			return profileDefinition{}, diagnostic(member, id, "hostname", "InvalidValue", err.Error())
		}
	}
	if raw.Timezone != nil {
		definition.timezone, err = model.NewTimezone(*raw.Timezone)
		if err != nil {
			return profileDefinition{}, diagnostic(member, id, "timezone", "InvalidValue", err.Error())
		}
	}
	resources := len(definition.packages) + len(definition.services) + len(definition.homes) +
		len(definition.homeModes) + len(definition.accountLocks) + len(definition.memberships)
	if definition.hostname != nil {
		resources++
	}
	if definition.timezone != nil {
		resources++
	}
	if resources > maxResources {
		return profileDefinition{}, diagnostic(member, id, "", "Limit", "resource limit exceeded")
	}
	if resources == 0 && len(definition.includes) == 0 {
		return profileDefinition{}, diagnostic(member, id, "", "InvalidValue", "profile must contribute an include or resource")
	}
	delete(definition.parameters, "")
	for name, kind := range definition.parameters {
		if kind&parameterUsed == 0 {
			return profileDefinition{}, diagnostic(member, id, "parameters."+name, "InvalidValue", "parameter is never consumed or forwarded")
		}
		definition.parameters[name] = kind &^ parameterUsed
	}
	return definition, nil
}

func admitPackages(member, profile, field string, values []string) ([]semanticReference, error) {
	if values != nil && len(values) == 0 {
		return nil, diagnostic(member, profile, field, "InvalidValue", "explicit empty package list")
	}
	if len(values) > maxResources {
		return nil, diagnostic(member, profile, field, "Limit", "resource limit exceeded")
	}
	result := make([]semanticReference, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		reference, err := parseSemanticReference(value)
		if err != nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("%s[%d]", field, index), "InvalidValue", err.Error())
		}
		if reference.alias == "" {
			if _, err := model.NewPackageID(reference.name); err != nil {
				return nil, diagnostic(member, profile, fmt.Sprintf("%s[%d]", field, index), "InvalidValue", err.Error())
			}
		}
		key := reference.canonical()
		if _, exists := seen[key]; exists {
			return nil, diagnostic(member, profile, field, "Duplicate", "duplicate package reference "+key)
		}
		seen[key] = struct{}{}
		result = append(result, reference)
	}
	return result, nil
}

func admitServices(member, profile string, values map[string]rawService, parameters map[string]parameterKind) ([]serviceDefinition, error) {
	if values != nil && len(values) == 0 {
		return nil, diagnostic(member, profile, "services", "InvalidValue", "explicit empty services table")
	}
	if len(values) > maxResources {
		return nil, diagnostic(member, profile, "services", "Limit", "resource limit exceeded")
	}
	result := make([]serviceDefinition, 0, len(values))
	for _, name := range sortedKeys(values) {
		raw := values[name]
		reference, err := parseSemanticReference(name)
		if err != nil {
			return nil, diagnostic(member, profile, "services."+name, "InvalidValue", err.Error())
		}
		if reference.alias == "" {
			if _, err := model.NewServiceID(reference.name); err != nil {
				return nil, diagnostic(member, profile, "services."+name, "InvalidValue", err.Error())
			}
		}
		service := serviceDefinition{id: reference}
		switch target := raw.Target.(type) {
		case string:
			if target != "system" {
				return nil, diagnostic(member, profile, "services."+name+".target", "InvalidValue", "target must be system or exact user reference")
			}
		case map[string]any:
			if len(target) != 1 {
				return nil, diagnostic(member, profile, "services."+name+".target", "InvalidValue", "user target must have one field")
			}
			value, ok := target["user"]
			if !ok {
				return nil, diagnostic(member, profile, "services."+name+".target", "InvalidValue", "target field must be user")
			}
			user, err := admitReference(value, accountReference, parameters)
			if err != nil || user.parameter == "" {
				return nil, diagnostic(member, profile, "services."+name+".target.user", "InvalidValue", "user target requires an account_ref parameter")
			}
			service.user = &user
		default:
			return nil, diagnostic(member, profile, "services."+name+".target", "InvalidValue", "service target is required")
		}
		if raw.Enabled == nil && raw.Running == nil {
			return nil, diagnostic(member, profile, "services."+name, "InvalidValue", "service must own enabled or running")
		}
		service.enable = model.UnmanagedEnableIntent()
		if raw.Enabled != nil {
			if *raw.Enabled {
				service.enable = model.EnabledIntent()
			} else {
				service.enable = model.DisabledIntent()
			}
		}
		service.run = model.UnmanagedRunIntent()
		if raw.Running != nil {
			if *raw.Running {
				service.run = model.RunningIntent()
			} else {
				service.run = model.StoppedIntent()
			}
		}
		service.packages, err = admitPackages(member, profile, "services."+name+".packages", raw.Packages)
		if err != nil {
			return nil, err
		}
		result = append(result, service)
	}
	return result, nil
}

func admitAccountSet(member, profile, field string, values []rawAccount, parameters map[string]parameterKind) ([]reference, error) {
	if values != nil && len(values) == 0 {
		return nil, diagnostic(member, profile, field, "InvalidValue", "explicit empty collection")
	}
	if len(values) > maxResources {
		return nil, diagnostic(member, profile, field, "Limit", "resource limit exceeded")
	}
	result := make([]reference, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		reference, err := admitReference(raw.Account, accountReference, parameters)
		if err != nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("%s[%d].account", field, index), "InvalidValue", err.Error())
		}
		if _, exists := seen[reference.canonical()]; exists {
			return nil, diagnostic(member, profile, field, "Duplicate", "duplicate account reference")
		}
		seen[reference.canonical()] = struct{}{}
		result = append(result, reference)
	}
	return result, nil
}

func admitHomeModes(member, profile string, values []rawHomeMode, parameters map[string]parameterKind) ([]homeModeDefinition, error) {
	if values != nil && len(values) == 0 {
		return nil, diagnostic(member, profile, "home_modes", "InvalidValue", "explicit empty collection")
	}
	if len(values) > maxResources {
		return nil, diagnostic(member, profile, "home_modes", "Limit", "resource limit exceeded")
	}
	result := make([]homeModeDefinition, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		account, err := admitReference(raw.Account, accountReference, parameters)
		if err != nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("home_modes[%d].account", index), "InvalidValue", err.Error())
		}
		if len(raw.Mode) != 4 || raw.Mode[0] != '0' {
			return nil, diagnostic(member, profile, fmt.Sprintf("home_modes[%d].mode", index), "InvalidValue", "mode must be four octal characters")
		}
		parsed, err := strconv.ParseUint(raw.Mode, 8, 16)
		if err != nil || parsed > 0o777 {
			return nil, diagnostic(member, profile, fmt.Sprintf("home_modes[%d].mode", index), "InvalidValue", "mode must be 0000 through 0777")
		}
		if _, exists := seen[account.canonical()]; exists {
			return nil, diagnostic(member, profile, "home_modes", "Duplicate", "duplicate account reference")
		}
		seen[account.canonical()] = struct{}{}
		result = append(result, homeModeDefinition{account: account, mode: uint16(parsed)})
	}
	return result, nil
}

func admitMemberships(member, profile string, values []rawMembership, parameters map[string]parameterKind) ([]membershipDefinition, error) {
	if values != nil && len(values) == 0 {
		return nil, diagnostic(member, profile, "memberships", "InvalidValue", "explicit empty collection")
	}
	if len(values) > maxResources {
		return nil, diagnostic(member, profile, "memberships", "Limit", "resource limit exceeded")
	}
	result := make([]membershipDefinition, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		account, err := admitReference(raw.Account, accountReference, parameters)
		if err != nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("memberships[%d].account", index), "InvalidValue", err.Error())
		}
		group, err := admitReference(raw.Group, groupReference, parameters)
		if err != nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("memberships[%d].group", index), "InvalidValue", err.Error())
		}
		if raw.Present == nil {
			return nil, diagnostic(member, profile, fmt.Sprintf("memberships[%d].present", index), "InvalidValue", "present is required")
		}
		key := account.canonical() + "|" + group.canonical()
		if _, exists := seen[key]; exists {
			return nil, diagnostic(member, profile, "memberships", "Duplicate", "duplicate membership key")
		}
		seen[key] = struct{}{}
		result = append(result, membershipDefinition{account: account, group: group, present: *raw.Present})
	}
	return result, nil
}

func admitReference(value any, kind parameterKind, parameters map[string]parameterKind) (reference, error) {
	switch value := value.(type) {
	case string:
		if kind == profileReference {
			return reference{}, fmt.Errorf("profile_ref values must be forwarded parameters")
		}
		if kind == accountReference {
			key, err := model.NewAccountKey(value)
			if err != nil {
				return reference{}, err
			}
			return reference{literal: key, kind: kind}, nil
		}
		key, err := model.NewGroupKey(value)
		if err != nil {
			return reference{}, err
		}
		return reference{literal: key, kind: kind}, nil
	case map[string]any:
		if len(value) != 1 {
			return reference{}, fmt.Errorf("reference object must contain only parameter")
		}
		name, ok := value["parameter"].(string)
		if !ok || !validSymbol(name) {
			return reference{}, fmt.Errorf("reference parameter must be a Symbol")
		}
		if parameters[name]&^parameterUsed != kind {
			return reference{}, fmt.Errorf("missing or wrong-kind parameter %q", name)
		}
		if parameters[""] == parameterUsed {
			parameters[name] |= parameterUsed
		}
		return reference{parameter: name, kind: kind}, nil
	default:
		return reference{}, fmt.Errorf("reference must be a literal string or exact parameter object")
	}
}

func parseParameterKind(value string) (parameterKind, bool) {
	switch value {
	case "account_ref":
		return accountReference, true
	case "group_ref":
		return groupReference, true
	case "profile_ref":
		return profileReference, true
	default:
		return 0, false
	}
}

func parseSemanticReference(value string) (semanticReference, error) {
	parts := strings.Split(value, ":")
	switch len(parts) {
	case 1:
		if !validSymbol(parts[0]) {
			return semanticReference{}, fmt.Errorf("invalid local reference %q", value)
		}
		return semanticReference{name: parts[0]}, nil
	case 2:
		if !validSymbol(parts[0]) || !validSymbol(parts[1]) {
			return semanticReference{}, fmt.Errorf("invalid qualified reference %q", value)
		}
		return semanticReference{alias: parts[0], name: parts[1]}, nil
	default:
		return semanticReference{}, fmt.Errorf("invalid qualified reference %q", value)
	}
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

// IsSymbol reports whether value belongs to the profile language's common
// Symbol grammar.
func IsSymbol(value string) bool { return validSymbol(value) }

func diagnostic(member, profile, field, category, detail string) *Diagnostic {
	return &Diagnostic{Category: category, Member: member, Profile: profile, Field: field, Detail: detail}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
