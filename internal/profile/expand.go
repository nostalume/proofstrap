package profile

import (
	"fmt"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

type expansionLimits struct {
	instances  int
	nodes      int
	edges      int
	provenance int
}

var stageLimits = expansionLimits{
	instances:  4096,
	nodes:      32768,
	edges:      131072,
	provenance: 262144,
}

//sumtype:decl
type Argument interface {
	argument()
	argumentValue() namedArgument
}

type namedArgument struct {
	name  string
	value reference
}

func (namedArgument) argument() {}
func (a namedArgument) argumentValue() namedArgument {
	return a
}

func NewAccountArgument(name string, key model.AccountKey) (Argument, error) {
	if !validSymbol(name) || key == nil {
		return nil, fmt.Errorf("valid account argument name and key are required")
	}
	return namedArgument{name: name, value: reference{literal: key, kind: accountReference}}, nil
}

func NewGroupArgument(name string, key model.GroupKey) (Argument, error) {
	if !validSymbol(name) || key == nil {
		return nil, fmt.Errorf("valid group argument name and key are required")
	}
	return namedArgument{name: name, value: reference{literal: key, kind: groupReference}}, nil
}

//sumtype:decl
type Root interface {
	root()
	rootValue() root
}

type root struct {
	profile   string
	arguments map[string]reference
}

func (root) root() {}
func (r root) rootValue() root {
	return r
}

func NewRoot(profile string, arguments ...Argument) (Root, error) {
	if !validSymbol(profile) {
		return nil, fmt.Errorf("invalid root profile %q", profile)
	}
	values := make(map[string]reference, len(arguments))
	for _, argument := range arguments {
		if argument == nil {
			return nil, fmt.Errorf("nil root argument")
		}
		value := argument.argumentValue()
		if _, exists := values[value.name]; exists {
			return nil, fmt.Errorf("duplicate root argument %q", value.name)
		}
		values[value.name] = value.value
	}
	return root{profile: profile, arguments: values}, nil
}

func BindRoot(library Library, name string, values map[string]string, identities map[string]model.Key) (Root, error) {
	profileKey, exists := library.localProfiles[name]
	if !exists {
		return nil, fmt.Errorf("missing root profile %q", name)
	}
	parameters := library.profiles[profileKey].parameters
	if len(parameters) != len(values) || len(parameters) == 0 && values != nil {
		return nil, fmt.Errorf("arguments must exactly match profile parameters")
	}
	arguments := make([]Argument, 0, len(values))
	for _, parameter := range sortedKeys(parameters) {
		value, kind := values[parameter], parameters[parameter]
		prefix := "account:"
		if kind == groupReference {
			prefix = "group:"
		}
		key := identities[prefix+value]
		if key == nil {
			return nil, fmt.Errorf("argument %q does not name a declared %s", parameter, prefix[:len(prefix)-1])
		}
		arguments = append(arguments, namedArgument{name: parameter, value: reference{literal: key, kind: kind}})
	}
	return NewRoot(name, arguments...)
}

func Expand(base model.Graph, library Library, roots []Root) (model.Graph, error) {
	return expandWithLimits(base, library, roots, stageLimits)
}

type expander struct {
	library          Library
	limits           expansionLimits
	seen             map[string]struct{}
	contributionSeen map[string]struct{}
	contributions    []model.Contribution
}

func expandWithLimits(base model.Graph, library Library, roots []Root, limits expansionLimits) (model.Graph, error) {
	if len(library.profiles) == 0 {
		return base, fmt.Errorf("invalid empty admitted library")
	}
	canonicalRoots := make(map[string]root, len(roots))
	for index, candidate := range roots {
		if candidate == nil {
			return base, fmt.Errorf("root %d is nil", index)
		}
		value := candidate.rootValue()
		profileKey, exists := library.localProfiles[value.profile]
		definition := library.profiles[profileKey]
		if !exists {
			return base, fmt.Errorf("missing root profile %q", value.profile)
		}
		if err := exactBindings(definition.parameters, value.arguments); err != nil {
			return base, fmt.Errorf("root %s: %w", value.profile, err)
		}
		value.profile = profileKey
		canonicalRoots[instanceKey(value.profile, value.arguments)] = value
	}
	keys := sortedKeys(canonicalRoots)
	engine := expander{
		library:          library,
		limits:           limits,
		seen:             make(map[string]struct{}),
		contributionSeen: make(map[string]struct{}),
	}
	for _, key := range keys {
		candidate := canonicalRoots[key]
		if err := engine.instantiate(candidate.profile, candidate.arguments); err != nil {
			return base, err
		}
	}
	graph, err := base.Add(engine.contributions)
	if err != nil {
		return base, err
	}
	if err := validateExpansionLimits(graph, len(engine.seen), limits); err != nil {
		return base, err
	}
	return graph, nil
}

func (e *expander) instantiate(profileID string, bindings map[string]reference) error {
	key := instanceKey(profileID, bindings)
	if _, exists := e.seen[key]; exists {
		return nil
	}
	if len(e.seen) >= e.limits.instances {
		return fmt.Errorf("bound profile instance limit exceeded")
	}
	e.seen[key] = struct{}{}
	definition := e.library.profiles[profileID]
	children := make(map[string]root, len(definition.includes))
	for _, include := range definition.includes {
		arguments := make(map[string]reference, len(include.arguments))
		for name, expression := range include.arguments {
			bound, err := bindReference(expression, bindings)
			if err != nil {
				return fmt.Errorf("profile %s include %s argument %s: %w", profileID, include.profile, name, err)
			}
			arguments[name] = bound
		}
		children[instanceKey(include.profile, arguments)] = root{
			profile:   include.profile,
			arguments: arguments,
		}
	}
	for _, childKey := range sortedKeys(children) {
		child := children[childKey]
		if err := e.instantiate(child.profile, child.arguments); err != nil {
			return err
		}
	}
	return e.emit(definition, bindings, key)
}

func (e *expander) emit(definition profileDefinition, bindings map[string]reference, instance string) error {
	source, err := model.NewProvenance("profile:" + instance)
	if err != nil {
		return err
	}
	add := func(resource model.Resource) error {
		contributionKey := resource.Key().Canonical() + "|" + instance
		if _, exists := e.contributionSeen[contributionKey]; exists {
			return nil
		}
		if len(e.contributionSeen) >= e.limits.provenance {
			return fmt.Errorf("provenance contribution limit exceeded")
		}
		contribution, err := model.Contribute(resource, source)
		if err != nil {
			return err
		}
		e.contributionSeen[contributionKey] = struct{}{}
		e.contributions = append(e.contributions, contribution)
		return nil
	}
	for _, packageReference := range definition.packages {
		resource, err := e.packageResource(packageReference)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	for _, service := range definition.services {
		for _, packageReference := range service.packages {
			resource, err := e.packageResource(packageReference)
			if err != nil {
				return err
			}
			if err := add(resource); err != nil {
				return err
			}
		}
		resource, err := e.serviceResource(service, bindings)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	for _, expression := range definition.homes {
		account, err := boundAccount(expression, bindings)
		if err != nil {
			return err
		}
		resource, err := model.NewHome(account)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	for _, value := range definition.homeModes {
		account, err := boundAccount(value.account, bindings)
		if err != nil {
			return err
		}
		resource, err := model.NewHomeMode(account, value.mode)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	for _, expression := range definition.accountLocks {
		account, err := boundAccount(expression, bindings)
		if err != nil {
			return err
		}
		resource, err := model.NewAccountLock(account)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	for _, value := range definition.memberships {
		account, err := boundAccount(value.account, bindings)
		if err != nil {
			return err
		}
		group, err := boundGroup(value.group, bindings)
		if err != nil {
			return err
		}
		resource, err := model.NewMembership(account, group, value.present)
		if err != nil {
			return err
		}
		if err := add(resource); err != nil {
			return err
		}
	}
	if definition.hostname != nil {
		if err := add(definition.hostname); err != nil {
			return err
		}
	}
	if definition.timezone != nil {
		if err := add(definition.timezone); err != nil {
			return err
		}
	}
	return nil
}

func (e *expander) packageResource(reference semanticReference) (model.Resource, error) {
	if reference.alias != "" {
		return nil, fmt.Errorf("unresolved imported package %s", reference.canonical())
	}
	id, err := model.NewPackageID(reference.name)
	if err != nil {
		return nil, err
	}
	return model.NewPackage(id)
}

func (e *expander) serviceResource(definition serviceDefinition, bindings map[string]reference) (model.Resource, error) {
	if definition.id.alias != "" {
		return nil, fmt.Errorf("unresolved imported service %s", definition.id.canonical())
	}
	id, err := model.NewServiceID(definition.id.name)
	if err != nil {
		return nil, err
	}
	target := model.SystemServiceTarget()
	if definition.user != nil {
		account, err := boundAccount(*definition.user, bindings)
		if err != nil {
			return nil, err
		}
		target, err = model.UserServiceTarget(account)
		if err != nil {
			return nil, err
		}
	}
	packages := make([]model.PackageKey, 0, len(definition.packages))
	for _, reference := range definition.packages {
		if reference.alias != "" {
			return nil, fmt.Errorf("unresolved imported package %s", reference.canonical())
		}
		id, err := model.NewPackageID(reference.name)
		if err != nil {
			return nil, err
		}
		key, err := model.NewPackageKey(id)
		if err != nil {
			return nil, err
		}
		packages = append(packages, key)
	}
	return model.NewService(id, target, definition.enable, definition.run, packages)
}

func bindReference(expression reference, bindings map[string]reference) (reference, error) {
	if expression.parameter == "" {
		return expression, nil
	}
	bound, exists := bindings[expression.parameter]
	if !exists || bound.kind != expression.kind || bound.parameter != "" || bound.literal == nil {
		return reference{}, fmt.Errorf("unresolved or wrong-kind parameter %q", expression.parameter)
	}
	return bound, nil
}

func boundAccount(expression reference, bindings map[string]reference) (model.AccountKey, error) {
	bound, err := bindReference(expression, bindings)
	if err != nil {
		return nil, err
	}
	key, ok := bound.literal.(model.AccountKey)
	if !ok {
		return nil, fmt.Errorf("reference is not an account key")
	}
	return key, nil
}

func boundGroup(expression reference, bindings map[string]reference) (model.GroupKey, error) {
	bound, err := bindReference(expression, bindings)
	if err != nil {
		return nil, err
	}
	key, ok := bound.literal.(model.GroupKey)
	if !ok {
		return nil, fmt.Errorf("reference is not a group key")
	}
	return key, nil
}

func exactBindings(parameters map[string]parameterKind, bindings map[string]reference) error {
	if len(parameters) != len(bindings) {
		return fmt.Errorf("arguments must exactly match profile parameters")
	}
	for _, name := range sortedKeys(parameters) {
		kind := parameters[name]
		binding, exists := bindings[name]
		if !exists || binding.kind != kind || binding.parameter != "" || binding.literal == nil {
			return fmt.Errorf("missing or wrong-kind argument %q", name)
		}
	}
	return nil
}

func instanceKey(profile string, bindings map[string]reference) string {
	var builder strings.Builder
	builder.WriteString(profile)
	builder.WriteByte('|')
	for _, name := range sortedKeys(bindings) {
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(bindings[name].canonical())
		builder.WriteByte(';')
	}
	return builder.String()
}

func validateExpansionLimits(graph model.Graph, instances int, limits expansionLimits) error {
	if instances > limits.instances {
		return fmt.Errorf("bound profile instance limit exceeded")
	}
	nodes := graph.Nodes()
	if len(nodes) > limits.nodes {
		return fmt.Errorf("canonical node limit exceeded")
	}
	edges := 0
	provenance := 0
	for _, node := range nodes {
		edges += len(node.Dependencies())
		provenance += len(node.Provenance())
	}
	if edges > limits.edges {
		return fmt.Errorf("dependency edge limit exceeded")
	}
	if provenance > limits.provenance {
		return fmt.Errorf("provenance contribution limit exceeded")
	}
	return nil
}
