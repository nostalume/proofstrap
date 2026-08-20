package model

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

//sumtype:decl
type Provenance interface {
	provenance()
	sourceValue() string
}

type provenance struct{ source string }

func NewProvenance(source string) (Provenance, error) {
	if strings.TrimSpace(source) == "" || strings.ContainsAny(source, "\r\n") {
		return nil, fmt.Errorf("invalid empty or multiline provenance")
	}
	return provenance{source: source}, nil
}
func (provenance) provenance()           {}
func (p provenance) sourceValue() string { return p.source }

//sumtype:decl
type Contribution interface {
	contribution()
	parts() (Resource, provenance)
}

type contribution struct {
	resource   Resource
	provenance provenance
}

func Contribute(resource Resource, source Provenance) (Contribution, error) {
	value, ok := source.(provenance)
	if resource == nil || !ok {
		return nil, fmt.Errorf("resource and provenance are required")
	}
	return contribution{resource: resource, provenance: value}, nil
}
func (contribution) contribution()                   {}
func (c contribution) parts() (Resource, provenance) { return c.resource, c.provenance }

type graphNode struct {
	resource   Resource
	provenance map[string]struct{}
}

type Graph struct{ nodes map[string]graphNode }

func EmptyGraph() Graph { return Graph{} }

func (g Graph) Add(delta []Contribution) (Graph, error) {
	next := cloneNodes(g.nodes, len(delta))
	for i, item := range delta {
		if item == nil {
			return g, fmt.Errorf("contribution %d is nil", i)
		}
		resource, source := item.parts()
		if resource == nil || source.source == "" {
			return g, fmt.Errorf("contribution %d is invalid", i)
		}
		key := resource.Key().Canonical()
		if key == "" {
			return g, fmt.Errorf("contribution %d has invalid key", i)
		}
		if current, ok := next[key]; ok {
			if current.resource.desired() != resource.desired() ||
				!sameDependencies(current.resource, resource) {
				return g, fmt.Errorf("resource conflict for %s", key)
			}
			current.provenance[source.source] = struct{}{}
			next[key] = current
			continue
		}
		next[key] = graphNode{
			resource: resource,
			provenance: map[string]struct{}{
				source.source: {},
			},
		}
	}
	if err := validateGraph(next); err != nil {
		return g, err
	}
	return Graph{nodes: next}, nil
}

func sameDependencies(left, right Resource) bool {
	return slices.Equal(canonicalDependencies(left), canonicalDependencies(right))
}

func canonicalDependencies(resource Resource) []string {
	dependencies := resource.dependencies()
	keys := make([]string, 0, len(dependencies))
	for _, dependency := range dependencies {
		keys = append(keys, dependency.Canonical())
	}
	sort.Strings(keys)
	return keys
}

func cloneNodes(nodes map[string]graphNode, extra int) map[string]graphNode {
	cloned := make(map[string]graphNode, len(nodes)+extra)
	for key, node := range nodes {
		provenance := make(map[string]struct{}, len(node.provenance))
		for source := range node.provenance {
			provenance[source] = struct{}{}
		}
		cloned[key] = graphNode{resource: node.resource, provenance: provenance}
	}
	return cloned
}

func validateGraph(nodes map[string]graphNode) error {
	coordinates := make(map[coordinate]string)
	keys := make([]string, 0, len(nodes))
	for key := range nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		node := nodes[key]
		for _, dependency := range node.resource.dependencies() {
			dependencyKey := dependency.Canonical()
			if _, ok := nodes[dependencyKey]; !ok {
				return fmt.Errorf("missing dependency %s required by %s", dependencyKey, key)
			}
		}
		for _, coordinate := range node.resource.coordinates() {
			if owner, ok := coordinates[coordinate]; ok && owner != key {
				return fmt.Errorf("%s coordinate collision between %s and %s", coordinate.kind, owner, key)
			}
			coordinates[coordinate] = key
		}
	}
	return nil
}

//sumtype:decl
type Node interface {
	Key() Key
	Resource() Resource
	Dependencies() []Key
	Provenance() []string
	node()
}

type node struct{ value graphNode }

func (n node) Key() Key { return n.value.resource.Key() }

func (n node) Resource() Resource { return n.value.resource }

func (n node) Dependencies() []Key {
	dependencies := append([]Key(nil), n.value.resource.dependencies()...)
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Canonical() < dependencies[j].Canonical()
	})
	return dependencies
}

func (n node) Provenance() []string {
	provenance := make([]string, 0, len(n.value.provenance))
	for source := range n.value.provenance {
		provenance = append(provenance, source)
	}
	sort.Strings(provenance)
	return provenance
}
func (node) node() {}

func (g Graph) Nodes() []Node {
	nodes := make([]Node, 0, len(g.nodes))
	for _, value := range g.nodes {
		nodes = append(nodes, node{value: value})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Key().Canonical() < nodes[j].Key().Canonical()
	})
	return nodes
}

func PackageIDOf(candidate Node) (PackageID, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(packageResource)
	if !valid || !ok {
		return nil, false
	}
	return value.key.id, true
}

func ServiceIDOf(candidate Node) (ServiceID, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(serviceResource)
	if !valid || !ok {
		return nil, false
	}
	return value.key.id, true
}

type Group struct {
	name    string
	managed bool
	gid     uint32
	valid   bool
}

type Account struct {
	name, primaryGroup, home string
	uid                      uint32
	managed, valid           bool
}

type Service struct {
	id       ServiceID
	user     string
	enable   EnableIntent
	run      RunIntent
	packages []PackageKey
	valid    bool
}

type Home struct {
	account string
	valid   bool
}

type HomeMode struct {
	account string
	mode    uint16
	valid   bool
}

type AccountLock struct {
	account string
	valid   bool
}

type AccountShell struct {
	account string
	shell   string
	valid   bool
}

type Membership struct {
	account string
	group   string
	present bool
	valid   bool
}

type Hostname struct {
	value string
	valid bool
}
type Timezone struct {
	value string
	valid bool
}

func (value Group) Valid() bool              { return value.valid }
func (value Group) Name() string             { return value.name }
func (value Group) Managed() bool            { return value.managed }
func (value Group) GID() uint32              { return value.gid }
func (value Account) Valid() bool            { return value.valid }
func (value Account) Name() string           { return value.name }
func (value Account) Managed() bool          { return value.managed }
func (value Account) UID() uint32            { return value.uid }
func (value Account) PrimaryGroup() string   { return value.primaryGroup }
func (value Account) Home() string           { return value.home }
func (value Service) Valid() bool            { return value.valid }
func (value Service) ID() ServiceID          { return value.id }
func (value Service) Enable() EnableIntent   { return value.enable }
func (value Service) Run() RunIntent         { return value.run }
func (value Service) User() (string, bool)   { return value.user, value.valid && value.user != "" }
func (value Service) Packages() []PackageKey { return append([]PackageKey(nil), value.packages...) }
func (value Home) Valid() bool               { return value.valid }
func (value Home) Account() string           { return value.account }
func (value HomeMode) Valid() bool           { return value.valid }
func (value HomeMode) Account() string       { return value.account }
func (value HomeMode) Mode() uint16          { return value.mode }
func (value AccountLock) Valid() bool        { return value.valid }
func (value AccountLock) Account() string    { return value.account }
func (value AccountShell) Valid() bool       { return value.valid }
func (value AccountShell) Account() string   { return value.account }
func (value AccountShell) Shell() string     { return value.shell }
func (value Membership) Valid() bool         { return value.valid }
func (value Membership) Account() string     { return value.account }
func (value Membership) Group() string       { return value.group }
func (value Membership) Present() bool       { return value.present }
func (value Hostname) Valid() bool           { return value.valid }
func (value Hostname) Value() string         { return value.value }
func (value Timezone) Valid() bool           { return value.valid }
func (value Timezone) Value() string         { return value.value }

func resourceOf(candidate Node) (Resource, bool) {
	value, ok := candidate.(node)
	if !ok {
		return nil, false
	}
	return value.value.resource, true
}

func GroupOf(candidate Node) (Group, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(groupResource)
	if !valid || !ok {
		return Group{}, false
	}
	return Group{name: value.key.name, managed: value.managed, gid: value.gid, valid: true}, true
}

func AccountOf(candidate Node) (Account, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(accountResource)
	if !valid || !ok {
		return Account{}, false
	}
	result := Account{name: value.key.name, managed: value.managed, uid: value.uid, home: value.home, valid: true}
	if value.managed {
		result.primaryGroup = value.group.name
	}
	return result, true
}

func ServiceOf(candidate Node) (Service, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(serviceResource)
	if !valid || !ok {
		return Service{}, false
	}
	packages := make([]PackageKey, len(value.packages))
	for index, key := range value.packages {
		packages[index] = key
	}
	result := Service{
		id:       value.key.id,
		enable:   value.enable,
		run:      value.run,
		packages: packages,
		valid:    true,
	}
	if value.key.target.isUser {
		result.user = value.key.target.user.name
	}
	return result, true
}

func HomeOf(candidate Node) (Home, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(homeResource)
	if !valid || !ok {
		return Home{}, false
	}
	return Home{account: value.key.account.name, valid: true}, true
}

func HomeModeOf(candidate Node) (HomeMode, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(homeModeResource)
	if !valid || !ok {
		return HomeMode{}, false
	}
	return HomeMode{account: value.key.account.name, mode: value.mode, valid: true}, true
}

func AccountLockOf(candidate Node) (AccountLock, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(accountLockResource)
	if !valid || !ok {
		return AccountLock{}, false
	}
	return AccountLock{account: value.key.account.name, valid: true}, true
}

func AccountShellOf(candidate Node) (AccountShell, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(accountShellResource)
	if !valid || !ok {
		return AccountShell{}, false
	}
	return AccountShell{account: value.key.account.name, shell: value.shell, valid: true}, true
}

func MembershipOf(candidate Node) (Membership, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(membershipResource)
	if !valid || !ok {
		return Membership{}, false
	}
	return Membership{account: value.key.account.name, group: value.key.group.name, present: value.present, valid: true}, true
}

func HostnameOf(candidate Node) (Hostname, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(hostnameResource)
	if !valid || !ok {
		return Hostname{}, false
	}
	return Hostname{value: value.value, valid: true}, true
}

func TimezoneOf(candidate Node) (Timezone, bool) {
	resource, valid := resourceOf(candidate)
	value, ok := resource.(timezoneResource)
	if !valid || !ok {
		return Timezone{}, false
	}
	return Timezone{value: value.value, valid: true}, true
}
