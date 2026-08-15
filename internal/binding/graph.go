package binding

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

type Key interface {
	Canonical() string
	key()
}

type passthroughKey struct{ semantic model.Key }
type packageKey struct{ id PackageID }
type serviceKey struct {
	id       ServiceID
	semantic string
}

func (k passthroughKey) Canonical() string { return "semantic:" + encodePart(k.semantic.Canonical()) }
func (passthroughKey) key()                {}
func (k packageKey) Canonical() string {
	return "package:" + encodePart(k.id.backend.value) + encodePart(k.id.name)
}
func (packageKey) key() {}
func (k serviceKey) Canonical() string {
	return "service:" + encodePart(k.id.backend.value) + encodePart(k.id.name) + encodePart(k.semantic)
}
func (serviceKey) key() {}

func encodePart(value string) string { return fmt.Sprintf("%d:%s", len(value), value) }

type graphNode struct {
	key          Key
	semantic     model.Node
	dependencies []Key
	provenance   []string
}

type graphState struct{ nodes map[string]graphNode }
type Graph struct{ state *graphState }

type Node interface {
	Key() Key
	Semantic() model.Node
	Dependencies() []Key
	Provenance() []string
	node()
}

type node struct{ value graphNode }

func (n node) Key() Key             { return n.value.key }
func (n node) Semantic() model.Node { return n.value.semantic }
func (node) node()                  {}
func (n node) Dependencies() []Key  { return append([]Key(nil), n.value.dependencies...) }
func (n node) Provenance() []string { return append([]string(nil), n.value.provenance...) }

func (g Graph) Nodes() []Node {
	if g.state == nil {
		return nil
	}
	keys := make([]string, 0, len(g.state.nodes))
	for key := range g.state.nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Node, 0, len(keys))
	for _, key := range keys {
		result = append(result, node{value: g.state.nodes[key]})
	}
	return result
}

func PackageIDOf(candidate Node) (PackageID, bool) {
	value, ok := candidate.(node)
	if !ok {
		return PackageID{}, false
	}
	key, ok := value.value.key.(packageKey)
	if !ok {
		return PackageID{}, false
	}
	return key.id, true
}

func ServiceIDOf(candidate Node) (ServiceID, bool) {
	value, ok := candidate.(node)
	if !ok {
		return ServiceID{}, false
	}
	key, ok := value.value.key.(serviceKey)
	if !ok {
		return ServiceID{}, false
	}
	return key.id, true
}

type BlockerKind uint8

const (
	Conflict BlockerKind = iota + 1
	Unsupported
	Limit
)

func (k BlockerKind) String() string {
	switch k {
	case Conflict:
		return "Conflict"
	case Unsupported:
		return "Unsupported"
	case Limit:
		return "Limit"
	default:
		return "Invalid"
	}
}

type Blocker struct {
	Kind     BlockerKind
	Domain   Domain
	Backend  string
	Semantic string
	Native   string
	Sources  []string
	Detail   string
}

type Blocked struct{ blockers []Blocker }

func (e *Blocked) Error() string {
	return fmt.Sprintf("binding projection blocked by %d issue(s)", len(e.blockers))
}

func (e *Blocked) Blockers() []Blocker {
	result := make([]Blocker, len(e.blockers))
	for index, blocker := range e.blockers {
		result[index] = blocker
		result[index].Sources = append([]string(nil), blocker.Sources...)
	}
	return result
}

func blockerKey(value Blocker) string {
	return fmt.Sprintf("%03d\x00%03d\x00%s\x00%s\x00%s\x00%s", value.Kind, value.Domain,
		value.Backend, value.Semantic, value.Native, strings.Join(value.Sources, "\x00"))
}

func canonicalBlockers(values []Blocker) []Blocker {
	unique := make(map[string]Blocker, len(values))
	for _, value := range values {
		value.Sources = unionStrings(nil, value.Sources)
		unique[blockerKey(value)] = value
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Blocker, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}
