package engine

import (
	"container/heap"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxOperations = 32768
	maxEdges      = 131072
)

type Key struct{ value string }

func NewKey(value string) (Key, error) {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return Key{}, fmt.Errorf("invalid operation key")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return Key{}, fmt.Errorf("invalid operation key")
		}
	}
	return Key{value: value}, nil
}

func (key Key) String() string { return key.value }

type Declaration struct {
	Key          Key
	Dependencies []Key
}

type node struct {
	key          Key
	dependencies []string
	dependents   []string
}

type dagState struct {
	keys  []string
	nodes map[string]node
}

type DAG struct{ state *dagState }

type stringHeap []string

func (values stringHeap) Len() int           { return len(values) }
func (values stringHeap) Less(i, j int) bool { return values[i] < values[j] }
func (values stringHeap) Swap(i, j int)      { values[i], values[j] = values[j], values[i] }
func (values *stringHeap) Push(value any)    { *values = append(*values, value.(string)) }
func (values *stringHeap) Pop() any {
	old := *values
	value := old[len(old)-1]
	*values = old[:len(old)-1]
	return value
}

func Admit(declarations []Declaration) (DAG, error) {
	if len(declarations) == 0 {
		return DAG{}, fmt.Errorf("operation graph must be non-empty")
	}
	if len(declarations) > maxOperations {
		return DAG{}, fmt.Errorf("operation limit exceeded")
	}
	nodes := make(map[string]node, len(declarations))
	edges := 0
	for _, declaration := range declarations {
		if declaration.Key.value == "" {
			return DAG{}, fmt.Errorf("operation key is required")
		}
		name := declaration.Key.value
		if _, exists := nodes[name]; exists {
			return DAG{}, fmt.Errorf("duplicate operation key %q", name)
		}
		seen := make(map[string]struct{}, len(declaration.Dependencies))
		dependencies := make([]string, 0, len(declaration.Dependencies))
		for _, dependency := range declaration.Dependencies {
			if dependency.value == "" {
				return DAG{}, fmt.Errorf("operation %q has invalid dependency", name)
			}
			if _, exists := seen[dependency.value]; exists {
				return DAG{}, fmt.Errorf("operation %q has duplicate dependency %q", name, dependency.value)
			}
			seen[dependency.value] = struct{}{}
			dependencies = append(dependencies, dependency.value)
			edges++
			if edges > maxEdges {
				return DAG{}, fmt.Errorf("operation edge limit exceeded")
			}
		}
		sort.Strings(dependencies)
		nodes[name] = node{key: declaration.Key, dependencies: dependencies}
	}
	keys := make([]string, 0, len(nodes))
	for name := range nodes {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	indegree := make(map[string]int, len(nodes))
	for _, name := range keys {
		current := nodes[name]
		indegree[name] = len(current.dependencies)
		for _, dependency := range current.dependencies {
			parent, exists := nodes[dependency]
			if !exists {
				return DAG{}, fmt.Errorf("operation %q has missing dependency %q", name, dependency)
			}
			parent.dependents = append(parent.dependents, name)
			nodes[dependency] = parent
		}
	}
	for _, name := range keys {
		current := nodes[name]
		sort.Strings(current.dependents)
		nodes[name] = current
	}
	ready := make(stringHeap, 0)
	for _, name := range keys {
		if indegree[name] == 0 {
			heap.Push(&ready, name)
		}
	}
	visited := 0
	for ready.Len() != 0 {
		name := heap.Pop(&ready).(string)
		visited++
		for _, dependent := range nodes[name].dependents {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				heap.Push(&ready, dependent)
			}
		}
	}
	if visited != len(nodes) {
		return DAG{}, fmt.Errorf("operation graph contains a cycle")
	}
	return DAG{state: &dagState{keys: keys, nodes: nodes}}, nil
}

type Outcome uint8

const (
	Satisfied Outcome = iota + 1
	Blocked
	Failed
	Stale
)

func (outcome Outcome) String() string {
	switch outcome {
	case Satisfied:
		return "satisfied"
	case Blocked:
		return "blocked"
	case Failed:
		return "failed"
	case Stale:
		return "stale"
	default:
		return "invalid"
	}
}

type OperationStatus uint8

const (
	OperationPending OperationStatus = iota
	OperationSatisfied
	OperationBlocked
	OperationFailed
	OperationPruned
	OperationStale
)

func (status OperationStatus) String() string {
	switch status {
	case OperationPending:
		return "pending"
	case OperationSatisfied:
		return "satisfied"
	case OperationBlocked:
		return "blocked"
	case OperationFailed:
		return "failed"
	case OperationPruned:
		return "pruned"
	case OperationStale:
		return "stale"
	default:
		return "invalid"
	}
}

type Status uint8

const (
	Running Status = iota
	Converged
	Partial
	BlockedStatus
	FailedStatus
	StaleStatus
)

func (status Status) String() string {
	switch status {
	case Running:
		return "running"
	case Converged:
		return "converged"
	case Partial:
		return "partial"
	case BlockedStatus:
		return "blocked"
	case FailedStatus:
		return "failed"
	case StaleStatus:
		return "stale"
	default:
		return "invalid"
	}
}

type Result struct {
	Key    Key
	Status OperationStatus
	Detail string
}
