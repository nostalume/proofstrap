package engine

import (
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
	ready := make([]string, 0)
	for _, name := range keys {
		if indegree[name] == 0 {
			ready = append(ready, name)
		}
	}
	visited := 0
	for len(ready) != 0 {
		name := ready[0]
		ready = ready[1:]
		visited++
		for _, dependent := range nodes[name].dependents {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				ready = insertSorted(ready, dependent)
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

type executionState struct {
	dag      *dagState
	statuses map[string]OperationStatus
	stale    bool
}

type State struct{ state *executionState }

func (dag DAG) Start() State {
	if dag.state == nil {
		return State{}
	}
	return State{state: &executionState{dag: dag.state, statuses: make(map[string]OperationStatus, len(dag.state.keys))}}
}

func (state State) Next() (Key, bool) {
	if state.state == nil || state.state.stale {
		return Key{}, false
	}
	for _, name := range state.state.dag.keys {
		if state.state.statuses[name] != OperationPending {
			continue
		}
		ready := true
		for _, dependency := range state.state.dag.nodes[name].dependencies {
			if state.state.statuses[dependency] != OperationSatisfied {
				ready = false
				break
			}
		}
		if ready {
			return state.state.dag.nodes[name].key, true
		}
	}
	return Key{}, false
}

func (state State) Record(key Key, outcome Outcome) (State, error) {
	if state.state == nil {
		return state, fmt.Errorf("invalid execution state")
	}
	if outcome < Satisfied || outcome > Stale {
		return state, fmt.Errorf("invalid operation outcome")
	}
	offered, ok := state.Next()
	if !ok || offered != key {
		return state, fmt.Errorf("outcome does not match offered operation")
	}
	next := cloneExecution(state.state)
	switch outcome {
	case Satisfied:
		next.statuses[key.value] = OperationSatisfied
	case Blocked:
		next.statuses[key.value] = OperationBlocked
		prune(next, key.value)
	case Failed:
		next.statuses[key.value] = OperationFailed
		prune(next, key.value)
	case Stale:
		next.statuses[key.value] = OperationStale
		next.stale = true
	}
	return State{state: next}, nil
}

func prune(state *executionState, root string) {
	queue := append([]string(nil), state.dag.nodes[root].dependents...)
	for len(queue) != 0 {
		name := queue[0]
		queue = queue[1:]
		if state.statuses[name] != OperationPending {
			continue
		}
		state.statuses[name] = OperationPruned
		queue = append(queue, state.dag.nodes[name].dependents...)
	}
}

func cloneExecution(source *executionState) *executionState {
	statuses := make(map[string]OperationStatus, len(source.statuses))
	for key, status := range source.statuses {
		statuses[key] = status
	}
	return &executionState{dag: source.dag, statuses: statuses, stale: source.stale}
}

type Result struct {
	Key    Key
	Status OperationStatus
	Detail string
}

func (state State) Results() []Result {
	if state.state == nil {
		return nil
	}
	results := make([]Result, 0, len(state.state.dag.keys))
	for _, name := range state.state.dag.keys {
		results = append(results, Result{Key: state.state.dag.nodes[name].key, Status: state.state.statuses[name]})
	}
	return results
}

func (state State) Status() Status {
	if state.state == nil {
		return BlockedStatus
	}
	if state.state.stale {
		return StaleStatus
	}
	pending, satisfied, blocked, failed := 0, 0, 0, 0
	for _, status := range state.state.statuses {
		switch status {
		case OperationSatisfied:
			satisfied++
		case OperationBlocked:
			blocked++
		case OperationFailed:
			failed++
		}
	}
	for _, name := range state.state.dag.keys {
		if state.state.statuses[name] == OperationPending {
			pending++
		}
	}
	if pending != 0 {
		return Running
	}
	if failed == 0 && blocked == 0 {
		return Converged
	}
	if satisfied != 0 {
		return Partial
	}
	if failed != 0 {
		return FailedStatus
	}
	return BlockedStatus
}

func insertSorted(values []string, value string) []string {
	index := sort.SearchStrings(values, value)
	values = append(values, "")
	copy(values[index+1:], values[index:])
	values[index] = value
	return values
}
