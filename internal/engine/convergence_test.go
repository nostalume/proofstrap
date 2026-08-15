package engine_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/nostalume/proofstrap/internal/engine"
)

const (
	maxExhaustiveDAGs = 543
	maxTerminalTraces = 15000
	maxReplayedFrames = 60000
	maximumOperations = 32768
)

type oracle struct {
	dependencies [][]int
	statuses     []engine.OperationStatus
	stopped      bool
}

func newOracle(dependencies [][]int) oracle {
	return oracle{dependencies: dependencies, statuses: make([]engine.OperationStatus, len(dependencies))}
}

func (value oracle) clone() oracle {
	value.statuses = slices.Clone(value.statuses)
	return value
}

func (value oracle) offer() (int, bool) {
	if value.stopped {
		return 0, false
	}
	for operation, dependencies := range value.dependencies {
		if value.statuses[operation] != engine.OperationPending {
			continue
		}
		ready := true
		for _, dependency := range dependencies {
			if value.statuses[dependency] != engine.OperationSatisfied {
				ready = false
				break
			}
		}
		if ready {
			return operation, true
		}
	}
	return 0, false
}

func (value *oracle) apply(operation int, outcome engine.Outcome) {
	switch outcome {
	case engine.Satisfied:
		value.statuses[operation] = engine.OperationSatisfied
	case engine.Blocked:
		value.statuses[operation] = engine.OperationBlocked
		value.prune()
	case engine.Failed:
		value.statuses[operation] = engine.OperationFailed
		value.prune()
	case engine.Stale:
		value.statuses[operation] = engine.OperationStale
		value.stopped = true
	}
}

func (value *oracle) prune() {
	changed := true
	for changed {
		changed = false
		for operation, dependencies := range value.dependencies {
			if value.statuses[operation] != engine.OperationPending {
				continue
			}
			for _, dependency := range dependencies {
				status := value.statuses[dependency]
				if status == engine.OperationBlocked || status == engine.OperationFailed || status == engine.OperationPruned {
					value.statuses[operation] = engine.OperationPruned
					changed = true
					break
				}
			}
		}
	}
}

func (value oracle) status() engine.Status {
	pending, satisfied, blocked, failed := 0, 0, 0, 0
	for _, status := range value.statuses {
		switch status {
		case engine.OperationPending:
			pending++
		case engine.OperationSatisfied:
			satisfied++
		case engine.OperationBlocked:
			blocked++
		case engine.OperationFailed:
			failed++
		case engine.OperationStale:
			return engine.StaleStatus
		}
	}
	if pending != 0 {
		return engine.Running
	}
	if failed == 0 && blocked == 0 {
		return engine.Converged
	}
	if satisfied != 0 {
		return engine.Partial
	}
	if failed != 0 {
		return engine.FailedStatus
	}
	return engine.BlockedStatus
}

func (value oracle) details(keys []engine.Key) []string {
	details := make([]string, len(keys))
	for operation, status := range value.statuses {
		switch status {
		case engine.OperationBlocked:
			details[operation] = "blocked"
		case engine.OperationFailed:
			details[operation] = "failed"
		case engine.OperationStale:
			details[operation] = "stale"
		case engine.OperationPruned:
			for _, dependency := range value.dependencies[operation] {
				if value.statuses[dependency] != engine.OperationSatisfied {
					details[operation] = "dependency " + keys[dependency].String() + " did not converge"
					break
				}
			}
		}
	}
	return details
}

type graphFixture struct {
	dag          engine.DAG
	keys         []engine.Key
	dependencies [][]int
	description  string
}

func admittedFixture(t testing.TB, mask, operationCount int) (graphFixture, bool) {
	t.Helper()
	keys := make([]engine.Key, operationCount)
	for operation := range operationCount {
		keys[operation] = key(t, string(rune('a'+operation)))
	}
	dependencies := make([][]int, operationCount)
	bit := 0
	for from := range operationCount {
		for to := range operationCount {
			if from == to {
				continue
			}
			if mask&(1<<bit) != 0 {
				dependencies[to] = append(dependencies[to], from)
			}
			bit++
		}
	}
	declarations := make([]engine.Declaration, 0, operationCount)
	for operation := operationCount - 1; operation >= 0; operation-- {
		declaration := engine.Declaration{Key: keys[operation]}
		for _, dependency := range dependencies[operation] {
			declaration.Dependencies = append(declaration.Dependencies, keys[dependency])
		}
		declarations = append(declarations, declaration)
	}
	dag, err := engine.Admit(declarations)
	if err != nil {
		return graphFixture{}, false
	}
	return graphFixture{dag: dag, keys: keys, dependencies: dependencies, description: fmt.Sprintf("mask=%03x", mask)}, true
}

func detailFor(outcome engine.Outcome) string {
	switch outcome {
	case engine.Blocked:
		return "blocked"
	case engine.Failed:
		return "failed"
	case engine.Stale:
		return "stale"
	default:
		return ""
	}
}

func traceText(keys []engine.Key, outcomes []engine.Outcome, operations []int) string {
	var buffer bytes.Buffer
	for index, outcome := range outcomes {
		if index != 0 {
			buffer.WriteByte(',')
		}
		fmt.Fprintf(&buffer, "%s=%s", keys[operations[index]], outcome)
	}
	return buffer.String()
}

func compareCore(t testing.TB, fixture graphFixture, outcomes []engine.Outcome, operations []int, want oracle, state engine.State, checkpoint engine.Checkpoint) {
	t.Helper()
	context := fixture.description + " trace=" + traceText(fixture.keys, outcomes, operations)
	wantOffer, hasWant := want.offer()
	stateOffer, hasState := state.Next()
	checkpointOffer, hasCheckpoint := checkpoint.Next()
	if hasState != hasWant || hasCheckpoint != hasWant ||
		(hasWant && (stateOffer != fixture.keys[wantOffer] || checkpointOffer != fixture.keys[wantOffer])) {
		t.Fatalf("%s: offer oracle=%d/%v state=%s/%v checkpoint=%s/%v", context, wantOffer, hasWant, stateOffer, hasState, checkpointOffer, hasCheckpoint)
	}
	if state.Status() != want.status() || checkpoint.Status() != want.status() {
		t.Fatalf("%s: status oracle=%s state=%s checkpoint=%s", context, want.status(), state.Status(), checkpoint.Status())
	}
	compareResults(t, context+" state", fixture.keys, want, state.Results(), false)
	compareResults(t, context+" checkpoint", fixture.keys, want, checkpoint.Results(), true)
}

func compareResults(t testing.TB, context string, keys []engine.Key, want oracle, got []engine.Result, evidence bool) {
	t.Helper()
	if len(got) != len(keys) {
		t.Fatalf("%s: result count=%d want=%d", context, len(got), len(keys))
	}
	details := want.details(keys)
	for operation, result := range got {
		if result.Key != keys[operation] || result.Status != want.statuses[operation] {
			t.Fatalf("%s: result[%d]=%s/%s want=%s/%s", context, operation, result.Key, result.Status, keys[operation], want.statuses[operation])
		}
		if evidence && result.Detail != details[operation] {
			t.Fatalf("%s: detail[%d]=%q want=%q", context, operation, result.Detail, details[operation])
		}
		if !evidence && result.Detail != "" {
			t.Fatalf("%s: lightweight state retained detail %q", context, result.Detail)
		}
	}
}

func runSemanticTrace(t testing.TB, fixture graphFixture, outcomes []engine.Outcome, operations []int) int {
	t.Helper()
	want := newOracle(fixture.dependencies)
	state := fixture.dag.Start()
	run, initial, err := engine.Begin(fixture.dag, digest(t))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := run.Commit(initial)
	if err != nil {
		t.Fatal(err)
	}
	journal := initial.Frame()
	compareCore(t, fixture, nil, nil, want, state, checkpoint)
	for generation, outcome := range outcomes {
		offered, ok := want.offer()
		if !ok || offered != operations[generation] {
			t.Fatalf("%s: invalid trace at generation %d", fixture.description, generation+1)
		}
		candidate, err := checkpoint.Record(fixture.keys[offered], outcome, detailFor(outcome))
		if err != nil {
			t.Fatalf("%s generation=%d: %v", fixture.description, generation+1, err)
		}
		journal = append(journal, candidate.Frame()...)
		checkpoint, err = run.Commit(candidate)
		if err != nil {
			t.Fatal(err)
		}
		state, err = state.Record(fixture.keys[offered], outcome)
		if err != nil {
			t.Fatal(err)
		}
		want.apply(offered, outcome)
		compareCore(t, fixture, outcomes[:generation+1], operations[:generation+1], want, state, checkpoint)
	}
	if _, ok := want.offer(); ok {
		t.Fatalf("%s: trace is not terminal", fixture.description)
	}
	summary, err := engine.InspectJournal(fixture.dag, bytes.NewReader(journal))
	if err != nil {
		t.Fatalf("%s terminal journal: %v", fixture.description, err)
	}
	if summary.PlanDigest() != digest(t) || summary.Generation() != uint32(len(outcomes)) || summary.Status() != want.status() {
		t.Fatalf("%s: summary digest=%s generation=%d status=%s", fixture.description, summary.PlanDigest(), summary.Generation(), summary.Status())
	}
	compareResults(t, fixture.description+" summary", fixture.keys, want, summary.Results(), true)
	return len(outcomes) + 1
}

func enumerateTraces(t *testing.T, fixture graphFixture, terminalTraces, replayedFrames *int) {
	var walk func(oracle, []engine.Outcome, []int)
	walk = func(current oracle, outcomes []engine.Outcome, operations []int) {
		offered, ok := current.offer()
		if !ok {
			*terminalTraces = *terminalTraces + 1
			if *terminalTraces > maxTerminalTraces {
				t.Fatalf("terminal trace ceiling exceeded at %s", fixture.description)
			}
			*replayedFrames += runSemanticTrace(t, fixture, outcomes, operations)
			if *replayedFrames > maxReplayedFrames {
				t.Fatalf("replayed frame ceiling exceeded at %s", fixture.description)
			}
			return
		}
		for _, outcome := range []engine.Outcome{engine.Satisfied, engine.Blocked, engine.Failed, engine.Stale} {
			next := current.clone()
			next.apply(offered, outcome)
			walk(next, append(slices.Clone(outcomes), outcome), append(slices.Clone(operations), offered))
		}
	}
	walk(newOracle(fixture.dependencies), nil, nil)
}

func TestConvergenceExhaustive(t *testing.T) {
	const graphMasks = 1 << 12
	admitted, terminalTraces, replayedFrames := 0, 0, 0
	for mask := range graphMasks {
		fixture, ok := admittedFixture(t, mask, 4)
		if !ok {
			continue
		}
		admitted++
		if admitted > maxExhaustiveDAGs {
			t.Fatal("admitted DAG ceiling exceeded")
		}
		enumerateTraces(t, fixture, &terminalTraces, &replayedFrames)
	}
	if admitted != maxExhaustiveDAGs {
		t.Fatalf("admitted DAGs=%d want=%d", admitted, maxExhaustiveDAGs)
	}
	if terminalTraces == 0 || replayedFrames == 0 {
		t.Fatal("exhaustive search visited no terminal traces")
	}
}

func TestConvergenceReturnedValuesAreIsolated(t *testing.T) {
	fixture, ok := admittedFixture(t, 0, 4)
	if !ok {
		t.Fatal("independent graph rejected")
	}
	run, initial, _ := engine.Begin(fixture.dag, digest(t))
	frame := initial.Frame()
	frame[0] ^= 0xff
	if bytes.Equal(frame, initial.Frame()) {
		t.Fatal("candidate frame aliases returned bytes")
	}
	checkpoint, _ := run.Commit(initial)
	results := checkpoint.Results()
	results[0].Status = engine.OperationFailed
	if checkpoint.Results()[0].Status != engine.OperationPending {
		t.Fatal("checkpoint results alias reducer state")
	}
	summary, err := engine.InspectJournal(fixture.dag, bytes.NewReader(initial.Frame()))
	if err != nil {
		t.Fatal(err)
	}
	results = summary.Results()
	results[0].Status = engine.OperationFailed
	if summary.Results()[0].Status != engine.OperationPending {
		t.Fatal("summary results alias stored projection")
	}
}

func TestConvergenceMaximumOperations(t *testing.T) {
	declarations := make([]engine.Declaration, maximumOperations)
	for index := range maximumOperations {
		name := fmt.Sprintf("operation:%05d", maximumOperations-index-1)
		declarations[index] = engine.Declaration{Key: key(t, name)}
	}
	dag, err := engine.Admit(declarations)
	if err != nil {
		t.Fatal(err)
	}
	run, initial, err := engine.Begin(dag, digest(t))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := run.Commit(initial)
	if err != nil {
		t.Fatal(err)
	}
	for generation := 1; generation <= maximumOperations; generation++ {
		offer, ok := checkpoint.Next()
		want := fmt.Sprintf("operation:%05d", generation-1)
		if !ok || offer.String() != want {
			t.Fatalf("generation %d offer=%q want=%q", generation, offer, want)
		}
		candidate, err := checkpoint.Record(offer, engine.Satisfied, "")
		if err != nil || candidate.Generation() != uint32(generation) {
			t.Fatalf("generation %d candidate=%d err=%v", generation, candidate.Generation(), err)
		}
		checkpoint, err = run.Commit(candidate)
		if err != nil {
			t.Fatal(err)
		}
	}
	if checkpoint.Status() != engine.Converged {
		t.Fatalf("status=%s", checkpoint.Status())
	}
	results := checkpoint.Results()
	if len(results) != maximumOperations || results[0].Status != engine.OperationSatisfied || results[len(results)-1].Status != engine.OperationSatisfied {
		t.Fatalf("terminal result boundary is invalid: count=%d", len(results))
	}
	receipt, err := checkpoint.Receipt()
	if err != nil || !json.Valid(receipt) {
		t.Fatalf("terminal receipt invalid: bytes=%d err=%v", len(receipt), err)
	}
}

func FuzzConvergence(f *testing.F) {
	for _, seed := range [][]byte{{1}, {0x15}, {4, 3, 2, 1, 0xff}, {8, 7, 6, 5, 4, 3, 2, 1, 0xaa, 0x55}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		cursor := 0
		nextByte := func() byte {
			value := data[cursor%len(data)]
			cursor++
			return value
		}
		operationCount := int(nextByte()%8) + 1
		order := make([]int, operationCount)
		for index := range order {
			order[index] = index
		}
		for index := operationCount - 1; index > 0; index-- {
			other := int(nextByte()) % (index + 1)
			order[index], order[other] = order[other], order[index]
		}
		dependencies := make([][]int, operationCount)
		for earlier := 0; earlier < operationCount; earlier++ {
			for later := earlier + 1; later < operationCount; later++ {
				if nextByte()&1 != 0 {
					dependencies[order[later]] = append(dependencies[order[later]], order[earlier])
				}
			}
		}
		for operation := range dependencies {
			slices.Sort(dependencies[operation])
		}
		keys := make([]engine.Key, operationCount)
		declarations := make([]engine.Declaration, operationCount)
		for operation := range operationCount {
			keys[operation] = key(t, string(rune('a'+operation)))
		}
		for operation := range operationCount {
			declarations[operation].Key = keys[operation]
			for _, dependency := range dependencies[operation] {
				declarations[operation].Dependencies = append(declarations[operation].Dependencies, keys[dependency])
			}
		}
		for index := operationCount - 1; index > 0; index-- {
			other := int(nextByte()) % (index + 1)
			declarations[index], declarations[other] = declarations[other], declarations[index]
		}
		dag, err := engine.Admit(declarations)
		if err != nil {
			t.Fatal(err)
		}
		fixture := graphFixture{dag: dag, keys: keys, dependencies: dependencies, description: fmt.Sprintf("fuzz=%x", data)}
		current := newOracle(dependencies)
		var outcomes []engine.Outcome
		var operations []int
		for {
			offered, ok := current.offer()
			if !ok {
				break
			}
			outcome := engine.Outcome(nextByte()%4 + 1)
			outcomes = append(outcomes, outcome)
			operations = append(operations, offered)
			current.apply(offered, outcome)
		}
		runSemanticTrace(t, fixture, outcomes, operations)
	})
}
