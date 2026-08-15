package engine

import (
	"bytes"
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	journalSchema   = 1
	maxJournalBytes = 64 << 20
	maxDetailBytes  = 1024
)

type PlanDigest struct{ value string }

func ParsePlanDigest(value string) (PlanDigest, error) {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || !strings.HasPrefix(value, prefix) {
		return PlanDigest{}, fmt.Errorf("invalid Plan digest")
	}
	encoded := value[len(prefix):]
	if strings.ToLower(encoded) != encoded {
		return PlanDigest{}, fmt.Errorf("invalid Plan digest")
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return PlanDigest{}, fmt.Errorf("invalid Plan digest")
	}
	return PlanDigest{value: value}, nil
}

func (digest PlanDigest) String() string { return digest.value }

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

type operationRecord struct {
	status OperationStatus
	detail string
}

type statusCounts struct {
	pending, satisfied, blocked, failed, stale, pruned int
}

type reducer struct {
	dag       *dagState
	records   map[string]operationRecord
	remaining map[string]int
	ready     stringHeap
	counts    statusCounts
	stopped   bool
}

func newReducer(dag *dagState) *reducer {
	value := &reducer{
		dag: dag, records: make(map[string]operationRecord, len(dag.keys)),
		remaining: make(map[string]int, len(dag.keys)), counts: statusCounts{pending: len(dag.keys)},
	}
	for _, name := range dag.keys {
		value.remaining[name] = len(dag.nodes[name].dependencies)
		if value.remaining[name] == 0 {
			heap.Push(&value.ready, name)
		}
	}
	return value
}

func (value *reducer) offer() (Key, bool) {
	if value == nil || value.stopped {
		return Key{}, false
	}
	for value.ready.Len() != 0 {
		name := value.ready[0]
		if value.records[name].status == OperationPending {
			return value.dag.nodes[name].key, true
		}
		heap.Pop(&value.ready)
	}
	return Key{}, false
}

func (value *reducer) apply(key Key, outcome Outcome, detail string) error {
	offered, ok := value.offer()
	if !ok || offered != key {
		return fmt.Errorf("outcome does not match offered operation")
	}
	if err := validateDetail(outcome, detail); err != nil {
		return err
	}
	heap.Pop(&value.ready)
	switch outcome {
	case Satisfied:
		value.set(key.value, operationRecord{status: OperationSatisfied})
		for _, dependent := range value.dag.nodes[key.value].dependents {
			if value.records[dependent].status != OperationPending {
				continue
			}
			value.remaining[dependent]--
			if value.remaining[dependent] == 0 {
				heap.Push(&value.ready, dependent)
			}
		}
	case Blocked:
		value.set(key.value, operationRecord{status: OperationBlocked, detail: detail})
		value.prune(key.value)
	case Failed:
		value.set(key.value, operationRecord{status: OperationFailed, detail: detail})
		value.prune(key.value)
	case Stale:
		value.set(key.value, operationRecord{status: OperationStale, detail: detail})
		value.stopped = true
	default:
		return fmt.Errorf("invalid operation outcome")
	}
	return nil
}

func (value *reducer) set(name string, record operationRecord) {
	value.records[name] = record
	value.counts.pending--
	switch record.status {
	case OperationSatisfied:
		value.counts.satisfied++
	case OperationBlocked:
		value.counts.blocked++
	case OperationFailed:
		value.counts.failed++
	case OperationStale:
		value.counts.stale++
	case OperationPruned:
		value.counts.pruned++
	}
}

func (value *reducer) prune(root string) {
	queue := append([]string(nil), value.dag.nodes[root].dependents...)
	for len(queue) != 0 {
		name := queue[0]
		queue = queue[1:]
		if value.records[name].status != OperationPending {
			continue
		}
		value.set(name, operationRecord{status: OperationPruned})
		queue = append(queue, value.dag.nodes[name].dependents...)
	}
}

func (value *reducer) status() Status { return reduceCounts(value.counts) }

func reduceCounts(counts statusCounts) Status {
	if counts.stale != 0 {
		return StaleStatus
	}
	if counts.pending != 0 {
		return Running
	}
	if counts.failed == 0 && counts.blocked == 0 {
		return Converged
	}
	if counts.satisfied != 0 {
		return Partial
	}
	if counts.failed != 0 {
		return FailedStatus
	}
	return BlockedStatus
}

func (value *reducer) results() []Result {
	results := make([]Result, 0, len(value.dag.keys))
	for _, name := range value.dag.keys {
		record := value.records[name]
		detail := record.detail
		if record.status == OperationPruned {
			for _, dependency := range value.dag.nodes[name].dependencies {
				if value.records[dependency].status != OperationSatisfied {
					detail = "dependency " + dependency + " did not converge"
					break
				}
			}
		}
		results = append(results, Result{Key: value.dag.nodes[name].key, Status: record.status, Detail: detail})
	}
	return results
}

func validateDetail(outcome Outcome, detail string) error {
	valid := utf8.ValidString(detail) && len(detail) <= maxDetailBytes && strings.TrimSpace(detail) == detail && !strings.ContainsAny(detail, "\r\n")
	switch outcome {
	case Satisfied:
		if detail != "" {
			return fmt.Errorf("satisfied outcome forbids detail")
		}
	case Blocked, Failed, Stale:
		if detail == "" || !valid {
			return fmt.Errorf("outcome requires valid detail")
		}
	default:
		return fmt.Errorf("invalid operation outcome")
	}
	return nil
}

type Run struct {
	dag        *dagState
	digest     PlanDigest
	reducer    *reducer
	generation uint32
	committed  bool
	lastHash   [sha256.Size]byte
}

type Candidate struct {
	run        *Run
	base       uint32
	generation uint32
	key        Key
	outcome    Outcome
	detail     string
	frame      []byte
	hash       [sha256.Size]byte
	initial    bool
}

type Checkpoint struct {
	run        *Run
	generation uint32
	status     Status
}

func Begin(dag DAG, digest PlanDigest) (*Run, Candidate, error) {
	if dag.state == nil || digest.value == "" {
		return nil, Candidate{}, fmt.Errorf("DAG and Plan digest are required")
	}
	run := &Run{dag: dag.state, digest: digest, reducer: newReducer(dag.state)}
	encoded, hash, _ := initialFrame(digest)
	return run, Candidate{run: run, generation: 0, frame: encoded, hash: hash, initial: true}, nil
}

func InitialFrame(digest PlanDigest) ([]byte, error) {
	encoded, _, err := initialFrame(digest)
	return encoded, err
}

func initialFrame(digest PlanDigest) ([]byte, [sha256.Size]byte, error) {
	if digest.value == "" {
		return nil, [sha256.Size]byte{}, fmt.Errorf("Plan digest is required")
	}
	payload, _ := json.Marshal(initialPayload{Schema: journalSchema, PlanDigest: digest.value, Generation: 0})
	encoded, hash := frame(payload)
	return encoded, hash, nil
}

func (candidate Candidate) Frame() []byte      { return append([]byte(nil), candidate.frame...) }
func (candidate Candidate) Generation() uint32 { return candidate.generation }

func (run *Run) Commit(candidate Candidate) (Checkpoint, error) {
	if run == nil || candidate.run != run {
		return Checkpoint{}, fmt.Errorf("candidate belongs to another run")
	}
	if run.committed && candidate.generation == run.generation && candidate.hash == run.lastHash {
		return Checkpoint{run: run, generation: run.generation, status: run.reducer.status()}, nil
	}
	if !run.committed {
		if !candidate.initial || candidate.generation != 0 {
			return Checkpoint{}, fmt.Errorf("generation zero is required")
		}
		run.committed = true
	} else {
		if candidate.initial || candidate.base != run.generation || candidate.generation != run.generation+1 {
			return Checkpoint{}, fmt.Errorf("candidate generation is out of order")
		}
		if err := run.reducer.apply(candidate.key, candidate.outcome, candidate.detail); err != nil {
			return Checkpoint{}, err
		}
	}
	run.generation = candidate.generation
	run.lastHash = candidate.hash
	return Checkpoint{run: run, generation: run.generation, status: run.reducer.status()}, nil
}

func (checkpoint Checkpoint) current() bool {
	return checkpoint.run != nil && checkpoint.run.committed && checkpoint.generation == checkpoint.run.generation
}
func (checkpoint Checkpoint) Next() (Key, bool) {
	if !checkpoint.current() {
		return Key{}, false
	}
	return checkpoint.run.reducer.offer()
}
func (checkpoint Checkpoint) Generation() uint32 { return checkpoint.generation }
func (checkpoint Checkpoint) Status() Status     { return checkpoint.status }
func (checkpoint Checkpoint) Results() []Result {
	if !checkpoint.current() {
		return nil
	}
	return checkpoint.run.reducer.results()
}

func (checkpoint Checkpoint) Record(key Key, outcome Outcome, detail string) (Candidate, error) {
	if !checkpoint.current() {
		return Candidate{}, fmt.Errorf("checkpoint is not current")
	}
	if err := validateDetail(outcome, detail); err != nil {
		return Candidate{}, err
	}
	offered, ok := checkpoint.run.reducer.offer()
	if !ok || offered != key {
		return Candidate{}, fmt.Errorf("outcome does not match offered operation")
	}
	generation := checkpoint.generation + 1
	payload, _ := json.Marshal(deltaPayload{Generation: generation, Key: key.value, Outcome: outcome.String(), Detail: detail})
	framed, hash := frame(payload)
	return Candidate{run: checkpoint.run, base: checkpoint.generation, generation: generation, key: key, outcome: outcome, detail: detail, frame: framed, hash: hash}, nil
}

func (checkpoint Checkpoint) Receipt() ([]byte, error) {
	if !checkpoint.current() || checkpoint.run.reducer.status() == Running {
		return nil, fmt.Errorf("terminal checkpoint is required")
	}
	operations := encodeResults(checkpoint.run.reducer.results())
	return json.Marshal(receiptPayload{Schema: journalSchema, PlanDigest: checkpoint.run.digest.value, Status: checkpoint.run.reducer.status().String(), Operations: operations})
}

type initialPayload struct {
	Schema     int    `json:"schema"`
	PlanDigest string `json:"plan_digest"`
	Generation uint32 `json:"generation"`
}
type deltaPayload struct {
	Generation uint32 `json:"generation"`
	Key        string `json:"key"`
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail,omitempty"`
}
type encodedResult struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type receiptPayload struct {
	Schema     int             `json:"schema"`
	PlanDigest string          `json:"plan_digest"`
	Status     string          `json:"status"`
	Operations []encodedResult `json:"operations"`
}

// NoopReceipt returns the canonical terminal receipt for an admitted Plan with
// no executable operations. Such a Plan has no DAG or required journal.
func NoopReceipt(digest PlanDigest) ([]byte, error) {
	if digest.value == "" {
		return nil, fmt.Errorf("Plan digest is required")
	}
	return json.Marshal(receiptPayload{
		Schema: journalSchema, PlanDigest: digest.value, Status: Converged.String(),
		Operations: []encodedResult{},
	})
}

func frame(payload []byte) ([]byte, [sha256.Size]byte) {
	digest := sha256.Sum256(payload)
	result := make([]byte, 4+len(payload)+sha256.Size)
	binary.BigEndian.PutUint32(result[:4], uint32(len(payload)))
	copy(result[4:], payload)
	copy(result[4+len(payload):], digest[:])
	return result, digest
}

func encodeResults(results []Result) []encodedResult {
	encoded := make([]encodedResult, len(results))
	for index, result := range results {
		encoded[index] = encodedResult{Key: result.Key.value, Status: result.Status.String(), Detail: result.Detail}
	}
	return encoded
}

type JournalSummary struct {
	digest     PlanDigest
	generation uint32
	status     Status
	results    []Result
}

func (summary JournalSummary) PlanDigest() PlanDigest { return summary.digest }
func (summary JournalSummary) Generation() uint32     { return summary.generation }
func (summary JournalSummary) Status() Status         { return summary.status }
func (summary JournalSummary) Results() []Result      { return append([]Result(nil), summary.results...) }

func InspectJournal(dag DAG, reader io.Reader) (JournalSummary, error) {
	if dag.state == nil || reader == nil {
		return JournalSummary{}, fmt.Errorf("DAG and reader are required")
	}
	remaining := int64(maxJournalBytes)
	payload, raw, err := readFrame(reader, &remaining)
	if err != nil {
		return JournalSummary{}, err
	}
	var initial initialPayload
	if err := decodeCanonical(payload, &initial); err != nil || initial.Schema != journalSchema || initial.Generation != 0 {
		return JournalSummary{}, fmt.Errorf("invalid generation zero")
	}
	digest, err := ParsePlanDigest(initial.PlanDigest)
	if err != nil {
		return JournalSummary{}, err
	}
	run, candidate, _ := Begin(dag, digest)
	if !bytes.Equal(raw, candidate.frame) {
		return JournalSummary{}, fmt.Errorf("noncanonical generation zero")
	}
	checkpoint, _ := run.Commit(candidate)
	for {
		payload, raw, err = readFrame(reader, &remaining)
		if err == io.EOF {
			break
		}
		if err != nil {
			return JournalSummary{}, err
		}
		var delta deltaPayload
		if err := decodeCanonical(payload, &delta); err != nil {
			return JournalSummary{}, err
		}
		outcome, ok := parseOutcome(delta.Outcome)
		if !ok {
			return JournalSummary{}, fmt.Errorf("invalid journal outcome")
		}
		key, err := NewKey(delta.Key)
		if err != nil {
			return JournalSummary{}, err
		}
		candidate, err = checkpoint.Record(key, outcome, delta.Detail)
		if err != nil || delta.Generation != candidate.generation || !bytes.Equal(raw, candidate.frame) {
			return JournalSummary{}, fmt.Errorf("invalid journal transition")
		}
		checkpoint, err = run.Commit(candidate)
		if err != nil {
			return JournalSummary{}, err
		}
	}
	return JournalSummary{digest: digest, generation: checkpoint.generation, status: run.reducer.status(), results: run.reducer.results()}, nil
}

func readFrame(reader io.Reader, remaining *int64) ([]byte, []byte, error) {
	var prefix [4]byte
	n, err := io.ReadFull(reader, prefix[:])
	if err == io.EOF && n == 0 {
		return nil, nil, io.EOF
	}
	if err != nil {
		return nil, nil, fmt.Errorf("truncated journal frame")
	}
	length := int64(binary.BigEndian.Uint32(prefix[:]))
	if length == 0 || length+4+sha256.Size > *remaining {
		return nil, nil, fmt.Errorf("journal byte limit exceeded")
	}
	payload := make([]byte, length)
	var encodedHash [sha256.Size]byte
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, nil, fmt.Errorf("truncated journal payload")
	}
	if _, err := io.ReadFull(reader, encodedHash[:]); err != nil {
		return nil, nil, fmt.Errorf("truncated journal digest")
	}
	actual := sha256.Sum256(payload)
	if actual != encodedHash {
		return nil, nil, fmt.Errorf("journal frame digest mismatch")
	}
	*remaining -= length + 4 + sha256.Size
	raw := make([]byte, 4+len(payload)+sha256.Size)
	copy(raw, prefix[:])
	copy(raw[4:], payload)
	copy(raw[4+len(payload):], encodedHash[:])
	return payload, raw, nil
}

func decodeCanonical(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, payload) {
		return fmt.Errorf("noncanonical JSON")
	}
	return nil
}

func parseOutcome(value string) (Outcome, bool) {
	switch value {
	case "satisfied":
		return Satisfied, true
	case "blocked":
		return Blocked, true
	case "failed":
		return Failed, true
	case "stale":
		return Stale, true
	default:
		return 0, false
	}
}
