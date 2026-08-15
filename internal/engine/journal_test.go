package engine_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/engine"
)

const planDigestText = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func digest(t testing.TB) engine.PlanDigest {
	t.Helper()
	value, err := engine.ParsePlanDigest(planDigestText)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func journalDAG(t testing.TB) engine.DAG {
	t.Helper()
	a, b, c := key(t, "a"), key(t, "b"), key(t, "c")
	dag, err := engine.Admit([]engine.Declaration{{Key: c}, {Key: b, Dependencies: []engine.Key{a}}, {Key: a}})
	if err != nil {
		t.Fatal(err)
	}
	return dag
}

func TestJournalCandidateCommitAndReceipt(t *testing.T) {
	dag := journalDAG(t)
	run, initial, err := engine.Begin(dag, digest(t))
	if err != nil {
		t.Fatal(err)
	}
	if initial.Generation() != 0 || len(initial.Frame()) == 0 {
		t.Fatalf("initial = generation %d frame=%d", initial.Generation(), len(initial.Frame()))
	}
	checkpoint, err := run.Commit(initial)
	if err != nil {
		t.Fatal(err)
	}
	offer, ok := checkpoint.Next()
	if !ok || offer.String() != "a" {
		t.Fatalf("offer = %q, %v", offer, ok)
	}

	candidate, err := checkpoint.Record(offer, engine.Failed, "verification failed")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Generation() != 1 {
		t.Fatalf("candidate generation = %d", candidate.Generation())
	}
	// A candidate cannot offer work; only the committed value can.
	next, err := run.Commit(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if offer, ok := next.Next(); !ok || offer.String() != "c" {
		t.Fatalf("independent offer = %q, %v", offer, ok)
	}
	if again, err := run.Commit(candidate); err != nil || again.Generation() != next.Generation() || again.Status() != next.Status() {
		t.Fatal("Commit is not idempotent")
	}

	offer, _ = next.Next()
	finalCandidate, err := next.Record(offer, engine.Satisfied, "")
	if err != nil {
		t.Fatal(err)
	}
	final, err := run.Commit(finalCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status() != engine.Partial {
		t.Fatalf("status = %s", final.Status())
	}
	receipt, err := final.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"plan_digest":"` + planDigestText + `","status":"partial","operations":[{"key":"a","status":"failed","detail":"verification failed"},{"key":"b","status":"pruned","detail":"dependency a did not converge"},{"key":"c","status":"satisfied"}]}`
	if string(receipt) != want {
		t.Fatalf("receipt = %s\nwant = %s", receipt, want)
	}
}

func TestJournalInspectionUsesDAGReduction(t *testing.T) {
	dag := journalDAG(t)
	run, initial, _ := engine.Begin(dag, digest(t))
	checkpoint, _ := run.Commit(initial)
	first, _ := checkpoint.Next()
	candidate, err := checkpoint.Record(first, engine.Failed, "verification failed")
	if err != nil {
		t.Fatal(err)
	}
	log := append(initial.Frame(), candidate.Frame()...)
	summary, err := engine.InspectJournal(dag, bytes.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if summary.PlanDigest() != digest(t) || summary.Generation() != 1 || summary.Status() != engine.Running {
		t.Fatalf("summary = digest %s generation %d status %s", summary.PlanDigest(), summary.Generation(), summary.Status())
	}
	if got := summary.Results(); len(got) != 3 || got[1].Status != engine.OperationPruned {
		t.Fatalf("results = %#v", got)
	}

	corrupt := append([]byte(nil), log...)
	corrupt[len(corrupt)-1] ^= 1
	if summary, err := engine.InspectJournal(dag, bytes.NewReader(corrupt)); err == nil || !zeroSummary(summary) {
		t.Fatalf("corrupt inspection = %#v, %v", summary, err)
	}
	if summary, err := engine.InspectJournal(dag, bytes.NewReader(log[:len(log)-1])); err == nil || !zeroSummary(summary) {
		t.Fatalf("truncated inspection = %#v, %v", summary, err)
	}
}

func TestJournalRejectsInvalidDigestDetailAndReceiptState(t *testing.T) {
	for _, value := range []string{"", "sha256:ABC", "sha512:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("0", 63)} {
		if digest, err := engine.ParsePlanDigest(value); err == nil || digest != (engine.PlanDigest{}) {
			t.Fatalf("ParsePlanDigest(%q) = %#v, %v", value, digest, err)
		}
	}
	dag := journalDAG(t)
	run, initial, _ := engine.Begin(dag, digest(t))
	checkpoint, _ := run.Commit(initial)
	if receipt, err := checkpoint.Receipt(); err == nil || receipt != nil {
		t.Fatalf("running receipt = %q, %v", receipt, err)
	}
	offer, _ := checkpoint.Next()
	for _, test := range []struct {
		outcome engine.Outcome
		detail  string
	}{
		{engine.Satisfied, "unneeded"}, {engine.Failed, ""}, {engine.Blocked, " x\ny "}, {engine.Stale, strings.Repeat("x", 1025)},
	} {
		if candidate, err := checkpoint.Record(offer, test.outcome, test.detail); err == nil || len(candidate.Frame()) != 0 {
			t.Fatalf("invalid detail admitted: %#v, %v", candidate, err)
		}
	}
}

func TestJournalRejectsNoncanonicalFrame(t *testing.T) {
	dag := journalDAG(t)
	payload := []byte(`{ "schema": 1, "plan_digest": "` + planDigestText + `", "generation": 0 }`)
	frame := make([]byte, 4+len(payload)+32)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	// A valid hash with noncanonical JSON must still fail.
	sum := sha256.Sum256(payload)
	copy(frame[4+len(payload):], sum[:])
	if summary, err := engine.InspectJournal(dag, bytes.NewReader(frame)); err == nil || !zeroSummary(summary) {
		t.Fatalf("noncanonical inspection = %#v, %v", summary, err)
	}
}

func TestJournalStaleStopsAndReceiptsPendingWork(t *testing.T) {
	dag := journalDAG(t)
	run, initial, _ := engine.Begin(dag, digest(t))
	checkpoint, _ := run.Commit(initial)
	offer, _ := checkpoint.Next()
	candidate, err := checkpoint.Record(offer, engine.Stale, "host changed")
	if err != nil {
		t.Fatal(err)
	}
	final, err := run.Commit(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status() != engine.StaleStatus {
		t.Fatalf("status = %s", final.Status())
	}
	if _, ok := final.Next(); ok {
		t.Fatal("stale checkpoint offered work")
	}
	receipt, err := final.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"plan_digest":"` + planDigestText + `","status":"stale","operations":[{"key":"a","status":"stale","detail":"host changed"},{"key":"b","status":"pending"},{"key":"c","status":"pending"}]}`
	if string(receipt) != want {
		t.Fatalf("receipt = %s\nwant = %s", receipt, want)
	}
}

func TestJournalRejectsStaleForeignAndOldValues(t *testing.T) {
	dag := journalDAG(t)
	run, initial, _ := engine.Begin(dag, digest(t))
	checkpoint, _ := run.Commit(initial)
	offer, _ := checkpoint.Next()
	candidate, _ := checkpoint.Record(offer, engine.Satisfied, "")
	next, err := run.Commit(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpoint.Record(offer, engine.Satisfied, ""); err == nil {
		t.Fatal("stale checkpoint recorded an outcome")
	}
	if _, ok := checkpoint.Next(); ok {
		t.Fatal("stale checkpoint offered work")
	}

	other, foreign, _ := engine.Begin(dag, digest(t))
	if _, err := run.Commit(foreign); err == nil {
		t.Fatal("foreign candidate committed")
	}
	if _, err := other.Commit(candidate); err == nil {
		t.Fatal("candidate committed to foreign run")
	}
	if again, err := run.Commit(candidate); err != nil || again.Generation() != next.Generation() {
		t.Fatalf("current recommit = generation %d, %v", again.Generation(), err)
	}
	if _, err := run.Commit(initial); err == nil {
		t.Fatal("old candidate recommitted")
	}
}

func TestJournalRejectsUnknownAndTrailingJSON(t *testing.T) {
	dag := journalDAG(t)
	for _, payload := range [][]byte{
		[]byte(`{"schema":1,"plan_digest":"` + planDigestText + `","generation":0,"extra":true}`),
		[]byte(`{"schema":1,"plan_digest":"` + planDigestText + `","generation":0} {}`),
	} {
		framed := testFrame(payload)
		if summary, err := engine.InspectJournal(dag, bytes.NewReader(framed)); err == nil || !zeroSummary(summary) {
			t.Fatalf("invalid JSON inspection = %#v, %v", summary, err)
		}
	}
}

func testFrame(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	framed := make([]byte, 4+len(payload)+sha256.Size)
	binary.BigEndian.PutUint32(framed[:4], uint32(len(payload)))
	copy(framed[4:], payload)
	copy(framed[4+len(payload):], sum[:])
	return framed
}

func zeroSummary(summary engine.JournalSummary) bool {
	return summary.PlanDigest() == (engine.PlanDigest{}) && summary.Generation() == 0 &&
		summary.Status() == engine.Running && summary.Results() == nil
}

func FuzzJournal(f *testing.F) {
	dag := journalDAG(f)
	run, initial, err := engine.Begin(dag, digest(f))
	if err != nil {
		f.Fatal(err)
	}
	checkpoint, err := run.Commit(initial)
	if err != nil {
		f.Fatal(err)
	}
	offer, _ := checkpoint.Next()
	delta, err := checkpoint.Record(offer, engine.Satisfied, "")
	if err != nil {
		f.Fatal(err)
	}
	valid := append(initial.Frame(), delta.Frame()...)
	f.Add([]byte{})
	f.Add(initial.Frame())
	f.Add(valid)
	f.Fuzz(func(t *testing.T, journal []byte) {
		summary, err := engine.InspectJournal(dag, bytes.NewReader(journal))
		if err != nil {
			if !zeroSummary(summary) {
				t.Fatalf("failure returned nonzero summary: %#v", summary)
			}
			return
		}
		if summary.PlanDigest() != digest(t) || len(summary.Results()) != 3 {
			t.Fatalf("invalid accepted summary: %#v", summary)
		}
	})
}

func TestJournalFramesAreCompactDeltas(t *testing.T) {
	dag := journalDAG(t)
	run, initial, _ := engine.Begin(dag, digest(t))
	checkpoint, _ := run.Commit(initial)
	offer, _ := checkpoint.Next()
	candidate, _ := checkpoint.Record(offer, engine.Satisfied, "")
	payloadLength := int(binary.BigEndian.Uint32(candidate.Frame()[:4]))
	var decoded map[string]any
	if err := json.Unmarshal(candidate.Frame()[4:4+payloadLength], &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 || decoded["generation"] != float64(1) || decoded["key"] != "a" || decoded["outcome"] != "satisfied" {
		t.Fatalf("delta payload = %#v", decoded)
	}
}

func TestNoopReceiptUsesTheCanonicalTerminalProjection(t *testing.T) {
	planDigest := digest(t)
	receipt, err := engine.NoopReceipt(planDigest)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"plan_digest":"` + planDigest.String() + `","status":"converged","operations":[]}`
	if string(receipt) != want {
		t.Fatalf("NoopReceipt = %s, want %s", receipt, want)
	}
	if frame, err := engine.InitialFrame(engine.PlanDigest{}); err == nil || frame != nil {
		t.Fatalf("InitialFrame zero digest = %x, %v", frame, err)
	}
}
