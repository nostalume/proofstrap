package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/host"
	"github.com/nostalume/proofstrap/internal/pack"
)

type recordingJournal struct {
	events *[]string
	frames [][]byte
	failAt int
}

func publishApplyPlan(t *testing.T, plan Plan) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	if _, err := PublishPlan(path, plan); err != nil {
		t.Fatal(err)
	}
	return path
}

func (journal *recordingJournal) Append(frame []byte) error {
	*journal.events = append(*journal.events, "sync")
	journal.frames = append(journal.frames, append([]byte(nil), frame...))
	if journal.failAt != 0 && len(journal.frames) == journal.failAt {
		return os.ErrPermission
	}
	return nil
}

func (journal *recordingJournal) Close() error {
	*journal.events = append(*journal.events, "close")
	return nil
}

func TestApplyNoopNeedsNoJournalAndPublishesIdenticalReceipt(t *testing.T) {
	plan, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	if _, err := PublishPlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "receipt.json")
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := Apply(ctx, ApplyRequest{
		PlanPath: planPath, Accept: plan.Digest(), ReceiptPath: receiptPath,
		EffectiveUID: uint32(os.Geteuid()), Output: &stdout,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Status != engine.Converged || !bytes.Equal(result.Receipt, stdout.Bytes()) {
		t.Fatalf("Apply result = %#v, stdout = %q", result, stdout.Bytes())
	}
	published, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(published, result.Receipt) {
		t.Fatalf("published receipt = %q, %v", published, err)
	}
	if _, err := os.Stat(filepath.Join(root, "journal")); !os.IsNotExist(err) {
		t.Fatalf("unexpected journal state: %v", err)
	}
}

func TestApplyMakesEveryCandidateDurableBeforeCommitAndNextEffect(t *testing.T) {
	plan, err := seal(body{operations: []operation{
		{id: "a", kind: "test", review: []byte(`{"id":"a"}`)},
		{id: "b", kind: "test", review: []byte(`{"id":"b"}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	if _, err := PublishPlan(planPath, plan); err != nil {
		t.Fatal(err)
	}
	var events []string
	journal := &recordingJournal{events: &events}
	runtime := applyRuntime{
		euid:             func() (uint32, error) { return 0, nil },
		preflightOutputs: func(string, string) error { return nil },
		prepare: func(value operation) (preparedOperation, error) {
			id := value.id
			return preparedOperation{
				effectLimit: time.Second, postLimit: time.Second,
				admit: func(context.Context) (operationEffect, error) {
					events = append(events, "admit:"+id)
					return func(context.Context, postContext) (bool, error) {
						events = append(events, "effect:"+id)
						return true, nil
					}, nil
				},
			}, nil
		},
		openJournal:    func(string) (journalWriter, error) { return journal, nil },
		publishReceipt: func(string, []byte) error { return nil },
	}
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := applyWithRuntime(ctx, ApplyRequest{
		PlanPath: planPath, Accept: plan.Digest(), JournalPath: filepath.Join(root, "journal"),
		EffectiveUID: 0, Output: &stdout,
	}, runtime)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []string{"sync", "admit:a", "effect:a", "sync", "admit:b", "effect:b", "sync", "close"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
	if result.Status != engine.Converged || len(journal.frames) != 3 || !bytes.Equal(stdout.Bytes(), result.Receipt) {
		t.Fatalf("result = %#v, frames = %d, stdout = %q", result, len(journal.frames), stdout.Bytes())
	}
}

func TestApplyCreatesPostObservationContextAfterEffectAndIndependentOfCancellation(t *testing.T) {
	plan, err := seal(body{operations: []operation{{id: "a", kind: "test", review: []byte(`{"id":"a"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	journal := &recordingJournal{events: &events}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	runtime := applyRuntime{
		euid:             func() (uint32, error) { return 0, nil },
		preflightOutputs: func(string, string) error { return nil },
		prepare: func(operation) (preparedOperation, error) {
			return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
				return func(_ context.Context, freshPost postContext) (bool, error) {
					cancel()
					post, cancelPost := freshPost()
					defer cancelPost()
					deadline, bounded := post.Deadline()
					if post.Err() != nil || !bounded || time.Until(deadline) <= 0 {
						return true, errors.New("post-observation context was consumed by effect cancellation")
					}
					return true, nil
				}, nil
			}}, nil
		},
		openJournal:    func(string) (journalWriter, error) { return journal, nil },
		publishReceipt: func(string, []byte) error { return nil },
	}
	result, err := applyWithRuntime(ctx, ApplyRequest{
		PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: filepath.Join(t.TempDir(), "journal"),
		EffectiveUID: 0, Output: io.Discard,
	}, runtime)
	if err != nil || result.Status != engine.Converged {
		t.Fatalf("Apply = %#v, %v", result, err)
	}
}

func TestApplyDurabilityFailureStopsWithoutReceiptOrLaterEffect(t *testing.T) {
	plan, err := seal(body{operations: []operation{
		{id: "a", kind: "test", review: []byte(`{"id":"a"}`)},
		{id: "b", kind: "test", review: []byte(`{"id":"b"}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, wantEvents string
		failAt           int
	}{
		{"generation-zero", "sync,close", 1},
		{"first-candidate", "sync,admit:a,effect:a,sync,close", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			journal := &recordingJournal{events: &events, failAt: test.failAt}
			runtime := applyRuntime{
				euid:             func() (uint32, error) { return 0, nil },
				preflightOutputs: func(string, string) error { return nil },
				prepare: func(value operation) (preparedOperation, error) {
					id := value.id
					return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
						events = append(events, "admit:"+id)
						return func(context.Context, postContext) (bool, error) {
							events = append(events, "effect:"+id)
							return true, nil
						}, nil
					}}, nil
				},
				openJournal:    func(string) (journalWriter, error) { return journal, nil },
				publishReceipt: func(string, []byte) error { return nil },
			}
			var stdout bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := applyWithRuntime(ctx, ApplyRequest{
				PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: filepath.Join(t.TempDir(), "journal"),
				EffectiveUID: 0, Output: &stdout,
			}, runtime)
			if err == nil || result.Status != 0 || len(result.Receipt) != 0 || stdout.Len() != 0 {
				t.Fatalf("Apply = %#v, %v, stdout %q", result, err, stdout.Bytes())
			}
			if got := strings.Join(events, ","); got != test.wantEvents {
				t.Fatalf("events = %q, want %q", got, test.wantEvents)
			}
		})
	}
}

func TestApplyRecordsReviewedBarrierWithoutHostEffect(t *testing.T) {
	barrier := encodeBarrierReview("service:system:demo.service", "systemd-unit", "create a fresh Plan")
	plan, err := seal(body{operations: []operation{
		{id: "a", kind: "test", review: []byte(`{"id":"a"}`)},
		{id: "b", kind: "barrier", dependencies: []string{"a"}, review: barrier},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	journal := &recordingJournal{events: &events}
	runtime := applyRuntime{
		euid:             func() (uint32, error) { return 0, nil },
		preflightOutputs: func(string, string) error { return nil },
		prepare: func(operation) (preparedOperation, error) {
			return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
				return func(context.Context, postContext) (bool, error) {
					events = append(events, "effect")
					return true, nil
				}, nil
			}}, nil
		},
		openJournal:    func(string) (journalWriter, error) { return journal, nil },
		publishReceipt: func(string, []byte) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	result, err := applyWithRuntime(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: filepath.Join(t.TempDir(), "journal"), EffectiveUID: 0, Output: &stdout}, runtime)
	if err != nil || result.Status != engine.Partial || strings.Count(strings.Join(events, ","), "effect") != 1 || !bytes.Contains(result.Receipt, []byte(`"detail":"create a fresh Plan"`)) {
		t.Fatalf("Apply = %#v, %v, events %v", result, err, events)
	}
}

func TestApplyRejectsUnknownOperationBeforeCreatingJournal(t *testing.T) {
	plan, err := seal(body{operations: []operation{{id: "unknown", kind: "unknown", review: []byte(`{"value":1}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "journal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Apply(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: journalPath, EffectiveUID: uint32(os.Geteuid()), Output: io.Discard}); err == nil || !strings.Contains(err.Error(), "unknown operation kind") {
		t.Fatalf("Apply unknown operation = %v", err)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("journal exists after rejected operation: %v", err)
	}
}

func TestApplyPreflightsEveryOutputParentBeforeJournalOrEffect(t *testing.T) {
	plan, err := seal(body{operations: []operation{{id: "a", kind: "test", review: []byte(`{"id":"a"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	runtime := applyRuntime{
		euid: func() (uint32, error) { return 0, nil },
		prepare: func(operation) (preparedOperation, error) {
			return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
				events = append(events, "admit")
				return nil, nil
			}}, nil
		},
		preflightOutputs: func(string, string) error { events = append(events, "preflight"); return os.ErrPermission },
		openJournal:      func(string) (journalWriter, error) { events = append(events, "open"); return nil, nil },
		publishReceipt:   func(string, []byte) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = applyWithRuntime(ctx, ApplyRequest{
		PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: filepath.Join(t.TempDir(), "journal"),
		ReceiptPath: filepath.Join(t.TempDir(), "receipt"), EffectiveUID: 0, Output: io.Discard,
	}, runtime)
	if !errors.Is(err, os.ErrPermission) || strings.Join(events, ",") != "preflight" {
		t.Fatalf("Apply preflight = %v, events %v", err, events)
	}
}

func TestApplyNoopJournalIsExactPrivateGenerationZeroAndNoReplace(t *testing.T) {
	plan, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	journalPath := filepath.Join(root, "journal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	result, err := Apply(ctx, ApplyRequest{
		PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: journalPath,
		EffectiveUID: uint32(os.Geteuid()), Output: &stdout,
	})
	if err != nil || result.Status != engine.Converged {
		t.Fatalf("Apply = %#v, %v", result, err)
	}
	digest, _ := engine.ParsePlanDigest(plan.Digest().String())
	want, _ := engine.InitialFrame(digest)
	got, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("journal = %x, %v; want %x", got, err, want)
	}
	info, err := os.Stat(journalPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v, %v", info, err)
	}
	if _, err := Apply(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: journalPath, EffectiveUID: uint32(os.Geteuid()), Output: io.Discard}); err == nil {
		t.Fatal("existing journal was replaced")
	}
	after, _ := os.ReadFile(journalPath)
	if !bytes.Equal(after, want) {
		t.Fatal("existing journal changed")
	}
}

func TestApplyReceiptCollisionStillEmitsTruthfulTerminalBytes(t *testing.T) {
	plan, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt")
	if err := os.WriteFile(receiptPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	result, err := Apply(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), ReceiptPath: receiptPath, EffectiveUID: uint32(os.Geteuid()), Output: &stdout})
	if err == nil || result.Status != engine.Converged || !bytes.Equal(result.Receipt, stdout.Bytes()) {
		t.Fatalf("Apply = %#v, %v, stdout %q", result, err, stdout.Bytes())
	}
	if existing, _ := os.ReadFile(receiptPath); string(existing) != "existing" {
		t.Fatalf("existing receipt changed: %q", existing)
	}
}

func TestApplyUnsafeReceiptParentFailsBeforeJournalCreation(t *testing.T) {
	plan, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "journal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = Apply(ctx, ApplyRequest{
		PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: journalPath,
		ReceiptPath: filepath.Join(unsafe, "receipt"), EffectiveUID: uint32(os.Geteuid()), Output: io.Discard,
	})
	if err == nil {
		t.Fatal("unsafe receipt parent was admitted")
	}
	if _, statErr := os.Stat(journalPath); !os.IsNotExist(statErr) {
		t.Fatalf("journal created before output preflight: %v", statErr)
	}
}

func TestApplyOutcomeReductionControlsContinuation(t *testing.T) {
	tests := []struct {
		name         string
		dependencies []string
		firstStarted bool
		firstErr     error
		cancelRoot   bool
		wantStatus   engine.Status
		wantEffects  string
	}{
		{"independent failure continues", nil, false, errors.New("probe failed"), false, engine.Partial, "a,b"},
		{"dependent failure prunes", []string{"a"}, true, errors.New("postcondition failed"), false, engine.FailedStatus, "a"},
		{"stale stops globally", nil, false, host.ErrStale, false, engine.StaleStatus, "a"},
		{"cancellation before start stops globally", nil, false, context.Canceled, false, engine.StaleStatus, "a"},
		{"root cancellation suppresses later effects", nil, true, nil, true, engine.StaleStatus, "a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := seal(body{operations: []operation{
				{id: "a", kind: "test", review: []byte(`{"id":"a"}`)},
				{id: "b", kind: "test", dependencies: test.dependencies, review: []byte(`{"id":"b"}`)},
			}})
			if err != nil {
				t.Fatal(err)
			}
			var effects []string
			journal := &recordingJournal{events: new([]string)}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			runtime := applyRuntime{
				euid:             func() (uint32, error) { return 0, nil },
				preflightOutputs: func(string, string) error { return nil },
				prepare: func(value operation) (preparedOperation, error) {
					id := value.id
					return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
						return func(context.Context, postContext) (bool, error) {
							effects = append(effects, id)
							if id == "a" {
								if test.cancelRoot {
									cancel()
								}
								return test.firstStarted, test.firstErr
							}
							return true, nil
						}, nil
					}}, nil
				},
				openJournal:    func(string) (journalWriter, error) { return journal, nil },
				publishReceipt: func(string, []byte) error { return nil },
			}
			result, err := applyWithRuntime(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: filepath.Join(t.TempDir(), "journal"), EffectiveUID: 0, Output: io.Discard}, runtime)
			if err != nil || result.Status != test.wantStatus || strings.Join(effects, ",") != test.wantEffects {
				t.Fatalf("Apply = %#v, %v, effects %v", result, err, effects)
			}
		})
	}
}

func TestOutcomeDetailIsCanonicalAndBounded(t *testing.T) {
	detail := boundedDetail(errors.New("  bad\n" + strings.Repeat("界", 2000) + "  "))
	if strings.TrimSpace(detail) != detail || strings.ContainsAny(detail, "\r\n\x00") || len(detail) > 4096 || !strings.HasPrefix(detail, "bad") {
		t.Fatalf("bounded detail = %q (%d bytes)", detail, len(detail))
	}
	if outcome, _ := classifyOutcome(false, host.ErrStale); outcome != engine.Stale {
		t.Fatalf("stale outcome = %v", outcome)
	}
	if outcome, _ := classifyOutcome(true, host.ErrStale); outcome != engine.Failed {
		t.Fatalf("started stale outcome = %v", outcome)
	}
}

func TestApplyRejectsMissingJournalAndNonrootBeforeAdmission(t *testing.T) {
	plan, err := seal(body{operations: []operation{{id: "a", kind: "test", review: []byte(`{"id":"a"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		uid     uint32
		journal string
		want    string
	}{
		{"missing journal", 0, "", "journal path is required"},
		{"nonroot", 1000, filepath.Join(t.TempDir(), "journal"), "effective UID 0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var effects int
			runtime := applyRuntime{
				euid: func() (uint32, error) { return test.uid, nil },
				prepare: func(operation) (preparedOperation, error) {
					return preparedOperation{effectLimit: time.Second, postLimit: time.Second, admit: func(context.Context) (operationEffect, error) {
						effects++
						return nil, nil
					}}, nil
				},
				preflightOutputs: func(string, string) error { effects++; return nil },
				openJournal:      func(string) (journalWriter, error) { effects++; return nil, nil },
				publishReceipt:   func(string, []byte) error { return nil },
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := applyWithRuntime(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, plan), Accept: plan.Digest(), JournalPath: test.journal, EffectiveUID: test.uid, Output: io.Discard}, runtime)
			if err == nil || !strings.Contains(err.Error(), test.want) || effects != 0 {
				t.Fatalf("Apply = %v, effects %d", err, effects)
			}
		})
	}
}

func TestApplyRejectsAcceptanceAndBlockedPlanBeforeOutputs(t *testing.T) {
	blocked, err := seal(body{blockers: []blocker{{kind: "unsupported", resource: "package:x", detail: "unavailable"}}})
	if err != nil {
		t.Fatal(err)
	}
	exact, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, test := range []struct {
		name   string
		plan   Plan
		accept pack.Digest
	}{
		{"accept mismatch", exact, blocked.Digest()},
		{"blocked", blocked, blocked.Digest()},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "journal")
			if _, err := Apply(ctx, ApplyRequest{PlanPath: publishApplyPlan(t, test.plan), Accept: test.accept, JournalPath: journal, EffectiveUID: uint32(os.Geteuid()), Output: io.Discard}); err == nil {
				t.Fatal("invalid Apply was admitted")
			}
			if _, err := os.Stat(journal); !os.IsNotExist(err) {
				t.Fatalf("journal created: %v", err)
			}
		})
	}
}

func TestApplyReturnsCancellationBeforeReadingPlan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	result, err := Apply(ctx, ApplyRequest{PlanPath: "/missing", Accept: digest, EffectiveUID: uint32(os.Geteuid()), Output: io.Discard})
	if !errors.Is(err, context.Canceled) || len(result.Receipt) != 0 {
		t.Fatalf("Apply = %#v, %v", result, err)
	}
}
