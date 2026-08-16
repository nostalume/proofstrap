package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/pack"
)

const (
	admissionTimeout   = 10 * time.Second
	ordinaryTimeout    = 10 * time.Second
	commandTimeout     = 60 * time.Second
	packageTimeout     = 30 * time.Minute
	packagePostTimeout = 2 * time.Minute
	maxOutcomeDetail   = 1024
)

var ErrInvalidRequest = errors.New("invalid Apply request")

type ApplyRequest struct {
	PlanPath     string
	Accept       pack.Digest
	JournalPath  string
	ReceiptPath  string
	EffectiveUID uint32
	Output       io.Writer
}

type ApplyResult struct {
	Status  engine.Status
	Receipt []byte
}

type postContext func() (context.Context, context.CancelFunc)
type operationEffect func(context.Context, postContext) (bool, error)

type preparedOperation struct {
	barrier     *barrierReview
	admit       func(context.Context) (operationEffect, error)
	effectLimit time.Duration
	postLimit   time.Duration
}

type journalWriter interface {
	Append([]byte) error
	Close() error
}

type applyRuntime struct {
	euid             func() (uint32, error)
	prepare          func(operation) (preparedOperation, error)
	preflightOutputs func(string, string) error
	openJournal      func(string) (journalWriter, error)
	publishReceipt   func(string, []byte) error
}

func productionApplyRuntime() applyRuntime {
	return applyRuntime{
		euid:             func() (uint32, error) { return uint32(os.Geteuid()), nil },
		prepare:          prepareOperation,
		preflightOutputs: preflightOutputs,
		openJournal:      openJournal,
		publishReceipt:   publishReceipt,
	}
}

func Apply(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	return applyWithRuntime(ctx, request, productionApplyRuntime())
}

func applyWithRuntime(ctx context.Context, request ApplyRequest, runtime applyRuntime) (ApplyResult, error) {
	if ctx != nil && ctx.Err() != nil {
		return ApplyResult{}, ctx.Err()
	}
	if ctx == nil || request.Output == nil || request.Accept == (pack.Digest{}) ||
		runtime.euid == nil || runtime.prepare == nil || runtime.preflightOutputs == nil || runtime.openJournal == nil || runtime.publishReceipt == nil {
		return ApplyResult{}, fmt.Errorf("%w: active context, acceptance digest, output, and complete runtime are required", ErrInvalidRequest)
	}
	data, err := readPlanFile(request.PlanPath)
	if err != nil {
		return ApplyResult{}, err
	}
	plan, err := DecodePlan(data)
	if err != nil {
		return ApplyResult{}, err
	}
	if plan.digest != request.Accept {
		return ApplyResult{}, fmt.Errorf("accepted digest does not match Plan")
	}
	var envelope planEnvelope
	if err := strictJSON(plan.bytes, &envelope); err != nil {
		return ApplyResult{}, err
	}
	if len(envelope.Plan.Blockers) != 0 {
		return ApplyResult{}, fmt.Errorf("blocked Plan cannot Apply")
	}
	prepared, dag, err := prepareOperations(envelope.Plan.Operations, runtime.prepare)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	actualUID, err := runtime.euid()
	if err != nil {
		return ApplyResult{}, fmt.Errorf("inspect current principal: %w", err)
	}
	if actualUID != request.EffectiveUID {
		return ApplyResult{}, fmt.Errorf("current principal changed")
	}
	if len(prepared) != 0 && actualUID != 0 {
		return ApplyResult{}, fmt.Errorf("mutating Plan requires effective UID 0")
	}
	if request.JournalPath != "" && request.JournalPath == request.ReceiptPath || request.PlanPath == request.JournalPath || request.PlanPath == request.ReceiptPath {
		return ApplyResult{}, fmt.Errorf("%w: Plan, journal, and receipt paths must be distinct", ErrInvalidRequest)
	}
	if len(prepared) != 0 && request.JournalPath == "" {
		return ApplyResult{}, fmt.Errorf("%w: journal path is required for a mutating Plan", ErrInvalidRequest)
	}
	if err := runtime.preflightOutputs(request.JournalPath, request.ReceiptPath); err != nil {
		return ApplyResult{}, err
	}
	digest, err := engine.ParsePlanDigest(plan.digest.String())
	if err != nil {
		return ApplyResult{}, err
	}
	if len(prepared) == 0 {
		if request.JournalPath != "" {
			journal, err := runtime.openJournal(request.JournalPath)
			if err != nil {
				return ApplyResult{}, err
			}
			frame, _ := engine.InitialFrame(digest)
			err = errors.Join(journal.Append(frame), journal.Close())
			if err != nil {
				return ApplyResult{}, err
			}
		}
		receipt, err := engine.NoopReceipt(digest)
		if err != nil {
			return ApplyResult{}, err
		}
		return emitReceipt(request, runtime, engine.Converged, receipt)
	}
	journal, err := runtime.openJournal(request.JournalPath)
	if err != nil {
		return ApplyResult{}, err
	}
	result, runErr := executePrepared(ctx, dag, digest, prepared, journal)
	closeErr := journal.Close()
	if runErr != nil || closeErr != nil {
		return ApplyResult{}, errors.Join(runErr, closeErr)
	}
	return emitReceipt(request, runtime, result.Status, result.Receipt)
}

func prepareOperations(items []wireOperation, prepare func(operation) (preparedOperation, error)) (map[string]preparedOperation, engine.DAG, error) {
	prepared := make(map[string]preparedOperation, len(items))
	if len(items) == 0 {
		return prepared, engine.DAG{}, nil
	}
	declarations := make([]engine.Declaration, len(items))
	for index, item := range items {
		key, err := engine.NewKey(item.ID)
		if err != nil {
			return nil, engine.DAG{}, err
		}
		dependencies := make([]engine.Key, len(item.Dependencies))
		for dependencyIndex, dependency := range item.Dependencies {
			dependencies[dependencyIndex], err = engine.NewKey(dependency)
			if err != nil {
				return nil, engine.DAG{}, err
			}
		}
		declarations[index] = engine.Declaration{Key: key, Dependencies: dependencies}
		if item.Kind == "barrier" {
			review, err := decodeBarrierReview(item.Review)
			if err != nil {
				return nil, engine.DAG{}, err
			}
			prepared[item.ID] = preparedOperation{barrier: &review}
			continue
		}
		value, err := prepare(operation{id: item.ID, kind: item.Kind, dependencies: item.Dependencies, review: item.Review})
		if err != nil || value.admit == nil || value.effectLimit <= 0 || value.postLimit <= 0 {
			if err == nil {
				err = fmt.Errorf("operation %q preparation is incomplete", item.ID)
			}
			return nil, engine.DAG{}, err
		}
		prepared[item.ID] = value
	}
	dag, err := engine.Admit(declarations)
	return prepared, dag, err
}

func executePrepared(ctx context.Context, dag engine.DAG, digest engine.PlanDigest, prepared map[string]preparedOperation, journal journalWriter) (ApplyResult, error) {
	run, initial, err := engine.Begin(dag, digest)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := journal.Append(initial.Frame()); err != nil {
		return ApplyResult{}, err
	}
	checkpoint, err := run.Commit(initial)
	if err != nil {
		return ApplyResult{}, err
	}
	for key, ok := checkpoint.Next(); ok; key, ok = checkpoint.Next() {
		item := prepared[key.String()]
		outcome, detail := engine.Satisfied, ""
		if cancellation := ctx.Err(); cancellation != nil {
			outcome, detail = engine.Stale, boundedDetail(cancellation)
		} else if item.barrier != nil {
			outcome, detail = engine.Blocked, item.barrier.Reason
		} else {
			admitCtx, cancelAdmit := context.WithTimeout(ctx, admissionTimeout)
			effect, admitErr := item.admit(admitCtx)
			cancelAdmit()
			started := false
			var effectErr error
			if admitErr == nil {
				effectCtx, cancelEffect := context.WithTimeout(ctx, item.effectLimit)
				freshPost := func() (context.Context, context.CancelFunc) {
					return context.WithTimeout(context.WithoutCancel(ctx), item.postLimit)
				}
				started, effectErr = effect(effectCtx, freshPost)
				cancelEffect()
			} else {
				effectErr = admitErr
			}
			outcome, detail = classifyOutcome(started, effectErr)
		}
		candidate, err := checkpoint.Record(key, outcome, detail)
		if err != nil {
			return ApplyResult{}, err
		}
		if err := journal.Append(candidate.Frame()); err != nil {
			return ApplyResult{}, err
		}
		checkpoint, err = run.Commit(candidate)
		if err != nil {
			return ApplyResult{}, err
		}
	}
	receipt, err := checkpoint.Receipt()
	return ApplyResult{Status: checkpoint.Status(), Receipt: receipt}, err
}

func classifyOutcome(started bool, err error) (engine.Outcome, string) {
	if err == nil {
		if started {
			return engine.Satisfied, ""
		}
		return engine.Failed, "operation completed without starting its reviewed effect"
	}
	detail := boundedDetail(err)
	if !started && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isStale(err)) {
		return engine.Stale, detail
	}
	return engine.Failed, detail
}

func boundedDetail(err error) string {
	text := strings.Join(strings.Fields(strings.ToValidUTF8(err.Error(), "�")), " ")
	for len(text) > maxOutcomeDetail {
		_, width := utf8.DecodeLastRuneInString(text)
		text = text[:len(text)-width]
	}
	if text == "" {
		return "operation failed"
	}
	return text
}

func emitReceipt(request ApplyRequest, runtime applyRuntime, status engine.Status, receipt []byte) (ApplyResult, error) {
	result := ApplyResult{Status: status, Receipt: append([]byte(nil), receipt...)}
	var publishErr error
	if request.ReceiptPath != "" {
		publishErr = runtime.publishReceipt(request.ReceiptPath, receipt)
	}
	written, outputErr := request.Output.Write(receipt)
	if outputErr == nil && written != len(receipt) {
		outputErr = io.ErrShortWrite
	}
	return result, errors.Join(publishErr, outputErr)
}
