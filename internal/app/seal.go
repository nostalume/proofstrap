package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/pack"
)

const maxPlanBytes = 64 << 20

var ErrInvalidPlan = errors.New("invalid Plan artifact")

type operation struct {
	id           string
	kind         string
	dependencies []string
	review       []byte
}

type blocker struct {
	kind, resource, detail string
}

type barrierReview struct {
	Resource   string `json:"resource"`
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

type body struct {
	operations []operation
	blockers   []blocker
}

type Plan struct {
	bytes      []byte
	seal       []byte
	digest     pack.Digest
	operations int
	blockers   int
}

func (plan Plan) Bytes() []byte       { return append([]byte(nil), plan.bytes...) }
func (plan Plan) Digest() pack.Digest { return plan.digest }
func (plan Plan) Checkpoints() int    { return 1 + plan.operations }
func (plan Plan) Blocked() bool       { return plan.blockers != 0 }
func (plan Plan) sealBytes() []byte   { return append([]byte(nil), plan.seal...) }

type wireOperation struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Dependencies []string        `json:"dependencies"`
	Review       json.RawMessage `json:"review,omitempty"`
}

type wireBlocker struct {
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
}

type wireBody struct {
	Operations []wireOperation `json:"operations"`
	Blockers   []wireBlocker   `json:"blockers"`
}

type sealEnvelope struct {
	Schema int      `json:"schema"`
	Plan   wireBody `json:"plan"`
}

type planEnvelope struct {
	Schema int      `json:"schema"`
	Digest string   `json:"digest"`
	Plan   wireBody `json:"plan"`
}

func seal(value body) (Plan, error) {
	wire, err := canonicalBody(value)
	if err != nil {
		return Plan{}, err
	}
	sealBytes, err := json.Marshal(sealEnvelope{Schema: 1, Plan: wire})
	if err != nil {
		return Plan{}, err
	}
	sum := sha256.Sum256(sealBytes)
	digestText := "sha256:" + hex.EncodeToString(sum[:])
	digest, err := pack.ParseDigest(digestText)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := json.Marshal(planEnvelope{Schema: 1, Digest: digestText, Plan: wire})
	if err != nil {
		return Plan{}, err
	}
	if len(encoded) > maxPlanBytes {
		return Plan{}, fmt.Errorf("plan exceeds 64 MiB")
	}
	return Plan{bytes: encoded, seal: sealBytes, digest: digest, operations: len(wire.Operations), blockers: len(wire.Blockers)}, nil
}

func canonicalBody(value body) (wireBody, error) {
	if len(value.blockers) > 0 && len(value.operations) > 0 {
		return wireBody{}, fmt.Errorf("globally blocked plan cannot contain applicable operations")
	}
	operations := append([]operation(nil), value.operations...)
	sort.Slice(operations, func(i, j int) bool { return operations[i].id < operations[j].id })
	wireOperations := make([]wireOperation, len(operations))
	declarations := make([]engine.Declaration, len(operations))
	for index, item := range operations {
		if item.id == "" || item.kind == "" || !validText(item.id) || !validText(item.kind) {
			return wireBody{}, fmt.Errorf("operation identity and kind are required")
		}
		if index > 0 && item.id == operations[index-1].id {
			return wireBody{}, fmt.Errorf("duplicate operation %q", item.id)
		}
		dependencies := append([]string(nil), item.dependencies...)
		sort.Strings(dependencies)
		keys := make([]engine.Key, len(dependencies))
		for dependencyIndex, dependency := range dependencies {
			if dependencyIndex > 0 && dependency == dependencies[dependencyIndex-1] {
				return wireBody{}, fmt.Errorf("operation %q has duplicate dependency %q", item.id, dependency)
			}
			key, err := engine.NewKey(dependency)
			if err != nil {
				return wireBody{}, err
			}
			keys[dependencyIndex] = key
		}
		key, err := engine.NewKey(item.id)
		if err != nil {
			return wireBody{}, err
		}
		if item.kind == "barrier" {
			if len(dependencies) == 0 {
				return wireBody{}, fmt.Errorf("barrier %q requires dependencies", item.id)
			}
			if _, err := decodeBarrierReview(item.review); err != nil {
				return wireBody{}, fmt.Errorf("barrier %q review: %w", item.id, err)
			}
		} else if err := canonicalReview(item.review); err != nil {
			return wireBody{}, fmt.Errorf("operation %q review: %w", item.id, err)
		}
		wireOperations[index] = wireOperation{ID: item.id, Kind: item.kind, Dependencies: dependencies, Review: append(json.RawMessage(nil), item.review...)}
		declarations[index] = engine.Declaration{Key: key, Dependencies: keys}
	}
	if len(declarations) > 0 {
		if _, err := engine.Admit(declarations); err != nil {
			return wireBody{}, err
		}
	}
	uniqueBlockers := make(map[string]blocker, len(value.blockers))
	for _, item := range value.blockers {
		item.detail = strings.Join(strings.Fields(strings.ToValidUTF8(item.detail, "�")), " ")
		uniqueBlockers[item.kind+"\x00"+item.resource+"\x00"+item.detail] = item
	}
	blockers := make([]blocker, 0, len(uniqueBlockers))
	for _, item := range uniqueBlockers {
		blockers = append(blockers, item)
	}
	sort.Slice(blockers, func(i, j int) bool {
		left, right := blockers[i], blockers[j]
		if left.kind != right.kind {
			return left.kind < right.kind
		}
		if left.resource != right.resource {
			return left.resource < right.resource
		}
		return left.detail < right.detail
	})
	wireBlockers := make([]wireBlocker, len(blockers))
	for index, item := range blockers {
		if item.kind == "" || item.resource == "" || item.detail == "" || !validText(item.kind) || !validText(item.resource) || !validText(item.detail) {
			return wireBody{}, fmt.Errorf("complete blocker is required")
		}
		wireBlockers[index] = wireBlocker{Kind: item.kind, Resource: item.resource, Detail: item.detail}
	}
	return wireBody{Operations: wireOperations, Blockers: wireBlockers}, nil
}

func DecodePlan(data []byte) (Plan, error) {
	plan, err := decodePlan(data)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	return plan, nil
}

func decodePlan(data []byte) (Plan, error) {
	if len(data) == 0 || len(data) > maxPlanBytes {
		return Plan{}, fmt.Errorf("plan must contain 1..64 MiB")
	}
	var envelope planEnvelope
	if err := strictJSON(data, &envelope); err != nil {
		return Plan{}, err
	}
	if envelope.Schema != 1 {
		return Plan{}, fmt.Errorf("plan schema must be 1")
	}
	value := body{operations: make([]operation, len(envelope.Plan.Operations)), blockers: make([]blocker, len(envelope.Plan.Blockers))}
	for index, item := range envelope.Plan.Operations {
		value.operations[index] = operation{id: item.ID, kind: item.Kind, dependencies: item.Dependencies, review: item.Review}
	}
	for index, item := range envelope.Plan.Blockers {
		value.blockers[index] = blocker{kind: item.Kind, resource: item.Resource, detail: item.Detail}
	}
	canonical, err := seal(value)
	if err != nil {
		return Plan{}, err
	}
	if envelope.Digest != canonical.digest.String() {
		return Plan{}, fmt.Errorf("plan digest mismatch")
	}
	if !bytes.Equal(data, canonical.bytes) {
		return Plan{}, fmt.Errorf("plan is not canonical")
	}
	return canonical, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("plan has trailing data")
	}
	return nil
}

func canonicalReview(data []byte) error {
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' || !json.Valid(data) {
		return fmt.Errorf("canonical JSON object is required")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil || !bytes.Equal(compact.Bytes(), data) {
		return fmt.Errorf("canonical JSON object is required")
	}
	return nil
}

func decodeBarrierReview(data []byte) (barrierReview, error) {
	var review barrierReview
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&review); err != nil {
		return barrierReview{}, fmt.Errorf("decode reviewed barrier: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return barrierReview{}, fmt.Errorf("reviewed barrier has trailing data")
	}
	if !validText(review.Resource) || review.Resource == "" || !validText(review.Capability) || review.Capability == "" || !validText(review.Reason) || review.Reason == "" {
		return barrierReview{}, fmt.Errorf("complete reviewed barrier is required")
	}
	canonical, err := json.Marshal(review)
	if err != nil || !bytes.Equal(data, canonical) {
		return barrierReview{}, fmt.Errorf("reviewed barrier is not canonical")
	}
	return review, nil
}

func encodeBarrierReview(resource, capability, reason string) []byte {
	encoded, _ := json.Marshal(barrierReview{Resource: resource, Capability: capability, Reason: reason})
	return encoded
}

func validText(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
