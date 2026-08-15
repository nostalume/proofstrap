package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSealIsCanonicalAndIndependentOfInputOrder(t *testing.T) {
	left := body{
		operations: []operation{
			{id: "service:agent:runtime", kind: "service", dependencies: []string{"package:zypper"}, review: []byte(`{"axis":"runtime"}`)},
			{id: "package:zypper", kind: "package", review: []byte(`{"backend":"zypper"}`)},
		},
	}
	right := body{
		operations: []operation{left.operations[1], left.operations[0]},
	}
	first, err := seal(left)
	if err != nil {
		t.Fatal(err)
	}
	second, err := seal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || first.Digest() != second.Digest() {
		t.Fatalf("order changed artifact:\n%s\n%s", first.Bytes(), second.Bytes())
	}
	if first.Checkpoints() != 3 {
		t.Fatalf("checkpoints = %d, want 3", first.Checkpoints())
	}
	decoded, err := DecodePlan(first.Bytes())
	if err != nil || !bytes.Equal(decoded.Bytes(), first.Bytes()) {
		t.Fatalf("DecodePlan = %s, %v", decoded.Bytes(), err)
	}

	var envelope struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(first.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	sealBytes := first.sealBytes()
	sum := sha256.Sum256(sealBytes)
	if envelope.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q for %s", envelope.Digest, sealBytes)
	}
}

func TestDecodePlanRejectsNoncanonicalUnknownAndInvalidGraphs(t *testing.T) {
	valid, err := seal(body{operations: []operation{{id: "one", kind: "host", review: []byte(`{"x":1}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"spacing":  bytes.Replace(valid.Bytes(), []byte(`{"schema"`), []byte("{ \"schema\""), 1),
		"trailing": append(append([]byte(nil), valid.Bytes()...), '\n'),
		"unknown":  bytes.Replace(valid.Bytes(), []byte(`{"schema":1`), []byte(`{"unknown":0,"schema":1`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePlan(data); err == nil {
				t.Fatalf("%s plan admitted", name)
			}
		})
	}
	if _, err := seal(body{operations: []operation{{id: "one", kind: "host", dependencies: []string{"missing"}, review: []byte(`{"x":1}`)}}}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing dependency = %v", err)
	}
	if _, err := seal(body{operations: []operation{
		{id: "one", kind: "host", dependencies: []string{"two"}, review: []byte(`{"x":1}`)},
		{id: "two", kind: "host", dependencies: []string{"one"}, review: []byte(`{"x":2}`)},
	}}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle = %v", err)
	}
}

func TestSealAdmitsExactEmptyPlanAndRejectsApplicableBlockedPlan(t *testing.T) {
	exact, err := seal(body{})
	if err != nil || exact.Checkpoints() != 1 {
		t.Fatalf("empty exact plan = %#v, %v", exact, err)
	}
	want := `{"schema":1,"digest":"sha256:6e798e7de28e940a0eecede9ff1e10d4b479db250a983744d5311354a80ffb64","plan":{"operations":[],"blockers":[]}}`
	if string(exact.Bytes()) != want {
		t.Fatalf("empty plan golden = %s", exact.Bytes())
	}
	if _, err := seal(body{
		operations: []operation{{id: "one", kind: "host", review: []byte(`{"x":1}`)}},
		blockers:   []blocker{{kind: "unsupported", resource: "timezone", detail: "blocked"}},
	}); err == nil {
		t.Fatal("globally blocked plan retained applicable operation")
	}
}

func TestSealCompactsRepeatedBlockerFacts(t *testing.T) {
	item := blocker{kind: "unsupported", resource: "hostname", detail: "representation unavailable"}
	one, err := seal(body{blockers: []blocker{item}})
	if err != nil {
		t.Fatal(err)
	}
	two, err := seal(body{blockers: []blocker{item, item}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Fatalf("duplicate blocker changed seal:\n%s\n%s", one.Bytes(), two.Bytes())
	}
}

func TestSealRequiresCanonicalReviewedBarrier(t *testing.T) {
	review := []byte(`{"resource":"service:system:demo.service","capability":"systemd-unit","reason":"install the delivering package and create a fresh Plan"}`)
	plan, err := seal(body{operations: []operation{
		{id: "package:zypper", kind: "package", review: []byte(`{"backend":"zypper"}`)},
		{id: "service:system:demo.service:barrier", kind: "barrier", dependencies: []string{"package:zypper"}, review: review},
	}})
	if err != nil {
		t.Fatalf("seal reviewed barrier: %v", err)
	}
	decoded, err := DecodePlan(plan.Bytes())
	if err != nil || !bytes.Equal(decoded.Bytes(), plan.Bytes()) {
		t.Fatalf("DecodePlan reviewed barrier = %#v, %v", decoded, err)
	}
	rendered, err := RenderPlan(plan)
	if err != nil || !strings.Contains(rendered, "install the delivering package and create a fresh Plan") {
		t.Fatalf("RenderPlan reviewed barrier = %q, %v", rendered, err)
	}

	for name, invalid := range map[string][]byte{
		"empty":              nil,
		"missing capability": []byte(`{"resource":"service:system:demo.service","reason":"create a fresh Plan"}`),
		"unknown field":      []byte(`{"resource":"service:system:demo.service","capability":"systemd-unit","reason":"create a fresh Plan","command":"systemctl"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := seal(body{operations: []operation{
				{id: "package:zypper", kind: "package", review: []byte(`{"backend":"zypper"}`)},
				{id: "barrier", kind: "barrier", dependencies: []string{"package:zypper"}, review: invalid},
			}}); err == nil {
				t.Fatal("invalid barrier review was admitted")
			}
		})
	}
}
