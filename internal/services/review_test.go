package services

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReviewRoundTripsEveryAxisWithoutCommands(t *testing.T) {
	fixture := newSystemdFixture()
	selected, err := selectSystem(testContext(t), fixture.effects())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Operation{}
	for _, item := range []struct {
		name    string
		desired demand
		before  unitRecord
	}{
		{"enable-start", demand{unit: "demo.service", persistence: wantOn, runtime: wantOn}, unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}},
		{"stop-disable", demand{unit: "demo.service", persistence: wantOff, runtime: wantOff}, unitRecord{id: "demo.service", load: "loaded", unitFile: "enabled", active: "active", sub: "running"}},
	} {
		planned := reconcile(item.desired, item.before)
		for _, operation := range planned.Operations() {
			operation.evidence = selected.evidence
			cases[item.name+"-"+operation.verb()] = operation
		}
	}
	principal, _ := NewPrincipal("alice", 1000, "/home/alice")
	userSelected, err := selectUser(testContext(t), fixture.effects(), principal)
	if err != nil {
		t.Fatal(err)
	}
	userOperation := reconcile(demand{unit: "pipewire.service", runtime: wantOn, user: "alice"}, unitRecord{id: "pipewire.service", load: "loaded", unitFile: "enabled", active: "inactive", sub: "dead"}).Operations()[0]
	userOperation.evidence = userSelected.evidence
	cases["user-start"] = userOperation
	if len(cases) != 5 {
		t.Fatalf("operations=%#v", cases)
	}
	for name, operation := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := EncodeReview(operation)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{`"command"`, `"argv"`, `"args"`, "--now", "--machine="} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("authority %q in %s", forbidden, encoded)
				}
			}
			review, err := DecodeReview(encoded)
			if err != nil {
				t.Fatal(err)
			}
			fresh := selected
			if operation.evidence.scope == userScope {
				fresh = userSelected
			}
			reconstructed, err := Reconstruct(review, fresh)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reconstructed, operation) {
				t.Fatalf("round trip differs: %#v / %#v", reconstructed, operation)
			}
			reencoded, _ := EncodeReview(reconstructed)
			if !bytes.Equal(encoded, reencoded) {
				t.Fatalf("bytes drifted: %s / %s", encoded, reencoded)
			}
		})
	}
}

func TestReviewRejectsSyntaxAuthorityAndFreshPlaneDrift(t *testing.T) {
	fixture := newSystemdFixture()
	selected, _ := selectSystem(testContext(t), fixture.effects())
	operation := reconcile(demand{unit: "demo.service", runtime: wantOn}, unitRecord{id: "demo.service", load: "loaded", unitFile: "disabled", active: "inactive", sub: "dead"}).Operations()[0]
	operation.evidence = selected.evidence
	encoded, err := EncodeReview(operation)
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string][]byte{
		"leading":            append([]byte(" "), encoded...),
		"trailing":           append(append([]byte{}, encoded...), '\n'),
		"outer command":      bytes.Replace(encoded, []byte(`{"kind"`), []byte(`{"command":["bad"],"kind"`), 1),
		"unknown kind":       bytes.Replace(encoded, []byte(`"start"`), []byte(`"restart"`), 1),
		"invalid digest":     bytes.Replace(encoded, []byte(`"sha256":"01`), []byte(`"sha256":"zz`), 1),
		"scope substitution": bytes.Replace(encoded, []byte(`"scope":"system"`), []byte(`"scope":"user"`), 1),
		"option unit":        bytes.Replace(encoded, []byte(`"unit":"demo.service"`), []byte(`"unit":"-bad.service"`), 1),
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReview(value); err == nil {
				t.Fatalf("accepted %s", value)
			}
		})
	}
	review, err := DecodeReview(encoded)
	if err != nil {
		t.Fatal(err)
	}
	drifted := *selected
	drifted.evidence.version = "257"
	if _, err := Reconstruct(review, &drifted); !errors.Is(err, ErrStale) {
		t.Fatalf("drift=%v", err)
	}
	if _, err := DecodeReview([]byte(strings.Repeat("x", maxReviewBytes+1))); err == nil {
		t.Fatal("accepted oversized review")
	}
}
