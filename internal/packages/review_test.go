package packages

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

func TestReviewRoundTripReconstructsGuardsWithoutCommands(t *testing.T) {
	proof := zypperProof{
		zypper:        reviewIdentity("/usr/bin/zypper", 1),
		zypperVersion: "1.14.89",
		rpm:           reviewIdentity("/usr/bin/rpm", 2),
		rpmVersion:    "4.20.1-1",
	}
	operation := reviewOperation(t, proof)

	encoded, err := EncodeReview(operation)
	if err != nil {
		t.Fatal(err)
	}
	const golden = `{"backend":"zypper","role":"system","tools":[{"name":"rpm","path":"/usr/bin/rpm","sha256":"0200000000000000000000000000000000000000000000000000000000000000","version":"4.20.1-1"},{"name":"zypper","path":"/usr/bin/zypper","sha256":"0100000000000000000000000000000000000000000000000000000000000000","version":"1.14.89"}],"installed":[],"roots":[],"demands":[{"name":"pkg","state":"missing"}],"deltas":[{"kind":"add","key":"pkg","before":"","after":"installed"},{"kind":"root-add","key":"pkg","before":"","after":"direct"}]}`
	if string(encoded) != golden {
		t.Fatalf("review bytes changed:\n got %s\nwant %s", encoded, golden)
	}
	for _, forbidden := range []string{"command", "argv", "--install", "--download"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("review contains execution field %q: %s", forbidden, encoded)
		}
	}
	review, err := DecodeReview(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if review.Backend() != operation.Backend() || review.Role() != SystemCandidate || !review.state.before.equal(operation.before) || len(review.Deltas()) != 2 {
		t.Fatalf("decoded review differs: %#v", review)
	}

	behavior := &operationBehavior{commit: commitResult{Started: true}}
	fresh := selectedForProof(operation.Backend(), SystemCandidate, proof, behavior)
	reconstructed, err := Reconstruct(review, fresh)
	if err != nil {
		t.Fatal(err)
	}
	after := verificationObservation(t, []string{"pkg"}, []record{{Key: "pkg", State: "installed"}}, []string{"pkg"}, []demand{{Name: "pkg", State: demandDirect}})
	behavior.observations = []Observation{reconstructed.before, after}
	effect, cancelEffect, post, cancelPost := boundedContexts(t)
	defer cancelEffect()
	defer cancelPost()
	result, err := reconstructed.Apply(effect, postContext(post), fresh)
	if err != nil || !result.Started() {
		t.Fatalf("reconstructed Apply = %#v, %v", result, err)
	}
	if !reflect.DeepEqual(behavior.calls, []string{"observe", "commit", "observe", "verify"}) {
		t.Fatalf("reconstructed calls = %v", behavior.calls)
	}
}

func TestReviewSupportsEveryAdmittedProofShape(t *testing.T) {
	cases := []struct {
		name  string
		proof proof
	}{
		{"zypper", zypperProof{zypper: reviewIdentity("/usr/bin/zypper", 1), zypperVersion: "1.14.89", rpm: reviewIdentity("/usr/bin/rpm", 2), rpmVersion: "4.20.1-1"}},
		{"apt", aptProof{get: reviewIdentity("/usr/bin/apt-get", 1), getVersion: "3.0.3", query: reviewIdentity("/usr/bin/dpkg-query", 2), queryVersion: "1.22.21", mark: reviewIdentity("/usr/bin/apt-mark", 3), markVersion: "3.0.3", dpkg: reviewIdentity("/usr/bin/dpkg", 4), dpkgVersion: "1.22.21", nativeArch: "amd64"}},
		{"dnf5", dnf5Proof{executable: reviewIdentity("/usr/bin/dnf5", 1), version: "5.2.14.0"}},
		{"dnf4", dnf4Proof{executable: reviewIdentity("/usr/bin/dnf", 1), version: "4.22.0"}},
		{"apk", apkProof{executable: reviewIdentity("/sbin/apk", 1), version: "3.0.6-r0", architecture: "x86_64"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			operation := reviewOperation(t, test.proof)
			encoded, err := EncodeReview(operation)
			if err != nil {
				t.Fatal(err)
			}
			review, err := DecodeReview(encoded)
			if err != nil {
				t.Fatal(err)
			}
			fresh := selectedForProof(operation.Backend(), SystemCandidate, test.proof, fakeBehavior{})
			if _, err := Reconstruct(review, fresh); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReviewRejectsSyntaxAuthorityAndFreshEvidenceDrift(t *testing.T) {
	proof := dnf5Proof{executable: reviewIdentity("/usr/bin/dnf5", 1), version: "5.2.14.0"}
	operation := reviewOperation(t, proof)
	encoded, err := EncodeReview(operation)
	if err != nil {
		t.Fatal(err)
	}

	invalid := map[string][]byte{
		"unknown command": bytes.Replace(encoded, []byte(`{"backend"`), []byte(`{"command":["bad"],"backend"`), 1),
		"noncanonical":    append([]byte(" "), encoded...),
		"trailing":        append(append([]byte(nil), encoded...), '\n'),
		"unknown backend": bytes.Replace(encoded, []byte(`"dnf5"`), []byte(`"other"`), 1),
		"invalid role":    bytes.Replace(encoded, []byte(`"system"`), []byte(`"root"`), 1),
		"invalid tool":    bytes.Replace(encoded, []byte(`"name":"dnf5"`), []byte(`"name":"shell"`), 1),
		"invalid digest":  bytes.Replace(encoded, []byte(`"sha256":"01`), []byte(`"sha256":"zz`), 1),
		"invalid demand":  bytes.Replace(encoded, []byte(`"state":"missing"`), []byte(`"state":"wanted"`), 1),
		"forbidden delta": bytes.Replace(encoded, []byte(`{"kind":"add","key":"pkg","before":"","after":"installed"}`), []byte(`{"kind":"remove","key":"pkg","before":"installed","after":""}`), 1),
		"missing roots":   removeReviewField(encoded, `,"roots":`, `,"demands":`),
		"missing deltas":  append(append([]byte(nil), encoded[:bytes.Index(encoded, []byte(`,"deltas":`))]...), '}'),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReview(data); err == nil {
				t.Fatalf("accepted invalid review: %s", data)
			}
		})
	}

	review, err := DecodeReview(encoded)
	if err != nil {
		t.Fatal(err)
	}
	drifted := dnf5Proof{executable: reviewIdentity("/usr/bin/dnf5", 9), version: "5.2.14.0"}
	driftBehavior := &operationBehavior{}
	if _, err := Reconstruct(review, selectedForProof(operation.Backend(), SystemCandidate, drifted, driftBehavior)); !errors.Is(err, ErrStale) || len(driftBehavior.calls) != 0 {
		t.Fatalf("proof drift = %v", err)
	}
	otherBackend := backend(t, "dnf4")
	if _, err := Reconstruct(review, selectedForProof(otherBackend, SystemCandidate, dnf4Proof{executable: reviewIdentity("/usr/bin/dnf", 1), version: "4.22.0"}, fakeBehavior{})); !errors.Is(err, ErrStale) {
		t.Fatalf("backend substitution = %v", err)
	}
}

func TestEncodeReviewRejectsBackendProofMismatch(t *testing.T) {
	operation := reviewOperation(t, dnf5Proof{executable: reviewIdentity("/usr/bin/dnf5", 1), version: "5.2.14.0"})
	operation.evidence.backend = backend(t, "apt")
	if _, err := EncodeReview(operation); err == nil {
		t.Fatal("encoded DNF5 proof as Apt evidence")
	}
}

func TestDecodeReviewIsBounded(t *testing.T) {
	if _, err := DecodeReview([]byte(strings.Repeat("x", maxReviewBytes+1))); err == nil {
		t.Fatal("accepted oversized review")
	}
}

func reviewOperation(t *testing.T, native proof) Operation {
	t.Helper()
	name := ""
	switch native.(type) {
	case zypperProof:
		name = "zypper"
	case aptProof:
		name = "apt"
	case dnf5Proof:
		name = "dnf5"
	case dnf4Proof:
		name = "dnf4"
	case apkProof:
		name = "apk"
	default:
		t.Fatalf("unsupported test proof %T", native)
	}
	selected := selectedForProof(backend(t, name), SystemCandidate, native, fakeBehavior{})
	before := verificationObservation(t, []string{"pkg"}, nil, nil, []demand{{Name: "pkg", State: demandMissing}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Add, "pkg", "", "installed"),
		mustDelta(t, RootAdd, "pkg", "", "direct"),
	})
	decision, _ := Decide(offer)
	operation, err := NewOperation(selected, before, decision)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func selectedForProof(backend binding.PackageBackendID, role CandidateRole, native proof, behavior behavior) Selected {
	return Selected{evidence: candidateEvidence{backend: backend, role: role, state: candidateAdmitted, proof: native}, behavior: behavior}
}

func reviewIdentity(path string, marker byte) linux.Identity {
	identity := linux.Identity{Path: path}
	identity.Digest[0] = marker
	return identity
}

func removeReviewField(data []byte, start, end string) []byte {
	left := bytes.Index(data, []byte(start))
	right := bytes.Index(data, []byte(end))
	if left < 0 || right <= left {
		panic("review field markers not found")
	}
	result := append([]byte(nil), data[:left]...)
	return append(result, data[right:]...)
}
