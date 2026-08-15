package host

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReviewRoundTripsEveryHostOperationWithoutExecutionAuthority(t *testing.T) {
	hostnameEvidence := selectedHostname(&effectFixture{}).evidence
	timezoneEvidence := selectedTimezone(&effectFixture{}).evidence
	hostnameBefore := hostnameObservation{persistent: exactHostnameFile("old"), runtime: "old"}
	zone := zoneFile{regular: true, tzif: true, mode: 0o644, uid: 0, gid: 0, device: 3, inode: 4}
	timezoneBefore := timezoneObservation{present: true, zone: "UTC", target: "/usr/share/zoneinfo/UTC", zoneFile: zoneFile{regular: true, tzif: true, mode: 0o644, uid: 0, gid: 0, device: 3, inode: 2}, device: 1, inode: 9}
	operations := []Operation{
		{kind: writeHostnameOperation, desired: "node", hostnameBefore: hostnameObservation{persistent: hostnameBefore.persistent}, evidence: hostnameEvidence},
		{kind: setHostnameOperation, desired: "node", hostnameBefore: hostnameObservation{runtime: hostnameBefore.runtime}, evidence: hostnameEvidence},
		{kind: writeTimezoneOperation, desired: "Asia/Shanghai", timezoneBefore: timezoneBefore, zone: zone, evidence: timezoneEvidence},
	}
	for _, operation := range operations {
		encoded, err := EncodeReview(operation)
		if err != nil {
			t.Fatalf("EncodeReview(%v): %v", operation.kind, err)
		}
		for _, forbidden := range []string{"command", "argv", "sethostname", "rename"} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatalf("review contains %q: %s", forbidden, encoded)
			}
		}
		review, err := DecodeReview(encoded)
		if err != nil {
			t.Fatalf("DecodeReview(%v): %v", operation.kind, err)
		}
		fresh := &Selected{evidence: operation.evidence, effects: (&effectFixture{}).effects()}
		reconstructed, err := Reconstruct(review, fresh)
		if err != nil || reconstructed != operation {
			t.Fatalf("Reconstruct(%v) = %#v, %v", operation.kind, reconstructed, err)
		}
	}
}

func TestReviewRejectsNoncanonicalSyntaxAndFreshEvidenceDrift(t *testing.T) {
	operation := Operation{
		kind:           setHostnameOperation,
		desired:        "node",
		hostnameBefore: hostnameObservation{runtime: "old"},
		evidence:       selectedHostname(&effectFixture{}).evidence,
	}
	encoded, err := EncodeReview(operation)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"unknown":  bytes.Replace(encoded, []byte(`"desired":"node"`), []byte(`"unknown":0,"desired":"node"`), 1),
		"trailing": append(append([]byte(nil), encoded...), '\n'),
		"spacing":  bytes.Replace(encoded, []byte(`{"kind"`), []byte(`{ "kind"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if review, err := DecodeReview(bad); err == nil || review.valid() {
				t.Fatalf("DecodeReview admitted %s: %#v, %v", bad, review, err)
			}
		})
	}
	review, err := DecodeReview(encoded)
	if err != nil {
		t.Fatal(err)
	}
	fresh := &Selected{evidence: operation.evidence, effects: (&effectFixture{}).effects()}
	fresh.evidence.etc.inode++
	if _, err := Reconstruct(review, fresh); !errors.Is(err, ErrStale) {
		t.Fatalf("fresh evidence drift = %v", err)
	}
	if strings.Contains(string(encoded), "proofstrap-hostname") {
		t.Fatalf("review leaked staging detail: %s", encoded)
	}
}
