package identity

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/linux"
)

func TestReviewRoundTripsEveryIdentityOperationWithoutAuthority(t *testing.T) {
	evidence := reviewEvidence()
	account := accountIntent{name: "alice", managed: true, uid: 1000, primaryGroup: "users", home: "/home/alice"}
	home := homeIntent{path: "/home/alice", uid: 1000, gid: 1000}
	operations := map[string]Operation{
		"group":      {kind: createGroupOperation, evidence: evidence, group: groupIntent{name: "users", managed: true, gid: 1000}, groupBefore: missingGroupObservation()},
		"account":    {kind: createAccountOperation, evidence: evidence, account: account, primary: GroupFact{Name: "users", GID: 1000}, accountBefore: missingAccountObservation()},
		"lock":       {kind: lockAccountOperation, evidence: evidence, lockAccount: "alice"},
		"shell":      {kind: setShellOperation, evidence: evidence, shellAccount: "alice", shellValue: "/bin/bash", shellBefore: passwdRecord{name: "alice", uid: 1000, gid: 1000, home: "/home/alice", shell: "/bin/sh"}},
		"membership": {kind: setMembershipOperation, evidence: evidence, membershipAccount: "alice", membershipGroup: "wheel", membershipPresent: true, membershipBefore: groupRecord{name: "wheel", gid: 10, members: []string{"bob"}}},
		"home":       {kind: createHomeOperation, evidence: evidence, account: accountIntent{name: "alice"}, homeIntent: home, homeBefore: homeState{trusted: true}},
		"home-mode":  {kind: setHomeModeOperation, evidence: evidence, account: accountIntent{name: "alice"}, homeIntent: home, homeMode: 0o750, homeBefore: homeState{exists: true, trusted: true, directory: true, uid: 1000, gid: 1000, mode: 0o700}},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			encoded, err := EncodeReview(operation)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{`"command"`, `"argv"`, "--create-home", "--gid", "--shell"} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("review contains authority %q: %s", forbidden, encoded)
				}
			}
			review, err := DecodeReview(encoded)
			if err != nil {
				t.Fatal(err)
			}
			reconstructed, err := Reconstruct(review, &Selected{evidence: evidence, effects: shadowEffects{identify: func(string) (linux.Identity, error) { return linux.Identity{}, nil }, run: func(context.Context, linux.Identity, []string, []byte) (linux.Result, error) {
				return linux.Result{}, nil
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reconstructed, operation) {
				t.Fatalf("round trip differs:\n got %#v\nwant %#v", reconstructed, operation)
			}
			reencoded, err := EncodeReview(reconstructed)
			if err != nil || !bytes.Equal(encoded, reencoded) {
				t.Fatalf("canonical bytes drifted: %v", err)
			}
		})
	}
}

func TestReviewRejectsSyntaxAuthorityAndEvidenceDrift(t *testing.T) {
	operation := Operation{kind: lockAccountOperation, evidence: reviewEvidence(), lockAccount: "alice"}
	encoded, err := EncodeReview(operation)
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing newline":   append(append([]byte{}, encoded...), '\n'),
		"outer authority":    bytes.Replace(encoded, []byte(`{"kind"`), []byte(`{"command":["bad"],"kind"`), 1),
		"payload authority":  bytes.Replace(encoded, []byte(`{"account":"alice"`), []byte(`{"argv":["bad"],"account":"alice"`), 1),
		"unknown kind":       bytes.Replace(encoded, []byte(`"account-lock"`), []byte(`"account-delete"`), 1),
		"invalid digest":     bytes.Replace(encoded, []byte(`"sha256":"01`), []byte(`"sha256":"zz`), 1),
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
	fresh := reviewSelected(operation.evidence)
	fresh.evidence.tools[0].identity.Digest[0]++
	if _, err := Reconstruct(review, fresh); !errors.Is(err, ErrStale) {
		t.Fatalf("drift = %v", err)
	}
	if _, err := DecodeReview([]byte(strings.Repeat("x", maxReviewBytes+1))); err == nil {
		t.Fatal("accepted oversized review")
	}
}

func reviewEvidence() selectionEvidence {
	capabilities := []Capability{ObserveIdentity, CreateGroup, CreateAccount, ObserveLock, ModifyAccount, ModifyMembership}
	names := []string{"getent", "groupadd", "useradd", "passwd", "usermod", "gpasswd"}
	paths := []string{getentPath, groupaddPath, useraddPath, passwdPath, usermodPath, gpasswdPath}
	tools := make([]toolEvidence, len(names))
	for index := range names {
		identity := linux.Identity{Path: paths[index]}
		identity.Digest[0] = byte(index + 1)
		tools[index] = toolEvidence{name: names[index], identity: identity}
	}
	return selectionEvidence{capabilities: capabilities, tools: tools, rootGroup: groupRecord{name: "root", gid: 0}, rootAccount: passwdRecord{name: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/sh"}}
}

func reviewSelected(evidence selectionEvidence) *Selected {
	return &Selected{evidence: evidence, effects: shadowEffects{identify: func(string) (linux.Identity, error) { return linux.Identity{}, nil }, run: func(_ context.Context, _ linux.Identity, _ []string, _ []byte) (linux.Result, error) {
		return linux.Result{}, nil
	}}}
}
