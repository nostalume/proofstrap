package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/inventory"
)

func TestBuildPlanAcceptsTwoPinnedSemanticSources(t *testing.T) {
	root := t.TempDir()
	corePath, extraPath := filepath.Join(root, "core.pstrap"), filepath.Join(root, "extra.pstrap")
	core := buildInlineSemanticAt(t, filepath.Join(root, "core"), corePath, `[profiles.workstation]
parameters = { account = "account_ref", desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
[profiles.workstation.include.arguments]
account = { parameter = "account" }
`)
	extra := buildInlineSemanticAt(t, filepath.Join(root, "extra"), extraPath, `[profiles.home]
parameters = { account = "account_ref" }
homes = [{ account = { parameter = "account" } }]
`)
	config := []byte(fmt.Sprintf(`schema=3
include=[{profile="core:workstation",arguments={account="alice",desktop="extra:home"}}]
[sources]
core=%q
extra=%q
[accounts.alice]
`, core.Digest(), extra.Digest()))
	plan, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: config,
		Environment: inventory.Environment{}, PackFiles: []string{corePath, extraPath}})
	if err != nil || len(plan.Bytes()) == 0 {
		t.Fatalf("BuildPlan = %#v, %v", plan, err)
	}
	storage := inventory.Environment{XDGDataHome: filepath.Join(root, "xdg")}
	for _, path := range []string{corePath, extraPath} {
		if _, err := inventory.ImportUser(buildContext(t), storage, path, nil); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: config,
		Environment: inventory.Environment{PackStore: filepath.Join(storage.XDGDataHome, "proofstrap", "packs")}})
	if err != nil || !bytes.Equal(stored.Bytes(), plan.Bytes()) {
		t.Fatalf("stored Plan differs: %v", err)
	}
}

func TestBuildPlanRejectsInvalidRequestBeforeSourceOrHostObservation(t *testing.T) {
	if _, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: []byte("schema = 3\n")}); err == nil {
		t.Fatal("invalid config admitted")
	}
	if _, err := BuildPlan(nil, Request{Origin: "test", Config: []byte("schema = 3\n")}); err == nil {
		t.Fatal("nil context admitted")
	}
}

func TestBuildPlanReturnsCancellationBeforeDecode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildPlan(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BuildPlan = %v", err)
	}
}

func buildContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}
