package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/inventory"
)

func TestBuildPlanProducesCanonicalBlockedPlanForUnsupportedExactBackend(t *testing.T) {
	plan, err := BuildPlan(buildContext(t), Request{
		Origin: "test", Config: []byte("schema = 2\npackages = [\"flatpak:org.example.App\"]\n"), Environment: inventory.Environment{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Checkpoints() != 1 {
		t.Fatalf("checkpoints = %d", plan.Checkpoints())
	}
	rendered, err := RenderPlan(plan)
	if err != nil || !strings.Contains(rendered, "status: blocked") || !strings.Contains(rendered, "package:flatpak") {
		t.Fatalf("render = %q, %v", rendered, err)
	}
	if decoded, err := DecodePlan(plan.Bytes()); err != nil || decoded.Digest() != plan.Digest() {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}
}

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
	config := []byte(fmt.Sprintf(`schema=2
profiles=[{profile="core:workstation",arguments={account="alice",desktop="extra:home"}}]
[sources]
core=%q
extra=%q
[accounts.alice]
`, core.Digest(), extra.Digest()))
	plan, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: config,
		Environment: inventory.Environment{}, Bundles: []string{corePath, extraPath}})
	if err != nil || len(plan.Bytes()) == 0 {
		t.Fatalf("BuildPlan = %#v, %v", plan, err)
	}
}

func TestBuildPlanRejectsInvalidRequestBeforeSourceOrHostObservation(t *testing.T) {
	if _, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: []byte("schema = 2\n")}); err == nil {
		t.Fatal("invalid config admitted")
	}
	if _, err := BuildPlan(nil, Request{Origin: "test", Config: []byte("schema = 2\npackages = [\"flatpak:x\"]\n")}); err == nil {
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

func TestBuildPlanServiceSelectsExactOpenRCBackendWithoutSystemdFallback(t *testing.T) {
	plan, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: []byte(`schema = 2
[services."openrc:sshd"]
target = "system"
running = true
`)})
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderPlan(plan)
	if err != nil || !strings.Contains(rendered, "status: blocked") || !strings.Contains(rendered, "service-principal:openrc:") {
		t.Fatalf("render = %q, %v", rendered, err)
	}
}

func buildContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}
