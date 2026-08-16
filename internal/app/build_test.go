package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/inventory"
)

func TestBuildPlanProducesCanonicalBlockedPlanForUnsupportedExactBackend(t *testing.T) {
	plan, err := BuildPlan(buildContext(t), Request{
		Origin: "test", Config: []byte("schema = 1\npackages = [\"flatpak:org.example.App\"]\n"), Environment: inventory.Environment{},
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

func TestBuildPlanRejectsInvalidRequestBeforeSourceOrHostObservation(t *testing.T) {
	if _, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: []byte("schema = 2\n")}); err == nil {
		t.Fatal("invalid config admitted")
	}
	if _, err := BuildPlan(nil, Request{Origin: "test", Config: []byte("schema = 1\npackages = [\"flatpak:x\"]\n")}); err == nil {
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
	plan, err := BuildPlan(buildContext(t), Request{Origin: "test", Config: []byte(`schema = 1
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
