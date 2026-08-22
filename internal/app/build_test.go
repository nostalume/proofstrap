package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestBuildPlanAcceptsTwoPinnedSemanticSources(t *testing.T) {
	root := t.TempDir()
	core := buildInlineSemantic(t, filepath.Join(root, "core"), `[profiles.workstation]
parameters = { account = "account_ref", desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
[profiles.workstation.include.arguments]
account = { parameter = "account" }
`)
	extra := buildInlineSemantic(t, filepath.Join(root, "extra"), `[profiles.home]
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
	target, err := document.Decode("test", config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(buildContext(t), Request{Document: target, Sources: []pack.Source{core, extra}})
	if err != nil || len(plan.Bytes()) == 0 {
		t.Fatalf("BuildPlan = %#v, %v", plan, err)
	}
	stored, err := BuildPlan(buildContext(t), Request{Document: target, Sources: []pack.Source{extra, core}})
	if err != nil || !bytes.Equal(stored.Bytes(), plan.Bytes()) {
		t.Fatalf("stored Plan differs: %v", err)
	}
}

func TestBuildPlanRejectsInvalidRequestBeforeSourceOrHostObservation(t *testing.T) {
	if _, err := BuildPlan(buildContext(t), Request{}); err == nil {
		t.Fatal("invalid request admitted")
	}
	if _, err := BuildPlan(nil, Request{}); err == nil {
		t.Fatal("nil context admitted")
	}
}

func buildInlineSemantic(t testing.TB, input, profiles string) pack.Source {
	t.Helper()
	if err := os.MkdirAll(input, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, "proofstrap.toml")
	inputData := "schema=3\ninclude=[{profile='fixture'}]\n[profiles.fixture]\npackages=['fixture']\n" + profiles
	if err := os.WriteFile(path, []byte(inputData), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(input, "dist")
	config, err := packbuild.Build(context.Background(), path, output)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	target, err := document.Decode(config, data)
	if err != nil || len(target.View().Sources) != 1 {
		t.Fatalf("generated fixture = %#v, %v", target.View(), err)
	}
	source, err := pack.LoadExact(context.Background(), []string{filepath.Join(output, "packs")}, target.View().Sources[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	return source
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
