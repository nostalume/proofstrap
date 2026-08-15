package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/app"
	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/pack"
)

const commandEmptyPlanJSON = `{"schema":1,"digest":"sha256:6e798e7de28e940a0eecede9ff1e10d4b479db250a983744d5311354a80ffb64","plan":{"operations":[],"blockers":[]}}`

func TestCutoverGrammarRejectsLegacyAndForbiddenInputs(t *testing.T) {
	called := false
	applications := applicationCommands{
		buildPlan: func(context.Context, app.Request) (app.Plan, error) { called = true; return app.Plan{}, nil },
		apply: func(context.Context, app.ApplyRequest) (app.ApplyResult, error) {
			called = true
			return app.ApplyResult{}, nil
		},
	}
	environment := processEnvironment{inventory: inventory.Environment{Home: "/home/test"}, effectiveUID: 0}
	for _, arguments := range [][]string{
		nil, {"modules"}, {"_create-home"}, {"plan", "module"}, {"plan", "--config", "relative", "--output", "/tmp/plan"},
		{"plan", "--config", "/tmp/config", "--config", "/tmp/other", "--output", "/tmp/plan"},
		{"apply", "--config", "/tmp/config"}, {"apply", "--plan", "/tmp/plan", "--accept", "bad"},
		{"apply", "--plan", "/tmp/plan", "--plan", "/tmp/other", "--accept", "sha256:" + strings.Repeat("1", 64)},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), environment, inventoryCommands{}, applications, arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("invalid grammar reached application authority")
	}
}

func TestPlanPublishesArtifactAndRendersReview(t *testing.T) {
	plan, err := app.DecodePlan([]byte(commandEmptyPlanJSON))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	outputPath := filepath.Join(root, "plan.json")
	bundleOne := filepath.Join(root, "one.pstrap")
	bundleTwo := filepath.Join(root, "two.pstrap")
	config := []byte("schema = 1\npackages = [\"flatpak:x\"]\n")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var got app.Request
	applications := applicationCommands{buildPlan: func(_ context.Context, request app.Request) (app.Plan, error) {
		got = request
		return plan, nil
	}}
	var stdout, stderr bytes.Buffer
	arguments := []string{"plan", "--profile-bundle", bundleOne, "--output", outputPath, "--config", configPath, "--profile-bundle", bundleTwo}
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, arguments, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || got.Origin != configPath || !bytes.Equal(got.Config, config) || strings.Join(got.Bundles, ",") != bundleOne+","+bundleTwo {
		t.Fatalf("code=%d request=%#v stdout=%q stderr=%q", code, got, stdout.String(), stderr.String())
	}
	published, err := os.ReadFile(outputPath)
	if err != nil || string(published) != commandEmptyPlanJSON || !strings.Contains(stdout.String(), "status: applicable") || !strings.Contains(stdout.String(), plan.Digest().String()) {
		t.Fatalf("published=%q err=%v stdout=%q", published, err, stdout.String())
	}
}

func TestPlanPublishesBlockedArtifactAndReturnsOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	blocked, err := app.BuildPlan(ctx, app.Request{Origin: "test", Config: []byte("schema = 1\npackages = [\"flatpak:x\"]\n")})
	if err != nil || !blocked.Blocked() {
		t.Fatalf("blocked Plan = %#v, %v", blocked, err)
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	outputPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(configPath, []byte("schema = 1\npackages = [\"flatpak:x\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applications := applicationCommands{buildPlan: func(context.Context, app.Request) (app.Plan, error) { return blocked, nil }}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"plan", "--config", configPath, "--output", outputPath}, &stdout, &stderr)
	if code != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "status: blocked") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if published, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(published, blocked.Bytes()) {
		t.Fatalf("published=%q err=%v", published, err)
	}
}

func TestApplyMapsTerminalStatusAndPassesExactRequest(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	journalPath := filepath.Join(root, "journal")
	receiptPath := filepath.Join(root, "receipt")
	for _, test := range []struct {
		name       string
		status     engine.Status
		err        error
		receipt    []byte
		want       int
		wantOutput string
	}{
		{"converged", engine.Converged, nil, []byte("receipt\n"), 0, "receipt\n"},
		{"partial", engine.Partial, nil, []byte("partial\n"), 3, "partial\n"},
		{"failed", engine.FailedStatus, nil, []byte("failed\n"), 1, "failed\n"},
		{"canceled before result", 0, context.Canceled, nil, 130, ""},
		{"output failure", engine.Converged, errors.New("output failed"), []byte("truth\n"), 1, "truth\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got app.ApplyRequest
			applications := applicationCommands{apply: func(_ context.Context, request app.ApplyRequest) (app.ApplyResult, error) {
				got = request
				if len(test.receipt) != 0 {
					_, _ = request.Output.Write(test.receipt)
				}
				return app.ApplyResult{Status: test.status, Receipt: test.receipt}, test.err
			}}
			var stdout, stderr bytes.Buffer
			arguments := []string{"apply", "--receipt", receiptPath, "--accept", digest.String(), "--journal", journalPath, "--plan", planPath}
			code := runCommand(context.Background(), processEnvironment{effectiveUID: 42}, inventoryCommands{}, applications, arguments, &stdout, &stderr)
			if code != test.want || stdout.String() != test.wantOutput || got.PlanPath != planPath || got.Accept != digest || got.JournalPath != journalPath || got.ReceiptPath != receiptPath || got.EffectiveUID != 42 {
				t.Fatalf("code=%d request=%#v stdout=%q stderr=%q", code, got, stdout.String(), stderr.String())
			}
		})
	}
}

func TestApplyLetsDecodedPlanDecideJournalRequirementAndMapsSchemaErrors(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	planPath := filepath.Join(t.TempDir(), "plan.json")
	for _, test := range []struct {
		name string
		err  error
	}{
		{"journal required after decode", fmt.Errorf("%w: journal path is required", app.ErrInvalidRequest)},
		{"invalid Plan schema", fmt.Errorf("%w: schema", app.ErrInvalidPlan)},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			applications := applicationCommands{apply: func(_ context.Context, request app.ApplyRequest) (app.ApplyResult, error) {
				called = true
				if request.JournalPath != "" {
					t.Fatal("CLI synthesized a journal path")
				}
				return app.ApplyResult{}, test.err
			}}
			var stdout, stderr bytes.Buffer
			code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"apply", "--plan", planPath, "--accept", digest}, &stdout, &stderr)
			if code != 2 || !called || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
			}
		})
	}
}

func TestProductionApplyMapsInvalidPlanSchemaToUsage(t *testing.T) {
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, []byte(`{"schema":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{effectiveUID: uint32(os.Geteuid())}, inventoryCommands{}, productionApplication,
		[]string{"apply", "--plan", planPath, "--accept", "sha256:" + strings.Repeat("1", 64)}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPlanOversizeConfigIsSchemaFailureBeforeBuild(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	if err := os.WriteFile(configPath, bytes.Repeat([]byte{'x'}, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	applications := applicationCommands{buildPlan: func(context.Context, app.Request) (app.Plan, error) { called = true; return app.Plan{}, nil }}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications,
		[]string{"plan", "--config", configPath, "--output", filepath.Join(root, "plan.json")}, &stdout, &stderr)
	if code != 2 || called || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Limit") {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRootHelpListsOnlyCutoverCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applicationCommands{}, []string{"--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || stdout.String() != rootUsage+"\n" || strings.Contains(stdout.String(), "modules") || strings.Contains(stdout.String(), "_create-home") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type cutoverFailWriter struct{ err error }

func (writer cutoverFailWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestPlanBrokenOutputIsFailureAfterPublication(t *testing.T) {
	plan, _ := app.DecodePlan([]byte(commandEmptyPlanJSON))
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	outputPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(configPath, []byte("schema = 1\npackages = [\"flatpak:x\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applications := applicationCommands{buildPlan: func(context.Context, app.Request) (app.Plan, error) { return plan, nil }}
	var stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"plan", "--config", configPath, "--output", outputPath}, cutoverFailWriter{io.ErrClosedPipe}, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("published Plan missing: %v", err)
	}
}
