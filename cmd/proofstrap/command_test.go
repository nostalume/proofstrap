package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/app"
	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/pack"
)

const commandBlockedDocument = `schema = 3
include = [{ profile = "blocked" }]

[profiles.blocked]
packages = ["unmapped"]
`

func TestPlanAndApplyParsersCanonicalizeRelativeArtifactPaths(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	configPath, outputPath, store, packFiles, ok := parsePlan([]string{
		"--config", "config/../target.toml", "--output", "plan.json", "--pack-store", "packs", "--pack-file", "packs/core.pstrap",
	})
	if !ok || configPath != filepath.Join(directory, "target.toml") || outputPath != filepath.Join(directory, "plan.json") ||
		store != filepath.Join(directory, "packs") || !reflect.DeepEqual(packFiles, []string{filepath.Join(directory, "packs", "core.pstrap")}) {
		t.Fatalf("parsePlan = %q, %q, %v, %t", configPath, outputPath, packFiles, ok)
	}
	planPath, accepted, journalPath, receiptPath, ok := parseApply([]string{
		"--plan", "plan.json", "--accept", "sha256:" + strings.Repeat("1", 64), "--journal", "state/journal", "--receipt", "receipt.json",
	})
	if !ok || accepted == "" || planPath != filepath.Join(directory, "plan.json") ||
		journalPath != filepath.Join(directory, "state", "journal") || receiptPath != filepath.Join(directory, "receipt.json") {
		t.Fatalf("parseApply = %q, %q, %q, %q, %t", planPath, accepted, journalPath, receiptPath, ok)
	}
}

func TestPlanParserAggregatesGroupedAndRepeatedPackFiles(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	_, _, _, packFiles, ok := parsePlan([]string{
		"--pack-file", "one.pstrap", "two.pstrap", "--config", "config.toml",
		"--pack-file", "three.pstrap", "--output", "plan.json",
	})
	want := []string{
		filepath.Join(directory, "one.pstrap"), filepath.Join(directory, "two.pstrap"), filepath.Join(directory, "three.pstrap"),
	}
	if !ok || !reflect.DeepEqual(packFiles, want) {
		t.Fatalf("pack files = %v, ok = %t; want %v, true", packFiles, ok, want)
	}
	for _, arguments := range [][]string{
		{"--config", "config.toml", "--output", "plan.json", "--pack-file"},
		{"--config", "config.toml", "--output", "plan.json", "--pack-file", "--unknown"},
		{"--pack-file", ""},
	} {
		if _, _, _, _, ok := parsePlan(arguments); ok {
			t.Fatalf("empty --pack-file group accepted: %v", arguments)
		}
	}
}

const commandEmptyPlanJSON = `{"schema":1,"digest":"sha256:6e798e7de28e940a0eecede9ff1e10d4b479db250a983744d5311354a80ffb64","plan":{"operations":[],"blockers":[]}}`
const commandBlockedPlanJSON = `{"schema":1,"digest":"sha256:a11e921054be7aab1654009effd14a75305787cfff2f3f7cc32bf501bd38afb9","plan":{"operations":[],"blockers":[{"kind":"unsupported","resource":"test","detail":"fixture"}]}}`

func TestPlanAndApplyUseWorkingDirectoryDefaults(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	plan, _ := app.DecodePlan([]byte(commandEmptyPlanJSON))
	var planned app.Request
	var applied app.ApplyRequest
	applications := applicationCommands{
		buildPlan: func(_ context.Context, request app.Request) (app.Plan, error) {
			planned = request
			return plan, nil
		},
		apply: func(_ context.Context, request app.ApplyRequest) (app.ApplyResult, error) {
			applied = request
			return app.ApplyResult{Status: engine.Converged}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"plan"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), filepath.Join(directory, "proofstrap.toml")) {
		t.Fatalf("missing default: code=%d stderr=%q", code, stderr.String())
	}
	if err := os.WriteFile("proofstrap.toml", []byte(commandBlockedDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"plan"}, &stdout, &stderr); code != 0 {
		t.Fatalf("plan: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	digest := "sha256:" + strings.Repeat("1", 64)
	stdout.Reset()
	stderr.Reset()
	if code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, []string{"apply", "--accept", digest}, &stdout, &stderr); code != 0 {
		t.Fatalf("apply: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if planned.Origin != filepath.Join(directory, "proofstrap.toml") || applied.PlanPath != filepath.Join(directory, "plan.json") || applied.JournalPath != filepath.Join(directory, "apply.journal") {
		t.Fatalf("planned=%#v applied=%#v", planned, applied)
	}
}

func TestAdjacentReleaseRootUsesKernelResolvedPath(t *testing.T) {
	if got := adjacentReleaseRoot("/opt/proofstrap/releases/generation/proofstrap"); got != "/opt/proofstrap/releases/generation/packs" {
		t.Fatalf("adjacent release root = %q", got)
	}
	for _, path := range []string{"", "relative", "/opt/proofstrap/releases/generation/proofstrap (deleted)"} {
		if got := adjacentReleaseRoot(path); got != "" {
			t.Fatalf("invalid executable %q produced release root %q", path, got)
		}
	}
}

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
		nil, {"modules"}, {"_create-home"}, {"plan", "module"}, {"plan", "--profile-bundle", "old.pstrap"},
		{"plan", "--config=x"}, {"plan", "-c", "x"}, {"plan", "--conf", "x"}, {"plan", "--output", ""}, {"plan", "--pack-store", ""}, {"plan", "--pack-store=x"},
		{"plan", "--pack-store", "/tmp/a", "--pack-store", "/tmp/b"},
		{"plan", "--config", "/tmp/config", "--config", "/tmp/other", "--output", "/tmp/plan"},
		{"apply"}, {"apply", "--accept=" + strings.Repeat("1", 64)}, {"apply", "-a", "sha256:" + strings.Repeat("1", 64)}, {"apply", "--accept", ""}, {"apply", "--accept", "sha256:" + strings.Repeat("1", 64), "--journal", ""},
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
	packFileOne := filepath.Join(root, "one.pstrap")
	packFileTwo := filepath.Join(root, "two.pstrap")
	store := filepath.Join(root, "packs")
	config := []byte(commandBlockedDocument)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var got app.Request
	applications := applicationCommands{buildPlan: func(_ context.Context, request app.Request) (app.Plan, error) {
		got = request
		return plan, nil
	}}
	var stdout, stderr bytes.Buffer
	arguments := []string{"plan", "--pack-file", packFileOne, "--output", outputPath, "--pack-store", store, "--config", configPath, "--pack-file", packFileTwo}
	code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applications, arguments, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || got.Origin != configPath || got.Environment.PackStore != store || !bytes.Equal(got.Config, config) || strings.Join(got.PackFiles, ",") != packFileOne+","+packFileTwo {
		t.Fatalf("code=%d request=%#v stdout=%q stderr=%q", code, got, stdout.String(), stderr.String())
	}
	published, err := os.ReadFile(outputPath)
	if err != nil || string(published) != commandEmptyPlanJSON || !strings.Contains(stdout.String(), "status: applicable") || !strings.Contains(stdout.String(), plan.Digest().String()) {
		t.Fatalf("published=%q err=%v stdout=%q", published, err, stdout.String())
	}
}

func TestPlanPublishesBlockedArtifactAndReturnsOne(t *testing.T) {
	blocked, err := app.DecodePlan([]byte(commandBlockedPlanJSON))
	if err != nil || !blocked.Blocked() {
		t.Fatalf("blocked Plan = %#v, %v", blocked, err)
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	outputPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(configPath, []byte(commandBlockedDocument), 0o600); err != nil {
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

func TestApplyDefaultsJournalAndMapsSchemaErrors(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	planPath := filepath.Join(t.TempDir(), "plan.json")
	for _, test := range []struct {
		name string
		err  error
	}{
		{"invalid Apply request", fmt.Errorf("%w: request", app.ErrInvalidRequest)},
		{"invalid Plan schema", fmt.Errorf("%w: schema", app.ErrInvalidPlan)},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			applications := applicationCommands{apply: func(_ context.Context, request app.ApplyRequest) (app.ApplyResult, error) {
				called = true
				if filepath.Base(request.JournalPath) != "apply.journal" {
					t.Fatalf("default journal = %q", request.JournalPath)
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

func TestHelpStatesExactCommandGrammar(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		usage     string
	}{
		{[]string{"--help"}, rootUsage}, {[]string{"plan", "--help"}, planUsage}, {[]string{"apply", "--help"}, applyUsage},
	} {
		var stdout, stderr bytes.Buffer
		code := runCommand(context.Background(), processEnvironment{}, inventoryCommands{}, applicationCommands{}, test.arguments, &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 || stdout.String() != test.usage+"\n" || strings.Contains(stdout.String(), "_create-home") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", test.arguments, code, stdout.String(), stderr.String())
		}
	}
}

type cutoverFailWriter struct{ err error }

func (writer cutoverFailWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestPlanBrokenOutputIsFailureAfterPublication(t *testing.T) {
	plan, _ := app.DecodePlan([]byte(commandEmptyPlanJSON))
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	outputPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(configPath, []byte(commandBlockedDocument), 0o600); err != nil {
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
