package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nostalume/proofstrap/internal/app"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/pack"
)

const (
	rootUsage       = "usage: proofstrap <import|inspect|plan|apply> [OPTIONS]"
	planUsage       = "usage: proofstrap plan --config FILE --output PLAN [--profile-bundle ARCHIVE [ARCHIVE ...]]"
	applyUsage      = "usage: proofstrap apply --plan PLAN --accept sha256:DIGEST [--journal FILE] [--receipt FILE]"
	maxConfigBytes  = 1 << 20
	planningTimeout = 30 * time.Minute
)

type processEnvironment struct {
	inventory    inventory.Environment
	effectiveUID uint32
}

type applicationCommands struct {
	buildPlan func(context.Context, app.Request) (app.Plan, error)
	apply     func(context.Context, app.ApplyRequest) (app.ApplyResult, error)
}

var productionApplication = applicationCommands{buildPlan: app.BuildPlan, apply: app.Apply}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	executable, _ := os.Readlink("/proc/self/exe")
	environment := processEnvironment{
		inventory:    inventory.Environment{ReleaseRoot: adjacentReleaseRoot(executable), XDGDataHome: os.Getenv("XDG_DATA_HOME"), Home: os.Getenv("HOME")},
		effectiveUID: uint32(os.Geteuid()),
	}
	os.Exit(runCommand(ctx, environment, productionInventory, productionApplication, os.Args[1:], os.Stdout, os.Stderr))
}

func adjacentReleaseRoot(executable string) string {
	if strings.HasSuffix(executable, " (deleted)") || !linux.CleanAbsoluteNonRoot(executable) {
		return ""
	}
	return filepath.Join(filepath.Dir(executable), "packs")
}

func runCommand(ctx context.Context, environment processEnvironment, inventoryCommands inventoryCommands, application applicationCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		return writeHelp(stdout, stderr, rootUsage)
	}
	if len(arguments) == 0 {
		return grammarError(stderr, rootUsage)
	}
	switch arguments[0] {
	case "import":
		return runImport(ctx, environment.inventory, inventoryCommands, arguments[1:], stdout, stderr)
	case "inspect":
		return runInspect(ctx, environment.inventory, inventoryCommands, arguments[1:], stdout, stderr)
	case "plan":
		return runPlan(ctx, environment.inventory, application, arguments[1:], stdout, stderr)
	case "apply":
		return runApply(ctx, environment.effectiveUID, application, arguments[1:], stdout, stderr)
	default:
		return grammarError(stderr, rootUsage)
	}
}

func runPlan(ctx context.Context, environment inventory.Environment, application applicationCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		return writeHelp(stdout, stderr, planUsage)
	}
	configPath, outputPath, bundles, ok := parsePlan(arguments)
	if !ok || application.buildPlan == nil {
		return grammarError(stderr, planUsage)
	}
	data, err := readConfig(configPath)
	if err != nil {
		return planFailure(err, stderr)
	}
	planCtx, cancel := context.WithTimeout(ctx, planningTimeout)
	defer cancel()
	plan, err := application.buildPlan(planCtx, app.Request{Origin: configPath, Config: data, Environment: environment, Bundles: bundles})
	if err != nil {
		return planFailure(err, stderr)
	}
	if _, err := app.PublishPlan(outputPath, plan); err != nil {
		return reportError(err, stderr)
	}
	review, err := app.RenderPlan(plan)
	if err != nil {
		return reportError(err, stderr)
	}
	if _, err := io.WriteString(stdout, review); err != nil {
		return reportError(err, stderr)
	}
	if plan.Blocked() {
		return 1
	}
	return 0
}

func runApply(ctx context.Context, effectiveUID uint32, application applicationCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		return writeHelp(stdout, stderr, applyUsage)
	}
	planPath, accepted, journalPath, receiptPath, ok := parseApply(arguments)
	if !ok || application.apply == nil {
		return grammarError(stderr, applyUsage)
	}
	digest, err := pack.ParseDigest(accepted)
	if err != nil {
		return grammarError(stderr, applyUsage)
	}
	result, err := application.apply(ctx, app.ApplyRequest{
		PlanPath: planPath, Accept: digest, JournalPath: journalPath, ReceiptPath: receiptPath,
		EffectiveUID: effectiveUID, Output: stdout,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, app.ErrInvalidPlan) || errors.Is(err, app.ErrInvalidRequest) {
			return 2
		}
		if len(result.Receipt) == 0 && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return 130
		}
		return 1
	}
	return statusCode(result.Status)
}

func parsePlan(arguments []string) (configPath, outputPath string, bundles []string, ok bool) {
	seenConfig, seenOutput := false, false
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--config":
			if seenConfig || index+1 >= len(arguments) {
				return "", "", nil, false
			}
			seenConfig, index, configPath = true, index+1, arguments[index+1]
		case "--output":
			if seenOutput || index+1 >= len(arguments) {
				return "", "", nil, false
			}
			seenOutput, index, outputPath = true, index+1, arguments[index+1]
		case "--profile-bundle":
			before := len(bundles)
			for index+1 < len(arguments) && !strings.HasPrefix(arguments[index+1], "--") {
				index++
				bundles = append(bundles, arguments[index])
			}
			if len(bundles) == before {
				return "", "", nil, false
			}
		default:
			return "", "", nil, false
		}
	}
	paths := []*string{&configPath, &outputPath}
	for index := range bundles {
		paths = append(paths, &bundles[index])
	}
	if !seenConfig || !seenOutput || configPath == "" || outputPath == "" || !canonicalCLIPaths(paths...) {
		return "", "", nil, false
	}
	return configPath, outputPath, bundles, true
}

func parseApply(arguments []string) (planPath, accepted, journalPath, receiptPath string, ok bool) {
	seen := make(map[string]bool, 4)
	values := map[string]*string{"--plan": &planPath, "--accept": &accepted, "--journal": &journalPath, "--receipt": &receiptPath}
	for index := 0; index < len(arguments); index++ {
		target, known := values[arguments[index]]
		if !known || seen[arguments[index]] || index+1 >= len(arguments) {
			return "", "", "", "", false
		}
		seen[arguments[index]], index = true, index+1
		*target = arguments[index]
	}
	if !seen["--plan"] || !seen["--accept"] || planPath == "" || !canonicalCLIPaths(&planPath, &journalPath, &receiptPath) {
		return "", "", "", "", false
	}
	return planPath, accepted, journalPath, receiptPath, true
}

func readConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &config.Diagnostic{Category: "InvalidValue", Detail: "config is not a regular file"}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, &config.Diagnostic{Category: "Limit", Detail: "config exceeds 1 MiB"}
	}
	return data, nil
}

func planFailure(err error, stderr io.Writer) int {
	fmt.Fprintln(stderr, err)
	var diagnostic *config.Diagnostic
	if errors.As(err, &diagnostic) {
		return 2
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 130
	}
	return 1
}

func statusCode(status engine.Status) int {
	switch status {
	case engine.Converged:
		return 0
	case engine.Partial:
		return 3
	default:
		return 1
	}
}

func reportError(err error, stderr io.Writer) int {
	fmt.Fprintln(stderr, err)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 130
	}
	return 1
}

func writeHelp(stdout, stderr io.Writer, usage string) int {
	if _, err := fmt.Fprintln(stdout, usage); err != nil {
		return reportError(err, stderr)
	}
	return 0
}
