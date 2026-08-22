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
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/engine"
	"github.com/nostalume/proofstrap/internal/pack"
)

const (
	rootUsage       = "usage: proofstrap <import|inspect|plan|apply> [OPTIONS]"
	planUsage       = "usage: proofstrap plan [--config FILE] [--output PLAN] [--pack-store DIR [DIR ...]] [--pack-file FILE [FILE ...]]"
	applyUsage      = "usage: proofstrap apply [--plan PLAN] --accept sha256:DIGEST [--journal FILE] [--receipt FILE]"
	maxConfigBytes  = 1 << 20
	planningTimeout = 30 * time.Minute
)

type processEnvironment struct {
	xdgDataHome  string
	home         string
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
	environment := processEnvironment{
		xdgDataHome:  os.Getenv("XDG_DATA_HOME"),
		home:         os.Getenv("HOME"),
		effectiveUID: uint32(os.Geteuid()),
	}
	os.Exit(runCommand(ctx, environment, productionArchives, productionApplication, os.Args[1:], os.Stdout, os.Stderr))
}

func runCommand(ctx context.Context, environment processEnvironment, archives archiveCommands, application applicationCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		return writeHelp(stdout, stderr, rootUsage)
	}
	if len(arguments) == 0 {
		return grammarError(stderr, rootUsage)
	}
	switch arguments[0] {
	case "import":
		return runImport(ctx, environment, archives, arguments[1:], stdout, stderr)
	case "inspect":
		return runInspect(ctx, archives, arguments[1:], stdout, stderr)
	case "plan":
		return runPlan(ctx, application, arguments[1:], stdout, stderr)
	case "apply":
		return runApply(ctx, environment.effectiveUID, application, arguments[1:], stdout, stderr)
	default:
		return grammarError(stderr, rootUsage)
	}
}

func runPlan(ctx context.Context, application applicationCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		return writeHelp(stdout, stderr, planUsage)
	}
	configPath, outputPath, stores, packFiles, ok := parsePlan(arguments)
	if !ok || application.buildPlan == nil {
		return grammarError(stderr, planUsage)
	}
	data, err := readConfig(configPath)
	if err != nil {
		return planFailure(err, stderr)
	}
	planCtx, cancel := context.WithTimeout(ctx, planningTimeout)
	defer cancel()
	target, err := document.Decode(configPath, data)
	if err != nil {
		return planFailure(err, stderr)
	}
	sources, err := acquireSources(planCtx, configPath, target, stores, packFiles)
	if err != nil {
		return planFailure(err, stderr)
	}
	plan, err := application.buildPlan(planCtx, app.Request{Document: target, Sources: sources})
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

func parsePlan(arguments []string) (configPath, outputPath string, stores, packFiles []string, ok bool) {
	configPath, outputPath = "proofstrap.toml", "plan.json"
	seen := make(map[string]bool, 2)
	values := map[string]*string{"--config": &configPath, "--output": &outputPath}
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--config", "--output":
			target := values[arguments[index]]
			if seen[arguments[index]] || index+1 >= len(arguments) {
				return "", "", nil, nil, false
			}
			seen[arguments[index]], index = true, index+1
			*target = arguments[index]
		case "--pack-store", "--pack-file":
			target := &packFiles
			if arguments[index] == "--pack-store" {
				target = &stores
			}
			before := len(*target)
			for index+1 < len(arguments) && !strings.HasPrefix(arguments[index+1], "--") {
				index++
				if arguments[index] == "" {
					return "", "", nil, nil, false
				}
				*target = append(*target, arguments[index])
			}
			if len(*target) == before {
				return "", "", nil, nil, false
			}
		default:
			return "", "", nil, nil, false
		}
	}
	paths := []*string{&configPath, &outputPath}
	for index := range stores {
		paths = append(paths, &stores[index])
	}
	for index := range packFiles {
		paths = append(paths, &packFiles[index])
	}
	if configPath == "" || outputPath == "" || !canonicalCLIPaths(paths...) || duplicatePaths(stores) || duplicatePaths(packFiles) {
		return "", "", nil, nil, false
	}
	return configPath, outputPath, stores, packFiles, true
}

func duplicatePaths(paths []string) bool {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if _, exists := seen[path]; exists {
			return true
		}
		seen[path] = struct{}{}
	}
	return false
}

func acquireSources(ctx context.Context, configPath string, target document.Document, stores, files []string) ([]pack.Source, error) {
	view := target.View()
	if len(view.Sources) == 0 {
		if len(stores)+len(files) != 0 {
			return nil, fmt.Errorf("pack inputs require declared source roots")
		}
		return nil, nil
	}
	if len(stores) > 64 || len(files) > 64 {
		return nil, fmt.Errorf("at most 64 pack stores and files are admitted")
	}
	provided := make([]pack.Source, 0, len(files))
	for _, path := range files {
		source, err := pack.ReadFile(ctx, path)
		if err != nil {
			return nil, err
		}
		provided = append(provided, source)
	}
	sibling := filepath.Join(filepath.Dir(configPath), "packs")
	if _, err := os.Lstat(sibling); err == nil {
		stores = append([]string{sibling}, stores...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if duplicatePaths(stores) {
		return nil, fmt.Errorf("duplicate pack store")
	}
	roots := make([]pack.Digest, len(view.Sources))
	for index, source := range view.Sources {
		roots[index] = source.Digest
	}
	return pack.ResolveClosure(ctx, roots, provided, func(ctx context.Context, digest pack.Digest) (pack.Source, error) {
		if len(stores) == 0 {
			return pack.Source{}, &pack.Diagnostic{Source: digest.String(), Category: pack.MissingRequirement, Detail: "exact source is unavailable"}
		}
		return pack.LoadExact(ctx, stores, digest)
	})
}

func parseApply(arguments []string) (planPath, accepted, journalPath, receiptPath string, ok bool) {
	planPath, journalPath = "plan.json", "apply.journal"
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
	if !seen["--accept"] || accepted == "" || planPath == "" || journalPath == "" || seen["--receipt"] && receiptPath == "" || !canonicalCLIPaths(&planPath, &journalPath, &receiptPath) {
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
		return nil, &document.Diagnostic{Category: "InvalidValue", Detail: "config is not a regular file"}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, &document.Diagnostic{Category: "Limit", Detail: "config exceeds 1 MiB"}
	}
	return data, nil
}

func planFailure(err error, stderr io.Writer) int {
	fmt.Fprintln(stderr, err)
	var diagnostic *document.Diagnostic
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
