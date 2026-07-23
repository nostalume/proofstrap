package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/nostalume/proofstrap/internal/proofstrap"
)

var runnerFactory = func() proofstrap.Runner { return proofstrap.OSRunner{} }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "usage: proofstrap <modules|plan|apply> [OPTIONS] [MODULE...]")
		return 2
	}
	switch arguments[0] {
	case "modules":
		return runModules(arguments[1:], stdout, stderr)
	case "plan":
		return runPlan(arguments[1:], stdout, stderr)
	case "apply":
		return runApply(arguments[1:], stdout, stderr)
	case "_create-home":
		return runCreateHome(arguments[1:], stderr)
	default:
		fmt.Fprintln(stderr, "usage: proofstrap <modules|plan|apply> [OPTIONS] [MODULE...]")
		return 2
	}
}

func runCreateHome(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("_create-home", flag.ContinueOnError)
	flags.SetOutput(stderr)
	uid := flags.Uint64("uid", 0, "account uid")
	gid := flags.Uint64("gid", 0, "primary gid")
	modeText := flags.String("mode", "", "home mode")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if len(flags.Args()) != 1 || *uid == 0 || *uid > uint64(^uint32(0)) || *gid > uint64(^uint32(0)) || len(*modeText) != 4 || (*modeText)[0] != '0' {
		fmt.Fprintln(stderr, "invalid create-home operation")
		return 2
	}
	mode, err := strconv.ParseUint(*modeText, 8, 12)
	if err != nil || mode > 0o777 {
		fmt.Fprintln(stderr, "invalid create-home operation")
		return 2
	}
	creation := proofstrap.HomeCreation{Path: flags.Arg(0), Mode: uint32(mode), UID: uint32(*uid), GID: uint32(*gid)}
	if err := runnerFactory().CreateHome(creation); err != nil {
		fmt.Fprintln(stderr, "create home:", err)
		return 1
	}
	return 0
}

func runModules(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "usage: proofstrap modules")
		return 2
	}
	for _, module := range proofstrap.Modules() {
		if _, err := fmt.Fprintln(stdout, module); err != nil {
			fmt.Fprintln(stderr, "modules output:", err)
			return 1
		}
	}
	return 0
}

func runPlan(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "TOML file containing a modules list")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	state, code, err := requestedState(flags.Args(), *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return code
	}
	runner := runnerFactory()
	plan := proofstrap.Plan(state, runner)
	if err := renderPlan(stdout, plan); err != nil {
		fmt.Fprintln(stderr, "plan output:", err)
		return 1
	}
	if plan.Blocked() {
		return 1
	}
	return 0
}

func runApply(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "TOML file containing a modules list")
	accepted := flags.String("accept", "", "digest printed by proofstrap plan")
	receiptPath := flags.String("receipt", "", "optional receipt output file")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	state, code, err := requestedState(flags.Args(), *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return code
	}
	if *accepted == "" {
		fmt.Fprintln(stderr, "apply requires --accept DIGEST from a reviewed plan")
		return 2
	}
	receipt := proofstrap.Apply(state, runnerFactory(), *accepted)
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "receipt error:", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		fmt.Fprintln(stderr, "receipt error:", err)
		return 1
	}
	if *receiptPath != "" {
		encoded = append(encoded, '\n')
		if err := writeReceipt(*receiptPath, encoded); err != nil {
			fmt.Fprintln(stderr, "receipt error:", err)
			return 1
		}
	}
	if receipt.Status != proofstrap.Succeeded && receipt.Status != proofstrap.ReplanRequired {
		return 1
	}
	return 0
}

func writeReceipt(path string, encoded []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return fmt.Errorf("open receipt")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return fmt.Errorf("receipt path is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := file.Truncate(0); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func renderPlan(stdout io.Writer, plan proofstrap.ReviewPlan) error {
	var rendered strings.Builder
	fmt.Fprintf(&rendered, "Plan modules: %v\n", plan.Modules)
	if plan.Account != nil {
		fmt.Fprintf(&rendered, "Plan account: %s\n", safeReviewText(plan.Account.Summary()))
	}
	fmt.Fprintf(&rendered, "Host OS ID: %s\n", safeReviewText(plan.Host.ID))
	fmt.Fprintf(&rendered, "Host OS version: %s\n", safeReviewText(plan.Host.Version))
	fmt.Fprintf(&rendered, "Host OS ID like: %s\n", safeReviewText(fmt.Sprint(plan.Host.Like)))
	fmt.Fprintf(&rendered, "Host PID 1: %s\n", safeReviewText(plan.Host.PID1))
	for _, fact := range plan.Facts {
		fmt.Fprintf(&rendered, "Fact %s: %s\n", safeReviewText(fact.Subject), safeReviewText(fact.Detail))
	}
	for _, change := range plan.Changes {
		fmt.Fprintf(&rendered, "Change %s: %s\n", safeReviewText(change.ID), safeReviewText(change.Detail))
		if change.Command != nil {
			fmt.Fprintf(&rendered, "Command %s: %s\n", safeReviewText(change.ID), safeReviewText(change.Command.String()))
		}
	}

	for _, blocker := range plan.Blockers {
		fmt.Fprintf(&rendered, "Blocker %s: %s\n", safeReviewText(blocker.Subject), safeReviewText(blocker.Detail))
	}
	fmt.Fprintf(&rendered, "Plan digest: %s\n", plan.Digest())
	_, err := io.WriteString(stdout, rendered.String())
	return err
}

func safeReviewText(value string) string {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return strconv.Quote(value)
	}
	return value
}

func requestedState(arguments []string, explicitConfig string) (proofstrap.DesiredState, int, error) {
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") {
			return proofstrap.DesiredState{}, 2, fmt.Errorf("flags must appear before module IDs")
		}
	}
	if explicitConfig != "" && len(arguments) != 0 {
		return proofstrap.DesiredState{}, 2, fmt.Errorf("cannot combine --config with module IDs")
	}
	if len(arguments) > 0 {
		state, err := proofstrap.NewDesiredState(arguments)
		if err != nil {
			return proofstrap.DesiredState{}, 2, err
		}
		return state, 0, nil
	}
	state, err := readDesiredState(explicitConfig)
	if err != nil {
		return proofstrap.DesiredState{}, 1, fmt.Errorf("config error: %w", err)
	}
	if state.Empty() {
		return proofstrap.DesiredState{}, 2, fmt.Errorf("module IDs or a config file with desired state are required")
	}
	return state, 0, nil
}

func readDesiredState(explicit string) (proofstrap.DesiredState, error) {
	environment := os.Getenv("PROOFSTRAP_CONFIG")
	if explicit != "" || environment != "" {
		path, err := findConfigFile(explicit, "", environment, "")
		if err != nil || path == "" {
			return proofstrap.DesiredState{}, err
		}
		return proofstrap.ReadDesiredState(path)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return proofstrap.DesiredState{}, err
	}
	global := ""
	if directory, err := os.UserConfigDir(); err == nil {
		global = filepath.Join(directory, "proofstrap", "proofstrap.toml")
	}
	path, err := findConfigFile("", filepath.Join(cwd, "proofstrap.toml"), "", global)
	if err != nil || path == "" {
		return proofstrap.DesiredState{}, err
	}
	return proofstrap.ReadDesiredState(path)
}
