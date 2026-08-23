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

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

const (
	usage = "usage: proofstrap-pack (build --input FILE --output DIR | check --input FILE --package-backend BACKEND --service-backend BACKEND)"

	rootHelp = `Build deterministic Proofstrap workspaces for distribution.

Usage:
  proofstrap-pack build --input FILE --output DIR
  proofstrap-pack check --input FILE --package-backend BACKEND --service-backend BACKEND

Commands:
  build   Compile local declarations into exact profile packs
  check   Prove binding closure for explicit backends without touching the host

Ordinary machine customization does not require this tool. Use it only when
publishing changed catalogue definitions.`

	buildHelp = `Compile one schema-3 author document into an exact workspace.

Usage:
  proofstrap-pack build --input FILE --output DIR

Options:
  --input FILE    Readable schema-3 author document
  --output DIR    Absent destination workspace

Behavior:
  Reads imported packs only from packs/ beside FILE, promotes local declarations
  into .pstrap objects, proves equivalent resolved meaning, and atomically
  publishes DIR without replacement.

Output:
  Prints the generated proofstrap.toml path to stdout. The author input is never
  rewritten and no digest is inserted into it.

Example:
  proofstrap-pack build --input ./linux.toml --output ./dist`

	checkHelp = `Prove that a workspace closes under explicit package and service backends.

Usage:
  proofstrap-pack check --input FILE --package-backend BACKEND --service-backend BACKEND

The command reads packs/ beside FILE, performs no host detection or mutation,
prints nothing on success, and reports every canonical projection blocker.`
)

type buildFunc func(context.Context, string, string) (string, error)
type checkFunc func(context.Context, string, string, string) error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, packbuild.Build, packbuild.Check, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, build buildFunc, check checkFunc, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		fmt.Fprintln(stdout, rootHelp)
		return 0
	}
	if len(arguments) == 2 && arguments[0] == "build" && arguments[1] == "--help" {
		fmt.Fprintln(stdout, buildHelp)
		return 0
	}
	if len(arguments) == 2 && arguments[0] == "check" && arguments[1] == "--help" {
		fmt.Fprintln(stdout, checkHelp)
		return 0
	}
	if values, ok := parse(arguments, "check", "--input", "--package-backend", "--service-backend"); ok {
		return report(check(ctx, values[0], values[1], values[2]), stderr)
	}
	values, ok := parse(arguments, "build", "--input", "--output")
	if !ok {
		fmt.Fprintln(stderr, "invalid arguments")
		fmt.Fprintln(stderr, usage)
		fmt.Fprintln(stderr, "Try 'proofstrap-pack --help'.")
		return 2
	}
	config, err := build(ctx, values[0], values[1])
	if err != nil {
		return report(err, stderr)
	}
	if _, err := fmt.Fprintln(stdout, config); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func report(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var blocked *binding.Blocked
	if errors.As(err, &blocked) {
		for _, item := range blocked.Blockers() {
			fmt.Fprintf(stderr, "%s %s backend=%s semantic=%s native=%s sources=%s: %s\n",
				item.Kind, item.Domain, item.Backend, item.Semantic, item.Native, strings.Join(item.Sources, ","), item.Detail)
		}
	} else {
		fmt.Fprintln(stderr, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 130
	}
	return 1
}

func parse(arguments []string, command string, flags ...string) ([]string, bool) {
	if len(arguments) != 1+2*len(flags) || arguments[0] != command {
		return nil, false
	}
	values := make([]string, len(flags))
	for index := 1; index < len(arguments); index += 2 {
		matched := false
		for slot, flag := range flags {
			if arguments[index] == flag && values[slot] == "" {
				values[slot], matched = arguments[index+1], true
				break
			}
		}
		if !matched {
			return nil, false
		}
	}
	for slot, value := range values {
		if value == "" || strings.ContainsRune(value, 0) {
			return nil, false
		}
		if flags[slot] == "--input" || flags[slot] == "--output" {
			absolute, err := filepath.Abs(value)
			if err != nil || absolute == string(filepath.Separator) {
				return nil, false
			}
			values[slot] = absolute
		}
	}
	return values, true
}
