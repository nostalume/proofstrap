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

	"github.com/nostalume/proofstrap/internal/packbuild"
)

const (
	usage = "usage: proofstrap-pack build --input FILE --output DIR"

	rootHelp = `Build deterministic Proofstrap workspaces for distribution.

Usage:
  proofstrap-pack build --input FILE --output DIR

Commands:
  build   Compile local declarations into exact profile packs

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
)

type buildFunc func(context.Context, string, string) (string, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, packbuild.Build, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, build buildFunc, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		fmt.Fprintln(stdout, rootHelp)
		return 0
	}
	if len(arguments) == 2 && arguments[0] == "build" && arguments[1] == "--help" {
		fmt.Fprintln(stdout, buildHelp)
		return 0
	}
	input, output, ok := parseBuild(arguments)
	if !ok {
		fmt.Fprintln(stderr, "invalid arguments")
		fmt.Fprintln(stderr, usage)
		fmt.Fprintln(stderr, "Try 'proofstrap-pack build --help'.")
		return 2
	}
	config, err := build(ctx, input, output)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, config); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseBuild(arguments []string) (input, output string, ok bool) {
	if len(arguments) != 5 || arguments[0] != "build" {
		return "", "", false
	}
	for index := 1; index < len(arguments); index += 2 {
		switch arguments[index] {
		case "--input":
			input = arguments[index+1]
		case "--output":
			output = arguments[index+1]
		default:
			return "", "", false
		}
	}
	for _, target := range []*string{&input, &output} {
		absolute, err := filepath.Abs(*target)
		if *target == "" || strings.ContainsRune(*target, 0) || err != nil || absolute == string(filepath.Separator) {
			return "", "", false
		}
		*target = absolute
	}
	return input, output, true
}
