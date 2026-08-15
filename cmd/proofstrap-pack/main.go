package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

const usage = "usage: proofstrap-pack build --input ABSOLUTE_DIR --output ABSOLUTE_FILE"

type buildFunc func(context.Context, string, string) (pack.Digest, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, packbuild.Build, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, build buildFunc, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(arguments) == 0 || arguments[0] != "build" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if len(arguments) == 2 && (arguments[1] == "--help" || arguments[1] == "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if countFlag(arguments[1:], "--input") != 1 || countFlag(arguments[1:], "--output") != 1 {
		fmt.Fprintln(stderr, "input and output are required exactly once")
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "absolute authoring directory")
	output := flags.String("output", "", "absolute output archive")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, "invalid arguments")
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *input == "" || *output == "" || len(flags.Args()) != 0 {
		fmt.Fprintln(stderr, "input and output are required exactly once")
		fmt.Fprintln(stderr, usage)
		return 2
	}
	digest, err := build(ctx, *input, *output)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, digest.String()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func countFlag(arguments []string, name string) int {
	count := 0
	for _, argument := range arguments {
		if argument == name || len(argument) > len(name) && argument[:len(name)+1] == name+"=" {
			count++
		}
	}
	return count
}
