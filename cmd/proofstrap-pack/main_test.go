package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestRunBuildPrintsOnlyDigest(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	called := false
	build := func(_ context.Context, input, output string) (pack.Digest, error) {
		called = input == filepath.Join(directory, "input") && output == filepath.Join(directory, "output.pstrap")
		return digest, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "input", "--output", "output.pstrap"}, &stdout, &stderr)
	if code != 0 || !called || stdout.String() != digest.String()+"\n" || stderr.Len() != 0 {
		t.Fatalf("run = %d, called=%v, stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunGrammarAndHelp(t *testing.T) {
	called := false
	build := func(context.Context, string, string) (pack.Digest, error) { called = true; return pack.Digest{}, nil }
	for _, test := range []struct {
		name   string
		args   []string
		code   int
		stdout bool
	}{
		{"help", []string{"--help"}, 0, true},
		{"build-help", []string{"build", "--help"}, 0, true},
		{"missing", []string{"build", "--input", "/input"}, 2, false},
		{"duplicate", []string{"build", "--input", "/one", "--input", "/two", "--output", "/output"}, 2, false},
		{"short help", []string{"-h"}, 2, false}, {"short flag", []string{"build", "-input", "/input", "--output", "/output"}, 2, false},
		{"equal form", []string{"build", "--input=/input", "--output=/output"}, 2, false}, {"abbreviated", []string{"build", "--in", "/input", "--output", "/output"}, 2, false},
		{"empty", []string{"build", "--input", "", "--output", "/output"}, 2, false}, {"NUL", []string{"build", "--input", "in\x00put", "--output", "/output"}, 2, false},
		{"root", []string{"build", "--input", "/", "--output", "/output"}, 2, false}, {"extra", []string{"build", "--input", "/input", "--output", "/output", "extra"}, 2, false},
		{"unknown", []string{"unknown"}, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), build, test.args, &stdout, &stderr); code != test.code {
				t.Fatalf("code = %d", code)
			}
			if test.stdout != (stdout.Len() > 0) {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
	if called {
		t.Fatal("invalid grammar invoked builder")
	}
}

func TestRunBuildRelativeAndAbsolutePathsProduceSameBytes(t *testing.T) {
	input, _ := filepath.Abs("../../internal/packbuild/testdata/deterministic/input")
	directory := t.TempDir()
	relativeInput, _ := filepath.Rel(directory, input)
	t.Chdir(directory)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), packbuild.Build, []string{"build", "--input", relativeInput, "--output", "relative.pstrap"}, &stdout, &stderr); code != 0 {
		t.Fatalf("relative build: code=%d stderr=%q", code, stderr.String())
	}
	relative, _ := os.ReadFile("relative.pstrap")
	digest := stdout.String()
	stdout.Reset()
	stderr.Reset()
	absolutePath := filepath.Join(directory, "absolute.pstrap")
	if code := run(context.Background(), packbuild.Build, []string{"build", "--input", input, "--output", absolutePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("absolute build: code=%d stderr=%q", code, stderr.String())
	}
	absolute, _ := os.ReadFile(absolutePath)
	if !bytes.Equal(relative, absolute) || stdout.String() != digest {
		t.Fatal("relative and absolute builds differ")
	}
}

func TestRunCancellation(t *testing.T) {
	build := func(context.Context, string, string) (pack.Digest, error) { return pack.Digest{}, context.Canceled }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "/input", "--output", "/output"}, &stdout, &stderr)
	if code != 130 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("run = %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
