package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nostalume/proofstrap/internal/packbuild"
)

func TestRunBuildPrintsOnlyGeneratedConfig(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	config := filepath.Join(directory, "dist", "proofstrap.toml")
	called := false
	build := func(_ context.Context, input, output string) (string, error) {
		called = input == filepath.Join(directory, "input.toml") && output == filepath.Join(directory, "dist")
		return config, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "input.toml", "--output", "dist"}, &stdout, &stderr)
	if code != 0 || !called || stdout.String() != config+"\n" || stderr.Len() != 0 {
		t.Fatalf("run = %d, called=%v, stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunGrammarAndHelp(t *testing.T) {
	called := false
	build := func(context.Context, string, string) (string, error) { called = true; return "", nil }
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

func TestRunBuildRelativeInputAndOutput(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	if err := os.WriteFile("input.toml", []byte("schema=3\nhostname='host'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), packbuild.Build, []string{"build", "--input", "input.toml", "--output", "dist"}, &stdout, &stderr); code != 0 {
		t.Fatalf("relative build: code=%d stderr=%q", code, stderr.String())
	}
	if stdout.String() != filepath.Join(directory, "dist", "proofstrap.toml")+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunCancellation(t *testing.T) {
	build := func(context.Context, string, string) (string, error) { return "", context.Canceled }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "/input", "--output", "/output"}, &stdout, &stderr)
	if code != 130 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("run = %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
