package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/pack"
)

func TestRunBuildPrintsOnlyDigest(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	called := false
	build := func(_ context.Context, input, output string) (pack.Digest, error) {
		called = input == "/input" && output == "/output.pstrap"
		return digest, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "/input", "--output", "/output.pstrap"}, &stdout, &stderr)
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

func TestRunCancellation(t *testing.T) {
	build := func(context.Context, string, string) (pack.Digest, error) { return pack.Digest{}, context.Canceled }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), build, []string{"build", "--input", "/input", "--output", "/output"}, &stdout, &stderr)
	if code != 130 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("run = %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
