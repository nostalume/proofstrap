package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/pack"
)

func TestRunInventoryCanonicalizesRelativeArchivePaths(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	want := filepath.Join(directory, "packs", "custom.pstrap")
	called := []string{}
	commands := inventoryCommands{
		importUser: func(_ context.Context, _ inventory.Environment, path string, _ *pack.Digest) (inventory.Record, error) {
			called = append(called, "import:"+path)
			return inventory.Record{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
		},
		inspectArchive: func(_ context.Context, path string, _ *pack.Digest) (inventory.Record, error) {
			called = append(called, "inspect:"+path)
			return inventory.Record{Description: pack.Description{Digest: digest, Kind: pack.Semantic}}, nil
		},
	}
	for _, arguments := range [][]string{
		{"import", "packs/../packs/custom.pstrap"},
		{"import", "--digest", digest.String(), "packs/../packs/custom.pstrap"},
		{"inspect", "packs/custom.pstrap"},
		{"inspect", "--digest", digest.String(), "packs/custom.pstrap"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, arguments, &stdout, &stderr); code != 0 {
			t.Fatalf("%v: code=%d stderr=%q", arguments, code, stderr.String())
		}
	}
	if wantCalls := []string{"import:" + want, "import:" + want, "inspect:" + want, "inspect:" + want}; !reflect.DeepEqual(called, wantCalls) {
		t.Fatalf("calls = %v, want %v", called, wantCalls)
	}
}

func TestRunInventoryExactGrammarAndJSON(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	called := ""
	commands := inventoryCommands{
		importUser: func(_ context.Context, environment inventory.Environment, path string, got *pack.Digest) (inventory.Record, error) {
			called = "import-user:" + environment.Home + ":" + path + ":" + got.String()
			return inventory.Record{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
		},
		inspectStored: func(_ context.Context, _ inventory.Environment, got *pack.Digest) ([]inventory.Record, error) {
			called = "inspect-stored"
			if got == nil || *got != digest {
				t.Fatalf("digest = %v", got)
			}
			return []inventory.Record{{Description: pack.Description{
				Digest: digest, Kind: pack.Semantic,
				Requirements: []pack.Requirement{{Handle: "core", Digest: digest}},
				Members:      []string{"profiles/base.toml"},
			}, Scopes: []string{"release", "user"}}}, nil
		},
	}
	environment := inventory.Environment{Home: "/home/alice"}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{inventory: environment}, commands, applicationCommands{}, []string{"inspect", digest.String()}, &stdout, &stderr)
	want := "[\n  {\n    \"digest\": \"" + digest.String() + "\",\n    \"kind\": \"semantic\",\n    \"requirements\": [\n      {\n        \"handle\": \"core\",\n        \"digest\": \"" + digest.String() + "\"\n      }\n    ],\n    \"members\": [\n      \"profiles/base.toml\"\n    ],\n    \"scopes\": [\n      \"release\",\n      \"user\"\n    ]\n  }\n]\n"
	if code != 0 || called != "inspect-stored" || stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf("inspect code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := runCommand(context.Background(), processEnvironment{inventory: environment}, commands, applicationCommands{}, []string{"import", "--digest", digest.String(), "/tmp/custom.pstrap"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"scopes": [`) || !strings.Contains(stdout.String(), `"user"`) || !strings.HasPrefix(called, "import-user:/home/alice:/tmp/custom.pstrap:") {
		t.Fatalf("import code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunInventoryInvalidGrammarDoesNotInvokeOperations(t *testing.T) {
	called := false
	commands := inventoryCommands{importUser: func(context.Context, inventory.Environment, string, *pack.Digest) (inventory.Record, error) {
		called = true
		return inventory.Record{}, nil
	}}
	for _, arguments := range [][]string{
		{"import"},
		{"import", "--digest", "sha256:" + strings.Repeat("1", 64)},
		{"import", "--digest", "bad", "/tmp/a"},
		{"inspect", "--digest", "sha256:" + strings.Repeat("1", 64)},
		{"inspect", "--", "sha256:" + strings.Repeat("1", 64)},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("invalid grammar invoked inventory")
	}
}

func TestRunInventoryHelpDoesNotInvokeOperations(t *testing.T) {
	called := false
	commands := inventoryCommands{inspectStored: func(context.Context, inventory.Environment, *pack.Digest) ([]inventory.Record, error) {
		called = true
		return nil, nil
	}}
	for _, arguments := range [][]string{{"--help"}, {"import", "--help"}, {"inspect", "--help"}} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, arguments, &stdout, &stderr); code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("help invoked inventory")
	}
}

func TestRunInventoryOperationFailuresAndEmptyJSON(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	commands := inventoryCommands{inspectStored: func(context.Context, inventory.Environment, *pack.Digest) ([]inventory.Record, error) {
		return []inventory.Record{}, nil
	}}
	var stdout, stderr bytes.Buffer
	if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect"}, &stdout, &stderr); code != 0 || stdout.String() != "[]\n" || stderr.Len() != 0 {
		t.Fatalf("empty = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	commands.inspectStored = func(context.Context, inventory.Environment, *pack.Digest) ([]inventory.Record, error) {
		return nil, errors.New("failure")
	}
	stdout.Reset()
	if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect", digest.String()}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("failure = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	commands.inspectStored = func(context.Context, inventory.Environment, *pack.Digest) ([]inventory.Record, error) {
		return nil, context.Canceled
	}
	stderr.Reset()
	if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect", digest.String()}, &stdout, &stderr); code != 130 || stdout.Len() != 0 {
		t.Fatalf("canceled = %d, %q, %q", code, stdout.String(), stderr.String())
	}
}

func TestRunImportReportsOutputFailureAfterPublication(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	published := false
	commands := inventoryCommands{importUser: func(_ context.Context, _ inventory.Environment, _ string, expected *pack.Digest) (inventory.Record, error) {
		published = true
		if expected != nil {
			t.Fatal("digest-free import supplied an expectation")
		}
		return inventory.Record{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
	}}
	sentinel := errors.New("broken stdout")
	var stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"import", "/tmp/a"}, cutoverFailWriter{sentinel}, &stderr)
	if code != 1 || !published || !strings.Contains(stderr.String(), sentinel.Error()) {
		t.Fatalf("code=%d published=%t stderr=%q", code, published, stderr.String())
	}
}

func TestEncodeRecordsEnforcesJSONLimit(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	record := inventory.Record{Description: pack.Description{
		Digest: digest, Kind: pack.Semantic,
		Requirements: []pack.Requirement{}, Members: []string{strings.Repeat("x", maxInspectJSON)},
	}, Scopes: []string{}}
	if encoded, err := encodeRecords([]inventory.Record{record}); encoded != nil || err == nil {
		t.Fatalf("oversize JSON = %d bytes, %v", len(encoded), err)
	}
}
