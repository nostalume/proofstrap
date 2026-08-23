package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/pack"
)

func TestRunArchivesCanonicalizesRelativePaths(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	want := filepath.Join(directory, "packs", "custom.pstrap")
	called := []string{}
	commands := archiveCommands{
		importUser: func(_ context.Context, _ processEnvironment, path string, _ *pack.Digest) (archiveRecord, error) {
			called = append(called, "import:"+path)
			return archiveRecord{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
		},
		inspectArchive: func(_ context.Context, path string, _ *pack.Digest) (archiveRecord, error) {
			called = append(called, "inspect:"+path)
			return archiveRecord{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{}}, nil
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

func TestRunArchivesExactGrammarAndJSON(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	called := ""
	commands := archiveCommands{
		importUser: func(_ context.Context, environment processEnvironment, path string, got *pack.Digest) (archiveRecord, error) {
			called = "import-user:" + environment.home + ":" + path + ":" + got.String()
			return archiveRecord{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
		},
		inspectArchive: func(_ context.Context, path string, got *pack.Digest) (archiveRecord, error) {
			called = "inspect:" + path
			if got == nil || *got != digest {
				t.Fatalf("digest = %v", got)
			}
			return archiveRecord{Description: pack.Description{
				Digest: digest, Kind: pack.Semantic,
				Requirements: []pack.Requirement{{Handle: "core", Digest: digest}},
				Members:      []string{"profiles/base.toml"},
			}, Scopes: []string{}}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect", "--digest", digest.String(), "/tmp/custom.pstrap"}, &stdout, &stderr)
	if code != 0 || !strings.HasPrefix(called, "inspect:") || !strings.Contains(stdout.String(), `"requirements": [`) || !strings.Contains(stdout.String(), `"scopes": []`) || stderr.Len() != 0 {
		t.Fatalf("inspect code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	stdout.Reset()
	code = runCommand(context.Background(), processEnvironment{home: "/home/alice"}, commands, applicationCommands{}, []string{"import", "--digest", digest.String(), "/tmp/custom.pstrap"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"user"`) || !strings.HasPrefix(called, "import-user:/home/alice:") {
		t.Fatalf("import code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunArchivesInvalidGrammarDoesNotInvokeOperations(t *testing.T) {
	called := false
	commands := archiveCommands{importUser: func(context.Context, processEnvironment, string, *pack.Digest) (archiveRecord, error) {
		called = true
		return archiveRecord{}, nil
	}}
	for _, arguments := range [][]string{
		{"import"}, {"import", "--digest", "sha256:" + strings.Repeat("1", 64)}, {"import", "--digest", "bad", "/tmp/a"},
		{"inspect"}, {"inspect", "sha256:" + strings.Repeat("1", 64)}, {"inspect", "--digest", "sha256:" + strings.Repeat("1", 64)}, {"inspect", "--", "/tmp/a"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("invalid grammar invoked archive operation")
	}
}

func TestRunArchivesHelpDoesNotInvokeOperations(t *testing.T) {
	called := false
	commands := archiveCommands{inspectArchive: func(context.Context, string, *pack.Digest) (archiveRecord, error) {
		called = true
		return archiveRecord{}, nil
	}}
	for _, arguments := range [][]string{{"--help"}, {"import", "--help"}, {"inspect", "--help"}} {
		var stdout, stderr bytes.Buffer
		if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, arguments, &stdout, &stderr); code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("help invoked archive operation")
	}
}

func TestRunInspectMapsFailureAndCancellation(t *testing.T) {
	commands := archiveCommands{inspectArchive: func(context.Context, string, *pack.Digest) (archiveRecord, error) {
		return archiveRecord{}, errors.New("failure")
	}}
	var stdout, stderr bytes.Buffer
	if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect", "/tmp/a"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("failure = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	commands.inspectArchive = func(context.Context, string, *pack.Digest) (archiveRecord, error) {
		return archiveRecord{}, context.Canceled
	}
	stderr.Reset()
	if code := runCommand(context.Background(), processEnvironment{}, commands, applicationCommands{}, []string{"inspect", "/tmp/a"}, &stdout, &stderr); code != 130 || stdout.Len() != 0 {
		t.Fatalf("canceled = %d, %q, %q", code, stdout.String(), stderr.String())
	}
}

func TestRunImportReportsOutputFailureAfterPublication(t *testing.T) {
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	published := false
	commands := archiveCommands{importUser: func(_ context.Context, _ processEnvironment, _ string, expected *pack.Digest) (archiveRecord, error) {
		published = true
		if expected != nil {
			t.Fatal("digest-free import supplied an expectation")
		}
		return archiveRecord{Description: pack.Description{Digest: digest, Kind: pack.Semantic}, Scopes: []string{"user"}}, nil
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
	record := archiveRecord{Description: pack.Description{Digest: digest, Kind: pack.Semantic, Requirements: []pack.Requirement{}, Members: []string{strings.Repeat("x", maxInspectJSON)}}, Scopes: []string{}}
	if encoded, err := encodeRecords([]archiveRecord{record}); encoded != nil || err == nil {
		t.Fatalf("oversize JSON = %d bytes, %v", len(encoded), err)
	}
}
