package linuxexec_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/linuxexec"
)

const captureLimit = 8 << 20

func identify(t *testing.T, path string) linuxexec.Identity {
	t.Helper()
	identity, err := linuxexec.Identify(path)
	if err != nil {
		t.Fatalf("Identify(%q): %v", path, err)
	}
	return identity
}

func deadlineContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestIdentifyReturnsCanonicalByteIdentity(t *testing.T) {
	candidate := "/bin/sh"
	wantPath, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}

	got := identify(t, candidate)
	if got.Path != wantPath || got.Digest != sha256.Sum256(wantBytes) {
		t.Fatalf("Identify(%q) = %#v, want path %q and matching digest", candidate, got, wantPath)
	}
}

func TestIdentifyRejectsRelativeAndUntrustedPaths(t *testing.T) {
	if _, err := linuxexec.Identify("bin/sh"); err == nil {
		t.Fatal("relative executable admitted")
	}

	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := linuxexec.Identify(path); err == nil {
		t.Fatal("executable below untrusted parent admitted")
	}
	if _, err := linuxexec.Identify("/etc/passwd"); err == nil {
		t.Fatal("root-owned non-executable admitted")
	}
}

func TestRunPassesArgumentsAndInputLiterally(t *testing.T) {
	printf := identify(t, "/usr/bin/printf")
	result, err := linuxexec.Run(deadlineContext(t), printf, []string{"%s", "$HOME;*"}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 || string(result.Stdout) != "$HOME;*" || len(result.Stderr) != 0 {
		t.Fatalf("printf result=%#v err=%v", result, err)
	}

	cat := identify(t, "/usr/bin/cat")
	result, err = linuxexec.Run(deadlineContext(t), cat, nil, []byte("first\nsecond\n"))
	if err != nil || !result.Started || result.ExitCode != 0 || string(result.Stdout) != "first\nsecond\n" {
		t.Fatalf("cat result=%#v err=%v", result, err)
	}
}

func TestRunUsesOnlyFixedEnvironment(t *testing.T) {
	t.Setenv("PROOFSTRAP_AMBIENT_TEST", "must-not-leak")
	result, err := linuxexec.Run(deadlineContext(t), identify(t, "/usr/bin/env"), nil, nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		t.Fatalf("env result=%#v err=%v", result, err)
	}
	lines := strings.Split(strings.TrimSpace(string(result.Stdout)), "\n")
	want := map[string]bool{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin": false,
		"LC_ALL=C":                           false,
	}
	for _, line := range lines {
		if _, ok := want[line]; !ok {
			t.Fatalf("unexpected child environment entry %q in %q", line, result.Stdout)
		}
		want[line] = true
	}
	for line, found := range want {
		if !found {
			t.Fatalf("child environment lacks %q: %q", line, result.Stdout)
		}
	}
}

func TestRunReturnsNormalNonzeroExitAsResult(t *testing.T) {
	result, err := linuxexec.Run(deadlineContext(t), identify(t, "/bin/sh"), []string{"-c", "printf disabled; exit 7"}, nil)
	if err != nil || !result.Started || result.ExitCode != 7 || string(result.Stdout) != "disabled" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRunRequiresDeadlineAndRejectsIdentityDriftBeforeStart(t *testing.T) {
	identity := identify(t, "/usr/bin/true")
	result, err := linuxexec.Run(context.Background(), identity, nil, nil)
	if err == nil || result.Started {
		t.Fatalf("deadline-free result=%#v err=%v", result, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	result, err = linuxexec.Run(ctx, identity, nil, nil)
	if !errors.Is(err, context.Canceled) || result.Started {
		t.Fatalf("canceled result=%#v err=%v", result, err)
	}

	identity.Digest[0] ^= 0xff
	result, err = linuxexec.Run(deadlineContext(t), identity, nil, nil)
	if !errors.Is(err, linuxexec.ErrIdentityChanged) || result.Started {
		t.Fatalf("drift result=%#v err=%v", result, err)
	}

	result, err = linuxexec.Run(deadlineContext(t), linuxexec.Identity{Path: "/proofstrap-missing-executable"}, nil, nil)
	if err == nil || errors.Is(err, linuxexec.ErrIdentityChanged) || result.Started {
		t.Fatalf("unavailable identity result=%#v err=%v", result, err)
	}
}

func TestRunTimeoutAndSignalArePostStartErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := linuxexec.Run(ctx, identify(t, "/bin/sh"), []string{"-c", "sleep 10 & wait"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !result.Started {
		t.Fatalf("timeout result=%#v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("process group remained alive for %v", elapsed)
	}

	result, err = linuxexec.Run(deadlineContext(t), identify(t, "/bin/sh"), []string{"-c", "kill -TERM $$"}, nil)
	if err == nil || !result.Started {
		t.Fatalf("signal result=%#v err=%v", result, err)
	}
}

func TestRunCaptureLimitIsExactAndOverflowFailsClosed(t *testing.T) {
	head := identify(t, "/usr/bin/head")
	result, err := linuxexec.Run(deadlineContext(t), head, []string{"-c", "8388608", "/dev/zero"}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stdout) != captureLimit {
		t.Fatalf("exact-limit bytes=%d result=%#v err=%v", len(result.Stdout), result, err)
	}

	result, err = linuxexec.Run(deadlineContext(t), head, []string{"-c", "8388609", "/dev/zero"}, nil)
	if !errors.Is(err, linuxexec.ErrOutputLimit) || !result.Started || len(result.Stdout) != captureLimit {
		t.Fatalf("overflow bytes=%d result=%#v err=%v", len(result.Stdout), result, err)
	}

	shell := identify(t, "/bin/sh")
	result, err = linuxexec.Run(deadlineContext(t), shell, []string{"-c", "head -c 8388609 /dev/zero >&2"}, nil)
	if !errors.Is(err, linuxexec.ErrOutputLimit) || !result.Started || len(result.Stderr) != captureLimit {
		t.Fatalf("stderr overflow bytes=%d result=%#v err=%v", len(result.Stderr), result, err)
	}
}
