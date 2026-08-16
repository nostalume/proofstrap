package packages

import (
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/linux"
)

func TestNativeDiagnosticIsCanonicalText(t *testing.T) {
	result := linux.Result{Started: true, ExitCode: 1, Stderr: []byte("first\n  second\tthird \xff")}
	const want = "probe: native exit 1: first second third �"
	if got := nativeDiagnostic("probe", result, nil); got != want {
		t.Fatalf("native diagnostic = %q, want %q", got, want)
	}
}

func TestNativeDiagnosticPreservesBoundedFailureTail(t *testing.T) {
	result := linux.Result{Started: true, ExitCode: 4, Stdout: append(make([]byte, 5000), []byte("final failure\n")...)}
	got := nativeDiagnostic("commit", result, nil)
	if !strings.Contains(got, "final failure") || len(got) > 900 {
		t.Fatalf("native diagnostic lost bounded tail: len=%d text=%q", len(got), got)
	}
}
