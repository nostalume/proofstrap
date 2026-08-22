package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/document"
)

func BenchmarkBuildPlanDirect(b *testing.B) {
	target, err := document.Decode("benchmark", []byte("schema=3\ninclude=[{profile='x'}]\n[profiles.x]\npackages=['x']\n[package.flatpak]\nx=['x']\n"))
	if err != nil {
		b.Fatal(err)
	}
	request := Request{Document: target}
	benchmarkBuildPlan(b, request)
}

func BenchmarkComposeProfile(b *testing.B) {
	target, err := document.Decode("benchmark", []byte("schema=3\ninclude=[{profile='curl'}]\n[profiles.curl]\npackages=['curl']\n[package.zypper]\ncurl=['curl']\n"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, _, err := document.Resolve(ctx, target, nil)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkBuildPlan(b *testing.B, request Request) {
	b.Helper()
	b.ReportAllocs()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := BuildPlan(ctx, request)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyNoop(b *testing.B) {
	plan, err := seal(body{})
	if err != nil {
		b.Fatal(err)
	}
	planPath := filepath.Join(b.TempDir(), "plan.json")
	if _, err := PublishPlan(planPath, plan); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := Apply(ctx, ApplyRequest{
			PlanPath: planPath, Accept: plan.Digest(),
			EffectiveUID: uint32(os.Geteuid()), Output: io.Discard,
		})
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}
