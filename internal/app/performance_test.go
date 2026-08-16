package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/packbuild"
)

func BenchmarkBuildPlanDirect(b *testing.B) {
	request := Request{Origin: "benchmark", Config: []byte("schema = 1\npackages = [\"flatpak:x\"]\n")}
	benchmarkBuildPlan(b, request)
}

func BenchmarkBuildPlanProfile(b *testing.B) {
	root, err := filepath.Abs(filepath.Join("..", "..", "profiles"))
	if err != nil {
		b.Fatal(err)
	}
	output := b.TempDir()
	corePath := filepath.Join(output, "core.pstrap")
	linuxPath := filepath.Join(output, "linux.pstrap")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	core, err := packbuild.Build(ctx, filepath.Join(root, "core"), corePath)
	if err != nil {
		b.Fatal(err)
	}
	linux, err := packbuild.Build(ctx, filepath.Join(root, "linux"), linuxPath)
	if err != nil {
		b.Fatal(err)
	}
	config := fmt.Sprintf("schema = 1\nbindings = [\"linux\"]\nprofiles = [{ profile = \"core:curl\" }]\n[sources]\ncore = %q\nlinux = %q\n", core, linux)
	benchmarkBuildPlan(b, Request{
		Origin: "benchmark", Config: []byte(config),
		Environment: inventory.Environment{}, Bundles: []string{corePath, linuxPath},
	})
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
