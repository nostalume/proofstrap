package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/document"
	"github.com/nostalume/proofstrap/internal/pack"
)

func BenchmarkBuildPlanDirect(b *testing.B) {
	request := Request{Origin: "benchmark", Config: []byte("schema=3\ninclude=[{profile='x'}]\n[profiles.x]\npackages=['x']\n[package.flatpak]\nx=['x']\n")}
	benchmarkBuildPlan(b, request)
}

func BenchmarkComposeProfile(b *testing.B) {
	output := b.TempDir()
	corePath := filepath.Join(output, "core.pstrap")
	linuxPath := filepath.Join(output, "linux.pstrap")
	core := buildInlineSemanticAt(b, filepath.Join(output, "core"), corePath,
		"[profiles.curl]\npackages=['curl']\n")
	bindingRoot := filepath.Join(output, "linux")
	if err := os.MkdirAll(filepath.Join(bindingRoot, "bindings"), 0o755); err != nil {
		b.Fatal(err)
	}
	manifest := fmt.Sprintf("schema=1\nkind='binding'\n[requires]\ncore=%q\n", core.Digest())
	if err := os.WriteFile(filepath.Join(bindingRoot, "manifest.toml"), []byte(manifest), 0o644); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindingRoot, "bindings", "linux.toml"),
		[]byte("[package.zypper]\n'core:curl'=['curl']\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	linux := buildAppSource(b, bindingRoot, linuxPath)
	configData := fmt.Sprintf("schema = 3\nbindings = [\"linux\"]\ninclude = [{ profile = \"core:curl\" }]\n[sources]\ncore = %q\nlinux = %q\n", core.Digest(), linux.Digest())
	target, err := document.Decode("benchmark", []byte(configData))
	if err != nil {
		b.Fatal(err)
	}
	backend, _ := binding.NewPackageBackendID("zypper")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := compose(ctx, target, []pack.Source{core, linux}, binding.Backends{Package: backend})
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
