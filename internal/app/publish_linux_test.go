package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishPlanIsPrivateDurableNoReplaceAndResidueFree(t *testing.T) {
	plan, err := seal(body{operations: []operation{{id: "host:hostname:persistence", kind: "host", review: []byte(`{"axis":"persistence"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "plan.json")
	receipt, err := PublishPlan(path, plan)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Path() != path || receipt.Digest() != plan.Digest() {
		t.Fatalf("receipt = %#v", receipt)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, plan.Bytes()) {
		t.Fatalf("published bytes = %s, %v", data, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %o", info.Mode().Perm())
	}
	if _, err := PublishPlan(path, plan); !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision = %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 || entries[0].Name() != "plan.json" {
		t.Fatalf("publication residue = %#v", entries)
	}
}

func TestPublishPlanRejectsUnsafeTargetsWithoutOverwrite(t *testing.T) {
	plan, err := seal(body{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	out := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(out, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "plan.json")
	if err := os.Symlink(out, target); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishPlan(target, plan); !errors.Is(err, os.ErrExist) {
		t.Fatalf("symlink collision = %v", err)
	}
	data, _ := os.ReadFile(out)
	if string(data) != "safe" {
		t.Fatalf("outside target changed: %q", data)
	}
	if _, err := PublishPlan("relative.json", plan); err == nil {
		t.Fatal("relative output admitted")
	}
}

func TestRenderPlanUsesTheSealedBodyWithoutRecomputation(t *testing.T) {
	plan, err := seal(body{operations: []operation{
		{id: "package:zypper", kind: "package", review: []byte(`{"backend":"zypper"}`)},
		{id: "service:agent", kind: "service", dependencies: []string{"package:zypper"}, review: []byte(`{"unit":"agent.service"}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text, err := RenderPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"status: applicable", "digest: " + plan.Digest().String(), "checkpoints: 3", "package:zypper", "service:agent <- package:zypper"} {
		if !strings.Contains(text, want) {
			t.Fatalf("render missing %q:\n%s", want, text)
		}
	}
}
