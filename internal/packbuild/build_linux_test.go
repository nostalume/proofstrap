package packbuild

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

func TestBuildIsDeterministic(t *testing.T) {
	input := semanticTree(t)
	left := filepath.Join(t.TempDir(), "left.pstrap")
	right := filepath.Join(t.TempDir(), "right.pstrap")
	leftDigest, err := Build(context.Background(), input, left)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(input, "manifest.toml"), time.Unix(10, 0), time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(input, "profiles", "base.toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	rightDigest, err := Build(context.Background(), input, right)
	if err != nil {
		t.Fatal(err)
	}
	leftBytes, _ := os.ReadFile(left)
	rightBytes, _ := os.ReadFile(right)
	if leftDigest != rightDigest || !bytes.Equal(leftBytes, rightBytes) {
		t.Fatal("metadata changed deterministic artifact")
	}
	source, err := pack.Read(context.Background(), bytes.NewReader(leftBytes))
	if err != nil || source.Digest() != leftDigest || source.Kind() != pack.Semantic {
		t.Fatalf("built archive = %#v, %v", source, err)
	}
	info, _ := os.Stat(left)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("output mode = %o", info.Mode().Perm())
	}
}

func TestCreateStageHasBoundedDeterministicCollisions(t *testing.T) {
	parent := t.TempDir()
	fd, err := linux.OpenDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	token := bytes.Repeat([]byte{0x2a}, 16)
	name := ".proofstrap-pack-" + strings.Repeat("2a", 16)
	if err := os.WriteFile(filepath.Join(parent, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if stageFD, _, err := linux.CreateStageAt(fd, bytes.NewReader(bytes.Repeat(token, 16)), ".proofstrap-pack-"); err == nil || stageFD >= 0 {
		t.Fatalf("sixteen collisions = fd %d, error %v", stageFD, err)
	}
	available := bytes.Repeat([]byte{0x2b}, 16)
	stageFD, stageName, err := linux.CreateStageAt(fd, io.MultiReader(bytes.NewReader(token), bytes.NewReader(available)), ".proofstrap-pack-")
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stageFD)
	defer os.Remove(filepath.Join(parent, stageName))
	if stageName != ".proofstrap-pack-"+strings.Repeat("2b", 16) {
		t.Fatalf("stage name = %q", stageName)
	}
}

func TestBuildMatchesReviewedFixture(t *testing.T) {
	input, err := filepath.Abs(filepath.Join("testdata", "deterministic", "input"))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "actual.pstrap")
	digest, err := Build(context.Background(), input, output)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := pack.ParseDigest("sha256:b9d9b008b71a2a42f7e9b19e490817e4bd590db074b116d2449f68a893b4f30b")
	actual, _ := os.ReadFile(output)
	expected, err := os.ReadFile(filepath.Join("testdata", "deterministic", "expected.pstrap"))
	if err != nil {
		t.Fatal(err)
	}
	if digest != wantDigest || !bytes.Equal(actual, expected) {
		t.Fatalf("fixture drift: digest=%s bytes_equal=%v", digest, bytes.Equal(actual, expected))
	}
	for name, data := range map[string][]byte{"actual": actual, "expected": expected} {
		source, err := pack.Read(context.Background(), bytes.NewReader(data))
		if err != nil || source.Digest() != wantDigest {
			t.Fatalf("%s fixture admission = %#v, %v", name, source, err)
		}
	}
}

func TestBuildBindingTree(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bindings"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.toml"), []byte("schema=1\nkind='binding'\nrequires={core='sha256:"+strings.Repeat("1", 64)+"'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bindings", "base.toml"), []byte("[package.test]\n'core:base'=['base']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "binding.pstrap")
	digest, err := Build(context.Background(), root, output)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(output)
	source, err := pack.Read(context.Background(), bytes.NewReader(data))
	if err != nil || source.Digest() != digest || source.Kind() != pack.Binding {
		t.Fatalf("binding build = %#v, %v", source, err)
	}
}

func TestBuildIsAbsentOnlyAndFailClosed(t *testing.T) {
	input := semanticTree(t)
	output := filepath.Join(t.TempDir(), "pack.pstrap")
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if digest, err := Build(context.Background(), input, output); digest != (pack.Digest{}) || errorCategory(t, err) != OutputExists {
		t.Fatalf("existing output = %v, %v", digest, err)
	}
	data, _ := os.ReadFile(output)
	if string(data) != "keep" {
		t.Fatal("existing output changed")
	}
	if err := os.WriteFile(filepath.Join(input, ".hidden"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.pstrap")
	if digest, err := Build(context.Background(), input, missing); digest != (pack.Digest{}) || errorCategory(t, err) != InvalidInput {
		t.Fatalf("unknown input = %v, %v", digest, err)
	}
}

func TestBuildRejectsInvalidPathsWithoutPublication(t *testing.T) {
	input := semanticTree(t)
	for _, test := range []struct {
		name   string
		input  string
		output string
	}{
		{"relative-input", "relative", filepath.Join(t.TempDir(), "pack.pstrap")},
		{"unclean-input", input + string(filepath.Separator) + ".", filepath.Join(t.TempDir(), "pack.pstrap")},
		{"root-input", string(filepath.Separator), filepath.Join(t.TempDir(), "pack.pstrap")},
		{"relative-output", input, "pack.pstrap"},
		{"output-inside-input", input, filepath.Join(input, "pack.pstrap")},
		{"missing-output-parent", input, filepath.Join(t.TempDir(), "missing", "pack.pstrap")},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest, err := Build(context.Background(), test.input, test.output)
			if digest != (pack.Digest{}) || err == nil {
				t.Fatalf("Build = %v, %v", digest, err)
			}
			if filepath.IsAbs(test.output) {
				if _, statErr := os.Lstat(test.output); !os.IsNotExist(statErr) {
					t.Fatalf("failed Build published output: %v", statErr)
				}
			}
		})
	}
}

func TestBuildRejectsWrongTreeShapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"wrong-kind-directory", func(t *testing.T, root string) {
			mustRename(t, filepath.Join(root, "profiles"), filepath.Join(root, "bindings"))
		}},
		{"empty-content", func(t *testing.T, root string) {
			mustRemove(t, filepath.Join(root, "profiles", "base.toml"))
		}},
		{"nested-content", func(t *testing.T, root string) {
			mustRemove(t, filepath.Join(root, "profiles", "base.toml"))
			if err := os.Mkdir(filepath.Join(root, "profiles", "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid-content-name", func(t *testing.T, root string) {
			mustRename(t, filepath.Join(root, "profiles", "base.toml"), filepath.Join(root, "profiles", ".base.toml"))
		}},
		{"backup-entry", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "profiles", "base.toml~"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := semanticTree(t)
			test.mutate(t, root)
			output := filepath.Join(t.TempDir(), "pack.pstrap")
			digest, err := Build(context.Background(), root, output)
			if digest != (pack.Digest{}) || err == nil {
				t.Fatalf("Build = %v, %v", digest, err)
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatalf("failed Build published output: %v", statErr)
			}
		})
	}
}

func TestBuildContentLimitIsExact(t *testing.T) {
	root := semanticTree(t)
	path := filepath.Join(root, "profiles", "base.toml")
	prefix := []byte("[profiles.base]\npackages=['base']\n")
	exact := append(prefix, bytes.Repeat([]byte("\n"), maxContent-len(prefix))...)
	if err := os.WriteFile(path, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), root, filepath.Join(t.TempDir(), "exact.pstrap")); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	if err := os.WriteFile(path, append(exact, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "oversize.pstrap")
	if digest, err := Build(context.Background(), root, output); digest != (pack.Digest{}) || errorCategory(t, err) != InvalidInput {
		t.Fatalf("max+1 = %v, %v", digest, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("oversize input published output: %v", err)
	}
}

func TestBuildCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	digest, err := Build(ctx, semanticTree(t), filepath.Join(t.TempDir(), "pack.pstrap"))
	if digest != (pack.Digest{}) || !errors.Is(err, context.Canceled) || errorCategory(t, err) != Canceled {
		t.Fatalf("canceled Build = %v, %v", digest, err)
	}
}

func TestBuildRejectsSymlinkAndHardLinkedInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, root string) {
			path := filepath.Join(root, "profiles", "base.toml")
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("base.toml.real", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, root string) {
			path := filepath.Join(root, "profiles", "base.toml")
			if err := os.Link(path, filepath.Join(root, "profiles", "other.toml")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := semanticTree(t)
			test.mutate(t, root)
			output := filepath.Join(t.TempDir(), "output.pstrap")
			if digest, err := Build(context.Background(), root, output); digest != (pack.Digest{}) || err == nil {
				t.Fatalf("Build = %v, %v", digest, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failed Build published output: %v", err)
			}
		})
	}
}

func semanticTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.toml"), []byte("schema=1\nkind='semantic'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "profiles", "base.toml"), []byte("[profiles.base]\npackages=['base']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustRename(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func errorCategory(t *testing.T, err error) Category {
	t.Helper()
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatalf("error = %T, want Diagnostic", err)
	}
	return diagnostic.Category
}
