package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptVerifiesReleaseBeforeInstalling(t *testing.T) {
	root := filepath.Clean(filepath.Join(sourceDirectory(t), "..", ".."))
	script := filepath.Join(root, "install.sh")
	executable := []byte("#!/bin/sh\nset -eu\n[ \"$1\" = inspect ]\nif grep -q fixture-semantic-object \"$4\"; then printf '[{\"kind\": \"semantic\", \"requirements\": []}]\\n'; else semantic=$(grep -l fixture-semantic-object \"$(dirname \"$4\")\"/*.pstrap); digest=$(basename \"$semantic\" .pstrap); printf '[{\"kind\": \"binding\", \"requirements\": [{\"handle\": \"core\", \"digest\": \"sha256:%s\"}]}]\\n' \"$digest\"; fi\n")
	archive := releaseArchive(t, "amd64", executable)
	checksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	armArchive := releaseArchive(t, "arm64", executable)
	armChecksum := fmt.Sprintf("%x", sha256.Sum256(armArchive))
	extraArchive := releaseArchive(t, "amd64", executable, "extra")
	extraChecksum := checksumFor(extraArchive)
	badPackArchive := releaseArchive(t, "amd64", executable, "bad-pack-name")
	badPackChecksum := checksumFor(badPackArchive)
	missingArchive := releaseArchive(t, "amd64", executable, "missing-profile")
	missingChecksum := checksumFor(missingArchive)
	failingArchive := releaseArchive(t, "amd64", []byte("#!/bin/sh\nexit 1\n"))
	failingChecksum := checksumFor(failingArchive)
	truncated := archive[:len(archive)/2]
	truncatedChecksum := fmt.Sprintf("%x", sha256.Sum256(truncated))
	tests := []struct {
		name           string
		system         string
		machine        string
		archive        []byte
		manifest       string
		installFailure string
		moveFailure    string
		generation     bool
		existing       string
		wantLegacy     bool
		wantInstalled  string
		wantError      bool
	}{
		{name: "valid", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantInstalled: string(executable)},
		{name: "valid arm64", machine: "aarch64", archive: armArchive, manifest: armChecksum + "  ./proofstrap_linux_arm64.tar.gz\n", wantInstalled: string(executable)},
		{name: "missing checksum row", machine: "x86_64", archive: archive, manifest: checksum + "  ./another.tar.gz\n", wantError: true},
		{name: "duplicate checksum row", machine: "x86_64", archive: archive, manifest: strings.Repeat(checksum+"  ./proofstrap_linux_amd64.tar.gz\n", 2), wantError: true},
		{name: "wrong checksum", machine: "x86_64", archive: archive, manifest: strings.Repeat("0", 64) + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "truncated archive", machine: "x86_64", archive: truncated, manifest: truncatedChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "extra member", machine: "x86_64", archive: extraArchive, manifest: extraChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "missing member", machine: "x86_64", archive: missingArchive, manifest: missingChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "wrong pack filename", machine: "x86_64", archive: badPackArchive, manifest: badPackChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "staged binary failure", machine: "x86_64", archive: failingArchive, manifest: failingChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "unsupported architecture", machine: "riscv64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "non Linux", system: "Darwin", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "partial install", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", installFailure: "partial", wantError: true},
		{name: "regular upgrade retains legacy", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", existing: "existing-binary", wantInstalled: string(executable), wantLegacy: true},
		{name: "partial upgrade preserves existing", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", installFailure: "partial", existing: "existing-binary", wantInstalled: "existing-binary", wantError: true},
		{name: "publication failure preserves existing", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", moveFailure: "publication", existing: "existing-binary", wantInstalled: "existing-binary", wantError: true},
		{name: "launcher failure preserves existing", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", moveFailure: "launcher", existing: "existing-binary", wantInstalled: "existing-binary", wantError: true},
		{name: "existing generation conflicts", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", generation: true, existing: "existing-binary", wantInstalled: "existing-binary", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			bin := filepath.Join(workspace, "fake-bin")
			home := filepath.Join(workspace, "home")
			tmp := filepath.Join(workspace, "tmp")
			fixtures := filepath.Join(workspace, "fixtures")
			for _, directory := range []string{bin, home, tmp, fixtures} {
				if err := os.MkdirAll(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			writeExecutable(t, filepath.Join(bin, "uname"), `#!/bin/sh
case "${1:-}" in
  -s) printf '%s\n' "$FAKE_SYSTEM" ;;
  -m) printf '%s\n' "$FAKE_MACHINE" ;;
  *) exit 64 ;;
esac
`)
			writeExecutable(t, filepath.Join(bin, "curl"), `#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    --fail|--location|--show-error|--silent) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */checksums.txt) cp "$FIXTURE_CHECKSUMS" "$output" ;;
  */proofstrap_linux_*.tar.gz) cp "$FIXTURE_ARCHIVE" "$output" ;;
  *) exit 64 ;;
esac
`)
			writeExecutable(t, filepath.Join(bin, "install"), `#!/bin/sh
set -eu
for destination do :; done
if [ "${FAKE_INSTALL_FAILURE:-}" = partial ]; then
  printf partial > "$destination"
  exit 74
fi
exec /usr/bin/install "$@"
`)
			writeExecutable(t, filepath.Join(bin, "mv"), `#!/bin/sh
set -eu
for destination do :; done
case "${FAKE_MV_FAILURE:-}:$destination" in
  publication:*/.proofstrap-releases/*) exit 74 ;;
  launcher:*/proofstrap) exit 74 ;;
esac
exec /usr/bin/mv "$@"
`)
			archivePath := filepath.Join(fixtures, "archive.tar.gz")
			manifestPath := filepath.Join(fixtures, "checksums.txt")
			if err := os.WriteFile(archivePath, test.archive, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			installed := filepath.Join(home, ".local", "bin", "proofstrap")
			if test.existing != "" {
				if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(installed, []byte(test.existing), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if test.generation {
				if err := os.MkdirAll(filepath.Join(filepath.Dir(installed), ".proofstrap-releases", checksumFor(test.archive)), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			system := test.system
			if system == "" {
				system = "Linux"
			}
			command := exec.Command("sh", script)
			command.Env = append(os.Environ(),
				"PATH="+bin+":/usr/bin:/bin", "HOME="+home, "TMPDIR="+tmp,
				"FAKE_SYSTEM="+system, "FAKE_MACHINE="+test.machine, "FAKE_INSTALL_FAILURE="+test.installFailure,
				"FAKE_MV_FAILURE="+test.moveFailure,
				"FIXTURE_ARCHIVE="+archivePath, "FIXTURE_CHECKSUMS="+manifestPath,
			)
			output, err := command.CombinedOutput()
			if test.wantError && err == nil {
				t.Fatalf("expected failure, output=%s", output)
			}
			if !test.wantError && err != nil {
				t.Fatalf("install failed: %v: %s", err, output)
			}
			contents, readErr := os.ReadFile(installed)
			if test.wantInstalled == "" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("failure installed a binary: err=%v contents=%q", readErr, contents)
				}
			} else if readErr != nil || string(contents) != test.wantInstalled {
				t.Fatalf("installed err=%v contents=%q", readErr, contents)
			}
			if !test.wantError {
				info, err := os.Lstat(installed)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("launcher is not a symlink: %v, %v", info, err)
				}
				target, err := os.Readlink(installed)
				wantTarget := filepath.Join(".proofstrap-releases", checksumFor(test.archive), "proofstrap")
				if err != nil || target != wantTarget {
					t.Fatalf("launcher target = %q, %v; want %q", target, err, wantTarget)
				}
				packs, err := filepath.Glob(filepath.Join(filepath.Dir(installed), ".proofstrap-releases", checksumFor(test.archive), "packs", "sha256", "*.pstrap"))
				if err != nil || len(packs) != 2 {
					t.Fatalf("installed packs = %v, %v", packs, err)
				}
			}
			if test.wantLegacy {
				legacy, err := filepath.Glob(filepath.Join(filepath.Dir(installed), ".proofstrap-releases", "legacy-*", "proofstrap"))
				if err != nil || len(legacy) != 1 {
					t.Fatalf("legacy generations = %v, %v", legacy, err)
				}
				contents, err := os.ReadFile(legacy[0])
				if err != nil || string(contents) != test.existing {
					t.Fatalf("legacy contents = %q, %v", contents, err)
				}
			}
			installTemps, globErr := filepath.Glob(filepath.Join(filepath.Dir(installed), ".proofstrap-link.*"))
			if globErr != nil || len(installTemps) != 0 {
				t.Fatalf("install temporary cleanup err=%v paths=%v", globErr, installTemps)
			}
			stageTemps, globErr := filepath.Glob(filepath.Join(filepath.Dir(installed), ".proofstrap-releases", ".stage.*"))
			if globErr != nil || len(stageTemps) != 0 {
				t.Fatalf("release staging cleanup err=%v paths=%v", globErr, stageTemps)
			}
			entries, readDirErr := os.ReadDir(tmp)
			if readDirErr != nil || len(entries) != 0 {
				t.Fatalf("temporary cleanup err=%v entries=%v", readDirErr, entries)
			}
		})
	}
}

func sourceDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
}

func releaseArchive(t *testing.T, arch string, executable []byte, options ...string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	root := "proofstrap_linux_" + arch
	semantic := []byte("fixture-semantic-object")
	binding := []byte("fixture-binding-object")
	semanticName := fmt.Sprintf("%x.pstrap", sha256.Sum256(semantic))
	bindingName := fmt.Sprintf("%x.pstrap", sha256.Sum256(binding))
	for _, option := range options {
		if option == "bad-pack-name" {
			semanticName = strings.Repeat("0", 64) + ".pstrap"
		}
	}
	for _, directory := range []string{root + "/", root + "/spec/", root + "/packs/", root + "/packs/sha256/"} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: directory, Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	members := []struct {
		name string
		mode int64
		data []byte
	}{
		{root + "/proofstrap", 0o755, executable},
		{root + "/proofstrap-pack", 0o755, []byte("pack-builder")},
		{root + "/README.md", 0o644, []byte("readme")},
		{root + "/LICENSE", 0o644, []byte("license")},
		{root + "/spec/config.md", 0o644, []byte("config")},
		{root + "/spec/profile.md", 0o644, []byte("profile")},
		{root + "/packs/sha256/" + semanticName, 0o444, semantic},
		{root + "/packs/sha256/" + bindingName, 0o444, binding},
	}
	for _, option := range options {
		if option == "missing-profile" {
			members = append(members[:5], members[6:]...)
		}
	}
	for _, option := range options {
		if option == "extra" {
			members = append(members, struct {
				name string
				mode int64
				data []byte
			}{root + "/extra", 0o644, []byte("extra")})
		}
	}
	for _, member := range members {
		if err := tarWriter.WriteHeader(&tar.Header{Name: member.name, Mode: member.mode, Size: int64(len(member.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func checksumFor(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
