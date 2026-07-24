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
	archive := releaseArchive(t, "amd64", []byte("proofstrap-test-binary"))
	checksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	armArchive := releaseArchive(t, "arm64", []byte("proofstrap-test-binary"))
	armChecksum := fmt.Sprintf("%x", sha256.Sum256(armArchive))
	truncated := archive[:len(archive)/2]
	truncatedChecksum := fmt.Sprintf("%x", sha256.Sum256(truncated))
	tests := []struct {
		name           string
		system         string
		machine        string
		archive        []byte
		manifest       string
		installFailure string
		existing       string
		wantInstalled  string
		wantError      bool
	}{
		{name: "valid", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantInstalled: "proofstrap-test-binary"},
		{name: "valid arm64", machine: "aarch64", archive: armArchive, manifest: armChecksum + "  ./proofstrap_linux_arm64.tar.gz\n", wantInstalled: "proofstrap-test-binary"},
		{name: "missing checksum row", machine: "x86_64", archive: archive, manifest: checksum + "  ./another.tar.gz\n", wantError: true},
		{name: "duplicate checksum row", machine: "x86_64", archive: archive, manifest: strings.Repeat(checksum+"  ./proofstrap_linux_amd64.tar.gz\n", 2), wantError: true},
		{name: "wrong checksum", machine: "x86_64", archive: archive, manifest: strings.Repeat("0", 64) + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "truncated archive", machine: "x86_64", archive: truncated, manifest: truncatedChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "unsupported architecture", machine: "riscv64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "non Linux", system: "Darwin", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "partial install", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", installFailure: "partial", wantError: true},
		{name: "partial upgrade preserves existing", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", installFailure: "partial", existing: "existing-binary", wantInstalled: "existing-binary", wantError: true},
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
			system := test.system
			if system == "" {
				system = "Linux"
			}
			command := exec.Command("sh", script)
			command.Env = append(os.Environ(),
				"PATH="+bin+":/usr/bin:/bin", "HOME="+home, "TMPDIR="+tmp,
				"FAKE_SYSTEM="+system, "FAKE_MACHINE="+test.machine, "FAKE_INSTALL_FAILURE="+test.installFailure,
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
			installTemps, globErr := filepath.Glob(filepath.Join(filepath.Dir(installed), ".proofstrap.*"))
			if globErr != nil || len(installTemps) != 0 {
				t.Fatalf("install temporary cleanup err=%v paths=%v", globErr, installTemps)
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

func releaseArchive(t *testing.T, arch string, executable []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	name := "proofstrap_linux_" + arch + "/proofstrap"
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(executable)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(executable); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
