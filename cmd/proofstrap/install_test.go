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
	current, err := os.Getwd()
	must(t, err)
	root := filepath.Clean(filepath.Join(current, "..", ".."))
	script := filepath.Join(root, "install.sh")
	executable := []byte("#!/bin/sh\nset -eu\n[ \"$1\" = inspect ]\ngrep -q malformed-pack-object \"$4\" && exit 1\nprintf '[{}]\\n'\n")
	archive := releaseArchive(t, "amd64", executable)
	checksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	armArchive := releaseArchive(t, "arm64", executable)
	armChecksum := fmt.Sprintf("%x", sha256.Sum256(armArchive))
	threePackArchive := releaseArchive(t, "amd64", executable, "three-packs")
	threePackChecksum := checksumFor(threePackArchive)
	failingArchive := releaseArchive(t, "amd64", []byte("#!/bin/sh\nexit 1\n"))
	failingChecksum := checksumFor(failingArchive)
	truncated := archive[:len(archive)/2]
	truncatedChecksum := fmt.Sprintf("%x", sha256.Sum256(truncated))
	type installCase struct {
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
		wantPacks      int
		wantError      bool
	}
	tests := []installCase{
		{name: "valid", machine: "x86_64", archive: archive, manifest: checksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantInstalled: string(executable), wantPacks: 2},
		{name: "valid arm64", machine: "aarch64", archive: armArchive, manifest: armChecksum + "  ./proofstrap_linux_arm64.tar.gz\n", wantInstalled: string(executable), wantPacks: 2},
		{name: "valid three packs", machine: "x86_64", archive: threePackArchive, manifest: threePackChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantInstalled: string(executable), wantPacks: 3},
		{name: "missing checksum row", machine: "x86_64", archive: archive, manifest: checksum + "  ./another.tar.gz\n", wantError: true},
		{name: "duplicate checksum row", machine: "x86_64", archive: archive, manifest: strings.Repeat(checksum+"  ./proofstrap_linux_amd64.tar.gz\n", 2), wantError: true},
		{name: "wrong checksum", machine: "x86_64", archive: archive, manifest: strings.Repeat("0", 64) + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
		{name: "truncated archive", machine: "x86_64", archive: truncated, manifest: truncatedChecksum + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true},
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
	for _, option := range []string{"zero-packs", "65-packs", "malformed-name", "malformed-pack", "bad-pack-name", "missing-profile", "duplicate", "traversal", "link", "special", "extra", "oversize"} {
		candidate := releaseArchive(t, "amd64", executable, option)
		tests = append(tests, installCase{name: option, machine: "x86_64", archive: candidate, manifest: checksumFor(candidate) + "  ./proofstrap_linux_amd64.tar.gz\n", wantError: true})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			bin := filepath.Join(workspace, "fake-bin")
			home := filepath.Join(workspace, "home")
			tmp := filepath.Join(workspace, "tmp")
			fixtures := filepath.Join(workspace, "fixtures")
			config := filepath.Join(workspace, "proofstrap.toml")
			for _, directory := range []string{bin, home, tmp, fixtures} {
				must(t, os.MkdirAll(directory, 0o755))
			}
			must(t, os.WriteFile(config, []byte("user-config"), 0o600))
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
			must(t, os.WriteFile(archivePath, test.archive, 0o600))
			must(t, os.WriteFile(manifestPath, []byte(test.manifest), 0o600))
			installed := filepath.Join(home, ".local", "bin", "proofstrap")
			if test.existing != "" {
				must(t, os.MkdirAll(filepath.Dir(installed), 0o755))
				must(t, os.WriteFile(installed, []byte(test.existing), 0o755))
			}
			if test.generation {
				must(t, os.MkdirAll(filepath.Join(filepath.Dir(installed), ".proofstrap-releases", checksumFor(test.archive)), 0o755))
			}
			system := test.system
			if system == "" {
				system = "Linux"
			}
			command := exec.Command("sh", script)
			command.Dir = workspace
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
				wantPacks := test.wantPacks
				if wantPacks == 0 {
					wantPacks = 2
				}
				if err != nil || len(packs) != wantPacks {
					t.Fatalf("installed packs = %v, %v", packs, err)
				}
				for _, object := range packs {
					if info, err := os.Stat(object); err != nil || info.Mode().Perm() != 0o444 {
						t.Fatalf("pack mode = %v, %v", info, err)
					}
				}
				if _, err := os.Stat(filepath.Join(filepath.Dir(packs[0]), "..", "..", "proofstrap-pack")); !os.IsNotExist(err) {
					t.Fatalf("runtime generation contains author tool: %v", err)
				}
				starter := filepath.Join(filepath.Dir(installed), ".proofstrap-releases", checksumFor(test.archive), "examples", "bootstrap.toml")
				if contents, err := os.ReadFile(starter); err != nil || !bytes.Contains(contents, []byte("profiles = [{ profile = \"core:bootstrap-cli\" }]")) || !bytes.Contains(output, []byte("plan --config "+starter+" --output ./plan.json")) || !bytes.Contains(output, []byte("cp -- \""+starter+"\" ./proofstrap.toml")) {
					t.Fatalf("starter config = %q, %v; output=%q", contents, err, output)
				}
				if info, err := os.Stat(starter); err != nil || info.Mode().Perm() != 0o444 {
					t.Fatalf("starter mode = %v, %v", info, err)
				}
			}
			if contents, err := os.ReadFile(config); err != nil || string(contents) != "user-config" {
				t.Fatalf("installer changed user config: %q, %v", contents, err)
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

func writeExecutable(t *testing.T, path, contents string) {
	must(t, os.WriteFile(path, []byte(contents), 0o755))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func releaseArchive(t *testing.T, arch string, executable []byte, options ...string) []byte {
	var compressed bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressed, gzip.NoCompression)
	must(t, err)
	tarWriter := tar.NewWriter(gzipWriter)
	root := "proofstrap_linux_" + arch
	semantic := []byte("fixture-semantic-object")
	binding := []byte("fixture-binding-object")
	desktop := []byte("fixture-desktop-object")
	for _, option := range options {
		if option == "malformed-pack" {
			binding = []byte("malformed-pack-object")
		} else if option == "oversize" {
			binding = bytes.Repeat([]byte("x"), 33554433)
		}
	}
	semanticName := fmt.Sprintf("%x.pstrap", sha256.Sum256(semantic))
	bindingName := fmt.Sprintf("%x.pstrap", sha256.Sum256(binding))
	for _, option := range options {
		switch option {
		case "bad-pack-name":
			semanticName = strings.Repeat("0", 64) + ".pstrap"
		case "malformed-name":
			semanticName = "bad.pstrap"
		}
	}
	for _, directory := range []string{root + "/", root + "/docs/", root + "/examples/", root + "/packs/", root + "/packs/sha256/"} {
		must(t, tarWriter.WriteHeader(&tar.Header{Name: directory, Mode: 0o755, Typeflag: tar.TypeDir}))
	}
	type archiveMember struct {
		name string
		mode int64
		data []byte
		kind byte
		link string
	}
	members := []archiveMember{
		{name: root + "/proofstrap", mode: 0o755, data: executable},
		{name: root + "/README.md", mode: 0o644, data: []byte("readme")},
		{name: root + "/LICENSE", mode: 0o644, data: []byte("license")},
		{name: root + "/docs/config.md", mode: 0o644, data: []byte("config")},
		{name: root + "/docs/profile.md", mode: 0o644, data: []byte("profile")},
		{name: root + "/examples/bootstrap.toml", mode: 0o644, data: []byte(fmt.Sprintf("schema = 2\n\nbindings = [\"linux\"]\nprofiles = [{ profile = \"core:bootstrap-cli\" }]\n\n[sources]\ncore = \"sha256:%s\"\nlinux = \"sha256:%s\"\n", strings.TrimSuffix(semanticName, ".pstrap"), strings.TrimSuffix(bindingName, ".pstrap")))},
		{name: root + "/packs/sha256/" + semanticName, mode: 0o444, data: semantic},
		{name: root + "/packs/sha256/" + bindingName, mode: 0o444, data: binding},
	}
	for _, option := range options {
		if option == "three-packs" {
			desktopName := fmt.Sprintf("%x.pstrap", sha256.Sum256(desktop))
			members = append(members, archiveMember{name: root + "/packs/sha256/" + desktopName, mode: 0o444, data: desktop})
		}
		if option == "zero-packs" {
			members = members[:len(members)-2]
		}
		if option == "65-packs" {
			for index := 0; index < 63; index++ {
				data := []byte(fmt.Sprintf("fixture-extra-%d", index))
				members = append(members, archiveMember{name: root + "/packs/sha256/" + fmt.Sprintf("%x.pstrap", sha256.Sum256(data)), mode: 0o444, data: data})
			}
		}
		if option == "duplicate" {
			members = append(members, members[0])
		}
		if option == "traversal" {
			members = append(members, archiveMember{name: root + "/../escape", mode: 0o644, data: []byte("escape")})
		}
		if option == "link" || option == "special" {
			members = append(members[:1], members[2:]...)
			kind := byte(tar.TypeSymlink)
			if option == "special" {
				kind = tar.TypeFifo
			}
			members = append(members, archiveMember{name: root + "/README.md", mode: 0o644, kind: kind, link: "LICENSE"})
		}
	}
	for _, option := range options {
		if option == "missing-profile" {
			members = append(members[:4], members[5:]...)
		}
	}
	for _, option := range options {
		if option == "extra" {
			members = append(members, archiveMember{name: root + "/extra", mode: 0o644, data: []byte("extra")})
		}
	}
	for _, member := range members {
		kind := member.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		must(t, tarWriter.WriteHeader(&tar.Header{Name: member.name, Mode: member.mode, Size: int64(len(member.data)), Typeflag: kind, Linkname: member.link}))
		_, err := tarWriter.Write(member.data)
		must(t, err)
	}
	must(t, tarWriter.Close())
	must(t, gzipWriter.Close())
	return compressed.Bytes()
}

func checksumFor(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
