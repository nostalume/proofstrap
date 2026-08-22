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
	"testing"
)

func TestInstallerPublishesOnlyRuntimeAndDocumentation(t *testing.T) {
	current, err := os.Getwd()
	must(t, err)
	script := filepath.Join(current, "..", "..", "install.sh")
	executable := []byte("#!/bin/sh\n[ \"$1\" = --help ]\n")
	valid := releaseArchive(t, "amd64", executable, "")
	tests := []struct {
		name, system, machine, defect    string
		badChecksum, existing, wantError bool
	}{
		{name: "valid", system: "Linux", machine: "x86_64"},
		{name: "upgrade", system: "Linux", machine: "x86_64", existing: true},
		{name: "wrong checksum", system: "Linux", machine: "x86_64", badChecksum: true, wantError: true},
		{name: "extra member", system: "Linux", machine: "x86_64", defect: "extra", wantError: true},
		{name: "traversal", system: "Linux", machine: "x86_64", defect: "traversal", wantError: true},
		{name: "symlink", system: "Linux", machine: "x86_64", defect: "link", wantError: true},
		{name: "non Linux", system: "Darwin", machine: "x86_64", wantError: true},
		{name: "unsupported architecture", system: "Linux", machine: "riscv64", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			bin, home, temporary := filepath.Join(workspace, "bin"), filepath.Join(workspace, "home"), filepath.Join(workspace, "tmp")
			for _, path := range []string{bin, home, temporary} {
				must(t, os.MkdirAll(path, 0o755))
			}
			writeExecutable(t, filepath.Join(bin, "uname"), "#!/bin/sh\n[ \"$1\" = -s ] && echo \"$FAKE_SYSTEM\" || echo \"$FAKE_MACHINE\"\n")
			writeExecutable(t, filepath.Join(bin, "curl"), `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do case "$1" in -o) output=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
case "$url" in */checksums.txt) cp "$FIXTURE_CHECKSUMS" "$output" ;; *) cp "$FIXTURE_ARCHIVE" "$output" ;; esac
`)
			archive := valid
			if test.defect != "" {
				archive = releaseArchive(t, "amd64", executable, test.defect)
			}
			archivePath, checksums := filepath.Join(workspace, "archive"), filepath.Join(workspace, "checksums")
			must(t, os.WriteFile(archivePath, archive, 0o600))
			digest := checksumFor(archive)
			if test.badChecksum {
				digest = fmt.Sprintf("%064d", 0)
			}
			must(t, os.WriteFile(checksums, []byte(digest+"  ./proofstrap_linux_amd64.tar.gz\n"), 0o600))
			launcher := filepath.Join(home, ".local", "bin", "proofstrap")
			if test.existing {
				must(t, os.MkdirAll(filepath.Dir(launcher), 0o755))
				must(t, os.WriteFile(launcher, []byte("old"), 0o755))
			}
			command := exec.Command("sh", script)
			command.Dir = workspace
			command.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "HOME="+home, "TMPDIR="+temporary,
				"FAKE_SYSTEM="+test.system, "FAKE_MACHINE="+test.machine, "FIXTURE_ARCHIVE="+archivePath, "FIXTURE_CHECKSUMS="+checksums)
			output, err := command.CombinedOutput()
			if test.wantError != (err != nil) {
				t.Fatalf("error=%v output=%s", err, output)
			}
			if test.wantError {
				if test.existing {
					contents, _ := os.ReadFile(launcher)
					if string(contents) != "old" {
						t.Fatalf("existing launcher changed: %q", contents)
					}
				}
				return
			}
			info, err := os.Lstat(launcher)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("launcher=%v, %v", info, err)
			}
			generation := filepath.Join(filepath.Dir(launcher), ".proofstrap-releases", checksumFor(archive))
			for _, path := range []string{"proofstrap", "README.md", "LICENSE", "docs/config.md", "docs/profile.md"} {
				if _, err := os.Stat(filepath.Join(generation, path)); err != nil {
					t.Fatalf("missing %s: %v", path, err)
				}
			}
			for _, absent := range []string{"packs", "examples", "proofstrap-pack"} {
				if _, err := os.Stat(filepath.Join(generation, absent)); !os.IsNotExist(err) {
					t.Fatalf("unexpected runtime payload %s", absent)
				}
			}
		})
	}
}

func releaseArchive(t *testing.T, arch string, executable []byte, defect string) []byte {
	t.Helper()
	root := "proofstrap_linux_" + arch
	type member struct {
		name string
		mode int64
		data []byte
		kind byte
		link string
	}
	members := []member{
		{name: root + "/", mode: 0o755, kind: tar.TypeDir}, {name: root + "/docs/", mode: 0o755, kind: tar.TypeDir},
		{name: root + "/proofstrap", mode: 0o755, data: executable}, {name: root + "/README.md", mode: 0o644, data: []byte("readme")},
		{name: root + "/LICENSE", mode: 0o644, data: []byte("license")}, {name: root + "/docs/config.md", mode: 0o644, data: []byte("config")},
		{name: root + "/docs/profile.md", mode: 0o644, data: []byte("profile")},
	}
	switch defect {
	case "extra":
		members = append(members, member{name: root + "/extra", mode: 0o644, data: []byte("extra")})
	case "traversal":
		members = append(members, member{name: root + "/../escape", mode: 0o644, data: []byte("escape")})
	case "link":
		members[3] = member{name: root + "/README.md", mode: 0o644, kind: tar.TypeSymlink, link: "LICENSE"}
	}
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, item := range members {
		kind := item.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		must(t, tarWriter.WriteHeader(&tar.Header{Name: item.name, Mode: item.mode, Size: int64(len(item.data)), Typeflag: kind, Linkname: item.link}))
		if kind == tar.TypeReg {
			_, err := tarWriter.Write(item.data)
			must(t, err)
		}
	}
	must(t, tarWriter.Close())
	must(t, gzipWriter.Close())
	return output.Bytes()
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(contents), 0o755))
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func checksumFor(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
