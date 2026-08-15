package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxFSHostnamePublicationIsMetadataCompleteAndStaleGuarded(t *testing.T) {
	filesystem := testLinuxFS(t)
	before, err := filesystem.observeHostnameFile()
	if err != nil || before.present {
		t.Fatalf("missing hostname = %#v, %v", before, err)
	}
	started, err := filesystem.writeHostname(before, "node")
	if err != nil || !started {
		t.Fatalf("write hostname = %t, %v", started, err)
	}
	after, err := filesystem.observeHostnameFile()
	if err != nil || !after.present || !after.regular || after.contents != "node\n" || after.mode != 0o644 || after.uid != filesystem.uid || after.gid != filesystem.gid {
		t.Fatalf("hostname after = %#v, %v", after, err)
	}
	entries, _ := os.ReadDir(filesystem.etc)
	if len(entries) != 1 || entries[0].Name() != "hostname" {
		t.Fatalf("hostname publication residue = %#v", entries)
	}

	stale := after
	stale.inode++
	if started, err := filesystem.writeHostname(stale, "other"); !errors.Is(err, ErrStale) || started {
		t.Fatalf("stale hostname write = %t, %v", started, err)
	}
	contents, _ := os.ReadFile(filepath.Join(filesystem.etc, "hostname"))
	if string(contents) != "node\n" {
		t.Fatalf("stale write changed hostname: %q", contents)
	}
}

func TestLinuxFSHostnameObservationBlocksSymlinkAndUnsafeMetadata(t *testing.T) {
	filesystem := testLinuxFS(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(filesystem.etc, "hostname")); err != nil {
		t.Fatal(err)
	}
	observed, err := filesystem.observeHostnameFile()
	if err != nil || observed.blocked == "" {
		t.Fatalf("symlink hostname = %#v, %v", observed, err)
	}
	if err := os.Remove(filepath.Join(filesystem.etc, "hostname")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filesystem.etc, "hostname"), []byte("node\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(filesystem.etc, "hostname"), 0o666); err != nil {
		t.Fatal(err)
	}
	observed, err = filesystem.observeHostnameFile()
	if err != nil || observed.blocked == "" {
		t.Fatalf("writable hostname = %#v, %v", observed, err)
	}
}

func TestLinuxFSTimezoneContainmentObservationAndPublication(t *testing.T) {
	filesystem := testLinuxFS(t)
	zonePath := filepath.Join(filesystem.zoneinfo, "Asia", "Shanghai")
	if err := os.MkdirAll(filepath.Dir(zonePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zonePath, []byte("TZifpayload"), 0o644); err != nil {
		t.Fatal(err)
	}
	zone, err := filesystem.zone("Asia/Shanghai")
	if err != nil || !zone.regular || !zone.tzif {
		t.Fatalf("zone = %#v, %v", zone, err)
	}
	before, err := filesystem.observeTimezone()
	if err != nil || before.present {
		t.Fatalf("missing localtime = %#v, %v", before, err)
	}
	started, err := filesystem.writeTimezone(before, "Asia/Shanghai", zone)
	if err != nil || !started {
		t.Fatalf("write timezone = %t, %v", started, err)
	}
	after, err := filesystem.observeTimezone()
	if err != nil || !after.present || after.blocked != "" || after.zone != "Asia/Shanghai" || after.zoneFile != zone {
		t.Fatalf("timezone after = %#v, %v", after, err)
	}
	target, _ := os.Readlink(filepath.Join(filesystem.etc, "localtime"))
	if target != "/usr/share/zoneinfo/Asia/Shanghai" {
		t.Fatalf("localtime target = %q", target)
	}
	entries, _ := os.ReadDir(filesystem.etc)
	if len(entries) != 1 || entries[0].Name() != "localtime" {
		t.Fatalf("timezone publication residue = %#v", entries)
	}

	if err := os.Remove(zonePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/escape", zonePath); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystem.zone("Asia/Shanghai"); err == nil {
		t.Fatal("zoneinfo symlink escape was admitted")
	}
}

func TestLinuxFSTimezoneSecondaryRepresentationIsExplicitlyUnsupported(t *testing.T) {
	filesystem := testLinuxFS(t)
	absent, err := filesystem.secondaryAbsent()
	if err != nil || !absent {
		t.Fatalf("secondary absence = %t, %v", absent, err)
	}
	if err := os.WriteFile(filepath.Join(filesystem.etc, "timezone"), []byte("UTC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	absent, err = filesystem.secondaryAbsent()
	if !errors.Is(err, ErrUnsupported) || absent || !strings.Contains(err.Error(), "timezone") {
		t.Fatalf("secondary representation = %t, %v", absent, err)
	}
}

func TestLinuxFSTimezoneObservationAcceptsRelativeTargetAndBlocksOtherShapes(t *testing.T) {
	filesystem := testLinuxFS(t)
	zonePath := filepath.Join(filesystem.zoneinfo, "UTC")
	if err := os.WriteFile(zonePath, []byte("TZifpayload"), 0o644); err != nil {
		t.Fatal(err)
	}
	localtime := filepath.Join(filesystem.etc, "localtime")
	if err := os.Symlink("../usr/share/zoneinfo/UTC", localtime); err != nil {
		t.Fatal(err)
	}
	observed, err := filesystem.observeTimezone()
	if err != nil || observed.blocked != "" || observed.zone != "UTC" {
		t.Fatalf("relative localtime = %#v, %v", observed, err)
	}
	if err := os.Remove(localtime); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localtime, []byte("TZifpayload"), 0o644); err != nil {
		t.Fatal(err)
	}
	observed, err = filesystem.observeTimezone()
	if err != nil || observed.blocked == "" {
		t.Fatalf("regular localtime = %#v, %v", observed, err)
	}
	if err := os.WriteFile(filepath.Join(filesystem.zoneinfo, "bad"), []byte("not-zone-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystem.zone("bad"); err == nil {
		t.Fatal("non-TZif zone was admitted")
	}
}

func testLinuxFS(t *testing.T) linuxFS {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	zoneinfo := filepath.Join(root, "usr", "share", "zoneinfo")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(zoneinfo, 0o755); err != nil {
		t.Fatal(err)
	}
	return linuxFS{etc: etc, zoneinfo: zoneinfo, uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
}
