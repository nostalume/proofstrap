package identity

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHomePublicationIsMetadataCompleteAndNoReplace(t *testing.T) {
	parent := t.TempDir()
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	started, err := createHomeAt(fd, "alice", uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil || !started {
		t.Fatalf("create = %t, %v", started, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(fd, "alice", &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		t.Fatalf("published metadata = %#v", stat)
	}
	if _, err := os.Lstat(filepath.Join(parent, ".alice.proofstrap-stage")); !os.IsNotExist(err) {
		t.Fatalf("stage remains: %v", err)
	}
	if started, err := createHomeAt(fd, "alice", uint32(os.Getuid()), uint32(os.Getgid())); err == nil || started {
		t.Fatalf("replaced final: %t, %v", started, err)
	}

	started, err = chmodHomeAt(fd, "alice", 0o750)
	if err != nil || !started {
		t.Fatalf("chmod = %t, %v", started, err)
	}
	if err := unix.Fstatat(fd, "alice", &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&0o777 != 0o750 {
		t.Fatalf("mode = %o, %v", stat.Mode&0o777, err)
	}
}

func TestHomePublicationBlocksSymlinksAndCrashOrphans(t *testing.T) {
	parent := t.TempDir()
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	if err := os.Symlink("elsewhere", filepath.Join(parent, "linked")); err != nil {
		t.Fatal(err)
	}
	if started, err := createHomeAt(fd, "linked", uint32(os.Getuid()), uint32(os.Getgid())); err == nil || started {
		t.Fatalf("accepted symlink: %t, %v", started, err)
	}
	if err := os.Mkdir(filepath.Join(parent, ".orphan.proofstrap-stage"), 0o700); err != nil {
		t.Fatal(err)
	}
	if started, err := createHomeAt(fd, "orphan", uint32(os.Getuid()), uint32(os.Getgid())); err == nil || started {
		t.Fatalf("bypassed orphan: %t, %v", started, err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "orphan")); !os.IsNotExist(err) {
		t.Fatalf("orphan target appeared: %v", err)
	}
	if fd, err := openTrustedDirectory(parent); err == nil {
		unix.Close(fd)
		t.Fatal("accepted user-owned or writable test ancestry as root-trusted")
	}
}
