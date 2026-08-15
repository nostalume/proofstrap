package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	logicalEtc      = "/etc"
	logicalZoneinfo = "/usr/share/zoneinfo"
)

type linuxFS struct {
	etc, zoneinfo string
	uid, gid      uint32
}

func productionFS() linuxFS {
	return linuxFS{etc: logicalEtc, zoneinfo: logicalZoneinfo, uid: 0, gid: 0}
}

func SelectHostname(ctx context.Context) (*Selected, error) {
	if !futureContext(ctx) {
		return nil, fmt.Errorf("bounded hostname selection context is required")
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: effective UID is not root", ErrUnauthorized)
	}
	filesystem := productionFS()
	etc, err := filesystem.directoryEvidence(filesystem.etc, logicalEtc)
	if err != nil {
		return nil, fmt.Errorf("%w: admit /etc: %v", ErrUnsupported, err)
	}
	return &Selected{evidence: selectionEvidence{kind: hostnameMechanism, euid: 0, etc: etc}, effects: filesystem.effects()}, nil
}

func SelectTimezone(ctx context.Context) (*Selected, error) {
	if !futureContext(ctx) {
		return nil, fmt.Errorf("bounded timezone selection context is required")
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: effective UID is not root", ErrUnauthorized)
	}
	filesystem := productionFS()
	absent, err := filesystem.secondaryAbsent()
	if err != nil {
		return nil, err
	}
	if !absent {
		return nil, fmt.Errorf("%w: secondary timezone representation exists", ErrUnsupported)
	}
	etc, err := filesystem.directoryEvidence(filesystem.etc, logicalEtc)
	if err != nil {
		return nil, fmt.Errorf("%w: admit /etc: %v", ErrUnsupported, err)
	}
	zoneinfo, err := filesystem.directoryEvidence(filesystem.zoneinfo, logicalZoneinfo)
	if err != nil {
		return nil, fmt.Errorf("%w: admit zoneinfo: %v", ErrUnsupported, err)
	}
	return &Selected{evidence: selectionEvidence{kind: timezoneMechanism, euid: 0, etc: etc, zoneinfo: zoneinfo, secondaryAbsent: true}, effects: filesystem.effects()}, nil
}

func (filesystem linuxFS) effects() effects {
	return effects{
		observeHostname: func() (hostnameObservation, error) {
			persistent, err := filesystem.observeHostnameFile()
			if err != nil {
				return hostnameObservation{}, err
			}
			runtime, err := os.Hostname()
			if err != nil {
				return hostnameObservation{}, fmt.Errorf("observe runtime hostname: %w", err)
			}
			if !validHostname(runtime) {
				return hostnameObservation{persistent: persistent, runtimeBlocked: "runtime hostname is not canonical"}, nil
			}
			return hostnameObservation{persistent: persistent, runtime: runtime}, nil
		},
		writeHostname: filesystem.writeHostname,
		setHostname: func(value string) (bool, error) {
			err := unix.Sethostname([]byte(value))
			return true, err
		},
		zone:            filesystem.zone,
		observeTimezone: filesystem.observeTimezone,
		writeTimezone:   filesystem.writeTimezone,
	}
}

func (filesystem linuxFS) directoryEvidence(actual, logical string) (directoryEvidence, error) {
	fd, err := unix.Open(actual, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return directoryEvidence{}, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return directoryEvidence{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return directoryEvidence{}, fmt.Errorf("%s is not a directory", logical)
	}
	value := directoryEvidence{path: logical, directory: true, mode: stat.Mode & 0o777, uid: stat.Uid, gid: stat.Gid, device: uint64(stat.Dev), inode: stat.Ino}
	if value.uid != filesystem.uid || value.gid != filesystem.gid || value.mode&0o022 != 0 {
		return directoryEvidence{}, fmt.Errorf("%s ownership or mode is unsafe", logical)
	}
	return value, nil
}

func (filesystem linuxFS) observeHostnameFile() (hostnameFile, error) {
	parent, err := unix.Open(filesystem.etc, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return hostnameFile{}, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, "hostname", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return hostnameFile{}, nil
	}
	if errors.Is(err, unix.ELOOP) {
		return hostnameFile{present: true, blocked: "hostname file is a symbolic link"}, nil
	}
	if err != nil {
		return hostnameFile{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(filesystem.etc, "hostname"))
	if file == nil {
		unix.Close(fd)
		return hostnameFile{}, fmt.Errorf("open hostname returned an invalid descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return hostnameFile{}, err
	}
	value := hostnameFile{present: true, regular: stat.Mode&unix.S_IFMT == unix.S_IFREG, mode: stat.Mode & 0o777, uid: stat.Uid, gid: stat.Gid, device: uint64(stat.Dev), inode: stat.Ino}
	if !value.regular {
		value.blocked = "hostname file is not regular"
		return value, nil
	}
	if value.uid != filesystem.uid || value.gid != filesystem.gid || value.mode&0o022 != 0 {
		value.blocked = "hostname file ownership or mode is unsafe"
		return value, nil
	}
	contents, err := io.ReadAll(io.LimitReader(file, 66))
	if err != nil {
		return hostnameFile{}, err
	}
	if len(contents) == 66 || len(contents) < 2 || contents[len(contents)-1] != '\n' || strings.ContainsAny(string(contents[:len(contents)-1]), "\r\n") || !validHostname(string(contents[:len(contents)-1])) {
		value.blocked = "hostname file does not contain one canonical line"
		return value, nil
	}
	value.contents = string(contents)
	return value, nil
}

func (filesystem linuxFS) writeHostname(before hostnameFile, desired string) (started bool, err error) {
	if !validHostname(desired) || before.blocked != "" {
		return false, fmt.Errorf("valid desired hostname and safe before-state are required")
	}
	fresh, err := filesystem.observeHostnameFile()
	if err != nil {
		return false, err
	}
	if fresh != before {
		return false, fmt.Errorf("%w: persistent hostname changed before publication", ErrStale)
	}
	stage, err := os.CreateTemp(filesystem.etc, ".proofstrap-hostname-")
	if err != nil {
		return false, err
	}
	started = true
	stagePath := stage.Name()
	defer func() { err = errors.Join(err, removeIfPresent(stagePath)) }()
	if _, err = io.WriteString(stage, desired+"\n"); err != nil {
		stage.Close()
		return started, err
	}
	if err = stage.Chmod(0o644); err == nil {
		err = stage.Chown(int(filesystem.uid), int(filesystem.gid))
	}
	if err == nil {
		err = stage.Sync()
	}
	if closeErr := stage.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return started, err
	}
	target := filepath.Join(filesystem.etc, "hostname")
	if !before.present {
		err = unix.Renameat2(unix.AT_FDCWD, stagePath, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	} else {
		err = os.Rename(stagePath, target)
	}
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return started, fmt.Errorf("hostname appeared during publication")
		}
		return started, err
	}
	err = syncDirectory(filesystem.etc)
	return started, err
}

func (filesystem linuxFS) zone(name string) (zoneFile, error) {
	if !validTimezone(name) {
		return zoneFile{}, fmt.Errorf("invalid timezone %q", name)
	}
	root, err := unix.Open(filesystem.zoneinfo, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return zoneFile{}, err
	}
	fd := root
	components := strings.Split(name, "/")
	for index, component := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return zoneFile{}, fmt.Errorf("open timezone %q: %w", name, openErr)
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), filepath.Join(filesystem.zoneinfo, name))
	if file == nil {
		unix.Close(fd)
		return zoneFile{}, fmt.Errorf("open timezone returned invalid descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return zoneFile{}, err
	}
	value := zoneFile{regular: stat.Mode&unix.S_IFMT == unix.S_IFREG, mode: stat.Mode & 0o777, uid: stat.Uid, gid: stat.Gid, device: uint64(stat.Dev), inode: stat.Ino}
	if !value.regular || value.uid != filesystem.uid || value.gid != filesystem.gid || value.mode&0o022 != 0 {
		return zoneFile{}, fmt.Errorf("timezone %q is not a safe regular file", name)
	}
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(file, prefix); err != nil || string(prefix) != "TZif" {
		return zoneFile{}, fmt.Errorf("timezone %q is not TZif data", name)
	}
	value.tzif = true
	return value, nil
}

func (filesystem linuxFS) observeTimezone() (timezoneObservation, error) {
	path := filepath.Join(filesystem.etc, "localtime")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return timezoneObservation{}, nil
	}
	if err != nil {
		return timezoneObservation{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return timezoneObservation{}, fmt.Errorf("localtime lacks stat evidence")
	}
	value := timezoneObservation{present: true, device: uint64(stat.Dev), inode: stat.Ino}
	if info.Mode()&os.ModeSymlink == 0 {
		value.blocked = "localtime is not a symbolic link"
		return value, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return timezoneObservation{}, err
	}
	zone, ok := timezoneTarget(target)
	if !ok || !validTimezone(zone) {
		value.blocked = "localtime target is outside canonical zoneinfo"
		return value, nil
	}
	data, err := filesystem.zone(zone)
	if err != nil {
		value.blocked = err.Error()
		return value, nil
	}
	value.zone, value.target, value.zoneFile = zone, target, data
	return value, nil
}

func timezoneTarget(target string) (string, bool) {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(logicalEtc, resolved)
	}
	resolved = filepath.Clean(resolved)
	prefix := logicalZoneinfo + "/"
	if !strings.HasPrefix(resolved, prefix) {
		return "", false
	}
	return strings.TrimPrefix(resolved, prefix), true
}

func (filesystem linuxFS) writeTimezone(before timezoneObservation, desired string, reviewed zoneFile) (started bool, err error) {
	if !validTimezone(desired) || before.blocked != "" || !reviewed.regular || !reviewed.tzif {
		return false, fmt.Errorf("valid desired timezone and safe evidence are required")
	}
	absent, err := filesystem.secondaryAbsent()
	if err != nil || !absent {
		return false, err
	}
	freshZone, err := filesystem.zone(desired)
	if err != nil {
		return false, err
	}
	if freshZone != reviewed {
		return false, fmt.Errorf("%w: desired timezone data changed", ErrStale)
	}
	fresh, err := filesystem.observeTimezone()
	if err != nil {
		return false, err
	}
	if fresh != before {
		return false, fmt.Errorf("%w: localtime changed before publication", ErrStale)
	}
	placeholder, err := os.CreateTemp(filesystem.etc, ".proofstrap-localtime-")
	if err != nil {
		return false, err
	}
	started = true
	stagePath := placeholder.Name()
	if closeErr := placeholder.Close(); closeErr != nil {
		os.Remove(stagePath)
		return started, closeErr
	}
	if err := os.Remove(stagePath); err != nil {
		return started, err
	}
	defer func() { err = errors.Join(err, removeIfPresent(stagePath)) }()
	if err := os.Symlink(logicalZoneinfo+"/"+desired, stagePath); err != nil {
		return started, err
	}
	if err := os.Lchown(stagePath, int(filesystem.uid), int(filesystem.gid)); err != nil {
		return started, err
	}
	target := filepath.Join(filesystem.etc, "localtime")
	if !before.present {
		err = unix.Renameat2(unix.AT_FDCWD, stagePath, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	} else {
		err = os.Rename(stagePath, target)
	}
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return started, fmt.Errorf("localtime appeared during publication")
		}
		return started, err
	}
	err = syncDirectory(filesystem.etc)
	return started, err
}

func (filesystem linuxFS) secondaryAbsent() (bool, error) {
	for _, relative := range []string{"timezone", filepath.Join("sysconfig", "clock")} {
		_, err := os.Lstat(filepath.Join(filesystem.etc, relative))
		if err == nil {
			return false, fmt.Errorf("%w: secondary timezone representation %s exists", ErrUnsupported, filepath.Join(logicalEtc, relative))
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return true, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	err = directory.Sync()
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	return err
}

func removeIfPresent(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
