package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/nostalume/proofstrap/internal/linux"
)

type systemEffects struct {
	identify func(string) (linux.Identity, error)
	run      func(context.Context, linux.Identity, []string, []byte) (linux.Result, error)
	euid     func() (uint32, error)
	pid1     func() (string, error)
	home     func(string) (homeEvidence, error)
}

func productionEffects() systemEffects {
	return systemEffects{
		identify: linux.Identify, run: linux.Run,
		euid: func() (uint32, error) { return uint32(os.Geteuid()), nil },
		pid1: func() (string, error) {
			data, err := os.ReadFile("/proc/1/comm")
			return strings.TrimSuffix(string(data), "\n"), err
		},
		home: inspectHome,
	}
}

func admitRoot(euid func() (uint32, error)) (uint32, error) {
	value, err := euid()
	if err != nil {
		return 0, fmt.Errorf("%w: inspect effective UID: %v", ErrIndeterminate, err)
	}
	if value != 0 {
		return value, fmt.Errorf("%w: effective UID %d is not root", ErrUnauthorized, value)
	}
	return value, nil
}

func identifyUnique(effects systemEffects, label string, candidates []string) (linux.Identity, error) {
	var identities []linux.Identity
	for _, candidate := range candidates {
		identity, err := effects.identify(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return linux.Identity{}, fmt.Errorf("%w: identify %s: %v", ErrIndeterminate, label, err)
		}
		if !filepath.IsAbs(identity.Path) || filepath.Clean(identity.Path) != identity.Path {
			return linux.Identity{}, fmt.Errorf("%w: %s identity path is invalid", ErrIndeterminate, label)
		}
		if !slices.Contains(identities, identity) {
			identities = append(identities, identity)
		}
	}
	if len(identities) == 0 {
		return linux.Identity{}, fmt.Errorf("%w: %s is absent", ErrUnsupported, label)
	}
	if len(identities) != 1 {
		return linux.Identity{}, fmt.Errorf("%w: fixed %s candidates disagree", ErrAmbiguous, label)
	}
	return identities[0], nil
}

func inspectHome(path string) (homeEvidence, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return homeEvidence{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return homeEvidence{}, fmt.Errorf("home ownership metadata unavailable")
	}
	return homeEvidence{path: path, uid: stat.Uid, gid: stat.Gid, mode: uint16(info.Mode().Perm()), device: uint64(stat.Dev), inode: stat.Ino, directory: info.IsDir() && info.Mode()&os.ModeSymlink == 0}, nil
}

func commandFailure(action string, result linux.Result, err error) error {
	if err == nil && result.Started && result.ExitCode == 0 && len(result.Stderr) == 0 {
		return nil
	}
	return errors.Join(fmt.Errorf("%s failed: started=%t exit=%d stderr=%q", action, result.Started, result.ExitCode, result.Stderr), err)
}
