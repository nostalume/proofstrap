package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
)

type openRCFileState struct {
	script    bool
	runlevels []string
}

type openRCEffects struct {
	control func() error
	inspect func([]string) (map[string]openRCFileState, error)
}

func SelectOpenRCSystem(ctx context.Context) (*Selected, error) {
	return selectOpenRCSystem(ctx, productionEffects(), productionOpenRCEffects())
}

func selectOpenRCSystem(ctx context.Context, effects systemEffects, openrc openRCEffects) (*Selected, error) {
	if !linux.FutureContext(ctx) || effects.identify == nil || effects.run == nil || effects.euid == nil || openrc.control == nil || openrc.inspect == nil {
		return nil, fmt.Errorf("bounded context and complete OpenRC effects are required")
	}
	euid, err := admitRoot(effects.euid)
	if err != nil {
		return nil, err
	}
	if err := openrc.control(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: OpenRC control plane is absent", ErrUnsupported)
		}
		return nil, fmt.Errorf("%w: inspect OpenRC control plane: %v", ErrIndeterminate, err)
	}
	service, err := identifyOpenRCTool(effects, "rc-service")
	if err != nil {
		return nil, err
	}
	status, err := identifyOpenRCTool(effects, "rc-status")
	if err != nil {
		return nil, err
	}
	update, err := identifyOpenRCTool(effects, "rc-update")
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, 3)
	for _, tool := range []linux.Identity{service, status, update} {
		version, versionErr := probeOpenRCVersion(ctx, effects, tool)
		if versionErr != nil {
			return nil, versionErr
		}
		versions = append(versions, version)
	}
	if versions[0] != versions[1] || versions[0] != versions[2] {
		return nil, fmt.Errorf("%w: OpenRC tool versions disagree", ErrAmbiguous)
	}
	result, err := effects.run(ctx, status, []string{"--runlevel"}, nil)
	if err != nil || !result.Started {
		return nil, fmt.Errorf("%w: %v", ErrIndeterminate, linux.CommandFailure("OpenRC control probe", result, err))
	}
	control := strings.TrimSuffix(string(result.Stdout), "\n")
	if result.ExitCode != 0 || len(result.Stderr) != 0 || !validText(control, 63) || strings.Contains(control, "\n") {
		return nil, fmt.Errorf("%w: OpenRC control plane is unusable", ErrUnsupported)
	}
	evidence := selectionEvidence{scope: systemScope, backend: "openrc", tool: service, status: status, update: update, version: versions[0], euid: euid, control: control}
	return &Selected{evidence: evidence, effects: effects, openrc: openrc}, nil
}

func identifyOpenRCTool(effects systemEffects, name string) (linux.Identity, error) {
	paths := make([]string, 0, 4)
	for _, directory := range []string{"/sbin", "/usr/sbin", "/bin", "/usr/bin"} {
		paths = append(paths, filepath.Join(directory, name))
	}
	return identifyUnique(effects, name, paths)
}

func probeOpenRCVersion(ctx context.Context, effects systemEffects, tool linux.Identity) (string, error) {
	result, err := effects.run(ctx, tool, []string{"--version"}, nil)
	if err != nil || !result.Started {
		return "", fmt.Errorf("%w: %v", ErrIndeterminate, linux.CommandFailure("OpenRC version probe", result, err))
	}
	line := strings.TrimSuffix(string(result.Stdout), "\n")
	fields := strings.Fields(line)
	if result.ExitCode != 0 || len(result.Stderr) != 0 || len(fields) < 2 || strings.Contains(line, "\n") || !validText(fields[len(fields)-1], 63) {
		return "", fmt.Errorf("%w: malformed OpenRC version", ErrIndeterminate)
	}
	return fields[len(fields)-1], nil
}

func (selected *Selected) observeOpenRC(ctx context.Context, desired []Demand) (map[string]unitRecord, error) {
	result, err := selected.effects.run(ctx, selected.evidence.status, []string{"--format", "ini", "--servicelist"}, nil)
	if err != nil || !result.Started {
		return nil, linux.CommandFailure("observe OpenRC services", result, err)
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 || len(result.Stdout) > maxObservationBytes {
		return nil, fmt.Errorf("OpenRC status output is invalid: started=%t exit=%d stdout-bytes=%d stderr=%q", result.Started, result.ExitCode, len(result.Stdout), result.Stderr)
	}
	statuses, err := parseOpenRCStatus(result.Stdout)
	if err != nil {
		return nil, err
	}
	units := make([]string, len(desired))
	for index := range desired {
		units[index] = desired[index].value.unit
	}
	files, err := selected.openrc.inspect(units)
	if err != nil {
		return nil, fmt.Errorf("inspect OpenRC service files: %w", err)
	}
	records := make(map[string]unitRecord, len(units))
	for _, unit := range units {
		file, exists := files[unit]
		if !exists || !file.script {
			records[unit] = unitRecord{id: unit, load: "not-found"}
			continue
		}
		state := statuses[unit]
		if state == "" {
			status, runErr := selected.effects.run(ctx, selected.evidence.tool, []string{unit, "status"}, nil)
			states := map[int]string{0: "started", 3: "stopped", 4: "stopping", 8: "starting", 16: "inactive", 32: "crashed"}
			state = states[status.ExitCode]
			if runErr != nil || !status.Started || len(status.Stdout)+len(status.Stderr) > maxObservationBytes || state == "" {
				return nil, linux.CommandFailure("observe OpenRC service "+unit, status, runErr)
			}
		}
		persistence := "disabled"
		if len(file.runlevels) == 1 && file.runlevels[0] == "default" {
			persistence = "enabled"
		} else if len(file.runlevels) != 0 {
			persistence = "non-default"
		}
		active, _ := reduceOpenRCState(state)
		records[unit] = unitRecord{id: unit, load: "loaded", unitFile: persistence, active: active, sub: state}
	}
	return records, nil
}

func parseOpenRCStatus(data []byte) (map[string]string, error) {
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("OpenRC status is not newline terminated")
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if strings.HasPrefix(line, "[") || line == "" {
			return nil, fmt.Errorf("OpenRC service list contains an invalid line")
		}
		name, raw, ok := strings.Cut(line, " = ")
		fields := strings.Fields(raw)
		if !ok || !validUnit(name) || len(fields) == 0 {
			return nil, fmt.Errorf("OpenRC service status line is invalid")
		}
		if _, known := reduceOpenRCState(fields[0]); !known {
			return nil, fmt.Errorf("OpenRC service status line is invalid")
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate OpenRC service status %q", name)
		}
		result[name] = fields[0]
	}
	return result, nil
}

func reduceOpenRCState(state string) (string, bool) {
	switch state {
	case "started":
		return "active", true
	case "stopped":
		return "inactive", true
	case "starting", "scheduled":
		return "activating", true
	case "stopping":
		return "deactivating", true
	case "failed", "crashed", "unsupervised":
		return "failed", true
	case "inactive", "hotplugged":
		return "openrc-" + state, true
	default:
		return "", false
	}
}

func productionOpenRCEffects() openRCEffects {
	return openRCEffects{control: inspectOpenRCControl, inspect: inspectOpenRCFiles}
}

func inspectOpenRCControl() error {
	for _, path := range []string{"/run/openrc/softlevel", "/etc/init.d", "/etc/runlevels", "/etc/runlevels/default"} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || path == "/run/openrc/softlevel" && !info.Mode().IsRegular() || path != "/run/openrc/softlevel" && !info.IsDir() {
			return fmt.Errorf("unsafe OpenRC control path %s", path)
		}
	}
	return nil
}

func inspectOpenRCFiles(units []string) (map[string]openRCFileState, error) {
	result := make(map[string]openRCFileState, len(units))
	runlevels, err := os.ReadDir("/etc/runlevels")
	if err != nil {
		return nil, err
	}
	for _, unit := range units {
		info, statErr := os.Lstat(filepath.Join("/etc/init.d", unit))
		state := openRCFileState{script: statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		for _, runlevel := range runlevels {
			if runlevel.Type()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("stacked OpenRC runlevels are unsupported")
			}
			if !runlevel.IsDir() || !validUnit(runlevel.Name()) {
				return nil, fmt.Errorf("OpenRC runlevel entry is invalid")
			}
			entryPath := filepath.Join("/etc/runlevels", runlevel.Name(), unit)
			entry, entryErr := os.Lstat(entryPath)
			if entryErr == nil {
				if entry.Mode()&os.ModeSymlink == 0 {
					return nil, fmt.Errorf("OpenRC runlevel entry is not a symlink")
				}
				target, readErr := os.Readlink(entryPath)
				if readErr != nil || target != filepath.Join("/etc/init.d", unit) {
					return nil, fmt.Errorf("OpenRC runlevel entry target is invalid")
				}
				state.runlevels = append(state.runlevels, runlevel.Name())
			} else if !errors.Is(entryErr, os.ErrNotExist) {
				return nil, entryErr
			}
		}
		slices.Sort(state.runlevels)
		result[unit] = state
	}
	return result, nil
}
