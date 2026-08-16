package packages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

const (
	apkPath       = "/sbin/apk"
	apkWorldPath  = "/etc/apk/world"
	apkWorldLimit = 1 << 20
)

type apkProof struct {
	executable   linux.Identity
	version      string
	architecture string
}

func (apkProof) proof() {}
func (value apkProof) equal(other proof) bool {
	candidate, ok := other.(apkProof)
	return ok && value == candidate
}

type apkFiles struct{ readWorld func() ([]byte, error) }
type apkBehavior struct {
	effects effects
	files   apkFiles
}

func systemAPKFiles() apkFiles { return apkFiles{readWorld: readAPKWorld} }

func readAPKWorld() ([]byte, error) {
	fd, err := linux.OpenRegular(apkWorldPath)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), apkWorldPath)
	if file == nil {
		return nil, fmt.Errorf("open APK world")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, apkWorldLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > apkWorldLimit {
		return nil, fmt.Errorf("APK world exceeds %d bytes", apkWorldLimit)
	}
	return data, nil
}

func probeAPK(ctx context.Context, effect effects, files apkFiles) candidate {
	backend, err := binding.NewPackageBackendID("apk")
	if err != nil {
		panic(err)
	}
	executable, err := effect.identify(apkPath)
	if errors.Is(err, os.ErrNotExist) {
		return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAbsent}}
	}
	if err != nil {
		return systemIndeterminate(backend, fmt.Sprintf("identify APK: %v", err))
	}
	result, runErr := effect.run(ctx, executable, []string{"--version"}, nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return systemIndeterminate(backend, nativeDiagnostic("probe APK", result, runErr))
	}
	version, compiledArch, supported, err := parseAPKVersion(result.Stdout)
	if err != nil {
		return systemIndeterminate(backend, err.Error())
	}
	if !supported {
		return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateUnsupported, detail: "unsupported APK version " + version}}
	}
	result, runErr = effect.run(ctx, executable, []string{"--print-arch"}, nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return systemIndeterminate(backend, nativeDiagnostic("probe APK architecture", result, runErr))
	}
	architecture, err := parseAPKArchitecture(result.Stdout)
	if err != nil || architecture != compiledArch {
		if err == nil {
			err = fmt.Errorf("APK compiled and native architectures disagree")
		}
		return systemIndeterminate(backend, err.Error())
	}
	if files.readWorld == nil {
		return systemIndeterminate(backend, "invalid APK filesystem effects")
	}
	world, err := files.readWorld()
	if err != nil {
		return systemIndeterminate(backend, fmt.Sprintf("read APK world: %v", err))
	}
	if _, _, _, err := parseAPKWorld(world); err != nil {
		return systemIndeterminate(backend, err.Error())
	}
	native := apkProof{executable: executable, version: version, architecture: architecture}
	return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAdmitted, proof: native}, behavior: apkBehavior{effects: effect, files: files}}
}

func parseAPKVersion(data []byte) (version, architecture string, supported bool, err error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", "", false, fmt.Errorf("malformed APK version output")
	}
	const prefix = "apk-tools "
	const marker = ", compiled for "
	line := string(data[:len(data)-1])
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ".") {
		return "", "", false, fmt.Errorf("malformed APK version output")
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(line, prefix), ".")
	version, architecture, found := strings.Cut(rest, marker)
	if !found || !apkAtom(version) || !validAPKArchitecture(architecture) {
		return "", "", false, fmt.Errorf("malformed APK version output")
	}
	major, _, found := strings.Cut(version, ".")
	if !found {
		return "", "", false, fmt.Errorf("malformed APK version %q", version)
	}
	return version, architecture, major == "3", nil
}

func parseAPKArchitecture(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", fmt.Errorf("malformed APK architecture output")
	}
	value := string(data[:len(data)-1])
	if !validAPKArchitecture(value) {
		return "", fmt.Errorf("invalid APK architecture %q", value)
	}
	return value, nil
}

func validAPKArchitecture(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' && character != '-' {
					return false
				}
			}
		}
	}
	return true
}

func apkAtom(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\t\n\r()")
}

func apkInventoryArgs() []string {
	return []string{"query", "--from", "installed", "--format", "json", "--fields", "name,version,arch,status", "--all-matches", "--", "*"}
}

func apkTransactionArgs(preview bool, desired []string) []string {
	args := []string{"add", "--cache-max-age", "2147483647", "--no-progress", "--no-interactive"}
	if preview {
		args = append(args, "--simulate")
	}
	args = append(args, "--")
	return append(args, desired...)
}

func (behavior apkBehavior) Observe(ctx context.Context, evidence proof, desired []string) (Observation, error) {
	native, ok := evidence.(apkProof)
	if !ok || behavior.files.readWorld == nil {
		return Observation{}, fmt.Errorf("APK proof and filesystem effects are required")
	}
	if err := validateAPKDesired(desired); err != nil {
		return Observation{}, err
	}
	result, runErr := behavior.effects.run(ctx, native.executable, apkInventoryArgs(), nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe APK packages", result, runErr))
	}
	world, err := behavior.files.readWorld()
	if err != nil {
		return Observation{}, fmt.Errorf("read APK world: %w", err)
	}
	return parseAPKObservation(result.Stdout, world, native.architecture, desired)
}

type apkInstalledWire struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Arch    string   `json:"arch"`
	Status  []string `json:"status"`
}

func parseAPKObservation(data, world []byte, architecture string, desired []string) (Observation, error) {
	if !validAPKArchitecture(architecture) {
		return Observation{}, fmt.Errorf("valid APK architecture is required")
	}
	var wires []apkInstalledWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wires); err != nil {
		return Observation{}, fmt.Errorf("decode APK installed query: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Observation{}, err
	}
	records := make([]record, 0, len(wires))
	installed := make(map[string]bool, len(wires))
	for _, wire := range wires {
		if !validAPKName(wire.Name) || !apkAtom(wire.Version) ||
			(wire.Arch != architecture && wire.Arch != "noarch") || len(wire.Status) != 1 || wire.Status[0] != "installed" {
			return Observation{}, fmt.Errorf("malformed APK installed package")
		}
		records = append(records, record{Key: wire.Name, State: wire.Version})
		installed[wire.Name] = true
	}
	roots, direct, conflicts, err := parseAPKWorld(world)
	if err != nil {
		return Observation{}, err
	}
	inventory, err := newInventory(records, roots)
	if err != nil {
		return Observation{}, fmt.Errorf("APK installed inventory: %w", err)
	}
	demands := make([]demand, len(desired))
	for index, name := range desired {
		if conflicts[name] {
			return Observation{}, fmt.Errorf("desired APK package %q conflicts with world", name)
		}
		state := demandMissing
		if installed[name] {
			state = demandDependency
		}
		if direct[name] {
			state = demandDirect
		}
		demands[index] = demand{Name: name, State: state}
	}
	return newObservation(desired, inventory, demands)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("package review contains multiple JSON values")
		}
		return fmt.Errorf("decode package review trailing data: %w", err)
	}
	return nil
}

func parseAPKWorld(data []byte) ([]string, map[string]bool, map[string]bool, error) {
	if len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, nil, nil, fmt.Errorf("truncated APK world")
	}
	roots := make([]string, 0)
	direct := make(map[string]bool)
	conflicts := make(map[string]bool)
	if len(data) == 0 {
		return roots, direct, conflicts, nil
	}
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		if line == "" || strings.TrimSpace(line) != line {
			return nil, nil, nil, fmt.Errorf("malformed APK world constraint")
		}
		conflict := strings.HasPrefix(line, "!")
		term := strings.TrimPrefix(line, "!")
		end := len(term)
		if index := strings.IndexAny(term, "@<>=~"); index >= 0 {
			end = index
		}
		name := term[:end]
		if !validAPKName(name) || end == 0 {
			return nil, nil, nil, fmt.Errorf("malformed APK world constraint %q", line)
		}
		if conflict {
			if conflicts[name] || direct[name] {
				return nil, nil, nil, fmt.Errorf("duplicate APK world package %q", name)
			}
			conflicts[name] = true
		} else {
			if direct[name] || conflicts[name] {
				return nil, nil, nil, fmt.Errorf("duplicate APK world package %q", name)
			}
			direct[name] = true
		}
		roots = append(roots, line)
	}
	return roots, direct, conflicts, nil
}

func validateAPKDesired(desired []string) error {
	for _, name := range desired {
		if !validAPKName(name) {
			return fmt.Errorf("APK desired package must be one concrete name: %q", name)
		}
	}
	return nil
}

func validAPKName(value string) bool {
	if value == "" || !apkNameAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !apkNameAlphaNumeric(value[index]) && !strings.ContainsRune("+_.-", rune(value[index])) {
			return false
		}
	}
	return true
}

func apkNameAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func (behavior apkBehavior) Preview(ctx context.Context, evidence proof, observation Observation) (Offer, error) {
	native, ok := evidence.(apkProof)
	if !ok || !observation.valid() {
		return Offer{}, fmt.Errorf("APK proof and observation are required")
	}
	return behavior.preview(ctx, native, observation)
}

func (behavior apkBehavior) preview(ctx context.Context, native apkProof, observation Observation) (Offer, error) {
	desired := desiredFrom(observation)
	result, runErr := behavior.effects.run(ctx, native.executable, apkTransactionArgs(true, desired), nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Offer{}, fmt.Errorf("%s", nativeDiagnostic("preview APK transaction", result, runErr))
	}
	return parseAPKOffer(result.Stdout, observation)
}

func parseAPKOffer(data []byte, observation Observation) (Offer, error) {
	if !observation.valid() || len(data) == 0 || data[len(data)-1] != '\n' {
		return Offer{}, fmt.Errorf("complete APK observation and transaction are required")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "OK: ") || !strings.HasSuffix(lines[len(lines)-1], " packages") {
		return Offer{}, fmt.Errorf("malformed APK transaction summary")
	}
	installed := make(map[string]string)
	for _, record := range observation.inventory().installed() {
		installed[record.Key] = record.State
	}
	deltas := make([]Delta, 0, len(lines)+len(observation.demands()))
	selected := make(map[string]bool)
	total := len(lines) - 1
	for index, line := range lines[:total] {
		kind, name, before, after, err := parseAPKAction(line, index+1, total)
		if err != nil {
			return Offer{}, err
		}
		current, exists := installed[name]
		switch kind {
		case Add:
			if exists {
				return Offer{}, fmt.Errorf("APK installs already observed package %q", name)
			}
			selected[name] = true
		case Upgrade, Downgrade, Remove, Replace, Unclassified:
			if !exists || current != before {
				return Offer{}, fmt.Errorf("APK action for %q does not match observation", name)
			}
		}
		delta, err := newDelta(kind, name, before, after)
		if err != nil {
			return Offer{}, err
		}
		deltas = append(deltas, delta)
	}
	for _, demand := range observation.demands() {
		if demand.State == demandMissing && !selected[demand.Name] {
			return Offer{}, fmt.Errorf("APK transaction does not select missing package %q", demand.Name)
		}
		if demand.State != demandDirect {
			delta, err := newDelta(RootAdd, demand.Name, "", "direct")
			if err != nil {
				return Offer{}, err
			}
			deltas = append(deltas, delta)
		}
	}
	return newOffer(deltas)
}

func parseAPKAction(line string, sequence, total int) (DeltaKind, string, string, string, error) {
	close := strings.Index(line, ") ")
	if len(line) < 5 || line[0] != '(' || close < 0 {
		return 0, "", "", "", fmt.Errorf("malformed APK transaction sequence")
	}
	left, right, found := strings.Cut(line[1:close], "/")
	actual, leftErr := strconv.Atoi(strings.TrimSpace(left))
	count, rightErr := strconv.Atoi(right)
	if !found || leftErr != nil || rightErr != nil || actual != sequence || count != total {
		return 0, "", "", "", fmt.Errorf("malformed APK transaction sequence")
	}
	rest := line[close+2:]
	actions := []struct {
		text string
		kind DeltaKind
		pair bool
	}{
		{"Installing", Add, false}, {"Upgrading", Upgrade, true}, {"Downgrading", Downgrade, true},
		{"Purging", Remove, false}, {"Reinstalling", Replace, false}, {"Replacing", Replace, true},
		{"Updating pinning", Unclassified, false},
	}
	for _, action := range actions {
		marker := action.text + " "
		if !strings.HasPrefix(rest, marker) {
			continue
		}
		payload := strings.TrimPrefix(rest, marker)
		open := strings.LastIndex(payload, " (")
		if open <= 0 || !strings.HasSuffix(payload, ")") {
			break
		}
		name := payload[:open]
		if at := strings.IndexByte(name, '@'); at >= 0 {
			if at == 0 || at == len(name)-1 || !apkAtom(name[at+1:]) {
				break
			}
			name = name[:at]
		}
		if !validAPKName(name) {
			break
		}
		versions := payload[open+2 : len(payload)-1]
		before, after := "", versions
		if action.pair {
			var found bool
			before, after, found = strings.Cut(versions, " -> ")
			if !found || !apkAtom(before) || !apkAtom(after) {
				break
			}
		} else if !apkAtom(after) {
			break
		}
		switch action.kind {
		case Remove:
			before, after = after, ""
		case Replace:
			if !action.pair {
				before = after
			}
			if before == after {
				after += " (replacement)"
			}
		case Unclassified:
			before, after = after, after+" (pinning)"
		}
		return action.kind, name, before, after, nil
	}
	return 0, "", "", "", fmt.Errorf("unsupported APK transaction action %q", line)
}

func (behavior apkBehavior) Commit(ctx context.Context, evidence proof, observation Observation, expected Offer) (commitResult, error) {
	native, ok := evidence.(apkProof)
	if !ok || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("APK proof, observation, and reviewed offer are required")
	}
	actual, err := behavior.preview(ctx, native, observation)
	if err != nil {
		return commitResult{}, err
	}
	if !actual.equal(expected) {
		return commitResult{}, fmt.Errorf("%w: APK transaction differs from reviewed offer", ErrStale)
	}
	result, runErr := behavior.effects.run(ctx, native.executable, apkTransactionArgs(false, desiredFrom(observation)), nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return commitResult{Started: result.Started}, fmt.Errorf("%s", nativeDiagnostic("commit APK transaction", result, runErr))
	}
	return commitResult{Started: true}, nil
}

func (apkBehavior) Verify(before Observation, offer Offer, after Observation) error {
	deltas, err := verifyObservationTransition(before, offer, after)
	if err != nil {
		return err
	}
	prior := make(map[string]record)
	current := make(map[string]record)
	for _, record := range before.inventory().installed() {
		prior[record.Key] = record
	}
	for _, record := range after.inventory().installed() {
		current[record.Key] = record
	}
	for _, delta := range deltas {
		old, hadOld := prior[delta.Key()]
		new, hasNew := current[delta.Key()]
		switch delta.Kind() {
		case Add:
			if hadOld || !hasNew || new.State != delta.After() {
				return fmt.Errorf("APK Add for %q does not match post-observation", delta.Key())
			}
			delete(current, delta.Key())
		case Upgrade:
			if !hadOld || old.State != delta.Before() || !hasNew || new.State != delta.After() {
				return fmt.Errorf("APK Upgrade for %q does not match post-observation", delta.Key())
			}
			delete(prior, delta.Key())
			delete(current, delta.Key())
		}
	}
	return equalRemainingRecords("APK", prior, current)
}
