package packages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

const (
	dnf5Path             = "/usr/bin/dnf5"
	dnf5TransactionFile  = "transaction.json"
	dnf5TransactionLimit = 8 << 20
)

type dnf5Proof struct {
	executable linux.Identity
	version    string
}

func (dnf5Proof) proof() {}

func (value dnf5Proof) equal(other proof) bool {
	candidate, ok := other.(dnf5Proof)
	return ok && value == candidate
}

// dnf5Files keeps the DNF5-specific temporary transaction directory out of the
// shared command effects. A stored transaction is adapter-private evidence.
type dnf5Files struct {
	mkdirTemp   func(dir, pattern string) (string, error)
	readBounded func(path string, limit int64) ([]byte, error)
	removeAll   func(path string) error
}

type dnf5Behavior struct {
	effects effects
	files   dnf5Files
}

func systemDNF5Files() dnf5Files {
	return dnf5Files{
		mkdirTemp: os.MkdirTemp,
		readBounded: func(path string, limit int64) ([]byte, error) {
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, limit+1))
			if err != nil {
				return nil, err
			}
			if int64(len(data)) > limit {
				return nil, fmt.Errorf("stored DNF5 transaction exceeds %d bytes", limit)
			}
			return data, nil
		},
		removeAll: os.RemoveAll,
	}
}

func probeDNF5(ctx context.Context, effect effects, files dnf5Files) candidate {
	backend, err := binding.NewPackageBackendID("dnf5")
	if err != nil {
		panic(err)
	}
	executable, err := effect.identify(dnf5Path)
	if errors.Is(err, os.ErrNotExist) {
		return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAbsent}}
	}
	if err != nil {
		return systemIndeterminate(backend, fmt.Sprintf("identify dnf5: %v", err))
	}
	result, err := effect.run(ctx, executable, []string{"--version"}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return systemIndeterminate(backend, nativeDiagnostic("probe dnf5", result, err))
	}
	version, supported, err := parseDNF5Version(result.Stdout)
	if err != nil {
		return systemIndeterminate(backend, err.Error())
	}
	if !supported {
		return candidate{evidence: candidateEvidence{
			backend: backend, role: SystemCandidate, state: candidateUnsupported,
			detail: "unsupported dnf5 version " + version,
		}}
	}
	if files.mkdirTemp == nil || files.readBounded == nil || files.removeAll == nil {
		return systemIndeterminate(backend, "invalid dnf5 filesystem effects")
	}
	return candidate{
		evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAdmitted, proof: dnf5Proof{executable: executable, version: version}},
		behavior: dnf5Behavior{effects: effect, files: files},
	}
}

func parseDNF5Version(data []byte) (string, bool, error) {
	line, _, found := strings.Cut(string(data), "\n")
	if !found || line == "" {
		return "", false, fmt.Errorf("malformed dnf5 version output")
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "dnf5" || fields[1] != "version" {
		return "", false, fmt.Errorf("malformed dnf5 version output")
	}
	parts := strings.Split(fields[2], ".")
	if len(parts) != 4 {
		return "", false, fmt.Errorf("malformed dnf5 version %q", fields[2])
	}
	for _, part := range parts {
		if part == "" {
			return "", false, fmt.Errorf("malformed dnf5 version %q", fields[2])
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return "", false, fmt.Errorf("malformed dnf5 version %q", fields[2])
		}
	}
	return fields[2], parts[0] == "5", nil
}

func dnf5StoreArgs(store string, desired []string, cacheOnly bool) []string {
	args := make([]string, 0, len(desired)+11)
	if cacheOnly {
		args = append(args, "--setopt=cacheonly=metadata")
	}
	args = append(args,
		"--assumeyes",
		"--setopt=best=true", "--setopt=multilib_policy=best", "--setopt=install_weak_deps=false",
		"--setopt=obsoletes=false", "--setopt=allow_vendor_change=false", "--setopt=allow_downgrade=false",
		"install", "--store="+store, "--",
	)
	return append(args, desired...)
}

func dnf5ReplayArgs(store string) []string { return []string{"--assumeyes", "replay", store} }

func dnf5TransactionPath(directory string) string {
	return filepath.Join(directory, dnf5TransactionFile)
}

const dnf5InventoryFormat = "%{name}\\t%{epoch}\\t%{version}\\t%{release}\\t%{arch}\\t%{vendor}\\t%{reason}\\n"

func dnf5InventoryArgs() []string {
	return []string{
		"--setopt=cacheonly=metadata", "--setopt=disable_excludes=*",
		"repoquery", "--installed", "--queryformat=" + dnf5InventoryFormat,
	}
}

func (behavior dnf5Behavior) Observe(ctx context.Context, evidence proof, desired []string) (Observation, error) {
	native, ok := evidence.(dnf5Proof)
	if !ok {
		return Observation{}, fmt.Errorf("dnf5 proof is required")
	}
	if err := validateDNF5Desired(desired); err != nil {
		return Observation{}, err
	}
	result, err := behavior.effects.run(ctx, native.executable, dnf5InventoryArgs(), nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe dnf5 packages", result, err))
	}
	return parseDNF5Observation(result.Stdout, desired)
}

func parseDNF5Observation(data []byte, desired []string) (Observation, error) {
	return parseDNFObservation(data, desired, dnfInventoryDialect{name: "dnf5", rootReason: dnf5RootReason})
}

func validateDNF5Desired(desired []string) error {
	return validateRPMDesired(desired, "dnf5")
}

func dnf5RootReason(reason string) (bool, bool) {
	switch reason {
	case "Dependency", "Weak Dependency":
		return false, true
	case "None", "User", "Group", "External User":
		return true, true
	default:
		return false, false
	}
}

type dnf5StoredTransaction struct {
	Version      string          `json:"version"`
	RPMs         []dnf5StoredRPM `json:"rpms"`
	Groups       json.RawMessage `json:"groups"`
	Environments json.RawMessage `json:"environments"`
}

type dnf5StoredRPM struct {
	NEVRA       string `json:"nevra"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	Repository  string `json:"repo_id"`
	PackagePath string `json:"package_path"`
}

type dnf5NEVRA struct{ name, epoch, version, release, architecture string }

func (value dnf5NEVRA) evr() string { return value.epoch + ":" + value.version + "-" + value.release }
func (value dnf5NEVRA) key() string { return value.name + "\t" + value.architecture }
func (value dnf5NEVRA) full() string {
	return value.name + "-" + value.evr() + "." + value.architecture
}

func (behavior dnf5Behavior) Preview(ctx context.Context, evidence proof, observation Observation) (offer Offer, err error) {
	native, ok := evidence.(dnf5Proof)
	if !ok || !observation.valid() {
		return Offer{}, fmt.Errorf("dnf5 proof and observation are required")
	}
	if err := validateDNF5Desired(desiredFrom(observation)); err != nil {
		return Offer{}, err
	}
	if behavior.files.mkdirTemp == nil || behavior.files.readBounded == nil || behavior.files.removeAll == nil {
		return Offer{}, fmt.Errorf("dnf5 filesystem effects are required")
	}
	directory, err := behavior.files.mkdirTemp("", "proofstrap-dnf5-")
	if err != nil {
		return Offer{}, fmt.Errorf("create dnf5 transaction directory: %w", err)
	}
	defer func() {
		if cleanup := behavior.files.removeAll(directory); cleanup != nil {
			offer = Offer{}
			err = errors.Join(err, fmt.Errorf("clean dnf5 transaction directory: %w", cleanup))
		}
	}()
	result, runErr := behavior.effects.run(ctx, native.executable, dnf5StoreArgs(directory, desiredFrom(observation), false), nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 {
		return Offer{}, fmt.Errorf("%s", nativeDiagnostic("store dnf5 transaction", result, runErr))
	}
	data, err := behavior.files.readBounded(dnf5TransactionPath(directory), dnf5TransactionLimit)
	if err != nil {
		return Offer{}, fmt.Errorf("read stored dnf5 transaction: %w", err)
	}
	return parseDNF5StoredOffer(data, observation)
}

func parseDNF5StoredOffer(data []byte, observation Observation) (Offer, error) {
	if !observation.valid() {
		return Offer{}, fmt.Errorf("complete dnf5 observation is required")
	}
	if err := validateDNF5Desired(desiredFrom(observation)); err != nil {
		return Offer{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stored dnf5StoredTransaction
	if err := decoder.Decode(&stored); err != nil {
		return Offer{}, fmt.Errorf("decode stored dnf5 transaction: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Offer{}, fmt.Errorf("trailing stored dnf5 transaction JSON")
		}
		return Offer{}, fmt.Errorf("trailing stored dnf5 transaction JSON: %w", err)
	}
	if !dnf5StoredVersion(stored.Version) || !dnf5EmptyCollection(stored.Groups) || !dnf5EmptyCollection(stored.Environments) {
		return Offer{}, fmt.Errorf("unsupported stored dnf5 transaction")
	}
	rows := make([]dnf5StoredRPM, len(stored.RPMs))
	nevras := make([]dnf5NEVRA, len(stored.RPMs))
	seen := make(map[string]struct{}, len(stored.RPMs))
	for index, row := range stored.RPMs {
		nevra, err := parseDNF5NEVRA(row.NEVRA)
		if err != nil || !dnf5Action(row.Action) || !dnf5StoredReason(row.Reason) || row.Repository == "" {
			return Offer{}, fmt.Errorf("malformed stored dnf5 package")
		}
		if _, exists := seen[nevra.full()]; exists {
			return Offer{}, fmt.Errorf("duplicate stored dnf5 package %q", nevra.full())
		}
		seen[nevra.full()] = struct{}{}
		inbound := row.Action == "Install" || row.Action == "Upgrade" || row.Action == "Downgrade" || row.Action == "Reinstall"
		if inbound {
			if !dnf5PackagePath(row.PackagePath) {
				return Offer{}, fmt.Errorf("unsafe stored dnf5 package path")
			}
		} else if row.PackagePath != "" {
			return Offer{}, fmt.Errorf("outbound stored dnf5 package has payload path")
		}
		rows[index], nevras[index] = row, nevra
	}
	preinstalled, err := dnf5Preinstalled(observation)
	if err != nil {
		return Offer{}, err
	}
	deltas, err := dnf5StoredDeltas(rows, nevras, preinstalled, observation)
	if err != nil {
		return Offer{}, err
	}
	return newOffer(deltas)
}

func dnf5StoredVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 2 || parts[0] != "1" || parts[1] == "" {
		return false
	}
	_, err := strconv.ParseUint(parts[1], 10, 32)
	return err == nil
}

func dnf5EmptyCollection(data json.RawMessage) bool {
	return len(data) == 0 || bytes.Equal(data, []byte("[]"))
}

func dnf5Action(action string) bool {
	switch action {
	case "Install", "Upgrade", "Downgrade", "Reinstall", "Remove", "Replaced", "Reason Change":
		return true
	default:
		return false
	}
}

func dnf5StoredReason(reason string) bool {
	switch reason {
	case "None", "Dependency", "User", "Clean", "Weak Dependency", "Group", "External User":
		return true
	default:
		return false
	}
}

func dnf5PackagePath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	relative := strings.TrimPrefix(value, "."+string(filepath.Separator))
	if filepath.Clean(relative) != relative {
		return false
	}
	return strings.HasPrefix(relative, "packages"+string(filepath.Separator)) && len(relative) > len("packages")+1
}

func parseDNF5NEVRA(value string) (dnf5NEVRA, error) {
	archAt := strings.LastIndex(value, ".")
	if archAt <= 0 || archAt == len(value)-1 {
		return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
	}
	prefix, architecture := value[:archAt], value[archAt+1:]
	releaseAt := strings.LastIndex(prefix, "-")
	if releaseAt <= 0 || releaseAt == len(prefix)-1 {
		return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
	}
	nameVersion, release := prefix[:releaseAt], prefix[releaseAt+1:]
	epoch, name, version := "0", "", ""
	if colon := strings.LastIndex(nameVersion, ":"); colon >= 0 {
		before, after := nameVersion[:colon], nameVersion[colon+1:]
		epochAt := strings.LastIndex(before, "-")
		if epochAt <= 0 || epochAt == len(before)-1 {
			return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
		}
		name, epoch, version = before[:epochAt], before[epochAt+1:], after
	} else {
		versionAt := strings.LastIndex(nameVersion, "-")
		if versionAt <= 0 || versionAt == len(nameVersion)-1 {
			return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
		}
		name, version = nameVersion[:versionAt], nameVersion[versionAt+1:]
	}
	if err := binding.ValidatePackageName(name); err != nil || !rpmAtom(epoch) || !rpmAtom(version) || !rpmAtom(release) || !rpmAtom(architecture) {
		return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
	}
	if _, err := strconv.ParseUint(epoch, 10, 32); err != nil {
		return dnf5NEVRA{}, fmt.Errorf("malformed dnf5 NEVRA %q", value)
	}
	return dnf5NEVRA{name: name, epoch: epoch, version: version, release: release, architecture: architecture}, nil
}

func dnf5Preinstalled(observation Observation) (map[string]dnf5NEVRA, error) {
	records := observation.inventory().installed()
	installed := make(map[string]dnf5NEVRA, len(records))
	for _, record := range records {
		fields := strings.Split(record.Key, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed observed dnf5 package key")
		}
		name, evr, architecture := fields[0], fields[1], fields[2]
		colon, releaseAt := strings.Index(evr, ":"), strings.LastIndex(evr, "-")
		if colon <= 0 || releaseAt <= colon+1 || releaseAt == len(evr)-1 {
			return nil, fmt.Errorf("malformed observed dnf5 package key")
		}
		nevra, err := parseDNF5NEVRA(name + "-" + evr + "." + architecture)
		if err != nil {
			return nil, fmt.Errorf("malformed observed dnf5 package key")
		}
		if _, exists := installed[nevra.full()]; exists {
			return nil, fmt.Errorf("duplicate observed dnf5 package")
		}
		installed[nevra.full()] = nevra
	}
	return installed, nil
}

func dnf5StoredDeltas(rows []dnf5StoredRPM, nevras []dnf5NEVRA, preinstalled map[string]dnf5NEVRA, observation Observation) ([]Delta, error) {
	if len(rows) != len(nevras) {
		return nil, fmt.Errorf("inconsistent stored dnf5 transaction")
	}
	demands := make(map[string]demand, len(observation.demands()))
	for _, demand := range observation.demands() {
		demands[demand.Name] = demand
	}
	targets := make(map[string]int, len(demands))
	for index, row := range rows {
		if row.Reason != "User" {
			if row.Action == "Reason Change" {
				return nil, fmt.Errorf("unexpected dnf5 root reason change")
			}
			continue
		}
		switch row.Action {
		case "Install", "Upgrade", "Downgrade", "Reinstall", "Reason Change":
			demand, ok := demands[nevras[index].name]
			if !ok {
				return nil, fmt.Errorf("unexpected dnf5 requested package %q", nevras[index].name)
			}
			if demand.State == demandDirect && row.Action == "Reason Change" {
				return nil, fmt.Errorf("redundant dnf5 root reason change")
			}
			targets[demand.Name]++
		default:
			return nil, fmt.Errorf("unexpected dnf5 root transition")
		}
	}
	for _, demand := range observation.demands() {
		if demand.State != demandDirect && targets[demand.Name] != 1 {
			return nil, fmt.Errorf("dnf5 transaction does not select desired package %q exactly once", demand.Name)
		}
		if targets[demand.Name] > 1 {
			return nil, fmt.Errorf("dnf5 transaction selects desired package %q more than once", demand.Name)
		}
	}
	usedReplaced := make([]bool, len(rows))
	replacedBy := make(map[int]int)
	for index, row := range rows {
		if row.Action != "Upgrade" && row.Action != "Downgrade" {
			continue
		}
		_, oldIndex, found, pairErr := dnf5ReplacedFor(index, rows, nevras, preinstalled, usedReplaced)
		if pairErr != nil {
			return nil, pairErr
		}
		if !found {
			return nil, fmt.Errorf("dnf5 %s lacks exact replaced package", strings.ToLower(row.Action))
		}
		usedReplaced[oldIndex] = true
		replacedBy[index] = oldIndex
	}
	deltas := make([]Delta, 0, len(rows)+len(observation.demands()))
	for index, row := range rows {
		nevra := nevras[index]
		var delta Delta
		var err error
		switch row.Action {
		case "Install":
			delta, err = newDelta(Add, nevra.key(), "", nevra.evr())
		case "Upgrade", "Downgrade":
			old := nevras[replacedBy[index]]
			kind := Upgrade
			if row.Action == "Downgrade" {
				kind = Downgrade
			}
			delta, err = newDelta(kind, nevra.key(), old.evr(), nevra.evr())
			if err == nil && old.architecture != nevra.architecture {
				architecture, architectureErr := newDelta(ArchitectureChange, nevra.key(), old.architecture, nevra.architecture)
				if architectureErr != nil {
					return nil, architectureErr
				}
				deltas = append(deltas, architecture)
			}
		case "Reinstall":
			if _, exists := preinstalled[nevra.full()]; !exists {
				return nil, fmt.Errorf("dnf5 reinstall lacks exact installed package")
			}
			delta, err = newDelta(Replace, nevra.key(), nevra.evr(), nevra.evr()+" (reinstall)")
		case "Remove":
			if _, exists := preinstalled[nevra.full()]; !exists {
				return nil, fmt.Errorf("dnf5 removal lacks exact installed package")
			}
			delta, err = newDelta(Remove, nevra.key(), nevra.evr(), "")
		case "Replaced":
			if usedReplaced[index] {
				continue
			}
			if _, exists := preinstalled[nevra.full()]; !exists {
				return nil, fmt.Errorf("dnf5 replaced package lacks exact installed package")
			}
			delta, err = newDelta(Remove, nevra.key(), nevra.evr(), "")
		case "Reason Change":
			if _, exists := preinstalled[nevra.full()]; !exists {
				return nil, fmt.Errorf("dnf5 reason change lacks exact installed package")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, delta)
	}
	for _, demand := range observation.demands() {
		if demand.State != demandDirect {
			delta, err := newDelta(RootAdd, demand.Name, "", "direct")
			if err != nil {
				return nil, err
			}
			deltas = append(deltas, delta)
		}
	}
	return deltas, nil
}

func dnf5ReplacedFor(inbound int, rows []dnf5StoredRPM, nevras []dnf5NEVRA, preinstalled map[string]dnf5NEVRA, used []bool) (dnf5NEVRA, int, bool, error) {
	var found dnf5NEVRA
	foundIndex := -1
	for index, row := range rows {
		if row.Action != "Replaced" || used[index] || nevras[index].name != nevras[inbound].name {
			continue
		}
		if _, exists := preinstalled[nevras[index].full()]; !exists {
			continue
		}
		if foundIndex >= 0 {
			return dnf5NEVRA{}, 0, false, fmt.Errorf("ambiguous dnf5 replaced package")
		}
		found, foundIndex = nevras[index], index
	}
	return found, foundIndex, foundIndex >= 0, nil
}

func (behavior dnf5Behavior) Commit(ctx context.Context, evidence proof, observation Observation, expected Offer) (result commitResult, err error) {
	native, ok := evidence.(dnf5Proof)
	if !ok || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("dnf5 proof, observation, and reviewed offer are required")
	}
	if err := validateDNF5Desired(desiredFrom(observation)); err != nil {
		return commitResult{}, err
	}
	if behavior.files.mkdirTemp == nil || behavior.files.readBounded == nil || behavior.files.removeAll == nil {
		return commitResult{}, fmt.Errorf("dnf5 filesystem effects are required")
	}
	directory, err := behavior.files.mkdirTemp("", "proofstrap-dnf5-")
	if err != nil {
		return commitResult{}, fmt.Errorf("create dnf5 transaction directory: %w", err)
	}
	defer func() {
		if cleanup := behavior.files.removeAll(directory); cleanup != nil {
			err = errors.Join(err, fmt.Errorf("clean dnf5 transaction directory: %w", cleanup))
		}
	}()
	stored, runErr := behavior.effects.run(ctx, native.executable, dnf5StoreArgs(directory, desiredFrom(observation), true), nil)
	if runErr != nil || !stored.Started || stored.ExitCode != 0 {
		return commitResult{}, fmt.Errorf("%s", nativeDiagnostic("store dnf5 apply transaction", stored, runErr))
	}
	data, err := behavior.files.readBounded(dnf5TransactionPath(directory), dnf5TransactionLimit)
	if err != nil {
		return commitResult{}, fmt.Errorf("read stored dnf5 apply transaction: %w", err)
	}
	actual, err := parseDNF5StoredOffer(data, observation)
	if err != nil {
		return commitResult{}, err
	}
	if !actual.equal(expected) {
		return commitResult{}, fmt.Errorf("%w: dnf5 stored transaction differs from reviewed offer", ErrStale)
	}
	replay, runErr := behavior.effects.run(ctx, native.executable, dnf5ReplayArgs(directory), nil)
	result = commitResult{Started: replay.Started}
	if runErr != nil || !replay.Started || replay.ExitCode != 0 {
		return result, fmt.Errorf("%s", nativeDiagnostic("replay dnf5 transaction", replay, runErr))
	}
	return result, nil
}

func (dnf5Behavior) Verify(before Observation, offer Offer, after Observation) error {
	return verifyRPMTransition("dnf5", before, offer, after)
}
