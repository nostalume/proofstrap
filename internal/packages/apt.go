package packages

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

const (
	aptGetPath     = "/usr/bin/apt-get"
	aptMarkPath    = "/usr/bin/apt-mark"
	dpkgQueryPath  = "/usr/bin/dpkg-query"
	dpkgPath       = "/usr/bin/dpkg"
	aptQueryFormat = `${binary:Package}\t${Architecture}\t${db:Status-Abbrev}\t${Version}\n`
)

type aptProof struct {
	get          linux.Identity
	getVersion   string
	query        linux.Identity
	queryVersion string
	mark         linux.Identity
	markVersion  string
	dpkg         linux.Identity
	dpkgVersion  string
	nativeArch   string
}

func (aptProof) proof() {}
func (value aptProof) equal(other proof) bool {
	candidate, ok := other.(aptProof)
	return ok && value == candidate
}

type aptBehavior struct{ effects effects }

func probeApt(ctx context.Context, effect effects) candidate {
	backend, err := binding.NewPackageBackendID("apt")
	if err != nil {
		panic(err)
	}
	paths := []string{aptGetPath, dpkgQueryPath, aptMarkPath, dpkgPath}
	identities := make([]linux.Identity, len(paths))
	for index, path := range paths {
		identities[index], err = effect.identify(path)
		if errors.Is(err, os.ErrNotExist) && index == 0 {
			return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAbsent}}
		}
		if err != nil {
			return systemIndeterminate(backend, fmt.Sprintf("identify Apt companion %s: %v", path, err))
		}
	}
	versions := make([]string, len(paths))
	for index, identity := range identities {
		result, runErr := effect.run(ctx, identity, []string{"--version"}, nil)
		if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
			return systemIndeterminate(backend, nativeDiagnostic("probe "+paths[index], result, runErr))
		}
		aptTool := index == 0 || index == 2
		versions[index], err = parseAptToolVersion(result.Stdout, aptTool)
		if err != nil {
			return systemIndeterminate(backend, err.Error())
		}
		if aptTool && !aptVersionSupported(versions[index]) {
			return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateUnsupported, detail: "unsupported Apt version " + versions[index]}}
		}
		if (index == 1 || index == 3) && !dpkgVersionSupported(versions[index]) {
			return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateUnsupported, detail: "unsupported dpkg version " + versions[index]}}
		}
	}
	if versions[0] != versions[2] || versions[1] != versions[3] {
		return systemIndeterminate(backend, "Apt companion versions disagree")
	}
	result, runErr := effect.run(ctx, identities[3], []string{"--print-architecture"}, nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 {
		return systemIndeterminate(backend, nativeDiagnostic("probe native architecture", result, runErr))
	}
	arch, err := parseAptArchitecture(result.Stdout)
	if err != nil {
		return systemIndeterminate(backend, err.Error())
	}
	native := aptProof{
		get: identities[0], getVersion: versions[0], query: identities[1], queryVersion: versions[1],
		mark: identities[2], markVersion: versions[2], dpkg: identities[3], dpkgVersion: versions[3], nativeArch: arch,
	}
	return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAdmitted, proof: native}, behavior: aptBehavior{effects: effect}}
}

func parseAptToolVersion(data []byte, aptTool bool) (string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return "", fmt.Errorf("truncated package-tool version output")
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	var version string
	if aptTool {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "apt" || len(fields[2]) < 3 || fields[2][0] != '(' || fields[2][len(fields[2])-1] != ')' {
			return "", fmt.Errorf("malformed Apt version output")
		}
		version = fields[1]
	} else {
		marker := " version "
		position := strings.LastIndex(line, marker)
		if position < 0 || (!strings.Contains(line, "dpkg") && !strings.Contains(line, "dpkg-query")) {
			return "", fmt.Errorf("malformed dpkg version output")
		}
		fields := strings.Fields(line[position+len(marker):])
		if len(fields) == 0 {
			return "", fmt.Errorf("malformed dpkg version output")
		}
		version = fields[0]
	}
	version = strings.TrimSuffix(version, ".")
	if !numericVersion(version) {
		return "", fmt.Errorf("malformed package-tool version %q", version)
	}
	return version, nil
}

func numericVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func aptVersionSupported(value string) bool {
	major := strings.SplitN(value, ".", 2)[0]
	return major == "2" || major == "3"
}

func dpkgVersionSupported(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 3 || parts[0] != "1" {
		return false
	}
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])
	return minor > 16 || minor == 16 && patch >= 2
}

func parseAptArchitecture(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", fmt.Errorf("malformed native architecture output")
	}
	value := string(data[:len(data)-1])
	if !validAptArch(value) {
		return "", fmt.Errorf("invalid native architecture %q", value)
	}
	return value, nil
}

type aptPackageID struct {
	name, arch, version string
	explicitArch        bool
}

func parseAptReference(value, nativeArch string) (aptPackageID, error) {
	if !validAptArch(nativeArch) || value == "" || strings.Count(value, "=") > 1 {
		return aptPackageID{}, fmt.Errorf("invalid Apt package reference %q", value)
	}
	left, version := value, ""
	if index := strings.IndexByte(value, '='); index >= 0 {
		left, version = value[:index], value[index+1:]
		if !validAptVersion(version) {
			return aptPackageID{}, fmt.Errorf("invalid Apt package version")
		}
	}
	if strings.Count(left, ":") > 1 {
		return aptPackageID{}, fmt.Errorf("invalid Apt package identity")
	}
	name, arch := left, nativeArch
	explicitArch := false
	if index := strings.IndexByte(left, ':'); index >= 0 {
		name, arch = left[:index], left[index+1:]
		explicitArch = true
	}
	if !validAptName(name) || !validAptArch(arch) {
		return aptPackageID{}, fmt.Errorf("invalid Apt package identity")
	}
	return aptPackageID{name: name, arch: arch, version: version, explicitArch: explicitArch}, nil
}

func validAptName(value string) bool {
	if len(value) < 2 || !asciiLowerOrDigit(value[0]) {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && !strings.ContainsRune("+.-", character) {
			return false
		}
	}
	return true
}

func validAptArch(value string) bool {
	if value == "" || !asciiLowerOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !asciiLowerOrDigit(value[index]) && value[index] != '-' {
			return false
		}
	}
	return true
}

func asciiLowerOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validAptVersion(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune(".+:~-", character)) {
			return false
		}
	}
	return true
}

func (value aptPackageID) key() string { return value.name + "\t" + value.arch }
func (value aptPackageID) argument() string {
	terms := []string{"?exact-name(" + value.name + ")", "?architecture(" + value.arch + ")"}
	if value.version != "" {
		terms = append(terms, "?version(^"+regexp.QuoteMeta(value.version)+"$)")
	}
	return "?narrow(" + strings.Join(terms, ",") + ")"
}

func aptInventoryArgs() []string { return []string{"-W", "-f=" + aptQueryFormat} }

func aptTransactionArgs(preview bool, desired []aptPackageID) []string {
	args := []string{"-q=2"}
	if preview {
		args = append(args, "--simulate")
	}
	args = append(args,
		"--yes", "--no-remove", "--no-install-recommends",
		"-o", "APT::Get::allow-downgrades=false",
		"-o", "APT::Get::allow-change-held-packages=false",
		"-o", "APT::Get::allow-remove-essential=false",
		"-o", "APT::Get::AllowUnauthenticated=false",
		"-o", "APT::Get::force-yes=false",
		"install", "--",
	)
	for _, value := range desired {
		args = append(args, value.argument())
	}
	return args
}

type aptInstalled struct {
	id      aptPackageID
	version string
	status  string
	manual  bool
}

func (behavior aptBehavior) Observe(ctx context.Context, evidence proof, desired []string) (Observation, error) {
	native, ok := evidence.(aptProof)
	if !ok || !validAptArch(native.nativeArch) {
		return Observation{}, fmt.Errorf("Apt proof is required")
	}
	wants := append([]string(nil), desired...)
	sort.Strings(wants)
	refs := make([]aptPackageID, len(wants))
	seen := make(map[string]struct{}, len(wants))
	for index, value := range wants {
		if index != 0 && wants[index-1] == value {
			return Observation{}, fmt.Errorf("duplicate desired package %q", value)
		}
		var err error
		refs[index], err = parseAptReference(value, native.nativeArch)
		if err != nil {
			return Observation{}, err
		}
		if _, exists := seen[refs[index].key()]; exists {
			return Observation{}, fmt.Errorf("duplicate normalized Apt package %q", refs[index].key())
		}
		seen[refs[index].key()] = struct{}{}
	}
	result, err := behavior.effects.run(ctx, native.query, aptInventoryArgs(), nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe dpkg inventory", result, err))
	}
	installed, err := parseAptInventory(result.Stdout)
	if err != nil {
		return Observation{}, err
	}
	byKey := make(map[string]*aptInstalled, len(installed))
	for index := range installed {
		key := installed[index].id.key()
		if _, exists := byKey[key]; exists {
			return Observation{}, fmt.Errorf("duplicate dpkg package %q", key)
		}
		byKey[key] = &installed[index]
	}
	result, err = behavior.effects.run(ctx, native.mark, []string{"showmanual"}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe Apt roots", result, err))
	}
	if err := applyAptRoots(result.Stdout, native.nativeArch, byKey); err != nil {
		return Observation{}, err
	}
	records := make([]record, len(installed))
	roots := make([]string, 0)
	for index, value := range installed {
		records[index] = record{Key: value.id.key(), State: value.version + "\t" + value.status}
		if value.manual {
			roots = append(roots, value.id.key())
		}
	}
	inventory, err := newInventory(records, roots)
	if err != nil {
		return Observation{}, err
	}
	demands := make([]demand, len(wants))
	for index, ref := range refs {
		state := demandMissing
		if value := findAptInstalled(ref, byKey); value != nil && (ref.version == "" || ref.version == value.version) {
			state = demandDependency
			if value.manual {
				state = demandDirect
			}
		}
		demands[index] = demand{Name: wants[index], State: state}
	}
	return newObservation(wants, inventory, demands)
}

func findAptInstalled(ref aptPackageID, installed map[string]*aptInstalled) *aptInstalled {
	if value := installed[ref.key()]; value != nil {
		return value
	}
	if !ref.explicitArch && ref.arch != "all" {
		return installed[ref.name+"\tall"]
	}
	return nil
}

func parseAptInventory(data []byte) ([]aptInstalled, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("truncated dpkg inventory")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	values := make([]aptInstalled, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || !validAptArch(fields[1]) || len(fields[2]) != 3 || !validAptVersion(fields[3]) {
			return nil, fmt.Errorf("malformed dpkg inventory row")
		}
		name := strings.TrimSuffix(fields[0], ":"+fields[1])
		if !validAptName(name) {
			return nil, fmt.Errorf("malformed dpkg package identity")
		}
		switch fields[2] {
		case "ii ", "hi ":
			values = append(values, aptInstalled{id: aptPackageID{name: name, arch: fields[1]}, version: fields[3], status: fields[2]})
		case "rc ", "pc ":
			continue
		default:
			return nil, fmt.Errorf("unsupported dpkg status %q for %s", fields[2], fields[0])
		}
	}
	return values, nil
}

func applyAptRoots(data []byte, nativeArch string, installed map[string]*aptInstalled) error {
	if len(data) != 0 && data[len(data)-1] != '\n' {
		return fmt.Errorf("truncated Apt root output")
	}
	if len(data) == 0 {
		return nil
	}
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		ref, err := parseAptReference(line, nativeArch)
		if err != nil || ref.version != "" {
			return fmt.Errorf("malformed Apt root %q", line)
		}
		value := findAptInstalled(ref, installed)
		if value == nil || value.manual {
			return fmt.Errorf("contradictory Apt root %q", line)
		}
		value.manual = true
	}
	return nil
}

func aptRefsFromObservation(observation Observation, nativeArch string) ([]aptPackageID, error) {
	demands := observation.demands()
	refs := make([]aptPackageID, len(demands))
	for index, demand := range demands {
		var err error
		refs[index], err = parseAptReference(demand.Name, nativeArch)
		if err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func (behavior aptBehavior) Preview(ctx context.Context, evidence proof, observation Observation) (Offer, error) {
	native, ok := evidence.(aptProof)
	if !ok || !observation.valid() {
		return Offer{}, fmt.Errorf("Apt proof and observation are required")
	}
	refs, err := aptRefsFromObservation(observation, native.nativeArch)
	if err != nil {
		return Offer{}, err
	}
	result, err := behavior.effects.run(ctx, native.get, aptTransactionArgs(true, refs), nil)
	if err != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Offer{}, fmt.Errorf("%s", nativeDiagnostic("preview Apt transaction", result, err))
	}
	deltas, err := behavior.parseAptPreview(ctx, native, observation, result.Stdout)
	if err != nil {
		return Offer{}, err
	}
	for _, demand := range observation.demands() {
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

type aptPreviewInstall struct {
	id             aptPackageID
	old, candidate string
}

func (behavior aptBehavior) parseAptPreview(ctx context.Context, native aptProof, observation Observation, data []byte) ([]Delta, error) {
	if len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("truncated Apt preview")
	}
	held := make(map[string]bool)
	for _, record := range observation.inventory().installed() {
		if strings.HasSuffix(record.State, "\thi ") {
			held[record.Key] = true
		}
	}
	installs := make(map[string]aptPreviewInstall)
	configured := make(map[string]string)
	deltas := make([]Delta, 0)
	if len(data) == 0 {
		return deltas, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Inst "):
			value, err := parseAptInstallLine(line[5:], native.nativeArch)
			if err != nil || installs[value.id.key()].candidate != "" || held[value.id.key()] {
				if err == nil {
					err = fmt.Errorf("contradictory or held Apt install %q", value.id.key())
				}
				return nil, err
			}
			installs[value.id.key()] = value
		case strings.HasPrefix(line, "Conf "):
			id, version, err := parseAptCandidateLine(line[5:], native.nativeArch)
			if err != nil || configured[id.key()] != "" {
				if err == nil {
					err = fmt.Errorf("duplicate Apt configure %q", id.key())
				}
				return nil, err
			}
			configured[id.key()] = version
		case strings.HasPrefix(line, "Remv "):
			id, version, err := parseAptRemoveLine(line[5:], native.nativeArch)
			if err != nil {
				return nil, err
			}
			delta, err := newDelta(Remove, id.key(), version, "")
			if err != nil {
				return nil, err
			}
			deltas = append(deltas, delta)
		default:
			return nil, fmt.Errorf("unknown Apt preview operation")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Apt preview: %w", err)
	}
	keys := make([]string, 0, len(installs))
	for key := range installs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := installs[key]
		if configured[key] != value.candidate {
			return nil, fmt.Errorf("incomplete Apt configure evidence for %q", key)
		}
		kind := Add
		before := ""
		if value.old != "" {
			before = value.old
			kind = Replace
			if value.old != value.candidate {
				result, err := behavior.effects.run(ctx, native.dpkg, []string{"--compare-versions", value.old, "eq", value.candidate}, nil)
				if err != nil || !result.Started || (result.ExitCode != 0 && result.ExitCode != 1) || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
					return nil, fmt.Errorf("%s", nativeDiagnostic("compare Debian versions", result, err))
				}
				if result.ExitCode == 1 {
					kind = Upgrade
				}
			}
		}
		after := value.candidate
		if kind == Replace {
			after += " (reinstall)"
		}
		delta, err := newDelta(kind, key, before, after)
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, delta)
	}
	for key := range configured {
		if _, exists := installs[key]; !exists {
			return nil, fmt.Errorf("orphan Apt configure %q", key)
		}
	}
	return deltas, nil
}

func parseAptInstallLine(value, nativeArch string) (aptPreviewInstall, error) {
	name, rest, ok := strings.Cut(value, " ")
	if !ok {
		return aptPreviewInstall{}, fmt.Errorf("malformed Apt Inst row")
	}
	id, err := parseAptReference(name, nativeArch)
	if err != nil || id.version != "" {
		return aptPreviewInstall{}, fmt.Errorf("malformed Apt Inst identity")
	}
	old := ""
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "] ")
		if end < 2 || !validAptVersion(rest[1:end]) {
			return aptPreviewInstall{}, fmt.Errorf("malformed Apt current version")
		}
		old, rest = rest[1:end], rest[end+2:]
	}
	id, version, err := aptCandidateID(id, rest)
	if err != nil {
		return aptPreviewInstall{}, err
	}
	return aptPreviewInstall{id: id, old: old, candidate: version}, nil
}

func parseAptCandidateLine(value, nativeArch string) (aptPackageID, string, error) {
	name, rest, ok := strings.Cut(value, " ")
	if !ok {
		return aptPackageID{}, "", fmt.Errorf("malformed Apt Conf row")
	}
	id, err := parseAptReference(name, nativeArch)
	if err != nil || id.version != "" {
		return aptPackageID{}, "", fmt.Errorf("malformed Apt Conf identity")
	}
	return aptCandidateID(id, rest)
}

func aptCandidateID(id aptPackageID, value string) (aptPackageID, string, error) {
	version, arch, err := aptCandidate(value)
	if err != nil {
		return id, "", err
	}
	if id.explicitArch && id.arch != arch {
		return aptPackageID{}, "", fmt.Errorf("Apt candidate architecture differs from request")
	}
	id.arch = arch
	return id, version, nil
}

func aptCandidate(value string) (string, string, error) {
	if len(value) < 4 || value[0] != '(' || value[len(value)-1] != ')' {
		return "", "", fmt.Errorf("malformed Apt candidate")
	}
	fields := strings.Fields(value[1 : len(value)-1])
	last := ""
	if len(fields) != 0 {
		last = fields[len(fields)-1]
	}
	if len(fields) < 2 || !validAptVersion(fields[0]) || len(last) < 3 || last[0] != '[' || last[len(last)-1] != ']' || !validAptArch(last[1:len(last)-1]) {
		return "", "", fmt.Errorf("malformed Apt candidate")
	}
	return fields[0], last[1 : len(last)-1], nil
}

func parseAptRemoveLine(value, nativeArch string) (aptPackageID, string, error) {
	name, rest, ok := strings.Cut(value, " ")
	if !ok || len(rest) < 3 || rest[0] != '[' || rest[len(rest)-1] != ']' || !validAptVersion(rest[1:len(rest)-1]) {
		return aptPackageID{}, "", fmt.Errorf("malformed Apt Remv row")
	}
	id, err := parseAptReference(name, nativeArch)
	if err != nil || id.version != "" {
		return aptPackageID{}, "", fmt.Errorf("malformed Apt Remv identity")
	}
	return id, rest[1 : len(rest)-1], nil
}

func (behavior aptBehavior) Commit(ctx context.Context, evidence proof, observation Observation, expected Offer) (commitResult, error) {
	native, ok := evidence.(aptProof)
	if !ok || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("Apt proof, observation, and reviewed offer are required")
	}
	actual, err := behavior.Preview(ctx, evidence, observation)
	if err != nil {
		return commitResult{}, err
	}
	if !actual.equal(expected) {
		return commitResult{}, fmt.Errorf("%w: Apt transaction differs from reviewed offer", ErrStale)
	}
	refs, err := aptRefsFromObservation(observation, native.nativeArch)
	if err != nil {
		return commitResult{}, err
	}
	result, err := behavior.effects.run(ctx, native.get, aptTransactionArgs(false, refs), nil)
	commit := commitResult{Started: result.Started}
	if err != nil || !result.Started || result.ExitCode != 0 {
		return commit, fmt.Errorf("%s", nativeDiagnostic("commit Apt transaction", result, err))
	}
	return commit, nil
}

func (aptBehavior) Verify(before Observation, offer Offer, after Observation) error {
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
			if hadOld || !hasNew || new.State != delta.After()+"\tii " {
				return fmt.Errorf("Apt Add for %q does not match post-observation", delta.Key())
			}
			delete(current, delta.Key())
		case Upgrade:
			oldVersion, oldStatus, ok := strings.Cut(old.State, "\t")
			newVersion, newStatus, nextOK := strings.Cut(new.State, "\t")
			if !hadOld || !hasNew || !ok || !nextOK || oldVersion != delta.Before() || newVersion != delta.After() || oldStatus != newStatus {
				return fmt.Errorf("Apt Upgrade for %q does not match post-observation", delta.Key())
			}
			delete(prior, delta.Key())
			delete(current, delta.Key())
		}
	}
	if len(prior) != len(current) {
		return fmt.Errorf("Apt installed package set changed outside reviewed offer")
	}
	for key, record := range prior {
		if current[key] != record {
			return fmt.Errorf("Apt installed package %q changed outside reviewed offer", key)
		}
	}
	return nil
}
