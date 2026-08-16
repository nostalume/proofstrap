package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linux"
)

const (
	dnf4Path = "/usr/bin/dnf4"
	dnfPath  = "/usr/bin/dnf"
)

type dnf4Proof struct {
	executable linux.Identity
	version    string
}

func (dnf4Proof) proof() {}
func (value dnf4Proof) equal(other proof) bool {
	candidate, ok := other.(dnf4Proof)
	return ok && value == candidate
}

type dnf4Behavior struct{ effects effects }

func probeDNF4(ctx context.Context, effect effects) candidate {
	backend, err := binding.NewPackageBackendID("dnf4")
	if err != nil {
		panic(err)
	}
	identities := make([]linux.Identity, 0, 2)
	for _, path := range []string{dnf4Path, dnfPath} {
		identity, identifyErr := effect.identify(path)
		switch {
		case errors.Is(identifyErr, os.ErrNotExist):
			continue
		case identifyErr != nil:
			return systemIndeterminate(backend, fmt.Sprintf("identify DNF4 alias %s: %v", path, identifyErr))
		}
		if len(identities) != 0 && identities[0] != identity {
			return systemIndeterminate(backend, "DNF4 aliases resolve to different executable identities")
		}
		if len(identities) == 0 {
			identities = append(identities, identity)
		}
	}
	if len(identities) == 0 {
		return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAbsent}}
	}
	result, runErr := effect.run(ctx, identities[0], []string{"--version"}, nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return systemIndeterminate(backend, nativeDiagnostic("probe DNF4", result, runErr))
	}
	version, supported, parseErr := parseDNF4Version(result.Stdout)
	if parseErr != nil {
		return systemIndeterminate(backend, parseErr.Error())
	}
	if !supported {
		return candidate{evidence: candidateEvidence{
			backend: backend, role: SystemCandidate, state: candidateUnsupported,
			detail: "unsupported DNF version " + version,
		}}
	}
	proof := dnf4Proof{executable: identities[0], version: version}
	return candidate{
		evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAdmitted, proof: proof},
		behavior: dnf4Behavior{effects: effect},
	}
}

func parseDNF4Version(data []byte) (string, bool, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return "", false, fmt.Errorf("malformed DNF version output")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	fields := strings.Fields(lines[0])
	value := ""
	switch {
	case len(fields) == 1:
		value = fields[0]
	case len(fields) == 3 && fields[0] == "dnf5" && fields[1] == "version":
		value = fields[2]
	default:
		return "", false, fmt.Errorf("malformed DNF version output")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", false, fmt.Errorf("malformed DNF version %q", value)
	}
	numbers := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" {
			return "", false, fmt.Errorf("malformed DNF version %q", value)
		}
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return "", false, fmt.Errorf("malformed DNF version %q", value)
		}
		numbers[index] = number
	}
	if fields[0] == "dnf5" {
		return value, false, nil
	}
	for index := 1; index < len(lines); {
		if lines[index] == "" {
			index++
			if index == len(lines) {
				return "", false, fmt.Errorf("malformed DNF version output")
			}
		}
		if index+1 >= len(lines) || !strings.HasPrefix(lines[index], "  Installed: ") ||
			!strings.HasPrefix(lines[index+1], "  Built    : ") {
			return "", false, fmt.Errorf("malformed DNF version output")
		}
		index += 2
	}
	if numbers[0] != 4 {
		return value, false, nil
	}
	supported := numbers[1] > 2 || numbers[1] == 2 && len(numbers) >= 3 && numbers[2] >= 23
	return value, supported, nil
}

func dnf4TransactionArgs(preview, cacheOnly bool, desired []string) []string {
	args := make([]string, 0, len(desired)+12)
	if cacheOnly {
		args = append(args, "--cacheonly")
	}
	args = append(args,
		"--color=never", "--setopt=best=true", "--setopt=multilib_policy=best",
		"--setopt=install_weak_deps=false", "--setopt=obsoletes=false",
		"--setopt=allow_vendor_change=false", "--setopt=strict=true", "--setopt=tsflags=",
	)
	if preview {
		args = append(args, "--assumeno")
	} else {
		args = append(args, "--assumeyes")
	}
	args = append(args, "install-n", "--")
	return append(args, desired...)
}

const dnf4InventoryFormat = "%{name}\\t%{epoch}\\t%{version}\\t%{release}\\t%{arch}\\t%{vendor}\\t%{reason}\\n"

func dnf4InventoryArgs() []string {
	return []string{
		"--cacheonly", "--quiet", "--disableexcludes=all", "repoquery", "--installed",
		"--queryformat=" + dnf4InventoryFormat,
	}
}

func (behavior dnf4Behavior) Observe(ctx context.Context, evidence proof, desired []string) (Observation, error) {
	native, ok := evidence.(dnf4Proof)
	if !ok {
		return Observation{}, fmt.Errorf("DNF4 proof is required")
	}
	if err := validateDNF4Desired(desired); err != nil {
		return Observation{}, err
	}
	result, runErr := behavior.effects.run(ctx, native.executable, dnf4InventoryArgs(), nil)
	if runErr != nil || !result.Started || result.ExitCode != 0 || len(result.Stderr) != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe DNF4 packages", result, runErr))
	}
	return parseDNF4Observation(result.Stdout, desired)
}

func parseDNF4Observation(data []byte, desired []string) (Observation, error) {
	return parseDNFObservation(data, desired, dnfInventoryDialect{
		name: "DNF4", canonicalEpoch: true, vendorAtom: true, rootReason: dnf4RootReason,
	})
}

func validateDNF4Desired(desired []string) error {
	return validateRPMDesired(desired, "DNF4")
}

func dnf4RootReason(reason string) (bool, bool) {
	switch reason {
	case "dependency", "weak-dependency":
		return false, true
	case "user", "group", "unknown":
		return true, true
	default:
		return false, false
	}
}

func (behavior dnf4Behavior) Preview(ctx context.Context, evidence proof, observation Observation) (Offer, error) {
	native, ok := evidence.(dnf4Proof)
	if !ok || !observation.valid() {
		return Offer{}, fmt.Errorf("DNF4 proof and observation are required")
	}
	return behavior.preview(ctx, native, observation, false)
}

func (behavior dnf4Behavior) preview(ctx context.Context, native dnf4Proof, observation Observation, cacheOnly bool) (Offer, error) {
	if err := validateDNF4Desired(desiredFrom(observation)); err != nil {
		return Offer{}, err
	}
	result, runErr := behavior.effects.run(ctx, native.executable, dnf4TransactionArgs(true, cacheOnly, desiredFrom(observation)), nil)
	if runErr != nil || !result.Started || len(result.Stderr) != 0 {
		return Offer{}, fmt.Errorf("%s", nativeDiagnostic("preview DNF4 transaction", result, runErr))
	}
	offer, transaction, err := parseDNF4Preview(result.Stdout, observation)
	if err != nil {
		return Offer{}, err
	}
	if transaction && result.ExitCode != 1 || !transaction && result.ExitCode != 0 {
		return Offer{}, fmt.Errorf("unexpected DNF4 preview exit %d", result.ExitCode)
	}
	return offer, nil
}

type dnf4PreviewRow struct {
	kind            DeltaKind
	name, arch, evr string
	requested       bool
}

func parseDNF4Preview(data []byte, observation Observation) (Offer, bool, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return Offer{}, false, fmt.Errorf("truncated DNF4 preview")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	resolved := -1
	for index, line := range lines {
		if line == "Dependencies resolved." {
			if resolved >= 0 {
				return Offer{}, false, fmt.Errorf("duplicate DNF4 preview envelope")
			}
			resolved = index
		}
	}
	if resolved < 0 {
		return Offer{}, false, fmt.Errorf("missing DNF4 dependency-resolution evidence")
	}
	semantic := lines[resolved+1:]
	if len(semantic) == 2 && semantic[0] == "Nothing to do." && semantic[1] == "Complete!" {
		for _, demand := range observation.demands() {
			if demand.State == demandMissing {
				return Offer{}, false, fmt.Errorf("DNF4 reported no package transaction for missing demand %q", demand.Name)
			}
		}
		offer, err := dnf4Offer(nil, observation)
		return offer, false, err
	}
	if len(semantic) < 8 || !dnf4Rule(semantic[0]) || semantic[2] != semantic[0] {
		return Offer{}, false, fmt.Errorf("malformed DNF4 transaction banner")
	}
	starts, err := dnf4Columns(semantic[1])
	if err != nil {
		return Offer{}, false, err
	}
	rows, summaryIndex, counts, err := dnf4Table(semantic, starts)
	if err != nil {
		return Offer{}, false, err
	}
	end, err := dnf4Summary(semantic, summaryIndex, semantic[0], counts)
	if err != nil {
		return Offer{}, false, err
	}
	if err := dnf4PreviewTail(semantic[end:]); err != nil {
		return Offer{}, false, err
	}
	offer, err := dnf4Offer(rows, observation)
	return offer, true, err
}

func dnf4Rule(line string) bool {
	if len(line) < 8 {
		return false
	}
	for index := range line {
		if line[index] != '=' {
			return false
		}
	}
	return true
}

func dnf4Columns(header string) ([]int, error) {
	starts := make([]int, 0, 5)
	fields := make([]string, 0, 5)
	for index := 0; index < len(header); {
		for index < len(header) && header[index] == ' ' {
			index++
		}
		if index == len(header) {
			break
		}
		start := index
		for index < len(header) && header[index] != ' ' {
			index++
		}
		starts = append(starts, start)
		fields = append(fields, header[start:index])
	}
	if len(fields) != 5 || fields[0] != "Package" || fields[2] != "Version" || fields[4] != "Size" ||
		(fields[1] != "Arch" && fields[1] != "Architecture") || (fields[3] != "Repo" && fields[3] != "Repository") {
		return nil, fmt.Errorf("unsupported DNF4 transaction header")
	}
	return starts, nil
}

func dnf4Table(lines []string, starts []int) ([]dnf4PreviewRow, int, map[string]int, error) {
	rows := make([]dnf4PreviewRow, 0)
	counts := map[string]int{"Install": 0, "Upgrade": 0, "Remove": 0, "Downgrade": 0, "Skip": 0}
	section := ""
	sectionRows := 0
	for index := 3; index < len(lines); index++ {
		line := lines[index]
		if line == "" {
			if section == "" || sectionRows == 0 || index+1 >= len(lines) || lines[index+1] != "Transaction Summary" {
				return nil, 0, nil, fmt.Errorf("malformed DNF4 transaction table")
			}
			return rows, index + 1, counts, nil
		}
		if strings.HasSuffix(line, ":") && line[0] != ' ' {
			if section != "" && sectionRows == 0 {
				return nil, 0, nil, fmt.Errorf("empty DNF4 transaction section %q", section)
			}
			section = strings.TrimSuffix(line, ":")
			sectionRows = 0
			if _, _, _, ok := dnf4Section(section); !ok {
				return nil, 0, nil, fmt.Errorf("unsupported DNF4 transaction section %q", section)
			}
			continue
		}
		kind, summary, requested, ok := dnf4Section(section)
		if !ok || strings.HasPrefix(strings.TrimSpace(line), "replacing ") {
			return nil, 0, nil, fmt.Errorf("unsupported DNF4 transaction row")
		}
		fields, err := dnf4TableFields(line, starts)
		if err != nil {
			return nil, 0, nil, err
		}
		if err := validateDNF4Desired([]string{fields[0]}); err != nil || !rpmAtom(fields[1]) || !rpmAtom(fields[3]) || !rpmAtom(fields[4]) {
			return nil, 0, nil, fmt.Errorf("malformed DNF4 transaction package row")
		}
		evr, err := normalizeDNF4EVR(fields[2])
		if err != nil {
			return nil, 0, nil, err
		}
		rows = append(rows, dnf4PreviewRow{kind: kind, name: fields[0], arch: fields[1], evr: evr, requested: requested})
		if summary != "" {
			counts[summary]++
		}
		sectionRows++
	}
	return nil, 0, nil, fmt.Errorf("missing DNF4 Transaction Summary")
}

func dnf4Section(section string) (DeltaKind, string, bool, bool) {
	switch section {
	case "Installing":
		return Add, "Install", true, true
	case "Installing dependencies":
		return Add, "Install", false, true
	case "Upgrading":
		return Upgrade, "Upgrade", true, true
	case "Reinstalling":
		return Replace, "", true, true
	case "Removing", "Removing dependent packages", "Removing unused dependencies":
		return Remove, "Remove", section == "Removing", true
	case "Downgrading":
		return Downgrade, "Downgrade", true, true
	default:
		return 0, "", false, false
	}
}

func dnf4TableFields(line string, starts []int) ([]string, error) {
	if len(starts) != 5 || len(line) <= starts[4] {
		return nil, fmt.Errorf("short DNF4 transaction row")
	}
	fields := make([]string, 5)
	for index := 0; index < 4; index++ {
		if len(line) < starts[index+1] {
			return nil, fmt.Errorf("short DNF4 transaction row")
		}
		fields[index] = strings.TrimSpace(line[starts[index]:starts[index+1]])
	}
	fields[4] = strings.TrimSpace(line[starts[4]:])
	for _, field := range fields {
		if field == "" {
			return nil, fmt.Errorf("incomplete DNF4 transaction row")
		}
	}
	return fields, nil
}

func normalizeDNF4EVR(value string) (string, error) {
	if !rpmAtom(value) {
		return "", fmt.Errorf("malformed DNF4 EVR %q", value)
	}
	epoch := "0"
	rest := value
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		epoch, rest = value[:colon], value[colon+1:]
	}
	if _, err := strconv.ParseUint(epoch, 10, 32); err != nil || rest == "" || !strings.Contains(rest, "-") {
		return "", fmt.Errorf("malformed DNF4 EVR %q", value)
	}
	return epoch + ":" + rest, nil
}

func dnf4Summary(lines []string, index int, rule string, expected map[string]int) (int, error) {
	if index+1 >= len(lines) || lines[index] != "Transaction Summary" || lines[index+1] != rule {
		return 0, fmt.Errorf("malformed DNF4 Transaction Summary")
	}
	actual := make(map[string]int)
	index += 2
	for index < len(lines) && lines[index] != "" {
		fields := strings.Fields(lines[index])
		if len(fields) != 3 || (fields[2] != "Package" && fields[2] != "Packages") {
			return 0, fmt.Errorf("malformed DNF4 summary row")
		}
		if _, known := expected[fields[0]]; !known || actual[fields[0]] != 0 {
			return 0, fmt.Errorf("unknown or duplicate DNF4 summary action %q", fields[0])
		}
		count, err := strconv.Atoi(fields[1])
		if err != nil || count <= 0 || fields[2] == "Package" && count != 1 || fields[2] == "Packages" && count == 1 {
			return 0, fmt.Errorf("malformed DNF4 summary count")
		}
		actual[fields[0]] = count
		index++
	}
	if index == len(lines) {
		return 0, fmt.Errorf("truncated DNF4 Transaction Summary")
	}
	for action, count := range expected {
		if actual[action] != count {
			return 0, fmt.Errorf("DNF4 summary %s count %d does not match %d rows", action, actual[action], count)
		}
	}
	return index + 1, nil
}

func dnf4PreviewTail(lines []string) error {
	if len(lines) == 0 || lines[len(lines)-1] != "Operation aborted." {
		return fmt.Errorf("missing DNF4 preview abort")
	}
	for _, line := range lines[:len(lines)-1] {
		if !strings.HasPrefix(line, "Total size: ") && !strings.HasPrefix(line, "Total download size: ") &&
			!strings.HasPrefix(line, "Installed size: ") && !strings.HasPrefix(line, "Freed space: ") {
			return fmt.Errorf("unsupported DNF4 preview trailer")
		}
	}
	return nil
}

func dnf4Offer(rows []dnf4PreviewRow, observation Observation) (Offer, error) {
	installed := make(map[string][]string)
	byName := make(map[string][]struct{ arch, evr string })
	for _, record := range observation.inventory().installed() {
		fields := strings.Split(record.Key, "\t")
		if len(fields) != 3 {
			return Offer{}, fmt.Errorf("malformed observed DNF4 package key")
		}
		installed[fields[0]+"\t"+fields[2]] = append(installed[fields[0]+"\t"+fields[2]], fields[1])
		byName[fields[0]] = append(byName[fields[0]], struct{ arch, evr string }{fields[2], fields[1]})
	}
	deltas := make([]Delta, 0, len(rows)+len(observation.demands()))
	requested := make(map[string]int)
	for _, row := range rows {
		key := row.name + "\t" + row.arch
		versions := installed[key]
		before := ""
		if row.kind != Add {
			if len(versions) == 1 {
				before = versions[0]
			} else if len(versions) == 0 && (row.kind == Upgrade || row.kind == Downgrade) && len(byName[row.name]) == 1 {
				before = byName[row.name][0].evr
				architecture, err := newDelta(ArchitectureChange, key, byName[row.name][0].arch, row.arch)
				if err != nil {
					return Offer{}, err
				}
				deltas = append(deltas, architecture)
			} else {
				return Offer{}, fmt.Errorf("DNF4 %s lacks one exact installed package", row.kind)
			}
		}
		if row.kind == Remove && before != row.evr || row.kind == Replace && before != row.evr {
			return Offer{}, fmt.Errorf("DNF4 %s does not match installed package", row.kind)
		}
		after := row.evr
		if row.kind == Remove {
			after = ""
		} else if row.kind == Replace {
			after += " (reinstall)"
		}
		delta, err := newDelta(row.kind, key, before, after)
		if err != nil {
			return Offer{}, err
		}
		deltas = append(deltas, delta)
		if row.requested {
			requested[row.name]++
		}
	}
	for _, demand := range observation.demands() {
		if requested[demand.Name] > 1 || demand.State == demandMissing && requested[demand.Name] != 1 {
			return Offer{}, fmt.Errorf("DNF4 transaction does not select desired package %q exactly", demand.Name)
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

func dnf4MarkArgs(identities []string) []string {
	args := []string{"--cacheonly", "--color=never", "mark", "install", "--"}
	return append(args, identities...)
}

func (behavior dnf4Behavior) Commit(ctx context.Context, evidence proof, observation Observation, expected Offer) (commitResult, error) {
	native, ok := evidence.(dnf4Proof)
	if !ok || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("DNF4 proof, observation, and reviewed offer are required")
	}
	actual, err := behavior.preview(ctx, native, observation, true)
	if err != nil {
		return commitResult{}, err
	}
	if !actual.equal(expected) {
		return commitResult{}, fmt.Errorf("%w: DNF4 transaction differs from reviewed offer", ErrStale)
	}
	corrections, err := dnf4RootCorrections(observation, expected)
	if err != nil {
		return commitResult{}, err
	}
	started := false
	if dnf4PackageChanges(expected) {
		result, runErr := behavior.effects.run(ctx, native.executable, dnf4TransactionArgs(false, true, desiredFrom(observation)), nil)
		started = result.Started
		if runErr != nil || !result.Started || result.ExitCode != 0 {
			return commitResult{Started: started}, fmt.Errorf("%s", nativeDiagnostic("commit DNF4 transaction", result, runErr))
		}
	}
	if len(corrections) != 0 {
		result, runErr := behavior.effects.run(ctx, native.executable, dnf4MarkArgs(corrections), nil)
		started = started || result.Started
		if runErr != nil || !result.Started || result.ExitCode != 0 {
			return commitResult{Started: started}, fmt.Errorf("%s", nativeDiagnostic("correct DNF4 package roots", result, runErr))
		}
	}
	return commitResult{Started: started}, nil
}

func (dnf4Behavior) Verify(before Observation, offer Offer, after Observation) error {
	return verifyRPMTransition("DNF4", before, offer, after)
}

func dnf4PackageChanges(offer Offer) bool {
	for _, delta := range offer.deltas() {
		switch delta.Kind() {
		case Add, Upgrade, Downgrade, Remove, Replace:
			return true
		}
	}
	return false
}

func dnf4RootCorrections(observation Observation, offer Offer) ([]string, error) {
	selected := make(map[string]string)
	for _, delta := range offer.deltas() {
		if delta.Kind() != Add && delta.Kind() != Upgrade {
			continue
		}
		fields := strings.Split(delta.Key(), "\t")
		if len(fields) != 2 || !rpmAtom(delta.After()) {
			return nil, fmt.Errorf("malformed DNF4 selected package delta")
		}
		identity := fields[0] + "-" + delta.After() + "." + fields[1]
		if prior := selected[fields[0]]; prior != "" && prior != identity {
			return nil, fmt.Errorf("ambiguous DNF4 selected root identity for %q", fields[0])
		}
		selected[fields[0]] = identity
	}
	installed := make(map[string][]string)
	for _, record := range observation.inventory().installed() {
		fields := strings.Split(record.Key, "\t")
		if len(fields) != 3 || !rpmAtom(fields[1]) || !rpmAtom(fields[2]) {
			return nil, fmt.Errorf("malformed observed DNF4 package key")
		}
		installed[fields[0]] = append(installed[fields[0]], fields[0]+"-"+fields[1]+"."+fields[2])
	}
	corrections := make([]string, 0)
	for _, demand := range observation.demands() {
		if demand.State != demandDependency {
			continue
		}
		identity := selected[demand.Name]
		if identity == "" {
			matches := installed[demand.Name]
			if len(matches) != 1 {
				return nil, fmt.Errorf("ambiguous DNF4 installed root identity for %q", demand.Name)
			}
			identity = matches[0]
		}
		corrections = append(corrections, identity)
	}
	sort.Strings(corrections)
	return corrections, nil
}
