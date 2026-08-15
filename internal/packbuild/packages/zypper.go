package packages

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/linuxexec"
)

const (
	zypperPath = "/usr/bin/zypper"
	rpmPath    = "/usr/bin/rpm"
	rpmFormat  = `%{NAME:json}\t%{EPOCHNUM}\t%{VERSION:json}\t%{RELEASE:json}\t%{ARCH:json}\t%{VENDOR:json}\n`
)

type zypperProof struct {
	zypper        linuxexec.Identity
	zypperVersion string
	rpm           linuxexec.Identity
	rpmVersion    string
}

func (zypperProof) proof() {}
func (value zypperProof) equal(other proof) bool {
	candidate, ok := other.(zypperProof)
	return ok && value == candidate
}

type zypperBehavior struct{ effects effects }

func probeZypper(ctx context.Context, effect effects) candidate {
	backend, err := binding.NewPackageBackendID("zypper")
	if err != nil {
		panic(err)
	}
	zypper, err := effect.identify(zypperPath)
	if errors.Is(err, os.ErrNotExist) {
		return candidate{evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAbsent}}
	}
	if err != nil {
		return zypperIndeterminate(backend, fmt.Sprintf("identify zypper: %v", err))
	}
	rpm, err := effect.identify(rpmPath)
	if err != nil {
		return zypperIndeterminate(backend, fmt.Sprintf("identify rpm companion: %v", err))
	}

	result, err := effect.run(ctx, zypper, []string{"--version"}, nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		return zypperIndeterminate(backend, nativeDiagnostic("probe zypper", result, err))
	}
	zypperVersion, supported, err := parseZypperVersion(result.Stdout)
	if err != nil {
		return zypperIndeterminate(backend, err.Error())
	}
	if !supported {
		return candidate{evidence: candidateEvidence{
			backend: backend, role: SystemCandidate, state: candidateUnsupported,
			detail: "unsupported zypper version " + zypperVersion,
		}}
	}

	result, err = effect.run(ctx, rpm, rpmSelfArgs(), nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		return zypperIndeterminate(backend, nativeDiagnostic("probe rpm companion", result, err))
	}
	rows, err := parseRPMRows(result.Stdout)
	if err != nil || len(rows) != 1 || rows[0].name != "rpm" {
		if err == nil {
			err = fmt.Errorf("rpm self-query returned %d records", len(rows))
		}
		return zypperIndeterminate(backend, err.Error())
	}
	proof := zypperProof{
		zypper: zypper, zypperVersion: zypperVersion,
		rpm: rpm, rpmVersion: rows[0].version + "-" + rows[0].release,
	}
	return candidate{
		evidence: candidateEvidence{backend: backend, role: SystemCandidate, state: candidateAdmitted, proof: proof},
		behavior: zypperBehavior{effects: effect},
	}
}

func zypperIndeterminate(backend binding.PackageBackendID, detail string) candidate {
	return candidate{evidence: candidateEvidence{
		backend: backend, role: SystemCandidate, state: candidateIndeterminate, detail: detail,
	}}
}

func parseZypperVersion(data []byte) (string, bool, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || strings.Count(string(data), "\n") != 1 {
		return "", false, fmt.Errorf("malformed zypper version output")
	}
	fields := strings.Fields(strings.TrimSuffix(string(data), "\n"))
	if len(fields) != 2 || fields[0] != "zypper" {
		return "", false, fmt.Errorf("malformed zypper version output")
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) != 3 {
		return "", false, fmt.Errorf("malformed zypper version %q", fields[1])
	}
	for _, part := range parts {
		if part == "" {
			return "", false, fmt.Errorf("malformed zypper version %q", fields[1])
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return "", false, fmt.Errorf("malformed zypper version %q", fields[1])
		}
	}
	return fields[1], parts[0] == "1" && parts[1] == "14", nil
}

func rpmSelfArgs() []string      { return []string{"-q", "--queryformat", rpmFormat, "--", "rpm"} }
func rpmInventoryArgs() []string { return []string{"-qa", "--queryformat", rpmFormat} }
func rpmProviderArgs(name string) []string {
	return []string{"-q", "--whatprovides", "--queryformat", `%{NAME:json}\t%{ARCH:json}\n`, "--", name}
}
func zypperRootArgs() []string {
	return []string{"--terse", "--non-interactive", "--no-refresh", "packages", "--userinstalled"}
}
func zypperTransactionArgs(preview bool, desired []string) []string {
	args := []string{
		"--xmlout", "--non-interactive", "--no-refresh", "install",
	}
	if preview {
		args = append(args, "--dry-run")
	}
	args = append(args,
		"--details", "--no-recommends", "--no-force-resolution",
		"--no-allow-downgrade", "--no-allow-name-change", "--no-allow-arch-change", "--no-allow-vendor-change", "--",
	)
	return append(args, desired...)
}

type rpmRecord struct {
	name, epoch, version, release, arch, vendor string
}

func parseRPMRows(data []byte) ([]rpmRecord, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("truncated RPM query output")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	rows := make([]rpmRecord, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return nil, fmt.Errorf("malformed RPM query row")
		}
		decoded := make([]string, 0, 5)
		for _, index := range []int{0, 2, 3, 4, 5} {
			value, err := strconv.Unquote(fields[index])
			if err != nil {
				return nil, fmt.Errorf("malformed RPM JSON field: %w", err)
			}
			decoded = append(decoded, value)
		}
		epoch, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed RPM epoch %q", fields[1])
		}
		row := rpmRecord{
			name: decoded[0], epoch: strconv.FormatUint(epoch, 10), version: decoded[1],
			release: decoded[2], arch: decoded[3], vendor: decoded[4],
		}
		if row.name == "" || row.version == "" || row.release == "" || row.arch == "" {
			return nil, fmt.Errorf("incomplete RPM query row")
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (behavior zypperBehavior) Observe(ctx context.Context, evidence proof, desired []string) (Observation, error) {
	native, ok := evidence.(zypperProof)
	if !ok {
		return Observation{}, fmt.Errorf("zypper proof is required")
	}
	wants := append([]string(nil), desired...)
	sort.Strings(wants)
	for index, name := range wants {
		if err := binding.ValidatePackageName(name); err != nil {
			return Observation{}, err
		}
		if index != 0 && wants[index-1] == name {
			return Observation{}, fmt.Errorf("duplicate desired package %q", name)
		}
	}

	result, err := behavior.effects.run(ctx, native.rpm, rpmInventoryArgs(), nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe RPM inventory", result, err))
	}
	rows, err := parseRPMRows(result.Stdout)
	if err != nil {
		return Observation{}, err
	}
	records := make([]record, len(rows))
	for index, row := range rows {
		records[index] = record{
			Key:   row.name + "\t" + row.epoch + ":" + row.version + "-" + row.release + "\t" + row.arch,
			State: row.vendor,
		}
	}

	result, err = behavior.effects.run(ctx, native.zypper, zypperRootArgs(), nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		return Observation{}, fmt.Errorf("%s", nativeDiagnostic("observe Zypper roots", result, err))
	}
	roots, err := parseZypperRoots(result.Stdout)
	if err != nil {
		return Observation{}, err
	}
	inventory, err := newInventory(records, roots)
	if err != nil {
		return Observation{}, err
	}
	rootSet := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		rootSet[root] = struct{}{}
	}
	demands := make([]demand, 0, len(wants))
	for _, name := range wants {
		result, err = behavior.effects.run(ctx, native.rpm, rpmProviderArgs(name), nil)
		state, resolveErr := resolveZypperDemand(name, rootSet, result, err)
		if resolveErr != nil {
			return Observation{}, resolveErr
		}
		demands = append(demands, demand{Name: name, State: state})
	}
	return newObservation(wants, inventory, demands)
}

func parseZypperRoots(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	roots := make([]string, 0)
	for scanner.Scan() {
		line++
		text := scanner.Text()
		switch line {
		case 1:
			if text != "Loading repository data..." {
				return nil, fmt.Errorf("unexpected Zypper root prelude")
			}
		case 2:
			if text != "Reading installed packages..." {
				return nil, fmt.Errorf("unexpected Zypper root prelude")
			}
		case 3:
			if !slices.Equal(splitColumns(text, "|"), []string{"S", "Repository", "Name", "Version", "Arch"}) {
				return nil, fmt.Errorf("unexpected Zypper root header")
			}
		case 4:
			if !separatorColumns(text) {
				return nil, fmt.Errorf("unexpected Zypper root separator")
			}
		default:
			columns := splitColumns(text, "|")
			if len(columns) != 5 || columns[0] != "i+" || columns[1] != "@System" ||
				columns[2] == "" || columns[3] == "" || columns[4] == "" {
				return nil, fmt.Errorf("malformed Zypper root row")
			}
			roots = append(roots, columns[2]+"\t"+columns[4])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Zypper roots: %w", err)
	}
	if line < 4 || len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("truncated Zypper root output")
	}
	return roots, nil
}

func splitColumns(line, separator string) []string {
	parts := strings.Split(line, separator)
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func separatorColumns(line string) bool {
	columns := splitColumns(line, "+")
	if len(columns) != 5 {
		return false
	}
	for _, column := range columns {
		if len(column) < 1 || strings.Trim(column, "-") != "" {
			return false
		}
	}
	return true
}

func resolveZypperDemand(name string, roots map[string]struct{}, result linuxexec.Result, runErr error) (demandState, error) {
	if runErr != nil || !result.Started {
		return 0, fmt.Errorf("%s", nativeDiagnostic("resolve "+name, result, runErr))
	}
	if result.ExitCode == 1 && string(result.Stdout) == "no package provides "+name+"\n" && len(result.Stderr) == 0 {
		return demandMissing, nil
	}
	if result.ExitCode != 0 {
		return 0, fmt.Errorf("%s", nativeDiagnostic("resolve "+name, result, nil))
	}
	providers, err := parseProviderRows(result.Stdout)
	if err != nil || len(providers) == 0 {
		if err == nil {
			err = fmt.Errorf("empty provider result")
		}
		return 0, fmt.Errorf("resolve %s: %w", name, err)
	}
	for _, provider := range providers {
		if _, direct := roots[provider]; direct {
			return demandDirect, nil
		}
	}
	return demandDependency, nil
}

func parseProviderRows(data []byte) ([]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("truncated provider output")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	providers := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed provider row")
		}
		name, err := strconv.Unquote(fields[0])
		if err != nil {
			return nil, fmt.Errorf("malformed provider name: %w", err)
		}
		arch, err := strconv.Unquote(fields[1])
		if err != nil || name == "" || arch == "" {
			return nil, fmt.Errorf("malformed provider architecture")
		}
		providers = append(providers, name+"\t"+arch)
	}
	return providers, nil
}

func (behavior zypperBehavior) Preview(ctx context.Context, evidence proof, observation Observation) (Offer, error) {
	native, ok := evidence.(zypperProof)
	if !ok || !observation.valid() {
		return Offer{}, fmt.Errorf("zypper proof and observation are required")
	}
	desired := desiredFrom(observation)
	result, err := behavior.effects.run(ctx, native.zypper, zypperTransactionArgs(true, desired), nil)
	if err != nil || !result.Started || result.ExitCode != 0 {
		return Offer{}, fmt.Errorf("%s", nativeDiagnostic("preview Zypper transaction", result, err))
	}
	deltas, err := parseZypperOffer(result.Stdout)
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

func desiredFrom(observation Observation) []string {
	demands := observation.demands()
	desired := make([]string, len(demands))
	for index, demand := range demands {
		desired[index] = demand.Name
	}
	return desired
}

func parseZypperOffer(data []byte) ([]Delta, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	streams := 0
	summaries := 0
	declared := -1
	changes := 0
	deltas := make([]Delta, 0)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed Zypper preview XML: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "stream":
			streams++
			if streams != 1 {
				return nil, fmt.Errorf("duplicate Zypper XML stream")
			}
		case "message":
			if kind, found := xmlAttribute(start, "type"); !found || (kind != "info" && kind != "warning") {
				return nil, fmt.Errorf("unexpected Zypper message")
			}
			if err := decoder.Skip(); err != nil {
				return nil, fmt.Errorf("malformed Zypper preview XML: %w", err)
			}
		case "prompt":
			if err := parseZypperPrompt(decoder, start); err != nil {
				return nil, err
			}
		case "progress", "fileconflict-summary":
			if err := decoder.Skip(); err != nil {
				return nil, fmt.Errorf("malformed Zypper preview XML: %w", err)
			}
		case "install-summary":
			summaries++
			if summaries != 1 {
				return nil, fmt.Errorf("duplicate Zypper install summary")
			}
			value, found := xmlAttribute(start, "packages-to-change")
			if !found {
				return nil, fmt.Errorf("Zypper summary lacks package count")
			}
			declared, err = strconv.Atoi(value)
			if err != nil || declared < 0 {
				return nil, fmt.Errorf("invalid Zypper package count")
			}
			parsed, count, err := parseZypperSummary(decoder, start)
			if err != nil {
				return nil, err
			}
			deltas = append(deltas, parsed...)
			changes += count
		default:
			return nil, fmt.Errorf("unexpected Zypper preview element %q", start.Name.Local)
		}
	}
	if streams != 1 || summaries != 1 || declared != changes {
		return nil, fmt.Errorf("incomplete Zypper install summary")
	}
	return deltas, nil
}

func parseZypperPrompt(decoder *xml.Decoder, prompt xml.StartElement) error {
	accepted := false
	allowed := map[string]struct{}{"y": {}, "n": {}, "v": {}, "a": {}, "r": {}, "m": {}, "d": {}, "g": {}}
	for {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("malformed Zypper prompt: %w", err)
		}
		switch value := token.(type) {
		case xml.EndElement:
			if value.Name == prompt.Name {
				if !accepted {
					return fmt.Errorf("Zypper prompt requires unresolved policy")
				}
				return nil
			}
		case xml.StartElement:
			switch value.Name.Local {
			case "text", "description":
				if err := decoder.Skip(); err != nil {
					return fmt.Errorf("malformed Zypper prompt: %w", err)
				}
			case "option":
				choice, found := xmlAttribute(value, "value")
				if !found {
					return fmt.Errorf("malformed Zypper prompt option")
				}
				if _, ok := allowed[choice]; !ok {
					return fmt.Errorf("Zypper prompt requires unresolved policy")
				}
				if defaultValue, found := xmlAttribute(value, "default"); found && defaultValue == "1" && choice == "y" {
					accepted = true
				}
				if err := decoder.Skip(); err != nil {
					return fmt.Errorf("malformed Zypper prompt: %w", err)
				}
			default:
				return fmt.Errorf("unexpected Zypper prompt element %q", value.Name.Local)
			}
		}
	}
}

func parseZypperSummary(decoder *xml.Decoder, summary xml.StartElement) ([]Delta, int, error) {
	deltas := make([]Delta, 0)
	changes := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, 0, fmt.Errorf("malformed Zypper install summary: %w", err)
		}
		switch value := token.(type) {
		case xml.EndElement:
			if value.Name == summary.Name {
				return deltas, changes, nil
			}
		case xml.StartElement:
			groupKind, ok := zypperGroupKind(value.Name.Local)
			if !ok {
				return nil, 0, fmt.Errorf("unknown Zypper transaction section %q", value.Name.Local)
			}
			parsed, count, err := parseZypperGroup(decoder, value, groupKind)
			if err != nil {
				return nil, 0, err
			}
			deltas = append(deltas, parsed...)
			changes += count
		}
	}
}

type zypperTransactionGroup struct {
	state        DeltaKind
	architecture bool
}

func zypperGroupKind(name string) (zypperTransactionGroup, bool) {
	switch name {
	case "to-install":
		return zypperTransactionGroup{state: Add}, true
	case "to-upgrade":
		return zypperTransactionGroup{state: Upgrade}, true
	case "to-downgrade":
		return zypperTransactionGroup{state: Downgrade}, true
	case "to-remove":
		return zypperTransactionGroup{state: Remove}, true
	case "to-reinstall":
		return zypperTransactionGroup{state: Replace}, true
	case "to-upgrade-change-arch":
		return zypperTransactionGroup{state: Upgrade, architecture: true}, true
	case "to-downgrade-change-arch":
		return zypperTransactionGroup{state: Downgrade, architecture: true}, true
	case "to-change-arch":
		return zypperTransactionGroup{architecture: true}, true
	default:
		return zypperTransactionGroup{}, false
	}
}

func parseZypperGroup(decoder *xml.Decoder, group xml.StartElement, kind zypperTransactionGroup) ([]Delta, int, error) {
	deltas := make([]Delta, 0)
	count := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, 0, fmt.Errorf("malformed Zypper transaction section: %w", err)
		}
		switch value := token.(type) {
		case xml.EndElement:
			if value.Name == group.Name {
				return deltas, count, nil
			}
		case xml.StartElement:
			if value.Name.Local != "solvable" {
				return nil, 0, fmt.Errorf("unexpected Zypper transaction row %q", value.Name.Local)
			}
			rows, err := zypperSolvableDeltas(value, kind)
			if err != nil {
				return nil, 0, err
			}
			deltas = append(deltas, rows...)
			count++
			if err := decoder.Skip(); err != nil {
				return nil, 0, fmt.Errorf("malformed Zypper solvable: %w", err)
			}
		}
	}
}

func zypperSolvableDeltas(element xml.StartElement, group zypperTransactionGroup) ([]Delta, error) {
	name, hasName := xmlAttribute(element, "name")
	edition, hasEdition := xmlAttribute(element, "edition")
	arch, hasArch := xmlAttribute(element, "arch")
	kind, hasKind := xmlAttribute(element, "type")
	if !hasName || !hasEdition || !hasArch || !hasKind || kind != "package" || name == "" || edition == "" || arch == "" {
		return nil, fmt.Errorf("incomplete Zypper package solvable")
	}
	key := name + "\t" + arch
	deltas := make([]Delta, 0, 2)
	var delta Delta
	var err error
	switch group.state {
	case Add:
		delta, err = newDelta(Add, key, "", edition)
	case Remove:
		delta, err = newDelta(Remove, key, edition, "")
	case Replace:
		delta, err = newDelta(Replace, key, edition, edition+" (reinstall)")
	case Upgrade, Downgrade:
		old, found := xmlAttribute(element, "edition-old")
		if !found || old == "" {
			return nil, fmt.Errorf("Zypper transition lacks old edition")
		}
		delta, err = newDelta(group.state, key, old, edition)
	}
	if err != nil {
		return nil, err
	}
	if group.state != 0 {
		deltas = append(deltas, delta)
	}
	if group.architecture {
		oldArch, found := xmlAttribute(element, "arch-old")
		if !found || oldArch == "" {
			return nil, fmt.Errorf("Zypper architecture transition lacks old architecture")
		}
		architecture, err := newDelta(ArchitectureChange, key, oldArch, arch)
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, architecture)
	}
	return deltas, nil
}

func xmlAttribute(element xml.StartElement, name string) (string, bool) {
	for _, attribute := range element.Attr {
		if attribute.Name.Local == name {
			return attribute.Value, true
		}
	}
	return "", false
}

func (behavior zypperBehavior) Commit(ctx context.Context, evidence proof, observation Observation, expected Offer) (commitResult, error) {
	native, ok := evidence.(zypperProof)
	if !ok || !observation.valid() || !expected.valid() {
		return commitResult{}, fmt.Errorf("zypper proof, observation, and reviewed offer are required")
	}
	actual, err := behavior.Preview(ctx, evidence, observation)
	if err != nil {
		return commitResult{}, err
	}
	if !actual.equal(expected) {
		return commitResult{}, fmt.Errorf("%w: Zypper transaction differs from reviewed offer", ErrStale)
	}
	result, err := behavior.effects.run(ctx, native.zypper, zypperTransactionArgs(false, desiredFrom(observation)), nil)
	commit := commitResult{Started: result.Started}
	if err != nil || !result.Started || result.ExitCode != 0 {
		return commit, fmt.Errorf("%s", nativeDiagnostic("commit Zypper transaction", result, err))
	}
	return commit, nil
}

func (zypperBehavior) Verify(before Observation, offer Offer, after Observation) error {
	deltas, err := verifyObservationTransition(before, offer, after)
	if err != nil {
		return err
	}
	prior := make(map[string]record)
	priorAxes := make(map[string]struct{})
	current := make(map[string]record)
	for _, record := range before.inventory().installed() {
		prior[record.Key] = record
		fields := strings.Split(record.Key, "\t")
		if len(fields) == 3 {
			priorAxes[fields[0]+"\t"+fields[2]] = struct{}{}
		}
	}
	for _, record := range after.inventory().installed() {
		current[record.Key] = record
	}
	for _, delta := range deltas {
		name, arch, ok := strings.Cut(delta.Key(), "\t")
		if !ok {
			return fmt.Errorf("malformed reviewed Zypper package key")
		}
		oldKey := name + "\t" + delta.Before() + "\t" + arch
		newKey := name + "\t" + delta.After() + "\t" + arch
		old, hadOld := prior[oldKey]
		new, hasNew := current[newKey]
		switch delta.Kind() {
		case Add:
			_, existed := priorAxes[delta.Key()]
			if delta.Before() != "" || existed || !hasNew {
				return fmt.Errorf("Zypper Add for %q does not match post-observation", delta.Key())
			}
			delete(current, newKey)
		case Upgrade:
			if !hadOld || !hasNew || old.State != new.State {
				return fmt.Errorf("Zypper Upgrade for %q does not match post-observation", delta.Key())
			}
			delete(prior, oldKey)
			delete(current, newKey)
		}
	}
	return equalRemainingRecords("Zypper", prior, current)
}

func nativeDiagnostic(action string, result linuxexec.Result, err error) string {
	if err != nil {
		return fmt.Sprintf("%s: %v", action, err)
	}
	detail := result.Stderr
	if len(detail) == 0 {
		detail = result.Stdout
	}
	const limit = 4096
	if len(detail) > limit {
		detail = detail[:limit]
	}
	text := strings.TrimSpace(string(detail))
	if text == "" {
		return fmt.Sprintf("%s: native exit %d", action, result.ExitCode)
	}
	return fmt.Sprintf("%s: native exit %d: %s", action, result.ExitCode, text)
}
