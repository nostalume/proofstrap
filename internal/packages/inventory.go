package packages

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
)

func verifyRPMTransition(manager string, before Observation, offer Offer, after Observation) error {
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
			return fmt.Errorf("malformed reviewed %s package key", manager)
		}
		oldKey := name + "\t" + delta.Before() + "\t" + arch
		newKey := name + "\t" + delta.After() + "\t" + arch
		old, hadOld := prior[oldKey]
		new, hasNew := current[newKey]
		switch delta.Kind() {
		case Add:
			_, existed := priorAxes[delta.Key()]
			if delta.Before() != "" || existed || !hasNew {
				return fmt.Errorf("%s Add for %q does not match post-observation", manager, delta.Key())
			}
			delete(current, newKey)
		case Upgrade:
			if !hadOld || !hasNew || old.State != new.State {
				return fmt.Errorf("%s Upgrade for %q does not match post-observation", manager, delta.Key())
			}
			delete(prior, oldKey)
			delete(current, newKey)
		case Replace:
			unchanged, exists := current[oldKey]
			if !hadOld || !exists || old != unchanged {
				return fmt.Errorf("%s exact reinstall for %q does not match post-observation", manager, delta.Key())
			}
		}
	}
	return equalRemainingRecords(manager, prior, current)
}

type record struct {
	Key   string
	State string
}

type dnfInventoryDialect struct {
	name                       string
	canonicalEpoch, vendorAtom bool
	rootReason                 func(string) (bool, bool)
}

func parseDNFObservation(data []byte, desired []string, dialect dnfInventoryDialect) (Observation, error) {
	if len(data) != 0 && data[len(data)-1] != '\n' {
		return Observation{}, fmt.Errorf("truncated %s installed package query", dialect.name)
	}
	installed := make([]record, 0)
	roots := make([]string, 0)
	seenNames := make(map[string]bool)
	rootNames := make(map[string]bool)
	if len(data) != 0 {
		for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) != 7 {
				return Observation{}, fmt.Errorf("malformed %s installed package row", dialect.name)
			}
			name, epoch, version, release, arch, vendor, reason := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]
			epochNumber, epochErr := strconv.ParseUint(epoch, 10, 32)
			if binding.ValidatePackageName(name) != nil || epochErr != nil || !rpmAtom(version) || !rpmAtom(release) || !rpmAtom(arch) ||
				(dialect.vendorAtom && !rpmAtom(vendor)) || !dialect.vendorAtom && vendor == "" {
				return Observation{}, fmt.Errorf("malformed %s installed package row", dialect.name)
			}
			root, known := dialect.rootReason(reason)
			if !known {
				return Observation{}, fmt.Errorf("unknown %s installed package reason %q", dialect.name, reason)
			}
			if dialect.canonicalEpoch {
				epoch = strconv.FormatUint(epochNumber, 10)
			}
			key := name + "\t" + epoch + ":" + version + "-" + release + "\t" + arch
			installed = append(installed, record{Key: key, State: vendor})
			if root {
				roots = append(roots, key)
				rootNames[name] = true
			}
			seenNames[name] = true
		}
	}
	state, err := newInventory(installed, roots)
	if err != nil {
		return Observation{}, fmt.Errorf("%s installed package inventory: %w", dialect.name, err)
	}
	demands := make([]demand, len(desired))
	for index, name := range desired {
		status := demandMissing
		if seenNames[name] {
			status = demandDependency
		}
		if rootNames[name] {
			status = demandDirect
		}
		demands[index] = demand{Name: name, State: status}
	}
	return newObservation(desired, state, demands)
}

func validateRPMDesired(desired []string, manager string) error {
	for _, name := range desired {
		for index := range len(name) {
			character := name[index]
			if !rpmNameCharacter(character) && (index == 0 || !strings.ContainsRune("._+-", rune(character))) {
				return fmt.Errorf("%s desired package must be a concrete RPM name: %q", manager, name)
			}
		}
		if name == "" {
			return fmt.Errorf("%s desired package must be a concrete RPM name: %q", manager, name)
		}
	}
	return nil
}

func rpmNameCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func rpmAtom(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\t\n\r")
}

type inventoryState struct {
	installed []record
	roots     []string
}

type inventory struct{ state *inventoryState }

func newInventory(installed []record, roots []string) (inventory, error) {
	records := append([]record(nil), installed...)
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	for index, record := range records {
		if record.Key == "" {
			return inventory{}, fmt.Errorf("installed record key is required")
		}
		if index != 0 && records[index-1].Key == record.Key {
			return inventory{}, fmt.Errorf("duplicate installed record key %q", record.Key)
		}
	}
	canonicalRoots := append([]string(nil), roots...)
	sort.Strings(canonicalRoots)
	for index, root := range canonicalRoots {
		if root == "" {
			return inventory{}, fmt.Errorf("package root is required")
		}
		if index != 0 && canonicalRoots[index-1] == root {
			return inventory{}, fmt.Errorf("duplicate package root %q", root)
		}
	}
	return inventory{state: &inventoryState{installed: records, roots: canonicalRoots}}, nil
}

func (inventory inventory) valid() bool { return inventory.state != nil }

func (inventory inventory) installed() []record {
	if inventory.state == nil {
		return nil
	}
	return inventory.state.installed
}

func (inventory inventory) roots() []string {
	if inventory.state == nil {
		return nil
	}
	return inventory.state.roots
}

func (inventory inventory) equal(other inventory) bool {
	return inventory.state != nil && other.state != nil &&
		slices.Equal(inventory.state.installed, other.state.installed) && slices.Equal(inventory.state.roots, other.state.roots)
}

type demandState uint8

const (
	demandMissing demandState = iota + 1
	demandDependency
	demandDirect
)

type demand struct {
	Name  string
	State demandState
}

type observationState struct {
	inventory inventory
	demands   []demand
}

type Observation struct{ state *observationState }

func newObservation(desired []string, inventory inventory, demands []demand) (Observation, error) {
	if !inventory.valid() {
		return Observation{}, fmt.Errorf("complete inventory is required")
	}
	wants := append([]string(nil), desired...)
	sort.Strings(wants)
	for index, name := range wants {
		if err := binding.ValidatePackageName(name); err != nil {
			return Observation{}, fmt.Errorf("invalid desired package %q: %w", name, err)
		}
		if index != 0 && wants[index-1] == name {
			return Observation{}, fmt.Errorf("duplicate desired package %q", name)
		}
	}
	states := append([]demand(nil), demands...)
	sort.Slice(states, func(i, j int) bool { return states[i].Name < states[j].Name })
	if len(wants) != len(states) {
		return Observation{}, fmt.Errorf("demand results do not cover desired packages")
	}
	for index, state := range states {
		if state.State < demandMissing || state.State > demandDirect {
			return Observation{}, fmt.Errorf("invalid demand state for %q", state.Name)
		}
		if state.Name != wants[index] {
			return Observation{}, fmt.Errorf("demand result %q does not match desired package %q", state.Name, wants[index])
		}
	}
	return Observation{state: &observationState{inventory: inventory, demands: states}}, nil
}

func (observation Observation) valid() bool { return observation.state != nil }

func (observation Observation) inventory() inventory {
	if observation.state == nil {
		return inventory{}
	}
	return observation.state.inventory
}

func (observation Observation) demands() []demand {
	if observation.state == nil {
		return nil
	}
	return observation.state.demands
}

func (observation Observation) equal(other Observation) bool {
	return observation.state != nil && other.state != nil && observation.state.inventory.equal(other.state.inventory) &&
		slices.Equal(observation.state.demands, other.state.demands)
}

func verifyObservationTransition(before Observation, offer Offer, after Observation) ([]Delta, error) {
	if !before.valid() || !offer.valid() || !after.valid() {
		return nil, fmt.Errorf("complete package transition evidence is required")
	}
	beforeDemands, afterDemands := before.demands(), after.demands()
	if len(beforeDemands) != len(afterDemands) {
		return nil, fmt.Errorf("post-observation desired package set changed")
	}
	wantRoots := make(map[string]struct{})
	for index := range beforeDemands {
		if beforeDemands[index].Name != afterDemands[index].Name {
			return nil, fmt.Errorf("post-observation desired package set changed")
		}
		if afterDemands[index].State != demandDirect {
			return nil, fmt.Errorf("desired package %q is not direct after commit", afterDemands[index].Name)
		}
		if beforeDemands[index].State != demandDirect {
			wantRoots[beforeDemands[index].Name] = struct{}{}
		}
	}
	packageDeltas := make([]Delta, 0)
	rootDeltas := make(map[string]struct{})
	for _, delta := range offer.deltas() {
		switch delta.Kind() {
		case Add, Upgrade, Replace:
			packageDeltas = append(packageDeltas, delta)
		case RootAdd:
			if _, exists := rootDeltas[delta.Key()]; exists {
				return nil, fmt.Errorf("duplicate reviewed package root %q", delta.Key())
			}
			rootDeltas[delta.Key()] = struct{}{}
		default:
			return nil, fmt.Errorf("package verification received forbidden %s delta", delta.Kind())
		}
	}
	if len(rootDeltas) != len(wantRoots) {
		return nil, fmt.Errorf("reviewed package roots do not match pre-observation")
	}
	for _, delta := range packageDeltas {
		if delta.Kind() == Replace && !exactReinstallForRoot(delta, rootDeltas) {
			return nil, fmt.Errorf("package verification received forbidden %s delta", delta.Kind())
		}
	}
	for name := range wantRoots {
		if _, exists := rootDeltas[name]; !exists {
			return nil, fmt.Errorf("reviewed package root %q does not match pre-observation", name)
		}
	}
	beforeRoots, afterRoots := before.inventory().roots(), after.inventory().roots()
	left, right, added := 0, 0, 0
	for left < len(beforeRoots) && right < len(afterRoots) {
		switch {
		case beforeRoots[left] == afterRoots[right]:
			left++
			right++
		case beforeRoots[left] > afterRoots[right]:
			added++
			right++
		default:
			return nil, fmt.Errorf("package root %q disappeared after commit", beforeRoots[left])
		}
	}
	if left != len(beforeRoots) {
		return nil, fmt.Errorf("package root %q disappeared after commit", beforeRoots[left])
	}
	added += len(afterRoots) - right
	if len(rootDeltas) == 0 && added != 0 || len(rootDeltas) != 0 && (added == 0 || added > len(rootDeltas)) {
		return nil, fmt.Errorf("post-observation package root growth does not match reviewed roots")
	}
	return packageDeltas, nil
}

func equalRemainingRecords(manager string, prior, current map[string]record) error {
	if len(prior) != len(current) {
		return fmt.Errorf("%s installed package set changed outside reviewed offer", manager)
	}
	for key, record := range prior {
		if current[key] != record {
			return fmt.Errorf("%s installed package %q changed outside reviewed offer", manager, key)
		}
	}
	return nil
}
