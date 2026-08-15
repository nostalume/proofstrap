package packages

import (
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
)

type record struct {
	Key   string
	State string
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
	if inventory.state == nil || other.state == nil {
		return false
	}
	if len(inventory.state.installed) != len(other.state.installed) || len(inventory.state.roots) != len(other.state.roots) {
		return false
	}
	for index, record := range inventory.state.installed {
		if record != other.state.installed[index] {
			return false
		}
	}
	for index, root := range inventory.state.roots {
		if root != other.state.roots[index] {
			return false
		}
	}
	return true
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
	if observation.state == nil || other.state == nil || !observation.state.inventory.equal(other.state.inventory) ||
		len(observation.state.demands) != len(other.state.demands) {
		return false
	}
	for index, demand := range observation.state.demands {
		if demand != other.state.demands[index] {
			return false
		}
	}
	return true
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
		case Add, Upgrade:
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
