package packages

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type DeltaKind uint8

const (
	Add DeltaKind = iota + 1
	Upgrade
	Downgrade
	Remove
	Replace
	RootAdd
	RootRemove
	VendorChange
	ArchitectureChange
	Unclassified
)

func (kind DeltaKind) String() string {
	switch kind {
	case Add:
		return "add"
	case Upgrade:
		return "upgrade"
	case Downgrade:
		return "downgrade"
	case Remove:
		return "remove"
	case Replace:
		return "replace"
	case RootAdd:
		return "root-add"
	case RootRemove:
		return "root-remove"
	case VendorChange:
		return "vendor-change"
	case ArchitectureChange:
		return "architecture-change"
	case Unclassified:
		return "unclassified"
	default:
		return "invalid"
	}
}

type Delta struct {
	kind          DeltaKind
	key           string
	before, after string
}

func newDelta(kind DeltaKind, key, before, after string) (Delta, error) {
	if key == "" || kind < Add || kind > Unclassified {
		return Delta{}, fmt.Errorf("valid package delta kind and key are required")
	}
	valid := false
	switch kind {
	case Add, RootAdd:
		valid = before == "" && after != ""
	case Remove, RootRemove:
		valid = before != "" && after == ""
	default:
		valid = before != "" && after != "" && before != after
	}
	if !valid {
		return Delta{}, fmt.Errorf("invalid %s transition for %q", kind, key)
	}
	return Delta{kind: kind, key: key, before: before, after: after}, nil
}

func (delta Delta) Kind() DeltaKind { return delta.kind }
func (delta Delta) Key() string     { return delta.key }
func (delta Delta) Before() string  { return delta.before }
func (delta Delta) After() string   { return delta.after }

type offerState struct{ deltas []Delta }
type Offer struct{ state *offerState }

func newOffer(deltas []Delta) (Offer, error) {
	canonical := append([]Delta(nil), deltas...)
	axes := make(map[string]struct{}, len(canonical))
	for _, delta := range canonical {
		if _, err := newDelta(delta.kind, delta.key, delta.before, delta.after); err != nil {
			return Offer{}, err
		}
		if axis := deltaAxis(delta); axis != "" {
			key := delta.key + "\x00" + axis
			if _, exists := axes[key]; exists {
				return Offer{}, fmt.Errorf("contradictory %s deltas for %q", axis, delta.key)
			}
			axes[key] = struct{}{}
		}
	}
	sort.Slice(canonical, func(i, j int) bool { return deltaLess(canonical[i], canonical[j]) })
	for index := 1; index < len(canonical); index++ {
		if canonical[index-1] == canonical[index] {
			return Offer{}, fmt.Errorf("duplicate package delta for %q", canonical[index].key)
		}
	}
	return Offer{state: &offerState{deltas: canonical}}, nil
}

func deltaAxis(delta Delta) string {
	switch delta.kind {
	case Add, Upgrade, Downgrade, Remove, Replace:
		return "package-state"
	case RootAdd, RootRemove:
		return "root"
	case VendorChange:
		return "vendor"
	case ArchitectureChange:
		return "architecture"
	default:
		return ""
	}
}

func deltaLess(left, right Delta) bool {
	if left.kind != right.kind {
		return left.kind < right.kind
	}
	if left.key != right.key {
		return left.key < right.key
	}
	if left.before != right.before {
		return left.before < right.before
	}
	return left.after < right.after
}

func (offer Offer) valid() bool { return offer.state != nil }
func (offer Offer) deltas() []Delta {
	if offer.state == nil {
		return nil
	}
	return offer.state.deltas
}
func (offer Offer) Deltas() []Delta { return append([]Delta(nil), offer.deltas()...) }

func (offer Offer) equal(other Offer) bool {
	return offer.state != nil && other.state != nil && slices.Equal(offer.state.deltas, other.state.deltas)
}

type decisionState struct {
	offer    Offer
	blockers []Delta
}

type Decision struct{ state *decisionState }

func Decide(offer Offer) (Decision, error) {
	if !offer.valid() {
		return Decision{}, fmt.Errorf("valid package offer is required")
	}
	blockers := make([]Delta, 0)
	roots := make(map[string]struct{})
	for _, delta := range offer.state.deltas {
		if delta.kind == RootAdd {
			roots[delta.key] = struct{}{}
		}
	}
	for _, delta := range offer.state.deltas {
		if delta.kind != Add && delta.kind != Upgrade && delta.kind != RootAdd && !exactReinstallForRoot(delta, roots) {
			blockers = append(blockers, delta)
		}
	}
	return Decision{state: &decisionState{offer: offer, blockers: blockers}}, nil
}

func exactReinstallForRoot(delta Delta, roots map[string]struct{}) bool {
	name, _, ok := strings.Cut(delta.key, "\t")
	_, promoted := roots[name]
	return ok && promoted && delta.kind == Replace && delta.after == delta.before+" (reinstall)"
}

func (decision Decision) Allowed() bool {
	return decision.state != nil && len(decision.state.blockers) == 0
}

func (decision Decision) Blockers() []Delta {
	if decision.state == nil {
		return nil
	}
	return append([]Delta(nil), decision.state.blockers...)
}
