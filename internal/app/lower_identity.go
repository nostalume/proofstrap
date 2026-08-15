package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/identity"
	"github.com/nostalume/proofstrap/internal/model"
)

type identityResult struct {
	operations []operation
	satisfies  map[string]string
	facts      map[string]identity.AccountFact
	blockers   []blocker
}

func lowerIdentity(ctx context.Context, projected binding.Graph) identityResult {
	result := identityResult{satisfies: map[string]string{}, facts: map[string]identity.AccountFact{}}
	capabilities := identityCapabilities(projected)
	if len(capabilities) == 0 {
		return result
	}
	selected, err := identity.Select(ctx, capabilities)
	if err != nil {
		result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: "identity", detail: err.Error()})
		return result
	}
	groups := map[string]model.Group{}
	accounts := map[string]model.Account{}
	for _, node := range identityNodes(projected) {
		if value, ok := model.GroupOf(node.Semantic()); ok {
			groups[value.Name()] = value
		}
		if value, ok := model.AccountOf(node.Semantic()); ok {
			accounts[value.Name()] = value
		}
	}
	for _, node := range identityNodes(projected) {
		semantic := node.Semantic()
		if !isIdentityResource(semantic) {
			continue
		}
		dependencies := operationDependencies(semantic, result.satisfies)
		key := semantic.Key().Canonical()
		id := "identity:" + key
		if len(dependencies) > 0 && identityNeedsExistingPrincipal(semantic) {
			result.operations = append(result.operations, operation{
				id: id, kind: "barrier", dependencies: dependencies,
				review: encodeBarrierReview(key, "identity-principal", "establish the required identity and create a fresh Plan"),
			})
			result.satisfies[key] = id
			continue
		}
		planned, planErr := planIdentity(ctx, selected, semantic, groups, accounts)
		if planErr != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: key, detail: planErr.Error()})
			continue
		}
		if planned.Decision().Kind() == identity.Blocked {
			result.blockers = append(result.blockers, blocker{kind: "blocked", resource: key, detail: planned.Decision().Detail()})
			continue
		}
		if fact, ok := planned.AccountFact(); ok {
			result.facts[fact.Name()] = fact
		}
		native, changed := planned.Operation()
		if !changed {
			continue
		}
		review, encodeErr := identity.EncodeReview(native)
		if encodeErr != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: key, detail: encodeErr.Error()})
			continue
		}
		result.operations = append(result.operations, operation{id: id, kind: "identity", dependencies: dependencies, review: review})
		result.satisfies[key] = id
	}
	return result
}

func planIdentity(ctx context.Context, selected *identity.Selected, node model.Node, groups map[string]model.Group, accounts map[string]model.Account) (identity.Planned, error) {
	if value, ok := model.GroupOf(node); ok {
		return selected.PlanGroup(ctx, value)
	}
	if value, ok := model.AccountOf(node); ok {
		return selected.PlanAccount(ctx, value, groups[value.PrimaryGroup()])
	}
	if value, ok := model.HomeOf(node); ok {
		return selected.PlanHome(ctx, value, accounts[value.Account()])
	}
	if value, ok := model.HomeModeOf(node); ok {
		return selected.PlanHomeMode(ctx, value, accounts[value.Account()])
	}
	if value, ok := model.AccountLockOf(node); ok {
		return selected.PlanLock(ctx, value)
	}
	if value, ok := model.AccountShellOf(node); ok {
		return selected.PlanShell(ctx, value)
	}
	if value, ok := model.MembershipOf(node); ok {
		return selected.PlanMembership(ctx, value)
	}
	return identity.Planned{}, fmt.Errorf("unsupported identity resource")
}

func identityNodes(projected binding.Graph) []binding.Node {
	var result []binding.Node
	for _, node := range projected.Nodes() {
		if isIdentityResource(node.Semantic()) {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := identityRank(result[i].Semantic()), identityRank(result[j].Semantic())
		if left != right {
			return left < right
		}
		return result[i].Semantic().Key().Canonical() < result[j].Semantic().Key().Canonical()
	})
	return result
}

func identityRank(node model.Node) int {
	if _, ok := model.GroupOf(node); ok {
		return 0
	}
	if _, ok := model.AccountOf(node); ok {
		return 1
	}
	return 2
}

func operationDependencies(node model.Node, satisfies map[string]string) []string {
	values := map[string]struct{}{}
	for _, dependency := range node.Dependencies() {
		if id := satisfies[dependency.Canonical()]; id != "" {
			values[id] = struct{}{}
		}
	}
	return mapKeys(values)
}

func identityNeedsExistingPrincipal(node model.Node) bool {
	if _, ok := model.HomeOf(node); ok {
		return true
	}
	if _, ok := model.HomeModeOf(node); ok {
		return true
	}
	if _, ok := model.AccountLockOf(node); ok {
		return true
	}
	if _, ok := model.AccountShellOf(node); ok {
		return true
	}
	_, ok := model.MembershipOf(node)
	return ok
}

func identityCapabilities(projected binding.Graph) []identity.Capability {
	required := map[identity.Capability]bool{}
	for _, node := range projected.Nodes() {
		semantic := node.Semantic()
		switch {
		case isIdentityResource(semantic):
			required[identity.ObserveIdentity] = true
		}
		if value, ok := model.GroupOf(semantic); ok && value.Managed() {
			required[identity.CreateGroup] = true
		}
		if value, ok := model.AccountOf(semantic); ok && value.Managed() {
			required[identity.CreateAccount] = true
			required[identity.ObserveLock] = true
		}
		if _, ok := model.AccountLockOf(semantic); ok {
			required[identity.ObserveLock] = true
		}
		if _, ok := model.AccountShellOf(semantic); ok {
			required[identity.ModifyAccount] = true
		}
		if _, ok := model.MembershipOf(semantic); ok {
			required[identity.ModifyMembership] = true
		}
	}
	result := make([]identity.Capability, 0, len(required))
	for capability := identity.ObserveIdentity; capability <= identity.ModifyMembership; capability++ {
		if required[capability] {
			result = append(result, capability)
		}
	}
	return result
}

func isIdentityResource(node model.Node) bool {
	if _, ok := model.GroupOf(node); ok {
		return true
	}
	if _, ok := model.AccountOf(node); ok {
		return true
	}
	if _, ok := model.HomeOf(node); ok {
		return true
	}
	if _, ok := model.HomeModeOf(node); ok {
		return true
	}
	if _, ok := model.AccountLockOf(node); ok {
		return true
	}
	if _, ok := model.AccountShellOf(node); ok {
		return true
	}
	_, ok := model.MembershipOf(node)
	return ok
}
