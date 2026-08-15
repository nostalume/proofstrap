package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/identity"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/services"
)

type serviceItem struct {
	id, resource, user string
	demand             services.Demand
	dependencies       []string
}

type serviceResult struct {
	operations []operation
	blockers   []blocker
}

func lowerServices(ctx context.Context, target config.Target, projected binding.Graph, hostBackend binding.PackageBackendID, satisfies map[string]string, packageOperations map[string]struct{}, facts map[string]identity.AccountFact) serviceResult {
	result := serviceResult{}
	items := make(map[string]serviceItem)
	for _, node := range projected.Nodes() {
		id, ok := binding.ServiceIDOf(node)
		if !ok {
			continue
		}
		if id.Backend().String() != "systemd" {
			result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: "service:" + id.Backend().String() + ":" + id.Name(), detail: "service backend is unavailable"})
			continue
		}
		demand, err := services.DemandOf(node)
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: node.Key().Canonical(), detail: err.Error()})
			continue
		}
		user := ""
		if semantic, ok := model.ServiceOf(node.Semantic()); ok {
			user, _ = semantic.User()
		}
		item := serviceItem{id: serviceOperationBase(id.Name(), user), resource: node.Semantic().Key().Canonical(), user: user, demand: demand, dependencies: operationDependencies(node.Semantic(), satisfies)}
		if _, exists := items[item.id]; exists {
			result.blockers = append(result.blockers, blocker{kind: "conflict", resource: item.id, detail: "duplicate concrete service demand"})
		} else {
			items[item.id] = item
		}
	}
	for _, configured := range target.Services() {
		id, exact := configured.ID().Exact()
		if !exact {
			var err error
			backend, _ := binding.NewServiceBackendID("systemd")
			id, err = binding.NewServiceID(backend, configured.ID().Name())
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: "service", detail: err.Error()})
				continue
			}
		}
		if id.Backend().String() != "systemd" {
			result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: "service:" + id.Backend().String() + ":" + id.Name(), detail: "service backend is unavailable"})
			continue
		}
		demand, err := services.NewDemand(id, configured.Target(), configured.Enable(), configured.Run())
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: "service:" + id.Name(), detail: err.Error()})
			continue
		}
		user, _ := model.ServiceTargetUser(configured.Target())
		dependencies := map[string]struct{}{}
		if user != "" {
			if dependency := satisfies["account:"+user]; dependency != "" {
				dependencies[dependency] = struct{}{}
			}
		}
		for _, reference := range configured.Packages() {
			backend := hostBackend
			if native, ok := reference.Exact(); ok {
				backend = native.Backend()
			}
			operationID := "package:" + backend.String()
			if _, exists := packageOperations[operationID]; exists {
				dependencies[operationID] = struct{}{}
			}
		}
		item := serviceItem{id: serviceOperationBase(id.Name(), user), resource: "service:" + id.Backend().String() + ":" + id.Name(), user: user, demand: demand, dependencies: mapKeys(dependencies)}
		if _, exists := items[item.id]; exists {
			result.blockers = append(result.blockers, blocker{kind: "conflict", resource: item.id, detail: "duplicate concrete service demand"})
		} else {
			items[item.id] = item
		}
	}
	ordered := make([]serviceItem, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].id < ordered[j].id })
	byUser := map[string][]serviceItem{}
	for _, item := range ordered {
		if len(item.dependencies) > 0 {
			result.operations = append(result.operations, operation{
				id: item.id + ":barrier", kind: "barrier", dependencies: item.dependencies,
				review: encodeBarrierReview(item.resource, "systemd-control-plane", "establish the service prerequisites and create a fresh Plan"),
			})
			continue
		}
		byUser[item.user] = append(byUser[item.user], item)
	}
	users := make([]string, 0, len(byUser))
	for user := range byUser {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		var selected *services.Selected
		var err error
		if user == "" {
			selected, err = services.SelectSystem(ctx)
		} else if fact, exists := facts[user]; exists {
			principal, principalErr := services.NewPrincipal(fact.Name(), fact.UID(), fact.Home())
			if principalErr != nil {
				err = principalErr
			} else {
				selected, err = services.SelectUser(ctx, principal)
			}
		} else {
			err = fmt.Errorf("exact account fact is unavailable")
		}
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: "service-principal:" + user, detail: err.Error()})
			continue
		}
		demands := make([]services.Demand, len(byUser[user]))
		for index := range demands {
			demands[index] = byUser[user][index].demand
		}
		observed, err := selected.Observe(ctx, demands)
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: "service-principal:" + user, detail: err.Error()})
			continue
		}
		for _, item := range byUser[user] {
			plan, err := selected.Reconcile(item.demand, observed)
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: item.resource, detail: err.Error()})
				continue
			}
			if plan.Persistence().Kind() == services.Blocked {
				result.blockers = append(result.blockers, blocker{kind: "blocked", resource: item.resource, detail: plan.Persistence().Detail()})
				continue
			}
			if plan.Runtime().Kind() == services.Blocked {
				result.blockers = append(result.blockers, blocker{kind: "blocked", resource: item.resource, detail: plan.Runtime().Detail()})
				continue
			}
			prior := []string(nil)
			for index, native := range plan.Operations() {
				review, err := services.EncodeReview(native)
				if err != nil {
					result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: item.resource, detail: err.Error()})
					break
				}
				id := item.id + ":" + threeDigits(index)
				result.operations = append(result.operations, operation{id: id, kind: "service", dependencies: prior, review: review})
				prior = []string{id}
			}
		}
	}
	return result
}

func serviceOperationBase(unit, user string) string {
	if user == "" {
		return "service:system:" + unit
	}
	return "service:user:" + user + ":" + unit
}
