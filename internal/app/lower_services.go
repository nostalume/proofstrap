package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/identity"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/services"
)

type serviceItem struct {
	id, resource, backend, user string
	demand                      services.Demand
	dependencies                []string
}

type serviceResult struct {
	operations []operation
	blockers   []blocker
}

func lowerServices(ctx context.Context, projected binding.Graph, satisfies map[string]string, facts map[string]identity.AccountFact) serviceResult {
	result := serviceResult{}
	items := make(map[string]serviceItem)
	for _, node := range projected.Nodes() {
		id, ok := binding.ServiceIDOf(node)
		if !ok {
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
		backend := id.Backend().String()
		item := serviceItem{id: serviceOperationBase(backend, id.Name(), user), resource: node.Semantic().Key().Canonical(), backend: backend, user: user, demand: demand, dependencies: operationDependencies(node.Semantic(), satisfies)}
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
	byPrincipal := map[string][]serviceItem{}
	for _, item := range ordered {
		if len(item.dependencies) > 0 {
			result.operations = append(result.operations, operation{
				id: item.id + ":barrier", kind: "barrier", dependencies: item.dependencies,
				review: encodeBarrierReview(item.resource, item.backend+"-control-plane", "establish the service prerequisites and create a fresh Plan"),
			})
			continue
		}
		key := item.backend + "\x00" + item.user
		byPrincipal[key] = append(byPrincipal[key], item)
	}
	principals := make([]string, 0, len(byPrincipal))
	for key := range byPrincipal {
		principals = append(principals, key)
	}
	sort.Strings(principals)
	for _, key := range principals {
		backend, user, _ := strings.Cut(key, "\x00")
		var selected *services.Selected
		var err error
		if user == "" {
			selected, err = services.SelectSystemBackend(ctx, backend)
		} else if fact, exists := facts[user]; exists {
			principal, principalErr := services.NewPrincipal(fact.Name(), fact.UID(), fact.Home())
			if principalErr != nil {
				err = principalErr
			} else {
				selected, err = services.SelectUserBackend(ctx, backend, principal)
			}
		} else {
			err = fmt.Errorf("exact account fact is unavailable")
		}
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: "service-principal:" + backend + ":" + user, detail: err.Error()})
			continue
		}
		demands := make([]services.Demand, len(byPrincipal[key]))
		for index := range demands {
			demands[index] = byPrincipal[key][index].demand
		}
		observed, err := selected.Observe(ctx, demands)
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: "service-principal:" + backend + ":" + user, detail: err.Error()})
			continue
		}
		for _, item := range byPrincipal[key] {
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

func serviceOperationBase(backend, unit, user string) string {
	if user == "" {
		return "service:" + backend + ":system:" + unit
	}
	return "service:" + backend + ":user:" + user + ":" + unit
}
