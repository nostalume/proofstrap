package app

import (
	"context"

	"github.com/nostalume/proofstrap/internal/packbuild/packages"
)

type packageResult struct {
	operations []operation
	blockers   []blocker
}

type packagePlanner func(packageGroup) (operation, bool, *blocker)

func lowerPackageGroups(groups []packageGroup, plan packagePlanner) packageResult {
	result := packageResult{}
	byID := make(map[string]packageGroup, len(groups))
	for _, group := range groups {
		byID["package:"+group.backend.String()] = group
	}
	state := make(map[string]uint8, len(groups))
	outputs := make(map[string]string, len(groups))
	failed := make(map[string]bool, len(groups))
	var visit func(string)
	visit = func(id string) {
		if state[id] == 2 {
			return
		}
		if state[id] == 1 {
			result.blockers = append(result.blockers, blocker{kind: "cycle", resource: id, detail: "package backend dependency cycle"})
			failed[id] = true
			return
		}
		group, exists := byID[id]
		if !exists {
			result.blockers = append(result.blockers, blocker{kind: "missing", resource: id, detail: "package provider group is missing"})
			failed[id] = true
			return
		}
		state[id] = 1
		var pending []string
		for _, dependency := range group.dependencies {
			visit(dependency)
			if failed[dependency] {
				failed[id] = true
			}
			if output := outputs[dependency]; output != "" {
				pending = append(pending, output)
			}
		}
		if !failed[id] {
			if len(pending) > 0 {
				result.operations = append(result.operations, operation{
					id: id, kind: "barrier", dependencies: pending,
					review: encodeBarrierReview(id, "package-backend:"+group.backend.String(), "install the provider packages and create a fresh Plan"),
				})
				outputs[id] = id
			} else {
				operation, changed, issue := plan(group)
				if issue != nil {
					result.blockers = append(result.blockers, *issue)
					failed[id] = true
				} else if changed {
					result.operations = append(result.operations, operation)
					outputs[id] = operation.id
				}
			}
		}
		state[id] = 2
	}
	for _, group := range groups {
		visit("package:" + group.backend.String())
	}
	return result
}

func lowerPackages(ctx context.Context, groups []packageGroup) packageResult {
	return lowerPackageGroups(groups, func(group packageGroup) (operation, bool, *blocker) {
		resource := "package:" + group.backend.String()
		selected, issue := packageSelection(packages.SelectExact(ctx, group.backend), resource)
		if issue != nil {
			return operation{}, false, issue
		}
		observed, err := selected.Observe(ctx, group.names)
		if err != nil {
			return operation{}, false, &blocker{kind: "indeterminate", resource: resource, detail: err.Error()}
		}
		offer, err := selected.Preview(ctx, observed)
		if err != nil {
			return operation{}, false, &blocker{kind: "indeterminate", resource: resource, detail: err.Error()}
		}
		decision, err := packages.Decide(offer)
		if err != nil {
			return operation{}, false, &blocker{kind: "indeterminate", resource: resource, detail: err.Error()}
		}
		if !decision.Allowed() {
			return operation{}, false, &blocker{kind: "forbidden", resource: resource, detail: "package offer contains forbidden transitions"}
		}
		if len(offer.Deltas()) == 0 {
			return operation{}, false, nil
		}
		native, err := packages.NewOperation(selected, observed, decision)
		if err != nil {
			return operation{}, false, &blocker{kind: "indeterminate", resource: resource, detail: err.Error()}
		}
		review, err := packages.EncodeReview(native)
		if err != nil {
			return operation{}, false, &blocker{kind: "indeterminate", resource: resource, detail: err.Error()}
		}
		return operation{id: resource, kind: "package", review: review}, true, nil
	})
}
