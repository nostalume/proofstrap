package app

import (
	"context"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/host"
	"github.com/nostalume/proofstrap/internal/model"
)

type hostResult struct {
	operations []operation
	satisfies  map[string]string
	blockers   []blocker
}

func lowerHost(ctx context.Context, projected binding.Graph, prior map[string]string) hostResult {
	result := hostResult{satisfies: map[string]string{}}
	for _, node := range projected.Nodes() {
		semantic := node.Semantic()
		key := semantic.Key().Canonical()
		dependencies := operationDependencies(semantic, prior)
		if hostname, ok := model.HostnameOf(semantic); ok {
			if len(dependencies) > 0 {
				id := "host:" + key + ":barrier"
				result.operations = append(result.operations, operation{
					id: id, kind: "barrier", dependencies: dependencies,
					review: encodeBarrierReview(key, "hostname-representation", "establish the prerequisite and create a fresh Plan"),
				})
				result.satisfies[key] = id
				continue
			}
			selected, err := host.SelectHostname(ctx)
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: key, detail: err.Error()})
				continue
			}
			plan, err := selected.PlanHostname(ctx, hostname)
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: key, detail: err.Error()})
				continue
			}
			operations := plan.Operations()
			result.addPlan(key, operations, func(index int) ([]byte, error) { return host.EncodeReview(operations[index]) }, dependencies)
			for _, axis := range []host.Axis{host.HostnamePersistence, host.HostnameRuntime} {
				if decision, exists := plan.Decision(axis); exists && decision.Kind() == host.Blocked {
					result.blockers = append(result.blockers, blocker{kind: "blocked", resource: key, detail: decision.Detail()})
				}
			}
		}
		if timezone, ok := model.TimezoneOf(semantic); ok {
			if len(dependencies) > 0 {
				id := "host:" + key + ":barrier"
				result.operations = append(result.operations, operation{
					id: id, kind: "barrier", dependencies: dependencies,
					review: encodeBarrierReview(key, "timezone-representation", "establish the prerequisite and create a fresh Plan"),
				})
				result.satisfies[key] = id
				continue
			}
			selected, err := host.SelectTimezone(ctx)
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "unsupported", resource: key, detail: err.Error()})
				continue
			}
			plan, err := selected.PlanTimezone(ctx, timezone)
			if err != nil {
				result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: key, detail: err.Error()})
				continue
			}
			operations := plan.Operations()
			result.addPlan(key, operations, func(index int) ([]byte, error) { return host.EncodeReview(operations[index]) }, dependencies)
			if decision, exists := plan.Decision(host.TimezonePersistence); exists && decision.Kind() == host.Blocked {
				result.blockers = append(result.blockers, blocker{kind: "blocked", resource: key, detail: decision.Detail()})
			}
		}
	}
	return result
}

func (result *hostResult) addPlan(key string, native []host.Operation, encode func(int) ([]byte, error), dependencies []string) {
	prior := append([]string(nil), dependencies...)
	for index := range native {
		review, err := encode(index)
		if err != nil {
			result.blockers = append(result.blockers, blocker{kind: "indeterminate", resource: key, detail: err.Error()})
			return
		}
		id := "host:" + key + ":" + threeDigits(index)
		result.operations = append(result.operations, operation{id: id, kind: "host", dependencies: prior, review: review})
		prior = []string{id}
		result.satisfies[key] = id
	}
}

func threeDigits(value int) string {
	return string([]byte{'0' + byte(value/100%10), '0' + byte(value/10%10), '0' + byte(value%10)})
}
