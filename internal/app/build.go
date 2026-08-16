package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/inventory"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/packages"
	"github.com/nostalume/proofstrap/internal/services"
)

type Request struct {
	Origin      string
	Config      []byte
	Environment inventory.Environment
	Bundles     []string
}

func BuildPlan(ctx context.Context, request Request) (Plan, error) {
	if ctx != nil && ctx.Err() != nil {
		return Plan{}, ctx.Err()
	}
	deadline, bounded := time.Time{}, false
	if ctx != nil {
		deadline, bounded = ctx.Deadline()
	}
	if ctx == nil || !bounded || !deadline.After(time.Now()) {
		return Plan{}, fmt.Errorf("active bounded planning context is required")
	}
	target, err := config.Decode(request.Origin, request.Config)
	if err != nil {
		return Plan{}, err
	}
	declared := target.Sources()
	var sources []pack.Source
	if len(declared) == 0 {
		if len(request.Bundles) != 0 {
			return Plan{}, fmt.Errorf("bundles require declared source roots")
		}
	} else {
		roots := make([]pack.Digest, len(declared))
		for index, source := range declared {
			roots[index] = source.Digest
		}
		sources, err = inventory.AcquireClosure(ctx, request.Environment, roots, request.Bundles)
		if err != nil {
			return Plan{}, err
		}
	}

	var hostBackend binding.PackageBackendID
	if needsHostPackageBackend(target) {
		selection := packages.SelectHost(ctx)
		selected, issue := packageSelection(selection, "package:host")
		if issue != nil {
			return seal(body{blockers: []blocker{*issue}})
		}
		hostBackend = selected.Backend()
	}
	projected := binding.Graph{}
	if len(target.Profiles()) != 0 || len(target.Bindings()) != 0 || len(target.Direct().Nodes()) != 0 {
		semantic, catalogues, resolveErr := resolveComposition(ctx, target, sources)
		if resolveErr != nil {
			return Plan{}, resolveErr
		}
		var serviceBackend binding.ServiceBackendID
		if graphNeedsServiceBackend(semantic) {
			selected, selectErr := services.SelectHostSystem(ctx)
			if selectErr != nil {
				return seal(body{blockers: []blocker{{kind: "unsupported", resource: "service:host", detail: selectErr.Error()}}})
			}
			serviceBackend, _ = binding.NewServiceBackendID(selected.Backend())
		}
		projected, err = binding.Project(ctx, semantic, binding.Backends{Package: hostBackend, Service: serviceBackend}, catalogues)
		if err != nil {
			return Plan{}, err
		}
	}
	groups, err := groupPackages(target, projected, hostBackend)
	if err != nil {
		return Plan{}, err
	}
	packagePlan := lowerPackages(ctx, groups)
	operations := append([]operation(nil), packagePlan.operations...)
	blockers := append([]blocker(nil), packagePlan.blockers...)
	identityPlan := lowerIdentity(ctx, projected)
	operations = append(operations, identityPlan.operations...)
	blockers = append(blockers, identityPlan.blockers...)
	satisfies := make(map[string]string)
	operationIDs := make(map[string]struct{}, len(operations))
	for _, item := range operations {
		operationIDs[item.id] = struct{}{}
	}
	for _, node := range projected.Nodes() {
		if id, ok := binding.PackageIDOf(node); ok {
			operationID := "package:" + id.Backend().String()
			if _, exists := operationIDs[operationID]; exists {
				satisfies[node.Semantic().Key().Canonical()] = operationID
			}
		}
	}
	for resource, operationID := range identityPlan.satisfies {
		satisfies[resource] = operationID
	}
	hostPlan := lowerHost(ctx, projected, satisfies)
	operations = append(operations, hostPlan.operations...)
	blockers = append(blockers, hostPlan.blockers...)
	for resource, operationID := range hostPlan.satisfies {
		satisfies[resource] = operationID
	}
	servicePlan := lowerServices(ctx, target, projected, hostBackend, satisfies, operationIDs, identityPlan.facts)
	operations = append(operations, servicePlan.operations...)
	blockers = append(blockers, servicePlan.blockers...)
	if len(blockers) != 0 {
		return seal(body{blockers: blockers})
	}
	return seal(body{operations: operations})
}

func graphNeedsServiceBackend(graph model.Graph) bool {
	for _, node := range graph.Nodes() {
		if _, ok := model.ServiceIDOf(node); ok {
			return true
		}
	}
	return false
}

func needsHostPackageBackend(target config.Target) bool {
	if len(target.Profiles()) != 0 || len(target.Bindings()) != 0 {
		return true
	}
	for _, reference := range target.Packages() {
		if _, exact := reference.Exact(); !exact {
			return true
		}
	}
	return false
}

func packageSelection(selection packages.Selection, resource string) (packages.Selected, *blocker) {
	switch value := selection.(type) {
	case packages.Selected:
		return value, nil
	case packages.Unsupported:
		return packages.Selected{}, &blocker{kind: "unsupported", resource: resource, detail: "package backend is unavailable"}
	case packages.Indeterminate:
		return packages.Selected{}, &blocker{kind: "indeterminate", resource: resource, detail: value.Detail()}
	case packages.Ambiguous:
		names := make([]string, len(value.Backends()))
		for index, backend := range value.Backends() {
			names[index] = backend.String()
		}
		return packages.Selected{}, &blocker{kind: "ambiguous", resource: resource, detail: "admitted package backends: " + strings.Join(names, ",")}
	default:
		return packages.Selected{}, &blocker{kind: "indeterminate", resource: resource, detail: "invalid package selection"}
	}
}
