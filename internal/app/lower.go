package app

import (
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
)

type packageGroup struct {
	backend      binding.PackageBackendID
	names        []string
	dependencies []string
}

func groupPackages(target config.Target, projected binding.Graph, host binding.PackageBackendID) ([]packageGroup, error) {
	type aggregate struct {
		backend      binding.PackageBackendID
		names        map[string]struct{}
		dependencies map[string]struct{}
	}
	groups := make(map[string]*aggregate)
	add := func(backend binding.PackageBackendID, name string) {
		key := backend.String()
		group := groups[key]
		if group == nil {
			group = &aggregate{backend: backend, names: make(map[string]struct{}), dependencies: make(map[string]struct{})}
			groups[key] = group
		}
		group.names[name] = struct{}{}
	}
	resolve := func(reference config.PackageRef) (binding.PackageBackendID, string, error) {
		if exact, ok := reference.Exact(); ok {
			return exact.Backend(), exact.Name(), nil
		}
		if host.String() == "" {
			return binding.PackageBackendID{}, "", fmt.Errorf("host package backend is required for %q", reference.Name())
		}
		return host, reference.Name(), nil
	}
	for _, node := range projected.Nodes() {
		if id, ok := binding.PackageIDOf(node); ok {
			add(id.Backend(), id.Name())
		}
	}
	for _, reference := range target.Packages() {
		backend, name, err := resolve(reference)
		if err != nil {
			return nil, err
		}
		add(backend, name)
	}
	for _, via := range target.Via() {
		group := groups[via.Backend().String()]
		if group == nil {
			return nil, fmt.Errorf("via backend %q has no demand", via.Backend())
		}
		for _, provider := range via.Packages() {
			backend, _, err := resolve(provider)
			if err != nil {
				return nil, err
			}
			dependency := "package:" + backend.String()
			if dependency == "package:"+via.Backend().String() {
				return nil, fmt.Errorf("package backend %q bootstraps itself", via.Backend())
			}
			group.dependencies[dependency] = struct{}{}
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]packageGroup, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		names := mapKeys(group.names)
		dependencies := mapKeys(group.dependencies)
		result = append(result, packageGroup{backend: group.backend, names: names, dependencies: dependencies})
	}
	return result, nil
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
