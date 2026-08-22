package app

import (
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
)

type packageGroup struct {
	backend      binding.PackageBackendID
	names        []string
	dependencies []string
}

func groupPackages(projected binding.Graph) ([]packageGroup, error) {
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
	for _, node := range projected.Nodes() {
		if id, ok := binding.PackageIDOf(node); ok {
			add(id.Backend(), id.Name())
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
