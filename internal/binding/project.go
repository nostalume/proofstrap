package binding

import (
	"context"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/model"
)

const (
	maxProjectedNodes      = 32768
	maxProjectedEdges      = 131072
	maxProjectedProvenance = 262144
)

type emission struct {
	key               Key
	semantic          model.Node
	provenance        []string
	bindingProvenance []string
	domain            Domain
	backend           string
	native            string
	semanticID        string
}

func Project(ctx context.Context, semantic model.Graph, backends Backends, active []Catalogue) (Graph, error) {
	if err := canceled(ctx); err != nil {
		return Graph{}, err
	}
	merged, disputed, conflicts, err := activeMappings(ctx, active, backends)
	if err != nil {
		return Graph{}, err
	}
	blockers := append([]Blocker(nil), conflicts...)
	emissions := make(map[string][]emission)
	nativeOwners := make(map[string]emission)
	nodeCount, provenanceCount := 0, 0
	for _, semanticNode := range semantic.Nodes() {
		if err := canceled(ctx); err != nil {
			return Graph{}, err
		}
		semanticKey := semanticNode.Key().Canonical()
		var emitted []emission
		if id, ok := model.PackageIDOf(semanticNode); ok {
			emitted, blockers = emitPackage(semanticNode, id, backends.Package, merged, disputed, blockers)
		} else if id, ok := model.ServiceIDOf(semanticNode); ok {
			emitted, blockers = emitService(semanticNode, id, backends.Service, merged, disputed, blockers)
		} else {
			emitted = []emission{{key: passthroughKey{semantic: semanticNode.Key()}, semantic: semanticNode, provenance: semanticNode.Provenance()}}
		}
		emissions[semanticKey] = emitted
		if nodeCount > maxProjectedNodes-len(emitted) {
			nodeCount = maxProjectedNodes + 1
		} else {
			nodeCount += len(emitted)
		}
		for _, item := range emitted {
			if provenanceCount > maxProjectedProvenance-len(item.provenance) {
				provenanceCount = maxProjectedProvenance + 1
			} else {
				provenanceCount += len(item.provenance)
			}
			if item.domain == 0 {
				continue
			}
			collision := item.domain.String() + "\x00" + item.backend + "\x00" + item.native
			if prior, exists := nativeOwners[collision]; exists && prior.semanticID != item.semanticID {
				blockers = append(blockers, Blocker{
					Kind: Conflict, Domain: item.domain, Backend: item.backend,
					Semantic: item.semanticID, Native: item.native,
					Sources: unionStrings(prior.bindingProvenance, item.bindingProvenance),
					Detail:  "native identity collision",
				})
				continue
			}
			nativeOwners[collision] = item
		}
	}
	if nodeCount > maxProjectedNodes {
		blockers = append(blockers, Blocker{Kind: Limit, Detail: "projected node limit exceeded"})
	}
	if provenanceCount > maxProjectedProvenance {
		blockers = append(blockers, Blocker{Kind: Limit, Detail: "projected provenance limit exceeded"})
	}
	edgeCount := 0
	for _, semanticNode := range semantic.Nodes() {
		if err := canceled(ctx); err != nil {
			return Graph{}, err
		}
		for _, dependency := range semanticNode.Dependencies() {
			var within bool
			edgeCount, within = addProduct(edgeCount,
				len(emissions[semanticNode.Key().Canonical()]), len(emissions[dependency.Canonical()]), maxProjectedEdges)
			if !within {
				break
			}
		}
	}
	if edgeCount > maxProjectedEdges {
		blockers = append(blockers, Blocker{Kind: Limit, Detail: "projected dependency edge limit exceeded"})
	}
	if err := canceled(ctx); err != nil {
		return Graph{}, err
	}
	if blockers = canonicalBlockers(blockers); len(blockers) > 0 {
		return Graph{}, &Blocked{blockers: blockers}
	}
	nodes := make(map[string]graphNode, nodeCount)
	for _, semanticNode := range semantic.Nodes() {
		dependencies := semanticNode.Dependencies()
		for _, item := range emissions[semanticNode.Key().Canonical()] {
			projectedDependencies := make([]Key, 0)
			for _, dependency := range dependencies {
				for _, prerequisite := range emissions[dependency.Canonical()] {
					projectedDependencies = append(projectedDependencies, prerequisite.key)
				}
			}
			sort.Slice(projectedDependencies, func(i, j int) bool {
				return projectedDependencies[i].Canonical() < projectedDependencies[j].Canonical()
			})
			nodes[item.key.Canonical()] = graphNode{
				key: item.key, semantic: item.semantic, dependencies: projectedDependencies,
				provenance: append([]string(nil), item.provenance...),
			}
		}
	}
	if err := canceled(ctx); err != nil {
		return Graph{}, err
	}
	return Graph{state: &graphState{nodes: nodes}}, nil
}

func activeMappings(ctx context.Context, active []Catalogue, backends Backends) (map[mappingKey]mapping, map[mappingKey]struct{}, []Blocker, error) {
	candidates := make(map[mappingKey][]mapping)
	var blockers []Blocker
	for _, catalogue := range active {
		if err := canceled(ctx); err != nil {
			return nil, nil, nil, err
		}
		if catalogue.state == nil {
			continue
		}
		for key, candidate := range catalogue.state.mappings {
			if err := canceled(ctx); err != nil {
				return nil, nil, nil, err
			}
			selected := key.domain == Package && key.backend == backends.Package.value ||
				key.domain == Service && key.backend == backends.Service.value
			if !selected {
				continue
			}
			candidates[key] = append(candidates[key], candidate)
		}
	}
	merged := make(map[mappingKey]mapping, len(candidates))
	disputed := make(map[mappingKey]struct{})
	keys := sortedMappingKeys(candidates)
	for _, key := range keys {
		byOutputs := make(map[string]mapping)
		allSources := []string(nil)
		for _, candidate := range candidates[key] {
			outputKey := strings.Join(candidate.outputs, "\x00")
			current := byOutputs[outputKey]
			current.outputs = candidate.outputs
			current.sources = unionStrings(current.sources, candidate.sources)
			byOutputs[outputKey] = current
			allSources = unionStrings(allSources, candidate.sources)
		}
		if len(byOutputs) != 1 {
			blockers = append(blockers, Blocker{Kind: Conflict, Domain: key.domain, Backend: key.backend,
				Semantic: key.semantic, Sources: allSources, Detail: "active catalogues disagree"})
			disputed[key] = struct{}{}
			continue
		}
		for _, value := range byOutputs {
			merged[key] = value
		}
	}
	return merged, disputed, blockers, nil
}

func addProduct(current, left, right, limit int) (int, bool) {
	if left == 0 || right == 0 {
		return current, true
	}
	if current > limit || left > (limit-current)/right {
		return limit + 1, false
	}
	return current + left*right, true
}

func sortedMappingKeys[V any](values map[mappingKey]V) []mappingKey {
	keys := make([]mappingKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := keys[i], keys[j]
		if left.domain != right.domain {
			return left.domain < right.domain
		}
		if left.backend != right.backend {
			return left.backend < right.backend
		}
		return left.semantic < right.semantic
	})
	return keys
}

func emitPackage(node model.Node, id model.PackageID, backend PackageBackendID, mappings map[mappingKey]mapping, disputed map[mappingKey]struct{}, blockers []Blocker) ([]emission, []Blocker) {
	key := mappingKey{domain: Package, backend: backend.value, semantic: id.String()}
	value, exists := mappings[key]
	if _, exists := disputed[key]; exists {
		return nil, blockers
	}
	if backend.value == "" || !exists {
		return nil, append(blockers, Blocker{Kind: Unsupported, Domain: Package, Backend: backend.value,
			Semantic: node.Key().Canonical(), Detail: "no active package mapping"})
	}
	result := make([]emission, 0, len(value.outputs))
	for _, output := range value.outputs {
		result = append(result, emission{key: packageKey{id: PackageID{backend: backend, name: output}}, semantic: node,
			provenance: unionStrings(node.Provenance(), value.sources), bindingProvenance: value.sources,
			domain: Package, backend: backend.value, native: output, semanticID: id.String()})
	}
	return result, blockers
}

func emitService(node model.Node, id model.ServiceID, backend ServiceBackendID, mappings map[mappingKey]mapping, disputed map[mappingKey]struct{}, blockers []Blocker) ([]emission, []Blocker) {
	key := mappingKey{domain: Service, backend: backend.value, semantic: id.String()}
	value, exists := mappings[key]
	if _, exists := disputed[key]; exists {
		return nil, blockers
	}
	if backend.value == "" || !exists {
		return nil, append(blockers, Blocker{Kind: Unsupported, Domain: Service, Backend: backend.value,
			Semantic: node.Key().Canonical(), Detail: "no active service mapping"})
	}
	result := make([]emission, 0, len(value.outputs))
	for _, output := range value.outputs {
		result = append(result, emission{key: serviceKey{id: ServiceID{backend: backend, name: output}, semantic: node.Key().Canonical()}, semantic: node,
			provenance: unionStrings(node.Provenance(), value.sources), bindingProvenance: value.sources,
			domain: Service, backend: backend.value, native: output, semanticID: id.String()})
	}
	return result, blockers
}
