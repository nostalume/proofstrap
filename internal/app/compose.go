package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
)

func compose(ctx context.Context, target config.Target, sources []pack.Source, backends binding.Backends) (binding.Graph, error) {
	if ctx == nil || ctx.Err() != nil {
		return binding.Graph{}, context.Canceled
	}
	byDigest := make(map[pack.Digest]pack.Source, len(sources))
	for _, source := range sources {
		if source.Digest() == (pack.Digest{}) {
			return binding.Graph{}, fmt.Errorf("invalid acquired source")
		}
		if _, exists := byDigest[source.Digest()]; exists {
			return binding.Graph{}, fmt.Errorf("duplicate acquired source %s", source.Digest())
		}
		byDigest[source.Digest()] = source
	}
	aliases := make(map[string]pack.Source, len(target.Sources()))
	for _, declared := range target.Sources() {
		source, exists := byDigest[declared.Digest]
		if !exists {
			return binding.Graph{}, fmt.Errorf("declared source %q is unavailable", declared.Alias)
		}
		aliases[declared.Alias] = source
	}

	type roots struct {
		source pack.Source
		values []profile.Root
	}
	semanticRoots := make(map[pack.Digest]roots)
	for _, selected := range target.Profiles() {
		source, exists := aliases[selected.Source]
		if !exists || source.Kind() != pack.Semantic {
			return binding.Graph{}, fmt.Errorf("profile source %q is unavailable or not semantic", selected.Source)
		}
		group := semanticRoots[source.Digest()]
		group.source = source
		group.values = append(group.values, selected.Root)
		semanticRoots[source.Digest()] = group
	}
	digests := make([]pack.Digest, 0, len(semanticRoots))
	for digest := range semanticRoots {
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
	graph := target.Direct()
	if graph.Nodes() == nil {
		graph = model.EmptyGraph()
	}
	for _, digest := range digests {
		group := semanticRoots[digest]
		resolved, err := pack.Resolve(ctx, group.source, sources)
		if err != nil {
			return binding.Graph{}, err
		}
		graph, err = profile.Expand(graph, resolved.Library(), group.values)
		if err != nil {
			return binding.Graph{}, err
		}
	}

	catalogues := make([]binding.Catalogue, 0, len(target.Bindings()))
	for _, selected := range target.Bindings() {
		source, exists := aliases[selected.Source]
		if !exists || source.Kind() != pack.Binding {
			return binding.Graph{}, fmt.Errorf("binding source %q is unavailable or not binding", selected.Source)
		}
		catalogue, err := pack.ResolveCatalogue(ctx, source, sources)
		if err != nil {
			return binding.Graph{}, err
		}
		catalogues = append(catalogues, catalogue)
	}
	return binding.Project(ctx, graph, backends, catalogues)
}
