package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/config"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
)

func compose(ctx context.Context, target config.Target, sources []pack.Source, backends binding.Backends) (binding.Graph, error) {
	graph, catalogues, err := resolveComposition(ctx, target, sources)
	if err != nil {
		return binding.Graph{}, err
	}
	return binding.Project(ctx, graph, backends, catalogues)
}

func resolveComposition(ctx context.Context, target config.Target, sources []pack.Source) (model.Graph, []binding.Catalogue, error) {
	if ctx == nil || ctx.Err() != nil {
		return model.Graph{}, nil, context.Canceled
	}
	byDigest := make(map[pack.Digest]pack.Source, len(sources))
	for _, source := range sources {
		if source.Digest() == (pack.Digest{}) {
			return model.Graph{}, nil, fmt.Errorf("invalid acquired source")
		}
		if _, exists := byDigest[source.Digest()]; exists {
			return model.Graph{}, nil, fmt.Errorf("duplicate acquired source %s", source.Digest())
		}
		byDigest[source.Digest()] = source
	}
	aliases := make(map[string]pack.Source, len(target.Sources()))
	for _, declared := range target.Sources() {
		source, exists := byDigest[declared.Digest]
		if !exists {
			return model.Graph{}, nil, fmt.Errorf("declared source %q is unavailable", declared.Alias)
		}
		aliases[declared.Alias] = source
	}
	used := make(map[string]struct{}, len(aliases))
	resolved := make(map[pack.Digest]pack.Pack)
	resolve := func(source pack.Source) (pack.Pack, error) {
		if value, exists := resolved[source.Digest()]; exists {
			return value, nil
		}
		value, err := pack.Resolve(ctx, source, sources)
		resolved[source.Digest()] = value
		return value, err
	}
	resolveProfile := func(value string) (profile.Library, string, error) {
		alias, name, ok := strings.Cut(value, ":")
		if !ok || strings.Contains(name, ":") || !profile.IsSymbol(alias) || !profile.IsSymbol(name) {
			return profile.Library{}, "", fmt.Errorf("profile reference must be source-alias:ProfileID")
		}
		source, exists := aliases[alias]
		if !exists || source.Kind() != pack.Semantic {
			return profile.Library{}, "", fmt.Errorf("profile source %q is unavailable or not semantic", alias)
		}
		packValue, err := resolve(source)
		if err != nil {
			return profile.Library{}, "", err
		}
		used[alias] = struct{}{}
		return packValue.Library(), name, nil
	}

	graph := target.Direct()
	if graph.Nodes() == nil {
		graph = model.EmptyGraph()
	}
	identities := make(map[string]model.Key, len(graph.Nodes()))
	for _, node := range graph.Nodes() {
		identities[node.Key().Canonical()] = node.Key()
	}
	bound := make([]profile.Root, 0, len(target.Profiles()))
	for _, selected := range target.Profiles() {
		source, exists := aliases[selected.Source]
		if !exists || source.Kind() != pack.Semantic {
			return model.Graph{}, nil, fmt.Errorf("profile source %q is unavailable or not semantic", selected.Source)
		}
		resolved, err := resolve(source)
		if err != nil {
			return model.Graph{}, nil, err
		}
		root, err := profile.BindRoot(resolved.Library(), selected.Name, selected.Arguments, identities, resolveProfile)
		if err != nil {
			return model.Graph{}, nil, &config.Diagnostic{Category: "InvalidValue", Field: "profiles." + selected.Source + ":" + selected.Name + ".arguments", Detail: err.Error()}
		}
		used[selected.Source] = struct{}{}
		bound = append(bound, root)
	}
	for _, selected := range target.Bindings() {
		source, exists := aliases[selected.Source]
		if !exists || source.Kind() != pack.Binding {
			return model.Graph{}, nil, fmt.Errorf("binding source %q is unavailable or not binding", selected.Source)
		}
		used[selected.Source] = struct{}{}
	}
	for _, source := range target.Sources() {
		if _, exists := used[source.Alias]; !exists {
			return model.Graph{}, nil, &config.Diagnostic{Category: "UnusedSource", Field: "sources." + source.Alias, Detail: "source alias is unused"}
		}
	}
	if len(bound) != 0 {
		var err error
		if graph, err = profile.Expand(graph, profile.Library{}, bound); err != nil {
			return model.Graph{}, nil, err
		}
	}
	catalogues := make([]binding.Catalogue, 0, len(target.Bindings()))
	for _, selected := range target.Bindings() {
		catalogue, err := pack.ResolveCatalogue(ctx, aliases[selected.Source], sources)
		if err != nil {
			return model.Graph{}, nil, err
		}
		catalogues = append(catalogues, catalogue)
	}
	return graph, catalogues, nil
}
