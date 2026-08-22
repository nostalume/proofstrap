package document

import (
	"context"
	"fmt"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
)

func Resolve(ctx context.Context, target Document, sources []pack.Source) (model.Graph, []binding.Catalogue, error) {
	graph, catalogues, _, err := resolve(ctx, target, sources, "")
	return graph, catalogues, err
}

func ResolvePromotion(ctx context.Context, target Document, sources []pack.Source, alias string) (model.Graph, []binding.Catalogue, []profile.CallSyntax, error) {
	return resolve(ctx, target, sources, alias)
}

func resolve(ctx context.Context, target Document, sources []pack.Source, promotionAlias string) (model.Graph, []binding.Catalogue, []profile.CallSyntax, error) {
	if ctx == nil || ctx.Err() != nil {
		return model.Graph{}, nil, nil, context.Canceled
	}
	view := target.View()
	byDigest := make(map[pack.Digest]pack.Source, len(sources))
	for _, source := range sources {
		if source.Digest() == (pack.Digest{}) {
			return model.Graph{}, nil, nil, fmt.Errorf("invalid acquired source")
		}
		if _, exists := byDigest[source.Digest()]; exists {
			return model.Graph{}, nil, nil, fmt.Errorf("duplicate acquired source %s", source.Digest())
		}
		byDigest[source.Digest()] = source
	}
	aliases := make(map[string]pack.Source, len(view.Sources))
	for _, declared := range view.Sources {
		source, exists := byDigest[declared.Digest]
		if !exists {
			return model.Graph{}, nil, nil, fmt.Errorf("declared source %q is unavailable", declared.Name)
		}
		aliases[declared.Name] = source
	}
	used := make(map[string]struct{}, len(aliases))
	resolved := make(map[pack.Digest]pack.Pack)
	local := profile.Library{}
	resolveSemantic := func(alias string) (profile.Library, error) {
		source, exists := aliases[alias]
		if !exists || source.Kind() != pack.Semantic {
			return profile.Library{}, fmt.Errorf("profile source %q is unavailable or not semantic", alias)
		}
		if value, exists := resolved[source.Digest()]; exists {
			used[alias] = struct{}{}
			return value.Library(), nil
		}
		value, err := pack.Resolve(ctx, source, sources)
		if err != nil {
			return profile.Library{}, err
		}
		resolved[source.Digest()] = value
		used[alias] = struct{}{}
		return value.Library(), nil
	}
	resolveRequirements := func(handles []string) (map[string]profile.Library, error) {
		result := make(map[string]profile.Library, len(handles))
		for _, handle := range handles {
			library, err := resolveSemantic(handle)
			if err != nil {
				return nil, err
			}
			result[handle] = library
		}
		return result, nil
	}
	resolveProfile := func(value string) (profile.Library, string, error) {
		alias, name, ok := strings.Cut(value, ":")
		if !ok && profile.IsSymbol(value) && local.Present() {
			return local, value, nil
		}
		if !ok || strings.Contains(name, ":") || !profile.IsSymbol(alias) || !profile.IsSymbol(name) {
			return profile.Library{}, "", fmt.Errorf("profile reference must be ProfileID or source-alias:ProfileID")
		}
		library, err := resolveSemantic(alias)
		return library, name, err
	}

	if view.Profiles.Present() {
		required, err := resolveRequirements(profile.Requirements(view.Profiles))
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
		local, err = profile.Link(view.Origin, view.Profiles, required)
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	graph := view.Direct
	if graph.Nodes() == nil {
		graph = model.EmptyGraph()
	}
	identities := make(map[string]model.Key, len(graph.Nodes()))
	for _, node := range graph.Nodes() {
		identities[node.Key().Canonical()] = node.Key()
	}
	bound := make([]profile.Root, 0, len(view.Include))
	var promoted []profile.CallSyntax
	if promotionAlias != "" {
		promoted = make([]profile.CallSyntax, 0, len(view.Include))
	}
	for _, call := range view.Include {
		root, rendered, err := profile.BindCall(local, call, identities, resolveProfile, promotionAlias)
		if err != nil {
			return model.Graph{}, nil, nil, &Diagnostic{Category: "InvalidValue", Field: "include", Detail: err.Error()}
		}
		bound = append(bound, root)
		if rendered != nil {
			promoted = append(promoted, *rendered)
		}
	}
	if len(bound) != 0 {
		var err error
		graph, err = profile.Expand(graph, local, bound)
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	catalogues := make([]binding.Catalogue, 0, len(view.Bindings)+1)
	if view.Mappings.Present() {
		required, err := resolveRequirements(binding.Requirements(view.Mappings))
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
		catalogue, err := binding.Link(ctx, view.Mappings, local, required)
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
		catalogues = append(catalogues, catalogue)
	}
	for _, selected := range view.Bindings {
		source, exists := aliases[selected]
		if !exists || source.Kind() != pack.Binding {
			return model.Graph{}, nil, nil, fmt.Errorf("binding source %q is unavailable or not binding", selected)
		}
		catalogue, err := pack.ResolveCatalogue(ctx, source, sources)
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
		used[selected] = struct{}{}
		catalogues = append(catalogues, catalogue)
	}
	for _, source := range view.Sources {
		if _, exists := used[source.Name]; !exists {
			return model.Graph{}, nil, nil, &Diagnostic{Category: "UnusedSource", Field: "sources." + source.Name, Detail: "source alias is unused"}
		}
	}
	return graph, catalogues, promoted, nil
}
