package pack

import (
	"context"
	"sort"
)

// ResolveClosure returns exactly the sources reachable from roots. Provided
// sources take precedence over the loader and must all be reachable.
func ResolveClosure(ctx context.Context, roots []Digest, provided []Source, load func(context.Context, Digest) (Source, error)) ([]Source, error) {
	if ctx == nil {
		return nil, cancellationDiagnostic(context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return nil, cancellationDiagnostic(err)
	}
	if len(roots) == 0 || len(roots) > maxClosureSources || len(provided) > maxClosureSources {
		return nil, diagnostic(Limit, "", "", "closure requires 1..64 roots and at most 64 provided sources", nil)
	}
	inventory := make(map[Digest]Source, len(provided))
	for _, source := range provided {
		if source.state == nil || source.Digest() == (Digest{}) {
			return nil, diagnostic(InvalidValue, "", "", "provided source is invalid", nil)
		}
		if _, exists := inventory[source.Digest()]; exists {
			return nil, locatedDiagnostic(source, Duplicate, "", "", "duplicate provided source digest", nil)
		}
		inventory[source.Digest()] = source
	}
	orderedRoots := append([]Digest(nil), roots...)
	sort.Slice(orderedRoots, func(i, j int) bool { return orderedRoots[i].String() < orderedRoots[j].String() })
	for index, digest := range orderedRoots {
		if digest == (Digest{}) {
			return nil, diagnostic(InvalidValue, "", "", "closure root digest is required", nil)
		}
		if index > 0 && digest == orderedRoots[index-1] {
			return nil, &Diagnostic{Source: digest.String(), Category: Duplicate, Detail: "duplicate closure root"}
		}
	}
	ordered, used, err := walkClosure(ctx, orderedRoots, inventory, load)
	if err != nil {
		return nil, err
	}
	for digest := range inventory {
		if _, exists := used[digest]; !exists {
			return nil, &Diagnostic{Source: digest.String(), Category: UnusedRequirement, Detail: "provided source is outside requested closure"}
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Digest().String() < ordered[j].Digest().String() })
	return ordered, nil
}

func walkClosure(ctx context.Context, roots []Digest, inventory map[Digest]Source, load func(context.Context, Digest) (Source, error)) ([]Source, map[Digest]struct{}, error) {
	state := make(map[Digest]uint8)
	used := make(map[Digest]struct{})
	ordered := make([]Source, 0)
	var compressed int64
	var visit func(Digest, Source, string) error
	visit = func(digest Digest, parent Source, field string) error {
		if err := ctx.Err(); err != nil {
			return cancellationDiagnostic(err)
		}
		if state[digest] == 1 {
			return locatedDiagnostic(parent, Cycle, "manifest.toml", field, "requirement cycle", nil)
		}
		if state[digest] == 2 {
			return nil
		}
		source, exists := inventory[digest]
		if !exists && load != nil {
			var err error
			source, err = load(ctx, digest)
			if err != nil {
				return err
			}
			if source.state == nil || source.Digest() != digest {
				return &Diagnostic{Source: digest.String(), Category: Integrity, Detail: "loader returned a different or invalid source"}
			}
			inventory[digest] = source
			exists = true
		}
		if !exists {
			if parent.state != nil {
				return locatedDiagnostic(parent, MissingRequirement, "manifest.toml", field, "required source is unavailable", nil)
			}
			return &Diagnostic{Source: digest.String(), Category: MissingRequirement, Detail: "exact source is unavailable"}
		}
		if parent.state != nil && source.Kind() != Semantic {
			return locatedDiagnostic(parent, KindMismatch, "manifest.toml", field, "required source is not semantic", nil)
		}
		if len(state) >= maxClosureSources {
			return locatedDiagnostic(source, Limit, "manifest.toml", "requires", "closure source limit exceeded", nil)
		}
		compressed += source.state.compressed
		if compressed > maxClosureBytes {
			return locatedDiagnostic(source, Limit, "manifest.toml", "requires", "closure compressed-byte limit exceeded", nil)
		}
		state[digest] = 1
		used[digest] = struct{}{}
		for _, handle := range sortedRequirementHandles(source.state.requirements) {
			if err := visit(source.state.requirements[handle], source, "requires."+handle); err != nil {
				return err
			}
		}
		state[digest] = 2
		ordered = append(ordered, source)
		return nil
	}
	for _, digest := range roots {
		if err := visit(digest, Source{}, ""); err != nil {
			return nil, nil, err
		}
	}
	return ordered, used, nil
}
