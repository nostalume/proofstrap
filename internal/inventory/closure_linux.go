package inventory

import (
	"context"
	"errors"
	"sort"

	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

const maxClosureInputs = 64

// AcquireClosure reads explicit pack files once, loads missing digests from exact
// store locations, and returns only the closure reachable from roots.
func AcquireClosure(ctx context.Context, environment Environment, roots []pack.Digest, packFiles []string) ([]pack.Source, error) {
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	if len(roots) == 0 || len(roots) > maxClosureInputs || len(packFiles) > maxClosureInputs {
		return nil, diagnostic(pack.Limit, "", "closure requires 1..64 roots and at most 64 pack files", nil)
	}
	queue := append([]pack.Digest(nil), roots...)
	sort.Slice(queue, func(i, j int) bool { return queue[i].String() < queue[j].String() })
	for index, digest := range queue {
		if digest == (pack.Digest{}) {
			return nil, diagnostic(pack.InvalidValue, "", "closure root digest is required", nil)
		}
		if index > 0 && digest == queue[index-1] {
			return nil, diagnostic(pack.Duplicate, digest.String(), "duplicate closure root", nil)
		}
	}

	provided := make(map[pack.Digest]pack.Source, len(packFiles))
	paths := make(map[string]struct{}, len(packFiles))
	for _, path := range packFiles {
		if _, exists := paths[path]; exists {
			return nil, diagnostic(pack.Duplicate, path, "duplicate pack file path", nil)
		}
		paths[path] = struct{}{}
		source, err := readSource(ctx, path, "pack file")
		if err != nil {
			return nil, err
		}
		if _, exists := provided[source.Digest()]; exists {
			return nil, diagnostic(pack.Duplicate, path, "duplicate pack file digest", nil)
		}
		provided[source.Digest()] = source
	}

	stores, err := closureStores(environment)
	if err != nil {
		return nil, err
	}
	rootSet := make(map[pack.Digest]struct{}, len(roots))
	for _, digest := range roots {
		rootSet[digest] = struct{}{}
	}
	loaded := make(map[pack.Digest]pack.Source)
	usedPackFiles := make(map[pack.Digest]struct{})
	for len(queue) > 0 {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		digest := queue[0]
		queue = queue[1:]
		if _, exists := loaded[digest]; exists {
			continue
		}
		source, supplied := provided[digest]
		if supplied {
			usedPackFiles[digest] = struct{}{}
		} else {
			if len(stores) == 0 {
				return nil, diagnostic(pack.MissingRequirement, digest.String(), "exact source is unavailable", nil)
			}
			var loadErr error
			source, loadErr = pack.LoadExact(ctx, stores, digest)
			if loadErr != nil {
				return nil, diagnostic(packCategory(loadErr), digest.String(), "load exact closure source", loadErr)
			}
		}
		if _, root := rootSet[digest]; !root && source.Kind() != pack.Semantic {
			return nil, diagnostic(pack.KindMismatch, digest.String(), "required closure source is not semantic", nil)
		}
		loaded[digest] = source
		if len(loaded) > maxClosureInputs {
			return nil, diagnostic(pack.Limit, digest.String(), "closure source limit exceeded", nil)
		}
		for _, requirement := range source.Description().Requirements {
			queue = append(queue, requirement.Digest)
		}
	}
	for digest := range provided {
		if _, used := usedPackFiles[digest]; !used {
			return nil, diagnostic(pack.UnusedRequirement, digest.String(), "pack file is outside requested closure", nil)
		}
	}
	result := make([]pack.Source, 0, len(loaded))
	for _, source := range loaded {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Digest().String() < result[j].Digest().String() })
	return result, nil
}

func closureStores(environment Environment) ([]string, error) {
	roots := []string{environment.PackStore}
	if environment.PackStore == "" {
		roots = nil
	}
	scopes, err := availableScopes(environment)
	if err != nil {
		return nil, err
	}
	for _, candidate := range scopes {
		fd, exists, err := openScope(candidate.root)
		if err != nil {
			return nil, diagnostic(pack.CorruptStore, candidate.root, "scope is unsafe or incomplete", err)
		}
		if !exists {
			continue
		}
		if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EINTR) {
			return nil, diagnostic(pack.IO, candidate.root, "close scope", err)
		}
		roots = append(roots, candidate.root)
	}
	return roots, nil
}
