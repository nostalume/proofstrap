package inventory

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

const maxClosureInputs = 64

// AcquireClosure reads explicit bundles once, loads missing digests from exact
// store locations, and returns only the closure reachable from roots.
func AcquireClosure(ctx context.Context, environment Environment, roots []pack.Digest, bundles []string) ([]pack.Source, error) {
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	if len(roots) == 0 || len(roots) > maxClosureInputs || len(bundles) > maxClosureInputs {
		return nil, diagnostic(pack.Limit, "", "closure requires 1..64 roots and at most 64 bundles", nil)
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

	provided := make(map[pack.Digest]pack.Source, len(bundles))
	paths := make(map[string]struct{}, len(bundles))
	for _, path := range bundles {
		if _, exists := paths[path]; exists {
			return nil, diagnostic(pack.Duplicate, path, "duplicate bundle path", nil)
		}
		paths[path] = struct{}{}
		source, err := readBundle(ctx, path)
		if err != nil {
			return nil, err
		}
		if _, exists := provided[source.Digest()]; exists {
			return nil, diagnostic(pack.Duplicate, path, "duplicate bundle digest", nil)
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
	usedBundles := make(map[pack.Digest]struct{})
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
			usedBundles[digest] = struct{}{}
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
		if _, used := usedBundles[digest]; !used {
			return nil, diagnostic(pack.UnusedRequirement, digest.String(), "bundle is outside requested closure", nil)
		}
	}
	result := make([]pack.Source, 0, len(loaded))
	for _, source := range loaded {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Digest().String() < result[j].Digest().String() })
	return result, nil
}

func readBundle(ctx context.Context, path string) (pack.Source, error) {
	if !validPath(path) {
		return pack.Source{}, diagnostic(pack.InvalidValue, path, "bundle path must be clean absolute and non-root", nil)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return pack.Source{}, diagnostic(pack.IO, path, "open bundle", err)
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return pack.Source{}, diagnostic(pack.IO, path, "inspect bundle", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return pack.Source{}, diagnostic(pack.InvalidValue, path, "bundle is not a regular file", nil)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	source, err := pack.Read(ctx, file)
	if err != nil {
		return pack.Source{}, diagnosticFromPack(path, err)
	}
	return source, nil
}

func closureStores(environment Environment) ([]string, error) {
	var roots []string
	for _, candidate := range availableScopes(environment) {
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
