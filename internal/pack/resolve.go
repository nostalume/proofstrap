package pack

import (
	"context"
	"errors"
	"sort"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/profile"
)

const (
	maxClosureSources = 64
	maxClosureBytes   = 128 << 20
)

type packState struct {
	digest  Digest
	library profile.Library
}

type Pack struct{ state *packState }

func (p Pack) Digest() Digest {
	if p.state == nil {
		return Digest{}
	}
	return p.state.digest
}

func (p Pack) Library() profile.Library {
	if p.state == nil {
		return profile.Library{}
	}
	return p.state.library
}

func Resolve(ctx context.Context, root Source, available []Source) (Pack, error) {
	if ctx == nil {
		return Pack{}, cancellationDiagnostic(context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return Pack{}, cancellationDiagnostic(err)
	}
	if root.state == nil || root.state.kind != Semantic {
		return Pack{}, diagnostic(KindMismatch, "", "", "root must be an admitted semantic source", nil)
	}
	ordered, err := semanticClosure(ctx, root, available)
	if err != nil {
		return Pack{}, err
	}
	libraries := make(map[Digest]profile.Library, len(ordered))
	for _, source := range ordered {
		if err := ctx.Err(); err != nil {
			return Pack{}, cancellationDiagnostic(err)
		}
		required := make(map[string]profile.Library, len(source.state.requirements))
		for handle, digest := range source.state.requirements {
			required[handle] = libraries[digest]
		}
		members := make([]profile.Member, len(source.state.members))
		for index, member := range source.state.members {
			members[index] = profile.Member{Path: member.path, Data: append([]byte(nil), member.data...)}
		}
		library, err := admitProfileMembers(source.Digest().String(), members, required)
		if err != nil {
			return Pack{}, convertProfileDiagnostic(source, err)
		}
		if err := ctx.Err(); err != nil {
			return Pack{}, cancellationDiagnostic(err)
		}
		libraries[source.Digest()] = library
	}
	return Pack{state: &packState{digest: root.Digest(), library: libraries[root.Digest()]}}, nil
}

func ResolveCatalogue(ctx context.Context, root Source, available []Source) (binding.Catalogue, error) {
	if ctx == nil {
		return binding.Catalogue{}, cancellationDiagnostic(context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return binding.Catalogue{}, cancellationDiagnostic(err)
	}
	if root.state == nil || root.state.kind != Binding {
		return binding.Catalogue{}, diagnostic(KindMismatch, "", "", "root must be an admitted binding source", nil)
	}
	semanticRoot := Source{state: &sourceState{
		digest: root.state.digest, kind: Semantic, compressed: root.state.compressed,
		requirements: root.state.requirements, members: nil,
	}}
	inventory := append([]Source(nil), available...)
	ordered, err := semanticClosure(ctx, semanticRoot, inventory)
	if err != nil {
		return binding.Catalogue{}, err
	}
	libraries := make(map[Digest]profile.Library, len(ordered))
	for _, source := range ordered {
		if source.Digest() == root.Digest() {
			continue
		}
		required := make(map[string]profile.Library, len(source.state.requirements))
		for handle, digest := range source.state.requirements {
			required[handle] = libraries[digest]
		}
		library, err := admitProfileMembers(source.Digest().String(), profileMembers(source), required)
		if err != nil {
			return binding.Catalogue{}, convertProfileDiagnostic(source, err)
		}
		libraries[source.Digest()] = library
	}
	required := make(map[string]profile.Library, len(root.state.requirements))
	for handle, digest := range root.state.requirements {
		required[handle] = libraries[digest]
	}
	members := make([]binding.Member, len(root.state.members))
	for index, member := range root.state.members {
		members[index] = binding.Member{Path: member.path, Data: append([]byte(nil), member.data...)}
	}
	catalogue, err := admitBindingMembers(ctx, root.Digest().String(), members, required)
	if err != nil {
		return binding.Catalogue{}, convertBindingDiagnostic(root, err)
	}
	return catalogue, nil
}

func admitProfileMembers(origin string, members []profile.Member, required map[string]profile.Library) (profile.Library, error) {
	inputs := make([]profile.Input, len(members))
	for index, member := range members {
		input, err := profile.Parse(member)
		if err != nil {
			return profile.Library{}, err
		}
		inputs[index] = input
	}
	module, err := profile.Admit(inputs)
	if err != nil {
		return profile.Library{}, err
	}
	return profile.Link(origin, module, required)
}

func admitBindingMembers(ctx context.Context, origin string, members []binding.Member, required map[string]profile.Library) (binding.Catalogue, error) {
	inputs := make([]binding.Input, len(members))
	for index, member := range members {
		input, err := binding.Parse(member)
		if err != nil {
			return binding.Catalogue{}, err
		}
		inputs[index] = input
	}
	module, err := binding.Admit(ctx, origin, inputs)
	if err != nil {
		return binding.Catalogue{}, err
	}
	return binding.Link(ctx, module, required)
}

func semanticClosure(ctx context.Context, root Source, available []Source) ([]Source, error) {
	inventory := make(map[Digest]Source, len(available)+1)
	for _, source := range available {
		if source.state != nil {
			inventory[source.Digest()] = source
		}
	}
	inventory[root.Digest()] = root
	state := make(map[Digest]uint8)
	ordered := make([]Source, 0)
	var bytes int64
	var visit func(Source) error
	visit = func(source Source) error {
		if err := ctx.Err(); err != nil {
			return cancellationDiagnostic(err)
		}
		if state[source.Digest()] == 1 {
			return locatedDiagnostic(source, Cycle, "manifest.toml", "requires", "requirement cycle", nil)
		}
		if state[source.Digest()] == 2 {
			return nil
		}
		if len(state) >= maxClosureSources {
			return locatedDiagnostic(source, Limit, "manifest.toml", "requires", "closure source limit exceeded", nil)
		}
		bytes += source.state.compressed
		if bytes > maxClosureBytes {
			return locatedDiagnostic(source, Limit, "manifest.toml", "requires", "closure compressed-byte limit exceeded", nil)
		}
		state[source.Digest()] = 1
		for _, handle := range sortedRequirementHandles(source.state.requirements) {
			digest := source.state.requirements[handle]
			required, exists := inventory[digest]
			if !exists {
				return locatedDiagnostic(source, MissingRequirement, "manifest.toml", "requires."+handle, "required source is unavailable", nil)
			}
			if required.Kind() != Semantic {
				return locatedDiagnostic(source, KindMismatch, "manifest.toml", "requires."+handle, "required source is not semantic", nil)
			}
			if state[digest] == 1 {
				return locatedDiagnostic(source, Cycle, "manifest.toml", "requires."+handle, "requirement cycle", nil)
			}
			if err := visit(required); err != nil {
				return err
			}
		}
		state[source.Digest()] = 2
		ordered = append(ordered, source)
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return ordered, nil
}

func profileMembers(source Source) []profile.Member {
	members := make([]profile.Member, len(source.state.members))
	for index, member := range source.state.members {
		members[index] = profile.Member{Path: member.path, Data: append([]byte(nil), member.data...)}
	}
	return members
}

func sortedRequirementHandles(requirements map[string]Digest) []string {
	result := make([]string, 0, len(requirements))
	for handle := range requirements {
		result = append(result, handle)
	}
	sort.Strings(result)
	return result
}

func locatedDiagnostic(source Source, category Category, member, field, detail string, cause error) *Diagnostic {
	result := diagnostic(category, member, field, detail, cause)
	result.Source = source.Digest().String()
	return result
}

func convertProfileDiagnostic(source Source, err error) error {
	var sourceDiagnostic *profile.Diagnostic
	if !errors.As(err, &sourceDiagnostic) {
		return locatedDiagnostic(source, InvalidValue, "", "", err.Error(), err)
	}
	return &Diagnostic{
		Source: source.Digest().String(), Category: Category(sourceDiagnostic.Category),
		Member: sourceDiagnostic.Member, Profile: sourceDiagnostic.Profile,
		Field: sourceDiagnostic.Field, Line: sourceDiagnostic.Line,
		Column: sourceDiagnostic.Column, Detail: sourceDiagnostic.Detail, cause: err,
	}
}

func convertBindingDiagnostic(source Source, err error) error {
	var canceled *binding.Canceled
	if errors.As(err, &canceled) {
		return err
	}
	var sourceDiagnostic *binding.Diagnostic
	if !errors.As(err, &sourceDiagnostic) {
		return locatedDiagnostic(source, InvalidValue, "", "", err.Error(), err)
	}
	return &Diagnostic{
		Source: source.Digest().String(), Category: Category(sourceDiagnostic.Category),
		Member: sourceDiagnostic.Member, Field: sourceDiagnostic.Field,
		Line: sourceDiagnostic.Line, Column: sourceDiagnostic.Column,
		Detail: sourceDiagnostic.Detail, cause: err,
	}
}
