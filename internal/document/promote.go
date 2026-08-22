package document

import (
	"fmt"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
	"github.com/pelletier/go-toml/v2"
)

type Promotion struct {
	Semantic, Binding                 []byte
	SemanticRequires, BindingRequires []string
	BindingUsesLocal                  bool
	calls                             []profile.CallSyntax
}

func Promote(target Document, semanticAlias string, calls []profile.CallSyntax) (Promotion, error) {
	if target.state == nil {
		return Promotion{}, fmt.Errorf("document is required")
	}
	var result Promotion
	result.calls = append([]profile.CallSyntax(nil), calls...)
	var err error
	if target.state.profiles.Present() {
		result.Semantic, err = profile.Encode(target.state.profileInput)
		if err != nil {
			return Promotion{}, err
		}
		result.SemanticRequires = profile.Requirements(target.state.profiles)
	}
	if target.state.mappings.Present() {
		result.Binding, err = binding.EncodePromoted(target.state.bindingInput, semanticAlias)
		if err != nil {
			return Promotion{}, err
		}
		result.BindingRequires = binding.Requirements(target.state.mappings)
		result.BindingUsesLocal = binding.UsesLocal(target.state.mappings)
	}
	return result, nil
}

func RenderTarget(target Document, promotion Promotion, semanticAlias string, semanticDigest *pack.Digest, bindingAlias string, bindingDigest *pack.Digest) ([]byte, error) {
	if target.state == nil {
		return nil, fmt.Errorf("document is required")
	}
	raw := target.state.raw
	raw.ProfileFields = ProfileFields{}
	raw.BindingFields = BindingFields{}
	raw.Include = append([]profile.CallSyntax(nil), promotion.calls...)
	needed := make(map[string]struct{})
	promotedCalls, err := profile.AdmitCalls(promotion.calls)
	if err != nil {
		return nil, err
	}
	for _, handle := range append(profile.CallRequirements(promotedCalls), target.state.bindings...) {
		needed[handle] = struct{}{}
	}
	_, rootedLocal := needed[semanticAlias]
	rootedLocal = rootedLocal && semanticDigest != nil
	if rootedLocal {
		needed[semanticAlias] = struct{}{}
	}
	if bindingDigest != nil {
		needed[bindingAlias] = struct{}{}
	}
	raw.Sources = make(map[string]string, len(needed))
	for _, source := range target.state.sources {
		if _, ok := needed[source.Name]; ok {
			raw.Sources[source.Name] = source.Digest.String()
		}
	}
	if rootedLocal {
		raw.Sources[semanticAlias] = semanticDigest.String()
	}
	raw.SelectedBindings = append([]string(nil), target.state.bindings...)
	if bindingDigest != nil {
		raw.Sources[bindingAlias] = bindingDigest.String()
		raw.SelectedBindings = append(raw.SelectedBindings, bindingAlias)
	}
	if len(raw.Sources) == 0 {
		raw.Sources = nil
	}
	return toml.Marshal(raw)
}
