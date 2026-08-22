package document

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
	"github.com/pelletier/go-toml/v2"
)

const (
	maxBytes     = 1 << 20
	maxSources   = 64
	maxResources = 32768
	maxEdges     = 131072
)

type Diagnostic struct {
	Category string
	Field    string
	Line     int
	Column   int
	Detail   string
}

func (d *Diagnostic) Error() string {
	location := "document"
	if d.Line > 0 {
		location += fmt.Sprintf(":%d:%d", d.Line, d.Column)
	}
	if d.Field != "" {
		location += " field=" + d.Field
	}
	return location + ": " + d.Category + ": " + d.Detail
}

type Source struct {
	Name   string
	Digest pack.Digest
}

type state struct {
	origin   string
	sources  []Source
	bindings []string
	include  []profile.Call
	profiles profile.Module
	mappings binding.Module
	direct   model.Graph
}

type Document struct{ state *state }

type View struct {
	Origin   string
	Sources  []Source
	Bindings []string
	Include  []profile.Call
	Profiles profile.Module
	Mappings binding.Module
	Direct   model.Graph
}

func (d Document) View() View {
	if d.state == nil {
		return View{Direct: model.EmptyGraph()}
	}
	return View{
		Origin: d.state.origin, Sources: append([]Source(nil), d.state.sources...), Bindings: append([]string(nil), d.state.bindings...),
		Include: append([]profile.Call(nil), d.state.include...), Profiles: d.state.profiles,
		Mappings: d.state.mappings, Direct: d.state.direct,
	}
}

type ProfileFields profile.Syntax
type BindingFields binding.Syntax

type rawDocument struct {
	Schema           *int                 `toml:"schema"`
	Sources          map[string]string    `toml:"sources"`
	SelectedBindings []string             `toml:"bindings"`
	Include          []profile.CallSyntax `toml:"include"`
	ProfileFields
	BindingFields
	Groups   map[string]rawGroup   `toml:"groups"`
	Accounts map[string]rawAccount `toml:"accounts"`
	Hostname *string               `toml:"hostname"`
	Timezone *string               `toml:"timezone"`
}

type rawGroup struct {
	GID *uint32 `toml:"gid"`
}

type rawAccount struct {
	UID           *uint32         `toml:"uid"`
	Group         *string         `toml:"group"`
	Home          *string         `toml:"home"`
	HomeMode      *string         `toml:"home_mode"`
	Shell         *string         `toml:"shell"`
	Locked        *bool           `toml:"locked"`
	Supplementary map[string]bool `toml:"supplementary"`
}

func Decode(origin string, data []byte) (Document, error) {
	if strings.TrimSpace(origin) == "" || strings.ContainsAny(origin, "\r\n") {
		return Document{}, diagnostic("InvalidValue", "", "origin is required")
	}
	if len(data) == 0 {
		return Document{}, diagnostic("InvalidValue", "", "document must be non-empty")
	}
	if len(data) > maxBytes {
		return Document{}, diagnostic("Limit", "", "document exceeds 1 MiB")
	}
	if !utf8.Valid(data) {
		return Document{}, diagnostic("Syntax", "", "document is not valid UTF-8")
	}
	var raw rawDocument
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Document{}, syntaxDiagnostic(err)
	}
	if raw.Schema == nil {
		return Document{}, diagnostic("InvalidValue", "schema", "schema is required")
	}
	if *raw.Schema != 3 {
		return Document{}, diagnostic("UnsupportedSchema", "schema", "schema must be 3")
	}
	sources, err := admitSources(raw.Sources)
	if err != nil {
		return Document{}, err
	}
	bindings, err := admitSelections(raw.SelectedBindings, sources)
	if err != nil {
		return Document{}, err
	}
	include, err := profile.AdmitCalls(raw.Include)
	if err != nil {
		return Document{}, diagnostic("InvalidValue", "include", err.Error())
	}
	var profiles profile.Module
	profileSyntax := profile.Syntax(raw.ProfileFields)
	if profileSyntax.Profiles != nil {
		input, err := profile.Embed(origin, profileSyntax)
		if err != nil {
			return Document{}, convertProfile(err)
		}
		profiles, err = profile.Admit([]profile.Input{input})
		if err != nil {
			return Document{}, convertProfile(err)
		}
	}
	var mappings binding.Module
	bindingSyntax := binding.Syntax(raw.BindingFields)
	if bindingSyntax.Package != nil || bindingSyntax.Service != nil || bindingSyntax.Bind != nil {
		input, err := binding.Embed(origin, bindingSyntax)
		if err != nil {
			return Document{}, convertBinding(err)
		}
		mappings, err = binding.Admit(context.Background(), origin, []binding.Input{input})
		if err != nil {
			return Document{}, convertBinding(err)
		}
	}
	direct, err := admitIdentity(origin, raw)
	if err != nil {
		return Document{}, err
	}
	known := sourceSet(sources)
	for _, handle := range append(append(append(profile.Requirements(profiles), profile.CallRequirements(include)...), binding.Requirements(mappings)...), bindings...) {
		if _, exists := known[handle]; !exists {
			return Document{}, diagnostic("MissingReference", "sources."+handle, "source alias is not declared")
		}
	}
	resources, edges := profile.Stats(profiles)
	resources += len(direct.Nodes())
	for _, node := range direct.Nodes() {
		edges += len(node.Dependencies())
	}
	if resources > maxResources || edges > maxEdges {
		return Document{}, diagnostic("Limit", "", "combined semantic limit exceeded")
	}
	if len(include) == 0 && len(direct.Nodes()) == 0 {
		return Document{}, diagnostic("InvalidValue", "", "document must request desired state")
	}
	return Document{state: &state{origin, sources, bindings, include, profiles, mappings, direct}}, nil
}

func syntaxDiagnostic(err error) *Diagnostic {
	result := diagnostic("Syntax", "", "invalid document TOML")
	var decodeError *toml.DecodeError
	if errors.As(err, &decodeError) {
		result.Line, result.Column = decodeError.Position()
	}
	return result
}

func admitSources(raw map[string]string) ([]Source, error) {
	if raw != nil && len(raw) == 0 {
		return nil, diagnostic("InvalidValue", "sources", "explicit empty sources table")
	}
	if len(raw) > maxSources {
		return nil, diagnostic("Limit", "sources", "source alias limit exceeded")
	}
	result := make([]Source, 0, len(raw))
	for _, name := range sortedKeys(raw) {
		if !profile.IsSymbol(name) {
			return nil, diagnostic("InvalidValue", "sources."+name, "invalid source alias")
		}
		digest, err := pack.ParseDigest(raw[name])
		if err != nil {
			return nil, diagnostic("InvalidValue", "sources."+name, err.Error())
		}
		result = append(result, Source{Name: name, Digest: digest})
	}
	return result, nil
}

func admitSelections(raw []string, sources []Source) ([]string, error) {
	if raw != nil && len(raw) == 0 {
		return nil, diagnostic("InvalidValue", "bindings", "explicit empty bindings list")
	}
	known, seen := sourceSet(sources), make(map[string]struct{})
	for index, name := range raw {
		if !profile.IsSymbol(name) {
			return nil, diagnostic("InvalidValue", fmt.Sprintf("bindings[%d]", index), "invalid source alias")
		}
		if _, exists := known[name]; !exists {
			return nil, diagnostic("MissingReference", fmt.Sprintf("bindings[%d]", index), "source alias is not declared")
		}
		seen[name] = struct{}{}
	}
	return sortedKeys(seen), nil
}

func sourceSet(sources []Source) map[string]struct{} {
	result := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		result[source.Name] = struct{}{}
	}
	return result
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func convertProfile(err error) error {
	var source *profile.Diagnostic
	if errors.As(err, &source) {
		return &Diagnostic{source.Category, source.Field, source.Line, source.Column, source.Detail}
	}
	return err
}

func convertBinding(err error) error {
	var source *binding.Diagnostic
	if errors.As(err, &source) {
		return &Diagnostic{source.Category, source.Field, source.Line, source.Column, source.Detail}
	}
	return err
}

func diagnostic(category, field, detail string) *Diagnostic {
	return &Diagnostic{Category: category, Field: field, Detail: detail}
}
