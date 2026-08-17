package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/pack"
	"github.com/nostalume/proofstrap/internal/profile"
	"github.com/pelletier/go-toml/v2"
)

const (
	maxBytes     = 1 << 20
	maxSources   = 64
	maxProfiles  = 4096
	maxArguments = 16
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
	location := "config"
	if d.Line > 0 {
		location += fmt.Sprintf(":%d:%d", d.Line, d.Column)
	}
	if d.Field != "" {
		location += " field=" + d.Field
	}
	return location + ": " + d.Category + ": " + d.Detail
}

type Source struct {
	Alias  string
	Digest pack.Digest
}

type Binding struct{ Source string }

type Profile struct {
	Source    string
	Name      string
	Arguments map[string]string
}

type targetState struct {
	sources  []Source
	bindings []Binding
	profiles []Profile
	direct   model.Graph
	packages []PackageRef
	services []Service
	via      []Via
}

type Target struct{ state *targetState }

func (t Target) Sources() []Source {
	if t.state == nil {
		return nil
	}
	return append([]Source(nil), t.state.sources...)
}

func (t Target) Bindings() []Binding {
	if t.state == nil {
		return nil
	}
	return append([]Binding(nil), t.state.bindings...)
}

func (t Target) Profiles() []Profile {
	if t.state == nil {
		return nil
	}
	result := append([]Profile(nil), t.state.profiles...)
	for index := range result {
		result[index].Arguments = maps.Clone(result[index].Arguments)
	}
	return result
}

func (t Target) Direct() model.Graph {
	if t.state == nil {
		return model.EmptyGraph()
	}
	return t.state.direct
}

func (t Target) Packages() []PackageRef {
	if t.state == nil {
		return nil
	}
	return append([]PackageRef(nil), t.state.packages...)
}

func (t Target) Services() []Service {
	if t.state == nil {
		return nil
	}
	return append([]Service(nil), t.state.services...)
}

func (t Target) Via() []Via {
	if t.state == nil {
		return nil
	}
	return append([]Via(nil), t.state.via...)
}

type rawTarget struct {
	Schema   *int                  `toml:"schema"`
	Sources  map[string]string     `toml:"sources"`
	Bindings []string              `toml:"bindings"`
	Profiles []rawProfile          `toml:"profiles"`
	Packages []string              `toml:"packages"`
	Services map[string]rawService `toml:"services"`
	Via      map[string][]string   `toml:"via"`
	Groups   map[string]rawGroup   `toml:"groups"`
	Accounts map[string]rawAccount `toml:"accounts"`
	Hostname *string               `toml:"hostname"`
	Timezone *string               `toml:"timezone"`
}

type rawProfile struct {
	Profile   string            `toml:"profile"`
	Arguments map[string]string `toml:"arguments"`
}

type rawService struct {
	Target   string   `toml:"target"`
	Packages []string `toml:"packages"`
	Enabled  *bool    `toml:"enabled"`
	Running  *bool    `toml:"running"`
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

func Decode(origin string, data []byte) (Target, error) {
	if strings.TrimSpace(origin) == "" || strings.ContainsAny(origin, "\r\n") {
		return Target{}, diagnostic("InvalidValue", "", "origin is required")
	}
	if len(data) == 0 {
		return Target{}, diagnostic("InvalidValue", "", "config must be non-empty")
	}
	if len(data) > maxBytes {
		return Target{}, diagnostic("Limit", "", "config exceeds 1 MiB")
	}
	if !utf8.Valid(data) {
		return Target{}, diagnostic("Syntax", "", "config is not valid UTF-8")
	}
	var envelope struct {
		Schema *int `toml:"schema"`
	}
	if err := toml.Unmarshal(data, &envelope); err != nil {
		return Target{}, syntaxDiagnostic(err)
	}
	if envelope.Schema == nil {
		return Target{}, diagnostic("InvalidValue", "schema", "schema is required")
	}
	if *envelope.Schema != 2 {
		return Target{}, diagnostic("UnsupportedSchema", "schema", "schema must be 2")
	}
	var raw rawTarget
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Target{}, syntaxDiagnostic(err)
	}
	sources, err := admitSources(raw.Sources)
	if err != nil {
		return Target{}, err
	}
	bindings, err := admitBindings(raw.Bindings, sources)
	if err != nil {
		return Target{}, err
	}
	direct, accounts, _, err := admitPortable(origin, raw)
	if err != nil {
		return Target{}, err
	}
	profiles, err := admitProfiles(raw.Profiles, sources)
	if err != nil {
		return Target{}, err
	}
	packages, services, via, err := admitNative(raw, accounts)
	if err != nil {
		return Target{}, err
	}
	if len(direct.Nodes())+len(packages)+len(services) > maxResources {
		return Target{}, diagnostic("Limit", "", "combined resource limit exceeded")
	}
	edges := 0
	for _, node := range direct.Nodes() {
		edges += len(node.Dependencies())
	}
	for _, service := range services {
		edges += len(service.packages)
	}
	for _, relation := range via {
		edges += len(relation.packages)
	}
	if edges > maxEdges {
		return Target{}, diagnostic("Limit", "", "combined dependency edge limit exceeded")
	}
	if len(profiles) == 0 && len(direct.Nodes()) == 0 && len(packages) == 0 && len(services) == 0 {
		return Target{}, diagnostic("InvalidValue", "", "config must request desired state")
	}
	return Target{state: &targetState{
		sources: sources, bindings: bindings, profiles: profiles,
		direct: direct, packages: packages, services: services, via: via,
	}}, nil
}

func syntaxDiagnostic(err error) *Diagnostic {
	result := diagnostic("Syntax", "", "invalid config TOML")
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
	aliases := sortedKeys(raw)
	result := make([]Source, 0, len(aliases))
	for _, alias := range aliases {
		if !profile.IsSymbol(alias) {
			return nil, diagnostic("InvalidValue", "sources."+alias, "invalid source alias")
		}
		digest, err := pack.ParseDigest(raw[alias])
		if err != nil {
			return nil, diagnostic("InvalidValue", "sources."+alias, err.Error())
		}
		result = append(result, Source{Alias: alias, Digest: digest})
	}
	return result, nil
}

func admitBindings(raw []string, sources []Source) ([]Binding, error) {
	used := make(map[string]struct{})
	if raw != nil && len(raw) == 0 {
		return nil, diagnostic("InvalidValue", "bindings", "explicit empty bindings list")
	}
	if len(raw) > maxSources {
		return nil, diagnostic("Limit", "bindings", "binding selection limit exceeded")
	}
	known := sourceSet(sources)
	for index, alias := range raw {
		if !profile.IsSymbol(alias) {
			return nil, diagnostic("InvalidValue", fmt.Sprintf("bindings[%d]", index), "invalid source alias")
		}
		if _, ok := known[alias]; !ok {
			return nil, diagnostic("MissingReference", fmt.Sprintf("bindings[%d]", index), "source alias is not declared")
		}
		used[alias] = struct{}{}
	}
	aliases := sortedKeys(used)
	result := make([]Binding, len(aliases))
	for index, alias := range aliases {
		result[index] = Binding{Source: alias}
	}
	return result, nil
}

func admitProfiles(raw []rawProfile, sources []Source) ([]Profile, error) {
	if raw != nil && len(raw) == 0 {
		return nil, diagnostic("InvalidValue", "profiles", "explicit empty profiles list")
	}
	if len(raw) > maxProfiles {
		return nil, diagnostic("Limit", "profiles", "root profile limit exceeded")
	}
	known := sourceSet(sources)
	values := make(map[string]Profile, len(raw))
	for index, item := range raw {
		field := fmt.Sprintf("profiles[%d]", index)
		alias, name, ok := splitProfileReference(item.Profile)
		if !ok {
			return nil, diagnostic("InvalidValue", field+".profile", "profile must be source-alias:ProfileID")
		}
		if _, exists := known[alias]; !exists {
			return nil, diagnostic("MissingReference", field+".profile", "source alias is not declared")
		}
		arguments, key, err := admitArguments(field+".arguments", item.Arguments)
		if err != nil {
			return nil, err
		}
		canonical := alias + ":" + name + "|" + key
		values[canonical] = Profile{Source: alias, Name: name, Arguments: arguments}
	}
	keys := sortedKeys(values)
	result := make([]Profile, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result, nil
}

func admitArguments(field string, raw map[string]string) (map[string]string, string, error) {
	if raw == nil {
		return nil, "", nil
	}
	if raw != nil && len(raw) == 0 {
		return nil, "", diagnostic("InvalidValue", field, "explicit empty arguments table")
	}
	if len(raw) > maxArguments {
		return nil, "", diagnostic("Limit", field, "root argument limit exceeded")
	}
	names := sortedKeys(raw)
	result := make(map[string]string, len(names))
	var key strings.Builder
	for _, name := range names {
		if !profile.IsSymbol(name) {
			return nil, "", diagnostic("InvalidValue", field+"."+name, "invalid argument name")
		}
		value := raw[name]
		if value == "" {
			return nil, "", diagnostic("InvalidValue", field+"."+name, "argument value must be non-empty")
		}
		result[name] = value
		key.WriteString(name + "=" + value + ";")
	}
	return result, key.String(), nil
}

func splitProfileReference(value string) (string, string, bool) {
	alias, name, ok := strings.Cut(value, ":")
	return alias, name, ok && !strings.Contains(name, ":") && profile.IsSymbol(alias) && profile.IsSymbol(name)
}

func sourceSet(sources []Source) map[string]struct{} {
	result := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		result[source.Alias] = struct{}{}
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

func diagnostic(category, field, detail string) *Diagnostic {
	return &Diagnostic{Category: category, Field: field, Detail: detail}
}
