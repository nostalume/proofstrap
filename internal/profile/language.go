package profile

import (
	"fmt"
	"sort"

	"github.com/nostalume/proofstrap/internal/model"
)

const MaxMemberBytes = 1 << 20

type Member struct {
	Path string
	Data []byte
}

type Diagnostic struct {
	Category string
	Member   string
	Profile  string
	Field    string
	Line     int
	Column   int
	Detail   string
}

func (d *Diagnostic) Error() string {
	location := d.Member
	if d.Line > 0 {
		location += fmt.Sprintf(":%d:%d", d.Line, d.Column)
	}
	if d.Profile != "" {
		location += " profile=" + d.Profile
	}
	if d.Field != "" {
		location += " field=" + d.Field
	}
	return location + ": " + d.Category + ": " + d.Detail
}

type parameterKind uint8

const (
	accountReference parameterKind = iota + 1
	groupReference
	profileReference
	parameterUsed parameterKind = 1 << 7
)

type reference struct {
	literal   model.Key
	profile   string
	parameter string
	kind      parameterKind
}

func (r reference) canonical() string {
	if r.parameter != "" {
		return fmt.Sprintf("parameter:%d:%s", r.kind, r.parameter)
	}
	if r.profile != "" {
		return r.profile
	}
	return r.literal.Canonical()
}

type semanticReference struct {
	alias string
	name  string
}

func (r semanticReference) canonical() string {
	if r.alias == "" {
		return r.name
	}
	return r.alias + ":" + r.name
}

type includeDefinition struct {
	profile          string
	profileParameter string
	sourceArguments  map[string]any
	arguments        map[string]reference
}

type serviceDefinition struct {
	id       semanticReference
	user     *reference
	enable   model.EnableIntent
	run      model.RunIntent
	packages []semanticReference
}

type membershipDefinition struct {
	account reference
	group   reference
	present bool
}

type homeModeDefinition struct {
	account reference
	mode    uint16
}

type profileDefinition struct {
	id           string
	member       string
	parameters   map[string]parameterKind
	includes     []includeDefinition
	packages     []semanticReference
	services     []serviceDefinition
	homes        []reference
	homeModes    []homeModeDefinition
	accountLocks []reference
	memberships  []membershipDefinition
	hostname     model.Resource
	timezone     model.Resource
}

type Library struct {
	profiles       map[string]profileDefinition
	localProfiles  map[string]string
	packageSymbols map[string]struct{}
	serviceSymbols map[string]struct{}
}

func (l Library) ProfileIDs() []string {
	ids := make([]string, 0, len(l.localProfiles))
	for id := range l.localProfiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (l Library) DeclaresPackage(id model.PackageID) bool {
	return declares(id, l.packageSymbols)
}

func (l Library) DeclaresService(id model.ServiceID) bool {
	return declares(id, l.serviceSymbols)
}

func declares(id interface{ String() string }, symbols map[string]struct{}) bool {
	if id == nil {
		return false
	}
	_, exists := symbols[id.String()]
	return exists
}
