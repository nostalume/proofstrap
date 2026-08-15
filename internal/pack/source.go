package pack

import (
	"fmt"
	"sort"
)

type Kind uint8

const (
	Semantic Kind = iota + 1
	Binding
)

func (k Kind) String() string {
	switch k {
	case Semantic:
		return "semantic"
	case Binding:
		return "binding"
	default:
		return "invalid"
	}
}

type Category string

const (
	Syntax             Category = "Syntax"
	Limit              Category = "Limit"
	Integrity          Category = "Integrity"
	UnsupportedSchema  Category = "UnsupportedSchema"
	InvalidManifest    Category = "InvalidManifest"
	InvalidPath        Category = "InvalidPath"
	Duplicate          Category = "Duplicate"
	KindMismatch       Category = "KindMismatch"
	MissingRequirement Category = "MissingRequirement"
	MissingReference   Category = "MissingReference"
	WrongDomain        Category = "WrongDomain"
	Cycle              Category = "Cycle"
	UnusedRequirement  Category = "UnusedRequirement"
	InvalidValue       Category = "InvalidValue"
	TypeMismatch       Category = "TypeMismatch"
	Conflict           Category = "Conflict"
	CorruptStore       Category = "CorruptStore"
	IO                 Category = "IO"
	Canceled           Category = "Canceled"
)

type Diagnostic struct {
	Source   string
	Category Category
	Member   string
	Profile  string
	Field    string
	Line     int
	Column   int
	Detail   string
	cause    error
}

func (d *Diagnostic) Error() string {
	location := d.Source
	if d.Member != "" {
		if location != "" {
			location += " "
		}
		location += d.Member
	}
	if d.Line > 0 {
		location += fmt.Sprintf(":%d:%d", d.Line, d.Column)
	}
	if d.Profile != "" {
		if location != "" {
			location += " "
		}
		location += "profile=" + d.Profile
	}
	if d.Field != "" {
		if location != "" {
			location += " "
		}
		location += "field=" + d.Field
	}
	if location != "" {
		location += ": "
	}
	return location + string(d.Category) + ": " + d.Detail
}

func (d *Diagnostic) Unwrap() error { return d.cause }

type contentMember struct {
	path string
	data []byte
}

type sourceState struct {
	digest       Digest
	kind         Kind
	compressed   int64
	requirements map[string]Digest
	members      []contentMember
}

type Source struct {
	state *sourceState
}

type Requirement struct {
	Handle string
	Digest Digest
}

type Description struct {
	Digest       Digest
	Kind         Kind
	Requirements []Requirement
	Members      []string
}

func (s Source) Digest() Digest {
	if s.state == nil {
		return Digest{}
	}
	return s.state.digest
}

func (s Source) Kind() Kind {
	if s.state == nil {
		return 0
	}
	return s.state.kind
}

func (s Source) Description() Description {
	if s.state == nil {
		return Description{}
	}
	requirements := make([]Requirement, 0, len(s.state.requirements))
	for handle, digest := range s.state.requirements {
		requirements = append(requirements, Requirement{Handle: handle, Digest: digest})
	}
	sort.Slice(requirements, func(i, j int) bool { return requirements[i].Handle < requirements[j].Handle })
	members := make([]string, len(s.state.members))
	for index, member := range s.state.members {
		members[index] = member.path
	}
	return Description{Digest: s.state.digest, Kind: s.state.kind, Requirements: requirements, Members: members}
}

func diagnostic(category Category, member, field, detail string, cause error) *Diagnostic {
	if detail == "" && cause != nil {
		detail = cause.Error()
	}
	return &Diagnostic{Category: category, Member: member, Field: field, Detail: detail, cause: cause}
}

func parseKind(value string) (Kind, error) {
	switch value {
	case "semantic":
		return Semantic, nil
	case "binding":
		return Binding, nil
	default:
		return 0, fmt.Errorf("kind must be semantic or binding")
	}
}
