package binding

import (
	"context"
	"fmt"
	"sort"
)

type Domain uint8

const (
	Package Domain = iota + 1
	Service
)

func (d Domain) String() string {
	if d == Package {
		return "package"
	}
	if d == Service {
		return "service"
	}
	return "invalid"
}

type Member struct {
	Path string
	Data []byte
}

type Diagnostic struct {
	Category string
	Member   string
	Field    string
	Line     int
	Column   int
	Detail   string
	cause    error
}

func (d *Diagnostic) Error() string {
	location := d.Member
	if d.Line > 0 {
		location += fmt.Sprintf(":%d:%d", d.Line, d.Column)
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
	return location + d.Category + ": " + d.Detail
}

func (d *Diagnostic) Unwrap() error { return d.cause }

type Canceled struct{ cause error }

func (e *Canceled) Error() string { return "binding operation canceled: " + e.cause.Error() }
func (e *Canceled) Unwrap() error { return e.cause }

type mappingKey struct {
	domain   Domain
	backend  string
	semantic string
}

type mapping struct {
	outputs []string
	sources []string
}

type catalogueState struct{ mappings map[mappingKey]mapping }
type Catalogue struct{ state *catalogueState }

func sortedStrings(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canceled(ctx context.Context) error {
	if ctx == nil {
		return &Canceled{cause: context.Canceled}
	}
	if err := ctx.Err(); err != nil {
		return &Canceled{cause: err}
	}
	return nil
}

var _ error = (*Diagnostic)(nil)
var _ error = (*Canceled)(nil)
