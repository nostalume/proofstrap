package inventory

import "github.com/nostalume/proofstrap/internal/pack"

type Diagnostic struct {
	Category pack.Category
	Path     string
	Detail   string
	cause    error
}

func (d *Diagnostic) Error() string {
	location := d.Path
	if location != "" {
		location += ": "
	}
	return location + string(d.Category) + ": " + d.Detail
}

func (d *Diagnostic) Unwrap() error { return d.cause }

func diagnostic(category pack.Category, path, detail string, cause error) *Diagnostic {
	if detail == "" && cause != nil {
		detail = cause.Error()
	}
	return &Diagnostic{Category: category, Path: path, Detail: detail, cause: cause}
}
