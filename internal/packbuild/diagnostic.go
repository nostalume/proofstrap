package packbuild

type Category string

const (
	InvalidInput Category = "InvalidInput"
	InputChanged Category = "InputChanged"
	OutputExists Category = "OutputExists"
	IO           Category = "IO"
	Canceled     Category = "Canceled"
)

type Diagnostic struct {
	Category Category
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

func diagnostic(category Category, path, detail string, cause error) *Diagnostic {
	if detail == "" && cause != nil {
		detail = cause.Error()
	}
	return &Diagnostic{Category: category, Path: path, Detail: detail, cause: cause}
}
