package inventory

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

const (
	releaseRoot       = "/usr/share/proofstrap/packs"
	systemRoot        = "/var/lib/proofstrap/packs"
	maxScopeEntries   = 4096
	maxRecords        = 4096
	maxProjectedItems = 65536
)

type Environment struct {
	ReleaseRoot string
	PackStore   string
	XDGDataHome string
	Home        string
}

type Record struct {
	Description pack.Description
	Scopes      []string
}

type scope struct {
	name string
	root string
}

type Diagnostic struct {
	Category pack.Category
	Path     string
	Detail   string
	cause    error
}

func (d *Diagnostic) Error() string {
	if d.Path != "" {
		return d.Path + ": " + string(d.Category) + ": " + d.Detail
	}
	return string(d.Category) + ": " + d.Detail
}

func (d *Diagnostic) Unwrap() error { return d.cause }

func diagnostic(category pack.Category, path, detail string, cause error) *Diagnostic {
	if detail == "" && cause != nil {
		detail = cause.Error()
	}
	return &Diagnostic{Category: category, Path: path, Detail: detail, cause: cause}
}

func ImportUser(ctx context.Context, environment Environment, archive string, expected *pack.Digest) (Record, error) {
	if err := validateArchive(ctx, archive, expected); err != nil {
		return Record{}, err
	}
	base, suffix, ok := userBase(environment)
	if !ok {
		return Record{}, diagnostic(pack.InvalidValue, "", "user scope is unavailable", nil)
	}
	var err error
	if suffix == nil {
		err = createBeneath(filepath.Dir(base), []string{filepath.Base(base), "proofstrap", "packs", "sha256"}, 0o700)
	} else {
		err = createBeneath(base, append(suffix, "proofstrap", "packs", "sha256"), 0o700)
	}
	if err != nil {
		return Record{}, diagnostic(pack.IO, base, "initialize user store", err)
	}
	return importArchive(ctx, userRoot(environment), archive, expected, "user")
}

func ImportSystem(ctx context.Context, archive string, expected *pack.Digest) (Record, error) {
	if err := validateArchive(ctx, archive, expected); err != nil {
		return Record{}, err
	}
	if err := createBeneath("/var/lib", []string{"proofstrap", "packs", "sha256"}, 0o755); err != nil {
		return Record{}, diagnostic(pack.IO, systemRoot, "initialize system store", err)
	}
	return importArchive(ctx, systemRoot, archive, expected, "system")
}

func importArchive(ctx context.Context, root, archive string, expected *pack.Digest, scope string) (Record, error) {
	source, err := pack.Import(ctx, root, archive, expected)
	if err != nil {
		return Record{}, err
	}
	return Record{Description: source.Description(), Scopes: []string{scope}}, nil
}

func InspectArchive(ctx context.Context, archive string, expected *pack.Digest) (Record, error) {
	if err := validateArchive(ctx, archive, expected); err != nil {
		return Record{}, err
	}
	source, err := readSource(ctx, archive, "archive")
	if err != nil {
		return Record{}, err
	}
	if expected != nil && source.Digest() != *expected {
		return Record{}, diagnostic(pack.Integrity, archive, "archive digest does not match expected digest", nil)
	}
	return Record{Description: source.Description(), Scopes: []string{}}, nil
}

func readSource(ctx context.Context, path, noun string) (pack.Source, error) {
	if !linux.CleanAbsoluteNonRoot(path) {
		return pack.Source{}, diagnostic(pack.InvalidValue, path, noun+" path must be clean absolute and non-root", nil)
	}
	fd, err := linux.OpenRegular(path)
	if err != nil {
		if errors.Is(err, linux.ErrNotRegular) {
			return pack.Source{}, diagnostic(pack.InvalidValue, path, noun+" is not a regular file", nil)
		}
		return pack.Source{}, diagnostic(pack.IO, path, "open "+noun, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	source, err := pack.Read(ctx, file)
	if err != nil {
		return pack.Source{}, diagnostic(packCategory(err), path, "pack admission failed", err)
	}
	return source, nil
}

func InspectStored(ctx context.Context, environment Environment, digest *pack.Digest) ([]Record, error) {
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	scopes, err := availableScopes(environment)
	if err != nil {
		return nil, err
	}
	if digest != nil {
		if *digest == (pack.Digest{}) {
			return nil, diagnostic(pack.InvalidValue, "", "digest is required", nil)
		}
		return inspectExact(ctx, scopes, *digest)
	}
	return inspectAll(ctx, scopes)
}

func inspectExact(ctx context.Context, scopes []scope, digest pack.Digest) ([]Record, error) {
	var result *Record
	for _, item := range scopes {
		fd, exists, err := openScope(item.root)
		if err != nil {
			return nil, diagnostic(pack.CorruptStore, item.root, "scope is unsafe or incomplete", err)
		}
		if !exists {
			continue
		}
		_ = unix.Close(fd)
		source, err := pack.LoadExact(ctx, []string{item.root}, digest)
		if err != nil {
			var packError *pack.Diagnostic
			if errors.As(err, &packError) && packError.Category == pack.MissingRequirement {
				continue
			}
			return nil, err
		}
		description := source.Description()
		if result == nil {
			result = &Record{Description: description, Scopes: []string{item.name}}
		} else if !reflect.DeepEqual(result.Description, description) {
			return nil, diagnostic(pack.CorruptStore, item.root, "duplicate source descriptions disagree", nil)
		} else {
			result.Scopes = append(result.Scopes, item.name)
		}
	}
	if result == nil {
		return nil, diagnostic(pack.MissingRequirement, digest.String(), "exact source is unavailable", nil)
	}
	records := []Record{*result}
	if err := checkRecordBudget(records); err != nil {
		return nil, err
	}
	return records, nil
}

func inspectAll(ctx context.Context, scopes []scope) ([]Record, error) {
	byDigest := make(map[pack.Digest]*Record)
	projected := 0
	for _, item := range scopes {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		fd, exists, err := openScope(item.root)
		if err != nil {
			return nil, diagnostic(pack.CorruptStore, item.root, "scope is unsafe or incomplete", err)
		}
		if !exists {
			continue
		}
		if err := inspectScope(ctx, fd, item, byDigest, &projected); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		_ = unix.Close(fd)
	}
	records := make([]Record, 0, len(byDigest))
	for _, record := range byDigest {
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Description.Digest.String() < records[j].Description.Digest.String()
	})
	if err := checkRecordBudget(records); err != nil {
		return nil, err
	}
	return records, nil
}

func inspectScope(ctx context.Context, fd int, item scope, byDigest map[pack.Digest]*Record, projected *int) error {
	duplicate, err := linux.OpenDirAt(fd, ".")
	if err != nil {
		return diagnostic(pack.IO, item.root, "open scope enumeration", err)
	}
	directory := os.NewFile(uintptr(duplicate), item.root)
	defer directory.Close()
	observed := 0
	for {
		if err := canceled(ctx); err != nil {
			return err
		}
		entries, err := directory.ReadDir(64)
		if err != nil && err != io.EOF {
			return diagnostic(pack.IO, item.root, "enumerate scope", err)
		}
		for _, entry := range entries {
			observed++
			if observed > maxScopeEntries {
				return diagnostic(pack.Limit, item.root, "scope entry limit exceeded", nil)
			}
			name := entry.Name()
			if inertStage(name) {
				continue
			}
			digest, valid := objectDigest(name)
			if !valid {
				return diagnostic(pack.CorruptStore, filepath.Join(item.root, "sha256", name), "unexpected store entry", nil)
			}
			objectFD, err := linux.OpenRegularAt(fd, name)
			if err != nil {
				return diagnostic(pack.CorruptStore, filepath.Join(item.root, "sha256", name), "stored object is unsafe or non-regular", err)
			}
			file := os.NewFile(uintptr(objectFD), name)
			source, readErr := pack.Read(ctx, file)
			_ = file.Close()
			if readErr != nil {
				return diagnostic(pack.CorruptStore, filepath.Join(item.root, "sha256", name), "stored object is invalid", readErr)
			}
			if source.Digest() != digest {
				return diagnostic(pack.CorruptStore, filepath.Join(item.root, "sha256", name), "stored object digest does not match its name", nil)
			}
			description := source.Description()
			if record := byDigest[digest]; record == nil {
				if len(byDigest) >= maxRecords {
					return diagnostic(pack.Limit, item.root, "source record limit exceeded", nil)
				}
				charge := len(description.Requirements) + len(description.Members) + 1
				if *projected > maxProjectedItems-charge {
					return diagnostic(pack.Limit, item.root, "inspection projection limit exceeded", nil)
				}
				*projected += charge
				byDigest[digest] = &Record{Description: description, Scopes: []string{item.name}}
			} else if !reflect.DeepEqual(record.Description, description) {
				return diagnostic(pack.CorruptStore, item.root, "duplicate source descriptions disagree", nil)
			} else {
				if *projected == maxProjectedItems {
					return diagnostic(pack.Limit, item.root, "inspection projection limit exceeded", nil)
				}
				*projected += 1
				record.Scopes = append(record.Scopes, item.name)
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func userBase(environment Environment) (string, []string, bool) {
	switch {
	case linux.CleanAbsoluteNonRoot(environment.XDGDataHome):
		return environment.XDGDataHome, nil, true
	case linux.CleanAbsoluteNonRoot(environment.Home):
		return environment.Home, []string{".local", "share"}, true
	default:
		return "", nil, false
	}
}

func userRoot(environment Environment) string {
	base, suffix, ok := userBase(environment)
	if !ok {
		return ""
	}
	return filepath.Join(append(append([]string{base}, suffix...), "proofstrap", "packs")...)
}

func availableScopes(environment Environment) ([]scope, error) {
	result := make([]scope, 0, 4)
	if environment.ReleaseRoot != "" {
		if !linux.CleanAbsoluteNonRoot(environment.ReleaseRoot) {
			return nil, diagnostic(pack.InvalidValue, environment.ReleaseRoot, "adjacent release root must be clean, absolute, and non-root", nil)
		}
		result = append(result, scope{name: "adjacent", root: environment.ReleaseRoot})
	}
	result = append(result, scope{name: "release", root: releaseRoot}, scope{name: "system", root: systemRoot})
	if root := userRoot(environment); root != "" {
		result = append(result, scope{name: "user", root: root})
	}
	return result, nil
}

func validateArchive(ctx context.Context, path string, expected *pack.Digest) error {
	if err := canceled(ctx); err != nil {
		return err
	}
	if !linux.CleanAbsoluteNonRoot(path) {
		return diagnostic(pack.InvalidValue, path, "archive path must be clean absolute and non-root", nil)
	}
	if expected != nil && *expected == (pack.Digest{}) {
		return diagnostic(pack.InvalidValue, path, "expected digest is invalid", nil)
	}
	return nil
}

func objectDigest(name string) (pack.Digest, bool) {
	if len(name) != 64+len(".pstrap") || !strings.HasSuffix(name, ".pstrap") {
		return pack.Digest{}, false
	}
	digest, err := pack.ParseDigest("sha256:" + strings.TrimSuffix(name, ".pstrap"))
	return digest, err == nil
}

func inertStage(name string) bool {
	if len(name) != len(".import-")+32 || !strings.HasPrefix(name, ".import-") {
		return false
	}
	for _, character := range strings.TrimPrefix(name, ".import-") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func checkRecordBudget(records []Record) error {
	if len(records) > maxRecords {
		return diagnostic(pack.Limit, "", "source record limit exceeded", nil)
	}
	total := 0
	for _, record := range records {
		total += len(record.Description.Requirements) + len(record.Description.Members) + len(record.Scopes)
		if total > maxProjectedItems {
			return diagnostic(pack.Limit, "", "inspection projection limit exceeded", nil)
		}
	}
	return nil
}

func canceled(ctx context.Context) error {
	if ctx == nil {
		return diagnostic(pack.Canceled, "", "inventory operation canceled", context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return diagnostic(pack.Canceled, "", "inventory operation canceled", err)
	}
	return nil
}

func packCategory(err error) pack.Category {
	var value *pack.Diagnostic
	if errors.As(err, &value) {
		return value.Category
	}
	return pack.IO
}
