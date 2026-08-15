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

func ImportUser(ctx context.Context, environment Environment, archive string, digest pack.Digest) error {
	if err := validateOperation(ctx, archive, digest); err != nil {
		return err
	}
	base, suffix, ok := userBase(environment)
	if !ok {
		return diagnostic(pack.InvalidValue, "", "user scope is unavailable", nil)
	}
	var err error
	if suffix == nil {
		err = createLeaf(base, 0o700)
		if err == nil {
			err = createBeneath(base, []string{"proofstrap", "packs", "sha256"}, 0o700)
		}
	} else {
		err = createBeneath(base, append(suffix, "proofstrap", "packs", "sha256"), 0o700)
	}
	if err != nil {
		return diagnostic(pack.IO, base, "initialize user store", err)
	}
	return pack.Import(ctx, userRoot(environment), archive, digest)
}

func ImportSystem(ctx context.Context, archive string, digest pack.Digest) error {
	if err := validateOperation(ctx, archive, digest); err != nil {
		return err
	}
	if err := createBeneath("/var/lib", []string{"proofstrap", "packs", "sha256"}, 0o755); err != nil {
		return diagnostic(pack.IO, systemRoot, "initialize system store", err)
	}
	return pack.Import(ctx, systemRoot, archive, digest)
}

func InspectArchive(ctx context.Context, archive string, expected pack.Digest) (Record, error) {
	if err := validateOperation(ctx, archive, expected); err != nil {
		return Record{}, err
	}
	fd, err := unix.Open(archive, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return Record{}, diagnostic(pack.IO, archive, "open archive", err)
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return Record{}, diagnostic(pack.IO, archive, "inspect archive", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return Record{}, diagnostic(pack.InvalidValue, archive, "archive is not a regular file", nil)
	}
	file := os.NewFile(uintptr(fd), archive)
	defer file.Close()
	source, err := pack.Read(ctx, file)
	if err != nil {
		return Record{}, diagnosticFromPack(archive, err)
	}
	if source.Digest() != expected {
		return Record{}, diagnostic(pack.Integrity, archive, "archive digest does not match expected digest", nil)
	}
	record := Record{Description: source.Description(), Scopes: []string{}}
	if err := checkRecordBudget([]Record{record}); err != nil {
		return Record{}, err
	}
	return record, nil
}

func InspectStored(ctx context.Context, environment Environment, digest *pack.Digest) ([]Record, error) {
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	scopes := availableScopes(environment)
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
	duplicate, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
			file, err := openRegularAt(fd, name)
			if err != nil {
				return diagnostic(pack.CorruptStore, filepath.Join(item.root, "sha256", name), "stored object is unsafe or non-regular", err)
			}
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
	if validPath(environment.XDGDataHome) {
		return environment.XDGDataHome, nil, true
	}
	if validPath(environment.Home) {
		return environment.Home, []string{".local", "share"}, true
	}
	return "", nil, false
}

func userRoot(environment Environment) string {
	base, suffix, ok := userBase(environment)
	if !ok {
		return ""
	}
	parts := append(append([]string(nil), suffix...), "proofstrap", "packs")
	return filepath.Join(append([]string{base}, parts...)...)
}

func availableScopes(environment Environment) []scope {
	result := []scope{{name: "release", root: releaseRoot}, {name: "system", root: systemRoot}}
	if root := userRoot(environment); root != "" {
		result = append(result, scope{name: "user", root: root})
	}
	return result
}

func validateOperation(ctx context.Context, path string, digest pack.Digest) error {
	if err := canceled(ctx); err != nil {
		return err
	}
	if !validPath(path) {
		return diagnostic(pack.InvalidValue, path, "archive path must be clean absolute and non-root", nil)
	}
	if digest == (pack.Digest{}) {
		return diagnostic(pack.InvalidValue, path, "digest is required", nil)
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

func diagnosticFromPack(path string, err error) error {
	return diagnostic(packCategory(err), path, "pack admission failed", err)
}

func packCategory(err error) pack.Category {
	var value *pack.Diagnostic
	if errors.As(err, &value) {
		return value.Category
	}
	return pack.IO
}
