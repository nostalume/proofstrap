package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
	"github.com/nostalume/proofstrap/internal/pack"
)

const (
	importUsage    = "usage: proofstrap import [--digest DIGEST] [--system] ARCHIVE"
	inspectUsage   = "usage: proofstrap inspect ARCHIVE | proofstrap inspect --digest DIGEST ARCHIVE"
	maxInspectJSON = 8 << 20
	systemPackRoot = "/var/lib/proofstrap/packs"
)

type archiveRecord struct {
	Description pack.Description
	Scopes      []string
}

type archiveCommands struct {
	importUser     func(context.Context, processEnvironment, string, *pack.Digest) (archiveRecord, error)
	importSystem   func(context.Context, string, *pack.Digest) (archiveRecord, error)
	inspectArchive func(context.Context, string, *pack.Digest) (archiveRecord, error)
}

var productionArchives = archiveCommands{
	importUser: importUser, importSystem: importSystem, inspectArchive: inspectArchive,
}

func runImport(ctx context.Context, environment processEnvironment, commands archiveCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		fmt.Fprintln(stdout, importUsage)
		return 0
	}
	expected, archive, system, ok := parseImport(arguments)
	if !ok {
		return grammarError(stderr, importUsage)
	}
	if !canonicalCLIPaths(&archive) {
		return grammarError(stderr, importUsage)
	}
	var record archiveRecord
	var err error
	if system {
		record, err = commands.importSystem(ctx, archive, expected)
	} else {
		record, err = commands.importUser(ctx, environment, archive, expected)
	}
	return writeRecords([]archiveRecord{record}, err, stdout, stderr)
}

func runInspect(ctx context.Context, commands archiveCommands, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--help" {
		fmt.Fprintln(stdout, inspectUsage)
		return 0
	}
	var records []archiveRecord
	var err error
	switch {
	case len(arguments) == 1 && !strings.HasPrefix(arguments[0], "-"):
		if strings.HasPrefix(arguments[0], "sha256:") || !canonicalCLIPaths(&arguments[0]) {
			return grammarError(stderr, inspectUsage)
		}
		var record archiveRecord
		record, err = commands.inspectArchive(ctx, arguments[0], nil)
		records = []archiveRecord{record}
	case len(arguments) == 3 && arguments[0] == "--digest" && arguments[2] != "" && canonicalCLIPaths(&arguments[2]):
		var digest pack.Digest
		digest, err = pack.ParseDigest(arguments[1])
		if err != nil {
			return grammarError(stderr, inspectUsage)
		}
		var record archiveRecord
		record, err = commands.inspectArchive(ctx, arguments[2], &digest)
		records = []archiveRecord{record}
	default:
		return grammarError(stderr, inspectUsage)
	}
	return writeRecords(records, err, stdout, stderr)
}

func writeRecords(records []archiveRecord, result error, stdout io.Writer, stderr io.Writer) int {
	if result != nil {
		return operationResult(result, stderr)
	}
	encoded, err := encodeRecords(records)
	if err != nil {
		return operationResult(err, stderr)
	}
	if _, err := stdout.Write(encoded); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseImport(arguments []string) (expected *pack.Digest, archive string, system, ok bool) {
	seenSystem, positional := false, false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !positional && argument == "--digest" && expected == nil && index+1 < len(arguments) {
			digest, err := pack.ParseDigest(arguments[index+1])
			if err != nil {
				return nil, "", false, false
			}
			expected, index = &digest, index+1
			continue
		}
		if !positional && argument == "--system" && !seenSystem {
			seenSystem, system = true, true
			continue
		}
		if strings.HasPrefix(argument, "-") || positional {
			return nil, "", false, false
		}
		positional, archive = true, argument
	}
	return expected, archive, system, positional && archive != ""
}

func encodeRecords(records []archiveRecord) ([]byte, error) {
	projected := make([]jsonRecord, len(records))
	for index, record := range records {
		requirements := make([]jsonRequirement, len(record.Description.Requirements))
		for requirementIndex, requirement := range record.Description.Requirements {
			requirements[requirementIndex] = jsonRequirement{Handle: requirement.Handle, Digest: requirement.Digest.String()}
		}
		members := append([]string{}, record.Description.Members...)
		scopes := append([]string{}, record.Scopes...)
		projected[index] = jsonRecord{Digest: record.Description.Digest.String(), Kind: record.Description.Kind.String(), Requirements: requirements, Members: members, Scopes: scopes}
	}
	buffer := &limitedBuffer{remaining: maxInspectJSON}
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(projected); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func importUser(ctx context.Context, environment processEnvironment, archive string, expected *pack.Digest) (archiveRecord, error) {
	var root string
	var anchor string
	var names []string
	switch {
	case linux.CleanAbsoluteNonRoot(environment.xdgDataHome):
		root = filepath.Join(environment.xdgDataHome, "proofstrap", "packs")
		anchor = filepath.Dir(environment.xdgDataHome)
		names = []string{filepath.Base(environment.xdgDataHome), "proofstrap", "packs", "sha256"}
	case linux.CleanAbsoluteNonRoot(environment.home):
		root = filepath.Join(environment.home, ".local", "share", "proofstrap", "packs")
		anchor = environment.home
		names = []string{".local", "share", "proofstrap", "packs", "sha256"}
	default:
		return archiveRecord{}, &pack.Diagnostic{Category: pack.InvalidValue, Detail: "user store is unavailable"}
	}
	if err := linux.CreateDirs(anchor, names, 0o700); err != nil {
		return archiveRecord{}, fmt.Errorf("initialize user store %q: %w", root, err)
	}
	return importInto(ctx, root, archive, expected, "user")
}

func importSystem(ctx context.Context, archive string, expected *pack.Digest) (archiveRecord, error) {
	if err := linux.CreateDirs("/var/lib", []string{"proofstrap", "packs", "sha256"}, 0o755); err != nil {
		return archiveRecord{}, fmt.Errorf("initialize system store %q: %w", systemPackRoot, err)
	}
	return importInto(ctx, systemPackRoot, archive, expected, "system")
}

func importInto(ctx context.Context, root, archive string, expected *pack.Digest, scope string) (archiveRecord, error) {
	source, err := pack.Import(ctx, root, archive, expected)
	if err != nil {
		return archiveRecord{}, err
	}
	return archiveRecord{Description: source.Description(), Scopes: []string{scope}}, nil
}

func inspectArchive(ctx context.Context, archive string, expected *pack.Digest) (archiveRecord, error) {
	source, err := pack.ReadFile(ctx, archive)
	if err != nil {
		return archiveRecord{}, err
	}
	if expected != nil && source.Digest() != *expected {
		return archiveRecord{}, &pack.Diagnostic{Source: source.Digest().String(), Category: pack.Integrity, Member: archive, Detail: "archive digest does not match expected digest"}
	}
	return archiveRecord{Description: source.Description(), Scopes: []string{}}, nil
}

type jsonRequirement struct {
	Handle string `json:"handle"`
	Digest string `json:"digest"`
}

type jsonRecord struct {
	Digest       string            `json:"digest"`
	Kind         string            `json:"kind"`
	Requirements []jsonRequirement `json:"requirements"`
	Members      []string          `json:"members"`
	Scopes       []string          `json:"scopes"`
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, errors.New("Limit: inspection JSON exceeds 8 MiB")
	}
	n, err := b.Buffer.Write(data)
	b.remaining -= n
	return n, err
}

func canonicalCLIPaths(paths ...*string) bool {
	for _, target := range paths {
		if *target == "" {
			continue
		}
		absolute, err := filepath.Abs(*target)
		if strings.ContainsRune(*target, 0) || err != nil || absolute == "/" {
			return false
		}
		*target = absolute
	}
	return true
}

func grammarError(stderr io.Writer, usage string) int {
	fmt.Fprintln(stderr, "invalid arguments")
	fmt.Fprintln(stderr, usage)
	return 2
}

func operationResult(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, err)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 130
	}
	return 1
}
