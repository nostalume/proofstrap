package inventory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/pack"
	"golang.org/x/sys/unix"
)

func TestImportUserAndInspectRoutes(t *testing.T) {
	t.Parallel()
	archive, digest := semanticArchive(t)
	base := filepath.Join(t.TempDir(), "xdg")
	path := filepath.Join(t.TempDir(), "custom.pstrap")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := Environment{XDGDataHome: base}
	local, err := InspectArchive(context.Background(), path, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(local.Scopes) != 0 || local.Description.Digest != digest {
		t.Fatalf("local record = %#v", local)
	}
	if err := ImportUser(context.Background(), environment, path, digest); err != nil {
		t.Fatal(err, errors.Unwrap(err))
	}
	records, err := InspectStored(context.Background(), environment, &digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !reflect.DeepEqual(records[0].Description, local.Description) || len(records[0].Scopes) != 1 || records[0].Scopes[0] != "user" {
		t.Fatalf("stored records = %#v", records)
	}
	all, err := InspectStored(context.Background(), environment, nil)
	if err != nil || len(all) != 1 || all[0].Description.Digest != digest {
		t.Fatalf("bare inspection = %#v, %v", all, err)
	}
	info, err := os.Stat(filepath.Join(base, "proofstrap", "packs", "sha256"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("initialized store = %v, %v", info, err)
	}
}

func TestUserDerivationAndInitializationLaws(t *testing.T) {
	home := t.TempDir()
	if got := userRoot(Environment{XDGDataHome: "relative", Home: home}); got != filepath.Join(home, ".local", "share", "proofstrap", "packs") {
		t.Fatalf("HOME fallback = %q", got)
	}
	if got := userRoot(Environment{XDGDataHome: "/clean/../unclean", Home: home}); got != filepath.Join(home, ".local", "share", "proofstrap", "packs") {
		t.Fatalf("unclean XDG fallback = %q", got)
	}
	if got := userRoot(Environment{}); got != "" {
		t.Fatalf("unavailable user root = %q", got)
	}
	base := filepath.Join(t.TempDir(), "xdg")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	archive, digest := semanticArchive(t)
	path := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportUser(context.Background(), Environment{XDGDataHome: base}, path, digest); err != nil {
		t.Fatal(err)
	}
	baseInfo, _ := os.Stat(base)
	if baseInfo.Mode().Perm() != 0o755 {
		t.Fatalf("existing XDG mode changed to %o", baseInfo.Mode().Perm())
	}
	for _, relative := range []string{"proofstrap", "proofstrap/packs", "proofstrap/packs/sha256"} {
		info, err := os.Stat(filepath.Join(base, relative))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("created %s = %v, %v", relative, info, err)
		}
	}
}

func TestInspectStoredIsFailClosed(t *testing.T) {
	archive, digest := semanticArchive(t)
	base := filepath.Join(t.TempDir(), "xdg")
	path := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := Environment{XDGDataHome: base}
	if err := ImportUser(context.Background(), environment, path, digest); err != nil {
		t.Fatal(err)
	}
	sha := filepath.Join(base, "proofstrap", "packs", "sha256")
	if err := os.WriteFile(filepath.Join(sha, ".import-"+strings.Repeat("a", 32)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if records, err := InspectStored(context.Background(), environment, nil); err != nil || len(records) != 1 {
		t.Fatalf("inert staging = %#v, %v", records, err)
	}
	if err := os.WriteFile(filepath.Join(sha, "backup"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if records, err := InspectStored(context.Background(), environment, nil); records != nil || category(t, err) != pack.CorruptStore {
		t.Fatalf("unexpected entry = %#v, %v", records, err)
	}
}

func TestInspectArchiveRejectsMismatchAndNonRegular(t *testing.T) {
	archive, _ := semanticArchive(t)
	path := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong, _ := pack.ParseDigest("sha256:" + strings.Repeat("2", 64))
	if record, err := InspectArchive(context.Background(), path, wrong); record.Description.Digest != (pack.Digest{}) || category(t, err) != pack.Integrity {
		t.Fatalf("mismatch = %#v, %v", record, err)
	}
	if record, err := InspectArchive(context.Background(), t.TempDir(), wrong); record.Description.Digest != (pack.Digest{}) || category(t, err) != pack.InvalidValue {
		t.Fatalf("directory = %#v, %v", record, err)
	}
}

func TestInventoryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InspectStored(ctx, Environment{}, nil)
	if !errors.Is(err, context.Canceled) || category(t, err) != pack.Canceled {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestAcquireClosureReadsExactBundlesAndRejectsUnusedInputs(t *testing.T) {
	dependencyBytes, dependencyDigest := sourceArchive(t,
		"schema=1\nkind='semantic'\n",
		"[profiles.base]\npackages=['base']\n")
	rootBytes, rootDigest := sourceArchive(t,
		fmt.Sprintf("schema=1\nkind='semantic'\n[requires]\ncore=%q\n", dependencyDigest.String()),
		"[profiles.workload]\ninclude=['core/base']\n")
	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.pstrap")
	dependencyPath := filepath.Join(directory, "dependency.pstrap")
	if err := os.WriteFile(rootPath, rootBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dependencyPath, dependencyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	sources, err := AcquireClosure(context.Background(), Environment{}, []pack.Digest{rootDigest}, []string{dependencyPath, rootPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Digest().String() > sources[1].Digest().String() {
		t.Fatalf("closure = %#v", sources)
	}
	found := map[pack.Digest]bool{}
	for _, source := range sources {
		found[source.Digest()] = true
	}
	if !found[rootDigest] || !found[dependencyDigest] {
		t.Fatalf("closure digests = %#v", found)
	}

	unusedBytes, _ := sourceArchive(t, "schema=1\nkind='semantic'\n", "[profiles.unused]\npackages=['unused']\n")
	unusedPath := filepath.Join(directory, "unused.pstrap")
	if err := os.WriteFile(unusedPath, unusedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireClosure(context.Background(), Environment{}, []pack.Digest{rootDigest}, []string{rootPath, dependencyPath, unusedPath}); category(t, err) != pack.UnusedRequirement {
		t.Fatalf("unused bundle = %v", err)
	}
	if _, err := AcquireClosure(context.Background(), Environment{}, []pack.Digest{rootDigest}, []string{rootPath, rootPath, dependencyPath}); category(t, err) != pack.Duplicate {
		t.Fatalf("duplicate bundle = %v", err)
	}
}

func TestRecordAndProjectionLimitsAreExact(t *testing.T) {
	records := make([]Record, maxRecords)
	if err := checkRecordBudget(records); err != nil {
		t.Fatalf("exact record limit = %v", err)
	}
	if err := checkRecordBudget(append(records, Record{})); category(t, err) != pack.Limit {
		t.Fatalf("record overflow = %v", err)
	}
	exact := []Record{{Description: pack.Description{Members: make([]string, maxProjectedItems)}, Scopes: []string{}}}
	if err := checkRecordBudget(exact); err != nil {
		t.Fatalf("exact projection limit = %v", err)
	}
	exact[0].Scopes = []string{"user"}
	if err := checkRecordBudget(exact); category(t, err) != pack.Limit {
		t.Fatalf("projection overflow = %v", err)
	}
}

func TestCorruptStoredArchiveWrapsPackDiagnostic(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	sha := filepath.Join(root, "sha256")
	if err := os.MkdirAll(sha, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, _ := pack.ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err := os.WriteFile(filepath.Join(sha, strings.TrimPrefix(digest.String(), "sha256:")+".pstrap"), []byte("invalid"), 0o444); err != nil {
		t.Fatal(err)
	}
	fd, _, err := openScope(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	projected := 0
	err = inspectScope(context.Background(), fd, scope{name: "user", root: root}, map[pack.Digest]*Record{}, &projected)
	if category(t, err) != pack.CorruptStore {
		t.Fatalf("category = %v", err)
	}
	var underlying *pack.Diagnostic
	if !errors.As(err, &underlying) {
		t.Fatalf("underlying pack diagnostic lost: %v", err)
	}
}

func TestInspectExactConsolidatesScopesAndExposesCorruption(t *testing.T) {
	archive, digest := semanticArchive(t)
	left := testStore(t, archive, digest)
	right := testStore(t, archive, digest)
	scopes := []scope{{name: "release", root: left}, {name: "user", root: right}}
	records, err := inspectExact(context.Background(), scopes, digest)
	if err != nil || len(records) != 1 || strings.Join(records[0].Scopes, ",") != "release,user" {
		t.Fatalf("exact scopes = %#v, %v", records, err)
	}
	object := filepath.Join(right, "sha256", strings.TrimPrefix(digest.String(), "sha256:")+".pstrap")
	if err := os.Chmod(object, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if records, err := inspectExact(context.Background(), scopes, digest); records != nil || err == nil {
		t.Fatalf("corrupt duplicate = %#v, %v", records, err)
	}
}

func TestImportConcurrentInitializersConverge(t *testing.T) {
	archive, digest := semanticArchive(t)
	base := filepath.Join(t.TempDir(), "xdg")
	path := filepath.Join(t.TempDir(), "source.pstrap")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := Environment{XDGDataHome: base}
	const workers = 8
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsByWorker <- ImportUser(context.Background(), environment, path, digest)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent import: %v", err)
		}
	}
	records, err := InspectStored(context.Background(), environment, nil)
	if err != nil || len(records) != 1 || records[0].Description.Digest != digest {
		t.Fatalf("converged inventory = %#v, %v", records, err)
	}
}

func TestCreateBeneathUsesModeOnlyForNewDirectories(t *testing.T) {
	anchor := t.TempDir()
	if err := os.Chmod(anchor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(anchor, "existing"), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := createBeneath(anchor, []string{"existing", "new"}, 0o755); err != nil {
		t.Fatal(err)
	}
	existing, _ := os.Stat(filepath.Join(anchor, "existing"))
	created, _ := os.Stat(filepath.Join(anchor, "existing", "new"))
	if existing.Mode().Perm() != 0o711 || created.Mode().Perm() != 0o755 {
		t.Fatalf("modes existing=%o new=%o", existing.Mode().Perm(), created.Mode().Perm())
	}
}

func TestInspectScopeEntryLimitIsExact(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	sha := filepath.Join(root, "sha256")
	if err := os.MkdirAll(sha, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := range maxScopeEntries {
		name := ".import-" + fmt.Sprintf("%032x", index)
		if err := os.WriteFile(filepath.Join(sha, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd, exists, err := openScope(root)
	if err != nil || !exists {
		t.Fatalf("open scope = %d, %v, %v", fd, exists, err)
	}
	projected := 0
	if err := inspectScope(context.Background(), fd, scope{name: "user", root: root}, map[pack.Digest]*Record{}, &projected); err != nil {
		t.Fatalf("exact entry limit = %v", err)
	}
	_ = unix.Close(fd)
	if err := os.WriteFile(filepath.Join(sha, ".import-"+strings.Repeat("f", 32)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, _, _ = openScope(root)
	defer unix.Close(fd)
	projected = 0
	if err := inspectScope(context.Background(), fd, scope{name: "user", root: root}, map[pack.Digest]*Record{}, &projected); category(t, err) != pack.Limit {
		t.Fatalf("entry overflow = %v", err)
	}
}

func testStore(t *testing.T, archive []byte, digest pack.Digest) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(filepath.Join(root, "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(digest.String(), "sha256:") + ".pstrap"
	if err := os.WriteFile(filepath.Join(root, "sha256", name), archive, 0o444); err != nil {
		t.Fatal(err)
	}
	return root
}

func category(t *testing.T, err error) pack.Category {
	t.Helper()
	var value *Diagnostic
	if !errors.As(err, &value) {
		t.Fatalf("error = %T, want inventory Diagnostic", err)
	}
	return value.Category
}

func semanticArchive(t *testing.T) ([]byte, pack.Digest) {
	t.Helper()
	return sourceArchive(t, "schema=1\nkind='semantic'\n", "[profiles.base]\npackages=['base']\n")
}

func sourceArchive(t *testing.T, manifest, profile string) ([]byte, pack.Digest) {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range []struct{ name, data string }{
		{"manifest.toml", manifest},
		{"profiles/base.toml", profile},
	} {
		header := &tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(member.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	source, err := pack.Read(context.Background(), bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return output.Bytes(), source.Digest()
}
