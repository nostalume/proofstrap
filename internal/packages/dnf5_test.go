package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/linux"
)

func TestDNF5VerifyAccountsForReviewedTransition(t *testing.T) {
	before := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\t0:8.0-1\tx86_64", State: "Fedora"}}, nil,
		[]demand{{Name: "curl", State: demandDependency}})
	after := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\t0:8.1-1\tx86_64", State: "Fedora"}}, []string{"curl\t0:8.1-1\tx86_64"},
		[]demand{{Name: "curl", State: demandDirect}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "curl\tx86_64", "0:8.0-1", "0:8.1-1"),
		mustDelta(t, RootAdd, "curl", "", "direct"),
	})
	behavior := dnf5Behavior{effects: effects{
		identify: func(string) (linux.Identity, error) { panic("Verify performed I/O") },
		run: func(context.Context, linux.Identity, []string, []byte) (linux.Result, error) {
			panic("Verify performed I/O")
		},
	}}
	if err := behavior.Verify(before, offer, after); err != nil {
		t.Fatal(err)
	}
	changed := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\t0:8.1-1\tx86_64", State: "Other"}}, after.inventory().roots(), after.demands())
	if err := behavior.Verify(before, offer, changed); err == nil {
		t.Fatal("DNF5 Verify accepted an unreviewed vendor change")
	}
	exerciseRPMVerification(t, behavior, "new\t0:2-1\tx86_64")
}

func TestDNF5AdmissionBindsExactExecutableAndMajorVersion(t *testing.T) {
	identity := linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	script := newDNF5Script(t, map[string]linux.Identity{dnf5Path: identity}, []dnf5Run{{
		identity: identity,
		args:     []string{"--version"},
		result:   started("dnf5 version 5.2.16.0\ndnf5 plugin API version 2.0\nlibdnf5 version 5.2.16.0\nLoaded dnf5 plugins:\n"),
	}})
	got := probeDNF5(ctx, script.effects(), dnf5TestFiles())
	proof, ok := got.evidence.proof.(dnf5Proof)
	if got.evidence.state != candidateAdmitted || !ok || proof.executable != identity || proof.version != "5.2.16.0" {
		t.Fatalf("candidate = %#v, proof = %#v", got.evidence, proof)
	}
	script.assertDone()

	absent := newDNF5Script(t, nil, nil)
	if got := probeDNF5(ctx, absent.effects(), dnf5TestFiles()); got.evidence.state != candidateAbsent {
		t.Fatalf("absent state = %v", got.evidence.state)
	}

	unsupported := newDNF5Script(t, map[string]linux.Identity{dnf5Path: identity}, []dnf5Run{{
		identity: identity, args: []string{"--version"}, result: started("dnf5 version 6.0.0.0\n"),
	}})
	if got := probeDNF5(ctx, unsupported.effects(), dnf5TestFiles()); got.evidence.state != candidateUnsupported {
		t.Fatalf("unsupported state = %v (%s)", got.evidence.state, got.evidence.detail)
	}
	unsupported.assertDone()

	malformed := newDNF5Script(t, map[string]linux.Identity{dnf5Path: identity}, []dnf5Run{{
		identity: identity, args: []string{"--version"}, result: started("dnf5 version five\n"),
	}})
	if got := probeDNF5(ctx, malformed.effects(), dnf5TestFiles()); got.evidence.state != candidateIndeterminate {
		t.Fatalf("malformed state = %v", got.evidence.state)
	}
	malformed.assertDone()
}

func TestDNF5ArgumentsFreezeSolverAndMetadataPolicy(t *testing.T) {
	desired := []string{"bash", "kernel-core"}
	store := "/tmp/proofstrap-dnf5-x"
	wantPlan := []string{
		"--assumeyes",
		"--setopt=best=true", "--setopt=multilib_policy=best", "--setopt=install_weak_deps=false",
		"--setopt=obsoletes=false", "--setopt=allow_vendor_change=false", "--setopt=allow_downgrade=false",
		"install", "--store=" + store, "--", "bash", "kernel-core",
	}
	if got := dnf5StoreArgs(store, desired, false); !reflect.DeepEqual(got, wantPlan) {
		t.Fatalf("plan args = %#v", got)
	}
	wantApply := append([]string{"--setopt=cacheonly=metadata"}, wantPlan...)
	if got := dnf5StoreArgs(store, desired, true); !reflect.DeepEqual(got, wantApply) {
		t.Fatalf("apply args = %#v", got)
	}
	if got := dnf5ReplayArgs(store); !reflect.DeepEqual(got, []string{"--assumeyes", "replay", store}) {
		t.Fatalf("replay args = %#v", got)
	}
	if !reflect.DeepEqual(desired, []string{"bash", "kernel-core"}) {
		t.Fatal("argument construction mutated desired data")
	}
}

type dnf5Run struct {
	identity linux.Identity
	args     []string
	result   linux.Result
	err      error
}

type dnf5Script struct {
	t          *testing.T
	identities map[string]linux.Identity
	runs       []dnf5Run
	index      int
}

func newDNF5Script(t *testing.T, identities map[string]linux.Identity, runs []dnf5Run) *dnf5Script {
	t.Helper()
	return &dnf5Script{t: t, identities: identities, runs: runs}
}

func (script *dnf5Script) effects() effects {
	return effects{
		identify: func(path string) (linux.Identity, error) {
			identity, ok := script.identities[path]
			if !ok {
				return linux.Identity{}, os.ErrNotExist
			}
			return identity, nil
		},
		run: func(ctx context.Context, identity linux.Identity, args []string, stdin []byte) (linux.Result, error) {
			if _, ok := ctx.Deadline(); !ok {
				script.t.Fatal("native run lacks deadline")
			}
			if len(stdin) != 0 {
				script.t.Fatalf("stdin = %q, want empty", stdin)
			}
			if script.index == len(script.runs) {
				script.t.Fatalf("unexpected run: %#v %#v", identity, args)
			}
			want := script.runs[script.index]
			script.index++
			if identity != want.identity || !reflect.DeepEqual(args, want.args) {
				script.t.Fatalf("run %d = %#v %#v, want %#v %#v", script.index, identity, args, want.identity, want.args)
			}
			return want.result, want.err
		},
	}
}

func (script *dnf5Script) assertDone() {
	if script.index != len(script.runs) {
		script.t.Fatalf("consumed %d of %d native runs", script.index, len(script.runs))
	}
}

func dnf5TestFiles() dnf5Files {
	return dnf5Files{
		mkdirTemp:   func(string, string) (string, error) { return "", errors.New("unexpected temporary directory") },
		readBounded: func(string, int64) ([]byte, error) { return nil, errors.New("unexpected file read") },
		removeAll:   func(string) error { return errors.New("unexpected cleanup") },
	}
}

func dnf5Fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/dnf5/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDNF5ObserveClassifiesInstalledRootsInOneQuery(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	data := "bash\t0\t5.2.37\t1.fc42\tx86_64\tFedora Project\tUser\n" +
		"kernel-core\t0\t6.14.3\t200.fc42\tx86_64\tFedora Project\tDependency\n" +
		"kernel-core\t0\t6.13.12\t100.fc42\tx86_64\tFedora Project\tWeak Dependency\n"
	script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5InventoryArgs(), result: started(data)}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := (dnf5Behavior{effects: script.effects(), files: dnf5TestFiles()}).Observe(ctx, proof, []string{"bash", "kernel-core", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	wantInventory, _ := newInventory([]record{
		{Key: "bash\t0:5.2.37-1.fc42\tx86_64", State: "Fedora Project"},
		{Key: "kernel-core\t0:6.13.12-100.fc42\tx86_64", State: "Fedora Project"},
		{Key: "kernel-core\t0:6.14.3-200.fc42\tx86_64", State: "Fedora Project"},
	}, []string{"bash\t0:5.2.37-1.fc42\tx86_64"})
	if !got.inventory().equal(wantInventory) {
		t.Fatalf("inventory = %#v, want %#v", got.inventory(), wantInventory)
	}
	wantDemands := []demand{{Name: "bash", State: demandDirect}, {Name: "kernel-core", State: demandDependency}, {Name: "missing", State: demandMissing}}
	if !reflect.DeepEqual(got.demands(), wantDemands) {
		t.Fatalf("demands = %#v, want %#v", got.demands(), wantDemands)
	}
	script.assertDone()
}

func TestDNF5ObserveRejectsAmbiguousOrUnknownReasons(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	for _, data := range []string{
		"pkg\t0\t1\t1\tx86_64\tvendor\tClean\n",
		"pkg\t0\t1\t1\tx86_64\tvendor\tunknown\n",
		"pkg\t0\t1\t1\tx86_64\tvendor\tUser\npkg\t0\t1\t1\tx86_64\tvendor\tUser\n",
		"pkg\t0\t1\t1\tx86_64\tvendor\tUser",
	} {
		script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5InventoryArgs(), result: started(data)}})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, err := (dnf5Behavior{effects: script.effects(), files: dnf5TestFiles()}).Observe(ctx, proof, []string{"pkg"})
		cancel()
		if err == nil || got.valid() {
			t.Fatalf("accepted malformed installed state %q: %#v", data, got)
		}
		script.assertDone()
	}
}

func TestDNF5ObserveRejectsNonConcreteDesiredNameBeforeNativeRun(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	runs := 0
	behavior := dnf5Behavior{effects: effects{run: func(context.Context, linux.Identity, []string, []byte) (linux.Result, error) {
		runs++
		return started(""), nil
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for _, desired := range []string{"curl >= 8", "@development-tools", "/tmp/curl.rpm", "libcurl.so.4()(64bit)", "curl*"} {
		if got, err := behavior.Observe(ctx, proof, []string{desired}); err == nil || got.valid() {
			t.Fatalf("accepted non-concrete desired name %q", desired)
		}
	}
	if runs != 0 {
		t.Fatalf("native runs = %d, want 0", runs)
	}
}

func TestDNF5PreviewStoresDecodesAndCleansOneTransaction(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandDependency, "curl\t0:8.0-1.fc42\tx86_64")
	files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-a", data: []byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Upgrade","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"},{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Replaced","reason":"Dependency","repo_id":"@System"}]}`)}
	script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, false), result: started("stored\n")}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	offer, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Preview(ctx, proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{mustDelta(t, Upgrade, "curl\tx86_64", "0:8.0-1.fc42", "0:8.1-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")})
	if !offer.equal(want) {
		t.Fatalf("offer = %#v, want %#v", offer.Deltas(), want.Deltas())
	}
	script.assertDone()
	files.assertDone(t)
}

func TestDNF5PreviewRejectsUnsafeStoredEvidenceAndStillCleans(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	for _, data := range [][]byte{
		[]byte(`{"version":"2.0","rpms":[]}`),
		[]byte(`{"version":"1.0","groups":[{}],"rpms":[]}`),
		[]byte(`{"version":"1.0","environments":[{}],"rpms":[]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"../escape.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/../packages/curl.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"packages"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Unknown","reason":"User","repo_id":"fedora"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"Unknown","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"},{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Remove","reason":"Clean","repo_id":"@System","package_path":"./packages/curl.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":[{"nevra":"provider-0:1-1.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/provider.rpm"}]}`),
		[]byte(`{"version":"1.0","rpms":`),
		[]byte(`{"version":"1.0","rpms":[]} trailing`),
	} {
		files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-b", data: data}
		script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, false), result: started("stored\n")}})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		offer, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Preview(ctx, proof, observation)
		cancel()
		if err == nil || offer.valid() {
			t.Fatalf("accepted stored evidence %q as %#v", data, offer)
		}
		script.assertDone()
		files.assertDone(t)
	}
}

func TestDNF5StoredReplacementPairingIsIndependentOfRowOrder(t *testing.T) {
	observation := dnf5Observation(t, "curl", demandDependency, "curl\t0:8.0-1.fc42\tx86_64")
	data := dnf5Fixture(t, "transaction-upgrade.json")
	got, err := parseDNF5StoredOffer(data, observation)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{mustDelta(t, Upgrade, "curl\tx86_64", "0:8.0-1.fc42", "0:8.1-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")})
	if !got.equal(want) {
		t.Fatalf("offer = %#v, want %#v", got.Deltas(), want.Deltas())
	}
}

func TestDNF5StoredActionsTranslateToCanonicalDeltas(t *testing.T) {
	tests := []struct {
		name        string
		observation Observation
		data        string
		want        []Delta
	}{
		{
			name:        "install",
			observation: dnf5Observation(t, "curl", demandMissing, ""),
			data:        string(dnf5Fixture(t, "transaction-install.json")),
			want:        []Delta{mustDelta(t, Add, "curl\tx86_64", "", "0:8.1-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")},
		},
		{
			name:        "reinstall",
			observation: dnf5Observation(t, "curl", demandDirect, "curl\t0:8.0-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Reinstall","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`,
			want:        []Delta{mustDelta(t, Replace, "curl\tx86_64", "0:8.0-1.fc42", "0:8.0-1.fc42 (reinstall)")},
		},
		{
			name:        "remove",
			observation: dnf5Observation(t, "curl", demandDirect, "curl\t0:8.0-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Remove","reason":"Clean","repo_id":"@System"}]}`,
			want:        []Delta{mustDelta(t, Remove, "curl\tx86_64", "0:8.0-1.fc42", "")},
		},
		{
			name:        "unpaired-replaced",
			observation: dnf5Observation(t, "curl", demandDirect, "curl\t0:8.0-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Replaced","reason":"Dependency","repo_id":"@System"}]}`,
			want:        []Delta{mustDelta(t, Remove, "curl\tx86_64", "0:8.0-1.fc42", "")},
		},
		{
			name:        "reason-change",
			observation: dnf5Observation(t, "curl", demandDependency, "curl\t0:8.0-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Reason Change","reason":"User","repo_id":"@System"}]}`,
			want:        []Delta{mustDelta(t, RootAdd, "curl", "", "direct")},
		},
		{
			name:        "downgrade",
			observation: dnf5Observation(t, "curl", demandDependency, "curl\t0:8.1-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Replaced","reason":"Dependency","repo_id":"@System"},{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Downgrade","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`,
			want:        []Delta{mustDelta(t, Downgrade, "curl\tx86_64", "0:8.1-1.fc42", "0:8.0-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")},
		},
		{
			name:        "architecture-change",
			observation: dnf5Observation(t, "curl", demandDependency, "curl\t0:8.0-1.fc42\tx86_64"),
			data:        `{"version":"1.0","rpms":[{"nevra":"curl-0:8.0-1.fc42.x86_64","action":"Replaced","reason":"Dependency","repo_id":"@System"},{"nevra":"curl-0:8.1-1.fc42.i686","action":"Upgrade","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`,
			want:        []Delta{mustDelta(t, ArchitectureChange, "curl\ti686", "x86_64", "i686"), mustDelta(t, Upgrade, "curl\ti686", "0:8.0-1.fc42", "0:8.1-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDNF5StoredOffer([]byte(test.data), test.observation)
			if err != nil {
				t.Fatal(err)
			}
			want, err := newOffer(test.want)
			if err != nil {
				t.Fatal(err)
			}
			if !got.equal(want) {
				t.Fatalf("offer = %#v, want %#v", got.Deltas(), want.Deltas())
			}
		})
	}
}

func TestDNF5StoredReasonsAreAcceptedOnlyThroughKnownNativeRows(t *testing.T) {
	observation := dnf5Observation(t, "wanted", demandMissing, "")
	reasons := []string{"None", "Dependency", "User", "Clean", "Weak Dependency", "Group", "External User"}
	for index, reason := range reasons {
		rows := `{"nevra":"wanted-0:1-1.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/wanted.rpm"}`
		if reason == "User" {
			_, err := parseDNF5StoredOffer([]byte(`{"version":"1.0","rpms":[`+rows+`]}`), observation)
			if err != nil {
				t.Fatalf("reason %q: %v", reason, err)
			}
			continue
		}
		name := fmt.Sprintf("dependency%d", index)
		rows += fmt.Sprintf(`,{"nevra":"%s-0:1-1.x86_64","action":"Install","reason":"%s","repo_id":"fedora","package_path":"./packages/%s.rpm"}`, name, reason, name)
		if _, err := parseDNF5StoredOffer([]byte(`{"version":"1.0","rpms":[`+rows+`]}`), observation); err != nil {
			t.Fatalf("reason %q: %v", reason, err)
		}
	}
	for _, reason := range []string{"", "user", "Unknown"} {
		if dnf5StoredReason(reason) {
			t.Fatalf("unknown reason %q accepted", reason)
		}
	}
}

type dnf5FileScript struct {
	directory string
	data      []byte
	mkdirErr  error
	readErr   error
	removeErr error
	mkdirs    int
	reads     int
	removes   []string
}

func (files *dnf5FileScript) effects() dnf5Files {
	return dnf5Files{
		mkdirTemp: func(dir, pattern string) (string, error) {
			if dir != "" || pattern != "proofstrap-dnf5-" {
				return "", fmt.Errorf("temporary directory = %q, %q", dir, pattern)
			}
			files.mkdirs++
			return files.directory, files.mkdirErr
		},
		readBounded: func(path string, limit int64) ([]byte, error) {
			if path != dnf5TransactionPath(files.directory) || limit != dnf5TransactionLimit {
				return nil, fmt.Errorf("read = %q, %d", path, limit)
			}
			files.reads++
			if files.readErr != nil {
				return nil, files.readErr
			}
			return append([]byte(nil), files.data...), nil
		},
		removeAll: func(path string) error { files.removes = append(files.removes, path); return files.removeErr },
	}
}

func (files *dnf5FileScript) assertDone(t *testing.T) {
	t.Helper()
	if files.mkdirs != 1 || files.reads != 1 || !reflect.DeepEqual(files.removes, []string{files.directory}) {
		t.Fatalf("file effects = mkdir:%d read:%d removes:%#v", files.mkdirs, files.reads, files.removes)
	}
}

func dnf5Observation(t *testing.T, desired string, state demandState, recordText string) Observation {
	t.Helper()
	installed := []record(nil)
	if recordText != "" {
		installed = append(installed, record{Key: recordText, State: "Fedora Project"})
	}
	inventory, err := newInventory(installed, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, err := newObservation([]string{desired}, inventory, []demand{{Name: desired, State: state}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDNF5CommitRestoresStoreOfferBeforeReplay(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	data := []byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.1-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`)
	expected, err := parseDNF5StoredOffer(data, observation)
	if err != nil {
		t.Fatal(err)
	}
	files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-c", data: data}
	script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, true), result: started("stored\n")}, {identity: proof.executable, args: dnf5ReplayArgs(files.directory), result: started("replayed\n")}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Commit(ctx, proof, observation, expected)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
	files.assertDone(t)
}

func TestDNF5CommitBlocksChangedOfferBeforeReplay(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	expected, _ := newOffer([]Delta{mustDelta(t, Add, "curl\tx86_64", "", "0:8.1-1.fc42"), mustDelta(t, RootAdd, "curl", "", "direct")})
	files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-d", data: []byte(`{"version":"1.0","rpms":[{"nevra":"curl-0:8.2-1.fc42.x86_64","action":"Install","reason":"User","repo_id":"fedora","package_path":"./packages/curl.rpm"}]}`)}
	script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, true), result: started("stored\n")}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Commit(ctx, proof, observation, expected)
	if err == nil || !errors.Is(err, ErrStale) || result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
	files.assertDone(t)
}

func TestDNF5FilesystemReadRejectsTheOverflowByte(t *testing.T) {
	path := t.TempDir() + "/transaction.json"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, dnf5TransactionLimit+1); err != nil {
		t.Fatal(err)
	}
	data, err := systemDNF5Files().readBounded(path, dnf5TransactionLimit)
	if err == nil || data != nil {
		t.Fatalf("overflow read = %d bytes, %v", len(data), err)
	}
}

func TestDNF5PreviewCleansAfterNativeReadAndCleanupFailures(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	valid := dnf5Fixture(t, "transaction-install.json")
	tests := []struct {
		name      string
		run       dnf5Run
		files     *dnf5FileScript
		wantReads int
	}{
		{"native", dnf5Run{identity: proof.executable, result: linux.Result{Started: true, ExitCode: 1}}, &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-native"}, 0},
		{"read", dnf5Run{identity: proof.executable, result: started("stored\n")}, &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-read", readErr: errors.New("read failed")}, 1},
		{"cleanup", dnf5Run{identity: proof.executable, result: started("stored\n")}, &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-cleanup", data: valid, removeErr: errors.New("cleanup failed")}, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run.args = dnf5StoreArgs(test.files.directory, []string{"curl"}, false)
			script := newDNF5Script(t, nil, []dnf5Run{test.run})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			offer, err := (dnf5Behavior{effects: script.effects(), files: test.files.effects()}).Preview(ctx, proof, observation)
			if err == nil || offer.valid() {
				t.Fatalf("preview = %#v, %v", offer, err)
			}
			if test.files.mkdirs != 1 || test.files.reads != test.wantReads || !reflect.DeepEqual(test.files.removes, []string{test.files.directory}) {
				t.Fatalf("file effects = mkdir:%d read:%d removes:%#v", test.files.mkdirs, test.files.reads, test.files.removes)
			}
			script.assertDone()
		})
	}
}

func TestDNF5PreviewJoinsPrimaryAndCleanupFailures(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	readErr, cleanupErr := errors.New("read failed"), errors.New("cleanup failed")
	files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-joined", readErr: readErr, removeErr: cleanupErr}
	script := newDNF5Script(t, nil, []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, false), result: started("stored\n")}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Preview(ctx, proof, observation)
	if !errors.Is(err, readErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("joined error = %v", err)
	}
	script.assertDone()
}

func TestDNF5PreviewDoesNotCleanAnUncreatedDirectory(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	files := &dnf5FileScript{mkdirErr: errors.New("mkdir failed")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := (dnf5Behavior{effects: newDNF5Script(t, nil, nil).effects(), files: files.effects()}).Preview(ctx, proof, dnf5Observation(t, "curl", demandMissing, ""))
	if err == nil || files.mkdirs != 1 || len(files.removes) != 0 {
		t.Fatalf("preview error = %v, file effects = mkdir:%d removes:%#v", err, files.mkdirs, files.removes)
	}
}

func TestDNF5CommitCleanupFailurePreservesReplayStarted(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	data := dnf5Fixture(t, "transaction-install.json")
	expected, err := parseDNF5StoredOffer(data, observation)
	if err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("cleanup failed")
	files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-cleanup-after-replay", data: data, removeErr: cleanupErr}
	script := newDNF5Script(t, nil, []dnf5Run{
		{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, true), result: started("stored\n")},
		{identity: proof.executable, args: dnf5ReplayArgs(files.directory), result: started("replayed\n")},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Commit(ctx, proof, observation, expected)
	if !result.Started || !errors.Is(err, cleanupErr) {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
}

func TestDNF5CommitStartedMeansReplayStarted(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	observation := dnf5Observation(t, "curl", demandMissing, "")
	data := dnf5Fixture(t, "transaction-install.json")
	expected, err := parseDNF5StoredOffer(data, observation)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		store       linux.Result
		replay      *dnf5Run
		wantStarted bool
	}{
		{"store-failure", linux.Result{Started: true, ExitCode: 1}, nil, false},
		{"replay-exit", started("stored\n"), &dnf5Run{identity: proof.executable, result: linux.Result{Started: true, ExitCode: 1}}, true},
		{"replay-transport", started("stored\n"), &dnf5Run{identity: proof.executable, result: linux.Result{Started: true}, err: context.DeadlineExceeded}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-" + test.name, data: data}
			runs := []dnf5Run{{identity: proof.executable, args: dnf5StoreArgs(files.directory, []string{"curl"}, true), result: test.store}}
			if test.replay != nil {
				test.replay.args = dnf5ReplayArgs(files.directory)
				runs = append(runs, *test.replay)
			}
			script := newDNF5Script(t, nil, runs)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := (dnf5Behavior{effects: script.effects(), files: files.effects()}).Commit(ctx, proof, observation, expected)
			if err == nil || result.Started != test.wantStarted {
				t.Fatalf("commit = %#v, %v", result, err)
			}
			wantReads := 1
			if test.replay == nil {
				wantReads = 0
			}
			if files.mkdirs != 1 || files.reads != wantReads || !reflect.DeepEqual(files.removes, []string{files.directory}) {
				t.Fatalf("file effects = mkdir:%d read:%d removes:%#v", files.mkdirs, files.reads, files.removes)
			}
			script.assertDone()
		})
	}
}

func TestDNF5AdapterObservesPreviewsCommitsAndReobserves(t *testing.T) {
	proof := dnf5Proof{executable: linux.Identity{Path: dnf5Path, Digest: [32]byte{1}}, version: "5.2.16.0"}
	planFiles := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-plan", data: dnf5Fixture(t, "transaction-upgrade.json")}
	applyFiles := &dnf5FileScript{directory: "/tmp/proofstrap-dnf5-apply", data: dnf5Fixture(t, "transaction-upgrade.json")}
	runs := []dnf5Run{
		{identity: proof.executable, args: dnf5InventoryArgs(), result: startedBytes(dnf5Fixture(t, "installed.tsv"))},
		{identity: proof.executable, args: dnf5StoreArgs(planFiles.directory, []string{"curl"}, false), result: started("stored\n")},
		{identity: proof.executable, args: dnf5StoreArgs(applyFiles.directory, []string{"curl"}, true), result: started("stored\n")},
		{identity: proof.executable, args: dnf5ReplayArgs(applyFiles.directory), result: started("replayed\n")},
		{identity: proof.executable, args: dnf5InventoryArgs(), result: startedBytes(dnf5Fixture(t, "installed-post.tsv"))},
	}
	script := newDNF5Script(t, nil, runs)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	planBehavior := dnf5Behavior{effects: script.effects(), files: planFiles.effects()}
	observation, err := planBehavior.Observe(ctx, proof, []string{"curl"})
	if err != nil || !reflect.DeepEqual(observation.demands(), []demand{{Name: "curl", State: demandDependency}}) {
		t.Fatalf("observation = %#v, %v", observation, err)
	}
	offer, err := planBehavior.Preview(ctx, proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	applyBehavior := dnf5Behavior{effects: script.effects(), files: applyFiles.effects()}
	result, err := applyBehavior.Commit(ctx, proof, observation, offer)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	post, err := applyBehavior.Observe(ctx, proof, []string{"curl"})
	if err != nil || !reflect.DeepEqual(post.demands(), []demand{{Name: "curl", State: demandDirect}}) {
		t.Fatalf("post-observation = %#v, %v", post, err)
	}
	if post.inventory().equal(observation.inventory()) {
		t.Fatal("post-observation lost package/root changes")
	}
	script.assertDone()
	planFiles.assertDone(t)
	applyFiles.assertDone(t)
}
