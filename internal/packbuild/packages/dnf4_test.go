package packages

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/linuxexec"
)

type dnf4Run struct {
	identity linuxexec.Identity
	args     []string
	result   linuxexec.Result
	err      error
}

type dnf4Script struct {
	t          *testing.T
	identities map[string]linuxexec.Identity
	runs       []dnf4Run
	index      int
}

func (script *dnf4Script) effects() effects {
	return effects{
		identify: func(path string) (linuxexec.Identity, error) {
			identity, ok := script.identities[path]
			if !ok {
				return linuxexec.Identity{}, os.ErrNotExist
			}
			return identity, nil
		},
		run: func(_ context.Context, identity linuxexec.Identity, args []string, _ []byte) (linuxexec.Result, error) {
			script.t.Helper()
			if script.index >= len(script.runs) {
				script.t.Fatalf("unexpected DNF4 run: %s %#v", identity.Path, args)
			}
			want := script.runs[script.index]
			script.index++
			if identity != want.identity || !reflect.DeepEqual(args, want.args) {
				script.t.Fatalf("DNF4 run = %s %#v, want %s %#v", identity.Path, args, want.identity.Path, want.args)
			}
			return want.result, want.err
		},
	}
}

func (script *dnf4Script) assertDone() {
	script.t.Helper()
	if script.index != len(script.runs) {
		script.t.Fatalf("consumed %d/%d DNF4 runs", script.index, len(script.runs))
	}
}

func mustInventory(t *testing.T, installed []record, roots []string) inventory {
	t.Helper()
	value, err := newInventory(installed, roots)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func dnf4Fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/dnf4/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dnf4Observation(t *testing.T, desired string, state demandState, installed ...record) Observation {
	t.Helper()
	inventory := mustInventory(t, installed, nil)
	value, err := newObservation([]string{desired}, inventory, []demand{{Name: desired, State: state}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDNF4AdmissionReducesAliasesAndBindsVersion(t *testing.T) {
	identity := linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}
	script := &dnf4Script{
		t: t,
		identities: map[string]linuxexec.Identity{
			dnf4Path: identity,
			dnfPath:  identity,
		},
		runs: []dnf4Run{{identity: identity, args: []string{"--version"}, result: started("4.23.0\n")}},
	}
	got := probeDNF4(context.Background(), script.effects())
	proof, ok := got.evidence.proof.(dnf4Proof)
	if !ok || got.evidence.state != candidateAdmitted || proof.executable != identity || proof.version != "4.23.0" {
		t.Fatalf("candidate = %#v, proof = %#v", got.evidence, proof)
	}
	script.assertDone()

	conflict := *script
	conflict.index = 0
	conflict.identities = map[string]linuxexec.Identity{
		dnf4Path: identity,
		dnfPath:  {Path: "/usr/bin/other-dnf", Digest: [32]byte{2}},
	}
	conflict.runs = nil
	if state := probeDNF4(context.Background(), conflict.effects()).evidence.state; state != candidateIndeterminate {
		t.Fatalf("conflicting aliases state = %v", state)
	}
}

func TestDNF4VersionFloorAndNativeDetailEnvelope(t *testing.T) {
	for _, test := range []struct {
		data      string
		version   string
		supported bool
		valid     bool
	}{
		{"4.2.22\n", "4.2.22", false, true},
		{"4.2.23\n", "4.2.23", true, true},
		{"4.23.0\n  Installed: dnf-4.23.0-1.noarch at Thu Jan  1 00:00:00 1970\n  Built    : Fedora Project at Thu Jan  1 00:00:00 1970\n", "4.23.0", true, true},
		{"dnf5 version 5.2.16.0\ndnf5 plugin API version 2.0\n", "5.2.16.0", false, true},
		{"four\n", "", false, false},
	} {
		version, supported, err := parseDNF4Version([]byte(test.data))
		if (err == nil) != test.valid || version != test.version || supported != test.supported {
			t.Fatalf("parse %q = %q, %v, %v", test.data, version, supported, err)
		}
	}
}

func TestDNF4ArgumentsAreExactAndApplyCacheIsFrozen(t *testing.T) {
	desired := []string{"curl", "git-core"}
	want := []string{
		"--color=never", "--setopt=best=true", "--setopt=multilib_policy=best",
		"--setopt=install_weak_deps=false", "--setopt=obsoletes=false",
		"--setopt=allow_vendor_change=false", "--setopt=strict=true", "--setopt=tsflags=",
		"--assumeno", "install-n", "--", "curl", "git-core",
	}
	if got := dnf4TransactionArgs(true, false, desired); !reflect.DeepEqual(got, want) {
		t.Fatalf("plan args = %#v", got)
	}
	want = append([]string{"--cacheonly"}, want...)
	if got := dnf4TransactionArgs(true, true, desired); !reflect.DeepEqual(got, want) {
		t.Fatalf("apply preview args = %#v", got)
	}
	want[9] = "--assumeyes"
	if got := dnf4TransactionArgs(false, true, desired); !reflect.DeepEqual(got, want) {
		t.Fatalf("commit args = %#v", got)
	}
}

func TestDNF4ObservationUsesOneReasonedInventory(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	data := []byte("bash\t0\t5.2\t1.fc40\tx86_64\tFedora Project\tuser\nlibcurl\t0\t8.0\t1.fc40\tx86_64\tFedora Project\tdependency\n")
	script := &dnf4Script{t: t, runs: []dnf4Run{{identity: proof.executable, args: dnf4InventoryArgs(), result: startedBytes(data)}}}
	got, err := (dnf4Behavior{effects: script.effects()}).Observe(context.Background(), proof, []string{"missing", "libcurl", "bash"})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newObservation([]string{"bash", "libcurl", "missing"}, mustInventory(t,
		[]record{{Key: "bash\t0:5.2-1.fc40\tx86_64", State: "Fedora Project"}, {Key: "libcurl\t0:8.0-1.fc40\tx86_64", State: "Fedora Project"}},
		[]string{"bash\t0:5.2-1.fc40\tx86_64"}), []demand{{Name: "bash", State: demandDirect}, {Name: "libcurl", State: demandDependency}, {Name: "missing", State: demandMissing}})
	if !got.equal(want) {
		t.Fatalf("observation = %#v, want %#v", got.demands(), want.demands())
	}
	script.assertDone()
}

func TestDNF4ObservationRejectsUnknownReasonAndNativeFailure(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	for _, run := range []dnf4Run{
		{identity: proof.executable, args: dnf4InventoryArgs(), result: started("pkg\t0\t1\t1\tx86_64\tvendor\tmystery\n")},
		{identity: proof.executable, args: dnf4InventoryArgs(), result: linuxexec.Result{}, err: errors.New("start")},
	} {
		script := &dnf4Script{t: t, runs: []dnf4Run{run}}
		if got, err := (dnf4Behavior{effects: script.effects()}).Observe(context.Background(), proof, []string{"pkg"}); err == nil || got.valid() {
			t.Fatalf("accepted invalid observation: %#v", got)
		}
	}
}

func TestDNF4ObservationClassifiesEveryAdmittedReason(t *testing.T) {
	data := []byte(strings.Join([]string{
		"dep\t0\t1\t1\tx86_64\tvendor\tdependency",
		"weak\t0\t1\t1\tx86_64\tvendor\tweak-dependency",
		"user\t0\t1\t1\tx86_64\tvendor\tuser",
		"group\t0\t1\t1\tx86_64\tvendor\tgroup",
		"external\t0\t1\t1\tx86_64\tvendor\tunknown",
	}, "\n") + "\n")
	got, err := parseDNF4Observation(data, []string{"dep", "weak", "user", "group", "external", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]demandState{"dep": demandDependency, "weak": demandDependency, "user": demandDirect, "group": demandDirect, "external": demandDirect, "missing": demandMissing}
	for _, demand := range got.demands() {
		if demand.State != want[demand.Name] {
			t.Fatalf("%s state = %v, want %v", demand.Name, demand.State, want[demand.Name])
		}
	}
	for _, bad := range [][]byte{
		[]byte("pkg\t0\t1\t1\tx86_64\tvendor\tclean\n"),
		[]byte("pkg\t0\t1\t1\tx86_64\tvendor\tuser"),
		[]byte("pkg\tbad\t1\t1\tx86_64\tvendor\tuser\n"),
		[]byte("pkg\t0\t1\t1\tx86_64\tvendor\tuser\npkg\t0\t1\t1\tx86_64\tvendor\tuser\n"),
	} {
		if value, err := parseDNF4Observation(bad, []string{"pkg"}); err == nil || value.valid() {
			t.Fatalf("accepted malformed observation %q", bad)
		}
	}
}

func TestDNF4RejectsNonConcreteDesiredNamesBeforeExecution(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	for _, name := range []string{"", "pkg*", "pkg-1:2-3", "/tmp/pkg.rpm", "capability(foo)", "pkg >= 1"} {
		script := &dnf4Script{t: t}
		if got, err := (dnf4Behavior{effects: script.effects()}).Observe(context.Background(), proof, []string{name}); err == nil || got.valid() {
			t.Fatalf("accepted desired name %q", name)
		}
		script.assertDone()
	}
}

func TestDNF4PreviewParsesCompleteTransactionAndSummary(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	observation := dnf4Observation(t, "kernel", demandMissing)
	result := linuxexec.Result{Started: true, ExitCode: 1, Stdout: dnf4Fixture(t, "preview-install.txt")}
	script := &dnf4Script{t: t, runs: []dnf4Run{{identity: proof.executable, args: dnf4TransactionArgs(true, false, []string{"kernel"}), result: result}}}
	got, err := (dnf4Behavior{effects: script.effects()}).Preview(context.Background(), proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{
		mustDelta(t, Add, "kernel\tx86_64", "", "0:4.18.0-348.23.1.el8_5"),
		mustDelta(t, Add, "kernel-core\tx86_64", "", "0:4.18.0-348.23.1.el8_5"),
		mustDelta(t, Add, "kernel-modules\tx86_64", "", "0:4.18.0-348.23.1.el8_5"),
		mustDelta(t, RootAdd, "kernel", "", "direct"),
	})
	if !got.equal(want) {
		t.Fatalf("offer = %#v, want %#v", got.Deltas(), want.Deltas())
	}
	script.assertDone()
}

func TestDNF4PreviewAdmitsOnlyExactNoPackageEnvelope(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	installed := record{Key: "curl\t0:8.0-1.fc40\tx86_64", State: "Fedora Project"}
	observation := dnf4Observation(t, "curl", demandDependency, installed)
	script := &dnf4Script{t: t, runs: []dnf4Run{{
		identity: proof.executable, args: dnf4TransactionArgs(true, false, []string{"curl"}),
		result: startedBytes(dnf4Fixture(t, "preview-nothing.txt")),
	}}}
	got, err := (dnf4Behavior{effects: script.effects()}).Preview(context.Background(), proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{mustDelta(t, RootAdd, "curl", "", "direct")})
	if !got.equal(want) {
		t.Fatalf("offer = %#v", got.Deltas())
	}

	bad := append([]byte(nil), dnf4Fixture(t, "preview-install.txt")...)
	bad = []byte(strings.Replace(string(bad), "Install  3 Packages", "Install  2 Packages", 1))
	failed := &dnf4Script{t: t, runs: []dnf4Run{{
		identity: proof.executable, args: dnf4TransactionArgs(true, false, []string{"curl"}),
		result: linuxexec.Result{Started: true, ExitCode: 1, Stdout: bad},
	}}}
	if got, err := (dnf4Behavior{effects: failed.effects()}).Preview(context.Background(), proof, observation); err == nil || got.valid() {
		t.Fatalf("accepted mismatched summary: %#v", got)
	}
}

func TestDNF4PreviewMapsRecognizedBlockingActions(t *testing.T) {
	installed := []record{
		{Key: "alpha\t0:1-1\tx86_64", State: "vendor"},
		{Key: "beta\t0:1-1\tnoarch", State: "vendor"},
		{Key: "gamma\t0:1-1\tx86_64", State: "vendor"},
		{Key: "delta\t0:2-1\tx86_64", State: "vendor"},
	}
	inventory := mustInventory(t, installed, []string{"alpha\t0:1-1\tx86_64"})
	observation, _ := newObservation([]string{"alpha"}, inventory, []demand{{Name: "alpha", State: demandDirect}})
	got, transaction, err := parseDNF4Preview(dnf4Fixture(t, "preview-actions.txt"), observation)
	if err != nil || !transaction {
		t.Fatalf("parse actions = %#v, %v, %v", got, transaction, err)
	}
	want, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "alpha\tx86_64", "0:1-1", "0:2-1"),
		mustDelta(t, Replace, "beta\tnoarch", "0:1-1", "0:1-1 (reinstall)"),
		mustDelta(t, Remove, "gamma\tx86_64", "0:1-1", ""),
		mustDelta(t, Downgrade, "delta\tx86_64", "0:2-1", "0:1-1"),
	})
	if !got.equal(want) {
		t.Fatalf("offer = %#v, want %#v", got.Deltas(), want.Deltas())
	}
	decision, _ := Decide(got)
	if decision.Allowed() {
		t.Fatal("blocking DNF4 actions were allowed")
	}
}

func TestDNF4PreviewRejectsUnsupportedOrIncompleteNativeEvidence(t *testing.T) {
	observation := dnf4Observation(t, "kernel", demandMissing)
	base := string(dnf4Fixture(t, "preview-install.txt"))
	for _, data := range []string{
		strings.Replace(base, "Installing dependencies:", "Installing weak dependencies:", 1),
		strings.Replace(base, "Installing dependencies:", "Installing group/module packages:", 1),
		strings.Replace(base, "Installing dependencies:", "Skipping packages with conflicts:", 1),
		strings.Replace(base, " kernel-core", "     replacing  old-kernel.x86_64 0:1-1\n kernel-core", 1),
		strings.Replace(base, "Operation aborted.", "unexpected trailer\nOperation aborted.", 1),
		strings.TrimSuffix(base, "\n"),
		strings.Replace(base, "Dependencies resolved.\n", "Dependencies resolved.\nDependencies resolved.\n", 1),
	} {
		if got, _, err := parseDNF4Preview([]byte(data), observation); err == nil || got.valid() {
			t.Fatalf("accepted invalid preview evidence")
		}
	}
}

func TestDNF4CommitRepreviewsInstallsAndCorrectsExactRoot(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	installed := record{Key: "curl\t0:8.0-1.fc40\tx86_64", State: "Fedora Project"}
	observation := dnf4Observation(t, "curl", demandDependency, installed)
	preview := linuxexec.Result{Started: true, ExitCode: 1, Stdout: dnf4Fixture(t, "preview-upgrade.txt")}
	expected, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "curl\tx86_64", "0:8.0-1.fc40", "0:8.1-1.fc40"),
		mustDelta(t, RootAdd, "curl", "", "direct"),
	})
	script := &dnf4Script{t: t, runs: []dnf4Run{
		{identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}), result: preview},
		{identity: proof.executable, args: dnf4TransactionArgs(false, true, []string{"curl"}), result: started("Complete!\n")},
		{identity: proof.executable, args: dnf4MarkArgs([]string{"curl-0:8.1-1.fc40.x86_64"}), result: started("curl-0:8.1-1.fc40.x86_64 marked as user installed.\n")},
	}}
	result, err := (dnf4Behavior{effects: script.effects()}).Commit(context.Background(), proof, observation, expected)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
}

func TestDNF4LifecycleCarriesOneProofThroughObservePreviewCommitObserve(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	before := []byte("curl\t0\t8.0\t1.fc40\tx86_64\tFedora Project\tdependency\n")
	after := []byte("curl\t0\t8.1\t1.fc40\tx86_64\tFedora Project\tuser\n")
	preview := linuxexec.Result{Started: true, ExitCode: 1, Stdout: dnf4Fixture(t, "preview-upgrade.txt")}
	script := &dnf4Script{t: t, runs: []dnf4Run{
		{identity: proof.executable, args: dnf4InventoryArgs(), result: startedBytes(before)},
		{identity: proof.executable, args: dnf4TransactionArgs(true, false, []string{"curl"}), result: preview},
		{identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}), result: preview},
		{identity: proof.executable, args: dnf4TransactionArgs(false, true, []string{"curl"}), result: started("Complete!\n")},
		{identity: proof.executable, args: dnf4MarkArgs([]string{"curl-0:8.1-1.fc40.x86_64"}), result: started("curl marked as user installed.\n")},
		{identity: proof.executable, args: dnf4InventoryArgs(), result: startedBytes(after)},
	}}
	behavior := dnf4Behavior{effects: script.effects()}

	observation, err := behavior.Observe(context.Background(), proof, []string{"curl"})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := behavior.Preview(context.Background(), proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Decide(offer)
	if err != nil || !decision.Allowed() {
		t.Fatalf("decision = %#v, %v", decision, err)
	}
	result, err := behavior.Commit(context.Background(), proof, observation, offer)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	observed, err := behavior.Observe(context.Background(), proof, []string{"curl"})
	if err != nil {
		t.Fatal(err)
	}
	demands := observed.demands()
	if len(demands) != 1 || demands[0] != (demand{Name: "curl", State: demandDirect}) {
		t.Fatalf("final demands = %#v", demands)
	}
	script.assertDone()
}

func TestDNF4VerifyAccountsForReviewedTransition(t *testing.T) {
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
	behavior := dnf4Behavior{effects: effects{
		identify: func(string) (linuxexec.Identity, error) { panic("Verify performed I/O") },
		run: func(context.Context, linuxexec.Identity, []string, []byte) (linuxexec.Result, error) {
			panic("Verify performed I/O")
		},
	}}
	if err := behavior.Verify(before, offer, after); err != nil {
		t.Fatal(err)
	}
	missingRoot := verificationObservation(t, []string{"curl"}, after.inventory().installed(), nil, after.demands())
	if err := behavior.Verify(before, offer, missingRoot); err == nil {
		t.Fatal("DNF4 Verify accepted a missing root transition")
	}
	exerciseRPMVerification(t, behavior, "new\t0:2-1\tx86_64")
}

func TestDNF4RootOnlyCommitSkipsPackageTransaction(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	installed := record{Key: "curl\t0:8.0-1.fc40\tx86_64", State: "Fedora Project"}
	observation := dnf4Observation(t, "curl", demandDependency, installed)
	expected, _ := newOffer([]Delta{mustDelta(t, RootAdd, "curl", "", "direct")})
	script := &dnf4Script{t: t, runs: []dnf4Run{
		{identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}), result: startedBytes(dnf4Fixture(t, "preview-nothing.txt"))},
		{identity: proof.executable, args: dnf4MarkArgs([]string{"curl-0:8.0-1.fc40.x86_64"}), result: started("curl marked as user installed.\n")},
	}}
	result, err := (dnf4Behavior{effects: script.effects()}).Commit(context.Background(), proof, observation, expected)
	if err != nil || !result.Started {
		t.Fatalf("root commit = %#v, %v", result, err)
	}
	script.assertDone()
}

func TestDNF4CommitBlocksDriftAndPreservesStarted(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	installed := record{Key: "curl\t0:8.0-1.fc40\tx86_64", State: "Fedora Project"}
	observation := dnf4Observation(t, "curl", demandDependency, installed)
	expected, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "curl\tx86_64", "0:8.0-1.fc40", "0:8.1-1.fc40"),
		mustDelta(t, RootAdd, "curl", "", "direct"),
	})
	drift := &dnf4Script{t: t, runs: []dnf4Run{{
		identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}),
		result: startedBytes(dnf4Fixture(t, "preview-nothing.txt")),
	}}}
	if result, err := (dnf4Behavior{effects: drift.effects()}).Commit(context.Background(), proof, observation, expected); err == nil || !errors.Is(err, ErrStale) || result.Started {
		t.Fatalf("drift commit = %#v, %v", result, err)
	}
	drift.assertDone()

	preview := linuxexec.Result{Started: true, ExitCode: 1, Stdout: dnf4Fixture(t, "preview-upgrade.txt")}
	failure := &dnf4Script{t: t, runs: []dnf4Run{
		{identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}), result: preview},
		{identity: proof.executable, args: dnf4TransactionArgs(false, true, []string{"curl"}), result: started("failed\n"), err: errors.New("wait")},
	}}
	if result, err := (dnf4Behavior{effects: failure.effects()}).Commit(context.Background(), proof, observation, expected); err == nil || !result.Started {
		t.Fatalf("failed commit = %#v, %v", result, err)
	}

	markFailure := &dnf4Script{t: t, runs: []dnf4Run{
		{identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"curl"}), result: preview},
		{identity: proof.executable, args: dnf4TransactionArgs(false, true, []string{"curl"}), result: started("Complete!\n")},
		{identity: proof.executable, args: dnf4MarkArgs([]string{"curl-0:8.1-1.fc40.x86_64"}), err: errors.New("start")},
	}}
	if result, err := (dnf4Behavior{effects: markFailure.effects()}).Commit(context.Background(), proof, observation, expected); err == nil || !result.Started {
		t.Fatalf("failed correction = %#v, %v", result, err)
	}
}

func TestDNF4RootCorrectionRejectsAmbiguousInstalledIdentity(t *testing.T) {
	proof := dnf4Proof{executable: linuxexec.Identity{Path: "/usr/bin/dnf-3", Digest: [32]byte{1}}, version: "4.23.0"}
	inventory := mustInventory(t, []record{
		{Key: "kernel\t0:1-1\tx86_64", State: "vendor"},
		{Key: "kernel\t0:2-1\tx86_64", State: "vendor"},
	}, nil)
	observation, _ := newObservation([]string{"kernel"}, inventory, []demand{{Name: "kernel", State: demandDependency}})
	expected, _ := newOffer([]Delta{mustDelta(t, RootAdd, "kernel", "", "direct")})
	script := &dnf4Script{t: t, runs: []dnf4Run{{
		identity: proof.executable, args: dnf4TransactionArgs(true, true, []string{"kernel"}),
		result: startedBytes(dnf4Fixture(t, "preview-nothing.txt")),
	}}}
	if result, err := (dnf4Behavior{effects: script.effects()}).Commit(context.Background(), proof, observation, expected); err == nil || result.Started {
		t.Fatalf("ambiguous correction = %#v, %v", result, err)
	}
	script.assertDone()
}
