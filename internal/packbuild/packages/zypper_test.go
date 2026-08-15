package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/linuxexec"
)

func TestZypperVerifyAccountsForReviewedTransition(t *testing.T) {
	before := verificationObservation(t, []string{"editor"},
		[]record{{Key: "vim\t0:9.0-1\tx86_64", State: "openSUSE"}}, nil,
		[]demand{{Name: "editor", State: demandDependency}})
	after := verificationObservation(t, []string{"editor"},
		[]record{{Key: "vim\t0:9.1-1\tx86_64", State: "openSUSE"}}, []string{"vim\tx86_64"},
		[]demand{{Name: "editor", State: demandDirect}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "vim\tx86_64", "0:9.0-1", "0:9.1-1"),
		mustDelta(t, RootAdd, "editor", "", "direct"),
	})
	behavior := zypperBehavior{effects: effects{
		identify: func(string) (linuxexec.Identity, error) { panic("Verify performed I/O") },
		run: func(context.Context, linuxexec.Identity, []string, []byte) (linuxexec.Result, error) {
			panic("Verify performed I/O")
		},
	}}
	if err := behavior.Verify(before, offer, after); err != nil {
		t.Fatal(err)
	}
	unexpected := verificationObservation(t, []string{"editor"}, append(after.inventory().installed(),
		record{Key: "extra\t0:1-1\tnoarch", State: "openSUSE"}), after.inventory().roots(), after.demands())
	if err := behavior.Verify(before, offer, unexpected); err == nil {
		t.Fatal("Zypper Verify accepted an unreviewed installed record")
	}
	exerciseRPMVerification(t, behavior, "new\tx86_64")
}

func TestZypperTransactionArgumentsAreRestrictiveAndStable(t *testing.T) {
	desired := []string{"a", "virtual >= 2"}
	wantPreview := []string{
		"--xmlout", "--non-interactive", "--no-refresh", "install", "--dry-run",
		"--details", "--no-recommends", "--no-force-resolution",
		"--no-allow-downgrade", "--no-allow-name-change", "--no-allow-arch-change", "--no-allow-vendor-change",
		"--", "a", "virtual >= 2",
	}
	if got := zypperTransactionArgs(true, desired); !reflect.DeepEqual(got, wantPreview) {
		t.Fatalf("preview args = %#v", got)
	}
	wantCommit := append([]string(nil), wantPreview...)
	wantCommit = append(wantCommit[:4], wantCommit[5:]...)
	if got := zypperTransactionArgs(false, desired); !reflect.DeepEqual(got, wantCommit) {
		t.Fatalf("commit args = %#v", got)
	}
	if !reflect.DeepEqual(desired, []string{"a", "virtual >= 2"}) {
		t.Fatal("argument construction mutated desired data")
	}
}

func TestZypperAdmissionClassifiesEvidenceWithoutDistroDispatch(t *testing.T) {
	zypper := linuxexec.Identity{Path: zypperPath, Digest: [32]byte{1}}
	rpm := linuxexec.Identity{Path: rpmPath, Digest: [32]byte{2}}
	for _, test := range []struct {
		name       string
		identities map[string]linuxexec.Identity
		runs       []zypperRun
		want       candidateState
	}{
		{name: "absent-primary", identities: nil, want: candidateAbsent},
		{name: "missing-companion", identities: map[string]linuxexec.Identity{zypperPath: zypper}, want: candidateIndeterminate},
		{name: "unsupported-zypper", identities: map[string]linuxexec.Identity{zypperPath: zypper, rpmPath: rpm}, runs: []zypperRun{
			{zypper, []string{"--version"}, linuxexec.Result{Started: true, Stdout: []byte("zypper 2.0.0\n")}, nil},
		}, want: candidateUnsupported},
		{name: "malformed-zypper", identities: map[string]linuxexec.Identity{zypperPath: zypper, rpmPath: rpm}, runs: []zypperRun{
			{zypper, []string{"--version"}, linuxexec.Result{Started: true, Stdout: []byte("1.14.94\n")}, nil},
		}, want: candidateIndeterminate},
		{name: "malformed-rpm-capability", identities: map[string]linuxexec.Identity{zypperPath: zypper, rpmPath: rpm}, runs: []zypperRun{
			{zypper, []string{"--version"}, linuxexec.Result{Started: true, Stdout: []byte("zypper 1.14.94\n")}, nil},
			{rpm, rpmSelfArgs(), linuxexec.Result{Started: true, Stdout: []byte("not-a-row\n")}, nil},
		}, want: candidateIndeterminate},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := newZypperScript(t, test.identities, test.runs)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got := probeZypper(ctx, script.effects())
			if got.evidence.state != test.want || got.evidence.backend.String() != "zypper" {
				t.Fatalf("probe = %#v, want state %v", got.evidence, test.want)
			}
			script.assertDone()
		})
	}
}

func TestZypperProofEqualityIncludesBothExecutablesAndVersions(t *testing.T) {
	base := zypperProof{
		zypper: linuxexec.Identity{Path: zypperPath, Digest: [32]byte{1}}, zypperVersion: "1.14.94",
		rpm: linuxexec.Identity{Path: rpmPath, Digest: [32]byte{2}}, rpmVersion: "4.20.1-6.1",
	}
	if !base.equal(base) {
		t.Fatal("proof is not equal to itself")
	}
	changed := base
	changed.rpm.Digest[0]++
	if base.equal(changed) || base.equal(fakeProof{value: "zypper"}) {
		t.Fatal("proof equality ignored concrete type or companion drift")
	}
}

func TestZypperAdapterObservesPreviewsAndCommitsThroughNativeEvidence(t *testing.T) {
	zypper := linuxexec.Identity{Path: "/usr/bin/zypper", Digest: [32]byte{1}}
	rpm := linuxexec.Identity{Path: "/usr/bin/rpm", Digest: [32]byte{2}}
	runs := []zypperRun{
		{zypper, []string{"--version"}, linuxexec.Result{Started: true, Stdout: []byte("zypper 1.14.94\n")}, nil},
		{rpm, rpmSelfArgs(), linuxexec.Result{Started: true, Stdout: fixture(t, "rpm-self.tsv")}, nil},
		{rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: fixture(t, "installed.tsv")}, nil},
		{zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: fixture(t, "roots.txt")}, nil},
		{rpm, rpmProviderArgs("bash"), linuxexec.Result{Started: true, Stdout: []byte("\"bash\"\t\"x86_64\"\n")}, nil},
		{rpm, rpmProviderArgs("editor"), linuxexec.Result{Started: true, Stdout: []byte("\"vim\"\t\"x86_64\"\n")}, nil},
		{rpm, rpmProviderArgs("missing"), linuxexec.Result{Started: true, ExitCode: 1, Stdout: []byte("no package provides missing\n")}, nil},
		{zypper, zypperTransactionArgs(true, []string{"bash", "editor", "missing"}), linuxexec.Result{Started: true, Stdout: fixture(t, "preview.xml")}, nil},
		{zypper, zypperTransactionArgs(true, []string{"bash", "editor", "missing"}), linuxexec.Result{Started: true, Stdout: fixture(t, "preview.xml")}, nil},
		{zypper, zypperTransactionArgs(false, []string{"bash", "editor", "missing"}), linuxexec.Result{Started: true, Stdout: []byte("<?xml version='1.0'?><stream/>\n")}, nil},
		{rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: fixture(t, "installed-post.tsv")}, nil},
		{zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: fixture(t, "roots-post.txt")}, nil},
		{rpm, rpmProviderArgs("bash"), linuxexec.Result{Started: true, Stdout: []byte("\"bash\"\t\"x86_64\"\n")}, nil},
		{rpm, rpmProviderArgs("editor"), linuxexec.Result{Started: true, Stdout: []byte("\"vim\"\t\"x86_64\"\n")}, nil},
		{rpm, rpmProviderArgs("missing"), linuxexec.Result{Started: true, Stdout: []byte("\"newpkg\"\t\"x86_64\"\n")}, nil},
	}
	script := newZypperScript(t, map[string]linuxexec.Identity{
		zypper.Path: zypper,
		rpm.Path:    rpm,
	}, runs)
	effect := script.effects()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	candidateValue := probeZypper(ctx, effect)
	if candidateValue.evidence.state != candidateAdmitted {
		t.Fatalf("probe state = %v (%s)", candidateValue.evidence.state, candidateValue.evidence.detail)
	}
	selected := selectExact(candidateValue.evidence.backend, []candidate{candidateValue}).(Selected)
	observation, err := selected.Observe(ctx, []string{"missing", "bash", "editor"})
	if err != nil {
		t.Fatal(err)
	}
	wantRecords := []record{
		{Key: "bash\t0:5.3.9-5.1\tx86_64", State: "openSUSE"},
		{Key: "vim\t2:9.1-3.1\tx86_64", State: "openSUSE"},
	}
	if got := observation.inventory().installed(); !reflect.DeepEqual(got, wantRecords) {
		t.Fatalf("installed = %#v, want %#v", got, wantRecords)
	}
	if got := observation.inventory().roots(); !reflect.DeepEqual(got, []string{"bash\tx86_64"}) {
		t.Fatalf("roots = %#v", got)
	}
	wantDemands := []demand{
		{Name: "bash", State: demandDirect},
		{Name: "editor", State: demandDependency},
		{Name: "missing", State: demandMissing},
	}
	if got := observation.demands(); !reflect.DeepEqual(got, wantDemands) {
		t.Fatalf("demands = %#v, want %#v", got, wantDemands)
	}

	offer, err := selected.Preview(ctx, observation)
	if err != nil {
		t.Fatal(err)
	}
	wantOffer, err := newOffer([]Delta{
		mustDelta(t, Add, "newpkg\tx86_64", "", "1.0-1"),
		mustDelta(t, Upgrade, "bash\tx86_64", "5.3.9-5.1", "5.3.9-6.2"),
		mustDelta(t, RootAdd, "editor", "", "direct"),
		mustDelta(t, RootAdd, "missing", "", "direct"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !offer.equal(wantOffer) {
		t.Fatalf("offer = %#v, want %#v", offer.Deltas(), wantOffer.Deltas())
	}
	result, err := selected.commit(ctx, observation, offer)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	post, err := selected.Observe(ctx, []string{"missing", "bash", "editor"})
	if err != nil {
		t.Fatal(err)
	}
	if got := post.demands(); !reflect.DeepEqual(got, []demand{
		{Name: "bash", State: demandDirect}, {Name: "editor", State: demandDirect}, {Name: "missing", State: demandDirect},
	}) {
		t.Fatalf("post demands = %#v", got)
	}
	if post.inventory().equal(observation.inventory()) {
		t.Fatal("post-observation did not preserve changed exact inventory")
	}
	script.assertDone()
}

func TestZypperPreviewClassifiesEveryNativeTransactionSection(t *testing.T) {
	for _, test := range []struct {
		name  string
		group string
		row   string
		kinds []DeltaKind
	}{
		{"install", "to-install", `type="package" name="pkg" edition="2-1" arch="x86_64"`, []DeltaKind{Add}},
		{"upgrade", "to-upgrade", `type="package" name="pkg" edition="2-1" edition-old="1-1" arch="x86_64"`, []DeltaKind{Upgrade}},
		{"downgrade", "to-downgrade", `type="package" name="pkg" edition="1-1" edition-old="2-1" arch="x86_64"`, []DeltaKind{Downgrade}},
		{"remove", "to-remove", `type="package" name="pkg" edition="1-1" arch="x86_64"`, []DeltaKind{Remove}},
		{"reinstall", "to-reinstall", `type="package" name="pkg" edition="1-1" arch="x86_64"`, []DeltaKind{Replace}},
		{"upgrade-architecture", "to-upgrade-change-arch", `type="package" name="pkg" edition="2-1" edition-old="1-1" arch="x86_64" arch-old="i586"`, []DeltaKind{Upgrade, ArchitectureChange}},
		{"downgrade-architecture", "to-downgrade-change-arch", `type="package" name="pkg" edition="1-1" edition-old="2-1" arch="x86_64" arch-old="i586"`, []DeltaKind{Downgrade, ArchitectureChange}},
		{"architecture", "to-change-arch", `type="package" name="pkg" edition="1-1" arch="x86_64" arch-old="i586"`, []DeltaKind{ArchitectureChange}},
	} {
		t.Run(test.name, func(t *testing.T) {
			deltas, err := parseZypperOffer(zypperOfferXML(test.group, test.row, 1))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]DeltaKind, len(deltas))
			for index, delta := range deltas {
				got[index] = delta.Kind()
			}
			if !reflect.DeepEqual(got, test.kinds) {
				t.Fatalf("kinds = %#v, want %#v", got, test.kinds)
			}
		})
	}
}

func TestZypperNativeParsersFailClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"rpm-truncated", []byte(`"pkg"\t0\t"1"\t"1"\t"x86_64"\t"vendor"`)},
		{"rpm-invalid-json", []byte("pkg\t0\t\"1\"\t\"1\"\t\"x86_64\"\t\"vendor\"\n")},
		{"rpm-invalid-epoch", []byte("\"pkg\"\tnone\t\"1\"\t\"1\"\t\"x86_64\"\t\"vendor\"\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if rows, err := parseRPMRows(test.data); err == nil || rows != nil {
				t.Fatalf("rows = %#v, %v", rows, err)
			}
		})
	}
	badRoots := strings.Replace(string(fixture(t, "roots.txt")), "i+ |", "i  |", 1)
	if roots, err := parseZypperRoots([]byte(badRoots)); err == nil || roots != nil {
		t.Fatalf("roots = %#v, %v", roots, err)
	}
	for _, data := range [][]byte{
		zypperOfferXML("unknown", `type="package" name="pkg" edition="1" arch="x86_64"`, 1),
		zypperOfferXML("to-install", `type="package" name="pkg" edition="1" arch="x86_64"`, 2),
		[]byte(`<?xml version="1.0"?><stream><install-summary packages-to-change="0">`),
		[]byte(`<?xml version="1.0"?><stream><message type="error">solver failed</message><install-summary packages-to-change="0"></install-summary></stream>`),
		[]byte(`<?xml version="1.0"?><stream><install-summary packages-to-change="0"></install-summary><prompt id="1"><text>Choose</text><option default="1" value="1"/></prompt></stream>`),
	} {
		if deltas, err := parseZypperOffer(data); err == nil || deltas != nil {
			t.Fatalf("preview = %#v, %v for %q", deltas, err, data)
		}
	}
}

func TestZypperObservationRejectsIncompleteOrContradictoryNativeState(t *testing.T) {
	proof := testZypperProof()
	installed := fixture(t, "installed.tsv")
	roots := fixture(t, "roots.txt")
	duplicateRoot := append(append([]byte(nil), roots...), []byte("i+ | @System | bash | 5.3.9-5.1 | x86_64\n")...)
	for _, test := range []struct {
		name string
		runs []zypperRun
	}{
		{"duplicate-installed", []zypperRun{
			{proof.rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: append(append([]byte(nil), installed...), installed...)}, nil},
			{proof.zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: roots}, nil},
		}},
		{"duplicate-root", []zypperRun{
			{proof.rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: installed}, nil},
			{proof.zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: duplicateRoot}, nil},
		}},
		{"truncated-root", []zypperRun{
			{proof.rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: installed}, nil},
			{proof.zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: roots[:len(roots)-1]}, nil},
		}},
		{"malformed-provider", []zypperRun{
			{proof.rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: installed}, nil},
			{proof.zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: roots}, nil},
			{proof.rpm, rpmProviderArgs("bash"), linuxexec.Result{Started: true, Stdout: []byte("bash\n")}, nil},
		}},
		{"unclassified-provider-failure", []zypperRun{
			{proof.rpm, rpmInventoryArgs(), linuxexec.Result{Started: true, Stdout: installed}, nil},
			{proof.zypper, zypperRootArgs(), linuxexec.Result{Started: true, Stdout: roots}, nil},
			{proof.rpm, rpmProviderArgs("bash"), linuxexec.Result{Started: true, ExitCode: 1, Stdout: []byte("database unavailable\n")}, nil},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := newZypperScript(t, nil, test.runs)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observation, err := (zypperBehavior{effects: script.effects()}).Observe(ctx, proof, []string{"bash"})
			if err == nil || observation.valid() {
				t.Fatalf("observation = %#v, %v", observation, err)
			}
			script.assertDone()
		})
	}
}

func TestZypperCommitPreservesStartedForEveryFailure(t *testing.T) {
	proof := testZypperProof()
	inventory, _ := newInventory(nil, nil)
	observation, _ := newObservation([]string{"pkg"}, inventory, []demand{{Name: "pkg", State: demandDirect}})
	expected, _ := newOffer(nil)
	for _, test := range []struct {
		name   string
		result linuxexec.Result
		err    error
	}{
		{"native", linuxexec.Result{Started: true, ExitCode: 107}, nil},
		{"transport-after-start", linuxexec.Result{Started: true}, context.DeadlineExceeded},
		{"invalid-not-started-success", linuxexec.Result{}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := newZypperScript(t, nil, []zypperRun{
				{proof.zypper, zypperTransactionArgs(true, []string{"pkg"}), started(`<?xml version="1.0"?><stream><install-summary packages-to-change="0"></install-summary></stream>`), nil},
				{proof.zypper, zypperTransactionArgs(false, []string{"pkg"}), test.result, test.err},
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := (zypperBehavior{effects: script.effects()}).Commit(ctx, proof, observation, expected)
			if err == nil || result.Started != test.result.Started {
				t.Fatalf("commit = %#v, %v", result, err)
			}
			script.assertDone()
		})
	}
}

func TestZypperCommitBlocksChangedOfferBeforeMutation(t *testing.T) {
	proof := testZypperProof()
	inventory, _ := newInventory(nil, nil)
	observation, _ := newObservation([]string{"pkg"}, inventory, []demand{{Name: "pkg", State: demandDirect}})
	expected, _ := newOffer(nil)
	changed := zypperOfferXML("to-install", `type="package" name="pkg" edition="1.0-1" arch="x86_64"`, 1)
	script := newZypperScript(t, nil, []zypperRun{{proof.zypper, zypperTransactionArgs(true, []string{"pkg"}), startedBytes(changed), nil}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (zypperBehavior{effects: script.effects()}).Commit(ctx, proof, observation, expected)
	if err == nil || !errors.Is(err, ErrStale) || result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
}

func testZypperProof() zypperProof {
	return zypperProof{
		zypper: linuxexec.Identity{Path: zypperPath, Digest: [32]byte{1}}, zypperVersion: "1.14.94",
		rpm: linuxexec.Identity{Path: rpmPath, Digest: [32]byte{2}}, rpmVersion: "4.20.1-6.1",
	}
}

func zypperOfferXML(group, row string, count int) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0"?><stream><install-summary packages-to-change="%d"><%s><solvable %s/></%s></install-summary></stream>`, count, group, row, group))
}

type zypperRun struct {
	identity linuxexec.Identity
	args     []string
	result   linuxexec.Result
	err      error
}

type zypperScript struct {
	t          *testing.T
	identities map[string]linuxexec.Identity
	runs       []zypperRun
	index      int
}

func newZypperScript(t *testing.T, identities map[string]linuxexec.Identity, runs []zypperRun) *zypperScript {
	t.Helper()
	return &zypperScript{t: t, identities: identities, runs: runs}
}

func (script *zypperScript) effects() effects {
	return effects{
		identify: func(path string) (linuxexec.Identity, error) {
			identity, ok := script.identities[path]
			if !ok {
				return linuxexec.Identity{}, os.ErrNotExist
			}
			return identity, nil
		},
		run: func(ctx context.Context, identity linuxexec.Identity, args []string, stdin []byte) (linuxexec.Result, error) {
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

func (script *zypperScript) assertDone() {
	if script.index != len(script.runs) {
		script.t.Fatalf("consumed %d of %d native runs", script.index, len(script.runs))
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/zypper/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
