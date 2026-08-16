package packages

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/linux"
)

func TestAptVerifyAccountsForReviewedTransition(t *testing.T) {
	before := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\tamd64", State: "8.0\tii "}}, nil,
		[]demand{{Name: "curl", State: demandDependency}})
	after := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\tamd64", State: "8.1\tii "}}, []string{"curl\tamd64"},
		[]demand{{Name: "curl", State: demandDirect}})
	offer, _ := newOffer([]Delta{
		mustDelta(t, Upgrade, "curl\tamd64", "8.0", "8.1"),
		mustDelta(t, RootAdd, "curl", "", "direct"),
	})
	behavior := aptBehavior{effects: effects{
		identify: func(string) (linux.Identity, error) { panic("Verify performed I/O") },
		run: func(context.Context, linux.Identity, []string, []byte) (linux.Result, error) {
			panic("Verify performed I/O")
		},
	}}
	if err := behavior.Verify(before, offer, after); err != nil {
		t.Fatal(err)
	}
	changed := verificationObservation(t, []string{"curl"},
		[]record{{Key: "curl\tamd64", State: "8.1\thi "}}, after.inventory().roots(), after.demands())
	if err := behavior.Verify(before, offer, changed); err == nil {
		t.Fatal("Apt Verify accepted an unreviewed status change")
	}
	addBefore := verificationObservation(t, []string{"git"},
		[]record{{Key: "keep\tamd64", State: "1\tii "}}, []string{"keep\tamd64"},
		[]demand{{Name: "git", State: demandMissing}})
	addAfter := verificationObservation(t, []string{"git"},
		[]record{{Key: "git\tamd64", State: "2\tii "}, {Key: "keep\tamd64", State: "1\tii "}},
		[]string{"git\tamd64", "keep\tamd64"}, []demand{{Name: "git", State: demandDirect}})
	addOffer, _ := newOffer([]Delta{
		mustDelta(t, Add, "git\tamd64", "", "2"),
		mustDelta(t, RootAdd, "git", "", "direct"),
	})
	if err := behavior.Verify(addBefore, addOffer, addAfter); err != nil {
		t.Fatalf("verify Apt Add: %v", err)
	}
	for name, bad := range map[string]Observation{
		"extra-record": verificationObservation(t, []string{"git"}, append(addAfter.inventory().installed(), record{Key: "extra\tall", State: "1\tii "}), addAfter.inventory().roots(), addAfter.demands()),
		"wrong-status": verificationObservation(t, []string{"git"}, []record{{Key: "git\tamd64", State: "2\thi "}, {Key: "keep\tamd64", State: "1\tii "}}, addAfter.inventory().roots(), addAfter.demands()),
		"excess-root":  verificationObservation(t, []string{"git"}, addAfter.inventory().installed(), []string{"extra", "git\tamd64", "keep\tamd64"}, addAfter.demands()),
	} {
		if err := behavior.Verify(addBefore, addOffer, bad); err == nil {
			t.Fatalf("Apt Verify accepted %s", name)
		}
	}
}

func TestAptReferencesAreConcreteAndEncodedExactly(t *testing.T) {
	for _, test := range []struct {
		input, native string
		id            aptPackageID
	}{
		{"python3.11", "amd64", aptPackageID{name: "python3.11", arch: "amd64"}},
		{"libssl3:arm64", "amd64", aptPackageID{name: "libssl3", arch: "arm64", explicitArch: true}},
		{"curl=8.14.1-2", "amd64", aptPackageID{name: "curl", arch: "amd64", version: "8.14.1-2"}},
		{"libc6:arm64=2:2.41-12", "amd64", aptPackageID{name: "libc6", arch: "arm64", version: "2:2.41-12", explicitArch: true}},
	} {
		got, err := parseAptReference(test.input, test.native)
		if err != nil || got != test.id {
			t.Fatalf("parse %q = %#v, %v", test.input, got, err)
		}
		if encoded := got.argument(); encoded == test.input || encoded == "" {
			t.Fatalf("unsafe/nonexistent encoding for %q: %q", test.input, encoded)
		}
	}
	if got, _ := parseAptReference("python3.11", "amd64"); got.argument() != "?narrow(?exact-name(python3.11),?architecture(amd64))" {
		t.Fatalf("unversioned encoding = %q", got.argument())
	}
	if got, _ := parseAptReference("curl=1:8.14.1+git-2", "amd64"); got.argument() != `?narrow(?exact-name(curl),?architecture(amd64),?version(^1:8\.14\.1\+git-2$))` {
		t.Fatalf("versioned encoding = %q", got.argument())
	}
	for _, bad := range []string{"", "virtual >= 2", "pkg/release", "pkg*", "pkg?", "pkg:", ":amd64", "pkg==1", "pkg=", "pkg:amd64:extra"} {
		if got, err := parseAptReference(bad, "amd64"); err == nil || got != (aptPackageID{}) {
			t.Fatalf("accepted %q as %#v", bad, got)
		}
	}
}

func TestAptTransactionArgumentsAreRestrictiveAndStable(t *testing.T) {
	refs := []aptPackageID{{name: "python3.11", arch: "amd64"}, {name: "curl", arch: "amd64", version: "8.0-1"}}
	want := []string{
		"-q=2", "--simulate", "--yes", "--no-remove", "--no-install-recommends",
		"-o", "APT::Get::allow-downgrades=false",
		"-o", "APT::Get::allow-change-held-packages=false",
		"-o", "APT::Get::allow-remove-essential=false",
		"-o", "APT::Get::AllowUnauthenticated=false",
		"-o", "APT::Get::force-yes=false",
		"install", "--",
		"?narrow(?exact-name(python3.11),?architecture(amd64))",
		"?narrow(?exact-name(curl),?architecture(amd64),?version(^8\\.0-1$))",
	}
	if got := aptTransactionArgs(true, refs); !reflect.DeepEqual(got, want) {
		t.Fatalf("preview args = %#v", got)
	}
	want = append(want[:1], want[2:]...)
	if got := aptTransactionArgs(false, refs); !reflect.DeepEqual(got, want) {
		t.Fatalf("commit args = %#v", got)
	}
}

func TestAptAdmissionBindsEveryCompanionVersionAndArchitecture(t *testing.T) {
	proof := testAptProof()
	identities := map[string]linux.Identity{
		aptGetPath: proof.get, dpkgQueryPath: proof.query, aptMarkPath: proof.mark, dpkgPath: proof.dpkg,
	}
	runs := []aptRun{
		{proof.get, []string{"--version"}, started("apt 2.6.1 (amd64)\nSupported modules:\n"), nil},
		{proof.query, []string{"--version"}, started("Debian 'dpkg-query' package management program query tool version 1.21.22 (amd64).\n"), nil},
		{proof.mark, []string{"--version"}, started("apt 2.6.1 (amd64)\nSupported modules:\n"), nil},
		{proof.dpkg, []string{"--version"}, started("Debian 'dpkg' package management program version 1.21.22 (amd64).\n"), nil},
		{proof.dpkg, []string{"--print-architecture"}, started("amd64\n"), nil},
	}
	script := newAptScript(t, identities, runs)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := probeApt(ctx, script.effects())
	if got.evidence.state != candidateAdmitted || !got.evidence.proof.equal(proof) {
		t.Fatalf("candidate = %#v", got.evidence)
	}
	script.assertDone()

	absent := newAptScript(t, nil, nil)
	got = probeApt(ctx, absent.effects())
	if got.evidence.state != candidateAbsent {
		t.Fatalf("absent state = %v", got.evidence.state)
	}

	unsupportedRuns := append([]aptRun(nil), runs...)
	unsupportedRuns[0].result = started("apt 1.9.4 (amd64)\n")
	unsupported := newAptScript(t, identities, unsupportedRuns[:1])
	got = probeApt(ctx, unsupported.effects())
	if got.evidence.state != candidateUnsupported {
		t.Fatalf("unsupported state = %v (%s)", got.evidence.state, got.evidence.detail)
	}
	unsupported.assertDone()
}

func TestAptProofEqualityIncludesArchitectureAndAllCompanions(t *testing.T) {
	base := testAptProof()
	if !base.equal(base) {
		t.Fatal("proof differs from itself")
	}
	changed := base
	changed.nativeArch = "arm64"
	if base.equal(changed) || base.equal(fakeProof{value: "apt"}) {
		t.Fatal("proof equality ignored architecture or concrete type")
	}
	changed = base
	changed.mark.Digest[0]++
	if base.equal(changed) {
		t.Fatal("proof equality ignored apt-mark identity")
	}
}

func TestAptAdapterObservesPreviewsAndCommitsThroughNativeEvidence(t *testing.T) {
	proof := testAptProof()
	runs := []aptRun{
		{proof.query, aptInventoryArgs(), startedBytes(aptFixture(t, "installed.tsv")), nil},
		{proof.mark, []string{"showmanual"}, startedBytes(aptFixture(t, "roots.txt")), nil},
		{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "bash", "dep", "newpkg")), startedBytes(aptFixture(t, "preview.txt")), nil},
		{proof.dpkg, []string{"--compare-versions", "1.0-1", "eq", "1.1-1"}, linux.Result{Started: true, ExitCode: 1}, nil},
		{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "bash", "dep", "newpkg")), startedBytes(aptFixture(t, "preview.txt")), nil},
		{proof.dpkg, []string{"--compare-versions", "1.0-1", "eq", "1.1-1"}, linux.Result{Started: true, ExitCode: 1}, nil},
		{proof.get, aptTransactionArgs(false, aptRefs(t, "amd64", "bash", "dep", "newpkg")), started("done\n"), nil},
		{proof.query, aptInventoryArgs(), startedBytes(aptFixture(t, "installed-post.tsv")), nil},
		{proof.mark, []string{"showmanual"}, startedBytes(aptFixture(t, "roots-post.txt")), nil},
	}
	script := newAptScript(t, nil, runs)
	behavior := aptBehavior{effects: script.effects()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := behavior.Observe(ctx, proof, []string{"newpkg", "bash", "dep"})
	if err != nil {
		t.Fatal(err)
	}
	if got := observation.inventory().installed(); !reflect.DeepEqual(got, []record{
		{Key: "bash\tamd64", State: "5.2.15-2\tii "},
		{Key: "dep\tamd64", State: "1.0-1\tii "},
		{Key: "held\tamd64", State: "3.0-1\thi "},
	}) {
		t.Fatalf("installed = %#v", got)
	}
	if got := observation.inventory().roots(); !reflect.DeepEqual(got, []string{"bash\tamd64", "held\tamd64"}) {
		t.Fatalf("roots = %#v", got)
	}
	if got := observation.demands(); !reflect.DeepEqual(got, []demand{
		{Name: "bash", State: demandDirect}, {Name: "dep", State: demandDependency}, {Name: "newpkg", State: demandMissing},
	}) {
		t.Fatalf("demands = %#v", got)
	}
	offer, err := behavior.Preview(ctx, proof, observation)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{
		mustDelta(t, Add, "newpkg\tamd64", "", "2.0-1"),
		mustDelta(t, Upgrade, "dep\tamd64", "1.0-1", "1.1-1"),
		mustDelta(t, RootAdd, "dep", "", "direct"),
		mustDelta(t, RootAdd, "newpkg", "", "direct"),
	})
	if !offer.equal(want) {
		t.Fatalf("offer = %#v, want %#v", offer.Deltas(), want.Deltas())
	}
	result, err := behavior.Commit(ctx, proof, observation, offer)
	if err != nil || !result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	post, err := behavior.Observe(ctx, proof, []string{"newpkg", "bash", "dep"})
	if err != nil || !reflect.DeepEqual(post.demands(), []demand{
		{Name: "bash", State: demandDirect}, {Name: "dep", State: demandDirect}, {Name: "newpkg", State: demandDirect},
	}) {
		t.Fatalf("post-observation = %#v, %v", post.demands(), err)
	}
	if post.inventory().equal(observation.inventory()) {
		t.Fatal("post-observation lost package/root changes")
	}
	script.assertDone()
}

func TestAptObservationRejectsPartialOrPendingDpkgState(t *testing.T) {
	proof := testAptProof()
	for _, status := range []string{"iH ", "iU ", "iF ", "iW ", "it ", "iHR", "iiR", "ri ", "pi ", "ui "} {
		inventory := []byte("pkg\tamd64\t" + status + "\t1.0\n")
		script := newAptScript(t, nil, []aptRun{
			{proof.query, aptInventoryArgs(), startedBytes(inventory), nil},
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := (aptBehavior{effects: script.effects()}).Observe(ctx, proof, []string{"pkg"})
		cancel()
		if err == nil {
			t.Fatalf("accepted dpkg status %q", status)
		}
		script.assertDone()
	}
}

func TestAptObservationRejectsDuplicateNormalizedDemandAndRoots(t *testing.T) {
	proof := testAptProof()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := (aptBehavior{}).Observe(ctx, proof, []string{"bash", "bash:amd64"}); err == nil || got.valid() {
		t.Fatalf("normalized duplicate = %#v, %v", got, err)
	}
	for _, roots := range []string{"missing\n", "bash\nbash:amd64\n"} {
		script := newAptScript(t, nil, []aptRun{
			{proof.query, aptInventoryArgs(), started("bash\tamd64\tii \t1.0\n"), nil},
			{proof.mark, []string{"showmanual"}, started(roots), nil},
		})
		got, err := (aptBehavior{effects: script.effects()}).Observe(ctx, proof, []string{"bash"})
		if err == nil || got.valid() {
			t.Fatalf("roots %q = %#v, %v", roots, got, err)
		}
		script.assertDone()
	}
}

func TestAptExactVersionMismatchIsMissing(t *testing.T) {
	proof := testAptProof()
	script := newAptScript(t, nil, []aptRun{
		{proof.query, aptInventoryArgs(), started("bash\tamd64\tii \t1.0\n"), nil},
		{proof.mark, []string{"showmanual"}, started("bash\n"), nil},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := (aptBehavior{effects: script.effects()}).Observe(ctx, proof, []string{"bash=2.0"})
	if err != nil || !reflect.DeepEqual(got.demands(), []demand{{Name: "bash=2.0", State: demandMissing}}) {
		t.Fatalf("observation = %#v, %v", got.demands(), err)
	}
	script.assertDone()
}

func TestAptUnqualifiedDemandAndRootAcceptArchitectureAll(t *testing.T) {
	proof := testAptProof()
	script := newAptScript(t, nil, []aptRun{
		{proof.query, aptInventoryArgs(), started("docs\tall\tii \t1.0\n"), nil},
		{proof.mark, []string{"showmanual"}, started("docs\n"), nil},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := (aptBehavior{effects: script.effects()}).Observe(ctx, proof, []string{"docs"})
	if err != nil || !reflect.DeepEqual(got.demands(), []demand{{Name: "docs", State: demandDirect}}) ||
		!reflect.DeepEqual(got.inventory().roots(), []string{"docs\tall"}) {
		t.Fatalf("observation = %#v %#v, %v", got.demands(), got.inventory().roots(), err)
	}
	script.assertDone()
}

func TestAptPreviewFailsClosedForHeldRemovalBrokenAndMalformedEvidence(t *testing.T) {
	proof := testAptProof()
	for _, test := range []struct {
		name, output string
		stderr       string
	}{
		{"held", "Inst held [3.0-1] (3.1-1 Debian [amd64])\n", ""},
		{"broken", "Inst dep [1.0-1] (1.1-1 Debian [amd64]) [broken]\n", ""},
		{"purge", "Purg dep [1.0-1]\n", ""},
		{"stderr", "", "warning\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := aptObservation(t)
			script := newAptScript(t, nil, []aptRun{{
				proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "held")),
				linux.Result{Started: true, Stdout: []byte(test.output), Stderr: []byte(test.stderr)}, nil,
			}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if offer, err := (aptBehavior{effects: script.effects()}).Preview(ctx, proof, observation); err == nil || offer.valid() {
				t.Fatalf("offer = %#v, %v", offer, err)
			}
			script.assertDone()
		})
	}
}

func TestAptPreviewClassifiesRemovalAsBlockedEvidence(t *testing.T) {
	proof := testAptProof()
	observation := aptObservation(t)
	script := newAptScript(t, nil, []aptRun{{
		proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "held")),
		started("Remv held [3.0-1]\n"), nil,
	}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	offer, err := (aptBehavior{effects: script.effects()}).Preview(ctx, proof, observation)
	if err != nil || len(offer.Deltas()) != 1 || offer.Deltas()[0].Kind() != Remove {
		t.Fatalf("offer = %#v, %v", offer.Deltas(), err)
	}
	decision, err := Decide(offer)
	if err != nil || decision.Allowed() {
		t.Fatalf("decision allowed removal: %#v, %v", decision, err)
	}
	script.assertDone()
}

func TestAptPreviewUsesNativeEqualityForReplacement(t *testing.T) {
	proof := testAptProof()
	observation := aptObservationWith(t, "pkg", "pkg\tamd64", "1.0\tii ")
	output := "Inst pkg [1.0] (1.00 Debian [amd64])\nConf pkg (1.00 Debian [amd64])\n"
	script := newAptScript(t, nil, []aptRun{
		{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "pkg")), started(output), nil},
		{proof.dpkg, []string{"--compare-versions", "1.0", "eq", "1.00"}, started(""), nil},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	offer, err := (aptBehavior{effects: script.effects()}).Preview(ctx, proof, observation)
	if err != nil || len(offer.Deltas()) != 1 || offer.Deltas()[0].Kind() != Replace {
		t.Fatalf("offer = %#v, %v", offer.Deltas(), err)
	}
	script.assertDone()
}

func TestAptPreviewRejectsIncompleteOperationStreams(t *testing.T) {
	proof := testAptProof()
	observation := aptObservationWith(t, "pkg", "pkg\tamd64", "1.0\tii ")
	for _, output := range []string{
		"Inst pkg [1.0] (2.0 Debian [amd64])",
		"Inst pkg [1.0] (2.0 Debian [amd64])\n",
		"Conf pkg (2.0 Debian [amd64])\n",
		"Inst pkg [1.0] (2.0 Debian [amd64])\nInst pkg [1.0] (2.0 Debian [amd64])\nConf pkg (2.0 Debian [amd64])\n",
		"Unknown pkg\n",
	} {
		script := newAptScript(t, nil, []aptRun{{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "pkg")), started(output), nil}})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		offer, err := (aptBehavior{effects: script.effects()}).Preview(ctx, proof, observation)
		cancel()
		if err == nil || offer.valid() {
			t.Fatalf("accepted %q as %#v", output, offer.Deltas())
		}
		script.assertDone()
	}
}

func TestAptCommitPreservesStarted(t *testing.T) {
	proof := testAptProof()
	observation := aptObservation(t)
	expected, _ := newOffer(nil)
	for _, test := range []struct {
		result linux.Result
		err    error
	}{
		{linux.Result{Started: true, ExitCode: 100}, nil},
		{linux.Result{Started: true}, context.DeadlineExceeded},
		{linux.Result{}, nil},
	} {
		script := newAptScript(t, nil, []aptRun{
			{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "held")), started(""), nil},
			{proof.get, aptTransactionArgs(false, aptRefs(t, "amd64", "held")), test.result, test.err},
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, err := (aptBehavior{effects: script.effects()}).Commit(ctx, proof, observation, expected)
		cancel()
		if err == nil || got.Started != test.result.Started {
			t.Fatalf("commit = %#v, %v", got, err)
		}
		script.assertDone()
	}
}

func TestAptCommitBlocksChangedOfferBeforeMutation(t *testing.T) {
	proof := testAptProof()
	observation := aptObservation(t)
	expected, _ := newOffer(nil)
	script := newAptScript(t, nil, []aptRun{{proof.get, aptTransactionArgs(true, aptRefs(t, "amd64", "held")), started("Remv held [3.0-1]\n"), nil}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (aptBehavior{effects: script.effects()}).Commit(ctx, proof, observation, expected)
	if err == nil || !errors.Is(err, ErrStale) || result.Started {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	script.assertDone()
}

func aptObservation(t *testing.T) Observation {
	t.Helper()
	inv, _ := newInventory([]record{{Key: "held\tamd64", State: "3.0-1\thi "}}, []string{"held\tamd64"})
	value, err := newObservation([]string{"held"}, inv, []demand{{Name: "held", State: demandDirect}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func aptObservationWith(t *testing.T, desired, key, state string) Observation {
	t.Helper()
	inv, _ := newInventory([]record{{Key: key, State: state}}, []string{key})
	value, err := newObservation([]string{desired}, inv, []demand{{Name: desired, State: demandDirect}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func aptRefs(t *testing.T, arch string, values ...string) []aptPackageID {
	t.Helper()
	refs := make([]aptPackageID, len(values))
	for i, value := range values {
		var err error
		refs[i], err = parseAptReference(value, arch)
		if err != nil {
			t.Fatal(err)
		}
	}
	return refs
}

func testAptProof() aptProof {
	return aptProof{
		get: linux.Identity{Path: aptGetPath, Digest: [32]byte{1}}, getVersion: "2.6.1",
		query: linux.Identity{Path: dpkgQueryPath, Digest: [32]byte{2}}, queryVersion: "1.21.22",
		mark: linux.Identity{Path: aptMarkPath, Digest: [32]byte{3}}, markVersion: "2.6.1",
		dpkg: linux.Identity{Path: dpkgPath, Digest: [32]byte{4}}, dpkgVersion: "1.21.22", nativeArch: "amd64",
	}
}

func started(text string) linux.Result { return startedBytes([]byte(text)) }
func startedBytes(data []byte) linux.Result {
	return linux.Result{Started: true, Stdout: data}
}

type aptRun struct {
	identity linux.Identity
	args     []string
	result   linux.Result
	err      error
}

type aptScript struct {
	t          *testing.T
	identities map[string]linux.Identity
	runs       []aptRun
	index      int
}

func newAptScript(t *testing.T, identities map[string]linux.Identity, runs []aptRun) *aptScript {
	t.Helper()
	return &aptScript{t: t, identities: identities, runs: runs}
}

func (script *aptScript) effects() effects {
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
				script.t.Fatalf("stdin = %q", stdin)
			}
			if script.index >= len(script.runs) {
				script.t.Fatalf("unexpected run %#v %#v", identity, args)
			}
			want := script.runs[script.index]
			script.index++
			if identity != want.identity || !reflect.DeepEqual(args, want.args) {
				script.t.Fatalf("run = %#v %#v, want %#v %#v", identity, args, want.identity, want.args)
			}
			return want.result, want.err
		},
	}
}

func (script *aptScript) assertDone() {
	script.t.Helper()
	if script.index != len(script.runs) {
		script.t.Fatalf("consumed %d of %d runs", script.index, len(script.runs))
	}
}

func aptFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/apt/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
