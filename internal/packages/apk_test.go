package packages

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nostalume/proofstrap/internal/linux"
)

type apkRun struct {
	args   []string
	result linux.Result
	err    error
}

type apkScript struct {
	t     *testing.T
	tool  linux.Identity
	runs  []apkRun
	index int
	world []byte
}

func (script *apkScript) effects() effects {
	return effects{
		identify: func(path string) (linux.Identity, error) {
			if path != apkPath || script.tool.Path == "" {
				return linux.Identity{}, os.ErrNotExist
			}
			return script.tool, nil
		},
		run: func(_ context.Context, identity linux.Identity, args []string, _ []byte) (linux.Result, error) {
			script.t.Helper()
			if identity != script.tool || script.index >= len(script.runs) {
				script.t.Fatalf("unexpected APK run: %s %#v", identity.Path, args)
			}
			want := script.runs[script.index]
			script.index++
			if !reflect.DeepEqual(args, want.args) {
				script.t.Fatalf("APK args = %#v, want %#v", args, want.args)
			}
			return want.result, want.err
		},
	}
}

func (script *apkScript) files() apkFiles {
	return apkFiles{readWorld: func() ([]byte, error) { return append([]byte(nil), script.world...), nil }}
}

func (script *apkScript) done() {
	script.t.Helper()
	if script.index != len(script.runs) {
		script.t.Fatalf("consumed %d/%d APK runs", script.index, len(script.runs))
	}
}

func apkFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/apk/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func apkObservation(t *testing.T, desired string, state demandState, installed []record, roots []string) Observation {
	t.Helper()
	value, err := newObservation([]string{desired}, mustInventory(t, installed, roots), []demand{{Name: desired, State: state}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestAPKAdmissionBindsV3ExecutableArchitectureAndWorld(t *testing.T) {
	tool := linux.Identity{Path: apkPath, Digest: [32]byte{1}}
	script := &apkScript{t: t, tool: tool, world: []byte("busybox\n"), runs: []apkRun{
		{args: []string{"--version"}, result: started("apk-tools 3.0.6-r0, compiled for x86_64.\n")},
		{args: []string{"--print-arch"}, result: started("x86_64\n")},
	}}
	got := probeAPK(context.Background(), script.effects(), script.files())
	proof, ok := got.evidence.proof.(apkProof)
	if !ok || got.evidence.state != candidateAdmitted || proof.executable != tool || proof.version != "3.0.6-r0" || proof.architecture != "x86_64" {
		t.Fatalf("candidate = %#v, proof = %#v", got.evidence, proof)
	}
	script.done()

	for _, version := range []string{"apk-tools 2.14.9, compiled for x86_64.\n", "malformed\n"} {
		bad := &apkScript{t: t, tool: tool, world: []byte("busybox\n"), runs: []apkRun{{args: []string{"--version"}, result: started(version)}}}
		state := probeAPK(context.Background(), bad.effects(), bad.files()).evidence.state
		if state != candidateUnsupported && state != candidateIndeterminate {
			t.Fatalf("version %q state = %v", version, state)
		}
	}
}

func TestAPKObservationCombinesInstalledJSONAndWorldOnce(t *testing.T) {
	proof := apkProof{executable: linux.Identity{Path: apkPath, Digest: [32]byte{1}}, version: "3.0.6-r0", architecture: "x86_64"}
	script := &apkScript{t: t, tool: proof.executable, world: []byte("alpine-baselayout\nbusybox=1.37.0-r31\n"), runs: []apkRun{{
		args: apkInventoryArgs(), result: startedBytes(apkFixture(t, "installed.json")),
	}}}
	got, err := (apkBehavior{effects: script.effects(), files: script.files()}).Observe(context.Background(), proof, []string{"busybox", "musl", "curl"})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newObservation([]string{"busybox", "musl", "curl"}, mustInventory(t,
		[]record{{Key: "alpine-baselayout", State: "3.7.2-r1"}, {Key: "busybox", State: "1.37.0-r31"}, {Key: "musl", State: "1.2.6-r2"}},
		[]string{"alpine-baselayout", "busybox=1.37.0-r31"}), []demand{{Name: "busybox", State: demandDirect}, {Name: "musl", State: demandDependency}, {Name: "curl", State: demandMissing}})
	if !got.equal(want) {
		t.Fatalf("observation = %#v / %#v", got.inventory().installed(), got.demands())
	}
	script.done()
}

func TestAPKEvidenceParsersFailClosed(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`[{"name":"busybox","version":"1","arch":"x86_64","status":["broken-files"]}]`),
		[]byte(`[{"name":"busybox","version":"1","arch":"armv7","status":["installed"]}]`),
		[]byte(`[{"name":"busybox","version":"1","arch":"x86_64","status":["installed"],"extra":true}]`),
		[]byte(`[{"name":"busybox"}]`),
	} {
		if value, err := parseAPKObservation(data, []byte("busybox\n"), "x86_64", []string{"busybox"}); err == nil || value.valid() {
			t.Fatalf("accepted malformed APK observation %q", data)
		}
	}
	for _, world := range [][]byte{[]byte("busybox"), []byte("\n"), []byte("!busybox\n"), []byte("busy box\n")} {
		if value, err := parseAPKObservation(apkFixture(t, "installed.json"), world, "x86_64", []string{"busybox"}); err == nil || value.valid() {
			t.Fatalf("accepted malformed/conflicting world %q", world)
		}
	}
}

func TestAPKEvidenceReducesNoopAddAndUpgrade(t *testing.T) {
	missing := apkObservation(t, "curl", demandMissing, nil, nil)
	add, err := parseAPKOffer(apkFixture(t, "add.txt"), missing)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := newOffer([]Delta{
		mustDelta(t, Add, "curl", "", "8.21.0-r0"),
		mustDelta(t, Add, "libcurl", "", "8.21.0-r0"),
		mustDelta(t, RootAdd, "curl", "", "direct"),
	})
	if !add.equal(want) {
		t.Fatalf("add offer = %#v", add.Deltas())
	}

	dependency := apkObservation(t, "busybox", demandDependency, []record{{Key: "busybox", State: "1.37.0-r31"}}, nil)
	noop, err := parseAPKOffer(apkFixture(t, "noop.txt"), dependency)
	if err != nil || len(noop.Deltas()) != 1 || noop.Deltas()[0].Kind() != RootAdd {
		t.Fatalf("no-op/root offer = %#v, %v", noop.Deltas(), err)
	}

	installed := []record{{Key: "apk-tools", State: "3.0.6-r0"}, {Key: "libapk", State: "3.0.6-r0"}}
	upgradeBefore := apkObservation(t, "apk-tools", demandDirect, installed, []string{"apk-tools"})
	upgrade, err := parseAPKOffer(apkFixture(t, "upgrade.txt"), upgradeBefore)
	if err != nil || len(upgrade.Deltas()) != 2 {
		t.Fatalf("upgrade offer = %#v, %v", upgrade.Deltas(), err)
	}
}

func TestAPKEvidenceMapsEveryOtherActionToBlocker(t *testing.T) {
	before := apkObservation(t, "alpha", demandDirect, []record{{Key: "alpha", State: "2-r0"}}, []string{"alpha"})
	cases := []string{
		"(1/1) Downgrading alpha (2-r0 -> 1-r0)\nOK: 1 MiB in 1 packages\n",
		"(1/1) Purging alpha (2-r0)\nOK: 1 MiB in 0 packages\n",
		"(1/1) Reinstalling alpha (2-r0)\nOK: 1 MiB in 1 packages\n",
		"(1/1) Replacing alpha (2-r0 -> 2-r0)\nOK: 1 MiB in 1 packages\n",
		"(1/1) Updating pinning alpha@edge (2-r0)\nOK: 1 MiB in 1 packages\n",
	}
	for _, data := range cases {
		offer, err := parseAPKOffer([]byte(data), before)
		if err != nil {
			t.Fatalf("parse %q: %v", data, err)
		}
		decision, err := Decide(offer)
		if err != nil || decision.Allowed() || len(decision.Blockers()) != 1 {
			t.Fatalf("forbidden action admitted: %#v, %v", offer.Deltas(), err)
		}
	}
	for _, data := range [][]byte{[]byte(""), []byte("(2/2) Installing curl (1-r0)\nOK: 1 MiB in 1 packages\n"), []byte("(1/1) Installing curl (1-r0)"), []byte("surprise\n")} {
		if offer, err := parseAPKOffer(data, before); err == nil || offer.valid() {
			t.Fatalf("accepted malformed transaction %q", data)
		}
	}
	padded := []byte("( 1/2) Installing libcurl (1-r0)\n( 2/2) Installing curl (1-r0)\nOK: 1 MiB in 2 packages\n")
	if offer, err := parseAPKOffer(padded, apkObservation(t, "curl", demandMissing, nil, nil)); err != nil || len(offer.Deltas()) != 3 {
		t.Fatalf("padded APK sequence = %#v, %v", offer.Deltas(), err)
	}
}

func TestAPKCommitRepreviewsExactOfferBeforeMutation(t *testing.T) {
	proof := apkProof{executable: linux.Identity{Path: apkPath, Digest: [32]byte{1}}, version: "3.0.6-r0", architecture: "x86_64"}
	before := apkObservation(t, "curl", demandMissing, nil, nil)
	offer, _ := parseAPKOffer(apkFixture(t, "add.txt"), before)
	script := &apkScript{t: t, tool: proof.executable, runs: []apkRun{
		{args: apkTransactionArgs(true, []string{"curl"}), result: startedBytes(apkFixture(t, "add.txt"))},
		{args: apkTransactionArgs(false, []string{"curl"}), result: linux.Result{Started: true, Stderr: []byte("post-install advice\n")}},
	}}
	result, err := (apkBehavior{effects: script.effects(), files: script.files()}).Commit(context.Background(), proof, before, offer)
	if err != nil || !result.Started {
		t.Fatalf("Commit = %#v, %v", result, err)
	}
	script.done()

	driftBytes := []byte("(1/1) Installing curl (9.0-r0)\nOK: 1 MiB in 1 packages\n")
	drift := &apkScript{t: t, tool: proof.executable, runs: []apkRun{{args: apkTransactionArgs(true, []string{"curl"}), result: startedBytes(driftBytes)}}}
	if result, err := (apkBehavior{effects: drift.effects(), files: drift.files()}).Commit(context.Background(), proof, before, offer); !errors.Is(err, ErrStale) || result.Started {
		t.Fatalf("drift Commit = %#v, %v", result, err)
	}
}

func TestAPKVerifyRequiresOnlyReviewedPackageAndRootChanges(t *testing.T) {
	before := apkObservation(t, "curl", demandMissing, []record{{Key: "busybox", State: "1-r0"}}, []string{"busybox"})
	after := apkObservation(t, "curl", demandDirect, []record{{Key: "busybox", State: "1-r0"}, {Key: "curl", State: "8-r0"}}, []string{"busybox", "curl"})
	offer, _ := newOffer([]Delta{mustDelta(t, Add, "curl", "", "8-r0"), mustDelta(t, RootAdd, "curl", "", "direct")})
	if err := (apkBehavior{}).Verify(before, offer, after); err != nil {
		t.Fatal(err)
	}
	changed := apkObservation(t, "curl", demandDirect, []record{{Key: "busybox", State: "2-r0"}, {Key: "curl", State: "8-r0"}}, []string{"busybox", "curl"})
	if err := (apkBehavior{}).Verify(before, offer, changed); err == nil {
		t.Fatal("accepted unreviewed package change")
	}
}
