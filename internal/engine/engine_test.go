package engine_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/engine"
)

func key(t testing.TB, value string) engine.Key {
	t.Helper()
	key, err := engine.NewKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDAGCanonicalScheduleAndFailureContainment(t *testing.T) {
	install := key(t, "package:flatpak")
	app := key(t, "package:flatpak:app")
	service := key(t, "service:app")
	account := key(t, "account:alice")
	dag, err := engine.Admit([]engine.Declaration{
		{Key: service, Dependencies: []engine.Key{app}},
		{Key: account},
		{Key: app, Dependencies: []engine.Key{install}},
		{Key: install},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := dag.Start()

	offer, ok := state.Next()
	if !ok || offer != account {
		t.Fatalf("first offer = %q, %v", offer, ok)
	}
	state, err = state.Record(offer, engine.Satisfied)
	if err != nil {
		t.Fatal(err)
	}
	offer, ok = state.Next()
	if !ok || offer != install {
		t.Fatalf("second offer = %q, %v", offer, ok)
	}
	state, err = state.Record(offer, engine.Failed)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Next(); ok {
		t.Fatal("dependent branch remained ready")
	}
	if state.Status() != engine.Partial {
		t.Fatalf("status = %s", state.Status())
	}

	want := map[string]engine.OperationStatus{
		"account:alice":       engine.OperationSatisfied,
		"package:flatpak":     engine.OperationFailed,
		"package:flatpak:app": engine.OperationPruned,
		"service:app":         engine.OperationPruned,
	}
	for _, result := range state.Results() {
		if want[result.Key.String()] != result.Status {
			t.Fatalf("result = %#v", result)
		}
		delete(want, result.Key.String())
	}
	if len(want) != 0 {
		t.Fatalf("missing results: %v", want)
	}
}

func TestDAGRejectsInvalidGraphsAtomically(t *testing.T) {
	a, b := key(t, "a"), key(t, "b")
	tests := []struct {
		name         string
		declarations []engine.Declaration
	}{
		{"empty", nil},
		{"zero-key", []engine.Declaration{{}}},
		{"duplicate-key", []engine.Declaration{{Key: a}, {Key: a}}},
		{"duplicate-dependency", []engine.Declaration{{Key: a}, {Key: b, Dependencies: []engine.Key{a, a}}}},
		{"missing-dependency", []engine.Declaration{{Key: a, Dependencies: []engine.Key{b}}}},
		{"self-cycle", []engine.Declaration{{Key: a, Dependencies: []engine.Key{a}}}},
		{"cycle", []engine.Declaration{{Key: a, Dependencies: []engine.Key{b}}, {Key: b, Dependencies: []engine.Key{a}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if dag, err := engine.Admit(test.declarations); err == nil || dag != (engine.DAG{}) {
				t.Fatalf("Admit = %#v, %v", dag, err)
			}
		})
	}
}

func TestDAGRejectsInvalidTransitionsWithoutChangingState(t *testing.T) {
	a, b := key(t, "a"), key(t, "b")
	dag, err := engine.Admit([]engine.Declaration{{Key: b}, {Key: a}})
	if err != nil {
		t.Fatal(err)
	}
	state := dag.Start()
	if next, err := state.Record(b, engine.Satisfied); err == nil || !reflect.DeepEqual(state.Results(), next.Results()) {
		t.Fatalf("non-offered transition changed state: %#v, %v", next.Results(), err)
	}
	if next, err := state.Record(a, engine.Outcome(99)); err == nil || !reflect.DeepEqual(state.Results(), next.Results()) {
		t.Fatalf("invalid outcome changed state: %#v, %v", next.Results(), err)
	}
	state, err = state.Record(a, engine.Satisfied)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := state.Record(a, engine.Satisfied); err == nil || !reflect.DeepEqual(state.Results(), next.Results()) {
		t.Fatalf("repeated transition changed state: %#v, %v", next.Results(), err)
	}
}

func TestDAGStaleStopsGlobally(t *testing.T) {
	a, b := key(t, "a"), key(t, "b")
	dag, err := engine.Admit([]engine.Declaration{{Key: b}, {Key: a}})
	if err != nil {
		t.Fatal(err)
	}
	state, err := dag.Start().Record(a, engine.Stale)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status() != engine.StaleStatus {
		t.Fatalf("status = %s", state.Status())
	}
	if _, ok := state.Next(); ok {
		t.Fatal("stale state offered work")
	}
	results := state.Results()
	if len(results) != 2 || results[0].Key != a || results[0].Status != engine.OperationStale ||
		results[1].Status != engine.OperationPending {
		t.Fatalf("stale results = %#v", results)
	}
}

func TestDAGTerminalStatusReduction(t *testing.T) {
	a, b := key(t, "a"), key(t, "b")
	tests := []struct {
		name    string
		outcome engine.Outcome
		status  engine.Status
	}{
		{"blocked", engine.Blocked, engine.BlockedStatus},
		{"failed", engine.Failed, engine.FailedStatus},
		{"converged", engine.Satisfied, engine.Converged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dag, err := engine.Admit([]engine.Declaration{{Key: b, Dependencies: []engine.Key{a}}, {Key: a}})
			if err != nil {
				t.Fatal(err)
			}
			state, err := dag.Start().Record(a, test.outcome)
			if err != nil {
				t.Fatal(err)
			}
			if test.outcome == engine.Satisfied {
				state, err = state.Record(b, engine.Satisfied)
				if err != nil {
					t.Fatal(err)
				}
			}
			if state.Status() != test.status {
				t.Fatalf("status = %s, want %s", state.Status(), test.status)
			}
		})
	}
}

func TestDAGKeyAdmission(t *testing.T) {
	for _, value := range []string{"", " x", "x ", "a\nb", strings.Repeat("x", 256), string([]byte{0xff})} {
		if key, err := engine.NewKey(value); err == nil || key != (engine.Key{}) {
			t.Fatalf("NewKey(%q) = %#v, %v", value, key, err)
		}
	}
	if got := key(t, "service:systemd:dbus:system").String(); got != "service:systemd:dbus:system" {
		t.Fatalf("key = %q", got)
	}
}

func TestDAGDeclarationOrderDoesNotChangeSchedule(t *testing.T) {
	a, b, c := key(t, "a"), key(t, "b"), key(t, "c")
	orders := [][]engine.Declaration{
		{{Key: c}, {Key: a}, {Key: b}},
		{{Key: b}, {Key: c}, {Key: a}},
	}
	for _, declarations := range orders {
		dag, err := engine.Admit(declarations)
		if err != nil {
			t.Fatal(err)
		}
		state := dag.Start()
		var got []string
		for {
			offer, ok := state.Next()
			if !ok {
				break
			}
			got = append(got, offer.String())
			state, err = state.Record(offer, engine.Satisfied)
			if err != nil {
				t.Fatal(err)
			}
		}
		if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("schedule = %v, want %v", got, want)
		}
	}
}

func FuzzAdmit(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2})
	f.Add([]byte{1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128 {
			data = data[:128]
		}
		declarations := make([]engine.Declaration, len(data))
		keys := make([]engine.Key, len(data))
		for index := range data {
			keys[index] = key(t, fmt.Sprintf("op:%03d", index))
		}
		for index, value := range data {
			declarations[index].Key = keys[index]
			if len(keys) != 0 && value&1 != 0 {
				declarations[index].Dependencies = []engine.Key{keys[int(value)%len(keys)]}
			}
		}
		dag, err := engine.Admit(declarations)
		if err != nil {
			if dag != (engine.DAG{}) {
				t.Fatal("failed admission returned nonzero DAG")
			}
			return
		}
		state := dag.Start()
		steps := 0
		for {
			offer, ok := state.Next()
			if !ok {
				break
			}
			state, err = state.Record(offer, engine.Satisfied)
			if err != nil {
				t.Fatal(err)
			}
			steps++
			if steps > len(data) {
				t.Fatal("schedule did not terminate")
			}
		}
		if state.Status() != engine.Converged {
			t.Fatalf("terminal status = %s", state.Status())
		}
	})
}
