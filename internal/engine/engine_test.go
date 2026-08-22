package engine_test

import (
	"fmt"
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

func TestDAGRejectsInvalidGraphsAtomically(t *testing.T) {
	a, b := key(t, "a"), key(t, "b")
	for _, declarations := range [][]engine.Declaration{
		nil, {{}}, {{Key: a}, {Key: a}},
		{{Key: a}, {Key: b, Dependencies: []engine.Key{a, a}}},
		{{Key: a}, {Key: b, Dependencies: []engine.Key{b}}},
		{{Key: a, Dependencies: []engine.Key{a}}},
		{{Key: a, Dependencies: []engine.Key{b}}, {Key: b, Dependencies: []engine.Key{a}}},
	} {
		if dag, err := engine.Admit(declarations); err == nil || dag != (engine.DAG{}) {
			t.Fatalf("Admit = %#v, %v", dag, err)
		}
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
		run, initial, err := engine.Begin(dag, digest(t))
		if err != nil {
			t.Fatal(err)
		}
		checkpoint, err := run.Commit(initial)
		if err != nil {
			t.Fatal(err)
		}
		steps := 0
		for offer, ok := checkpoint.Next(); ok; offer, ok = checkpoint.Next() {
			candidate, recordErr := checkpoint.Record(offer, engine.Satisfied, "")
			if recordErr != nil {
				t.Fatal(recordErr)
			}
			checkpoint, err = run.Commit(candidate)
			if err != nil {
				t.Fatal(err)
			}
			steps++
			if steps > len(data) {
				t.Fatal("schedule did not terminate")
			}
		}
		if checkpoint.Status() != engine.Converged {
			t.Fatalf("terminal status = %s", checkpoint.Status())
		}
	})
}
