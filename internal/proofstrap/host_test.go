package proofstrap

import (
	"reflect"
	"testing"
)

func TestObserveHostPreservesIdentityWithoutDispatch(t *testing.T) {
	tests := []struct {
		name, osRelease string
		wantFacts       HostFacts
		wantBlocker     string
	}{
		{name: "exact", osRelease: "ID=opensuse-tumbleweed\n", wantFacts: HostFacts{ID: "opensuse-tumbleweed"}},
		{name: "unknown derivative remains evidence", osRelease: "ID=nobara\nVERSION_ID=42\nID_LIKE=\"rhel fedora fedora\"\n", wantFacts: HostFacts{ID: "nobara", Version: "42", Like: []string{"fedora", "rhel"}}},
		{name: "ambiguous family is not host policy", osRelease: "ID=custom\nID_LIKE=\"arch fedora\"\n", wantFacts: HostFacts{ID: "custom", Like: []string{"arch", "fedora"}}},
		{name: "empty ID blocks", osRelease: "VERSION_ID=1\n", wantFacts: HostFacts{Version: "1"}, wantBlocker: "host:identity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{files: map[string][]byte{"/etc/os-release": []byte(test.osRelease)}}
			inspection := observeHost(runner)
			if !reflect.DeepEqual(inspection.facts, test.wantFacts) {
				t.Fatalf("facts = %#v, want %#v", inspection.facts, test.wantFacts)
			}
			if len(runner.pathCalls) != 0 {
				t.Fatalf("host inspection performed LookPath: %#v", runner.pathCalls)
			}
			if got := firstBlocker(inspection.blockers); got != test.wantBlocker {
				t.Fatalf("blocker = %q, want %q; blockers = %#v", got, test.wantBlocker, inspection.blockers)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("host inspection ran commands: %#v", runner.calls)
			}
		})
	}
}

func TestObservePID1RequiresOneNonemptyName(t *testing.T) {
	for _, test := range []struct {
		name, contents string
		want           string
		wantErr        bool
	}{
		{name: "systemd", contents: "systemd\n", want: "systemd"},
		{name: "other manager", contents: "openrc\n", want: "openrc"},
		{name: "empty", contents: "\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pid1, err := observePID1(&testRunner{files: map[string][]byte{"/proc/1/comm": []byte(test.contents)}})
			if test.wantErr {
				if err == nil {
					t.Fatalf("PID 1 %q was admitted", test.contents)
				}
				return
			}
			if err != nil || pid1 != test.want {
				t.Fatalf("pid1=%q err=%v", pid1, err)
			}
		})
	}
}

func firstBlocker(blockers []Blocker) string {
	if len(blockers) == 0 {
		return ""
	}
	return blockers[0].Subject
}
