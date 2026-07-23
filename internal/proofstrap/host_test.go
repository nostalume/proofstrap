package proofstrap

import (
	"reflect"
	"testing"
)

func TestObserveHostPreservesIdentityWithoutDispatch(t *testing.T) {
	tests := []struct {
		name, osRelease, pid1 string
		wantFacts             HostFacts
		wantBlocker           string
	}{
		{name: "exact", osRelease: "ID=opensuse-tumbleweed\n", pid1: "systemd\n", wantFacts: HostFacts{ID: "opensuse-tumbleweed", PID1: "systemd"}},
		{name: "unknown derivative remains evidence", osRelease: "ID=nobara\nVERSION_ID=42\nID_LIKE=\"rhel fedora fedora\"\n", pid1: "systemd\n", wantFacts: HostFacts{ID: "nobara", Version: "42", Like: []string{"fedora", "rhel"}, PID1: "systemd"}},
		{name: "ambiguous family is not host policy", osRelease: "ID=custom\nID_LIKE=\"arch fedora\"\n", pid1: "systemd\n", wantFacts: HostFacts{ID: "custom", Like: []string{"arch", "fedora"}, PID1: "systemd"}},
		{name: "other service manager is preserved", osRelease: "ID=alpine\n", pid1: "openrc\n", wantFacts: HostFacts{ID: "alpine", PID1: "openrc"}},
		{name: "empty ID blocks", osRelease: "VERSION_ID=1\n", pid1: "systemd\n", wantFacts: HostFacts{Version: "1", PID1: "systemd"}, wantBlocker: "host:identity"},
		{name: "empty PID 1 blocks", osRelease: "ID=custom\n", pid1: "\n", wantFacts: HostFacts{ID: "custom"}, wantBlocker: "service-manager"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{files: map[string][]byte{"/etc/os-release": []byte(test.osRelease), "/proc/1/comm": []byte(test.pid1)}}
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

func firstBlocker(blockers []Blocker) string {
	if len(blockers) == 0 {
		return ""
	}
	return blockers[0].Subject
}
