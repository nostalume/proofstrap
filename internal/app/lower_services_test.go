package app

import "testing"

func TestServiceOperationIdentityIncludesBackendAndPrincipal(t *testing.T) {
	systemd := serviceOperationBase("systemd", "agent", "")
	openrc := serviceOperationBase("openrc", "agent", "")
	user := serviceOperationBase("systemd", "agent", "alice")
	if systemd != "service:systemd:system:agent" || openrc != "service:openrc:system:agent" || user != "service:systemd:user:alice:agent" {
		t.Fatalf("service identities = %q, %q, %q", systemd, openrc, user)
	}
	if systemd == openrc {
		t.Fatal("same-name services collided across backends")
	}
}
