package proofstrap

import "testing"

func TestInspectAccessUsesNoUpdateSudoValidation(t *testing.T) {
	runner := &testRunner{
		paths:   map[string]string{"sudo": "/usr/bin/sudo"},
		results: map[string][]Result{"/usr/bin/sudo -N -n -v": {{ExitCode: 0}}},
	}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	access, ok := observed.(sudoAccess)
	if !ok || access.path != "/usr/bin/sudo" || detail != "sudo noninteractive: /usr/bin/sudo" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "/usr/bin/sudo -N -n -v" {
		t.Fatalf("calls=%#v", runner.calls)
	}
}

func TestInspectAccessClassifiesUnsupportedSudoNoUpdateProbe(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"sudo": "/usr/bin/sudo", "doas": "/usr/bin/doas", "true": "/home/operator/bin/true"},
		results: map[string][]Result{
			"/usr/bin/sudo -N -n -v":         {{ExitCode: 1, Stderr: "sudo: contraseña requerida"}},
			"/usr/bin/sudo -N -V":            {{ExitCode: 1, Stderr: "sudo: opción desconocida"}},
			"/usr/bin/doas -n /usr/bin/true": {{ExitCode: 0}},
		},
	}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	if _, ok := observed.(sudoNoUpdateProbeUnsupported); !ok || detail != "sudo no-update validation is unsupported: sudo: opción desconocida" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
	if len(runner.calls) != 2 || runner.calls[0] != "/usr/bin/sudo -N -n -v" || runner.calls[1] != "/usr/bin/sudo -N -V" {
		t.Fatalf("unsupported sudo fell back to another authority: calls=%#v", runner.calls)
	}
}

func TestInspectAccessReportsExternalSudoAuthentication(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"sudo": "/usr/bin/sudo"},
		results: map[string][]Result{
			"/usr/bin/sudo -N -n -v": {{ExitCode: 1, Stderr: "sudo: a password is required"}},
			"/usr/bin/sudo -N -V":    {{ExitCode: 0, Stdout: "Sudo version 1.9.17p2"}},
		},
	}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	if _, ok := observed.(sudoAuthenticationUnavailable); !ok || detail != "sudo authentication is unavailable noninteractively: sudo: a password is required; authenticate externally with /usr/bin/sudo -v, then rerun plan" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
	if len(runner.calls) != 2 || runner.calls[1] != "/usr/bin/sudo -N -V" {
		t.Fatalf("failed sudo validation did not prove no-update support: calls=%#v", runner.calls)
	}
}

func TestInspectAccessAdmitsOnlyNopassDoas(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"doas": "/usr/bin/doas", "true": "/home/operator/bin/true"},
		results: map[string][]Result{
			"/usr/bin/doas -n /usr/bin/true": {{ExitCode: 0}},
		},
	}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	access, ok := observed.(doasAccess)
	if !ok || access.path != "/usr/bin/doas" || detail != "doas nopass: /usr/bin/doas" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
	if containsString(runner.pathCalls, "true") {
		t.Fatalf("doas probe resolved true through caller PATH: pathCalls=%#v", runner.pathCalls)
	}
}

func TestInspectAccessRejectsInteractiveDoasPolicy(t *testing.T) {
	runner := &testRunner{
		paths: map[string]string{"doas": "/usr/bin/doas", "true": "/home/operator/bin/true"},
		results: map[string][]Result{
			"/usr/bin/doas -n /usr/bin/true": {{ExitCode: 1, Stderr: "Authentication required"}},
		},
	}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	if _, ok := observed.(doasNopassUnavailable); !ok || detail != "doas requires a matching nopass rule: Authentication required" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
}

func TestInspectAccessDoesNotResolveSu(t *testing.T) {
	runner := &testRunner{}
	observed, detail := inspectAccessFor(userPrincipal{uid: 1000}, runner)
	if _, ok := observed.(noPrivilege); !ok || detail != "no root, sudo, or doas privilege available" {
		t.Fatalf("access=%#v detail=%q", observed, detail)
	}
	if containsString(runner.pathCalls, "su") {
		t.Fatalf("authority observation resolved interactive su: pathCalls=%#v", runner.pathCalls)
	}
}
