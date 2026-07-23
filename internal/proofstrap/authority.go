package proofstrap

import (
	"context"
	"fmt"
	"strings"
)

const doasProbeCommand = "/usr/bin/true"

//sumtype:decl
type principal interface{ principal() }
type userPrincipal struct{ uid uint32 }
type rootPrincipal struct{}
type unknownPrincipal struct{ detail string }

func (userPrincipal) principal()    {}
func (rootPrincipal) principal()    {}
func (unknownPrincipal) principal() {}

//sumtype:decl
type access interface{ access() }
type rootAccess struct{}
type sudoAccess struct{ path string }
type doasAccess struct{ path string }
type sudoAuthenticationUnavailable struct{ path, detail string }
type sudoNoUpdateProbeUnsupported struct{ path, detail string }
type doasNopassUnavailable struct{ path, detail string }
type noPrivilege struct{ detail string }
type unknownAccess struct{ detail string }

func (rootAccess) access()                    {}
func (sudoAccess) access()                    {}
func (doasAccess) access()                    {}
func (sudoAuthenticationUnavailable) access() {}
func (sudoNoUpdateProbeUnsupported) access()  {}
func (doasNopassUnavailable) access()         {}
func (noPrivilege) access()                   {}
func (unknownAccess) access()                 {}

type authority struct {
	principal principal
	access    access
}

//sumtype:decl
type runtimeAdmission interface{ runtimeAdmission() }
type runtimeAdmitted struct{ detail string }
type runtimeDenied struct{ detail string }
type runtimeIndeterminate struct{ detail string }

func (runtimeAdmitted) runtimeAdmission()      {}
func (runtimeDenied) runtimeAdmission()        {}
func (runtimeIndeterminate) runtimeAdmission() {}

func inspectAuthority(runner Runner) (authority, []Fact) {
	uid, uidErr := runner.EffectiveUID()
	principal, principalDetail := classifyPrincipal(uid, uidErr)
	return authority{principal: principal}, []Fact{{Subject: "authority:principal", Detail: principalDetail}}
}

func classifyPrincipal(uid uint32, err error) (principal, string) {
	if err != nil {
		return unknownPrincipal{detail: err.Error()}, err.Error()
	}
	if uid == 0 {
		return rootPrincipal{}, "effective uid 0"
	}
	return userPrincipal{uid: uid}, fmt.Sprintf("effective uid %d", uid)
}

func inspectAccessFor(principal principal, runner Runner) (access, string) {
	if _, ok := principal.(rootPrincipal); ok {
		return rootAccess{}, "root"
	}
	var deferred access
	deferredDetail := ""
	if path, err := runner.LookPath("sudo"); err == nil {
		result := runner.Run(context.Background(), Command{Name: path, Args: []string{"-N", "-n", "-v"}})
		if result.ExitCode == 0 {
			return sudoAccess{path: path}, "sudo noninteractive: " + path
		}
		detail := nonempty(result.Stderr, result.Err)
		capability := runner.Run(context.Background(), Command{Name: path, Args: []string{"-N", "-V"}})
		if capability.ExitCode != 0 {
			deferredDetail = "sudo no-update validation is unsupported: " + nonempty(capability.Stderr, capability.Err)
			return sudoNoUpdateProbeUnsupported{path: path, detail: deferredDetail}, deferredDetail
		}
		deferredDetail = "sudo authentication is unavailable noninteractively: " + detail + "; authenticate externally with " + path + " -v, then rerun plan"
		deferred = sudoAuthenticationUnavailable{path: path, detail: deferredDetail}
	}
	if path, err := runner.LookPath("doas"); err == nil {
		result := runner.Run(context.Background(), Command{Name: path, Args: []string{"-n", doasProbeCommand}})
		if result.ExitCode == 0 {
			return doasAccess{path: path}, "doas nopass: " + path
		}
		if deferred == nil {
			detail := nonempty(result.Stderr, result.Err)
			deferredDetail = "doas requires a matching nopass rule: " + detail
			deferred = doasNopassUnavailable{path: path, detail: deferredDetail}
		}
	}
	if deferred != nil {
		return deferred, deferredDetail
	}
	detail := "no root, sudo, or doas privilege available"
	return noPrivilege{detail: detail}, detail
}

func (authority authority) runtimeAdmission(runner Runner, userEffect, needsManager bool, managerPath string) runtimeAdmission {
	if !userEffect {
		return runtimeAdmitted{}
	}
	switch principal := authority.principal.(type) {
	case rootPrincipal:
		return runtimeDenied{detail: "user service effects require running Proofstrap as the desktop user"}
	case unknownPrincipal:
		return runtimeIndeterminate{detail: principal.detail}
	case userPrincipal:
		if !needsManager {
			return runtimeAdmitted{}
		}
		if managerPath == "" {
			return runtimeIndeterminate{detail: "service-manager executable authority is unavailable"}
		}
		result := runner.Run(context.Background(), Command{Name: managerPath, Args: []string{"--user", "show-environment"}})
		if result.Err == nil && result.ExitCode == 0 {
			return runtimeAdmitted{detail: fmt.Sprintf("user manager reachable for uid %d", principal.uid)}
		}
		detail := nonempty(result.Stderr, result.Err)
		lower := strings.ToLower(detail)
		if strings.Contains(lower, "failed to connect") || strings.Contains(lower, "bus") || strings.Contains(lower, "no medium found") || strings.Contains(lower, "no such file") {
			return runtimeDenied{detail: detail}
		}
		return runtimeIndeterminate{detail: detail}
	default:
		return runtimeIndeterminate{detail: "unhandled principal variant"}
	}
}

func nonempty(stderr string, err error) string {
	if strings.TrimSpace(stderr) != "" {
		return strings.TrimSpace(stderr)
	}
	if err != nil {
		return err.Error()
	}
	return "unknown"
}

func (value authority) command(step step) (Command, error) {
	command := Command{Name: step.command.Name, Args: append([]string(nil), step.command.Args...), stdin: step.command.stdin, timeout: step.command.timeout}
	if step.access == directStep {
		if _, ok := value.principal.(userPrincipal); !ok {
			return Command{}, fmt.Errorf("user service requires desktop user")
		}
		return command, nil
	}
	switch access := value.access.(type) {
	case rootAccess:
		return command, nil
	case sudoAccess:
		return Command{Name: access.path, Args: append([]string{"-N", "-n", command.Name}, command.Args...), stdin: command.stdin, timeout: command.timeout}, nil
	case doasAccess:
		return Command{Name: access.path, Args: append([]string{"-n", command.Name}, command.Args...), stdin: command.stdin, timeout: command.timeout}, nil
	default:
		return Command{}, fmt.Errorf("noninteractive root access is unavailable")
	}
}

func (value authority) rootCommand(command Command) (Command, error) {
	return value.command(step{command: command, access: rootStep})
}
