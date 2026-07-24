package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/proofstrap"
)

func TestRunCreateHomeLeafUsesTypedCreateExclusiveOperation(t *testing.T) {
	runner := &cliRunner{}
	previous := runnerFactory
	runnerFactory = func() proofstrap.Runner { return runner }
	t.Cleanup(func() { runnerFactory = previous })
	var stdout, stderr bytes.Buffer
	code := run([]string{"_create-home", "--uid", "1000", "--gid", "1000", "--mode", "0700", "--", "/home/alice"}, &stdout, &stderr)
	want := proofstrap.HomeCreation{Path: "/home/alice", Mode: 0o700, UID: 1000, GID: 1000}
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 || len(runner.homeCreations) != 1 || runner.homeCreations[0] != want {
		t.Fatalf("code=%d stdout=%q stderr=%q creations=%#v", code, stdout.String(), stderr.String(), runner.homeCreations)
	}
}

func TestRunPlanUsesLiveEvidenceAndRendersActions(t *testing.T) {
	t.Run("package plan", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, planRunner(), "plan", "sway")
		if code != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		for _, want := range []string{
			"Host OS ID: opensuse-tumbleweed",
			"Host OS version:",
			"Host OS ID like: []",
			"Host PID 1: systemd",
			"Fact package-manager: zypper",
			"Change package-install:zypper: install=dbus-1,grim,libwayland-client0,slurp,sway,swayidle,swaylock",
			"Command package-install:zypper: /usr/bin/sudo -N -n /usr/bin/zypper --non-interactive install --no-recommends dbus-1 grim libwayland-client0 slurp sway swayidle swaylock",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout = %q, missing %q", stdout, want)
			}
		}
	})
	t.Run("service plan", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, planRunner(), "plan", "network")
		if code != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		for _, want := range []string{
			"Change services:system:enable: enable NetworkManager.service",
			"Change services:system:start: start NetworkManager.service",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout = %q, missing %q", stdout, want)
			}
		}
	})
}

func TestRunModulesIsSortedAndDoesNotCreateRunner(t *testing.T) {
	previous := runnerFactory
	runnerFactory = func() proofstrap.Runner {
		t.Fatal("modules created a host runner")
		return nil
	}
	t.Cleanup(func() { runnerFactory = previous })
	var stdout, stderr bytes.Buffer
	code := run([]string{"modules"}, &stdout, &stderr)
	want := "audio\ncurl\ndbus\ngit\nhyprland\nnetwork\npavucontrol\nqpwgraph\nsway\nvim\nwayland\nwl-paste\nxclip\nxsel\n"
	if code != 0 || stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunModulesRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"modules", "dbus"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: proofstrap modules") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunModulesReportsOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"modules"}, failingWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "modules output:") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunPlanConfigAndArguments(t *testing.T) {
	t.Run("explicit config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proofstrap.toml")
		if err := os.WriteFile(path, []byte("modules = [\"sway\"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCLI(t, planRunner(), "plan", "--config", path)
		if code != 0 || !strings.Contains(stdout, "Plan modules: [dbus sway wayland]") || !strings.Contains(stdout, "Change package-install:zypper") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("flags precede modules", func(t *testing.T) {
		code, _, stderr := runCLI(t, planRunner(), "plan", "sway", "--config", "x")
		if code != 2 || !strings.Contains(stderr, "flags must appear before module IDs") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
	t.Run("explicit config and modules are mutually exclusive", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proofstrap.toml")
		if err := os.WriteFile(path, []byte("modules = [\"sway\"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, planRunner(), "plan", "--config", path, "sway")
		if code != 2 || !strings.Contains(stderr, "cannot combine --config with module IDs") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
}

func TestRequestedStateAcceptsAccountOnlyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte("[account]\nstate = \"existing\"\nname = \"alice\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, code, err := requestedState(nil, path)
	if err != nil || code != 0 || state.Empty() {
		t.Fatalf("state=%#v code=%d err=%v", state, code, err)
	}
}

func TestRunPlanRendersAccountOnlyIdentification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte("[account]\nstate = \"existing\"\nname = \"alice\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := zypperRunner(1000)
	runner.paths["getent"] = "/usr/bin/getent"
	entry := proofstrap.Result{Stdout: "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"}
	for _, command := range []string{
		"/usr/bin/getent passwd alice",
		"/usr/bin/getent -s files passwd alice",
		"/usr/bin/getent passwd 1000",
		"/usr/bin/getent -s files passwd 1000",
	} {
		runner.results[command] = []proofstrap.Result{entry}
	}
	code, stdout, stderr := runCLI(t, runner, "plan", "--config", path)
	if code != 0 || !strings.Contains(stdout, "Plan account: existing name=alice") || !strings.Contains(stdout, "Fact account:alice: local and NSS identity agree") || strings.Contains(stdout, "Change ") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunPlanRendersHostnameOnlyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte("[host]\nhostname = \"node-1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := zypperRunner(0)
	runner.files["/etc/hostname"] = []byte("old\n")
	runner.files["/proc/sys/kernel/hostname"] = []byte("old\n")
	runner.paths["hostnamectl"] = "/usr/bin/hostnamectl"
	code, stdout, stderr := runCLI(t, runner, "plan", "--config", path)
	wantCommand := "Command hostname: /usr/bin/hostnamectl --no-ask-password --static --transient set-hostname node-1"
	if code != 0 || !strings.Contains(stdout, "Plan hostname: node-1\n") || !strings.Contains(stdout, wantCommand) || !strings.Contains(stdout, "Plan digest: sha256:") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("hostname-only root plan ran a command: %#v", runner.calls)
	}
}

func TestRenderPlanEscapesAccountReviewControlCharacters(t *testing.T) {
	plan := proofstrap.ReviewPlan{
		Account: proofstrap.PresentAccountReview{State: "present", Name: "alice", UID: 1000, Shell: "/bin/bash\nBlocker forged: detail", PrimaryGroup: "alice", PrimaryGID: 1000, Home: "/home/alice\nPlan digest: forged", HomeMode: "0700"},
		Host:    proofstrap.HostFacts{PID1: "systemd\nChange forged: detail"},
		Facts:   []proofstrap.Fact{{Subject: "account:alice", Detail: "home=/home/alice\nBlocker forged: detail"}},
	}
	var rendered bytes.Buffer
	if err := renderPlan(&rendered, plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.String(), "\nBlocker forged:") || strings.Contains(rendered.String(), "\nPlan digest: forged") || strings.Contains(rendered.String(), "\nChange forged:") || !strings.Contains(rendered.String(), `\nBlocker forged`) || !strings.Contains(rendered.String(), `\nChange forged`) {
		t.Fatalf("unsafe rendering: %q", rendered.String())
	}
}

func TestRenderPlanShowsDigestBoundHostnameIntent(t *testing.T) {
	plan := proofstrap.ReviewPlan{
		HostSettings: &proofstrap.HostSettingsReview{Hostname: "node-1"},
		Host:         proofstrap.HostFacts{ID: "test", PID1: "systemd"},
	}
	var rendered bytes.Buffer
	if err := renderPlan(&rendered, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "Plan hostname: node-1\n") {
		t.Fatalf("hostname intent is hidden: %q", rendered.String())
	}
}

func TestRenderPlanShowsDigestBoundTimezoneIntent(t *testing.T) {
	plan := proofstrap.ReviewPlan{
		HostSettings: &proofstrap.HostSettingsReview{Timezone: "Europe/Berlin"},
		Host:         proofstrap.HostFacts{ID: "test", PID1: "systemd"},
	}
	var rendered bytes.Buffer
	if err := renderPlan(&rendered, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "Plan timezone: Europe/Berlin\n") || strings.Contains(rendered.String(), "Plan hostname:") {
		t.Fatalf("timezone intent is hidden or hostname is fabricated: %q", rendered.String())
	}
}

func TestRunPlanRejectsAuthorizeFlagBeforeCreatingRunner(t *testing.T) {
	previous := runnerFactory
	runnerFactory = func() proofstrap.Runner {
		t.Fatal("rejected plan flag created a host runner")
		return nil
	}
	t.Cleanup(func() { runnerFactory = previous })
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--authorize", "sway"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined: -authorize") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunApplyRejectsAuthorizeFlag(t *testing.T) {
	code, stdout, stderr := runCLI(t, networkRunner(), "apply", "--authorize", "network")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "flag provided but not defined: -authorize") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunPlanReportsOutputFailure(t *testing.T) {
	old := runnerFactory
	runnerFactory = func() proofstrap.Runner { return audioPlanRunner(1000) }
	t.Cleanup(func() { runnerFactory = old })
	var stderr bytes.Buffer
	if code := run([]string{"plan", "audio"}, failingWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "plan output:") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunPlanReportsBehaviorAndRuntimeBlockers(t *testing.T) {
	t.Run("unknown OS is blocked only without a native package behavior", func(t *testing.T) {
		runner := &cliRunner{files: map[string][]byte{"/etc/os-release": []byte("ID=alpine\n"), "/proc/1/comm": []byte("systemd\n")}}
		code, stdout, _ := runCLI(t, runner, "plan", "sway")
		if code != 1 || !strings.Contains(stdout, "Blocker package-manager") {
			t.Fatalf("code=%d stdout=%q", code, stdout)
		}
	})
	t.Run("invalid module precedes host admission", func(t *testing.T) {
		runner := &cliRunner{files: map[string][]byte{"/etc/os-release": []byte("ID=alpine\n"), "/proc/1/comm": []byte("systemd\n")}}
		code, stdout, stderr := runCLI(t, runner, "plan", "typo")
		if code != 1 || !strings.Contains(stdout, "unknown module") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("root cannot be the explicit user-service target", func(t *testing.T) {
		runner := audioPlanRunner(0)
		code, stdout, stderr := runCLI(t, runner, "plan", "--config", audioConfig(t))
		if code != 1 || !strings.Contains(stdout, "Blocker account:target: user-service target must be non-root") || callIndex(runner.calls, "/usr/bin/systemctl --user show-environment") >= 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q calls=%#v", code, stdout, stderr, runner.calls)
		}
	})
}

func TestRunApplyRequiresDigestAndExecutesVerifiedSystemPlan(t *testing.T) {
	code, stdout, stderr := runCLI(t, networkRunner(), "apply", "network")
	if code != 2 || !strings.Contains(stderr, "--accept") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = runCLI(t, networkRunner(), "plan", "network")
	if code != 0 {
		t.Fatalf("plan code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	digest := planDigest(t, stdout)
	apply := networkRunner()
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	code, stdout, stderr = runCLI(t, apply, "apply", "--accept", digest, "--receipt", receiptPath, "network")
	if code != 0 || !strings.Contains(stdout, `"status": "succeeded"`) {
		t.Fatalf("apply code=%d stdout=%q stderr=%q calls=%#v", code, stdout, stderr, apply.calls)
	}
	var stdoutReceipt proofstrap.ApplyReceipt
	if err := json.Unmarshal([]byte(stdout), &stdoutReceipt); err != nil || stdoutReceipt.Status != proofstrap.Succeeded {
		t.Fatalf("stdout receipt=%#v err=%v output=%q", stdoutReceipt, err, stdout)
	}
	encoded, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != stdout {
		t.Fatalf("receipt file differs from stdout: file=%q stdout=%q", encoded, stdout)
	}
	info, err := os.Stat(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode=%v", info.Mode().Perm())
	}
	var receipt proofstrap.ApplyReceipt
	if err := json.Unmarshal(encoded, &receipt); err != nil {
		t.Fatalf("receipt JSON: %v\n%s", err, encoded)
	}
	wantOutcomes := []string{"services:system:enable", "services:system:start"}
	if receipt.PlanDigest != digest || receipt.Status != proofstrap.Succeeded || len(receipt.Outcomes) != len(wantOutcomes) {
		t.Fatalf("receipt = %#v", receipt)
	}
	for index, want := range wantOutcomes {
		if receipt.Outcomes[index].Action != want || receipt.Outcomes[index].Status != proofstrap.Applied {
			t.Errorf("outcome[%d] = %#v, want applied %q", index, receipt.Outcomes[index], want)
		}
	}
	for _, want := range []string{
		"/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service",
		"/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service",
	} {
		if callIndex(apply.calls, want) < 0 {
			t.Errorf("calls = %#v, missing %q", apply.calls, want)
		}
	}
}

func TestRunApplyRestrictsExistingReceiptFile(t *testing.T) {
	digest := planDigestForRunner(t, networkRunner(), "network")
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("old", 10_000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, networkRunner(), "apply", "--accept", digest, "--receipt", path, "network")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if code != 0 || err != nil || info.Mode().Perm() != 0o600 || string(encoded) != stdout {
		t.Fatalf("code=%d mode=%v err=%v file=%q stdout=%q stderr=%q", code, info.Mode().Perm(), err, encoded, stdout, stderr)
	}
}

func TestRunApplyRejectsSymlinkReceiptWithoutChangingTarget(t *testing.T) {
	digest := planDigestForRunner(t, networkRunner(), "network")
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, networkRunner(), "apply", "--accept", digest, "--receipt", link, "network")
	encoded, err := os.ReadFile(target)
	if code != 1 || err != nil || string(encoded) != "preserve" || !strings.Contains(stderr, "receipt error:") || !json.Valid([]byte(stdout)) {
		t.Fatalf("code=%d target=%q err=%v stdout=%q stderr=%q", code, encoded, err, stdout, stderr)
	}
}

func TestRunApplyEmitsJSONBeforeReceiptWriteFailure(t *testing.T) {
	digest := planDigestForRunner(t, networkRunner(), "network")
	code, stdout, stderr := runCLI(t, networkRunner(), "apply", "--accept", digest, "--receipt", t.TempDir(), "network")
	if code != 1 || !json.Valid([]byte(stdout)) || !strings.Contains(stderr, "receipt error:") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunApplyStopsBeforeReceiptFileWhenStdoutFails(t *testing.T) {
	digest := planDigestForRunner(t, networkRunner(), "network")
	path := filepath.Join(t.TempDir(), "receipt.json")
	old := runnerFactory
	runnerFactory = func() proofstrap.Runner { return networkRunner() }
	t.Cleanup(func() { runnerFactory = old })
	var stderr bytes.Buffer
	code := run([]string{"apply", "--accept", digest, "--receipt", path, "network"}, failingWriter{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "receipt error:") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("receipt file was written after stdout failure: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken output") }

func TestRunApplyEmitsJSONReceiptForBlockedPlan(t *testing.T) {
	code, planOutput, stderr := runCLI(t, planRunner(), "plan", "unknown")
	if code != 1 {
		t.Fatalf("plan code=%d stdout=%q stderr=%q", code, planOutput, stderr)
	}
	code, stdout, stderr := runCLI(t, planRunner(), "apply", "--accept", planDigest(t, planOutput), "unknown")
	var receipt proofstrap.ApplyReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || code != 1 || receipt.Status != proofstrap.Blocked {
		t.Fatalf("code=%d receipt=%#v err=%v stdout=%q stderr=%q", code, receipt, err, stdout, stderr)
	}
}

func TestRunApplyExitAndJSONForStaleAndFailedReceipts(t *testing.T) {
	failedDigest := planDigestForRunner(t, networkRunner(), "network")
	for _, test := range []struct {
		name   string
		runner *cliRunner
		digest string
		status proofstrap.RunStatus
	}{
		{name: "stale", runner: networkRunner(), digest: "sha256:wrong", status: proofstrap.Stale},
		{name: "failed", runner: failedNetworkRunner(), digest: failedDigest, status: proofstrap.Failed},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, test.runner, "apply", "--accept", test.digest, "network")
			var receipt proofstrap.ApplyReceipt
			if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || code != 1 || receipt.Status != test.status || stderr != "" {
				t.Fatalf("code=%d receipt=%#v err=%v stdout=%q stderr=%q", code, receipt, err, stdout, stderr)
			}
		})
	}
}

func TestRunApplyTreatsVerifiedPackageProgressAsSuccess(t *testing.T) {
	code, planOutput, stderr := runCLI(t, planRunner(), "plan", "sway")
	if code != 0 {
		t.Fatalf("plan code=%d stdout=%q stderr=%q", code, planOutput, stderr)
	}
	apply := packageApplyRunner()
	code, stdout, stderr := runCLI(t, apply, "apply", "--accept", planDigest(t, planOutput), "sway")
	var receipt proofstrap.ApplyReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || code != 0 || receipt.Status != proofstrap.ReplanRequired {
		t.Fatalf("code=%d receipt=%#v err=%v stdout=%q stderr=%q calls=%#v", code, receipt, err, stdout, stderr, apply.calls)
	}
	if callIndex(apply.calls, "/usr/bin/systemctl is-enabled NetworkManager.service") >= 0 {
		t.Fatalf("package progress crossed the service barrier: %#v", apply.calls)
	}
}

func TestRunApplyChecksUserManagerBeforeUserMutation(t *testing.T) {
	config := audioConfig(t)
	code, stdout, stderr := runCLI(t, audioApplyRunner(), "plan", "--config", config)
	if code != 0 {
		t.Fatalf("plan code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	apply := audioApplyRunner()
	code, stdout, stderr = runCLI(t, apply, "apply", "--accept", planDigest(t, stdout), "--config", config)
	if code != 0 {
		t.Fatalf("apply code=%d stdout=%q stderr=%q calls=%#v", code, stdout, stderr, apply.calls)
	}
	manager := callIndex(apply.calls, "/usr/bin/systemctl --user show-environment")
	mutation := callIndex(apply.calls, "/usr/bin/systemctl --user enable pipewire.service wireplumber.service")
	if manager < 0 || mutation < 0 || manager >= mutation {
		t.Fatalf("manager check must precede mutation: %#v", apply.calls)
	}
}

func runCLI(t *testing.T, runner proofstrap.Runner, args ...string) (int, string, string) {
	t.Helper()
	old := runnerFactory
	runnerFactory = func() proofstrap.Runner { return runner }
	t.Cleanup(func() { runnerFactory = old })
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func planDigest(t *testing.T, output string) string {
	t.Helper()
	parts := strings.Split(output, "Plan digest: ")
	if len(parts) != 2 {
		t.Fatalf("plan output has no digest: %q", output)
	}
	return strings.TrimSpace(strings.Split(parts[1], "\n")[0])
}

func planDigestForRunner(t *testing.T, runner proofstrap.Runner, module string) string {
	t.Helper()
	code, output, stderr := runCLI(t, runner, "plan", module)
	if code != 0 {
		t.Fatalf("plan code=%d output=%q stderr=%q", code, output, stderr)
	}
	return planDigest(t, output)
}

func planRunner() *cliRunner {
	runner := zypperRunner(1000)
	runner.results[rpmInventoryCommand()] = []proofstrap.Result{{ExitCode: 0, Stdout: "NetworkManager\n"}}
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []proofstrap.Result{{ExitCode: 1, Stdout: "disabled\n"}}
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []proofstrap.Result{{ExitCode: 3, Stdout: "inactive\n"}}
	return runner
}

func networkRunner() *cliRunner {
	runner := zypperRunner(1000)
	runner.results[rpmInventoryCommand()] = []proofstrap.Result{{ExitCode: 0, Stdout: "NetworkManager\n"}, {ExitCode: 0, Stdout: "NetworkManager\n"}, {ExitCode: 0, Stdout: "NetworkManager\n"}}
	runner.results["/usr/bin/systemctl is-enabled NetworkManager.service"] = []proofstrap.Result{
		{ExitCode: 1, Stdout: "disabled\n"}, {ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 1, Stdout: "disabled\n"},
		{ExitCode: 0, Stdout: "enabled\n"}, {ExitCode: 0, Stdout: "enabled\n"},
	}
	runner.results["/usr/bin/systemctl is-active NetworkManager.service"] = []proofstrap.Result{
		{ExitCode: 3, Stdout: "inactive\n"}, {ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 3, Stdout: "inactive\n"},
		{ExitCode: 0, Stdout: "active\n"}, {ExitCode: 0, Stdout: "active\n"},
	}

	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service"] = []proofstrap.Result{{ExitCode: 0}}
	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl start NetworkManager.service"] = []proofstrap.Result{{ExitCode: 0}}
	return runner
}

func failedNetworkRunner() *cliRunner {
	runner := networkRunner()
	runner.results["/usr/bin/sudo -N -n /usr/bin/systemctl enable NetworkManager.service"] = []proofstrap.Result{{ExitCode: 1, Stderr: "denied"}}
	return runner
}

func packageApplyRunner() *cliRunner {
	runner := zypperRunner(1000)
	before := "NetworkManager\n"
	after := "NetworkManager\ndbus-1\ngrim\nlibwayland-client0\nslurp\nsway\nswayidle\nswaylock\n"
	runner.results[rpmInventoryCommand()] = []proofstrap.Result{
		{ExitCode: 0, Stdout: before},
		{ExitCode: 0, Stdout: before},
		{ExitCode: 0, Stdout: after},
	}
	runner.results["/usr/bin/sudo -N -n /usr/bin/zypper --non-interactive install --no-recommends dbus-1 grim libwayland-client0 slurp sway swayidle swaylock"] = []proofstrap.Result{{ExitCode: 0}}
	return runner
}

func audioPlanRunner(uid uint32) *cliRunner {
	runner := zypperRunner(uid)
	runner.results[rpmInventoryCommand()] = []proofstrap.Result{{ExitCode: 0, Stdout: "pipewire\nwireplumber\npipewire-pulseaudio\nalsa-utils\n"}}
	runner.results["/usr/bin/systemctl --user is-enabled pipewire.service wireplumber.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "enabled\nenabled\n"}}
	runner.results["/usr/bin/systemctl --user is-active pipewire.service wireplumber.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "active\nactive\n"}}
	runner.results["/usr/bin/systemctl --user show-environment"] = []proofstrap.Result{{ExitCode: 0}}
	return runner
}

func audioApplyRunner() *cliRunner {
	runner := zypperRunner(1000)
	runner.results[rpmInventoryCommand()] = []proofstrap.Result{{ExitCode: 0, Stdout: "pipewire\nwireplumber\npipewire-pulseaudio\nalsa-utils\n"}, {ExitCode: 0, Stdout: "pipewire\nwireplumber\npipewire-pulseaudio\nalsa-utils\n"}, {ExitCode: 0, Stdout: "pipewire\nwireplumber\npipewire-pulseaudio\nalsa-utils\n"}}
	runner.results["/usr/bin/systemctl --user is-enabled pipewire.service wireplumber.service"] = []proofstrap.Result{
		{ExitCode: 1, Stdout: "disabled\ndisabled\n"}, {ExitCode: 1, Stdout: "disabled\ndisabled\n"},
		{ExitCode: 1, Stdout: "disabled\ndisabled\n"},
		{ExitCode: 0, Stdout: "enabled\nenabled\n"},
	}
	runner.results["/usr/bin/systemctl --user is-active pipewire.service wireplumber.service"] = []proofstrap.Result{
		{ExitCode: 3, Stdout: "inactive\ninactive\n"}, {ExitCode: 3, Stdout: "inactive\ninactive\n"},
		{ExitCode: 3, Stdout: "inactive\ninactive\n"},
		{ExitCode: 0, Stdout: "active\nactive\n"},
	}
	runner.results["/usr/bin/systemctl --user is-enabled pipewire.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "enabled\n"}}
	runner.results["/usr/bin/systemctl --user is-enabled wireplumber.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "enabled\n"}}
	runner.results["/usr/bin/systemctl --user is-active pipewire.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "active\n"}}
	runner.results["/usr/bin/systemctl --user is-active wireplumber.service"] = []proofstrap.Result{{ExitCode: 0, Stdout: "active\n"}}
	runner.results["/usr/bin/systemctl --user show-environment"] = []proofstrap.Result{{ExitCode: 0}}

	runner.results["/usr/bin/systemctl --user enable pipewire.service wireplumber.service"] = []proofstrap.Result{{ExitCode: 0}}
	runner.results["/usr/bin/systemctl --user start pipewire.service wireplumber.service"] = []proofstrap.Result{{ExitCode: 0}}
	return runner
}

func zypperRunner(uid uint32) *cliRunner {
	runner := &cliRunner{
		uid: uid, files: linuxFiles("opensuse-tumbleweed", "systemd"),
		paths:   map[string]string{"zypper": "/usr/bin/zypper", "rpm": "/usr/bin/rpm", "systemctl": "/usr/bin/systemctl", "sudo": "/usr/bin/sudo"},
		results: map[string][]proofstrap.Result{"/usr/bin/zypper --version": {{ExitCode: 0, Stdout: "zypper 1.14.87\n"}}, "/usr/bin/sudo -N -n -v": {{ExitCode: 0}}},
	}
	addCLIAccountResults(runner, "alice", uid, 12)
	return runner
}

func audioConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte("modules = [\"audio\"]\n[account]\nstate = \"existing\"\nname = \"alice\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func addCLIAccountResults(runner *cliRunner, name string, uid uint32, count int) {
	runner.paths["getent"] = "/usr/bin/getent"
	entry := proofstrap.Result{Stdout: fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash\n", name, uid, uid, name)}
	for _, key := range []string{
		"/usr/bin/getent passwd " + name,
		"/usr/bin/getent -s files passwd " + name,
		fmt.Sprintf("/usr/bin/getent passwd %d", uid),
		fmt.Sprintf("/usr/bin/getent -s files passwd %d", uid),
	} {
		queue := make([]proofstrap.Result, count)
		for i := range queue {
			queue[i] = entry
		}
		runner.results[key] = queue
	}
}

func rpmInventoryCommand() string { return "/usr/bin/rpm -qa --qf %{NAME}\\n" }

func linuxFiles(distribution, init string) map[string][]byte {
	return map[string][]byte{
		"/etc/os-release":             []byte("ID=" + distribution + "\n"),
		"/proc/1/comm":                []byte(init + "\n"),
		"/var/lib/zypp/AutoInstalled": {},
	}
}

func callIndex(calls []string, want string) int {
	for index, call := range calls {
		if call == want {
			return index
		}
	}
	return -1
}

func countCalls(calls []string, want string) int {
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}

type cliRunner struct {
	uid           uint32
	files         map[string][]byte
	paths         map[string]string
	results       map[string][]proofstrap.Result
	calls         []string
	homeCreations []proofstrap.HomeCreation
}

func (runner *cliRunner) EffectiveUID() (uint32, error) { return runner.uid, nil }
func (runner *cliRunner) ExecutableIdentity() (proofstrap.ExecutableIdentity, error) {
	return proofstrap.ExecutableIdentity{Path: "/usr/bin/proofstrap", Digest: "sha256:proofstrap-test"}, nil
}
func (runner *cliRunner) ReadFile(path string) ([]byte, error) {
	if value, ok := runner.files[path]; ok {
		return value, nil
	}
	return nil, errors.New("missing file")
}
func (runner *cliRunner) Lstat(string) (proofstrap.PathInfo, error) {
	return proofstrap.PathInfo{}, errors.New("missing path result")
}
func (runner *cliRunner) LookPath(name string) (string, error) {
	if value, ok := runner.paths[name]; ok {
		return value, nil
	}
	return "", errors.New("missing executable")
}

func (runner *cliRunner) CreateHome(creation proofstrap.HomeCreation) error {
	runner.homeCreations = append(runner.homeCreations, creation)
	return nil
}

func (runner *cliRunner) Run(_ context.Context, command proofstrap.Command) proofstrap.Result {
	key := command.String()
	runner.calls = append(runner.calls, key)
	queue := runner.results[key]
	if len(queue) == 0 {
		panic("missing command result: " + key)
	}
	result := queue[0]
	runner.results[key] = queue[1:]
	return result
}
