package proofstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDesiredStateRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte("modules = [\"sway\"]\nunexpected = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadDesiredState(path)
	if err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("error = %v, want unknown field rejection", err)
	}
}

func TestReadDesiredStateParsesExplicitExistingAccount(t *testing.T) {
	state, err := ReadDesiredState(writeDesiredFile(t, "modules = []\n[account]\nstate = \"existing\"\nname = \"alice\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	account, ok := state.account.(existingAccountIntent)
	if !ok || account.name != "alice" || state.Empty() {
		t.Fatalf("state=%#v account=%#v", state, state.account)
	}
}

func TestReadDesiredStateParsesCanonicalPresentAccount(t *testing.T) {
	state, err := ReadDesiredState(writeDesiredFile(t, `
modules = ["audio"]
[account]
state = "present"
name = "alice"
uid = 1000
shell = "/bin/bash"
[account.primary_group]
name = "alice"
gid = 1000
[account.home]
path = "/home/alice"
mode = "0700"
`))
	if err != nil {
		t.Fatal(err)
	}
	account, ok := state.account.(presentAccountIntent)
	if !ok || account.name != "alice" || account.uid != 1000 || account.shell != "/bin/bash" || account.primaryGroup != (primaryGroupIntent{name: "alice", gid: 1000}) || account.home != (homeIntent{path: "/home/alice", mode: 0o700}) {
		t.Fatalf("account=%#v", state.account)
	}
}

func TestReadDesiredStateRejectsRetiredRequiredGroups(t *testing.T) {
	_, err := ReadDesiredState(writeDesiredFile(t, "modules = []\n[account]\nstate = \"present\"\nname = \"alice\"\nuid = 1000\nshell = \"/bin/bash\"\nrequired_groups = []\n[account.primary_group]\nname = \"alice\"\ngid = 1000\n[account.home]\npath = \"/home/alice\"\nmode = \"0700\"\n"))
	if err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("error = %v, want retired field rejection", err)
	}
}

func TestReadDesiredStateRejectsInvalidAccountIntent(t *testing.T) {
	for name, contents := range map[string]string{
		"unknown state":         "[account]\nstate = \"managed\"\nname = \"alice\"\n",
		"existing extra uid":    "[account]\nstate = \"existing\"\nname = \"alice\"\nuid = 1000\n",
		"existing empty groups": "[account]\nstate = \"existing\"\nname = \"alice\"\nrequired_groups = []\n",
		"present missing home":  "[account]\nstate = \"present\"\nname = \"alice\"\nuid = 1000\nshell = \"/bin/bash\"\n[account.primary_group]\nname = \"alice\"\ngid = 1000\n",

		"numeric name":      "[account]\nstate = \"existing\"\nname = \"1000\"\n",
		"relative shell":    "[account]\nstate = \"present\"\nname = \"alice\"\nuid = 1000\nshell = \"bin/bash\"\n[account.primary_group]\nname = \"alice\"\ngid = 1000\n[account.home]\npath = \"/home/alice\"\nmode = \"0700\"\n",
		"invalid home mode": "[account]\nstate = \"present\"\nname = \"alice\"\nuid = 1000\nshell = \"/bin/bash\"\n[account.primary_group]\nname = \"alice\"\ngid = 1000\n[account.home]\npath = \"/home/alice\"\nmode = \"700\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadDesiredState(writeDesiredFile(t, contents)); err == nil {
				t.Fatal("invalid account intent admitted")
			}
		})
	}
}

func writeDesiredFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proofstrap.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
