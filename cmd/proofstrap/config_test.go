package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindConfigFileUsesExplicitThenEnvironmentThenDefaults(t *testing.T) {
	directory := t.TempDir()
	local := filepath.Join(directory, "local.toml")
	environment := filepath.Join(directory, "environment.toml")
	global := filepath.Join(directory, "global.toml")
	for _, path := range []string{local, environment, global} {
		if err := os.WriteFile(path, []byte("modules = []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got, err := findConfigFile(global, local, environment, ""); err != nil || got != global {
		t.Fatalf("explicit result=(%q, %v)", got, err)
	}
	if got, err := findConfigFile("", local, environment, global); err != nil || got != environment {
		t.Fatalf("default result=(%q, %v)", got, err)
	}
}

func TestFindConfigFileRejectsMissingExplicitPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if _, err := findConfigFile(missing, "", "", ""); err == nil {
		t.Fatal("missing explicit config was accepted")
	}
}

func TestFindConfigFileRejectsMissingEnvironmentPath(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.toml")
	local := filepath.Join(directory, "local.toml")
	if err := os.WriteFile(local, []byte("modules = []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findConfigFile("", local, missing, ""); err == nil {
		t.Fatal("missing environment-selected config silently fell back")
	}
}

func TestReadDesiredStateHonorsExplicitPathWithoutWorkingDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "explicit.toml")
	if err := os.WriteFile(config, []byte("modules = [\"audio\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deleted := filepath.Join(t.TempDir(), "deleted")
	if err := os.Mkdir(deleted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(deleted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	}()
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	state, err := readDesiredState(config)
	if err != nil || len(state.Modules) != 1 || state.Modules[0] != "audio" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}
