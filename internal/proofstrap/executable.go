package proofstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (OSRunner) ExecutableIdentity() (ExecutableIdentity, error) {
	path, err := os.Executable()
	if err != nil {
		return ExecutableIdentity{}, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	digest, err := runningExecutableDigest()
	if err != nil {
		return ExecutableIdentity{}, err
	}
	return ExecutableIdentity{Path: path, Digest: digest}, nil
}

func runningExecutableDigest() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

const proofstrapSelfPrefix = "@proofstrap-self="

func materializeProofstrapSelf(argument string) (string, error) {
	if !strings.HasPrefix(argument, proofstrapSelfPrefix) {
		return argument, nil
	}
	expected := strings.TrimPrefix(argument, proofstrapSelfPrefix)
	actual, err := runningExecutableDigest()
	if err != nil {
		return "", err
	}
	if actual != expected {
		return "", fmt.Errorf("running executable digest changed")
	}
	return fmt.Sprintf("/proc/%d/exe", os.Getpid()), nil
}
