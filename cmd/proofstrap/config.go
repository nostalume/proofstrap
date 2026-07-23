package main

import (
	"errors"
	"io/fs"
	"os"
)

func findConfigFile(explicit, local, environment, global string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	if environment != "" {
		if _, err := os.Stat(environment); err != nil {
			return "", err
		}
		return environment, nil
	}
	for _, path := range []string{local, global} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return "", nil
}
