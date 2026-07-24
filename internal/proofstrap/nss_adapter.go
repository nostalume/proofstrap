package proofstrap

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type nssSource uint8

const (
	nssGlobal nssSource = iota + 1
	nssFiles
)

type nssRecord struct {
	value   string
	missing bool
}

func lookupNSSRecord(ctx context.Context, runner Runner, getent string, source nssSource, database, key string) (nssRecord, error) {
	if database != "passwd" && database != "group" {
		return nssRecord{}, fmt.Errorf("unsupported NSS database %q", database)
	}
	args := []string{database, key}
	switch source {
	case nssGlobal:
	case nssFiles:
		args = []string{"-s", "files", database, key}
	default:
		panic("unknown NSS source")
	}
	result := runner.Run(ctx, Command{Name: getent, Args: args, timeout: 5 * time.Second})
	if result.Err == nil && result.ExitCode == 2 && result.Stdout == "" && result.Stderr == "" {
		return nssRecord{missing: true}, nil
	}
	if result.Err != nil || result.ExitCode != 0 || result.Stderr != "" {
		return nssRecord{}, fmt.Errorf("%s", resultDetail(result))
	}
	record, err := singleNSSRecord(database, result.Stdout)
	if err != nil {
		return nssRecord{}, err
	}
	return nssRecord{value: record}, nil
}

func singleNSSRecord(database, output string) (string, error) {
	if !strings.HasSuffix(output, "\n") {
		return "", fmt.Errorf("%s record is not newline terminated", database)
	}
	record := strings.TrimSuffix(output, "\n")
	if record == "" || strings.Contains(record, "\n") {
		count := 0
		if record != "" {
			count = strings.Count(record, "\n") + 1
		}
		return "", fmt.Errorf("%s lookup returned %d records", database, count)
	}
	return record, nil
}
