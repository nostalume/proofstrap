package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nostalume/proofstrap/internal/engine"
)

type faultJournalFile struct {
	data       []byte
	offset     int64
	syncCalls  int
	truncation int64
}

func (file *faultJournalFile) Write(data []byte) (int, error) {
	end := int(file.offset) + len(data)
	if end > len(file.data) {
		file.data = append(file.data, make([]byte, end-len(file.data))...)
	}
	copy(file.data[file.offset:], data)
	file.offset = int64(end)
	return len(data), nil
}

func (file *faultJournalFile) Sync() error {
	file.syncCalls++
	if file.syncCalls == 1 {
		return os.ErrPermission
	}
	return nil
}

func (file *faultJournalFile) Truncate(size int64) error {
	file.truncation = size
	file.data = file.data[:size]
	return nil
}

func (file *faultJournalFile) Seek(offset int64, whence int) (int64, error) {
	if whence != io.SeekStart {
		return 0, errors.New("unexpected seek")
	}
	file.offset = offset
	return offset, nil
}

func (*faultJournalFile) Close() error { return nil }

func TestJournalFailedSyncRestoresLastCommittedPrefix(t *testing.T) {
	file := &faultJournalFile{data: []byte("old"), offset: 3, truncation: -1}
	journal := &fileJournal{file: file, parent: -1, offset: 3}
	if err := journal.Append([]byte("new")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Append = %v", err)
	}
	if string(file.data) != "old" || file.truncation != 3 || file.offset != 3 || file.syncCalls != 2 {
		t.Fatalf("rollback = data %q truncate %d offset %d syncs %d", file.data, file.truncation, file.offset, file.syncCalls)
	}
}

func TestJournalPersistsInspectableEngineFrames(t *testing.T) {
	key, _ := engine.NewKey("one")
	dag, err := engine.Admit([]engine.Declaration{{Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := engine.ParsePlanDigest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	path := filepath.Join(t.TempDir(), "journal")
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	prepared := map[string]preparedOperation{"one": {
		effectLimit: time.Second, postLimit: time.Second,
		admit: func(context.Context) (operationEffect, error) {
			return func(context.Context, postContext) (bool, error) { return true, nil }, nil
		},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := executePrepared(ctx, dag, digest, prepared, journal)
	closeErr := journal.Close()
	if err != nil || closeErr != nil || result.Status != engine.Converged {
		t.Fatalf("execute = %#v, %v; close %v", result, err, closeErr)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	summary, err := engine.InspectJournal(dag, file)
	if err != nil || summary.Generation() != 1 || summary.Status() != engine.Converged {
		t.Fatalf("InspectJournal = %#v, %v", summary, err)
	}
}
