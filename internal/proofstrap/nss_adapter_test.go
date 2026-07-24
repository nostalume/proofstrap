package proofstrap

import (
	"context"
	"strings"
	"testing"
)

func TestNSSLookupBuildsGlobalAndFilesCommands(t *testing.T) {
	for _, test := range []struct {
		name   string
		source nssSource
		call   string
	}{
		{name: "global", source: nssGlobal, call: "/usr/bin/getent passwd alice"},
		{name: "files", source: nssFiles, call: "/usr/bin/getent -s files passwd alice"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &testRunner{results: map[string][]Result{test.call: {{Stdout: "alice:x:1000:1000::/home/alice:/bin/bash\n"}}}}
			record, err := lookupNSSRecord(context.Background(), runner, "/usr/bin/getent", test.source, "passwd", "alice")
			if err != nil || record.missing || record.value != "alice:x:1000:1000::/home/alice:/bin/bash" || len(runner.calls) != 1 || runner.calls[0] != test.call {
				t.Fatalf("record=%#v err=%v calls=%#v", record, err, runner.calls)
			}
		})
	}
}

func TestNSSLookupMissingIsExact(t *testing.T) {
	missing, err := lookupNSSRecord(context.Background(), &testRunner{results: map[string][]Result{
		"/usr/bin/getent group alice": {{ExitCode: 2}},
	}}, "/usr/bin/getent", nssGlobal, "group", "alice")
	if err != nil || !missing.missing {
		t.Fatalf("missing=%#v err=%v", missing, err)
	}
	_, err = lookupNSSRecord(context.Background(), &testRunner{results: map[string][]Result{
		"/usr/bin/getent group alice": {{ExitCode: 2, Stderr: "backend failed"}},
	}}, "/usr/bin/getent", nssGlobal, "group", "alice")
	if err == nil || !strings.Contains(err.Error(), "backend failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestNSSLookupRejectsMalformedFraming(t *testing.T) {
	for _, test := range []struct {
		database string
		output   string
		detail   string
	}{
		{database: "passwd", output: "alice:x:1000:1000::/home/alice:/bin/bash", detail: "passwd record is not newline terminated"},
		{database: "passwd", output: "alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n", detail: "passwd lookup returned 2 records"},
		{database: "group", output: "alice:x:1000:", detail: "group record is not newline terminated"},
		{database: "group", output: "alice:x:1000:\nbob:x:1001:\n", detail: "group lookup returned 2 records"},
	} {
		call := "/usr/bin/getent " + test.database + " alice"
		runner := &testRunner{results: map[string][]Result{
			call: {{Stdout: test.output}},
		}}
		if _, err := lookupNSSRecord(context.Background(), runner, "/usr/bin/getent", nssGlobal, test.database, "alice"); err == nil || err.Error() != test.detail {
			t.Fatalf("output=%q err=%v", test.output, err)
		}
	}
}
