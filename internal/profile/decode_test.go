package profile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func decodeTest(members []Member) (Library, error) {
	return Decode("test-origin", members, nil)
}

func TestDecodeLanguageCompleteMember(t *testing.T) {
	t.Parallel()
	data := readFixture(t, "valid", "complete.toml")
	library, err := decodeTest([]Member{{Path: "profiles/complete.toml", Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if got := library.ProfileIDs(); strings.Join(got, ",") != "desktop,user-audio" {
		t.Fatalf("profile IDs = %v", got)
	}
}

func TestDecodeAdmitsForwardedProfileTarget(t *testing.T) {
	data := []byte(`[profiles.workstation]
parameters = { desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
`)
	if _, err := decodeTest([]Member{{Path: "profiles/dynamic.toml", Data: data}}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejectsUnusedParameter(t *testing.T) {
	data := []byte("[profiles.bad]\nparameters={desktop='profile_ref'}\npackages=['sway']\n")
	if library, err := decodeTest([]Member{{Path: "profiles/bad.toml", Data: data}}); err == nil || len(library.ProfileIDs()) != 0 {
		t.Fatalf("Decode = %#v, %v", library, err)
	}
}

func TestDecodeLanguageInvalidFixtures(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join("testdata", "invalid"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 18 {
		t.Fatalf("invalid fixture count = %d, want 18", len(entries))
	}
	for _, entry := range entries {
		entry := entry
		t.Run(strings.TrimSuffix(entry.Name(), ".toml"), func(t *testing.T) {
			t.Parallel()
			data := readFixture(t, "invalid", entry.Name())
			library, err := decodeTest([]Member{{Path: "profiles/" + entry.Name(), Data: data}})
			if err == nil {
				t.Fatalf("invalid fixture admitted with profiles %v", library.ProfileIDs())
			}
			if !strings.Contains(err.Error(), entry.Name()) {
				t.Fatalf("diagnostic %q lacks member provenance", err)
			}
		})
	}
}

func TestDecodeLanguageAggregateIsAtomicAndOrderIndependent(t *testing.T) {
	t.Parallel()
	a := Member{Path: "profiles/a.toml", Data: []byte("[profiles.a]\npackages=[\"a\"]\n")}
	b := Member{Path: "profiles/b.toml", Data: []byte("[profiles.b]\npackages=[\"b\"]\n")}
	left, err := decodeTest([]Member{a, b})
	if err != nil {
		t.Fatal(err)
	}
	right, err := decodeTest([]Member{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(left.ProfileIDs(), ",") != strings.Join(right.ProfileIDs(), ",") {
		t.Fatalf("member order changed library: %v != %v", left.ProfileIDs(), right.ProfileIDs())
	}

	duplicate := Member{Path: "profiles/duplicate.toml", Data: []byte("[profiles.a]\npackages=[\"other\"]\n")}
	failed, err := decodeTest([]Member{a, duplicate})
	if err == nil {
		t.Fatal("duplicate profile admitted")
	}
	if len(failed.ProfileIDs()) != 0 {
		t.Fatalf("failed aggregate published %v", failed.ProfileIDs())
	}
}

func TestDecodeLanguageRawByteBoundary(t *testing.T) {
	t.Parallel()
	base := []byte("[profiles.a]\npackages=[\"a\"]\n")
	exact := append([]byte(nil), base...)
	for len(exact) < MaxMemberBytes {
		exact = append(exact, '#')
	}
	if _, err := decodeTest([]Member{{Path: "profiles/exact.toml", Data: exact}}); err != nil {
		t.Fatalf("exact byte limit rejected: %v", err)
	}
	tooLarge := append(exact, '#')
	if _, err := decodeTest([]Member{{Path: "profiles/large.toml", Data: tooLarge}}); err == nil {
		t.Fatal("byte limit plus one admitted")
	}
}

func TestDecodeLanguageLocatedSyntaxError(t *testing.T) {
	t.Parallel()
	_, err := decodeTest([]Member{{
		Path: "profiles/broken.toml",
		Data: []byte("[profiles.a]\npackages = [\n"),
	}})
	if err == nil {
		t.Fatal("broken TOML admitted")
	}
	diagnostic, ok := err.(*Diagnostic)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if diagnostic.Member != "profiles/broken.toml" || diagnostic.Line == 0 || diagnostic.Column == 0 {
		t.Fatalf("incomplete location: %#v", diagnostic)
	}
}

func TestDecodeLanguageRejectsDuplicateKeysAndIncludeCycle(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"duplicate-key.toml":       "[profiles.a]\\npackages=[\\\"a\\\"]\\npackages=[\\\"b\\\"]\\n",
		"cycle.toml":               "[profiles.a]\\n[[profiles.a.include]]\\nprofile=\\\"b\\\"\\n[profiles.b]\\n[[profiles.b.include]]\\nprofile=\\\"a\\\"\\n",
		"arguments-extra.toml":     "[profiles.base]\\nparameters={account=\\\"account_ref\\\"}\\nhomes=[{account={parameter=\\\"account\\\"}}]\\n[profiles.a]\\n[[profiles.a.include]]\\nprofile=\\\"base\\\"\\n[profiles.a.include.arguments]\\naccount=\\\"alice\\\"\\nextra=\\\"alice\\\"\\n",
		"arguments-forbidden.toml": "[profiles.base]\\npackages=[\\\"a\\\"]\\n[profiles.a]\\n[[profiles.a.include]]\\nprofile=\\\"base\\\"\\n[profiles.a.include.arguments]\\naccount=\\\"alice\\\"\\n",
	}
	for name, source := range cases {
		name, source := name, source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeTest([]Member{{Path: "profiles/" + name, Data: []byte(source)}}); err == nil {
				t.Fatal("invalid semantic member admitted")
			}
		})
	}
}

func TestDecodeLanguageRejectsInvalidUTF8AndCollectionLimits(t *testing.T) {
	t.Parallel()
	if _, err := decodeTest([]Member{{Path: "profiles/utf8.toml", Data: []byte{0xff}}}); err == nil {
		t.Fatal("invalid UTF-8 admitted")
	}
	var source strings.Builder
	source.WriteString("[profiles.a]\\npackages=[")
	for index := 0; index <= maxResources; index++ {
		if index > 0 {
			source.WriteByte(',')
		}
		source.WriteString("\\\"p")
		source.WriteString(strconv.Itoa(index))
		source.WriteByte('"')
	}
	source.WriteString("]\\n")
	if _, err := decodeTest([]Member{{
		Path: "profiles/resources-limit.toml",
		Data: []byte(source.String()),
	}}); err == nil {
		t.Fatal("resource limit plus one admitted")
	}
}

func TestDecodeLanguageStructuralDepth(t *testing.T) {
	t.Parallel()
	deep := "[profiles.a.services.agent]\ntarget={user="
	for range maxDepth {
		deep += "{parameter="
	}
	deep += "\"account\""
	for range maxDepth {
		deep += "}"
	}
	deep += "}\nrunning=true\n"
	_, err := decodeTest([]Member{{Path: "profiles/deep.toml", Data: []byte(deep)}})
	if err == nil {
		t.Fatal("structural depth above limit admitted")
	}
	diagnostic, ok := err.(*Diagnostic)
	if !ok || diagnostic.Category != "Limit" {
		t.Fatalf("depth error = %#v, want Limit diagnostic", err)
	}
}

func TestDecodeLanguageDynamicDepthBoundary(t *testing.T) {
	t.Parallel()
	member := func(depth int) Member {
		value := "\"alice\""
		for range depth {
			value = "{parameter=" + value + "}"
		}
		return Member{Path: "profiles/depth.toml", Data: []byte(
			"[profiles.base]\nparameters={account='account_ref'}\nhomes=[{account={parameter='account'}}]\n" +
				"[profiles.use]\n[[profiles.use.include]]\nprofile='base'\n[profiles.use.include.arguments]\naccount=" + value + "\n")}
	}

	_, exactErr := decodeTest([]Member{member(maxDepth)})
	if diagnostic, ok := exactErr.(*Diagnostic); ok && diagnostic.Category == "Limit" {
		t.Fatalf("exact dynamic depth rejected as Limit: %v", exactErr)
	}
	_, overflowErr := decodeTest([]Member{member(maxDepth + 1)})
	diagnostic, ok := overflowErr.(*Diagnostic)
	if !ok || diagnostic.Category != "Limit" {
		t.Fatalf("dynamic depth overflow = %#v, want Limit", overflowErr)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("[profiles.a]\npackages=[\"a\"]\n"))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMemberBytes+1 {
			data = data[:MaxMemberBytes+1]
		}
		library, err := decodeTest([]Member{{Path: "profiles/fuzz.toml", Data: data}})
		if err != nil && len(library.ProfileIDs()) != 0 {
			t.Fatalf("Decode returned partial Library with %v", err)
		}
	})
}

func readFixture(t *testing.T, class, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", class, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
