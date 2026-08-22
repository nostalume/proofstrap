package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestPackedAndEmbeddedAdmissionAgree(t *testing.T) {
	t.Parallel()
	body := readFixture(t, "valid", "complete.toml")
	packed, err := Parse(Member{Path: "profiles/complete.toml", Data: body})
	if err != nil {
		t.Fatal(err)
	}
	packedModule, err := Admit([]Input{packed})
	if err != nil {
		t.Fatal(err)
	}
	packedLibrary, err := Link("test-origin", packedModule, nil)
	if err != nil {
		t.Fatal(err)
	}

	var document struct {
		Schema int `toml:"schema"`
		Syntax
	}
	decoder := toml.NewDecoder(bytes.NewReader(append([]byte("schema=3\n"), body...))).DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	embedded, err := Embed("profiles/complete.toml", document.Syntax)
	if err != nil {
		t.Fatal(err)
	}
	embeddedModule, err := Admit([]Input{embedded})
	if err != nil {
		t.Fatal(err)
	}
	mutated := document.Syntax.Profiles["desktop"]
	mutated.Include[0].Arguments["account"] = "mallory"
	embeddedLibrary, err := Link("test-origin", embeddedModule, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(packedLibrary, embeddedLibrary) {
		t.Fatalf("packed and embedded libraries differ:\n%#v\n%#v", packedLibrary, embeddedLibrary)
	}
}

func admitTest(members []Member) (Library, error) {
	return admitInputs("test-origin", members, nil)
}

func admitInputs(origin string, members []Member, required map[string]Library) (Library, error) {
	inputs := make([]Input, len(members))
	for index, member := range members {
		input, err := Parse(member)
		if err != nil {
			return Library{}, err
		}
		inputs[index] = input
	}
	module, err := Admit(inputs)
	if err != nil {
		return Library{}, err
	}
	return Link(origin, module, required)
}

func TestAdmissionLanguageCompleteMember(t *testing.T) {
	t.Parallel()
	data := readFixture(t, "valid", "complete.toml")
	library, err := admitTest([]Member{{Path: "profiles/complete.toml", Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if got := library.ProfileIDs(); strings.Join(got, ",") != "desktop,user-audio" {
		t.Fatalf("profile IDs = %v", got)
	}
}

func TestAdmissionAdmitsForwardedProfileTarget(t *testing.T) {
	data := []byte(`[profiles.workstation]
parameters = { desktop = "profile_ref" }
[[profiles.workstation.include]]
profile = { parameter = "desktop" }
`)
	if _, err := admitTest([]Member{{Path: "profiles/dynamic.toml", Data: data}}); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionRejectsUnusedParameter(t *testing.T) {
	data := []byte("[profiles.bad]\nparameters={desktop='profile_ref'}\npackages=['sway']\n")
	if library, err := admitTest([]Member{{Path: "profiles/bad.toml", Data: data}}); err == nil || len(library.ProfileIDs()) != 0 {
		t.Fatalf("Decode = %#v, %v", library, err)
	}
}

func TestAdmissionLanguageInvalidFixtures(t *testing.T) {
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
			library, err := admitTest([]Member{{Path: "profiles/" + entry.Name(), Data: data}})
			if err == nil {
				t.Fatalf("invalid fixture admitted with profiles %v", library.ProfileIDs())
			}
			if !strings.Contains(err.Error(), entry.Name()) {
				t.Fatalf("diagnostic %q lacks member provenance", err)
			}
		})
	}
}

func TestAdmissionLanguageAggregateIsAtomicAndOrderIndependent(t *testing.T) {
	t.Parallel()
	a := Member{Path: "profiles/a.toml", Data: []byte("[profiles.a]\npackages=[\"a\"]\n")}
	b := Member{Path: "profiles/b.toml", Data: []byte("[profiles.b]\npackages=[\"b\"]\n")}
	left, err := admitTest([]Member{a, b})
	if err != nil {
		t.Fatal(err)
	}
	right, err := admitTest([]Member{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(left.ProfileIDs(), ",") != strings.Join(right.ProfileIDs(), ",") {
		t.Fatalf("member order changed library: %v != %v", left.ProfileIDs(), right.ProfileIDs())
	}

	duplicate := Member{Path: "profiles/duplicate.toml", Data: []byte("[profiles.a]\npackages=[\"other\"]\n")}
	failed, err := admitTest([]Member{a, duplicate})
	if err == nil {
		t.Fatal("duplicate profile admitted")
	}
	if len(failed.ProfileIDs()) != 0 {
		t.Fatalf("failed aggregate published %v", failed.ProfileIDs())
	}
}

func TestAdmissionLanguageRawByteBoundary(t *testing.T) {
	t.Parallel()
	base := []byte("[profiles.a]\npackages=[\"a\"]\n")
	exact := append([]byte(nil), base...)
	for len(exact) < MaxMemberBytes {
		exact = append(exact, '#')
	}
	if _, err := admitTest([]Member{{Path: "profiles/exact.toml", Data: exact}}); err != nil {
		t.Fatalf("exact byte limit rejected: %v", err)
	}
	tooLarge := append(exact, '#')
	if _, err := admitTest([]Member{{Path: "profiles/large.toml", Data: tooLarge}}); err == nil {
		t.Fatal("byte limit plus one admitted")
	}
}

func TestAdmissionLanguageLocatedSyntaxError(t *testing.T) {
	t.Parallel()
	_, err := admitTest([]Member{{
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

func TestAdmissionLanguageRejectsDuplicateKeysAndIncludeCycle(t *testing.T) {
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
			if _, err := admitTest([]Member{{Path: "profiles/" + name, Data: []byte(source)}}); err == nil {
				t.Fatal("invalid semantic member admitted")
			}
		})
	}
}

func TestAdmissionLanguageRejectsInvalidUTF8AndCollectionLimits(t *testing.T) {
	t.Parallel()
	if _, err := admitTest([]Member{{Path: "profiles/utf8.toml", Data: []byte{0xff}}}); err == nil {
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
	if _, err := admitTest([]Member{{
		Path: "profiles/resources-limit.toml",
		Data: []byte(source.String()),
	}}); err == nil {
		t.Fatal("resource limit plus one admitted")
	}
}

func TestAdmissionLanguageStructuralDepth(t *testing.T) {
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
	_, err := admitTest([]Member{{Path: "profiles/deep.toml", Data: []byte(deep)}})
	if err == nil {
		t.Fatal("structural depth above limit admitted")
	}
	diagnostic, ok := err.(*Diagnostic)
	if !ok || diagnostic.Category != "Limit" {
		t.Fatalf("depth error = %#v, want Limit diagnostic", err)
	}
}

func TestAdmissionLanguageDynamicDepthBoundary(t *testing.T) {
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

	_, exactErr := admitTest([]Member{member(maxDepth)})
	if diagnostic, ok := exactErr.(*Diagnostic); ok && diagnostic.Category == "Limit" {
		t.Fatalf("exact dynamic depth rejected as Limit: %v", exactErr)
	}
	_, overflowErr := admitTest([]Member{member(maxDepth + 1)})
	diagnostic, ok := overflowErr.(*Diagnostic)
	if !ok || diagnostic.Category != "Limit" {
		t.Fatalf("dynamic depth overflow = %#v, want Limit", overflowErr)
	}
}

func FuzzAdmission(f *testing.F) {
	f.Add([]byte("[profiles.a]\npackages=[\"a\"]\n"))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMemberBytes+1 {
			data = data[:MaxMemberBytes+1]
		}
		library, err := admitTest([]Member{{Path: "profiles/fuzz.toml", Data: data}})
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
