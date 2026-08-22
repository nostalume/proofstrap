package document_test

import (
	"errors"
	"testing"

	"github.com/nostalume/proofstrap/internal/document"
)

func TestDecodeSchemaThreeOwnsCompleteLocalSemanticsAndBindings(t *testing.T) {
	data := []byte(`schema = 3
include = [{ profile = "workstation" }]

[profiles.workstation]
packages = ["agent"]

[package.apt]
agent = ["agent-native"]
`)
	admitted, err := document.Decode("target.toml", data)
	if err != nil {
		t.Fatal(err)
	}
	view := admitted.View()
	if len(view.Include) != 1 || !view.Profiles.Present() || !view.Mappings.Present() {
		t.Fatalf("incomplete document view: %#v", view)
	}
}

func TestDecodeRejectsSchemaTwoAndRemovedNativeSyntax(t *testing.T) {
	for name, data := range map[string]string{
		"schema-two": "schema=2\ninclude=[{profile='x'}]\n",
		"packages":   "schema=3\npackages=['curl']\n",
		"services":   "schema=3\n[services.demo]\ntarget='system'\nrunning=true\n",
		"via":        "schema=3\n[via.flatpak]\npackages=['flatpak']\n",
	} {
		t.Run(name, func(t *testing.T) {
			admitted, err := document.Decode("target.toml", []byte(data))
			var diagnostic *document.Diagnostic
			if admitted != (document.Document{}) || !errors.As(err, &diagnostic) {
				t.Fatalf("Decode = %#v, %v", admitted, err)
			}
			if name == "schema-two" && diagnostic.Category != "UnsupportedSchema" {
				t.Fatalf("category = %s", diagnostic.Category)
			}
			if name != "schema-two" && diagnostic.Category != "Syntax" {
				t.Fatalf("category = %s", diagnostic.Category)
			}
		})
	}
}
