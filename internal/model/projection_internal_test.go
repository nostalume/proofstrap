package model

import "testing"

type foreignNode struct{}

func (foreignNode) Key() Key             { return hostnameKey{} }
func (foreignNode) Resource() Resource   { return hostnameResource{value: "foreign"} }
func (foreignNode) Dependencies() []Key  { return nil }
func (foreignNode) Provenance() []string { return nil }
func (foreignNode) node()                {}

func TestProjectionRejectsForeignNodeImplementation(t *testing.T) {
	if _, ok := HostnameOf(foreignNode{}); ok {
		t.Fatal("foreign node implementation was projected")
	}
}
