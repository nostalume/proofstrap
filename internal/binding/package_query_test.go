package binding

import "testing"

func TestPackageIDOfProjectedNode(t *testing.T) {
	backend, _ := NewPackageBackendID("zypper")
	id, _ := NewPackageID(backend, "editor")
	packageNode := node{value: graphNode{key: packageKey{id: id}}}

	got, ok := PackageIDOf(packageNode)
	if !ok || got != id {
		t.Fatalf("PackageIDOf = %#v, %v; want %#v, true", got, ok, id)
	}
	if _, ok := PackageIDOf(node{value: graphNode{key: passthroughKey{}}}); ok {
		t.Fatal("passthrough node identified as package")
	}
	if _, ok := PackageIDOf(nil); ok {
		t.Fatal("nil node identified as package")
	}
}

func TestServiceIDOfProjectedNode(t *testing.T) {
	backend, _ := NewServiceBackendID("systemd")
	id, _ := NewServiceID(backend, "sshd.service")
	serviceNode := node{value: graphNode{key: serviceKey{id: id}}}

	got, ok := ServiceIDOf(serviceNode)
	if !ok || got != id {
		t.Fatalf("ServiceIDOf = %#v, %v; want %#v, true", got, ok, id)
	}
	if _, ok := ServiceIDOf(node{value: graphNode{key: packageKey{}}}); ok {
		t.Fatal("package node identified as service")
	}
	if _, ok := ServiceIDOf(node{value: graphNode{key: passthroughKey{}}}); ok {
		t.Fatal("passthrough node identified as service")
	}
	if _, ok := ServiceIDOf(nil); ok {
		t.Fatal("nil node identified as service")
	}
}
