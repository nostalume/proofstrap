package binding_test

import (
	"strings"
	"testing"

	"github.com/nostalume/proofstrap/internal/binding"
)

func TestNativeIDsPreserveAdmittedBackendAndName(t *testing.T) {
	packageBackend, err := binding.NewPackageBackendID("zypper")
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := binding.NewPackageID(packageBackend, "libfoo:amd64")
	if err != nil {
		t.Fatal(err)
	}
	if packageID.Backend() != packageBackend || packageID.Name() != "libfoo:amd64" {
		t.Fatalf("package ID = (%q, %q)", packageID.Backend(), packageID.Name())
	}

	serviceBackend, err := binding.NewServiceBackendID("systemd")
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := binding.NewServiceID(serviceBackend, "dbus.service")
	if err != nil {
		t.Fatal(err)
	}
	if serviceID.Backend() != serviceBackend || serviceID.Name() != "dbus.service" {
		t.Fatalf("service ID = (%q, %q)", serviceID.Backend(), serviceID.Name())
	}
}

func TestNativeIDConstructionRejectsInvalidPartsAtomically(t *testing.T) {
	packageBackend, _ := binding.NewPackageBackendID("zypper")
	serviceBackend, _ := binding.NewServiceBackendID("systemd")
	invalidNames := []string{"", strings.Repeat("x", 256), string([]byte{0xff})}

	for _, name := range invalidNames {
		if id, err := binding.NewPackageID(packageBackend, name); err == nil || id != (binding.PackageID{}) {
			t.Fatalf("invalid package name admitted: id=%#v err=%v", id, err)
		}
		if id, err := binding.NewServiceID(serviceBackend, name); err == nil || id != (binding.ServiceID{}) {
			t.Fatalf("invalid service name admitted: id=%#v err=%v", id, err)
		}
	}

	if id, err := binding.NewPackageID(binding.PackageBackendID{}, "curl"); err == nil || id != (binding.PackageID{}) {
		t.Fatalf("zero package backend admitted: id=%#v err=%v", id, err)
	}
	if id, err := binding.NewServiceID(binding.ServiceBackendID{}, "dbus"); err == nil || id != (binding.ServiceID{}) {
		t.Fatalf("zero service backend admitted: id=%#v err=%v", id, err)
	}
}

func TestNativeNameAdmissionDoesNotRequireABackend(t *testing.T) {
	for _, name := range []string{"curl", "libfoo:amd64"} {
		if err := binding.ValidatePackageName(name); err != nil {
			t.Fatalf("package name %q: %v", name, err)
		}
		if err := binding.ValidateServiceName(name); err != nil {
			t.Fatalf("service name %q: %v", name, err)
		}
	}
	for _, name := range []string{"", strings.Repeat("x", 256), string([]byte{0xff})} {
		if err := binding.ValidatePackageName(name); err == nil {
			t.Fatalf("invalid package name %q admitted", name)
		}
		if err := binding.ValidateServiceName(name); err == nil {
			t.Fatalf("invalid service name %q admitted", name)
		}
	}
}
