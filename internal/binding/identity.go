package binding

import (
	"fmt"
	"unicode/utf8"
)

type PackageBackendID struct{ value string }
type ServiceBackendID struct{ value string }

func NewPackageBackendID(value string) (PackageBackendID, error) {
	if !validBackendID(value) {
		return PackageBackendID{}, fmt.Errorf("invalid package backend ID %q", value)
	}
	return PackageBackendID{value: value}, nil
}

func NewServiceBackendID(value string) (ServiceBackendID, error) {
	if !validBackendID(value) {
		return ServiceBackendID{}, fmt.Errorf("invalid service backend ID %q", value)
	}
	return ServiceBackendID{value: value}, nil
}

func (id PackageBackendID) String() string { return id.value }
func (id ServiceBackendID) String() string { return id.value }

type Backends struct {
	Package PackageBackendID
	Service ServiceBackendID
}

type PackageID struct {
	backend PackageBackendID
	name    string
}

type ServiceID struct {
	backend ServiceBackendID
	name    string
}

func NewPackageID(backend PackageBackendID, name string) (PackageID, error) {
	if backend.value == "" || !validNativeName(name) {
		return PackageID{}, fmt.Errorf("valid package backend and native name are required")
	}
	return PackageID{backend: backend, name: name}, nil
}

func NewServiceID(backend ServiceBackendID, name string) (ServiceID, error) {
	if backend.value == "" || !validNativeName(name) {
		return ServiceID{}, fmt.Errorf("valid service backend and native name are required")
	}
	return ServiceID{backend: backend, name: name}, nil
}

func (id PackageID) Backend() PackageBackendID { return id.backend }
func (id PackageID) Name() string              { return id.name }
func (id ServiceID) Backend() ServiceBackendID { return id.backend }
func (id ServiceID) Name() string              { return id.name }

func ValidatePackageName(value string) error {
	if !validNativeName(value) {
		return fmt.Errorf("invalid package native name")
	}
	return nil
}

func ValidateServiceName(value string) error {
	if !validNativeName(value) {
		return fmt.Errorf("invalid service native name")
	}
	return nil
}

func validBackendID(value string) bool {
	if value == "" || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	previousHyphen := false
	for _, character := range value[1:] {
		if character == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
		previousHyphen = false
	}
	return !previousHyphen
}

func validNativeName(value string) bool {
	return value != "" && len(value) <= 255 && utf8.ValidString(value)
}
