package binding

import (
	"context"
	"fmt"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

func Link(ctx context.Context, module Module, local profile.Library, required map[string]profile.Library) (Catalogue, error) {
	if err := canceled(ctx); err != nil {
		return Catalogue{}, err
	}
	if module.mappings == nil {
		return Catalogue{}, bindingDiagnostic("InvalidValue", "", "", "admitted binding module is required", nil)
	}
	used := make(map[string]struct{})
	for _, reference := range module.references {
		if err := canceled(ctx); err != nil {
			return Catalogue{}, err
		}
		library, exists := required[reference.handle]
		if reference.handle == "" {
			library, exists = local, local.Present()
		}
		if !exists {
			category, detail := "MissingReference", "missing requirement handle "+reference.handle
			if reference.handle == "" && reference.key {
				category, detail = "InvalidValue", "binding key must be handle:Symbol"
			}
			return Catalogue{}, bindingDiagnostic(category, reference.member, reference.field, detail, nil)
		}
		if reference.handle != "" {
			used[reference.handle] = struct{}{}
		}
		if category, err := proveDeclaration(reference.domain, library, reference.symbol); err != nil {
			return Catalogue{}, bindingDiagnostic(category, reference.member, reference.field, err.Error(), err)
		}
	}
	for _, handle := range sortedMapKeys(required) {
		if _, exists := used[handle]; !exists {
			return Catalogue{}, bindingDiagnostic("UnusedRequirement", "", "requires."+handle, "requirement handle is unused", nil)
		}
	}
	return Catalogue{state: &catalogueState{mappings: module.mappings}}, nil
}

func Requirements(module Module) []string {
	used := make(map[string]struct{})
	for _, reference := range module.references {
		if reference.handle != "" {
			used[reference.handle] = struct{}{}
		}
	}
	return sortedMapKeys(used)
}

func UsesLocal(module Module) bool {
	for _, reference := range module.references {
		if reference.handle == "" {
			return true
		}
	}
	return false
}

func (m Module) Present() bool { return m.mappings != nil }

func proveDeclaration(domain Domain, library profile.Library, symbol string) (string, error) {
	packageID, packageErr := model.NewPackageID(symbol)
	serviceID, serviceErr := model.NewServiceID(symbol)
	if packageErr != nil || serviceErr != nil {
		return "MissingReference", fmt.Errorf("invalid semantic Symbol")
	}
	if domain == Package {
		if library.DeclaresPackage(packageID) {
			return "", nil
		}
		if library.DeclaresService(serviceID) {
			return "WrongDomain", fmt.Errorf("wrong domain: declaration is a service")
		}
		return "MissingReference", fmt.Errorf("missing package declaration %s", symbol)
	}
	if library.DeclaresService(serviceID) {
		return "", nil
	}
	if library.DeclaresPackage(packageID) {
		return "WrongDomain", fmt.Errorf("wrong domain: declaration is a package")
	}
	return "MissingReference", fmt.Errorf("missing service declaration %s", symbol)
}
