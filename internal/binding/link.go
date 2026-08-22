package binding

import (
	"context"
	"fmt"

	"github.com/nostalume/proofstrap/internal/model"
	"github.com/nostalume/proofstrap/internal/profile"
)

// Link proves an admitted module against its exact semantic requirements.
func Link(ctx context.Context, module Module, required map[string]profile.Library) (Catalogue, error) {
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
		if !exists {
			return Catalogue{}, bindingDiagnostic("MissingReference", reference.member, reference.field, "missing requirement handle "+reference.handle, nil)
		}
		used[reference.handle] = struct{}{}
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
