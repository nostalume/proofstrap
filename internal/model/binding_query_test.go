package model_test

import (
	"testing"

	"github.com/nostalume/proofstrap/internal/model"
)

func TestBindableIDsAreTypedAndExcludeServiceTarget(t *testing.T) {
	packageID, err := model.NewPackageID("agent")
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := model.NewServiceID("agent")
	if err != nil {
		t.Fatal(err)
	}
	packageResource, _ := model.NewPackage(packageID)
	serviceResource, _ := model.NewService(
		serviceID, model.SystemServiceTarget(), model.UnmanagedEnableIntent(), model.RunningIntent(), nil,
	)
	provenance, _ := model.NewProvenance("test")
	packageContribution, _ := model.Contribute(packageResource, provenance)
	serviceContribution, _ := model.Contribute(serviceResource, provenance)
	graph, err := model.EmptyGraph().Add([]model.Contribution{packageContribution, serviceContribution})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range graph.Nodes() {
		if id, ok := model.PackageIDOf(node); ok {
			if id.String() != "agent" {
				t.Fatalf("PackageIDOf = %q", id.String())
			}
			if _, service := model.ServiceIDOf(node); service {
				t.Fatal("package node identified as service")
			}
			continue
		}
		id, ok := model.ServiceIDOf(node)
		if !ok || id.String() != "agent" {
			t.Fatalf("ServiceIDOf = %v, %v", id, ok)
		}
		if _, pkg := model.PackageIDOf(node); pkg {
			t.Fatal("service node identified as package")
		}
	}
}
