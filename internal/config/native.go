package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nostalume/proofstrap/internal/binding"
	"github.com/nostalume/proofstrap/internal/model"
)

type PackageRef struct {
	name  string
	exact binding.PackageID
}

func (r PackageRef) Name() string { return r.name }
func (r PackageRef) Exact() (binding.PackageID, bool) {
	if r.exact.Backend().String() == "" {
		return binding.PackageID{}, false
	}
	return r.exact, true
}

type ServiceRef struct {
	name  string
	exact binding.ServiceID
}

func (r ServiceRef) Name() string { return r.name }
func (r ServiceRef) Exact() (binding.ServiceID, bool) {
	if r.exact.Backend().String() == "" {
		return binding.ServiceID{}, false
	}
	return r.exact, true
}

type Service struct {
	id       ServiceRef
	target   model.ServiceTarget
	enable   model.EnableIntent
	run      model.RunIntent
	packages []PackageRef
}

func (s Service) ID() ServiceRef              { return s.id }
func (s Service) Target() model.ServiceTarget { return s.target }
func (s Service) Enable() model.EnableIntent  { return s.enable }
func (s Service) Run() model.RunIntent        { return s.run }
func (s Service) Packages() []PackageRef      { return append([]PackageRef(nil), s.packages...) }

type Via struct {
	backend  binding.PackageBackendID
	packages []PackageRef
}

func (v Via) Backend() binding.PackageBackendID { return v.backend }
func (v Via) Packages() []PackageRef            { return append([]PackageRef(nil), v.packages...) }

func admitNative(raw rawTarget, accounts map[string]model.AccountKey) ([]PackageRef, []Service, []Via, error) {
	packages, err := parsePackageList("packages", raw.Packages)
	if err != nil {
		return nil, nil, nil, err
	}
	services, servicePackages, err := admitServices(raw.Services, accounts)
	if err != nil {
		return nil, nil, nil, err
	}
	all := make(map[string]PackageRef)
	for _, ref := range append(packages, servicePackages...) {
		all[packageRefKey(ref)] = ref
	}
	via, providerPackages, err := admitVia(raw.Via, all)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ref := range providerPackages {
		all[packageRefKey(ref)] = ref
	}
	packages = sortedPackageRefs(all)
	edges := len(providerPackages)
	for _, service := range services {
		edges += len(service.packages)
	}
	if len(packages)+len(services) > maxResources {
		return nil, nil, nil, diagnostic("Limit", "", "native resource limit exceeded")
	}
	if edges > maxEdges {
		return nil, nil, nil, diagnostic("Limit", "", "native dependency edge limit exceeded")
	}
	return packages, services, via, nil
}

func parsePackageList(field string, raw []string) ([]PackageRef, error) {
	if raw != nil && len(raw) == 0 {
		return nil, diagnostic("InvalidValue", field, "explicit empty package list")
	}
	seen := make(map[string]PackageRef, len(raw))
	for index, value := range raw {
		ref, err := parsePackageRef(value)
		if err != nil {
			return nil, diagnostic("InvalidValue", fmt.Sprintf("%s[%d]", field, index), err.Error())
		}
		key := packageRefKey(ref)
		if _, exists := seen[key]; exists {
			return nil, diagnostic("Duplicate", fmt.Sprintf("%s[%d]", field, index), "duplicate package reference")
		}
		seen[key] = ref
	}
	return sortedPackageRefs(seen), nil
}

func parsePackageRef(value string) (PackageRef, error) {
	backend, name, qualified := strings.Cut(value, ":")
	if !qualified {
		if err := binding.ValidatePackageName(value); err != nil {
			return PackageRef{}, err
		}
		return PackageRef{name: value}, nil
	}
	backendID, err := binding.NewPackageBackendID(backend)
	if err != nil {
		return PackageRef{}, err
	}
	id, err := binding.NewPackageID(backendID, name)
	if err != nil {
		return PackageRef{}, err
	}
	return PackageRef{name: id.Name(), exact: id}, nil
}

func parseServiceRef(value string) (ServiceRef, error) {
	backend, name, qualified := strings.Cut(value, ":")
	if !qualified {
		if err := binding.ValidateServiceName(value); err != nil {
			return ServiceRef{}, err
		}
		return ServiceRef{name: value}, nil
	}
	backendID, err := binding.NewServiceBackendID(backend)
	if err != nil {
		return ServiceRef{}, err
	}
	id, err := binding.NewServiceID(backendID, name)
	if err != nil {
		return ServiceRef{}, err
	}
	return ServiceRef{name: id.Name(), exact: id}, nil
}

func admitServices(raw map[string]rawService, accounts map[string]model.AccountKey) ([]Service, []PackageRef, error) {
	if raw != nil && len(raw) == 0 {
		return nil, nil, diagnostic("InvalidValue", "services", "explicit empty services table")
	}
	services := make([]Service, 0, len(raw))
	var allPackages []PackageRef
	for _, name := range sortedKeys(raw) {
		field := "services." + name
		id, err := parseServiceRef(name)
		if err != nil {
			return nil, nil, diagnostic("InvalidValue", field, err.Error())
		}
		item := raw[name]
		target, err := admitServiceTarget(field+".target", item.Target, accounts)
		if err != nil {
			return nil, nil, err
		}
		if item.Enabled == nil && item.Running == nil {
			return nil, nil, diagnostic("InvalidValue", field, "service must own enabled or running")
		}
		packages, err := parsePackageList(field+".packages", item.Packages)
		if err != nil {
			return nil, nil, err
		}
		services = append(services, Service{
			id: id, target: target, enable: enableIntent(item.Enabled), run: runIntent(item.Running), packages: packages,
		})
		allPackages = append(allPackages, packages...)
	}
	return services, allPackages, nil
}

func admitServiceTarget(field, raw string, accounts map[string]model.AccountKey) (model.ServiceTarget, error) {
	if raw == "system" {
		return model.SystemServiceTarget(), nil
	}
	kind, name, ok := strings.Cut(raw, ":")
	if !ok || kind != "user" || name == "" || strings.Contains(name, ":") {
		return nil, diagnostic("InvalidValue", field, "target must be system or user:ACCOUNT")
	}
	account, exists := accounts[name]
	if !exists {
		return nil, diagnostic("MissingReference", field+".user", "account is not declared")
	}
	target, err := model.UserServiceTarget(account)
	if err != nil {
		return nil, diagnostic("InvalidValue", field, err.Error())
	}
	return target, nil
}

func admitVia(raw map[string][]string, demanded map[string]PackageRef) ([]Via, []PackageRef, error) {
	if raw != nil && len(raw) == 0 {
		return nil, nil, diagnostic("InvalidValue", "via", "explicit empty via table")
	}
	entries := make(map[string]Via, len(raw))
	for _, name := range sortedKeys(raw) {
		backend, err := binding.NewPackageBackendID(name)
		if err != nil {
			return nil, nil, diagnostic("InvalidValue", "via."+name, err.Error())
		}
		packages, err := parsePackageList("via."+name, raw[name])
		if err != nil {
			return nil, nil, err
		}
		entries[name] = Via{backend: backend, packages: packages}
	}
	state := make(map[string]uint8)
	used := make(map[string]struct{})
	providers := make(map[string]PackageRef)
	var visit func(string) error
	visit = func(name string) error {
		entry, exists := entries[name]
		if !exists {
			return nil
		}
		if state[name] == 1 {
			return diagnostic("Cycle", "via."+name, "package backend bootstrap cycle")
		}
		if state[name] == 2 {
			return nil
		}
		state[name] = 1
		used[name] = struct{}{}
		for _, ref := range entry.packages {
			providers[packageRefKey(ref)] = ref
			if exact, ok := ref.Exact(); ok {
				if err := visit(exact.Backend().String()); err != nil {
					return err
				}
			}
		}
		state[name] = 2
		return nil
	}
	for _, ref := range demanded {
		if exact, ok := ref.Exact(); ok {
			if err := visit(exact.Backend().String()); err != nil {
				return nil, nil, err
			}
		}
	}
	for name := range entries {
		if _, ok := used[name]; !ok {
			return nil, nil, diagnostic("InvalidValue", "via."+name, "via backend is unreachable")
		}
	}
	result := make([]Via, 0, len(used))
	for _, name := range sortedKeys(used) {
		result = append(result, entries[name])
	}
	return result, sortedPackageRefs(providers), nil
}

func packageRefKey(ref PackageRef) string {
	if exact, ok := ref.Exact(); ok {
		return "exact:" + exact.Backend().String() + ":" + exact.Name()
	}
	return "host:" + ref.Name()
}

func sortedPackageRefs(values map[string]PackageRef) []PackageRef {
	result := make([]PackageRef, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name() != result[j].Name() {
			return result[i].Name() < result[j].Name()
		}
		return packageRefKey(result[i]) < packageRefKey(result[j])
	})
	return result
}

func enableIntent(value *bool) model.EnableIntent {
	if value == nil {
		return model.UnmanagedEnableIntent()
	}
	if *value {
		return model.EnabledIntent()
	}
	return model.DisabledIntent()
}

func runIntent(value *bool) model.RunIntent {
	if value == nil {
		return model.UnmanagedRunIntent()
	}
	if *value {
		return model.RunningIntent()
	}
	return model.StoppedIntent()
}
