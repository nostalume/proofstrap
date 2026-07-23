package proofstrap

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type packageManager uint8

const (
	zypper packageManager = iota + 1
	apt
	dnf5
	pacman
	dnf4
)

func (manager packageManager) String() string {
	switch manager {
	case zypper:
		return "zypper"
	case apt:
		return "apt"
	case dnf5:
		return "dnf5"
	case pacman:
		return "pacman"
	case dnf4:
		return "dnf4"
	default:
		return "unknown"
	}
}

type packageSet map[string]struct{}

func equalPackageSet(left, right packageSet) bool {
	return len(left) == len(right) && subset(left, right)
}

func validatePackageName(name string) error {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " 	\r\n") {
		return fmt.Errorf("invalid package name %q", name)
	}
	return nil
}

type resolvedPackage struct {
	key  PackageKey
	name string
}

type packageDemand struct {
	required []resolvedPackage
}

type packageEvidence struct {
	installed packageSet
	rooted    packageSet
}

type packageBehavior struct {
	manager        packageManager
	version        string
	names          map[PackageKey]string
	inventory      func(context.Context, Runner) (packageEvidence, error)
	rootCommand    func([]string) Command
	installCommand func([]string) Command
}

func basePackageNames() map[PackageKey]string {
	return map[PackageKey]string{
		"ca-certificates": "ca-certificates", "curl": "curl", "git": "git", "vim": "vim",
		"dbus": "dbus", "wayland": "wayland", "sway": "sway", "swayidle": "swayidle", "swaylock": "swaylock",
		"grim": "grim", "slurp": "slurp", "hyprland": "hyprland", "networkmanager": "NetworkManager",
		"pipewire": "pipewire", "wireplumber": "wireplumber", "pipewire-pulse": "pipewire-pulseaudio",
		"alsa-utils": "alsa-utils",
		"qpwgraph":   "qpwgraph", "pavucontrol": "pavucontrol", "wl-clipboard": "wl-clipboard",
		"xclip": "xclip", "xsel": "xsel",
	}
}

func aptPackageNames() map[PackageKey]string {
	names := basePackageNames()
	names["networkmanager"] = "network-manager"
	names["wayland"] = "libwayland-client0"
	names["pipewire-pulse"] = "pipewire-pulse"
	delete(names, "hyprland")
	return names
}

func pacmanPackageNames() map[PackageKey]string {
	names := basePackageNames()
	names["networkmanager"] = "networkmanager"
	names["pipewire-pulse"] = "pipewire-pulse"
	return names
}

func zypperPackageNames() map[PackageKey]string {
	names := basePackageNames()
	names["dbus"] = "dbus-1"
	names["wayland"] = "libwayland-client0"
	names["git"] = "git-core"
	return names
}

func dnfPackageNames() map[PackageKey]string {
	names := basePackageNames()
	names["wayland"] = "libwayland-client"
	names["git"] = "git-core"
	names["vim"] = "vim-enhanced"
	return names
}

func dnf5PackageNames() map[PackageKey]string {
	names := dnfPackageNames()
	delete(names, "hyprland")
	return names
}

func dnf4PackageNames() map[PackageKey]string {
	names := dnfPackageNames()
	for _, key := range []PackageKey{"sway", "swayidle", "swaylock", "grim", "slurp", "hyprland", "qpwgraph", "wl-clipboard", "xclip", "xsel"} {
		delete(names, key)
	}
	return names
}

func (behavior packageBehavior) bind(selected selection) (packageDemand, []Blocker) {
	var demand packageDemand
	var blockers []Blocker
	nameFor := func(key PackageKey) (string, bool) {
		name, ok := behavior.names[key]
		return name, ok && name != ""
	}
	for _, key := range selected.packageKeys() {
		name, ok := nameFor(key)
		if !ok {
			blockers = append(blockers, Blocker{Subject: "binding:package:" + string(key), Detail: "no concrete package name"})
			continue
		}
		demand.required = append(demand.required, resolvedPackage{key: key, name: name})
	}
	return demand, blockers
}

func (behavior packageBehavior) inspect(ctx context.Context, runner Runner, demand packageDemand) packageState {
	evidence, err := behavior.inventory(ctx, runner)
	if err != nil {
		return packageBlocked{reason: "package evidence: " + err.Error()}
	}
	required := requiredSet(demand.required)
	missingPackages := difference(required, evidence.installed)
	if len(missingPackages) != 0 {
		if behavior.installCommand == nil {
			return packageBlocked{reason: "required packages are missing; package installation is not supported"}
		}
		return packageInstallChange{
			behavior: behavior, demand: demand, before: evidence, install: missingPackages,
			command: behavior.installCommand(sortedPackageSet(missingPackages)),
		}
	}
	missingRoots := difference(required, evidence.rooted)
	if len(missingRoots) == 0 {
		return packageDone{evidence: evidence}
	}
	if behavior.rootCommand == nil {
		return packageBlocked{reason: "package root mutation is not supported"}
	}
	return packageRootChange{
		behavior: behavior, demand: demand, before: evidence, root: missingRoots,
		command: behavior.rootCommand(sortedPackageSet(missingRoots)),
	}
}

func constructDNF4Behavior(paths map[string]string, version string) packageBehavior {
	return constructRPMBehavior(paths, dnf4, version, dnf4PackageNames())
}

func constructDNF5Behavior(paths map[string]string, version string) packageBehavior {
	return constructRPMBehavior(paths, dnf5, version, dnf5PackageNames())
}

func constructRPMBehavior(paths map[string]string, manager packageManager, version string, names map[PackageKey]string) packageBehavior {
	path := paths["dnf"]
	if manager == dnf5 {
		if nativePath := paths["dnf5"]; nativePath != "" {
			path = nativePath
		}
	}
	behavior := packageBehavior{
		manager: manager, version: version, names: names,
		installCommand: func(names []string) Command {
			return Command{Name: path, Args: append([]string{"install", "-y"}, names...), timeout: 10 * time.Minute}
		},
	}
	installed := Command{Name: paths["rpm"], Args: []string{"-qa", "--qf", `%{NAME}\n`}}
	rootFormat := `%{name}`
	if manager == dnf5 {
		rootFormat = `%{name}\n`
	}
	rooted := Command{Name: path, Args: []string{"repoquery", "--userinstalled", "--qf", rootFormat}}
	behavior.inventory = func(ctx context.Context, runner Runner) (packageEvidence, error) {
		result := runner.Run(ctx, installed)
		if result.Err != nil || result.ExitCode != 0 {
			return packageEvidence{}, fmt.Errorf("installed package inventory failed: %s", resultDetail(result))
		}
		installedNames, err := parsePlainPackageSet(result.Stdout)
		if err != nil {
			return packageEvidence{}, err
		}
		result = runner.Run(ctx, rooted)
		if result.Err != nil || result.ExitCode != 0 {
			return packageEvidence{}, fmt.Errorf("native package roots failed: %s", resultDetail(result))
		}
		rootedNames, err := parsePlainPackageSet(result.Stdout)
		if err != nil {
			return packageEvidence{}, fmt.Errorf("native package roots: %w", err)
		}
		if !subset(rootedNames, installedNames) {
			return packageEvidence{}, fmt.Errorf("native package roots contain names that are not installed")
		}
		return packageEvidence{installed: installedNames, rooted: rootedNames}, nil
	}
	return behavior
}

func constructAPTBehavior(paths map[string]string, version string) packageBehavior {
	return constructRootedCommandBehavior(
		apt, version, aptPackageNames(),
		Command{Name: paths["dpkg-query"], Args: []string{"-W", `-f=${binary:Package}\t${db:Status-Abbrev}\n`}},
		Command{Name: paths["apt-mark"], Args: []string{"showmanual"}},
		func(names []string) Command {
			return Command{Name: paths["apt-mark"], Args: append([]string{"manual"}, names...)}
		},
		func(names []string) Command {
			return Command{Name: paths["apt-get"], Args: append([]string{"install", "--yes", "--no-remove", "--no-install-recommends"}, names...), timeout: 10 * time.Minute}
		},
		parseAPTInstalledSet, parseAPTRootSet,
	)
}

func constructPacmanBehavior(paths map[string]string, version string) packageBehavior {
	return constructRootedCommandBehavior(
		pacman, version, pacmanPackageNames(),
		Command{Name: paths["pacman"], Args: []string{"-Qq"}},
		Command{Name: paths["pacman"], Args: []string{"-Qqe"}},
		func(names []string) Command {
			return Command{Name: paths["pacman"], Args: append([]string{"-D", "--asexplicit"}, names...)}
		},
		func(names []string) Command {
			return Command{Name: paths["pacman"], Args: append([]string{"-S", "--needed", "--noconfirm"}, names...), timeout: 10 * time.Minute}
		},
		parsePlainPackageSet, parsePlainPackageSet,
	)
}

func constructRootedCommandBehavior(
	manager packageManager,
	version string,
	names map[PackageKey]string,
	installed Command,
	rooted Command,
	rootMutation func([]string) Command,
	installMutation func([]string) Command,
	parseInstalled func(string) (packageSet, error),
	parseRooted func(string) (packageSet, error),
) packageBehavior {
	behavior := packageBehavior{manager: manager, version: version, names: names, rootCommand: rootMutation, installCommand: installMutation}
	behavior.inventory = func(ctx context.Context, runner Runner) (packageEvidence, error) {
		result := runner.Run(ctx, installed)
		if result.Err != nil || result.ExitCode != 0 {
			return packageEvidence{}, fmt.Errorf("installed package inventory failed: %s", resultDetail(result))
		}
		installedNames, err := parseInstalled(result.Stdout)
		if err != nil {
			return packageEvidence{}, err
		}
		result = runner.Run(ctx, rooted)
		if result.Err != nil || result.ExitCode != 0 {
			return packageEvidence{}, fmt.Errorf("native package roots failed: %s", resultDetail(result))
		}
		rootedNames, err := parseRooted(result.Stdout)
		if err != nil {
			return packageEvidence{}, fmt.Errorf("native package roots: %w", err)
		}
		if !subset(rootedNames, installedNames) {
			return packageEvidence{}, fmt.Errorf("native package roots contain names that are not installed")
		}
		return packageEvidence{installed: installedNames, rooted: rootedNames}, nil
	}
	return behavior
}

func constructZypperBehavior(paths map[string]string, version string) packageBehavior {
	behavior := packageBehavior{
		manager: zypper, version: version, names: zypperPackageNames(),
		installCommand: func(names []string) Command {
			return Command{Name: paths["zypper"], Args: append([]string{"--non-interactive", "install", "--no-recommends"}, names...), timeout: 10 * time.Minute}
		},
	}
	installed := Command{Name: paths["rpm"], Args: []string{"-qa", "--qf", `%{NAME}\n`}}
	behavior.inventory = func(ctx context.Context, runner Runner) (packageEvidence, error) {
		result := runner.Run(ctx, installed)
		if result.Err != nil || result.ExitCode != 0 {
			return packageEvidence{}, fmt.Errorf("installed package inventory failed: %s", resultDetail(result))
		}
		installedNames, err := parsePlainPackageSet(result.Stdout)
		if err != nil {
			return packageEvidence{}, err
		}
		automatic, err := runner.ReadFile("/var/lib/zypp/AutoInstalled")
		if err != nil {
			return packageEvidence{}, fmt.Errorf("native package roots failed: %w", err)
		}
		automaticNames, err := packageSetFromNames(strings.Fields(string(automatic)))
		if err != nil {
			return packageEvidence{}, fmt.Errorf("native package roots: %w", err)
		}
		return packageEvidence{installed: installedNames, rooted: difference(installedNames, automaticNames)}, nil
	}
	return behavior
}

func difference(left, right packageSet) packageSet {
	result := make(packageSet, len(left))
	for name := range left {
		if _, excluded := right[name]; !excluded {
			result[name] = struct{}{}
		}
	}
	return result
}

func union(left, right packageSet) packageSet {
	result := make(packageSet, len(left)+len(right))
	for name := range left {
		result[name] = struct{}{}
	}
	for name := range right {
		result[name] = struct{}{}
	}
	return result
}

//sumtype:decl
type packageState interface{ packageState() }

type packageDone struct {
	evidence packageEvidence
}
type packageRootChange struct {
	behavior packageBehavior
	demand   packageDemand
	before   packageEvidence
	root     packageSet
	command  Command
}
type packageInstallChange struct {
	behavior packageBehavior
	demand   packageDemand
	before   packageEvidence
	install  packageSet
	command  Command
}
type packageBlocked struct {
	reason string
}

func (packageDone) packageState()          {}
func (packageRootChange) packageState()    {}
func (packageInstallChange) packageState() {}
func (packageBlocked) packageState()       {}

func (change packageInstallChange) projectionFor(prepared Command) Change {
	command := Command{Name: prepared.Name, Args: append([]string(nil), prepared.Args...)}
	return Change{
		ID:      "package-install:" + change.behavior.manager.String(),
		Detail:  "install=" + strings.Join(sortedPackageSet(change.install), ","),
		Command: &command,
	}
}

func (change packageInstallChange) apply(ctx context.Context, runner Runner, prepared Command, guard packageMutationGuard) packageResult {
	if guard == nil {
		return packageResult{err: errors.New("package mutation guard is required")}
	}
	current, err := change.behavior.inventory(ctx, runner)
	if err != nil {
		return packageResult{err: err}
	}
	if !reflect.DeepEqual(current, change.before) {
		return packageResult{err: stalePrecondition{detail: "package evidence changed before installation"}}
	}
	if err := guard(); err != nil {
		return packageResult{err: err}
	}
	execution := runner.Run(ctx, prepared)
	postContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	after, observeErr := change.behavior.inventory(postContext, runner)
	cancel()
	result := packageResult{attempted: true}
	var failures []string
	if execution.Err != nil || execution.ExitCode != 0 {
		failures = append(failures, "native package installation failed: "+resultDetail(execution))
	}
	if observeErr != nil {
		failures = append(failures, "post-attempt package observation failed: "+observeErr.Error())
		result.err = errors.New(strings.Join(failures, "; "))
		return result
	}
	if !subset(change.before.installed, after.installed) {
		failures = append(failures, "package installation removed previously installed packages")
	}
	if !subset(requiredSet(change.demand.required), after.installed) {
		failures = append(failures, "required packages remain missing after installation")
	}
	expectedRooted := union(change.before.rooted, change.install)
	if !equalPackageSet(after.rooted, expectedRooted) {
		failures = append(failures, "post-attempt package roots differ from direct installation")
	}
	if len(failures) != 0 {
		result.err = errors.New(strings.Join(failures, "; "))
	}
	return result
}

func (change packageRootChange) projection() Change {
	return change.projectionFor(change.command)
}

func (change packageRootChange) projectionFor(prepared Command) Change {
	command := Command{Name: prepared.Name, Args: append([]string(nil), prepared.Args...)}
	return Change{
		ID:      "package-roots:" + change.behavior.manager.String(),
		Detail:  "root=" + strings.Join(sortedPackageSet(change.root), ","),
		Command: &command,
	}
}

func (change packageRootChange) apply(ctx context.Context, runner Runner, prepared Command, guard packageMutationGuard) packageResult {
	if guard == nil {
		return packageResult{err: errors.New("package mutation guard is required")}
	}
	expectedRooted := union(change.before.rooted, change.root)
	if !subset(requiredSet(change.demand.required), expectedRooted) {
		return packageResult{err: errors.New("root-only change does not contain every required package root")}
	}
	current, err := change.behavior.inventory(ctx, runner)
	if err != nil {
		return packageResult{err: err}
	}
	if !reflect.DeepEqual(current, change.before) {
		return packageResult{err: stalePrecondition{detail: "package evidence changed before root mutation"}}
	}
	if err := guard(); err != nil {
		return packageResult{err: err}
	}
	execution := runner.Run(ctx, prepared)
	postContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	after, observeErr := change.behavior.inventory(postContext, runner)
	cancel()
	result := packageResult{attempted: true}
	var failures []string
	if execution.Err != nil || execution.ExitCode != 0 {
		failures = append(failures, "native package root mutation failed: "+resultDetail(execution))
	}
	if observeErr != nil {
		failures = append(failures, "post-attempt package observation failed: "+observeErr.Error())
		result.err = errors.New(strings.Join(failures, "; "))
		return result
	}
	if !reflect.DeepEqual(after.installed, change.before.installed) {
		failures = append(failures, "root-only mutation changed installed packages")
	}
	if !equalPackageSet(after.rooted, expectedRooted) {
		failures = append(failures, "post-attempt package roots differ from accepted root-only change")
	}
	if len(failures) != 0 {
		result.err = errors.New(strings.Join(failures, "; "))
	}
	return result
}

func subset(left, right packageSet) bool {
	for name := range left {
		if _, ok := right[name]; !ok {
			return false
		}
	}
	return true
}

func recognizePackageBehavior(runner Runner) (packageBehavior, error) {
	type candidate struct {
		manager  packageManager
		version  string
		native   string
		behavior packageBehavior
	}
	var candidates []candidate
	var indeterminate []string
	probe := func(name string, manager packageManager, construct func(map[string]string, string) packageBehavior, dependencies ...string) {
		path, err := runner.LookPath(name)
		if err != nil {
			return
		}
		paths := map[string]string{name: path}
		for _, dependency := range dependencies {
			dependencyPath, err := runner.LookPath(dependency)
			if err != nil {
				indeterminate = append(indeterminate, fmt.Sprintf("%s is present but %s is unavailable", name, dependency))
				return
			}
			paths[dependency] = dependencyPath
		}
		result := runner.Run(context.Background(), Command{Name: path, Args: []string{"--version"}})
		if result.Err != nil || result.ExitCode != 0 {
			indeterminate = append(indeterminate, fmt.Sprintf("%s version probe failed: %s", name, resultDetail(result)))
			return
		}
		version := regexp.MustCompile(`\b\d+(?:\.\d+)+\b`).FindString(result.Stdout)
		if version == "" {
			indeterminate = append(indeterminate, fmt.Sprintf("%s version probe returned malformed evidence", name))
			return
		}
		if name == "dnf" || name == "dnf5" {
			major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
			if err != nil || major != 4 && major != 5 {
				indeterminate = append(indeterminate, fmt.Sprintf("unsupported dnf major in %q", version))
				return
			}
			if name == "dnf5" && major != 5 {
				indeterminate = append(indeterminate, fmt.Sprintf("dnf5 reported incompatible major in %q", version))
				return
			}
			if major == 5 {
				manager, construct = dnf5, constructDNF5Behavior
			} else {
				manager, construct = dnf4, constructDNF4Behavior
			}
		}
		native := ""
		if manager == dnf4 || manager == dnf5 {
			native = paths["rpm"]
		}
		candidates = append(candidates, candidate{
			manager: manager, version: version, native: native,
			behavior: construct(paths, version),
		})
	}
	probe("zypper", zypper, constructZypperBehavior, "rpm")
	probe("apt-get", apt, constructAPTBehavior, "apt-mark", "dpkg-query")
	probe("pacman", pacman, constructPacmanBehavior)
	probe("dnf5", dnf5, constructDNF5Behavior, "rpm")
	probe("dnf", dnf4, constructDNF4Behavior, "rpm")
	if len(indeterminate) != 0 {
		sort.Strings(indeterminate)
		return packageBehavior{}, fmt.Errorf("package manager evidence is indeterminate: %s", strings.Join(indeterminate, "; "))
	}
	unique := make(map[packageManager]candidate, len(candidates))
	for _, value := range candidates {
		if prior, ok := unique[value.manager]; ok {
			if prior.version != value.version {
				return packageBehavior{}, fmt.Errorf("package manager evidence is indeterminate: %s versions %s and %s", value.manager, prior.version, value.version)
			}
			if prior.native != value.native {
				return packageBehavior{}, fmt.Errorf("package manager evidence is indeterminate: %s aliases use different native inventories", value.manager)
			}
			if value.manager == dnf5 {
				if _, err := recognizeRPMDatabase(runner, value.native); err != nil {
					return packageBehavior{}, fmt.Errorf("package manager evidence is indeterminate: %w", err)
				}
			}
		}
		unique[value.manager] = value
	}
	if len(unique) == 0 {
		return packageBehavior{}, fmt.Errorf("package manager is unsupported")
	}
	if len(unique) != 1 {
		return packageBehavior{}, fmt.Errorf("package manager evidence is ambiguous: found %d behaviors", len(unique))
	}
	for _, value := range unique {
		return value.behavior, nil
	}
	panic("unreachable")
}

func recognizeRPMDatabase(runner Runner, executable string) (string, error) {
	result := runner.Run(context.Background(), Command{Name: executable, Args: []string{"--eval", "%{_dbpath}"}})
	if result.Err != nil || result.ExitCode != 0 {
		return "", fmt.Errorf("RPM database probe failed: %s", resultDetail(result))
	}
	database := strings.TrimSpace(result.Stdout)
	if database == "" || !strings.HasPrefix(database, "/") || strings.ContainsAny(database, "\r\n") {
		return "", fmt.Errorf("RPM database probe returned malformed evidence")
	}
	return database, nil
}

func requiredSet(required []resolvedPackage) packageSet {
	result := make(packageSet, len(required))
	for _, item := range required {
		result[item.name] = struct{}{}
	}
	return result
}

func packageSetFromNames(names []string) (packageSet, error) {
	result := make(packageSet, len(names))
	for _, name := range names {
		if err := validatePackageName(name); err != nil {
			return nil, err
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func parseAPTRootSet(output string) (packageSet, error) {
	names := nonemptyLines(output)
	for i, name := range names {
		names[i], _, _ = strings.Cut(name, ":")
	}
	return packageSetFromNames(names)
}

func sortedPackageSet(values packageSet) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parsePlainPackageSet(output string) (packageSet, error) {
	return packageSetFromNames(nonemptyLines(output))
}

func parseAPTInstalledSet(output string) (packageSet, error) {
	installed := make(packageSet)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed apt package inventory row %q", line)
		}
		if strings.TrimSpace(fields[1]) != "ii" {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if index := strings.LastIndex(name, ":"); index > 0 {
			name = name[:index]
		}
		if err := validatePackageName(name); err != nil {
			return nil, fmt.Errorf("invalid installed package name %q", name)
		}
		installed[name] = struct{}{}
	}
	return installed, nil
}
