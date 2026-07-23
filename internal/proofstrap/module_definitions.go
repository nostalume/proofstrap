package proofstrap

func rawCatalogue() catalogue {
	packageOnly := func(key PackageKey) requirement { return packageRequirement{packageKey: key} }
	service := func(packageKey PackageKey, serviceKey ServiceKey, scope ServiceScope) requirement {
		return serviceRequirement{packageKey: packageKey, serviceKey: serviceKey, scope: scope}
	}
	packages := []PackageKey{
		"dbus", "wayland", "sway", "swayidle", "swaylock", "grim", "slurp", "hyprland",
		"networkmanager", "pipewire", "wireplumber", "pipewire-pulse", "alsa-utils",
		"qpwgraph", "pavucontrol", "wl-clipboard", "xclip", "xsel",
	}
	packageSet := make(map[PackageKey]struct{}, len(packages))
	for _, key := range packages {
		packageSet[key] = struct{}{}
	}
	return catalogue{
		modules: map[moduleID]moduleDefinition{
			"dbus":    {requirements: []requirement{packageOnly("dbus")}},
			"wayland": {requires: []moduleID{"dbus"}, requirements: []requirement{packageOnly("wayland")}},
			"sway": {requires: []moduleID{"wayland"}, excludes: []moduleID{"hyprland"}, requirements: []requirement{
				packageOnly("sway"), packageOnly("swayidle"), packageOnly("swaylock"), packageOnly("grim"), packageOnly("slurp"),
			}},
			"hyprland":    {requires: []moduleID{"wayland"}, requirements: []requirement{packageOnly("hyprland")}},
			"qpwgraph":    {requirements: []requirement{packageOnly("qpwgraph")}},
			"pavucontrol": {requirements: []requirement{packageOnly("pavucontrol")}},
			"wl-paste":    {requirements: []requirement{packageOnly("wl-clipboard")}},
			"xclip":       {requirements: []requirement{packageOnly("xclip")}},
			"xsel":        {requirements: []requirement{packageOnly("xsel")}},
			"network":     {requirements: []requirement{service("networkmanager", "networkmanager", SystemService)}},
			"audio": {requirements: []requirement{
				service("pipewire", "pipewire", UserService), service("wireplumber", "wireplumber", UserService),
				packageOnly("pipewire-pulse"), packageOnly("alsa-utils"),
			}},
		},
		packages: packageSet,

		services: map[ServiceKey]struct{}{"networkmanager": {}, "pipewire": {}, "wireplumber": {}},
	}
}

var production = mustCompileCatalogue(rawCatalogue())
