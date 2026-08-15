# Target configuration specification

## Status and boundary

This is the production target-config contract. The CLI accepts it only through
an explicit absolute `proofstrap plan --config` path; there is no discovery or
environment-selected configuration.

One strict TOML document owns exact source pins, binding activation, root profile
instances, and direct machine truth. Config contains no commands, probes,
filesystem/store paths, overlays, executable policy, or adapter implementation.
Admission consumes supplied bytes and performs no I/O.

Proofstrap currently targets Linux. Pure admission and graph computation remain
separate from Linux file acquisition, observation, adapters, and mutation.

## Complete shape

Root values are written before tables so their TOML ownership stays visually
clear:

~~~toml
schema = 1

bindings = ["linux"]
packages = ["curl", "flatpak:org.example.App"]
hostname = "workstation"
timezone = "Asia/Shanghai"

profiles = [
  { profile = "core:desktop", arguments = { account = { account = "alice" }, group = { group = "users" } } },
]

memberships = [
  { account = "alice", group = "audio", present = true },
]

[sources]
core = "sha256:..."
linux = "sha256:..."

[via]
flatpak = ["flatpak"]

[groups.users]
gid = 1000

[groups.audio]

[accounts.alice]
uid = 1000
group = "users"
home = "/home/alice"
mode = "0700"
shell = "/bin/bash"
locked = true

[services.dbus]
target = "system"
packages = ["dbus"]
running = true
~~~

Every root field is optional except `schema = 1`, but the document must request
some desired state. Explicitly empty plural fields or tables fail.

## Sources, bindings, and profiles

`sources` maps a config-local Symbol alias to one exact archive digest. It does
not repeat archive kind, namespace, version, path, URL, registry, or store scope.
Every source alias must be used by `bindings` or `profiles`.

`bindings` is a non-empty list of source aliases when present. Activation does
not assert source kind; exact loading later requires a Binding archive.

Each `profiles` entry has one `source-alias:ProfileID` and, only when needed,
typed arguments:

~~~toml
profiles = [
  { profile = "core:desktop", arguments = { account = { account = "alice" } } },
]
~~~

Argument values are exactly `{ account = "NAME" }` or `{ group = "NAME" }`.
They reference resources declared by this config and never create them. Later
profile resolution checks exact parameter names and kinds.

## Native references and host detection

Direct native references use:

~~~text
name                 -> name on the detected host backend
backend:name         -> exact backend and native name
~~~

Only the first colon separates backend from name. A native name containing a
colon must be qualified; `zypper:libfoo:amd64` means backend `zypper` and name
`libfoo:amd64`.

There is no configured default backend. An unqualified reference remains a
typed Host reference after config admission. Later Linux observation resolves
it through exactly one admitted host/system adapter for that domain. A qualified
reference remains an Exact reference and bypasses host-backend selection.

Detection runs only for demanded unqualified domains. It probes supported
adapter control planes rather than mapping `/etc/os-release` distribution names
to behavior. No admitted candidate is Unsupported; several candidates are
Ambiguous; incomplete or contradictory evidence fails closed. Auxiliary package
backends such as Flatpak do not compete to become the host/system package
backend. Service detection is target-aware: system and user targets are admitted
against their actual observable managers independently.

The sealed Plan records the resolved backend, adapter identity, executable
identity, version, and required control-plane evidence. Apply re-observes these
facts; drift is stale. Detection adapts mechanism only. Native package names
that vary between distributions remain semantic-profile and binding authority,
not guessed aliases in direct config.

Package presence is an orderless non-empty list:

~~~toml
packages = ["curl", "flatpak:org.example.App"]
~~~

Equal Host references and equal Exact references deduplicate during config
admission. Host and Exact references remain distinct until observation resolves
Host; the later atomic native merge then deduplicates or reports conflicts.

## Services

~~~toml
[services.dbus]
target = "system"
packages = ["dbus"]
running = true

[services."systemd:pipewire"]
target = "user:alice"
enabled = true
running = true
~~~

The table key is a native service reference. Target is required and is exactly
`"system"` or `"user:declared-account"`. One string type keeps admission typed
without a custom TOML parser. `enabled` and `running` are
independent optional axes; at least one is required. Omission is unmanaged,
true is enabled/running, and false is disabled/stopped.

Optional service `packages` requests those packages present and creates their
closed delivery edges to the service. It is non-empty when present. A service
may require several packages and one package may deliver several services; the
reverse lookup is derived rather than authored.

## Package-backend bootstrap

~~~toml
[via]
flatpak = ["flatpak"]
~~~

`via.BACKEND` is a non-empty list of packages that can make that package backend
usable. Providers are implicitly requested. An unqualified provider uses the
detected host package backend; an exact provider uses its named backend. The
engine observes the requested backend first, converges providers only when
needed, and re-observes before dependent work.

Every `via` entry must be reachable from a requested package backend. Provider
references may induce another `via` step. Missing providers, unsupported
adapters, failed re-observation, and cycles—including self-provision—block
dependent work. A multi-manager bootstrap is an ordered, evidenced deployment,
not one globally reversible host transaction. There is no equivalent mechanism
for replacing or installing the host service manager.

## Accounts, groups, and host truth

Table keys supply identity; names are not repeated:

~~~toml
[groups.users]
gid = 1000

[groups.audio]

[accounts.alice]
uid = 1000
group = "users"
home = "/home/alice"
shell = "/bin/bash"
mode = "0700"
locked = true
~~~

A group with `gid` is managed; without it, external. An account with any of
`uid`, primary `group`, or `home` must provide all three and is managed; without
all three, external. `shell`, `mode`, and `locked` remain separate desired
resources despite their compact nesting. Mode requests home presence and exact
mode. `locked = false` is invalid because unlock intent is not modeled.

Memberships retain the profile-aligned form and require declared endpoints:

~~~toml
memberships = [
  { account = "alice", group = "audio", present = true },
]
~~~

Root `hostname` and `timezone` use the same model constructors and spelling as
profiles. They express exact supported Linux invariants without naming systemd
or another mutator. Missing safe adapter capability is Unsupported.

## Dependency and equality laws

The language has no generic `requires`, `depends_on`, capability, alternative,
or probe construct. Authored edges are only closed domain laws: service package
delivery, package-backend `via`, and identity/home/membership relationships.
Package-to-package dependencies such as a compositor's Wayland, X11, DBus, or
library requirements remain package-manager metadata.

Equal desired truth for one admitted reference identity deduplicates and retains
all provenance. Unequal truth conflicts. Host and Exact native references are
different identities until host evidence resolves them. After resolution, the
atomic native merge deduplicates equal exact truth and rejects unequal truth.
Order never decides a conflict and dependency collections compare as sets.
Resolved native service identity is backend, name, and target; lifecycle axes
and delivering packages are desired truth.

## Admission, limits, and diagnostics

Config bytes are non-empty and at most 1 MiB. Limits are 64 source aliases,
4,096 root instances, 16 arguments per root, 32,768 canonical resources, and
131,072 dependency edges. Small counters charge during admission; minimal input
does not preallocate maxima.

Unknown fields fail strict TOML decoding. Admission returns the first error in
canonical traversal order as a config-local diagnostic with category, field,
reliable line/column, and detail. Categories are `Syntax`, `InvalidValue`,
`MissingReference`, `Duplicate`, `Conflict`, `Cycle`, `UnusedSource`, and
`Limit`. Every failure returns the zero immutable Target.

## File boundary

The CLI requires one explicit clean absolute `--config` path, opens the selected
regular file once, and reads at most 1 MiB plus one overflow byte before pure
decoding. There is no environment, working-directory, or user-directory config
discovery.

There are no fragments, directories, overlays, includes, stdin, URLs,
environment interpolation, alternate schemas, or positional desired state.
