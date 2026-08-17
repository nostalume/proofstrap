# Target configuration specification

## Status and boundary

This is the production target-config contract. The CLI accepts it only through
an explicit `proofstrap plan --config` path; relative spelling is resolved once
against the process working directory. There is no discovery or
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
schema = 2

bindings = ["linux"]
packages = ["curl", "flatpak:org.example.App"]
hostname = "workstation"
timezone = "Asia/Shanghai"

profiles = [
  { profile = "core:desktop", arguments = { account = "alice", group = "users" } },
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
home_mode = "0700"
shell = "/bin/bash"
locked = true
supplementary = { audio = true }

[services.dbus]
target = "system"
packages = ["dbus"]
running = true
~~~

Every root field is optional except `schema = 2`, but the document must request
some desired state. `sources`, `bindings`, and `via` are supporting authority
and do not make an otherwise empty config valid. Explicitly empty plural fields
or tables fail.

## Sources, bindings, and profiles

`sources` maps a config-local Symbol alias to one exact archive digest. It does
not repeat archive kind, namespace, version, path, URL, registry, or store scope.
Every source alias must be used by `bindings`, a root profile, or a bound
`profile_ref` argument. This is checked after typed profile binding, not during
syntax-only config admission.

`bindings` is a non-empty list of source aliases when present. Activation does
not assert source kind; exact loading later requires a Binding archive.

Each `profiles` entry has one `source-alias:ProfileID` and, only when required by
that exact profile, scalar identity arguments:

~~~toml
profiles = [
  { profile = "core:workstation", arguments = { account = "alice", desktop = "components:sway" } },
]

[sources]
core = "sha256:..."
components = "sha256:..."
~~~

The resolved semantic library supplies each parameter's account, group, or
profile-reference kind. Account and group values name identities declared by
this config. A profile value is exactly `source-alias:ProfileID`; its alias must
name a pinned semantic source and the profile must exist there.
Resolution requires the exact parameter set and rejects missing, extra,
wrong-kind, or undeclared references. `arguments` is omitted for a parameterless
profile and is non-empty when present. Aliases are config-local authority:
canonical graph and provenance identity retain the selected digest/profile,
not the alias spelling. There are no categories, providers, defaults, fallback,
discovery, or backtracking.

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
home_mode = "0700"
locked = true
supplementary = { audio = true, docker = false }
~~~

A group with `gid` is managed; without it, external. An account with any of
`uid`, primary `group`, or `home` must provide all three and is managed; without
all three, external. `shell`, `home_mode`, `locked`, and `supplementary` remain
separate desired resources despite compact nesting. `home_mode` requests home
presence and exact mode. `locked = false` is invalid because unlock intent is
not modeled. A managed account may use either a managed primary group or a
declared external group whose exact nonzero GID is observed and sealed into the
Plan; Apply rechecks it before account creation.

`supplementary` is a non-empty map from declared group names to booleans. True
ensures one explicit `/etc/group` member edge; false removes that edge; omission
leaves it unowned. It never changes effective membership through the passwd
primary GID. A configured or host-observed primary-group pair is rejected.
Account/group deletion is not modeled.

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
reliable line/column, and detail. Categories are `Syntax`,
`UnsupportedSchema`, `InvalidValue`, `MissingReference`, `Duplicate`,
`Conflict`, `Cycle`, `UnusedSource`, and `Limit`. Every failure returns the zero
immutable Target.

## File boundary

The CLI canonicalizes one explicit `--config` spelling to a clean absolute path,
opens the selected regular file once, and reads at most 1 MiB plus one overflow
byte before pure decoding. Relative spelling uses the process working directory;
there is no environment or user-directory config discovery.

There are no fragments, directories, overlays, includes, stdin, URLs,
environment interpolation, compatibility schemas, or positional desired state.
Syntactically valid non-2 input receives `UnsupportedSchema`; schema 1 is not
reinterpreted.
