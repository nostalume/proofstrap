# Document specification

## Boundary

This is the public schema-3 document contract. A document contains declarative
truth only: exact source identities, selected roots, optional local profile and
binding declarations, and direct host/account intent. It contains no commands,
probes, store paths, URLs, overlays, executable policy, or adapter selection.

`proofstrap plan` reads `./proofstrap.toml` unless `--config FILE` replaces it.
There is no config search, merge, fragment, stdin, interpolation, or environment
substitution. Workspace placement is process input, not document truth: the
ordinary `$HOME/.proofstrap/proofstrap.toml` is selected explicitly or by first
entering that directory. Packs beside the selected config are its sibling store.

The complete executable example is [examples/proofstrap.toml](../examples/proofstrap.toml).

## Root grammar

Every document requires:

```toml
schema = 3
```

It may contain these root fields and tables:

| Field | Meaning |
| --- | --- |
| `sources = { alias = "sha256:..." }` | exact imported pack identities |
| `bindings = ["alias"]` | imported binding packs to activate |
| `include = [{ profile = "ref", arguments = {...} }]` | selected profile instances |
| `[profiles.ID]` | local reusable semantic declarations |
| `[package.BACKEND]`, `[service.BACKEND]`, `[[bind]]` | local native bindings |
| `[groups.NAME]`, `[accounts.NAME]` | direct identity and account intent |
| `hostname`, `timezone` | direct exact host intent |

The document must request desired state through `include` or direct identity,
account, hostname, or timezone resources. Sources, binding selection, and local
declarations alone are not roots. Unknown fields, explicit empty plural values,
and any schema other than integer 3 fail.

## Sources and roots

Aliases and profile IDs use the common `Symbol` grammar: 1–63 characters,
starting with lowercase ASCII, followed by lowercase ASCII, digits, or `-`.

```toml
include = [
  { profile = "core:desktop", arguments = { account = "alice" } },
  { profile = "local-tools" },
]
bindings = ["linux"]

[sources]
core = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
linux = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
```

`alias:profile` refers to an imported semantic pack. An unqualified profile is
local. Root arguments are non-empty string maps whose keys exactly match the
selected profile parameters. Account/group arguments name identities declared
in the same document; profile arguments name a local or qualified profile.

Every declared source must be used by a root, a transitive reference, or a
selected binding. `bindings` names declared sources and is required only for
imported binding packs. Local binding declarations are active by presence.
Aliases do not enter semantic identity; their exact digest and referenced symbol
do. Official examples already contain distributor-generated pins; ordinary
users do not calculate them. Changing a pin is an explicit catalogue update.

## Local declarations

`[profiles]`, `[package]`, `[service]`, and `[[bind]]` use exactly the grammar in
[profile.md](profile.md). Local and packed bodies pass through the same
admission and linking logic. Local references are unqualified; imported
semantic references use `alias:symbol`.

Plan admits local declarations directly; personal customization requires no
compile or digest. `proofstrap-pack build` is the separate distribution path: it
promotes local bodies into content-addressed packs and writes a generated target
with exact source digests. It preserves expanded meaning and never writes
manifests or digests back into the author input.

## Direct identity and host intent

Table keys supply names; names are not repeated as fields:

```toml
hostname = "workstation"
timezone = "Asia/Shanghai"

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
```

A group with `gid` is managed; without it, external. A managed group cannot use
GID zero. An account is managed only when `uid`, `group`, and `home` are all
present; with none of them it is external. Partial coordinates, UID zero,
undeclared primary groups, and `root` identity ownership fail.

`home_mode`, `shell`, `locked`, and `supplementary` are independent desired
resources and may target a declared external account. `home_mode` is four octal
characters and also requests home presence. Only `locked = true` is supported.
Supplementary entries require declared groups: true ensures the explicit member
edge, false removes it, and omission leaves it unmanaged. A primary group cannot
also be an authored supplementary edge. Account and group deletion, rename,
unlock, and coordinate mutation are not modeled.

Hostname and timezone request exact supported Linux state without selecting an
implementation.

## Admission and identity laws

The input is non-empty UTF-8 and at most 1 MiB. It admits at most 64 source
aliases, 32,768 combined semantic/direct resources, and 131,072 dependency
edges. Profile and binding sublimits are specified in [profile.md](profile.md).

Admission is strict and atomic. Equal desired resources deduplicate with all
provenance; unequal truth conflicts. Collections are order-insensitive after
admission. References and dependencies are validated before any host I/O.
Diagnostics contain a category, field, detail, and TOML line/column when the
decoder provides it. Important categories include `Syntax`,
`UnsupportedSchema`, `InvalidValue`, `MissingReference`, `Duplicate`,
`Conflict`, `Cycle`, `UnusedSource`, and `Limit`.

Plan canonicalizes the selected config path, opens one regular file once, and
reads bounded bytes before pure decoding. Source acquisition is a later exact
I/O boundary described in the [README](../README.md#exact-source-resolution).
