# Proofstrap

Proofstrap is a declarative Linux bootstrap tool. It resolves one schema-3
document and exact profile packs into a reviewed, digest-bound Plan. It mutates
the host only when that exact digest is accepted, and independently verifies
every attempted effect.

It manages supported packages, services, accounts, groups, homes,
supplementary memberships, hostname, and timezone. Profiles and bindings are
non-executable data; manager detection, commands, privilege, reconciliation,
and verification remain compiled into Proofstrap.

Apply is ordered and resumable, not a cross-domain rollback transaction. A
failure can leave verified partial progress recorded in the journal; create a
fresh Plan before continuing.

## Install

Linux `amd64` and `arm64` releases provide the runtime installer:

```sh
curl -fLso install.sh https://github.com/nostalume/proofstrap/releases/latest/download/install.sh
sh install.sh
```

The default destination is `$HOME/.local/bin`. Override it with an absolute
path:

```sh
PROOFSTRAP_INSTALL_DIR=/opt/proofstrap/bin sh install.sh
```

The installer verifies and atomically publishes an immutable runtime
generation. It does not fetch profiles, write user configuration, Plan, or
Apply. Profile authors install the separately released `proofstrap-pack` tool.

## Quick start

Obtain an exact workspace from the
[official profile releases](https://github.com/nostalume/proofstrap-core-profiles/releases)
or another distributor. Verify its published outer checksum, extract it, and
keep `proofstrap.toml` beside `packs/`:

```text
workspace/
├── proofstrap.toml
└── packs/
    └── sha256/
        └── DIGEST.pstrap
```

From that directory:

```sh
proofstrap plan
```

This reads `./proofstrap.toml`, creates `./plan.json` exclusively, and prints a
review with its digest and applicability. Review it. A mutating Plan requires
root and explicit acceptance:

```sh
sudo proofstrap apply --accept sha256:REVIEWED_PLAN_DIGEST \
  --receipt receipt.json
```

Apply reads `./plan.json`, creates `./apply.journal`, validates the sealed Plan,
reconstructs built-in authority from fresh evidence, and emits canonical receipt
JSON. Plan, journal, and receipt paths must be distinct and absent when created.

## Exact source resolution

`sources` aliases are local names for exact archive digests. They are not
repositories, versions, paths, or fallback selectors. Plan opens only objects
demanded by the selected closure, in this order:

1. exact archives supplied by `--pack-file`;
2. the `packs/` directory beside the selected config;
3. content-addressed roots supplied by `--pack-store`.

A corrupt exact object is an error. No executable-adjacent, system, user,
current-directory, or remote store is searched implicitly. `--pack-store` and
`--pack-file` may be repeated or followed by several values:

```sh
proofstrap plan --pack-store ./shared-packs ./extra-packs \
  --pack-file ./custom.pstrap
```

Import is optional persistence. It does not select or activate anything; name
the resulting store explicitly during Plan.

## Commands

```text
proofstrap import [--digest DIGEST] [--system] ARCHIVE
```

Validate one archive and publish it to the user store, or the system store with
`--system`. `--digest` is an optional byte-identity assertion. Success prints
bounded structural JSON including the computed digest and persisted scope.

```text
proofstrap inspect ARCHIVE
proofstrap inspect --digest DIGEST ARCHIVE
```

Validate one local archive and print structural JSON without persistence,
semantic expansion, or host inspection.

```text
proofstrap plan [--config FILE] [--output PLAN]
  [--pack-store DIR [DIR ...]] [--pack-file FILE [FILE ...]]
```

Decode one config, resolve exact packs, observe the host, and exclusively create
a sealed Plan. Defaults are `./proofstrap.toml` and `./plan.json`. Relative
paths resolve once against the working directory. Planning never mutates the
host or persists supplied packs.

```text
proofstrap apply [--plan PLAN] --accept sha256:DIGEST
  [--journal FILE] [--receipt FILE]
```

Apply only the accepted Plan. Defaults are `./plan.json` and
`./apply.journal`. Blocked, stale, malformed, or digest-mismatched Plans fail
before mutation.

```text
proofstrap-pack build --input FILE --output DIR
```

Compile one schema-3 source document into an absent deterministic workspace.
Local declarations become content-addressed packs; imported packs are read only
from the input's sibling `packs/` store. Success prints the generated config
path. See the executable [authoring example](examples/proofstrap.toml).

## Authoring model

One schema-3 document can be a ready-to-Plan target, a complete local profile
source, or both. Official and personal sources use the same language and tool.
Local profile and binding tables are active by presence; imported packs are
named in `sources`, and imported binding packs are additionally selected by
`bindings`. There is no special custom-profile mode.

The [document specification](docs/config.md) defines root composition and
direct machine truth. The [profile and binding specification](docs/profile.md)
defines reusable semantics, references, mappings, archive identity, and limits.
The tracked example is the only complete example document; specification
snippets are fragments of that grammar.

## Official profiles

The independent
[proofstrap-core-profiles](https://github.com/nostalume/proofstrap-core-profiles)
repository distributes non-executable profiles and bindings. Its release must
state the compatible Proofstrap author/runtime release and publish exact
checksums. Distribution names do not select behavior: applicability requires a
runtime adapter for the observed manager and a selected binding for every
expanded semantic resource.

## Status and recovery

| Code | Meaning |
| ---: | --- |
| `0` | Converged successfully. |
| `1` | Blocked, stale, failed, or publication failure. |
| `2` | CLI, document, or Plan grammar error. |
| `3` | Verified partial progress; create a fresh Plan. |
| `130` | Cancellation before a more specific result. |

Proofstrap does not promise rollback across native package managers, services,
identity databases, and filesystems. The journal and receipt report the proven
prefix. Re-observe and create a fresh Plan after partial progress or failure.

The runtime currently targets Linux. Package adapters cover Apt, Zypper, DNF5,
DNF4, and APK v3. Service adapters cover systemd and system-scope OpenRC.
Managers are selected from admitted control-plane evidence, never a hard-coded
distribution-name mapping. See [architecture.md](docs/architecture.md) for the
authority and failure boundaries.

## License

[MIT](LICENSE)
