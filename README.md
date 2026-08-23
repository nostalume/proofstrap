# Proofstrap

Proofstrap is a declarative Linux bootstrap tool. It turns one readable desired
state document and exact profile packs into a reviewed, digest-bound Plan. The
host changes only after that exact Plan digest is accepted, and every attempted
effect is independently verified.

Proofstrap manages supported packages, services, accounts, groups, homes,
supplementary memberships, hostname, and timezone. Profiles and bindings are
non-executable data; manager detection, commands, privilege, reconciliation,
and verification remain compiled into the runtime.

Apply is ordered, durable, and honest about partial progress. It is not a
cross-domain rollback transaction. After a partial result or failure, observe
the machine again by creating a fresh Plan.

## Install the runtime

Linux `amd64` and `arm64` releases provide an installer:

```sh
curl -fLso install.sh https://github.com/nostalume/proofstrap/releases/latest/download/install.sh
sh install.sh
```

The default launcher is `$HOME/.local/bin/proofstrap`. Override its directory
with an absolute path:

```sh
PROOFSTRAP_INSTALL_DIR=/opt/proofstrap/bin sh install.sh
```

The installer verifies and atomically publishes an immutable runtime generation.
It never fetches profiles, writes configuration, Plans, or Applies.

## Acquire a workspace

The independent
[official catalogue](https://github.com/nostalume/proofstrap-core-profiles)
publishes source-complete workspaces. Follow its fixed-tag acquisition procedure
to create an absent `$HOME/.proofstrap`:

```text
$HOME/.proofstrap/
├── proofstrap.toml       user-owned machine intent
├── core.toml             readable portable catalogue source
├── linux.toml            readable Linux catalogue and bindings
├── examples/             complete selectable targets
├── packs/sha256/         exact derived .pstrap objects
├── README.md
└── LICENSE
```

The outer release checksum verifies downloaded bytes against the published
value. It does not independently establish publisher trust. Runtime upgrades
never touch this workspace, and catalogue acquisition never overwrites one.

## Customize without compiling

Choose an official example as `proofstrap.toml`, then edit that file. Imported
official aliases retain distributor-generated digests; users do not calculate
them. Local profiles and bindings use the same schema and linker as packed
content and are planned directly:

```toml
schema = 3
include = [{ profile = "bootstrap" }]

[profiles.bootstrap]
packages = ["curl"]

[[bind]]
package = ["apk", "apt", "dnf4", "dnf5", "zypper"]
same = ["curl"]
```

No digest or `proofstrap-pack` invocation is needed for a self-contained local
document. Compilation is only for publishing changed catalogue definitions as
reusable exact packs. See the [document specification](docs/config.md) and
[profile specification](docs/profile.md).

## Plan and Apply

Plan explicitly from the workspace or enter it first:

```sh
proofstrap plan --config "$HOME/.proofstrap/proofstrap.toml"
```

Plan finds `packs/` beside the selected config, creates `./plan.json` without
replacement, and prints a review with its digest and applicability. Planning
does not mutate the host or persist supplied packs.

Review the complete output. A mutating Plan requires effective UID zero and
explicit acceptance. Apply outputs require a directory owned by that effective
principal, so create the root-owned run directory once and key outputs by the
reviewed Plan digest:

```sh
digest=sha256:REVIEWED_PLAN_DIGEST
run=/var/lib/proofstrap/runs
sudo install -d -m 0700 "$run"
sudo proofstrap apply --plan "$PWD/plan.json" --accept "$digest" \
  --journal "$run/${digest#sha256:}.journal" \
  --receipt "$run/${digest#sha256:}.receipt.json"
```

Apply creates outputs without replacement and prints canonical receipt JSON.
Plan, journal, and receipt paths must be distinct. The CLI journal default is
`./apply.journal` and is suitable only when its parent is owned by the effective
user. Blocked, stale, malformed, or digest-mismatched Plans fail before mutation.

## Maintain and update

`proofstrap.toml` is personal source truth; commit or back it up. Packs, Plans,
journals, and receipts are exact artifacts, not editing surfaces.

To update the official catalogue, acquire the new fixed release into a separate
absent directory. Review changed source, examples, and exact pins; reapply the
personal selection and local declarations; then Plan from that staged workspace.
Keep the old workspace until the new Plan is accepted. There is no implicit
merge, moving tag, fallback, or runtime-managed update.

## Exact pack resolution

Config `sources` map readable local aliases to exact `sha256:` identities. An
alias is not a path, version, repository, provider, or global namespace.
`linux:sway` selects profile `sway` from the exact semantic pack named by local
alias `linux`; one pack may contain many profiles.

Explicit `--pack-file` archives populate the initial inventory. Remaining
objects are resolved across the deterministic set of `packs/` beside the config
and explicit `--pack-store` roots. A store root contains `sha256/`. Proofstrap
opens only demanded `<digest>.pstrap` objects, hashes complete compressed bytes,
validates every present exact copy, and recursively admits manifest requirements.
It never scans for names, fetches remotely, or falls back to source TOML.

## Commands

```text
proofstrap plan [--config FILE] [--output PLAN]
  [--pack-store DIR [DIR ...]] [--pack-file FILE [FILE ...]]

proofstrap apply [--plan PLAN] --accept sha256:DIGEST
  [--journal FILE] [--receipt FILE]

proofstrap inspect [--digest sha256:DIGEST] ARCHIVE

proofstrap import [--digest sha256:DIGEST] [--system] ARCHIVE

proofstrap-pack build --input FILE --output DIR
```

Run `proofstrap <command> --help` for defaults, effects, output, and an example.
`inspect`, `import`, explicit stores, and `proofstrap-pack` are advanced archive,
storage, or distribution operations; the ordinary workspace path needs none of
them. Import does not select a profile or make a store implicit.

## Status and platform boundary

| Code | Meaning |
| ---: | --- |
| `0` | Success or converged. |
| `1` | Blocked, stale, failed, or publication failure. |
| `2` | Invalid CLI, document, or Plan. |
| `3` | Verified partial progress; create a fresh Plan. |
| `130` | Canceled. |

The runtime targets Linux. Package adapters cover Apt, Zypper, DNF5, DNF4, and
APK v3. Service adapters cover systemd and system-scope OpenRC. Managers are
selected from admitted control-plane evidence, never a distribution-name map.
See [architecture.md](docs/architecture.md) for authority and failure boundaries.

## License

[MIT](LICENSE)
