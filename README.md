# Proofstrap

Proofstrap is a declarative Linux bootstrap CLI. It turns strict, digest-pinned
configuration into a canonical Plan, requires explicit acceptance of that Plan,
then reconstructs built-in behavior from fresh host evidence before mutation.
Every attempted effect is independently observed and recorded in a durable
journal before execution advances.

Proofstrap manages modeled packages, services, accounts, groups, homes, hostname,
and timezone state. Profiles and bindings contain data only; commands, probes,
permissions, fallback, and mutation policy remain compiled behavior.

## Installation

Proofstrap requires Linux. The version-controlled [`install.sh`](install.sh)
installs a verified `amd64` or `arm64` release into `$HOME/.local/bin` by default:

```sh
curl --fail --location --show-error --silent \
  https://raw.githubusercontent.com/nostalume/proofstrap/main/install.sh \
  -o install.sh
sh install.sh
```

Set `PROOFSTRAP_INSTALL_DIR` to select another destination.

The installer verifies the outer archive and both bundled pack objects, stages a
complete content-addressed release beneath
`$PROOFSTRAP_INSTALL_DIR/.proofstrap-releases`, then atomically switches the
`proofstrap` launcher. Previous release generations remain available for
recovery. Reinstalling an already-present generation fails instead of replacing
it.

The user archive contains only the `proofstrap` runtime. Profile authors and
distributors use the separately checksummed `proofstrap-pack` archive for their
architecture; the runtime does not require that authoring tool.

Official releases bundle one semantic pack with package profiles `ca-certificates`,
`curl`, `git`, `gzip`, `tar`, and `vim`; `bootstrap-cli` composes those six
without adding behavior. The separately selected `ssh-server` profile requests
its package and the enabled/running system SSH service. One Linux binding pack
realizes these IDs for admitted backends. Run `proofstrap inspect` to obtain the
exact bundled digests for configuration; releases never expose a mutable
"latest profile" identity. Their data source and independent releases live in
the [official core-profile catalogue](https://github.com/nostalume/proofstrap-core-profiles);
Proofstrap release automation admits only its reviewed version and SHA-256 pins.

## Workflow

Release-bundled packs are acquired automatically by exact digest. Other exact
profile or binding archives may be imported into the user store, or into the
system store with `--system`:

```sh
proofstrap import --digest sha256:DIGEST /absolute/profile.pstrap
proofstrap inspect
proofstrap inspect sha256:DIGEST
proofstrap inspect --digest sha256:DIGEST /absolute/profile.pstrap
```

Build and review a canonical Plan. Bundle arguments are optional exact inputs for
digests already pinned by configuration:

```sh
proofstrap plan \
  --config /absolute/proofstrap.toml \
  --output /absolute/plan.json \
  --profile-bundle /absolute/profile.pstrap
```

Apply only the reviewed artifact and digest. A mutating Plan requires a new
journal path; a no-op Plan may omit it. The optional receipt file and standard
output receive identical canonical receipt bytes.

```sh
proofstrap apply \
  --plan /absolute/plan.json \
  --accept sha256:REVIEWED_DIGEST \
  --journal /absolute/apply.journal \
  --receipt /absolute/receipt.json
```

Plan and receipt destinations are create-exclusive: Proofstrap never replaces an
existing artifact. Exit status is `0` for convergence, `3` for verified partial
progress, `1` for blocked/stale/failed/output results, `2` for grammar or schema
errors, and `130` for cancellation before a more specific terminal result.

See the [target configuration specification](spec/config.md),
[profile and binding specification](spec/profile.md), and
[architecture](docs/architecture.md).

## Supported systems

Built-in package behavior covers Apt, Zypper, DNF5, DNF4, and APK v3. Service
behavior covers systemd and system-scope OpenRC. Distribution names are
provenance, not behavior selectors; Proofstrap admits the actual available
manager evidence.

## License

Proofstrap is licensed under the [MIT License](LICENSE).
