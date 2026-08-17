# Proofstrap

Proofstrap is a declarative Linux bootstrap tool. It reads one strict,
digest-pinned configuration, observes the host, and writes a canonical Plan.
It mutates the machine only when that exact Plan digest is accepted later.

Proofstrap manages supported packages, services, accounts, groups, homes,
supplementary group membership, hostname, and timezone. Profiles and bindings
are non-executable data. Detection, commands, privilege, reconciliation,
verification, and failure policy remain compiled into the runtime.

Every effect is guarded by fresh evidence and independently post-verified.
Apply is ordered and resumable, not a cross-domain rollback transaction: a
failure can leave verified partial progress, which is recorded in the journal
and requires a fresh Plan.

## Installation

Proofstrap releases support Linux `amd64` and `arm64`. Download the installer
before running it:

```sh
curl --fail --location --show-error --silent \
  https://github.com/nostalume/proofstrap/releases/latest/download/install.sh \
  -o install.sh
sh install.sh
```

The default destination is `$HOME/.local/bin`. Set
`PROOFSTRAP_INSTALL_DIR` to choose another absolute destination:

```sh
PROOFSTRAP_INSTALL_DIR=/absolute/bin sh install.sh
```

The installer verifies the release archive and its two bundled pack objects,
stages a content-addressed generation under `.proofstrap-releases`, and
atomically switches the `proofstrap` launcher. It never overwrites an existing
generation. Older generations remain available for manual recovery.

The user release contains the `proofstrap` runtime. Profile authors use the
separate `proofstrap-pack` release archive; the runtime installation does not
include that authoring command.

## Quick start

### 1. Inspect the bundled packs

```sh
proofstrap inspect
```

`inspect` emits JSON. A release record reports an exact digest, archive kind,
requirements, members, and storage scopes. The current official packs are:

```text
semantic  sha256:ec73d6e2c7e9c9ad87d9ec19034c51785af431f4e4328d432b35cbce85085197
binding   sha256:b1d58cc6d64b2b83296e354cd3441b71ab25f5f77f34da6c6140b762c318d9aa
```

### 2. Write a target configuration

Create `proofstrap.toml` in the working directory:

```toml
schema = 2

bindings = ["linux"]
profiles = [{ profile = "core:bootstrap-cli" }]

[sources]
core = "sha256:ec73d6e2c7e9c9ad87d9ec19034c51785af431f4e4328d432b35cbce85085197"
linux = "sha256:b1d58cc6d64b2b83296e354cd3441b71ab25f5f77f34da6c6140b762c318d9aa"
```

Config aliases such as `core` and `linux` are local names. Desired truth is the
exact digest, not a repository, release tag, path, or mutable latest version.

### 3. Build and review a Plan

```sh
proofstrap plan \
  --config proofstrap.toml \
  --output plan.json
```

The command creates `plan.json` exclusively and prints a review like:

```text
status: applicable
digest: sha256:...
checkpoints: ...
operation: ...
```

Do not apply a blocked Plan. Review the operations and retain the printed
digest. `progressable` means the Plan contains a verified barrier and may
intentionally stop after partial progress so the next invocation can replan
from fresh host state.

An archive path may supply bytes for a digest already pinned by config:

```sh
proofstrap plan \
  --config proofstrap.toml \
  --output plan.json \
  --profile-bundle packs/custom.pstrap
```

`--profile-bundle` does not change config truth and may be repeated.

### 4. Apply the accepted Plan

A mutating Plan requires effective UID 0 and a new journal path:

```sh
sudo "$HOME/.local/bin/proofstrap" apply \
  --plan plan.json \
  --accept sha256:REVIEWED_PLAN_DIGEST \
  --journal apply.journal \
  --receipt receipt.json
```

Apply reopens and validates the sealed Plan, checks the acceptance digest,
reconstructs executable and host authority, then performs ordered effects.
Canonical receipt JSON is always written to standard output; `--receipt`
optionally creates the same bytes as a file. A no-op Plan may omit `--journal`.

Plan, journal, and receipt paths must be distinct. Output files are
create-exclusive and are never silently replaced.

## Commands

### `proofstrap import`

```text
proofstrap import --digest DIGEST [--system] ARCHIVE
```

Verify an archive against `DIGEST`, admit its structure, and publish it into the
content-addressed user store. `--system` selects the system store. Importing a
binding does not activate it; config must select its source alias in
`bindings`.

### `proofstrap inspect`

```text
proofstrap inspect [DIGEST | --digest DIGEST ARCHIVE]
```

- No argument lists visible stored and release-bundled packs.
- `DIGEST` selects one visible stored pack.
- `--digest DIGEST ARCHIVE` verifies and inspects an archive without
  importing it.

Output is bounded structural JSON; it does not expand profiles or inspect host
state.

### `proofstrap plan`

```text
proofstrap plan --config FILE --output PLAN \
  [--profile-bundle ARCHIVE ...]
```

Read one regular config file once, resolve exact pack inputs, observe required
host capabilities, and create a sealed canonical Plan. Planning performs no
host mutation. Relative artifact paths are resolved once against the process
working directory and passed onward as clean absolute paths.

### `proofstrap apply`

```text
proofstrap apply --plan PLAN --accept sha256:DIGEST \
  [--journal FILE] [--receipt FILE]
```

Apply only the accepted Plan. A Plan containing effects requires root and a new
journal. Blocked, stale, malformed, or digest-mismatched Plans fail before
mutation.

### `proofstrap-pack build`

```text
proofstrap-pack build --input ABSOLUTE_DIR --output ABSOLUTE_FILE
```

Build one deterministic semantic or binding `.pstrap` archive from a strict
source directory. This command belongs to the separately distributed author
tool.

## Configuration

Proofstrap accepts one TOML schema and performs no config discovery, merging,
includes, interpolation, URL loading, or environment substitution:

```toml
schema = 2
```

Every field other than `schema` is optional, but the document must request some
desired state. Sources, bindings, and `via` only support desired state and do
not make an otherwise empty config valid. Explicitly empty plural fields are
invalid. Unknown fields fail. Schema 1 is unsupported and is not reinterpreted.

### Sources, bindings, and profiles

```toml
bindings = ["linux"]
profiles = [
  { profile = "core:bootstrap-cli" },
  { profile = "custom:user-audio", arguments = { owner = "alice", audio = "audio" } },
]

[sources]
core = "sha256:..."
custom = "sha256:..."
linux = "sha256:..."
```

`sources` maps local aliases to exact pack digests. `bindings` activates exact
binding packs. Each profile reference is `source-alias:profile-id`.

Profile argument names and account/group kinds come from the exact selected
semantic pack. Each scalar value must resolve to a matching identity declared
in the same config. The argument set must exactly match the profile parameters;
arguments do not create identities.

### Packages, services, and backend bootstrap

```toml
packages = ["curl", "flatpak:org.example.App"]

[via]
flatpak = ["flatpak"]

[services.sshd]
target = "system"
packages = ["openssh-server"]
enabled = true
running = true
```

An unqualified native name uses the detected host backend. `backend:name`
selects one exact backend. Package intent is presence-only; package removal is
not modeled.

A service target is `system` or `user:DECLARED_ACCOUNT`. `enabled` and
`running` are independent optional axes; omitted axes are unmanaged. `false`
requests disabled or stopped state, not service or package deletion. Service
`packages` request delivery packages and order them before service work.

`via.BACKEND` declares packages that can make a requested package backend
usable. It is an evidenced bootstrap relationship, not a fallback list.

### Groups, accounts, homes, and supplementary membership

Identity table keys are names:

```toml
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
supplementary = { audio = true, docker = false }
```

Identity authority is deliberately asymmetric:

- A group without `gid` is external and must already exist.
- A group with `gid` is created when absent; an existing different GID blocks.
- An account with none of `uid`, `group`, and `home` is external and must
  already exist.
- A managed account must provide all three of `uid`, primary `group`, and
  `home`. Its primary group may be managed or external; an external group's
  exact nonzero GID is sealed into the Plan and rechecked before creation. The
  account is created when absent; differing existing coordinates block.
- Partial coordinate tuples are invalid. Proofstrap does not rename identities
  or modify existing UID, GID, primary group, or passwd home.
- `shell`, `home_mode`, `locked`, and `supplementary` are independent desired
  resources and may also target a declared external account.
- `home_mode` requests home-directory presence plus its exact mode. The account's
  `home` field alone records the passwd coordinate and does not create a
  directory.
- `locked = true` requests a lock. Unlocking is not modeled.
- A newly created managed account must post-verify as locked even when the
  separate `locked` field is omitted.
- `supplementary` maps declared group names to booleans. True ensures one
  explicit `/etc/group` member edge; false removes it; omission leaves it
  unowned. Account and group deletion are not modeled.

Supplementary intent does not change or negate an account's primary group. A
configured or host-observed primary-group pair is rejected because effective
primary membership comes from the passwd GID, not the explicit `/etc/group`
member list.

Group creation precedes managed account creation. Home, shell, lock, and
supplementary membership depend on their declared identity endpoints. Each
effect is independently guarded and verified; the group is not treated as one
rollback transaction.

### Hostname and timezone

```toml
hostname = "workstation"
timezone = "Asia/Shanghai"
```

These fields request exact Linux host state without selecting an implementation
or executable in config.

The complete authoritative grammar, limits, equality rules, and diagnostics are
in the [target configuration specification](spec/config.md). Profile authoring
and archive rules are in the [profile and binding specification](spec/profile.md).

## Official core profiles

The independent
[proofstrap-core-profiles](https://github.com/nostalume/proofstrap-core-profiles)
repository owns the official non-executable catalogue. Proofstrap releases pin
and bundle exact published pack bytes; runtime config still selects them only by
digest.

The current semantic pack contains:

| Profile | Desired intent |
|---|---|
| `ca-certificates` | Install the CA certificate package. |
| `curl` | Install curl. |
| `git` | Install Git. |
| `gzip` | Install gzip. |
| `tar` | Install tar. |
| `vim` | Install Vim. |
| `bootstrap-cli` | Compose the six package profiles above. |
| `ssh-server` | Install the SSH server package and enable/start its system service. |

The current Linux binding pack maps these semantic IDs for Zypper, APK,
systemd, and OpenRC. Distribution names do not select behavior. A profile
becomes realizable only when the runtime admits the observed backend and the
active exact binding contains its mapping; runtime support for an adapter alone
does not invent a missing catalogue mapping.

Use the catalogue's immutable
[v0.1.0 release](https://github.com/nostalume/proofstrap-core-profiles/releases/tag/v0.1.0)
for independently distributed pack assets and checksums.

## Exit status and recovery

| Status | Meaning |
|---:|---|
| `0` | Converged successfully. |
| `1` | Blocked, stale, failed, or output publication failure. |
| `2` | CLI grammar, config, or Plan schema error. |
| `3` | Verified partial progress; create a fresh Plan. |
| `130` | Cancellation before a more specific terminal result. |

Proofstrap does not claim rollback over native package managers, services,
identity databases, and filesystems. The durable journal and canonical receipt
record what was attempted and verified. Re-observe and create a fresh Plan after
partial progress or failure.

## Supported systems

The runtime currently targets Linux. Built-in package adapters cover Apt,
Zypper, DNF5, DNF4, and APK v3. Service adapters cover systemd and system-scope
OpenRC. Host behavior is selected from admitted manager evidence, not from a
hard-coded distribution-name mapping.

See [architecture.md](docs/architecture.md) for ownership, Plan/Apply, journal,
and failure-domain details.

## License

Proofstrap is licensed under the [MIT License](LICENSE).
