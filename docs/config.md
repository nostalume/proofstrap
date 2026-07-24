# Configuration guide

Proofstrap accepts desired state as positional module IDs or as a strict TOML configuration file. Use a configuration file for reusable module selection, exact host settings, or account intent.

## Basic workflow

List the module IDs supported by the installed binary:

```sh
proofstrap modules
```

Review a configuration without changing the host:

```sh
proofstrap plan --config ./proofstrap.toml
```

Read the complete plan and copy its final `sha256:` digest. Apply the same desired state with that exact digest:

```sh
proofstrap apply \
  --config ./proofstrap.toml \
  --accept sha256:<reviewed-digest> \
  --receipt ./proofstrap-receipt.json
```

`--receipt` is optional. Apply also prints the JSON receipt to standard output.

Apply reconstructs the plan from fresh host evidence. If desired state, host evidence, effective commands, or available authority changed, the accepted digest does not match and mutation does not begin. A verified foundational change can return `replan_required`; run `plan` again, review the new plan, and accept its new digest.

Do not combine `--config` with positional module IDs. Put flags before positional module IDs.

## Configuration discovery

When no positional module IDs are supplied, Proofstrap chooses one configuration file in this order:

1. `--config PATH`
2. `PROOFSTRAP_CONFIG`
3. `./proofstrap.toml`
4. `$XDG_CONFIG_HOME/proofstrap/proofstrap.toml`, or `$HOME/.config/proofstrap/proofstrap.toml` when `XDG_CONFIG_HOME` is unset

An explicitly selected or environment-selected path must exist; Proofstrap does not silently fall back to another file. Positional module IDs use direct module-selection mode and do not load the default configuration locations.

## Complete example

```toml
modules = ["curl", "git"]

[host]
hostname = "node-1"
timezone = "Europe/Berlin"

[account]
state = "present"
name = "alice"
uid = 1000
shell = "/bin/bash"

[account.primary_group]
name = "alice"
gid = 1000

[account.home]
path = "/home/alice"
mode = "0700"
```

All sections are optional, but the resulting desired state must contain at least one module, host setting, or account intent. TOML decoding is strict: unknown or retired fields are errors.

## Fields

### `modules`

```toml
modules = ["curl", "git", "vim"]
```

`modules` is an array of Proofstrap module IDs. Duplicate IDs are deduplicated. Use `proofstrap modules` as the authority for the installed version; configurations cannot name arbitrary package-manager packages or systemd units.

The current catalogue contains:

```text
audio
curl
dbus
git
hyprland
network
pavucontrol
qpwgraph
sway
vim
wayland
wl-paste
xclip
xsel
```

Catalogue bindings and dependencies are versioned with the binary, so prefer `proofstrap modules` over copying this list into automation.

Some selection constraints are not shown by `proofstrap modules`:

- `audio` manages user-scoped PipeWire and WirePlumber services and therefore requires an explicit `[account]`. The identified target must be non-root, and Proofstrap must ultimately run with an effective UID matching that account. With `state = "present"`, first complete the primary-group, locked-account, and home replans; then run Proofstrap as that user to finish user-service reconciliation.
- `sway` and `hyprland` are mutually exclusive and cannot appear in the same desired state.

### `[host]`

```toml
[host]
hostname = "node-1"
timezone = "Etc/UTC"
```

`[host]` must contain `hostname`, `timezone`, or both.

- `hostname` is an exact lowercase ASCII DNS-style name, 1–64 bytes, with labels no longer than 63 bytes. Labels use `a-z`, `0-9`, and interior `-`; empty labels and leading or trailing `-` are rejected.
- `timezone` is a normalized relative zoneinfo path no longer than 4095 bytes, such as `Etc/UTC` or `Europe/Berlin`. Components are at most 255 bytes and use ASCII letters, digits, `_`, `+`, or `-`; absolute paths, `.`/`..`, empty components, and template syntax are rejected.

Hostname and timezone mutation require systemd. An already exact value remains reviewable without admitting a mutator. A verified host change returns `replan_required`.

### Existing account

Use `state = "existing"` to identify an account that must already exist:

```toml
[account]
state = "existing"
name = "alice"
```

An existing-account declaration accepts only `state` and `name`. It does not repair the account or accept UID, shell, group, or home fields.

### Present account

Use `state = "present"` for create-only establishment:

```toml
[account]
state = "present"
name = "alice"
uid = 1000
shell = "/bin/bash"

[account.primary_group]
name = "alice"
gid = 1000

[account.home]
path = "/home/alice"
mode = "0700"
```

A present account requires every field shown above:

- `name`: 1–32 ASCII bytes; starts with `a-z` or `_`, continues with lowercase letters, digits, `-`, or `_`, and may end with `$`; at the 32-byte limit, a final `_` is rejected
- `uid`: nonzero numeric `uint32` UID
- `shell`: canonical absolute path
- `primary_group.name`: the same grammar as the account name
- `primary_group.gid`: nonzero numeric `uint32` GID
- `home.path`: canonical absolute path
- `home.mode`: quoted four-digit octal mode from `0000` through `0777`

Account establishment is deliberately create-only. Proofstrap establishes the primary group, locked account, and home as separately reviewed transitions. After each verified foundational effect, plan again. Proofstrap does not repair an existing identity, set a usable password, or manage supplementary groups.

## Common errors

- **`cannot combine --config with module IDs`**: move all desired modules into the TOML file or use only positional IDs.
- **`flags must appear before module IDs`**: place flags before positional arguments.
- **strict-mode TOML error**: remove unknown, misspelled, or retired fields.
- **stale digest**: rerun `plan`; do not reuse an earlier digest.
- **blocked plan**: read every blocker. Resolve missing platform capability, account evidence, or noninteractive privilege authority outside Proofstrap before replanning.
- **privilege authentication required**: Proofstrap never prompts. Refresh credentials separately, for example with `sudo -v`, then rerun `plan`.