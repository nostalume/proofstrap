# Proofstrap

Proofstrap is a declarative Linux bootstrap CLI. You choose system capabilities, Proofstrap inspects the host, and it produces a digest-bound plan before changing anything. An accepted plan is rebuilt from fresh evidence at apply time, and every attempted package, service, account, group, or home change is observed again afterward.

Proofstrap manages supported system packages and services. It does not manage dotfiles, desktop application settings, disks, bootloaders, or general machine configuration.

## Installation

Proofstrap requires Linux and Go 1.26.5.

Install the latest source version with Go:

```sh
go install github.com/nostalume/proofstrap/cmd/proofstrap@latest
```

Ensure `GOBIN`, or `GOPATH/bin` when `GOBIN` is unset, is on `PATH`.

Tagged releases provide Linux `amd64` and `arm64` archives on the GitHub Releases page. Download the archive for your architecture, verify it with the published `checksums.txt`, and place `proofstrap` on `PATH`.

## How to use

### List capabilities

```sh
proofstrap modules
```

### Review a plan

Select one or more capabilities:

```sh
proofstrap plan network
proofstrap plan audio
```

For a minimal server baseline, select the package-only `curl` and `git` capabilities:

```sh
proofstrap plan curl git
```

Vim is an independent opt-in capability for systems that need it:

```sh
proofstrap plan curl git vim
```

The `curl` and `git` capabilities both require the system CA certificate package; Proofstrap deduplicates that shared requirement. Capability IDs and their native package bindings are owned by Proofstrap—the configuration does not accept arbitrary package-manager names.

Planning is read-only. The output contains facts, blockers, proposed changes, and a SHA-256 digest.

### Apply an accepted plan

Pass the exact digest from the reviewed plan:

```sh
proofstrap apply --accept sha256:<reviewed-digest> network
```

Proofstrap rebuilds the plan from live evidence before applying it. If the host changed, the digest is stale and no mutation starts. Some verified foundational or package changes return `replan_required`; run `plan` again and review the new digest instead of automatically repeating Apply.

Proofstrap never prompts for privilege credentials. If sudo authentication is required, refresh it outside Proofstrap and plan again:

```sh
sudo -v
proofstrap plan network
```

### Use a configuration file

Use `--config` when account intent or a reusable module selection is needed:

```toml
modules = ["audio"]

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

```sh
proofstrap plan --config ./proofstrap.toml
proofstrap apply --config ./proofstrap.toml --accept sha256:<reviewed-digest>
```

Use either positional module IDs or `--config`, not both. Config decoding is strict: unknown fields are rejected. Account creation is deliberately create-only and proceeds through separate primary-group, locked-account, and home plans. Proofstrap does not repair an existing identity, set a usable password, or manage supplementary memberships.

## Supported systems

Proofstrap recognizes direct package installation through Apt, Pacman, Zypper, DNF5, and DNF4. Apt and Pacman also support explicit package-root repair. `curl`, `git`, and `vim` are package-only bootstrap capabilities. Service management is systemd-only; `network` and `audio` are the current package-backed service capabilities.

See [Architecture](docs/architecture.md) for the conceptual model and workflow. Project goal and stack are summarized in [Agent context](docs/AGENT.md).

## License

Proofstrap is licensed under the [MIT License](LICENSE).
