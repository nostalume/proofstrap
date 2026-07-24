# Proofstrap

Proofstrap is a declarative Linux bootstrap CLI. You choose system capabilities and exact host settings, Proofstrap inspects the host, and it produces a digest-bound plan before changing anything. An accepted plan is rebuilt from fresh evidence at apply time, and every attempted hostname, timezone, package, service, account, group, or home change is observed again afterward.

Proofstrap manages supported system packages, services, and exact hostname and timezone establishment. It does not manage dotfiles, desktop application settings, clocks, RTC policy, NTP policy, disks, bootloaders, or general machine configuration.

## Installation

Proofstrap requires Linux. Prebuilt releases are static executables and do not require Go.

The version-controlled [`install.sh`](install.sh) installs the latest `amd64` or `arm64` release with `curl`, `sha256sum`, and `tar`. Download it so you can inspect the installer before running it:

```sh
curl --fail --location --show-error --silent \
  https://raw.githubusercontent.com/nostalume/proofstrap/main/install.sh \
  -o install.sh
sh install.sh
```

The Linux-only installer defaults to `$HOME/.local/bin`; set `PROOFSTRAP_INSTALL_DIR` to choose another destination. It requires exactly one checksum row for the selected archive, verifies the archive before reading its fixed executable member, and publishes through a same-directory atomic rename only after successful verification. A failed write cannot replace an existing binary. Ensure the chosen directory is on `PATH`. Tagged archives, `checksums.txt`, and `install.sh` are also available on the GitHub Releases page.

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

Use `--config` when host settings, account intent, or a reusable module selection is needed:

```toml
modules = ["audio"]

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

```sh
proofstrap plan --config ./proofstrap.toml
proofstrap apply --config ./proofstrap.toml --accept sha256:<reviewed-digest>
```

Use either positional module IDs or `--config`, not both. Config decoding is strict: unknown fields are rejected. A desired hostname must be lowercase ASCII DNS-style syntax and at most 64 bytes. Proofstrap independently observes `/etc/hostname` and the kernel runtime hostname; a required systemd change sets only static and transient names, verifies both, and returns `replan_required`. A desired timezone uses systemd's relative zone-name grammar. Proofstrap observes the `/etc/localtime` symlink, requires its canonical target to remain under `/usr/share/zoneinfo`, verifies a regular file, and reads only the `TZif` header; UTC remains valid when no UTC zonefile is installed. A required systemd change runs noninteractively through `timedatectl`, verifies the resulting state, and returns `replan_required`. Because timedated may update the hardware clock when its live `LocalRTC` property is true, timezone mutation requires fresh `LocalRTC=false` evidence immediately before execution. Account creation is deliberately create-only and proceeds through separate primary-group, locked-account, and home transitions with a fresh plan after each verified effect. Proofstrap does not repair an existing identity, set a usable password, or manage supplementary memberships.

## Supported systems

Proofstrap recognizes direct package installation through Apt, Pacman, Zypper, DNF5, and DNF4. Apt and Pacman also support explicit package-root repair. `curl`, `git`, and `vim` are package-only bootstrap capabilities. Service, hostname, and timezone mutation are systemd-only; already exact host settings remain independently reviewable without admitting mutators. `network` and `audio` are the current package-backed service capabilities.

See [Contract introduction](docs/contracts.md) for the behavior users and integrations may rely on, and [Architecture](docs/architecture.md) for the implementation model and workflow. Project goal and stack are summarized in [Agent context](docs/AGENT.md).

## License

Proofstrap is licensed under the [MIT License](LICENSE).
