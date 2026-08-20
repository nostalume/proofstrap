# Test boundaries

Proofstrap keeps three different claims separate:

- `go test ./...` proves deterministic core and adapter contracts. Native
  package and service commands are injected effects backed by fixtures.
- `test/release.sh DIST_DIR` proves a built release is structurally exact and
  executable on the current native Linux architecture. It inspects explicit
  archives and imports only into private `HOME`, `XDG_DATA_HOME`, and `TMPDIR`.
  It does not inspect the host, plan mutations, or invoke a native manager.
- `test/managers.sh [CASE...]` proves native package/service behavior against
  digest-pinned, offline Linux roots. With no arguments it runs all seven cases;
  explicit IDs are `package:apt`, `package:dnf4`, `package:dnf5`,
  `package:zypper`, `package:apk`, `service:systemd`, and `service:openrc`.
  Ordinary CI checks admission failures only. The opt-in workflow matrix and
  local qualification invoke this same runner.

Case bytes are selected only by `test/managers-version` and
`test/managers.sha256`. The immutable cache defaults to
`${XDG_CACHE_HOME:-$HOME/.cache}/proofstrap/cases/cases-v1`; set
`PROOFSTRAP_MANAGER_CACHE` to reuse an independently populated cache. A missing
object is downloaded to an exclusive temporary file, verified, then renamed.
A bad cached digest fails before extraction.

Package cases use private mount, PID, IPC, UTS, and network namespaces. An
ordinary user needs subordinate UID/GID ranges because APT drops privileges;
running the package cases as root does not. OpenRC uses a rootless user
namespace with its real init as PID 1. Systemd requires root, cgroup v2, and
`systemd-nspawn`; it runs directly with `--register=no`, private networking,
and no host journal link. The runner never invokes `sudo` or a host manager.

Every case performs Plan, bounded barrier re-Plan when package delivery must
precede a service, Apply with journal and receipt, independent native state
queries, and a zero-operation Plan. Cleanup records process start identities,
uses TERM with a bounded KILL fallback, rejects ambiguous residue, and deletes
only its sentinel-owned generation. Output is one machine-readable
`PASS`, `FAIL`, or `UNAVAILABLE` line per case; every non-PASS is nonzero.

`cmd/proofstrap/install_test.go` separately proves installer publication and
rollback against deterministic fake downloads and private filesystem roots.
`test/performance.sh` records binary/archive sizes and bounded benchmark samples;
it is measurement, not correctness evidence.
