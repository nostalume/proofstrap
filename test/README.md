# Test boundaries

Proofstrap keeps three different claims separate:

- `go test ./...` proves deterministic core and adapter contracts. Native
  package and service commands are injected effects backed by fixtures.
- `test/release.sh DIST_DIR` proves a built release is structurally exact and
  executable on the current native Linux architecture. It inspects explicit
  archives and imports only into private `HOME`, `XDG_DATA_HOME`, and `TMPDIR`.
  It does not inspect the host, plan mutations, or invoke a native manager.
- Native package/service qualification is release evidence for an exact
  rootfs, package manager, and init pair. It is not ordinary CI and is added
  only with its digest-pinned offline case.

`cmd/proofstrap/install_test.go` separately proves installer publication and
rollback against deterministic fake downloads and private filesystem roots.
`test/performance.sh` records binary/archive sizes and bounded benchmark samples;
it is measurement, not correctness evidence.
