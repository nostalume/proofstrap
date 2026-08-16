# Test environments

Proofstrap separates deterministic tests from native host mutation.

- `go test ./...` is the ordinary Linux test layer. Package-manager and
  service-manager adapters use injected executable and filesystem effects; native
  output is fixture data, and no host manager is invoked.
- Linux syscall and filesystem cases are owned by `_linux_test.go` files or
  `internal/linux`. They use private temporary roots and may rely on standard
  Linux executables, but do not change packages, services, users, repositories,
  or network configuration.
- `cmd/proofstrap/install_test.go` is a Linux installer black-box test. It runs
  `sh`, `install`, and `mv` against a private `HOME` and `TMPDIR`; download and
  release inputs are deterministic fakes.
- `test/release` builds and inspects local release artifacts without installing
  them into the developer's real home.
- `test/acceptance/run-family.sh` is the only native package/service integration
  layer. It is never run by ordinary CI. An explicit invocation creates a fresh
  sentinel-owned `systemd-nspawn` target, confines service work to a private
  network, verifies native post-state, and proves cleanup.

Unsupported hosts must fail during acceptance preflight. Tests must not skip into
real host behavior based on whichever package or service manager happens to be
installed.
