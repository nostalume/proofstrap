# Proofstrap

## Goal

Proofstrap is a declarative Linux bootstrap CLI. It turns selected capabilities and optional explicit account intent into a reviewed, digest-bound plan; applies only accepted plans; and verifies every attempted system effect. It manages supported system packages and services, not dotfiles or user-owned application configuration.

## Tech stack

- Linux
- Go 1.26.5
- Go standard library
- `github.com/pelletier/go-toml/v2` for strict TOML decoding
- Go `testing` with table-driven, side-effect-free tests
- `go-check-sumtype` for sealed sum-type exhaustiveness
- GitHub Actions for continuous integration and tagged Linux releases
