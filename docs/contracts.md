# Contract introduction

This document describes the behavior that users, operators, and integrations may rely on. It is intentionally narrower than an implementation inventory: private Go types, file placement, helper names, and native command selection may change while these contracts remain intact.

## Lifecycle

Proofstrap is a terminating bootstrap operation, not a resident manager:

```text
parse intent
-> observe demanded host state
-> reconcile
-> render a canonical review and digest
-> apply one accepted, freshly rebuilt plan
-> independently observe attempted effects
-> emit a receipt
-> exit
```

`plan` is read-only. `apply` requires the exact digest of a reviewed plan and rebuilds that plan from live evidence. Digest drift, blockers, lost authority, or stale immediate preconditions stop before the affected mutation. Proofstrap does not automatically accept or recursively apply a replacement plan.

## Intent and review

Intent consists only of supported capability IDs, exact modeled host settings, and an optional explicit account identity. Native package names, arbitrary commands, and unmodeled configuration are not accepted as desired state.

The review is a canonical public projection of:

- selected capabilities and modeled intent;
- observed facts relevant to the decision;
- blockers;
- proposed changes and effective commands;
- a SHA-256 semantic digest.

Rendered review data is not executable authority. Apply reconstructs private behavior and effective commands from intent, catalogue, current evidence, and admitted authority, then requires the reconstructed review digest to equal the accepted digest.

## Freshness and authority

Proofstrap admits only known noninteractive authority. It never prompts for credentials or refreshes a sudo/doas credential cache. Host, account, package, service, hostname, timezone, executable, and authority evidence is revalidated according to the capability that needs it; unrelated plans do not acquire unrelated host dependencies.

An accepted digest does not waive immediate guards. Drift before the first attempted action is reported as stale. Failure to observe a required guard is reported as failure rather than assumed equality.

## Mutation and verification

Mutation is bounded to modeled effects. Foundational identity and host-setting changes are isolated, and package progress that changes later decisions ends with `replan_required`. The operator must review the next plan.

A zero exit status is not proof of success. Every attempted effect receives an independent post-attempt observation, including failed and timed-out commands. Final success also requires aggregate selected package, service, conflict, account, and host invariants to remain satisfied.

Proofstrap does not promise rollback when the native operation is not atomic. Earlier verified outcomes remain visible if a later action or final aggregate verification fails.

## Receipt

The receipt is the authoritative account of an Apply attempt. It distinguishes:

- no attempted action because the accepted plan was stale or blocked;
- attempted action failure;
- command completion followed by failed verification;
- verified progress requiring a fresh plan;
- complete verified success.

Receipt status and per-action outcomes are derived from the same transition law so they cannot independently claim contradictory attempt or verification state.

## Linux filesystem boundary

Create-only home establishment uses descriptor-relative operations beneath trusted root-owned ancestors. Existing targets are not repaired. Timezone evidence canonicalizes the admitted zoneinfo target, opens every component with no-follow semantics, requires directory intermediates, opens the final component nonblocking, verifies a regular file on the same descriptor, and performs a bounded `TZif` read from that descriptor.

Proofstrap uses `golang.org/x/sys/unix` for direct Linux descriptor and secure-open operations. It retains standard-library `syscall` only where `os` or `os/exec` require its concrete types. This is an implementation dependency choice, not a portability promise; supported execution remains Linux `amd64` and `arm64`.

## Installer boundary

`install.sh` is the single maintained installer implementation. It:

- rejects non-Linux operating systems before downloading an asset;
- selects only the published Linux `amd64` or `arm64` archive name;
- requires exactly one syntactically valid manifest row for that archive;
- verifies SHA-256 before reading archive contents;
- streams only the fixed executable member into a temporary file;
- installs to a same-directory temporary file and atomically publishes only after checksum, archive, nonempty-member, and complete-write validation, preserving an existing binary on failure;
- cleans its temporary workspace on exit.

The checksum manifest and archive are delivered by the same GitHub Release. The checksum detects corruption and mismatched assets; it does not protect against compromise of the release publisher or of an installer fetched from an untrusted revision. Operators who require stronger provenance must pin and independently authenticate the installer/release source before execution.

## Explicit non-goals

Proofstrap is not:

- a dotfile or desktop-application manager;
- a general shell runner;
- an arbitrary package-name or systemd-unit API;
- a continuous reconciliation daemon;
- a clock, RTC, or NTP policy manager;
- a package removal, repository, disk, bootloader, or credential manager;
- a repair engine for mismatched existing identities or homes.

Unsupported, ambiguous, contradictory, or stale state fails closed rather than expanding the ownership boundary implicitly.