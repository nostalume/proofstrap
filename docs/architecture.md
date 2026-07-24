# Architecture

## Concept

Proofstrap is a declarative bootstrap system built around evidence rather than imperative scripts. A user supplies intent; Proofstrap derives requirements, observes the live host, reconciles intent with evidence, and exposes a reviewable transition. Mutation is allowed only after the user accepts the digest of that review.

The design separates six concepts:

1. **Intent** — selected capabilities, optional exact host settings, and optional explicit account identity.
2. **Catalogue** — immutable relationships between capabilities and abstract package or service requirements.
3. **Behavior** — platform-specific ownership of names, observations, reconciliation rules, and effects.
4. **Evidence** — typed observations of the current host, hostname, timezone, package roots, services, identity, authority, and filesystem state.
5. **Review** — a canonical public projection of facts, blockers, and proposed changes, bound by a semantic digest.
6. **Receipt** — the verified outcome of Apply, including partial progress and any required replan.

These concepts preserve a strict direction:

```text
intent -> requirements -> evidence -> reconciliation -> review
accepted review + fresh evidence -> guarded mutation -> verification -> receipt
```

Rendered review data is never executable authority. Apply reconstructs private behavior from the original intent and immutable catalogue, then compares the fresh review digest with the accepted digest.

## Boundaries

Proofstrap owns supported system package and service establishment plus explicitly modeled exact host settings. The current host-setting boundary is persistent/runtime hostname establishment and `/etc/localtime` timezone establishment. It does not own clocks, RTC policy, NTP policy, dotfiles, user application configuration, package removal, repository policy, boot state, disks, credentials, or broad system repair.

Support is explicit and fail-closed. A package manager, service manager, authority path, identity source, or filesystem transition is admitted only when its evidence and mutation laws are known. Unknown, conflicting, ambiguous, or stale evidence blocks before mutation.

Identity establishment is create-only. Existing identities and homes must already be exact; mismatches are blockers rather than repair requests. Supplementary memberships and usable credentials remain outside desired state.

## Planning workflow

Plan is read-only and noninteractive:

```text
read intent
-> compile and validate selected capabilities
-> observe host and demanded behaviors
-> reconcile exact persistent and runtime hostname evidence
-> reconcile exact timezone symlink and zoneinfo evidence
-> reconcile foundational identity state
-> reconcile package evidence
-> reconcile service evidence and conflicts
-> admit noninteractive authority only when a change needs it
-> render facts, blockers, changes, and digest
```

Foundational transitions are isolated. Hostname or timezone establishment, or creation of a primary group, locked account, home, or required package, completes as one verified step and returns `replan_required`. The next decision is made only from a fresh Plan.

Hostname intent is lower-case ASCII DNS-style syntax with Linux's 64-byte host-name limit. Observation reads persistent `/etc/hostname` and runtime `/proc/sys/kernel/hostname` state independently. Exact state needs no mutation authority and remains a guarded precondition before and after later effects in the same desired state: confirmed drift is stale, while inability to revalidate is a failed blocker. A change requires systemd PID 1 and executes noninteractively through `hostnamectl --static --transient`; pretty hostname is outside the owned state.

Timezone intent follows systemd's relative zone-name grammar under `/usr/share/zoneinfo`; `UTC` is always valid even when its zonefile is absent. Observation requires `/etc/localtime` to be an absolute or relative symlink into that tree and independently verifies that the canonical target remains in the tree, is a regular file, and begins with a bounded `TZif` header read, including valid in-tree aliases; a missing `/etc/localtime` is the documented UTC default. Exact state needs no mutator, authority, or RTC inspection and is guarded across later effects. A change requires systemd PID 1 and executes `timedatectl --no-ask-password set-timezone ZONE`. Because timedated caches RTC mode and may synchronize a local-time RTC while changing timezone, mutation queries timedated's live `LocalRTC` property during Plan and again immediately before execution; only `LocalRTC=false` is admitted. As with other immediate guards, a concurrent privileged writer in the remaining probe-to-command interval is outside the boundary Proofstrap can make atomic. Proofstrap does not own or repair RTC mode.

Package and service behaviors own their native names and evidence. Host distribution identity is provenance, not a switch that silently selects behavior. Service work begins only after delivering packages are installed and rooted.

## Apply workflow

Apply is a guarded execution of an accepted semantic plan:

```text
rebuild Plan from live evidence
-> reject blockers or digest drift
-> reconstruct private commands and authority
-> revalidate global and immediate preconditions
-> execute one admitted effect
-> independently observe its post-state
-> stop on failure or verified replan boundary
-> verify aggregate state
-> emit a receipt
```

A successful command is not proof of success. Verification comes from independent post-state observation. A failed or timed-out command is also followed by observation so that partial effects are recorded accurately.

Apply never prompts, refreshes credential caches, or recursively accepts a new plan. Authority expiry fails closed. Verified progress that changes the next decision is represented as `replan_required`, not hidden by an automatic loop.

## Safety model

The safety model is based on freshness, exactness, and bounded ownership:

- Intent and evidence are represented as closed typed states.
- Unknown or contradictory observations remain blockers.
- Public plans are canonical and digest-bound.
- Executable paths and relevant evidence are retained or rebound to stable running identity.
- Preconditions are checked after digest acceptance and immediately before mutation.
- Every attempted effect receives independent post-observation.
- Prior verified outcomes survive later failure in the receipt.
- No rollback is implied when the native system operation is not atomic.

This makes Proofstrap a review-and-verification workflow rather than a general shell runner or package manager.
