# Architecture

## Concept

Proofstrap is a declarative bootstrap system built around evidence rather than imperative scripts. A user supplies intent; Proofstrap derives requirements, observes the live host, reconciles intent with evidence, and exposes a reviewable transition. Mutation is allowed only after the user accepts the digest of that review.

The design separates six concepts:

1. **Intent** — selected capabilities and optional explicit account identity.
2. **Catalogue** — immutable relationships between capabilities and abstract package or service requirements.
3. **Behavior** — platform-specific ownership of names, observations, reconciliation rules, and effects.
4. **Evidence** — typed observations of the current host, package roots, services, identity, authority, and filesystem state.
5. **Review** — a canonical public projection of facts, blockers, and proposed changes, bound by a semantic digest.
6. **Receipt** — the verified outcome of Apply, including partial progress and any required replan.

These concepts preserve a strict direction:

```text
intent -> requirements -> evidence -> reconciliation -> review
accepted review + fresh evidence -> guarded mutation -> verification -> receipt
```

Rendered review data is never executable authority. Apply reconstructs private behavior from the original intent and immutable catalogue, then compares the fresh review digest with the accepted digest.

## Boundaries

Proofstrap owns supported system package and service establishment. It does not own dotfiles, user application configuration, package removal, repository policy, boot state, disks, credentials, or broad system repair.

Support is explicit and fail-closed. A package manager, service manager, authority path, identity source, or filesystem transition is admitted only when its evidence and mutation laws are known. Unknown, conflicting, ambiguous, or stale evidence blocks before mutation.

Identity establishment is create-only. Existing identities and homes must already be exact; mismatches are blockers rather than repair requests. Supplementary memberships and usable credentials remain outside desired state.

## Planning workflow

Plan is read-only and noninteractive:

```text
read intent
-> compile and validate selected capabilities
-> observe host and demanded behaviors
-> reconcile foundational identity state
-> reconcile package evidence
-> reconcile service evidence and conflicts
-> admit noninteractive authority only when a change needs it
-> render facts, blockers, changes, and digest
```

Foundational transitions are isolated. Creation of a primary group, locked account, home, or required package completes as one verified step and returns `replan_required`. The next decision is made only from a fresh Plan.

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
