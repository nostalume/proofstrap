# Architecture

## Authority flow

Proofstrap separates declarative truth, host evidence, and mutation authority:

```text
strict config + exact packs
-> semantic graph + native bindings
-> fresh typed host observations
-> canonical digest-bound Plan
-> explicit digest acceptance
-> fresh typed reconstruction
-> guarded effect + independent post-observation
-> durable journal frame
-> canonical terminal receipt
```

Serialized Plan review data is never executable authority. Apply recognizes a
closed operation kind, decodes its typed review, re-admits the named built-in
behavior, checks fresh evidence, and only then offers the effect. No JSON field,
profile, binding, or configuration value supplies an executable path or command.

## Ownership

- `cmd/proofstrap` owns exact CLI grammar, process environment, signals, streams,
  help, and exit mapping.
- `internal/config`, `internal/profile`, `internal/pack`, `internal/model`, and
  `internal/binding` own pure admission and composition.
- `internal/inventory` owns explicit content-addressed archive acquisition.
- Package, identity, host, and service domains own their typed evidence,
  reconciliation, reviewed operations, and guarded effects.
- `internal/app` composes domains, seals and publishes Plans, reconstructs Apply
  operations, and coordinates durable execution.
- `internal/engine` owns the pure dependency schedule, outcome reduction,
  journal frames, statuses, and receipt projection.
- Linux process and filesystem mechanisms remain below these semantic owners.

The production CLI has one path to Plan and Apply through `internal/app`; there
is no compatibility execution owner or alternate grammar.

## Plan

Plan reads one explicitly named absolute configuration file and optional exact
bundle paths. Configuration pins archive digests and selects roots; it contains
no store paths or behavior overrides. Acquisition resolves the complete pinned
closure, profile expansion produces backend-neutral resources, activated
bindings map native identities, and the app lowers the graph into typed reviewed
operations.

A global unsupported or contradictory condition produces a publishable blocked
Plan with no mutation authority. A progress barrier may follow reviewed
predecessors when fresh planning is required after foundational progress. Plan
publication is same-directory, create-exclusive, atomic, and durable.

## Apply

Apply accepts only a Plan path, its exact accepted digest, optional journal and
receipt paths, cancellation, current principal facts, and output. It never reads
configuration or packs. Before generation zero it validates the canonical Plan,
operation payloads, dependency graph, principal, and output parents.

Mutating execution uses one create-exclusive private journal descriptor:

```text
write + sync generation zero
-> execute one freshly reconstructed operation
-> independently observe its post-state
-> append + sync the candidate frame
-> commit the candidate in the pure engine
-> offer the next dependency-ready operation
```

A durability failure stops globally at the last proven prefix and emits no
fabricated terminal receipt. Independent operational failures may continue;
stale evidence and cancellation stop later effects. Terminal status and receipt
are projected once by the engine. Optional receipt publication is atomic and
no-replace, and standard output receives the same receipt bytes.

## Safety boundary

Proofstrap is Linux-focused and fail-closed. It does not promise that an admitted
native manager is benevolent; executable identity proves which local mechanism
was reviewed, not the mechanism's implementation. It does promise bounded input,
closed typed dispatch, exact evidence comparison, no shell interpretation,
noninteractive effects, independent verification, durable ordering, and honest
partial outcomes.

Unsupported managers, ambiguous evidence, unsafe filesystem ancestry, changed
principals, unknown schemas, and stale reviews do not select a fallback.
