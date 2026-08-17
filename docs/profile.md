# Profile and binding specification

## Status

This document specifies Proofstrap's profile and native-binding contract.
Archive and manifest admission, semantic resolution and expansion, binding
projection, deterministic pack building, local stores, explicit import,
structural inspection, target configuration, Plan/Apply pack integration,
official core/Linux packs, and executable-adjacent bundled acquisition are
implemented.

The authority, identity, digest, and failure laws below are the durable format
contract and do not depend on delivery-plan terminology.

## Purpose

Profiles move reusable desired-state composition out of Go without turning
Proofstrap into a privileged script runner. A profile names closed typed
resources and composes profiles. A binding pack translates backend-neutral
package and service identities for an observed backend. Observation, reconciliation,
commands, verification, permissions, and lifecycle policy remain engine-owned.

The goals are plural resources and instances, distribution-independent profiles,
exact digest-pinned truth, and rejection of ambient lookup, fallback, executable
content, and implicit authority.

## Approved design summary

| Area | Approved contract |
|---|---|
| Authority | Config selects exact roots; semantic packs compose intent; binding packs map names; code owns behavior and effects. |
| Identity | One Symbol grammar; semantic resource ID is domain kind plus global local name; exact digest selects source generation and provenance only. |
| Pack | One schema-selected semantic or binding tar-gzip archive with exact requirements and bounded streaming admission. |
| Acquisition | Fixed release/user/system content-addressed stores and create-exclusive atomic import. |
| Profile | Map-keyed declarations, compact typed parameters, exact includes, and canonical bound-instance identity. |
| Package | PackageRef set with direct-present intent only. |
| Service | ServiceRef plus explicit System/User target, independent lifecycle axes, and explicit delivering PackageRefs. |
| Graph | No generic authored dependency language; service delivery and closed domain laws create edges. |
| Binding | Exact independently backend-indexed package/service mappings; no topology or lifecycle authority. |
| Effects | Profiles contain no commands, probes, scripts, executable paths, permissions, fallback, or mutation policy. |

## Resolution model

Resolution is ordered and non-executable:

~~~text
admit config-pinned root packs
-> resolve exact manifest requirements from admitted stores
-> bind pack-local lexical aliases
-> instantiate selected and included profiles
-> expand target-independent semantic resources
-> apply config-activated bindings for observed domain backends
-> unify direct and bound native resources
-> derive conflicts or unsupported outcomes
~~~

No step executes a host command. Distribution identity remains provenance rather
than a selector.

## Construct inventory

The language is closed. Unknown fields and constructs are admission errors.

| Construct | Owner | Behavior |
|---|---|---|
| Config pack pin | Config | Admits an exact root pack identity and digest. |
| Profile selection | Config | Instantiates one root profile with typed arguments. |
| Binding activation | Config | Makes one exact binding pack participate. |
| Direct resource | Config | Declares machine-specific typed desired state. |
| Pack manifest | Pack | Declares schema, kind, and exact requirements. |
| Requirement | Manifest | Binds a private lexical handle to one exact admitted semantic pack. |
| Profile | Semantic pack | Defines reusable typed composition. |
| Parameter | Profile | Accepts an account, group, or exact profile reference. |
| Include | Profile | Instantiates another profile with typed arguments. |
| Semantic resource | Profile | Declares backend-neutral package or service intent. |
| Service package prerequisite | Service | Declares package presence and package-to-service delivery edges. |
| Dependency edge | Model/domain | Adds closed ordering and failure coupling; it is not a generic authored construct. |
| Native binding | Binding pack | Maps semantic identity to native identities. |
| Conflict | Engine-derived | Reports contradictory desired truth. |
| Unsupported | Engine-derived | Reports valid intent without an implementation. |
| Provenance | Engine-derived | Explains contributions without changing equality. |

There is no separate template construct. A profile with parameters is already a
template.

## Configuration authority

One strict versioned config remains the desired-state root. It pins root packs
separately from selecting profiles and activating bindings. Its pure admission
grammar and production CLI acquisition are implemented and specified by the
[target configuration specification](config.md).

~~~toml
schema = 1

bindings = ["linux"]
profiles = [
  { profile = "core:network", arguments = { account = { account = "alice" } } },
]

[sources]
core = "sha256:..."
linux = "sha256:..."

[accounts.alice]
~~~

Config aliases are local to config. Pack requirements cannot see them. A development
path may provide bytes for an already pinned identity but cannot alter truth.
Importing a binding pack never activates it; only explicit config selection does.

## Pack kinds and manifests

Every pack has exactly one authority kind:

- A `semantic` pack contains profiles and backend-neutral semantic intent.
- A `binding` pack contains native package/service name mappings.

Mixed packs are rejected. A manifest declares only its schema, kind, and
optional exact requirements.

~~~toml
schema = 1
kind = "semantic"

[requires]
core = "sha256:..."
~~~

Requirement handles are private lexical locators, not semantic identity, URLs,
registry keys, filesystem paths, or download instructions. Semantic and binding
packs may require semantic packs. Binding packs cannot be required.

`schema` is an exact positive integer selecting grammar and interpretation. It
is not an update selector or compatibility range; a runtime reads only schemas it
explicitly implements.

Pack and profile versions are absent. The exact source digest is the pack
generation, and a profile is identified by that digest plus its local ID. One
closure deduplicates identical digests. Updating is an explicit semantic-pack
digest replacement, coherent binding-pack replacement,
and newly reviewed Plan, never latest/range resolution.

## Requirements and acquisition

A requirement binds a private pack-local handle to an exact digest. The resolver
searches only admitted release, user, and system stores for that digest.

Requirements do not download, query a registry, select profiles, activate bindings,
inherit store precedence, provide transitive name scopes, or re-export names.
Requirement cycles fail.

Config pins roots; manifests pin exact transitive requirements. On a fresh system, a
release bundle or explicit import operation must place every required digest in
an admitted store. Missing content reports its exact identity and digest; another
stored generation is never substituted.

## Digest identities

A pack source digest is SHA-256 over the complete archive byte sequence exactly
as acquired. Config pins, manifest requirements, store keys, and import verification
all use that value. The manifest does not contain its enclosing archive digest,
which avoids a self-reference.

Recompression, member reordering, archive-header changes, or any other byte
change creates a new source identity even when decoded declarations are equal.
Repacking is republishing and requires new config and requirement pins. The
format has no normalized-archive digest and no separate canonical pack-contract
digest.

This source digest is distinct from the Plan semantic digest:

~~~text
pack source identity = SHA-256(exact archive bytes)
Plan semantic identity = SHA-256(canonical expanded review)
~~~

Packaging differences therefore change acquisition identity but not the
canonical semantics computed after successful admission and expansion.

## Archive envelope

An admitted pack is exactly one gzip stream containing one tar stream. The first
member is the regular file `manifest.toml`. Later regular files occur exactly
once in canonical path order under the kind-specific `profiles/` or
`bindings/` TOML prefix. Proofstrap checks actual decoded bytes and counts while
reading. The verified whole-archive digest is the sole integrity authority; the
manifest has no member list, sizes, or member digests.

The reader rejects concatenated gzip streams, non-padding trailing content,
directories, links, sparse files, devices, FIFOs, sockets, extension records,
duplicate/case-colliding paths, invalid-kind or out-of-order members. Absolute,
drive-qualified, UNC, empty, dot-segment,
traversal, and backslash paths also fail.

Admission streams validation and never performs generic extraction. Loose
directories are pack-builder inputs only; they are never admitted, selected, or
digest-pinned sources. Exact byte, count, path, and expansion ceilings are
engine-owned schema limits; a manifest cannot raise them.

### Authoring and runtime tools

The archive is the only admitted profile or binding representation, but it is
not the only authoring form:

~~~text
authoring directory
-> proofstrap-pack
-> deterministic .pstrap archive and SHA-256
-> proofstrap import/release bundle
-> Plan and Apply
~~~

`proofstrap-pack` is a separate distributor/profile-author executable. It owns
directory traversal, authoring validation, canonical member order, and archive
writing. Identical input with the same builder version produces identical bytes.
The builder validates its completed output through the shared archive reader
before publishing it.

Its implemented interface is exact and absent-only:

~~~text
proofstrap-pack build --input ABSOLUTE_DIR --output ABSOLUTE_FILE
~~~

Success prints only the completed archive's `sha256:<64-lower-hex>` identity.
The builder never overwrites an output or imports it into a runtime store.

`proofstrap` is the user/runtime executable. It imports and structurally inspects
exact archives but does not import the writer package. Plan uses the pack library
for pure semantic and binding resolution.
Release packs, store packs, explicit digest-pinned development archive paths,
and local imports use the same reader.

Loose directories, individual TOML files, inline profiles, stdin packs, URLs,
registry names, and unpinned archives are not runtime profile inputs. Direct
typed config resources remain the no-pack minimal path.

## Store publication

The sole authoritative stored name is:

~~~text
<store>/sha256/<64-lower-hex>.pstrap
~~~

Import requires the expected digest:

~~~text
open source once as a regular file
-> create-exclusive random staging file in the final directory
-> bounded copy while hashing exact bytes
-> compare expected digest
-> rewind and completely validate staged archive
-> flush staged file
-> atomically hard-link staging to final digest path
-> flush store directory
-> remove staging name
~~~

The final hard link is publication. Import never writes directly to the final
name and never uses an overwriting rename. An existing valid target is successful
deduplication; an invalid target is store corruption and is never replaced.
Concurrent importers converge through one link winner and loser verification.

A pre-link crash leaves inert staging. A post-link crash leaves a complete
authoritative pack and possibly inert staging. Resolvers recognize canonical
final names only. Cleanup is maintenance rather than recovery authority. Import
does not modify its source and preserves primary and cleanup errors.

No mutable index is authoritative. Plan derives exact paths without enumeration;
explicit listing may enumerate for presentation. Parsed packs may be cached only
within one process/run.

### Store scopes

| Scope | Root | Writer |
|---|---|---|
| Release | `/usr/share/proofstrap/packs` | OS/distribution packaging |
| System | `/var/lib/proofstrap/packs` | Explicit privileged import |
| User | `$XDG_DATA_HOME/proofstrap/packs` | Current user |

If XDG_DATA_HOME is absent or relative, user scope falls back to
`$HOME/.local/share/proofstrap/packs`. Without an absolute HOME, user scope is
unavailable. Every root uses the same content-addressed layout.

The release store is read-only to Proofstrap. Import defaults to user scope;
`--system` explicitly selects system scope and requires authority to be already
available without prompting. There is no release-scope import.

Config pins content, never store scope or filesystem path. Resolution derives the
exact digest path in every available scope. Valid duplicate copies deduplicate.
Any corrupt candidate is reported even if another scope contains valid bytes;
scope order never hides corruption or changes truth.

The runtime inventory interface is:

~~~text
proofstrap import --digest DIGEST [--system] ARCHIVE
proofstrap inspect
proofstrap inspect DIGEST
proofstrap inspect --digest DIGEST ARCHIVE
~~~

Import defaults to the user store and writes no success output. `--system`
selects the system store but never invokes privilege escalation or prompts.
Every import requires the expected whole-archive byte digest and never activates
profiles or bindings.

Bare `inspect` enumerates admitted stored sources. `inspect DIGEST` performs
non-enumerating exact lookup in every available scope. The path form admits one
local regular archive read-only and requires its observed digest to match the
explicit digest; it does not import it. A path alone is never identity.
Relative archive paths are resolved once against the process working directory
and passed to inventory as clean absolute paths without probing during parsing.

All inspect forms output one deterministic JSON array containing only digest,
kind, sorted direct requirements, canonical member paths, and observed scopes.
This is a structural projection, not a TOML conversion: raw authored content,
decoded resources, and transitive closure are not exposed. JSON is completely
validated and bounded before stdout is written.

Enumeration is fail-closed. Only canonical digest object names and exact inert
`.import-<32-lower-hex>` crash-left staging are recognized; every other entry or
corrupt candidate fails inspection. Inspection observes each scope once. Each
returned object describes exact admitted bytes, but the combined multi-store
view is not claimed to be an atomic filesystem snapshot.

Bare `inspect` is the only inventory enumeration. Removal, update, registry,
automatic acquisition, repair, staging cleanup, and garbage collection are not
implemented.

## Engine budgets

Limits are versioned engine constants. A config or pack cannot request larger
values, and the maxima are not allocation targets.

| Per archive or declaration | Maximum |
|---|---:|
| Compressed archive | 8 MiB |
| Decoded tar stream | 32 MiB |
| `manifest.toml` | 64 KiB |
| Individual content member | 1 MiB |
| Members after manifest | 256 |
| Content filename bytes | 99 |
| Requirements per pack | 64 |
| Profiles per semantic pack | 256 |
| Parameters per profile | 16 |
| Includes per profile | 64 |
| Resources per profile | 1,024 |
| Semantic dynamic-value container depth | 16 |
| Binding entries per pack | 8,192 |
| Native outputs per binding | 32 |

| Whole resolution | Maximum |
|---|---:|
| Packs in closure | 64 |
| Aggregate compressed source | 128 MiB |
| Bound profile instances | 4,096 |
| Canonical resource nodes | 32,768 |
| Dependency edges | 131,072 |
| Provenance contributions | 262,144 |

The exact maximum succeeds; maximum plus one fails. Arithmetic is checked before
allocation or append. Tar claims are checked before allocation and actual bytes
are enforced during streaming. Archive, closure,
expansion, graph, and provenance budgets remain independent.

A limit failure publishes neither a pack nor a partial graph and identifies the
budget, observed value, maximum, and source provenance. Cancellation is a
separate operational result. Wall-clock speed does not change semantic validity.
Raising a ceiling requires an engine/schema change.

These ceilings bound hostile input; they are not normal sizing hints. Minimal
inputs must not preallocate maximum-sized collections or activate unused
resolution phases.

### Enforcement and minimal cost

Budget checks belong to the owner performing the work, not to a late validation
pass or global policy framework. Small unexported counters charge before reads,
allocation, closure enqueue, instance creation, binding fan-out, and graph
mutation. A graph builder first computes its complete node, edge, and provenance
delta; either every charge succeeds or the builder remains unchanged.

Cycle, missing-reference, and binding-conflict validation happens before
expansion so structural defects retain precise diagnostics instead of becoming
limit failures. Closure traversal and profile expansion use visited and memo
tables and do not repeatedly scan or recursively expand the same input.

Empty collections remain unallocated. Non-empty collections may use validated
observed counts as capacity, never engine maxima. If config selects no packs,
profiles, or bindings, Proofstrap does not open/enumerate stores, initialize pack
indexes, or probe package/service backends unless direct resources demand them.
Exact store lookup uses the digest path rather than scanning installed packs.

There is no exported limits API, configurable budget policy, global budget
service, or third-party archive/graph framework.

## Names and references

One Symbol grammar applies to config aliases, requirement handles, profile IDs,
semantic package/service IDs, and parameter names:

~~~text
[a-z][a-z0-9-]{0,62}
~~~

There is no case folding, Unicode normalization, underscore variant, or separate
grammar for handles, profiles, and semantic resources. A qualified reference is
exactly `handle:name`, with both components Symbols.

A semantic identity is:

~~~text
(domain kind, local name)
~~~

Domain kind distinguishes equal names:

~~~text
(package, network-manager)
(service, network-manager)
~~~

Within its pack a source uses a short name:

~~~toml
packages = ["network-manager"]
~~~

Across packs it uses exactly one requirement handle:

~~~toml
packages = ["core:network-manager"]
~~~

Unqualified names resolve directly. Qualified names require a declared
requirement and prove that the required pack declares the typed resource before
reducing to the same global `(domain, name)` identity. Handle chains such as
`a:b:name`, ambient lookup, and
declaration-order resolution are rejected. The exact pack digest establishes the
source generation, so resource references carry no version suffix.

Content filenames use the flat USTAR-safe lowercase ASCII grammar:

~~~text
[a-z0-9][a-z0-9-]{0,93}.toml
~~~

The complete member path is exactly one kind-specific prefix plus that filename.
Native package and service names, backend IDs, account/group names, hostnames,
timezones, and filesystem paths retain their own domain validators and are never
coerced into a Symbol.

## Profiles, parameters, and includes

Each `profiles/*.toml` member is a container. Profile IDs are table keys:

~~~toml
[profiles.network]
packages = ["network-manager"]
parameters = { account = "account_ref", group = "group_ref" }
~~~

A member may contain multiple profiles and must contain at least one. The table
key is the sole local profile ID, so an `id` field is rejected. Every profile
ID is unique across the complete pack; a declaration cannot be reopened,
extended, or merged from another table or member.

Member paths provide packaging and error provenance only. They do not derive,
qualify, or scope profile identity. Moving an unchanged declaration between
members changes the exact archive source digest, but not admitted semantics or
the Plan semantic digest.

A profile has required typed parameters, exact includes, and typed resources.
The optional `parameters` field is a TOML 1.0 inline table from Symbol name to
exact kind. The admitted kinds are `account_ref`, `group_ref`, and `profile_ref`. Omission means
no parameters; an explicit empty map is rejected. Parameter order has no
meaning. Parameters have no defaults, optional form, or metadata object, and
every declaration must be consumed or forwarded.

Binding produces an AccountKey, GroupKey, or canonical pack-digest/profile
identity, never an interpolated string, and creates no resource. A separately
declared Account or Group node must satisfy every final identity reference.

Root selection and include share one instantiation law. Instance identity is pack
digest, profile ID, and canonical typed arguments. Identical instances
deduplicate; different bindings remain distinct.

~~~toml
[[profiles.network.include]]
profile = "core:user-service"

[profiles.network.include.arguments]
account = { parameter = "account" }
~~~

An include may bind a literal reference or forward a same-kind parameter. It
cannot override fields, acquire/import packs, activate bindings, or depend on
target facts. Definition include cycles fail before target inspection.

A dynamic target is exactly `{ parameter = "name" }`, where `name` is a
`profile_ref`. Its selected profile may come from another config-pinned semantic
source. The selected profile's complete parameter row must exactly match the
include argument names and kinds. Active dynamic cycles fail; a completed
repeated instance deduplicates. Config aliases disappear when the argument is
bound and never become semantic identity.

~~~toml
[profiles.workstation]
parameters = { account = "account_ref", desktop = "profile_ref" }

[[profiles.workstation.include]]
profile = { parameter = "desktop" }

[profiles.workstation.include.arguments]
account = { parameter = "account" }
~~~

An Include is an optional non-empty array of tables. Each entry requires exactly
`profile`. The `arguments` table is required when the resolved target has
parameters and forbidden when it has none. Its keys must match every target
parameter exactly. Missing, extra, duplicate, partial, and wrong-kind bindings
fail. Explicitly empty `include` or `arguments` fails. Duplicate canonical
Include instances within one profile fail; differently bound instances remain
distinct. Include ordering has no meaning.

Argument inputs are contextual:

~~~text
ArgumentExpr<K> = Literal(K) | Forward(ParameterName, K)
K = AccountKey | GroupKey | ProfileIdentity
~~~

A string literal is validated by the resolved target parameter kind.
`{ parameter = "name" }` is the only forwarding object; the named caller
parameter must exist and have the same kind. No coercion, inference, fallback,
interpolation, default, optional binding, or implicit resource creation exists.

Validation has two phases:

~~~text
admit string or exact forwarding-object syntax
-> resolve target profile and parameter schema
-> require exact argument keys
-> validate literals and same-kind forwarding
-> produce canonical typed arguments atomically
~~~

At most 16 arguments are admitted. The resulting AccountKeys and GroupKeys are
references; the final graph must still contain separately declared Account and
Group resources. Root-config argument source syntax belongs to the separate
target configuration contract.

## Whole-member admission

Each semantic content member is valid UTF-8 TOML 1.0, no larger than 1 MiB,
with exactly one non-empty root `profiles` table. At least one profile must be
declared, and every profile must contribute at least one Include or resource;
parameters alone do not make a profile meaningful. Comments and whitespace are
allowed. Trailing comments and whitespace are allowed after the root table;
another document or any content outside `profiles` is rejected.

Unknown fields fail at every level. Duplicate keys, reopened profile tables,
duplicate profile IDs, and conflicting TOML table forms fail. An explicitly
empty collection or table fails unless its field explicitly permits emptiness;
this format permits none. Structural nesting depth is at most 16. Counts are charged
before allocation.

Admission is two-phase and atomic:

~~~text
parse one complete member and admit its closed source shapes
-> resolve profile references and contextual argument schemas in the supplied library
-> validate pack-wide profile identity, cycles, references, and limits
-> publish the complete admitted library, or publish nothing
~~~

A syntax failure identifies member provenance and line and column. A semantic
failure identifies member provenance, profile ID, and canonical field path, and
also line and column when the TOML decoder supplies them reliably. Diagnostic
categories are stable; exact prose is not. Multiple members aggregate
atomically and independently of input order. Member paths are provenance only.

The following is one complete valid semantic member. It defines the include
target locally so its argument contract is visible:

~~~toml
[profiles.user-audio]
parameters = { account = "account_ref", group = "group_ref" }
homes = [{ account = { parameter = "account" } }]
home_modes = [{ account = { parameter = "account" }, mode = "0700" }]
account_locks = [{ account = { parameter = "account" } }]
memberships = [{ account = { parameter = "account" }, group = { parameter = "group" }, present = true }]

[profiles.user-audio.services.pipewire]
target = { user = { parameter = "account" } }
packages = ["pipewire"]
enabled = true
running = true

[profiles.desktop]
parameters = { account = "account_ref", group = "group_ref" }
packages = ["network-manager"]
hostname = "workstation"
timezone = "Asia/Shanghai"

[[profiles.desktop.include]]
profile = "user-audio"

[profiles.desktop.include.arguments]
account = { parameter = "account" }
group = { parameter = "group" }

[profiles.desktop.services.network-manager]
target = "system"
packages = ["network-manager"]
enabled = true
running = true
~~~

### Field and fixture matrix

Fixture names below are stable stems under
`internal/profile/testdata/invalid/`. “Resource” charges the
per-profile resource budget; collection counts are charged before allocation.

| Construct | Admitted shape and constructor owner | Identity and collection law | Budget charge | Required negative fixture stem |
|---|---|---|---|---|
| Member root | exact non-empty `profiles` table; `profile` decoder | member path is provenance only; whole member is atomic | 1 MiB; dynamic values depth 16 | `member-root-unknown` |
| Profile declaration | non-empty table keyed by Symbol; `profile` decoder | local Symbol; unique pack-wide; Include/resource required | 256 per pack | `profile-empty` |
| `parameters` | omitted or non-empty inline Symbol-to-kind table; profile constructor | parameter name + exact `account_ref`/`group_ref` kind; orderless, no duplicates | 16 per profile | `parameters-empty` |
| `include` | omitted or non-empty array of exact Include tables; expansion constructor | resolved target + canonical typed arguments; orderless, no duplicate instance | 64 per profile | `include-duplicate-instance` |
| Include `profile` | required ProfileRef string; profile resolver | canonical semantic profile ID | included with Include | `include-missing-profile` |
| Include `arguments` | exact non-empty contextual argument table iff target is parameterized; resolver | exact target parameter keys; literals or same-kind forwarding only | 16 per Include | `arguments-wrong-kind` |
| `packages` | omitted or non-empty PackageRef array; package constructor | canonical semantic package ID; orderless, no duplicates | 1 resource each | `packages-duplicate` |
| `services` entry | table keyed by ServiceRef; service constructor | semantic service ID + target; one declaration per profile | 1 resource each | `service-duplicate-id` |
| service `target` | required `"system"` or exact user-reference table; service constructor | part of ServiceKey | included with service | `service-target-shape` |
| service `enabled` / `running` | required booleans; service constructor | desired values, not identity; axes independent | included with service | `service-missing-running` |
| service `packages` | omitted or non-empty PackageRef array; edge constructor | orderless unique package prerequisites | resource plus edge each | `service-packages-empty` |
| `homes` | omitted or non-empty exact account-reference tables; Home constructor | AccountKey; presence-only, orderless unique | 1 resource each | `homes-empty` |
| `home_modes` | omitted or non-empty account plus four-octal-mode tables; HomeMode constructor | AccountKey; one value per key | 1 resource each | `home-mode-invalid` |
| `account_locks` | omitted or non-empty exact account-reference tables; AccountLock constructor | AccountKey; presence-only, orderless unique | 1 resource each | `account-lock-duplicate` |
| `memberships` | omitted or non-empty exact account/group/required-present tables; Membership constructor | AccountKey + GroupKey; one boolean per key | 1 resource each | `membership-missing-present` |
| `hostname` | omitted or validated string; Hostname constructor | singleton Hostname key | 1 resource | `hostname-invalid` |
| `timezone` | omitted or validated string; Timezone constructor | singleton Timezone key | 1 resource | `timezone-invalid` |
| forbidden profile fields | no `id`, `resources`, `requires`, `depends_on`, Account/Group, AccountShell, native name, backend, selector, or executable field | cannot construct authority or topology | none | `profile-forbidden-field` |

## Resource authority

Profiles own backend-neutral package and service intent. Config may declare native,
machine-specific resources directly. Both enter one canonical graph.

| Resource | Config | Semantic profile |
|---|---:|---:|
| Native package or service | Yes | No |
| Semantic package or service | No | Yes |
| Account or Group | Yes | No |
| Home, HomeMode, Membership, AccountLock | Yes | Yes, through typed references |
| AccountShell | Yes | No |
| Hostname or Timezone | Yes | Yes |

Config alone declares Accounts and Groups. Including a profile cannot decide
managed/external authority, choose UID/GID, or acquire identity-management
authority.

Profiles cannot declare, parameterize, or override AccountShell because its
desired value is an exact absolute target path. The canonical model reserves
AccountShell for direct machine intent, but its config shape, requiredness,
emission, and identity-adapter behavior are deferred entirely to the target
configuration and adapter stages.

### Identity-derived and host resource syntax

Identity-derived resources use closed plural fields; host singleton resources
use scalars:

~~~toml
[profiles.desktop]
parameters = { account = "account_ref", group = "group_ref" }

homes = [{ account = { parameter = "account" } }]
home_modes = [{ account = { parameter = "account" }, mode = "0700" }]
account_locks = [{ account = { parameter = "account" } }]
memberships = [
  {
    account = { parameter = "account" },
    group = { parameter = "group" },
    present = true,
  },
]

hostname = "workstation"
timezone = "Asia/Shanghai"
~~~

An account or group reference expression is exactly either its literal domain
name or a parameter forwarding object:

~~~toml
homes = [{ account = "alice" }]
memberships = [{ account = "alice", group = "audio", present = true }]
homes = [{ account = { parameter = "account" } }]
~~~

The containing field supplies the expected reference kind. Generic typed
wrappers, interpolation, and scalar/path parameters are rejected.

`homes` and `account_locks` are presence-only sets. `home_modes` requires
one exact four-character octal mode from `0000` through `0777`.
`memberships.present` is required: true requests membership and false requests
absence. Hostname and timezone use their domain validators and singleton keys.
Omission means unowned.

An explicitly empty plural field fails. Duplicate canonical resource keys
inside one profile fail even when values match; contradictory values also fail.
Equal resources from different expanded instances unify normally and retain all
provenance. A generic `resources = [{ kind = ... }]` union, singular aliases,
and profile AccountShell fields are forbidden.

A service declaration owns semantic ID, an exact service target, independent
persistence/runtime intent, and dependencies. A binding supplies native names
only.

## Package intent

The compact package form is:

~~~toml
[profiles.desktop]
packages = ["network-manager", "core:font-stack"]
~~~

These strings are PackageRef values, never native package-manager names:

~~~text
PackageRef = Local(Symbol) | Imported(Alias, Symbol)

"network-manager"
-> (package, network-manager)

"core:font-stack"
-> prove required pack `core` declares package `font-stack`
-> (package, font-stack)
~~~

The canonical semantic ID is `(package, local name)`. The exact
source digest is already fixed by the admitted closure and remains provenance;
it is not repeated in every reference. Text that happens to equal a native
package name is still semantic in this field. Only an active binding may produce
native package identities.

There is no separate package-ID declaration or export catalogue. A local
PackageRef introduces its ID into the pack-wide package symbol set, and every
local ID is addressable through an exact requirement handle. Qualified references
and binding entries must resolve to that set. A missing ID is MissingReference;
an existing ID without an active mapping for the observed package backend is
Unsupported.

Each entry means direct presence only. Package version, manager, scope, absence,
optionality, native fields, and per-entry objects are forbidden. Order has no
meaning. Duplicates inside one profile fail; identical package resources emitted
by multiple profile instances deduplicate during canonical unification.

## Service intent

The service table key is a ServiceRef:

~~~text
ServiceRef = Local(Symbol) | Imported(Alias, Symbol)
~~~

It resolves to the canonical semantic ID `(service, local name)`.
There is no repeated `id` field or local resource label. A qualified reference
contains a colon and must therefore be a quoted TOML key:

~~~toml
[profiles.desktop.services."core:pipewire"]
target = { user = { parameter = "account" } }
running = true
~~~

Local use introduces the ID into the pack-wide service symbol set. Qualified
references and binding entries must resolve to that set. Package and service IDs
remain different domains even when their local names are equal.

Service target is a closed sum:

~~~text
ServiceTarget = System | User(AccountKey)
~~~

~~~toml
[profiles.desktop.services.network-manager]
target = "system"
packages = ["network-manager"]
enabled = true
running = true

[profiles.desktop.services.pipewire]
target = { user = { parameter = "account" } }
enabled = true
running = true
~~~

A user target requires an `account_ref` parameter. A system target carries no
account. There are no independent `scope` and `principal` fields, implicit
system target, root/current/numeric user syntax, or authored execution principal.
Execution identity and any user-manager endpoint are derived later from the
admitted Account and live adapter evidence.

`enabled` and `running` are independent optional source fields. Omission
means Proofstrap does not own that axis. `true` requests Enabled or Running;
`false` explicitly authorizes Disabled or Stopped. The decoder preserves field
presence and admits closed three-state model values:

~~~text
EnableIntent = Unmanaged | Enabled | Disabled
RunIntent    = Unmanaged | Running | Stopped
~~~

A service with neither axis is rejected. Its optional non-empty `packages`
field contains PackageRefs. Every entry declares that package directly present
and adds its package-to-service prerequisite edge. Duplicate entries fail; one
package may serve several services and deduplicates as a resource while retaining
each edge.

The lifecycle axes are manager-independent.
Systemd, OpenRC, or another admitted service adapter must independently observe
and converge every requested axis. Missing capability derives Unsupported;
neither a binding nor an adapter may couple, reinterpret, or ignore intent.

Canonical service resource identity is semantic service ID plus target;
lifecycle intent does not enter the key. A ServiceRef occurs at most once in one
profile. The same parameterized profile may be instantiated for several
AccountKeys: identical bindings deduplicate and different bindings create
distinct service resources. The exact config syntax for expressing those plural
root instances is deferred to the target config grammar.

## Native binding catalogues

Package and service mappings are independently indexed by observed backend:

~~~toml
[package.zypper]
"core:network-manager" = ["NetworkManager"]

[package.apk]
"core:network-manager" = ["networkmanager"]

[service.systemd]
"core:network-manager" = ["NetworkManager.service"]

[service.openrc]
"core:network-manager" = ["networkmanager"]
~~~

The canonical binding key is:

~~~text
(domain kind, exact BackendID, canonical semantic identity)
~~~

This permits Zypper with OpenRC without a distro family or combined variant. A
binding emits one or more validated native identities in its own domain.
Identical active entries deduplicate; different outputs for one key conflict.
Inactive backend entries and mappings for resources absent from the semantic
graph are inert. A disputed active key reports Conflict, not Unsupported.

Backend IDs are typed separately for package and service domains. Their grammar
is `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`, with at most 63 bytes; a missing backend is
represented by the typed zero value for that domain. Native names are exact,
non-empty UTF-8 strings of at most 255 bytes. They are never normalized,
repaired, suffixed, or used as semantic IDs.

Every binding key is a direct `handle:Symbol` reference into a Semantic pack
named by the Binding pack's manifest requirements. Binding packs declare no
semantic symbols and cannot use unqualified or transitive references. Admission
allows at most 8,192 unique keys per catalogue, 32 orderless unique outputs per
key, and 1 MiB per member. Its raw shape is closed, so deeper or wrong-shaped
values fail strict TOML decoding rather than requiring a separate depth walker.
Exact maxima succeed; overflow fails atomically.

When a prerequisite emits several native resources, every dependent points to
every emitted prerequisite. Bindings cannot add includes, parameters, lifecycle
intent, principals, dependencies, or topology.

## Imports, includes, dependency edges, conflicts, and unsupported

- A **requirement** makes one exact semantic pack addressable through a lexical handle. It adds
  no desired resource or profile instance.
- An **include** instantiates one addressable profile with typed arguments. It
  contributes that instance's resources but adds no blanket ordering edge.
- A service **packages** field declares PackageRefs present and creates only
  their package-to-service delivery edges.
- A **dependency edge** orders concrete resources and failure-couples the
  dependent. The language authors no generic `requires` or `depends_on`; other
  edges come from closed Account/Home/Membership/service-target domain laws.
- A **conflict** means desired truth contradicts itself.
- **Unsupported** means valid intent lacks an admitted target implementation.

Using a cross-pack Include, PackageRef, or ServiceRef requires a manifest
requirement for addressability, but the requirement itself never selects or instantiates the
target.
A dependency edge never requires, includes, or invents a missing resource.

Conflict and unsupported are derived, never authored. Conflicts include
incompatible values for one logical resource, duplicate UID/GID ownership, or
differing active mappings for one binding key. Unsupported includes a missing
mapping for the observed backend or a missing safe adapter capability.

Missing requirement, missing reference, forbidden authority, observation failure,
conflict, and unsupported remain distinct diagnostics. Unsupported never causes
fallback.

## Provenance and determinism

Each resource retains canonical provenance for config location, pack digest,
profile definition and instance, source declaration, and binding entry.
Provenance survives deduplication but changes neither identity nor authority.

Expansion is invariant to pack load order, declaration order, map iteration, and
store location. Canonical ordering is engine-owned.

## Implementation boundary

Implemented functionality includes the closed semantic profile language, direct
exact requirement resolution, strict native-binding catalogues, active-backend
atomic projection, pure target-configuration admission, bounded deterministic
archive construction, content-addressed local stores, explicit user/system
import, and structural JSON inspection. Tests cover complete language and target
fixtures, archive and parser rejection matrices, deterministic bytes, store
containment, runtime inventory, and the composed build-to-projection path.

Production target-config acquisition, Plan/Apply pack integration, and native
host package-backend resolution are implemented. Official pack contents, a
release bundle, and installer activation remain deferred; they must reuse these
identities and authority rather than create parallel concepts.

## Forbidden constructs

The format rejects:

- separate templates or visibility/export declarations;
- distro families, ID-like selectors, variants, and realizations;
- predicates, priorities, inheritance, and fallback;
- conditional includes and target-dependent composition;
- parameter defaults, optional parameters, and generic scalar/path parameters;
- interpolation and environment expansion;
- commands, scripts, hooks, probes, parsers, and executable paths;
- registry lookup, implicit download/latest, pack/profile versions, and ranges;
- requirement re-export and handle chains;
- generic authored `requires` or `depends_on`;
- authored unsupported, conflict, or lifecycle permission; and
- binding-defined topology or cross-domain output.

New constructs require a demonstrated domain need and an explicit schema
decision. Unknown content fails closed rather than being ignored.
