# Profile and binding specification

## Boundary

Profiles express reusable backend-neutral desired state. Bindings map declared
semantic package and service symbols to native manager identities. Neither can
contain commands, probes, distribution tests, executable paths, fallback
selection, or mutation policy.

The same profile and binding body grammar is embedded in a schema-3 document or
stored in a pack. Official and personal sources have identical semantics.
`proofstrap-pack build` is the ordinary author path; generated manifests,
digests, and content-addressed filenames are outputs, never author input.

The complete executable document is
[examples/proofstrap.toml](../examples/proofstrap.toml). Snippets below are
grammar fragments rather than additional complete documents.

## Names and references

A `Symbol` is 1–63 characters: lowercase ASCII first, then lowercase ASCII,
digits, or `-`. Profile IDs, parameter names, source handles, and semantic
package/service IDs are Symbols.

Within a local document or one semantic pack, `name` is local and
`handle:name` refers through an exact declared semantic requirement. Exactly
one colon qualifies a reference. A handle is lexical scope, not a namespace,
provider, category, or fallback.

Pack requirements map handles to exact `sha256:` archive identities. `include`
creates profile-composition edges; a service's `packages` creates delivery
edges. There is no general `requires` field in profile bodies.

## Profile grammar

Profiles are keyed tables:

```toml
[profiles.desktop]
parameters = { account = "account_ref", session = "profile_ref" }
include = [
  { profile = { parameter = "session" } },
  { profile = "audio", arguments = { account = { parameter = "account" } } },
]
packages = ["dbus"]
homes = [{ account = { parameter = "account" } }]
home_modes = [{ account = { parameter = "account" }, mode = "0700" }]
account_locks = [{ account = { parameter = "account" } }]
memberships = [
  { account = { parameter = "account" }, group = "audio", present = true },
]
```

A profile must contribute at least one include or resource. Supported fields
are:

| Field | Desired meaning |
| --- | --- |
| `parameters` | typed inputs used or transparently forwarded by the body |
| `include` | local, imported, or parameter-selected profile instances |
| `packages` | orderless semantic package presence |
| `services` | semantic service lifecycle and delivery packages |
| `homes` | declared account home presence |
| `home_modes` | home presence and exact mode |
| `account_locks` | account locked state |
| `memberships` | exact explicit supplementary member edge |
| `hostname`, `timezone` | exact host state |

Explicit empty collections are invalid. Duplicate resources or include
instances are rejected. Equal resources contributed through different profiles
deduplicate later with provenance; unequal desired truth conflicts atomically.

### Parameters and includes

Parameter kinds are exactly `account_ref`, `group_ref`, and `profile_ref`.
Every parameter must be consumed or forwarded. A literal account/group value is
a string; transparent forwarding uses exactly `{ parameter = "name" }`.
`profile_ref` values can only be forwarded into an include target or argument.

Static include targets use `profile = "name"` or `"handle:name"`. Dynamic
targets use `profile = { parameter = "choice" }`. Arguments are forbidden for
a parameterless target and otherwise must exactly match its signature. Include
cycles, including dynamically selected cycles during expansion, fail. Ordering
does not choose among duplicates or conflicts.

Root `include` uses the same call shape, but its profile and argument values are
literal strings supplied by the target document.

### Packages and services

Package entries are semantic Symbols or qualified semantic references. They
request presence only; removal and alternatives are not modeled.

```toml
[profiles.desktop.services.session]
target = "system"
packages = ["session"]
enabled = true
running = true
```

The service table key is a semantic service reference. `target` is required:
`"system"`, or `{ user = { parameter = "account" } }` for a typed user target.
At least one of `enabled` and `running` is required. Each is independent: true
requests enabled/running and false requests disabled/stopped; omission leaves
that axis unmanaged. Optional non-empty `packages` request semantic delivery
packages and order them before service work.

### Accounts and host resources

`homes`, `home_modes`, and `account_locks` take account literals or
`account_ref` parameters. Memberships additionally take a group literal or
`group_ref` parameter and require `present`. Home modes are strings `0000`
through `0777`. These fields refer to identities declared by the target
document; profiles do not create account or group identities.

Hostname and timezone use the same validated model as direct document fields.
They are literal exact values, not adapter selectors.

## Binding grammar

A binding maps one declared semantic symbol and domain to 1–32 native outputs
for one backend. It never declares semantics. Direct tables are useful for
irregular mappings:

```toml
[package.apt]
"core:archive" = ["zip", "unzip"]

[service.systemd]
"core:ssh-server" = ["sshd.service"]
```

In a standalone binding pack, keys are `handle:Symbol` and the handle must be an
exact semantic requirement. In an embedded document, unqualified keys refer to
local profiles; qualification still refers to imported semantics.

Factored clauses remove repeated equal cells:

```toml
[[bind]]
package = ["apk", "apt", "dnf4", "dnf5", "zypper"]
from = "core"
same = ["curl", "dbus"]

[[bind]]
service = ["openrc", "systemd"]
from = "core"
to = { ssh-server = ["sshd"] }
```

Each clause supplies exactly one non-empty `package` or `service` backend list.
`from` is the semantic handle and may be omitted only for local declarations.
`same` maps each symbol to the identical native spelling; `to` maps a symbol to
an explicit non-empty output list. At least one is required, and their symbols
must not overlap.

Backend IDs and native outputs are data identities, not executables. Duplicate
cells, duplicate outputs, and two different semantic symbols emitting the same
native identity for one backend/domain conflict. A key must name a semantic
declaration in the correct domain. Missing, wrong-domain, or unused requirement
handles fail admission.

Binding activation does not probe a host. During Plan, the observed package and
service backends select cells from the already admitted catalogues. Every
demanded semantic native resource must map; missing mappings are reported
atomically as unsupported. Unused mappings are inert. Projection is orderless,
deduplicates equal output, rejects unequal output, and preserves provenance.

## Packs and exact identity

A `.pstrap` is one gzip stream containing a canonical USTAR archive. Its first
regular member is `manifest.toml`; remaining regular UTF-8 members are strictly
ordered and case-distinct. Semantic content lives under `profiles/`; binding
content under `bindings/`. Other paths, links, directories, devices, multiple
gzip streams, and trailing compressed data fail.

The strict manifest grammar is:

```toml
schema = 1
kind = "semantic" # or "binding"

[requires]
core = "sha256:..."
```

`requires` is omitted when absent and non-empty when present. It contains at
most 64 Symbol handles, each bound to an exact semantic-pack digest. Binding
requirements point to semantic packs; semantic requirements form an acyclic
exact closure. A pack cannot require itself.

Archive identity is SHA-256 over the complete compressed bytes. The same
semantic TOML in differently encoded archive bytes is a different source. The
reader computes identity while boundedly admitting the stream; `inspect` may
optionally compare it with an expected digest, and `import` publishes under
that computed identity without activation.

Authors normally do not write this envelope. The compiler promotes one schema-3
document into zero or one local semantic pack, zero or one local binding pack,
and a generated target. It reads imported objects only from the input's sibling
content-addressed store, checks that inputs remain unchanged, compares original
and generated resolved meaning, then publishes the absent output directory
atomically.

## Limits and diagnostics

Each semantic or binding TOML member is at most 1 MiB and strictly rejects
unknown fields. One semantic module admits at most 256 profiles; each profile
has at most 16 parameters, 64 includes, 1,024 resources, and structural depth
16. One binding catalogue has at most 8,192 cells and 32 native outputs per
cell. Projection admits at most 32,768 nodes, 131,072 edges, and 262,144
provenance entries.

One compressed pack is at most 8 MiB and 32 MiB decoded, with a 64 KiB manifest,
256 content members, and 1 MiB per content member. A resolved closure has at
most 64 sources and a bounded aggregate compressed size.

Admission and linking are atomic and deterministic. Diagnostics identify the
source/member, profile or field when applicable, category, detail, and TOML
line/column for syntax failures. Categories distinguish syntax and limits from
missing references, wrong domains, duplicates, conflicts, cycles, unused
requirements, unsupported projection, integrity, kind, and path failures.

## Non-goals

The language has no versions, provider categories, alternatives, defaults,
fallbacks, ordered overlays, arbitrary dependencies, scripts, remote fetch,
registries, signature policy, executable adapters, package removal, service
manager installation, account/group deletion, or dotfile/application
configuration. Adding one requires a separate authority and failure design; it
must not be encoded as a binding or reference spelling.
