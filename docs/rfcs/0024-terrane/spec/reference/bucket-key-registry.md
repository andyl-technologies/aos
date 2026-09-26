# Reference: identity domains, bucket keys, host-tier prefixes, and gate names

The authoritative registry of identity domain strings
([`../04-content-model.md`](../04-content-model.md) OBJ-2), bucket key
prefixes ([`../13-bucket-layout.md`](../13-bucket-layout.md) BKT-1), the
host-tier prefixes that extend a `file://` bucket
([`../14-host-tier.md`](../14-host-tier.md) HOST-1, BKT-15), and the grammar
of gate names ([`../00-conventions.md`](../00-conventions.md) §Gates). A
string absent from this document is unregistered
([`../00-conventions.md`](../00-conventions.md) CONV-3).

## Identity domains

Every immutable's identity is BLAKE3-256 over `domain || 0x00 || bytes`.
Each domain names one kind and one CDDL type in
[`terrane-v1.cddl`](terrane-v1.cddl).

| Domain string | Kind | Encoded as | Owner |
| --- | --- | --- | --- |
| `terrane-chunk-v1` | data chunk | plaintext bytes | 04, 05 |
| `terrane-manifest-v1` | object manifest | `manifest` | 04 |
| `terrane-node-v1` | tree node | `node` | 04, 06 |
| `terrane-commit-v1` | commit | `commit` (including its signature) | 04, 09 |
| `terrane-bundle-v1` | bundle | `bundle` | 04, 12 |
| `terrane-pack-v1` | pack file | binary pack bytes | 04, 12 |
| `terrane-index-v1` | per-pack index object or merged shard | binary index bytes | 04, 12 |
| `terrane-filter-v1` | filter | `filter` | 04, 12 |
| `terrane-attr-v1` | derived attribute record | `AttrRecord` | 04, 10 |
| `terrane-policy-v1` | ruleset, policy object, or token when hashed | `ruleset` / `token` | 04, 31, 22 |
| `terrane-memo-v1` | recipe memo | `memo` | 04, 10 |

Two further domain strings are used for derivations that are not stored
objects and therefore never appear in a pack:

| Domain string | Use | Owner |
| --- | --- | --- |
| `terrane-gear-v1` | seed of the BLAKE3-XOF that derives a chunk profile's gear table | 05, [`golden-vectors.md`](golden-vectors.md) |

A new digest algorithm is a new profile with its own domain set (OBJ-9);
the `-v1` suffix is part of the string and is not incremented in place.

## Bucket keys

All keys are relative to the store prefix. Mutability classes are those of
[`../13-bucket-layout.md`](../13-bucket-layout.md) BKT-2: **immutable**
keys are written once and never changed; **create-once** keys are written
with create-if-absent; **CAS** keys are written only with compare-and-swap.
`<aa>` is the first two lowercase hexadecimal characters of the pack id;
`<tenant>` is a registered tenant identifier or `_`; `<seq>` is a
zero-padded 20-digit decimal.

| Key | Holds | Class | Writer | Owner |
| --- | --- | --- | --- | --- |
| `objects/pack/<aa>/<pack-id>.pack` | pack file | immutable | any committing writer, compaction | 12, 13 |
| `objects/pack/<aa>/<pack-id>.idx` | per-pack index object | immutable | the pack's writer | 12, 13 |
| `objects/index/<epoch>/<shard>.idx` | merged index shard | immutable | collector | 12, 13, 17 |
| `objects/index/<epoch>/<shard>.flt` | shard filter | immutable | collector | 12, 13 |
| `objects/index/<epoch>/MANIFEST` | `IndexEpochManifest`, written last | immutable | collector | 13 |
| `refs/heads/<tenant>/<name>` | `RefRecord` of a branch | CAS | holders of `commit` | 09, 13 |
| `refs/tags/<tenant>/<name>` | `RefRecord` of a tag | create-once | holders of `tag` | 09, 13 |
| `refs/notes/<kind>/<tenant>/<name>` | advisory sidecar record | CAS | any authorized writer | 09, 13 |
| `refs/jobs/<tenant>/<id>` | `RefRecord` of a tree-job branch | CAS | the job | 09, 32 |
| `refs/conflicts/<tenant>/<ref>/<seq>` | `RefRecord` of an unresolved multi-writer merge | CAS | the losing writer, then resolvers | 09, 20 |
| `refs/derived/<tenant>/<name>` | `RefRecord` of a ruleset-derived root | CAS | realizing instances | 09, 31 |
| `logs/refs/heads/<tenant>/<name>/<seq>` | `RefLogRecord` | create-once | the advancing writer | 09, 13 |
| `gc/lease` | `GcLease` | CAS | collector | 17 |
| `gc/epoch/<n>` | epoch completion marker | create-once | collector | 13, 17 |
| `gc/<epoch>/roots` | root-set snapshot of a collection (GC-4) | create-once | collector | 17 |
| `gc/<epoch>/mark/<shard>` | mark-set checkpoint (GC-8) | create-once | collector | 17 |
| `trash/<epoch>/<pack-id>` | `Tombstone` | create-once | collector | 13, 17 |
| `CAPABILITIES` | `Capabilities`, including the store profile | CAS | the opening store | 13, 04 |

Registered sidecar kinds under `refs/notes/`: `profiles` (learned access
profiles, [`../19-tiering-and-topology.md`](../19-tiering-and-topology.md)),
`completeness` (cached completeness per property,
[`../08-properties.md`](../08-properties.md)), `memos` (recipe memo
pointers, [`../10-derived-data.md`](../10-derived-data.md)).

Keys under any other prefix are reserved. A reader MUST ignore them and
scrub MUST report them (BKT-1).

## Host-tier prefixes

A `disk` tier is a `file://` bucket in the layout above plus these
prefixes, which MUST NOT appear in an object-store bucket (BKT-15,
HOST-1).

| Prefix | Holds | Owner |
| --- | --- | --- |
| `chunks/<aa>/<hash>.<codec>` | cached individual chunk bodies, byte-identical to pack bodies (HOST-2) | 14 |
| `sealed/<aa>/<object-hash>` | sealed whole files, immutable by fs-verity or equivalent (HOST-3) | 14 |
| `staging/<publisher-id>/…` | publisher-private staging, never served (HOST-5) | 14 |
| `quarantine/<hash>` | content that failed verification, awaiting scrub | 14 |
| `pending-delete/<hash>` | first phase of two-phase delete | 14 |
| `state/` | embedded key-value store: pins, reservations, leases, verity bindings; never on the read path | 14 |

`<codec>` in `chunks/` is the decimal codec byte (`0`, `1`, `2`). Host
tiers per disclosure domain use one such layout per domain
([`../24-disclosure-domains.md`](../24-disclosure-domains.md)).

## Gate names

A gate is written `gate:<name>` where `<name>` matches:

```text
name    = segment *( "-" segment )
segment = 1*( %x61-7A / %x30-39 )        ; lowercase ASCII letters and digits
```

The first segment SHOULD be the lowercase area of the owning file's
requirement prefix (`tree`, `pack`, `gc`, `auth`, `perf`, …) so that a name
reads as `gate:<area>-<check>`. Names are unique across the specification;
[`../36-testing-and-conformance.md`](../36-testing-and-conformance.md)
§Gate registry is the authoritative list, and a gate cited by a requirement
but absent from that registry is a conformance error of this document
(TEST-16). `gate:perf-*` names are reserved for the measured budgets of
[`../35-performance-targets.md`](../35-performance-targets.md).

An adopting project maps a gate to its own check names outside this
directory; the mapping MUST preserve the gate name as a suffix so that a
failing check is traceable to the requirement it enforces.
