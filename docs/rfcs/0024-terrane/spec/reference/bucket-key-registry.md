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

Further purpose strings are used for derivations or signatures that are not
stored objects and therefore never appear as immutable kinds in a pack:

| Domain string | Use | Owner |
| --- | --- | --- |
| `terrane-gear-v1` | seed of the BLAKE3-XOF that derives a chunk profile's gear table | 05, [`golden-vectors.md`](golden-vectors.md) |
| `terrane-disclosure-target-v1` | BLAKE3-256 binding of the normalized unsigned destination commit | 23, `disclosure-statement` |
| `terrane-disclosure-proof-v1` | Ed25519 preimage prefix for the canonical source-authority disclosure statement | 23, `disclosure-statement` |

A new digest algorithm is a new profile with its own domain set (OBJ-9);
the `-v1` suffix is part of the string and is not incremented in place.

## Bucket keys

All keys are relative to the store prefix. Mutability classes are those of
[`../13-bucket-layout.md`](../13-bucket-layout.md) BKT-2: **immutable**
keys are written once and never changed; **create-once** keys are written
with create-if-absent; **CAS** keys are written only with compare-and-swap.
`<aa>` is the first two lowercase hexadecimal characters of the pack id;
`<tenant>` is a registered tenant identifier or `_`; `<seq>` is a
zero-padded 20-digit decimal. `<candidate-id>` is the lowercase 64-digit
hexadecimal form of a secure-random 32-byte reflog proposal ID. The colon
separator in a candidate filename cannot occur in a valid ref segment.
The following primary keys belong to layout version 2. Ref and sidecar leaves
append `:record`, and migrated legacy logs append `:legacy`. Public ref names
and the authoritative ref inventory remain unsuffixed. Version-1 unsuffixed
records and sequence files are registered only for explicit read-only legacy
access and externally fenced migration under BKT-3; they are never alternate
mutable authorities in version 2.

| Key | Holds | Class | Writer | Owner |
| --- | --- | --- | --- | --- |
| `objects/pack/<aa>/<pack-id>.pack` | pack file | immutable | any committing writer, compaction | 12, 13 |
| `objects/pack/<aa>/<pack-id>.idx` | per-pack index object | immutable | the pack's writer | 12, 13 |
| `objects/index/<generation>/<shard>.idx` | merged index shard | immutable | collector | 12, 13, 17 |
| `objects/index/<generation>/<shard>.flt` | shard filter | immutable | collector | 12, 13 |
| `objects/index/<generation>/MANIFEST` | `IndexGenerationManifest`, written last | immutable | collector | 13 |
| `refs/heads/<tenant>/<name>:record` | `RefRecord` of a branch | CAS | holders of `commit` | 09, 13 |
| `refs/tags/<tenant>/<name>:record` | `RefRecord` of a tag | create-once | holders of `tag` | 09, 13 |
| `refs/notes/<kind>/<tenant>/<name>:record` | advisory sidecar record | CAS | any authorized writer | 09, 13 |
| `refs/jobs/<tenant>/<id>:record` | `RefRecord` of a tree-job branch | CAS | the job | 09, 32 |
| `refs/conflicts/<tenant>/<ref>/<seq>:record` | `RefRecord` of an unresolved multi-writer merge | CAS | the losing writer, then resolvers | 09, 20 |
| `refs/derived/<tenant>/<name>:record` | `RefRecord` of a ruleset-derived root | CAS | realizing instances | 09, 31 |
| `logs/refs/heads/<tenant>/<name>/<seq>:legacy` | migrated legacy `RefLogRecord` | create-once | qualified migrator | 09, 13 |
| `logs/<ref>/<seq>:<candidate-id>` | selected/proposed `RefLogRecord` | create-once | the advancing writer | 09, 13 |
| `gc/lease` | `GcLease` | CAS | collector | 17 |
| `gc/cycle/<n>` | cycle completion marker | create-once | collector | 13, 17 |
| `gc/<cycle>/roots` | root-set snapshot of a collection (GC-4) | create-once | collector | 17 |
| `gc/<cycle>/mark/<shard>` | final mark-set checkpoint (GC-7) | create-once | collector | 17 |
| `gc/<cycle>/mark/<shard>/<revision>` | immutable incremental `GcMark` checkpoint | create-once | collector | 17 |
| `gc/<cycle>/state` | fenced `GcState` progress and checkpoint pointers | CAS | collector | 17 |
| `trash/<cycle>/<pack-id>` | `Tombstone` | create-once | collector | 13, 17 |
| `CAPABILITIES` | `Capabilities`, including the store profile | CAS | the opening store | 13, 04 |
| `publication/SELECTED-HISTORY` | portable complete `SelectedHistory`, including absent branches | CAS | selected publication | 09, 13, 17 |
| `publication/snapshots/<revision>:<operation-id>` | `PortableSnapshot` complete checkpoint or exact projection delta | create-once | selected publication | 09, 13 |
| `publication/PORTABLE` | exact `PortableCurrent` snapshot pointer | CAS | selected publication | 09, 13 |

Candidate-log `<ref>` values are registered branch names in `refs/heads/`,
`refs/jobs/`, `refs/conflicts/` or `refs/derived/`. Tags and advisory notes do
not acquire candidate logs. Candidate and migrated legacy filenames are
disjoint from valid ref segments. Neither a nested `<seq>/<candidate-id>`
directory nor an unsuffixed version-2 ref or legacy-log leaf is registered.

Portable snapshot revisions are canonical unsigned decimal. Their operation
IDs are the creating transaction's secure 32-byte nonce in lowercase 64-hex.
`publication/PORTABLE` selects one exact immutable snapshot; staged proposals
do not select themselves, and individual cache files cannot replace that
complete projection during fresh-copy validation.

Registered sidecar kinds under `refs/notes/`: `profiles` (learned access
profiles, [`../19-tiering-and-topology.md`](../19-tiering-and-topology.md)),
`completeness` (cached completeness per property,
[`../08-properties.md`](../08-properties.md)), `memos` (recipe memo
pointers, [`../10-derived-data.md`](../10-derived-data.md)).

Keys under any other prefix are reserved. A reader MUST ignore them and
scrub MUST report them (BKT-1).

## Protected publication control keys

D-79 registers these names relative to the backend's protected control
namespace, outside the portable local bucket root. They are not packed
content or ordinary import authority. Remote control namespaces use the
same names under genuinely registered provider authority. Protocol and
copy rules are in [`publication-authority.md`](publication-authority.md).

| Key | Holds | Class |
| --- | --- | --- |
| `backend-registration.cbor` | actual `BackendRegistration` activation/recovery binding | CAS |
| `publication/commits/<revision>` | authoritative `PublicationCommit` slot | create-once |
| `publication/transactions/<operation-id>` | exact `PublicationTransaction` | create-once |
| `publication/lineage/<digest>` | privately checked `CheckedLineage` | create-once |
| `publication/guards/<digest>` | immutable complete `GuardSnapshot` | create-once |
| `publication/STATE` | optional nonauthoritative selected state cache | CAS |
| `publication/CURRENT` | optional nonauthoritative `PublicationCurrent` cache | CAS |
| `gc/<cycle>/fence/<revision>` | exact current-v1 or copied-placement-v2 `GcFence` | create-once |
| `gc/<cycle>/reconcile/<operation-id>/<revision>` | exact local-v1 or permanent-v2 `GcReconciliation` | create-once |
| `gc/<cycle>/delete/<pack-id>/<operation-id>` | protected local-v1 or permanent/copied-v2 `DeleteOperation` | CAS |

Cycle/revision are canonical unsigned decimal, without leading zeroes
except `0`. Operation IDs are fresh secure 32-byte nonces in lowercase
64-hex form. Digests are lowercase 64-hex raw BLAKE3 of exact canonical
control bytes, without a content identity domain. A digest or named key
does not provide its private creation capability. Commit slots and
selected transactions remain retrievable and cannot be pruned or reused
without a separately registered protocol. D-82's
[remote deletion authority](remote-deletion-authority.md) registers the
version-2 sweep/copied-retirement preparations, ownership, placement fence
and repeatable-pass alternatives, selected
state key 7 and publication-proof case 3 at
these existing keys. Permanent-v2 owner/pass progress uses selected
transactions; its physical CAS record is a cache. Local-v1 physical CAS
remains unchanged. No key class or old local-version-1 bytes change.

Original-authority control has independently configured ownership. These
existing create-once records retain their canonical local schemas:

| Relative key | Holds |
| --- | --- |
| `registration.cbor` | `physical-registration` |
| `bootstrap-<original-id>-<ref-digest>-<epoch>.cbor` | `OriginalBootstrap` |
| `commit-<commit-id>.cbor` | `OriginalAssociation` |
| `import-<commit-id>.cbor` | `OriginalImport` |
| `import-binding-<commit-id>.cbor` | `OriginalImportBinding` |
| `import-trust-<import-digest>.cbor` | `OriginalImportTrust` |

IDs and digests are lowercase 64-hex; ref-digest is raw BLAKE3 of the exact
full ref name's UTF-8 bytes, and epoch is canonical unsigned decimal.
Exact relative selectors are consumed control pins, never inferred from
LIST. No ordinary bucket key or copied record creates this authority.

## Filesystem coordination files

These registered filesystem-only names implement BKT-13 and BKT-14 and
are not logical bucket keys or objects. They do not appear in object-store
buckets, authoritative catalogs, or logical listings.

| Name | Holds | Rule |
| --- | --- | --- |
| `.terrane-locks/<key-digest>` | local exclusion inode | stable while writers can hold it; never replaced or unlinked |
| `<protected-control>/.terrane-creation/<key-digest>` | protected `CreationJournal` incarnation evidence | replaced only under backend exclusion; never exposed or imported as content |
| `<directory>/.terrane-tmp:<random-id>` | unpublished staged bytes | synced before atomic publication; never readable as content |

`<key-digest>` is lowercase hexadecimal BLAKE3-256 of the logical key's
ASCII bytes; `<random-id>` is lowercase hexadecimal of 16 secure random
bytes. Coordination files have no content identity or cross-provider
version token. Creation journals supply only backend-local incarnation evidence.

Default protected backend control is the sibling
`.terrane-control:<root-digest>` outside the bucket root. The digest is raw
BLAKE3 of normalized absolute root bytes in lowercase 64-hex form. This is
a filesystem control placement, not a logical bucket key. Explicit external
control configuration may override the default while preserving its checked
physical ownership and copy boundary.

Deletion `<operation-id>` is the lowercase 64-digit hexadecimal spelling of
a fresh secure 32-byte nonce. Immutable operation authorization and exact
journal ownership permit physical recovery only; they never replace current
complete root, lease, catalog or exclusion checks. Ordinary logical writes
and content import MUST NOT create or replace this protected authority.

The colon in staging names is forbidden by REF-1, so a staged file cannot
alias a valid ref segment.

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
