# 13 — Bucket layout

This file owns the key layout of a Terrane store in an object store or on a
filesystem: which keys exist, what each holds, which are immutable, which
are written conditionally, and what an object-store backend must provide
for the layout to be safe under concurrent writers. The layout is the
durable form of the `bucket` backend and, by [STORE-13], of every `disk`
tier's persistent state.

## Overview

The layout borrows git's names because they are the right names: packs
under `objects/`, branches under `refs/heads/`, tags under `refs/tags/`,
reflogs under `logs/`, sidecars under `refs/notes/`. Only the names are
borrowed. The objects under them are Terrane packs and canonical CBOR
records, never git objects.

Everything under `objects/` is immutable and content- or id-addressed.
Everything under `refs/heads/` is mutable and changes only by
compare-and-swap. Everything under `logs/` and `refs/tags/` is written once
with create-if-absent. `gc/` holds the garbage collector's lease and cycle
markers. `trash/` holds tombstoned packs awaiting deletion. Protected
publication control selects these logical values through immutable commit
slots; payload copies carry portable selected history, not private authority.

## Key layout

```text
<prefix>/
  objects/
    pack/<aa>/<pack-id>.pack             sealed pack           immutable
    pack/<aa>/<pack-id>.idx              per-pack index        immutable
    index/<generation>/<shard>.idx            merged index shard    immutable
    index/<generation>/<shard>.flt            shard filter          immutable
    index/<generation>/MANIFEST               generation manifest        immutable
  refs/
    heads/<tenant>/<name>:record         branch ref record     CAS
    tags/<tenant>/<name>:record          tag ref record        create-once
    notes/<kind>/<tenant>/<name>:record  advisory sidecar      CAS
    jobs/<tenant>/<id>:record            tree-job ref record   CAS
    conflicts/<tenant>/<ref>/<seq>:record unresolved merge     CAS
    derived/<tenant>/<path>:record       realization root      CAS
  logs/
    refs/heads/<tenant>/<name>/<seq>:legacy migrated legacy log create-once
    <ref>/<seq>:<candidate-id>            candidate log record  create-once
  gc/
    lease                                collector lease       CAS
    cycle/<n>                            cycle marker          create-once
  trash/
    <cycle>/<pack-id>                    tombstone             create-once
  CAPABILITIES                           probe record          CAS
  publication/SELECTED-HISTORY            retained branch heads CAS
  publication/snapshots/<rev>:<operation> complete projection   create-once
  publication/PORTABLE                    exact snapshot       CAS
```

Protected control has the separately registered keys in
[`reference/bucket-key-registry.md`](reference/bucket-key-registry.md).
Its selection, activation and portable-copy rules are normative in
[`reference/publication-authority.md`](reference/publication-authority.md).

`<aa>` is the first two lowercase hexadecimal characters of the pack id, a
fan-out that keeps listings bounded on filesystems and spreads keys across
object-store partitions. `<tenant>` is a registered tenant identifier or the
literal `_` for a single-tenant store. `<seq>` is a zero-padded 20-digit
decimal so that lexical order is numeric order. Candidate IDs are secure-random
32-byte identifiers rendered as 64 lowercase hexadecimal digits. Candidate
filenames use a colon separator, disjoint from valid ref-name segments.
Layout version 2 appends the literal `:record` to the final segment of every
ref or advisory-sidecar key and `:legacy` to migrated sequence-only log keys.
These suffixes belong to bucket keys, never to public ref names, token patterns,
wire arguments or the key-10 ref-name inventory. Consequently records for both
`refs/heads/_/a` and `refs/heads/_/a/b` can coexist, as can a legacy log sequence
and a valid nested ref whose next segment is that decimal sequence. Candidate
IDs cannot equal `legacy`. The full registry of
prefixes, including reserved ones, is in
[`reference/bucket-key-registry.md`](reference/bucket-key-registry.md).

- **[BKT-1]** A conforming store MUST use exactly these keys under its
  prefix and MUST NOT write keys outside the registered prefixes.
  Unregistered keys found under a prefix MUST be ignored by readers and
  reported by scrub. *Gate:* `gate:bucket-key-registry`.
- **[BKT-2]** A key's mutability class (immutable, CAS, create-once) is
  fixed by this table. A store MUST NOT overwrite an immutable or
  create-once key, and MUST NOT write a CAS key without a condition.
  *Gate:* `gate:bucket-mutability-classes`.
- **[BKT-3]** The layout MUST be identical whether the backing store is an
  object store or a filesystem root. A directory produced by one MUST be
  readable as a bucket by the other after a byte-for-byte copy.
  *Gate:* `gate:bucket-file-layout`.

## What each key holds

### `objects/pack/`

Packs and per-pack indexes as defined in
[`12-pack-format.md`](12-pack-format.md). The `.idx` object is stored after
the `.pack` object and before any ref that references the pack's contents
([PACK-14]).

### `objects/index/<generation>/`

Merged index shards and filters for one compaction generation, plus a `MANIFEST`
listing every shard and filter in the generation with its hash and size,
so a reader can fetch a generation atomically and detect a partial one.

- **[BKT-4]** A generation's `MANIFEST` MUST be written last, after every
  shard and filter it lists. A reader MUST NOT use any shard from a
  generation whose
  `MANIFEST` is absent or lists a shard the reader cannot fetch or verify.
  The published generation MUST be selected through `CAPABILITIES` key 9
  by conditional selected publication after the manifest, and MUST NOT
  decrease.
  *Gate:* `gate:index-generation-manifest`.

The optional `CAPABILITIES` key 9 selects the current authoritative index
generation. A writer first stores and verifies every listed shard and
filter, then writes that generation's immutable `MANIFEST`, and finally
advances logical key 9 by selected CAS without decreasing its value. Readers
fetch this pointer and the exact named manifest; they never discover a
generation by `LIST`. An absent pointer supplies no published catalog.
Startup probes preserve the pointer, and a failed pointer CAS leaves an unpublished
generation available only for recovery. A manifest entry omits both filter
fields when no filter is published for that shard.

Optional manifest key 5 inventories published pack containers. Each entry
binds a pack id to the whole pack's identity and size and to its detached
index's identity and size. The inventory is ordered by pack id, has no
duplicates, and names only artifacts durably written before the manifest.
It makes whole-pack and detached-index `ContentStore` identities resolvable
without nesting packs or relying on `LIST`. Readers verify both artifacts
and their matching indexes before using an inventory entry; normal content
reads also honor the selected generation's tombstones. Container publication
does not make content excluded by those tombstones visible again.

Optional manifest key 6 binds every active physical pack exclusion to its
collection cycle and fencing epoch. It is a complete set sorted uniquely by
pack id; a present empty array establishes that no exclusion is active.
An absent legacy field does not establish that the set is empty. New catalog
publications preserve the exact complete set, including ordinary uploads that
readmit an identity into a fresh pack. The active binding governs whole-pack
and detached-index inventory lookup as well as member lookup. Its restore,
crash-recovery and deletion rules are GC-29.

Optional manifest key 7 is the complete permanent physical-pack burn set
under D-82. It MUST be sorted uniquely by unsigned pack-ID bytes and MUST
never lose an ID across selected generations. Present `[]` means known
empty; absent legacy key 7 means unknown. BKT-4 publication MUST preserve
the set on upload, repair, restore and compaction. A burn permanently
forbids serving or admitting the old pack and detached-index keys through
any member, container, inventory, cache or fallback path. It does not
quarantine the content identities, which may use verified fresh placements.
Unknown completeness MUST refuse remote deletion and same-ID readmission
unless independently qualified fenced migration establishes the exact set.
Its selected ownership, visibility and migration checks complete BKT-4
and BKT-5 in
[`reference/remote-deletion-authority.md`](reference/remote-deletion-authority.md).

### `refs/heads/`

One canonical CBOR ref record per branch
([`09-refs-and-commits.md`](09-refs-and-commits.md)): commit id, sequence,
writer epoch, home locality, and profile. Updated only by conditional write.

### `refs/tags/`

One ref record per tag, written once. A tag MAY carry a signed snapshot
envelope in its record.

### `refs/notes/`

Advisory sidecars keyed like refs: learned access profiles, prefetch hints,
and other data that MUST NOT affect identity or authority
([`19-tiering-and-topology.md`](19-tiering-and-topology.md)).

### `refs/jobs/`, `refs/conflicts/`, `refs/derived/`

Tree-job checkpoints, unresolved multi-writer merges, and memoized
realization roots, as registered by [`09-refs-and-commits.md`](09-refs-and-commits.md).
Job and derived refs are branches with the mutability of `refs/heads/`;
conflict refs advance by resolution at their original conflict key (REF-3).

### `logs/<ref>/`

Immutable reflog proposals for a branch. A candidate stores the complete
new and previous ref records, the previous commit, principal, reason and
timestamp. Whole-record head CAS selects one proposal per sequence. Only
that selected predecessor chain is committed history and supplies retained
content roots. Legacy sequence-only records remain readable.

### `gc/`

The collector lease record (holder, fencing epoch, expiry) and one marker
per completed cycle. See [`17-garbage-collection.md`](17-garbage-collection.md).

### `trash/`

One tombstone per pack removed from service, keyed by the cycle that
removed it. Bytes remain at `objects/pack/` until the deletion window
passes.

### `CAPABILITIES`

A record the store writes at first open and re-verifies on every open,
holding the results of the probes below and the layout version.

### Layout versions and legacy access

New authoritative namespaces MUST initialize layout version 2 before enabling
writes. Version 1 uses the former unsuffixed ref and sidecar keys and plain
20-digit legacy log filenames. Legacy record encodings and candidate-log keys
are unchanged. Explicit read-only compatibility MUST select the exact version-1
locations and refuse all writes, startup probe mutations and destructive
maintenance. A legacy reader MUST stop and reopen on a layout transition.
Ordinary version-2 write opens MUST refuse version 1 as migration-required;
opening an existing namespace MUST NOT silently upgrade its version. Unsupported
versions are refused. Probe updates preserve the selected version and all
optional authority fields. Version-2 filesystem effects verify their version
under the existing stable namespace exclusion.

D-79's CAPABILITIES key 11 independently marks checked publication authority.
Absent key 11 does not establish a fresh empty control chain. Activation of
existing version-2 payload requires the complete external quiescent fence,
validated genesis and restart rules in the publication reference. A layout
version alone never qualifies checked publication or destructive collection.

A version-1 to version-2 migration MUST establish exclusive, quiescent authority
over the complete namespace. It MUST stop and drain legacy readers, writers and
in-flight effects and prevent their resumption until cleanup and verification
complete. Filesystem migration also retains the actual stable exclusion inode;
the inode MUST NOT be replaced or unlinked. Provider migration requires actual
revocation or blocking of old write authority and drained conditional writes.
A `CAPABILITIES` CAS alone does not fence an already-open writer's independent
old ref key. A backend without this external authority MUST refuse migration.

Migration MUST have authoritative complete source evidence for the whole legacy
ref, sidecar and log namespace, not merely a selected subset. Every old regular
leaf that could obstruct a valid version-2 descendant MUST be relocated and
removed before ordinary version-2 admission. Key 10 inventories refs but does
not prove completeness of other artifacts. `LIST` is not completeness evidence;
unknown legacy completeness stays unknown. An implementation unable to prove
whole-namespace completeness MUST refuse migration and retain read-only
compatibility until such evidence is available.

Under the quiescent fence, migration MUST validate and durably create each new
key from the exact original bytes without replacing an existing destination.
An existing destination is usable only after exact equality; conflicting bytes
fail migration. All new keys MUST be durable before complete-record conditional
publication of version 2. The version switch preserves the profile, selected
generation, complete ref inventory and all other authority fields. Only after
the switch is durably established may obsolete version-1 files be removed,
using exact original-byte/version conditions and durable parent synchronization.
Cleanup and complete version-2 verification MUST finish before ordinary clients
resume, so old files cannot obstruct valid descendant directories.

After interruption, migration MUST reestablish its external fence and recover
from exact source/destination bytes and the authoritative selected version.
Matching duplicate bytes prove only that key's copy, never completeness or
writer exclusion. An uncertain version-switch outcome requires an authoritative
reread and MUST NOT be reported as success. If the fence cannot survive or be
reestablished without admitting clients, migration is unsupported. Version-2
writes never treat unsuffixed legacy copies as alternative mutable authority.
These rules are proved by BKT-1's registry, BKT-3's layout and BKT-14's CAS gates.

## Conditional writes

The layout has no separate coordinator database. Safety under concurrent
writers rests on conditional-write primitives and the registered immutable
publication chain. Mutable materialized payload keys are caches of selected
logical values once checked publication is active.

Two primitives are required:

1. **create-if-absent**: a write that fails if the key already exists.
2. **compare-and-swap**: a write that fails unless the key's current version
   matches a version the writer observed.

Their spelling on the major providers:

| Provider | create-if-absent | compare-and-swap |
| --- | --- | --- |
| Amazon S3 | `If-None-Match: *` on `PutObject` and `CompleteMultipartUpload` (generally available since August 2024) | `If-Match: <etag>` on `PutObject` (generally available since November 2024) |
| Google Cloud Storage | `x-goog-if-generation-match: 0` | `x-goog-if-generation-match: <generation>` |
| Cloudflare R2 | `If-None-Match: *` via the S3 API; `onlyIf.etagDoesNotMatch` via the Workers binding | `If-Match: <etag>` via the S3 API; `onlyIf.etagMatches` via the Workers binding |
| Filesystem | `open(O_CREAT \| O_EXCL)` then rename | write to a temporary name, `renameat2(RENAME_EXCHANGE)` or lock-and-rename against the observed inode |

- **[BKT-5]** A `ref_cas` on a `bucket` MUST compare the whole selected
  expected record or explicit absence and publish through D-79's exact
  next create-once commit slot. Backend version observations MUST remain
  opaque and MUST NOT substitute for the complete selected transaction or
  cross-key fence. A materialized ref-key update alone MUST NOT establish
  logical publication. *Gate:* `gate:bucket-ref-cas`.
- **[BKT-6]** A `ref_log_append` and every create-once key MUST be written
  with create-if-absent. A writer MUST treat a precondition failure as
  `exists` and MUST NOT retry with an unconditional write.
  *Gate:* `gate:bucket-create-once`.
- **[BKT-7]** Version tokens MUST be treated as opaque. An implementation
  MUST NOT parse an ETag, compare it to a content hash, or assume it is
  stable across providers, multipart uploads, or server-side copies.
  *Gate:* `gate:bucket-etag-opaque`.
- **[BKT-8]** A store MUST assume the object store provides strong
  read-after-write consistency for `GET` and `HEAD` of a key after a
  successful conditional `PUT` of that key. A store MUST NOT assume `LIST`
  is strongly consistent ([STORE-11]).
- **[BKT-9]** A multipart upload whose completion loses a conditional write
  MUST be aborted by the writer so it does not remain as orphaned storage.
  Where a writer cannot confirm the abort, the pack id MUST be recorded
  locally for a later abort attempt, and garbage collection MAY abort
  incomplete multipart uploads older than the grace window.
  *Gate:* `gate:bucket-multipart-abort`.

### Startup probe

Not every S3-compatible service honors conditional headers; some proxies
and older implementations silently drop them, which would turn a
compare-and-swap into an unconditional overwrite.

- **[BKT-10]** On every write-capable open, a `bucket` backend MUST probe both
  primitives against the `CAPABILITIES` key: perform a create-if-absent that is
  expected to fail against an existing key, and a compare-and-swap with a
  stale version token that is expected to fail. If either write succeeds,
  the backend MUST report `refs: single-writer` or, if configured to require
  multi-writer safety, MUST refuse to open. *Gate:* `gate:bucket-probe`.
  Explicit read-only legacy access performs no write probes and MUST NOT
  advertise verified ref-write capability.
  Active checked publication MUST additionally qualify actual linearizable
  create-if-absent and exact reads for its protected control namespace;
  a stale ETag failure alone does not qualify whole-transaction fencing.
- **[BKT-11]** A backend reporting `refs: single-writer` MUST refuse
  `ref_cas` and `ref_log_append` from more than one writer identity per
  process lifetime, and a `guard` above it MUST refuse tokens that would
  admit a second writer to any ref ([STORE-9], [STORE-28]).
- **[BKT-12]** The probe MUST also confirm ranged `GET` support and record
  whether presigned URLs can be minted; the results populate the capability
  set of [STORE-12].

## Filesystem backend

A `bucket(file://<root>)` is the same layout on a local filesystem.

- **[BKT-13]** Immutable keys MUST be written to a temporary name in the
  same directory, synced, and renamed into place with no-replace semantics;
  the parent directory MUST be synced after the rename.
  *Gate:* `gate:bucket-file-atomic-write`.
- **[BKT-14]** CAS keys on a filesystem MUST be implemented so that two
  concurrent writers cannot both succeed: either an exclusive lock held
  across read, compare, write, and rename, or an exchange rename against
  the observed inode. A filesystem that provides neither MUST be reported
  as `refs: single-writer`. *Gate:* `gate:bucket-file-cas`.
  Checked publication and each current-authority destructive effect MUST
  retain the same actual stable namespace exclusion through final comparison
  and effect, as defined in the publication reference.
Filesystem coordination files are separate from logical bucket keys.
Protected external-control `.terrane-creation/<key-digest>` journals retain
D-78's local physical incarnation evidence for collector artifacts. They are
not content, catalog members, imported snapshot authority or logical listing results;
only held backend exclusion may mutate them under GC-29's protocol.
The reserved `.terrane-locks/<key-digest>` files provide stable exclusion
inodes; `.terrane-tmp:<random-id>` files in a destination's directory hold
unpublished writes. Readers and logical listings ignore both, and scrub
recognizes them as coordination files rather than unknown bucket objects.
Writers never replace or unlink a live lock inode. A copied bucket recreates
locks locally and never treats copied staging files as published content.

- **[BKT-15]** A `disk` tier's durable state ([`14-host-tier.md`](14-host-tier.md))
  MUST be a valid `file://` bucket under this layout, extended only by the
  registered host-tier prefixes in
  [`reference/bucket-key-registry.md`](reference/bucket-key-registry.md).

## Tenancy in the key space

- **[BKT-16]** Refs, logs, and notes MUST be tenant-prefixed. Packs and
  indexes MUST NOT be tenant-prefixed; deduplication scope is enforced by
  disclosure domain ([`24-disclosure-domains.md`](24-disclosure-domains.md))
  and by `guard`, not by key layout. A store that requires physically
  separate byte pools per tenant uses separate prefixes or buckets and
  separate store expressions.

## Authoritative ref inventory

- **[BKT-17]** New buckets MUST initialize optional key 10 to a complete
  empty ref-name inventory before serving ref writes. The inventory MUST be
  sorted by unsigned UTF-8 bytes, contain unique registered full ref names,
  and never lose a name. Before first publishing a ref, its authority MUST
  durably add its name by whole-record `CAPABILITIES` CAS. Startup probes and
  index-pointer publication MUST preserve this inventory and key 11's
  publication marker. Active publication MUST select inventory, retained
  branch history and ref changes through the registered transaction protocol.
  Absence of key 10 in a legacy bucket means completeness is unknown, never
  an empty inventory.
  *Gate:* `gate:bucket-file-cas`.

A new empty inventory requires authoritative fresh bucket initialization;
opening an existing prefix or accepting a caller-supplied list is not proof
of completeness. Legacy migration must establish a complete inventory under
exclusive authority before installing key 10. Readers enumerate this exact
inventory and read each named ref from its authority; names may remain after
ref deletion or a losing first-write attempt. They do not infer completeness
from `LIST` or from the subset of names they happened to read.

## Interactions

- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the records
  under `refs/` and `logs/`.
- [`11-store-trait.md`](11-store-trait.md) maps `ref_cas`, `ref_log_append`,
  and `list` onto these keys and consumes the probe results.
- [`12-pack-format.md`](12-pack-format.md) defines the objects under
  `objects/`.
- [`14-host-tier.md`](14-host-tier.md) extends the filesystem form with
  host-only prefixes.
- [`17-garbage-collection.md`](17-garbage-collection.md) owns `gc/` and
  `trash/` and produces index generations.
- [`38-wasm-and-edge.md`](38-wasm-and-edge.md) relies on the R2 row of the
  conditional-write table.

## Informative: why refs are single keys rather than a log alone

A create-once proposal does not itself advance a branch: a writer may stop
between append and CAS, and concurrent writers may propose the same sequence.
Terrane keeps a whole-record logical CAS ref because readers and mirrors need
an exact selected head, and collectors need selected history independent of
bucket listings. The publication chain selects the head; the head selects its
candidate and complete predecessor chain. An inconsistent or missing selected
log is corruption; a reader never repairs the head from an unselected proposal.
