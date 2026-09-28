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
markers. `trash/` holds tombstoned packs awaiting deletion. There is
nothing else.

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
    heads/<tenant>/<name>                branch ref record     CAS
    tags/<tenant>/<name>                 tag ref record        create-once
    notes/<kind>/<tenant>/<name>         advisory sidecar      CAS
    jobs/<tenant>/<id>                   tree-job ref record   CAS
    conflicts/<tenant>/<ref>/<seq>       unresolved merge      create-once
    derived/<tenant>/<path>              realization root      CAS
  logs/
    refs/heads/<tenant>/<name>/<seq>     commit log record     create-once
  gc/
    lease                                collector lease       CAS
    cycle/<n>                            cycle marker          create-once
  trash/
    <cycle>/<pack-id>                    tombstone             create-once
  CAPABILITIES                           probe record          CAS
```

`<aa>` is the first two lowercase hexadecimal characters of the pack id, a
fan-out that keeps listings bounded on filesystems and spreads keys across
object-store partitions. `<tenant>` is a registered tenant identifier or the
literal `_` for a single-tenant store. `<seq>` is a zero-padded 20-digit
decimal so that lexical order is numeric order. The full registry of
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
  *Gate:* `gate:index-generation-manifest`.

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
conflict records are written once at their sequence number.

### `logs/refs/heads/`

The ordered commit log for a branch. Each record is written once at its
sequence number and holds the commit id, the previous sequence, the writer
epoch, and a timestamp. The log is the reflog, the snapshot list, and the
garbage-collection root set for the branch.

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

## Conditional writes

The layout has no coordinator. Safety under concurrent writers rests
entirely on the object store's conditional-write primitives.

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

- **[BKT-5]** A `ref_cas` on a `bucket` MUST be implemented as a
  compare-and-swap on the ref key using the version token (ETag,
  generation, or inode identity) observed by the most recent read of that
  key. A `ref_cas` with `expect = absent` MUST be implemented as
  create-if-absent. *Gate:* `gate:bucket-ref-cas`.
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

- **[BKT-10]** On every open, a `bucket` backend MUST probe both primitives
  against the `CAPABILITIES` key: perform a create-if-absent that is
  expected to fail against an existing key, and a compare-and-swap with a
  stale version token that is expected to fail. If either write succeeds,
  the backend MUST report `refs: single-writer` or, if configured to require
  multi-writer safety, MUST refuse to open. *Gate:* `gate:bucket-probe`.
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

A numbered create-once log is sufficient on its own to serialize writers:
the writer that creates `<seq+1>` wins. Terrane keeps a separate CAS ref
record as well because readers need one key to fetch, mirrors need one key
to replicate, and a garbage collector needs one key to root from without
listing. The log remains the authoritative history and the CAS record is a
pointer into it; a reader that finds them inconsistent trusts the log and
repairs the pointer ([`09-refs-and-commits.md`](09-refs-and-commits.md)).
