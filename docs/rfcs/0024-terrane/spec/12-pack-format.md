# 12 — Pack format and indexes

This file owns the on-disk and in-bucket container for immutable content:
the pack file, the per-pack index written beside it, the merged index shards
that let a reader find any content hash without opening every pack, the
approximate-membership filters that let a writer avoid negotiation round
trips, and the bundle, a meta object that ships a whole tree ahead of a
mount. Packs are the unit of upload, of ranged reads, of redundancy
placement, of compaction, and of garbage collection.

## Overview

A pack is an append-only sequence of entries followed by an index of those
entries and a footer that locates the index. The pack is self-describing: a
reader with only the pack's bytes can recover every entry's identity,
offset, length, codec, and kind. That property is what makes it safe to have
no database: every index in the system is a cache that can be rebuilt from
packs.

Every writer owns the packs it is writing. There are no shared open packs,
no leases on partially written packs, and no reaper for abandoned ones. A
writer seals a pack when it reaches a size threshold or a time threshold,
uploads it with its index, and only then references its contents from a
tree or commit. A tiny commit produces a tiny pack; compaction merges small
packs later ([`17-garbage-collection.md`](17-garbage-collection.md)).

Packs hold two classes of entry: data chunks, and meta objects (tree nodes,
manifests, commits, bundles, filters). Meta objects go into separate meta
packs so that a cold tree walk is a few large range reads rather than
hundreds of small ones scattered across data packs.

## Pack file layout

All integers are little-endian. Offsets are from the start of the file.

```text
+------------------+
| header (24 B)    |
+------------------+
| entry bodies ... |   concatenated, in write order, no padding required
+------------------+
| index            |   magic, count, fixed-width entries
+------------------+
| footer (16 B)    |
+------------------+
```

### Header

| Offset | Width | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `TRPK` |
| 4 | 2 | version | `1` |
| 6 | 2 | flags | bit 0: bodies are compressed by default; bit 1: meta pack; bits 2–15 reserved, zero |
| 8 | 16 | pack id | 128-bit random identifier chosen by the writer |

- **[PACK-1]** A pack MUST begin with the header above. A reader MUST reject
  a pack whose magic or version it does not recognize and MUST reject a pack
  with reserved flag bits set. *Gate:* `gate:pack-header`.
- **[PACK-2]** The pack id MUST be generated from at least 122 bits of
  entropy by the writer and MUST be the identifier under which the pack is
  stored ([`13-bucket-layout.md`](13-bucket-layout.md)). Two packs with the
  same id MUST be treated as the same pack. *Gate:* `gate:pack-id-unique`.

### Entry bodies

Each body is the stored bytes of one entry: a data chunk compressed with the
entry's codec, or a meta object in its canonical encoding. Bodies are
concatenated in the order the writer emitted them. A body MAY be followed by
padding only if the index records the padded offset of the next body.

### Index

The index begins with a 12-byte preamble and holds one fixed 56-byte entry
per body.

| Offset | Width | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `TRIX` |
| 4 | 8 | count | number of entries |

Each entry:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 32 | hash | content identity in the entry's domain ([`04-content-model.md`](04-content-model.md)) |
| 32 | 8 | offset | body offset from start of file |
| 40 | 4 | body length | stored (compressed) length |
| 44 | 4 | uncompressed length | plaintext length; equals body length when codec is `raw` |
| 48 | 1 | codec | `0` raw, `1` zstd, `2` zstd with dictionary; others reserved |
| 49 | 1 | kind | entry kind, see below |
| 50 | 2 | dictionary id | dictionary registry id when codec is `2`, else zero |
| 52 | 4 | reserved | zero |

Entry kinds:

| Value | Kind | Domain |
| --- | --- | --- |
| `0` | data chunk | chunk |
| `1` | manifest | object |
| `2` | tree node | tree |
| `3` | commit | commit |
| `4` | bundle | bundle |
| `5` | filter | filter |
| `6` | per-pack index copy | index |

- **[PACK-3]** Index entries MUST be sorted by hash ascending so that a
  reader can binary-search a mapped index. *Gate:* `gate:pack-index-sorted`.
- **[PACK-4]** Every body MUST be covered by exactly one index entry. A
  reader MUST reject a pack whose bodies and index disagree in count,
  offset, or length. *Gate:* `gate:pack-index-consistent`.
- **[PACK-5]** A pack MUST NOT contain two entries with the same hash and
  kind. It MAY contain the same hash under two kinds only when the domains
  are different by construction ([`04-content-model.md`](04-content-model.md)
  makes this impossible for well-formed content, so a reader MUST treat it as
  corruption). *Gate:* `gate:pack-index-consistent`.
- **[PACK-6]** The `kind` byte MUST be present and MUST match the identity
  domain under which the entry's hash was computed. A reader MUST NOT serve
  an entry under a kind other than the one recorded.
  *Gate:* `gate:pack-kind-domain`.

### Footer

| Offset | Width | Field | Value |
| --- | --- | --- | --- |
| 0 | 8 | index offset | offset of the index preamble |
| 8 | 4 | index crc | CRC32C over the index preamble and all entries |
| 12 | 4 | magic | ASCII `TRPE` |

- **[PACK-7]** A reader MUST locate the index through the footer, MUST
  verify the index CRC before using any entry, and MUST verify each body's
  content hash before serving it; the CRC protects the index, not the
  bodies. *Gate:* `gate:pack-footer-crc`.

## Self-describing recovery

- **[PACK-8]** Given only the bytes of a pack, an implementation MUST be
  able to reconstruct its per-pack index and every entry's identity without
  any external metadata. *Gate:* `gate:pack-self-describing`.
- **[PACK-9]** A pack whose footer or index is missing or corrupt MAY be
  recovered by scanning bodies from the header forward, decoding each body,
  and recomputing identities; entries that fail to decode or verify MUST be
  discarded and the pack MUST be rewritten by compaction rather than served
  in place. *Gate:* `gate:pack-scan-recovery`.

## Writer discipline

- **[PACK-10]** A pack MUST have exactly one writer, and that writer MUST
  hold the pack entirely locally until it is sealed. A store MUST NOT
  expose, index, or reference a pack before its writer has sealed and
  stored it together with its per-pack index.
  *Gate:* `gate:pack-single-writer`.
- **[PACK-11]** A writer MUST seal a data pack when its body size reaches
  32 MiB, and SHOULD seal an open pack after a bounded interval (RECOMMENDED
  30 seconds) so that a small commit never waits for a pack to fill. A
  writer MAY seal earlier. A meta pack SHOULD be sealed at the end of the
  commit that produced it.
- **[PACK-12]** A writer MUST emit data chunks into packs in tree order:
  entries of one directory adjacent, and the chunks of one object
  consecutive, so that a reader needing one file or one directory finds its
  bytes contiguous ([`21-bandwidth.md`](21-bandwidth.md)). Where an object's
  chunks already exist in other packs, the writer MUST NOT duplicate them.
  *Gate:* `gate:pack-tree-locality`.
- **[PACK-13]** Data chunks and meta objects MUST NOT be mixed in one pack.
  A meta pack sets header flag bit 1 and contains only kinds `1` through
  `6`. *Gate:* `gate:pack-meta-separation`.
- **[PACK-14]** The commit order in [`09-refs-and-commits.md`](09-refs-and-commits.md)
  applies: packs, then per-pack indexes, then the ref. A writer MUST NOT
  update a ref that references content in a pack whose index has not been
  stored. *Gate:* `gate:commit-order`.

## Per-pack index objects

Beside every pack the writer stores a copy of the pack's index as a separate
object, so a reader can learn a pack's contents without a range read into
the pack's tail.

- **[PACK-15]** The per-pack index object MUST be byte-identical to the
  index section of the pack, prefixed by the pack header, and stored under
  the pack id with the `.idx` suffix
  ([`13-bucket-layout.md`](13-bucket-layout.md)). *Gate:* `gate:pack-idx-object`.
- **[PACK-16]** A reader MUST treat the pack's own trailing index as
  authoritative when the two disagree, and MUST report the disagreement as
  corruption of the `.idx` object.

## Merged index shards

Per-pack indexes answer "what is in this pack." Merged indexes answer "which
pack holds this hash." They are periodically compacted by the garbage
collector's compaction phase and cached on local storage by every tier.

```text
objects/index/<generation>/<shard>.idx
```

`generation` is the compaction generation that produced the shard
([`17-garbage-collection.md`](17-garbage-collection.md)). `shard` is the first
byte of the content hash, so there are at most 256 shards per generation and a
lookup touches exactly one.

Each shard has the same preamble as a pack index and entries of this shape:

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 32 | hash | content identity |
| 32 | 16 | pack id | pack holding the body |
| 48 | 8 | offset | body offset within the pack |
| 56 | 4 | body length | |
| 60 | 4 | uncompressed length | |
| 64 | 1 | codec | |
| 65 | 1 | kind | |
| 66 | 1 | state | `0` live, `1` tombstone |
| 67 | 5 | reserved | zero |

- **[PACK-17]** Merged shards MUST be sorted by hash, MUST be immutable once
  written, and MUST be superseded only by a shard for a later generation. A
  reader consults the newest generation it holds and falls back to per-pack
  indexes for packs newer than that generation.
  *Gate:* `gate:index-shard-generations`.
- **[PACK-18]** A tombstone entry MUST be written for every hash whose pack
  was tombstoned by garbage collection, and MUST persist until the following
  compaction generation confirms the pack's bytes were deleted. A reader MUST NOT
  serve a hash whose newest entry is a tombstone.
  *Gate:* `gate:index-tombstones`.
- **[PACK-19]** An index refresh MUST be expressible as the set of shards
  whose generation is newer than the reader's, so that refreshing costs bytes
  proportional to change rather than to the index
  ([`21-bandwidth.md`](21-bandwidth.md)).
- **[PACK-20]** The merged index is a cache. An implementation MUST be able
  to rebuild every shard from per-pack index objects alone
  ([STORE-11] in [`11-store-trait.md`](11-store-trait.md)).
  *Gate:* `gate:index-rebuild`.

## Filters

A filter is an approximate-membership structure over one merged shard. It
lets a writer skip `has` for chunks the authority almost certainly holds,
and lets a `routed` store order children before asking them.

- **[PACK-21]** Each merged shard MUST have a filter object at
  `objects/index/<generation>/<shard>.flt`. The filter MUST be a ribbon or
  cuckoo filter over the shard's live hashes with a false-positive rate at
  or below 1% and a size of about one byte per entry.
  *Gate:* `gate:index-filter`.
- **[PACK-22]** A filter result MUST be used only as a hint. A positive
  result MUST be confirmed by `has` before a writer omits an upload; a
  negative result is definitive and MAY skip `has`.
  *Gate:* `gate:index-filter-hint-only`.
- **[PACK-23]** Filters MUST be fetched by generation delta like the shards they
  cover.

## Bundles

A bundle is a meta object that carries every tree node, manifest, and commit
a reader needs to realize a view, minus those the reader states it already
holds. It exists so that a mount never waits on per-node fetches.

- **[PACK-24]** A bundle MUST be a canonical CBOR object
  (`reference/terrane-v1.cddl` `bundle`) holding a list of `(kind, hash,
  bytes)` triples and the root commit it serves. A reader MUST verify each
  triple's identity before caching it and MUST reject the whole bundle if
  any triple fails. *Gate:* `gate:bundle-verify`.
- **[PACK-25]** A server producing a bundle MUST omit every object the
  requester lists as held, and SHOULD order the remaining objects root
  first so that a reader can begin lookup before the bundle is fully read.
- **[PACK-26]** A bundle is content-addressed like any meta object and MAY be
  cached and served from any tier.

## Whole-pack fetch

- **[PACK-27]** When a reader determines that a view needs at least a
  configurable fraction of a pack's bodies (RECOMMENDED default 50% by
  bytes), it SHOULD fetch the whole pack in one request rather than
  coalesced ranges, and MUST verify each body it admits exactly as it would
  for a ranged read.
- **[PACK-28]** Bodies fetched as part of a whole-pack or coalesced range
  read but not requested ("bystanders") MAY be admitted into a cache tier
  after verification and MUST NOT be pinned by that admission
  ([`14-host-tier.md`](14-host-tier.md)).

## Interactions

- [`04-content-model.md`](04-content-model.md) defines the identity domains
  that the `kind` byte selects.
- [`05-chunking.md`](05-chunking.md) defines the codecs and dictionary
  registry referenced by index entries.
- [`11-store-trait.md`](11-store-trait.md) defines `get` with a range, which
  resolves through these indexes to a body offset.
- [`13-bucket-layout.md`](13-bucket-layout.md) names where packs, indexes,
  and filters live.
- [`17-garbage-collection.md`](17-garbage-collection.md) tombstones packs,
  compacts under-utilized ones, and produces merged index generations.
- [`18-protocol.md`](18-protocol.md) carries bundles and filters over the
  wire.
- [`21-bandwidth.md`](21-bandwidth.md) relies on tree-order locality,
  filters, and generation deltas.

## Informative: what the format deliberately omits

There are no delta chains between entries: every body is independently
decodable so a ranged read never has to resolve another body first. There
are no loose objects: a one-chunk commit is a one-entry pack, which costs one
PUT and one index object rather than a directory of tiny keys. There is no
shared-open-pack protocol: the price is more small packs from busy writers,
paid back by compaction, and the reward is that no writer ever waits on
another and no reaper ever has to decide whether a writer is dead.
