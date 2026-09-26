# 16 — Block-device backend

This file owns the `blockdev` backend: a store that writes packs, indexes,
and refs directly to one raw block device with no filesystem beneath it. It
exists so that a machine with bare devices and no bucket can run a complete,
self-contained Terrane store, and so that on-premises warehouses need no
object-store software. The backend is the last storage component to be
implemented; every layer above the store interface is unchanged by its
presence.

## Model

The store interface of [`11-store-trait.md`](11-store-trait.md) needs only
two things from a backend: idempotent storage of immutable objects, and
conditional writes of small mutable refs. A raw device provides both with a
log-structured layout:

```text
+--------------+--------------+---------------+---------------------------+
| superblock A | superblock B | index region  | slab log (append-only)... |
+--------------+--------------+---------------+---------------------------+
```

- **Packs** are appended to slabs in the log and never rewritten. Allocation
  is a bump pointer; space is reclaimed by compaction
  ([`17-garbage-collection.md`](17-garbage-collection.md)), exactly as for a
  bucket.
- **Refs and the index** live in the index region. A change is committed by
  writing the inactive superblock with the new index-region generation and
  flipping which superblock is current. The flip is the device's conditional
  write, with the same semantics as an object store's `If-Match`.
- **Multiple devices** are handled by [`15-redundancy.md`](15-redundancy.md):
  a `blockdev` store is one child, and a mirror or parity set is a
  `replicated` or `striped` combinator over several.

The design follows the shape of ZFS uberblocks for the superblock ring and
of log-structured stores for the pack log. It is deliberately simple: no
block allocator with extents, no btree of blocks, no in-place update of
anything but the two superblocks.

## Device layout

- **[BLK-1]** A `blockdev` store MUST reserve two superblock slots of one
  device block each at the start of the device, followed by an index region
  of a size fixed at format time, followed by the slab log occupying the
  remainder. The sizes and the device block size MUST be recorded in both
  superblocks. *Gate:* `gate:blockdev-format-roundtrip`.
- **[BLK-2]** A superblock MUST contain: a magic value, the format version,
  the store identity, a monotonically increasing generation number, the
  offset and length of the current index-region generation, the log head
  offset, the free-list head, the flags word, a timestamp, and a checksum
  over the whole superblock. Its encoding is the fixed binary layout given
  in `reference/terrane-v1.cddl` §blockdev.
- **[BLK-3]** On open, the backend MUST read both superblocks, discard any
  whose checksum fails, and adopt the surviving one with the higher
  generation. If neither verifies the device MUST be treated as unformatted
  and the open MUST fail closed.
- **[BLK-4]** Slabs MUST be fixed-size regions of the log, each holding one
  or more whole packs and a slab header naming the packs it contains. A pack
  MUST NOT span slabs. A pack larger than a slab is written to a run of
  consecutive slabs recorded in the first slab's header.
- **[BLK-5]** The index region MUST hold at least two generations of the
  index so that the generation named by the previous superblock remains
  intact until the flip that supersedes it has been made durable.

## Writes and durability

- **[BLK-6]** A pack write MUST append the pack bytes and its trailer to the
  log, issue a device flush, then append the per-pack index to the index
  region, and only then consider the pack stored. A crash between these
  steps leaves either no record of the pack or a complete one.
- **[BLK-7]** A ref write MUST write the new index-region generation
  containing the ref value, flush, write the inactive superblock naming that
  generation with `generation + 1`, flush, and return. The write is a
  conditional write: the backend MUST compare the ref's current value and
  epoch under a store-wide ref lock before writing, and MUST reject the
  write on mismatch with the same error the bucket backend returns.
  *Gate:* `gate:blockdev-ref-cas`.
- **[BLK-8]** Superblock writes MUST alternate between the two slots so that
  the last durable superblock is never overwritten by a write that could
  fail mid-block.
- **[BLK-9]** Allocation MUST be a bump pointer at the log head. When the
  head reaches the end of the device, the backend MUST allocate from the
  free list of slabs returned by compaction, and MUST refuse writes with a
  space error when neither source can satisfy them.
- **[BLK-10]** Compaction MUST rewrite live packs from under-utilized slabs
  into new slabs at the head, update the index, flip the superblock, and only
  then add the vacated slabs to the free list. Slabs on the free list MUST
  retain their old headers until reused so that a crash during compaction
  leaves the prior generation recoverable.

## Reads

- **[BLK-11]** A read MUST locate the pack through the index region, read the
  requested range from the log, and verify it per
  [`15-redundancy.md`](15-redundancy.md) [RED-17] before returning it.
- **[BLK-12]** The backend MUST support ranged reads of chunk extents inside
  a pack without reading the whole pack, so that the block-device backend
  serves the same read patterns as a bucket.

## Recovery without a block map

Because packs are self-describing ([`12-pack-format.md`](12-pack-format.md))
and slabs carry headers, a device can be rebuilt from the log alone.

- **[BLK-13]** A recovery scan MUST be able to rebuild the index region by
  walking slab headers and pack trailers from the start of the log to the
  head, without any external record. A scan that finds a slab whose header
  and trailer disagree MUST quarantine that slab.
- **[BLK-14]** Scrub and resilver of a `blockdev` child under
  [`15-redundancy.md`](15-redundancy.md) MUST need nothing beyond the
  replicated index and the packs on surviving children; a lost device is
  replaced by formatting a new one and running resilver.

## Encryption

- **[BLK-15]** A `blockdev` store MAY encrypt slab contents at rest with a
  per-store key held by the operating process. When enabled, the superblocks
  and the slab headers MUST remain in the clear so that recovery and
  identification work without the key, and the pack hash MUST be computed
  over the plaintext so that identities do not change. The key management
  interface is out of scope for this version; the slot for it is the
  `encryption` property of [`08-properties.md`](08-properties.md).

## What is lost and how it is recovered

A raw device has no inodes. Two capabilities the filesystem-backed host tier
of [`14-host-tier.md`](14-host-tier.md) gets for free do not exist here:
sealed backing files that a kernel can verify and pass through, and a page
cache keyed by file that many consumers share.

- **[BLK-16]** A `blockdev` store MUST NOT be used as the backing for
  passthrough in [`27-surface-fuse.md`](27-surface-fuse.md) or as a data-only
  lower layer in
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md).
  Content from a `blockdev` store reaches those surfaces by being assembled
  into a filesystem-backed host tier first.
- **[BLK-17]** Content from a `blockdev` store MAY be served directly through
  the block surface of
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md), which
  maps block ranges to pack extents and benefits from the block-layer page
  cache.
- **[BLK-18]** The RECOMMENDED deployment on a host with raw devices is
  `tiered[disk(small, filesystem-backed), blockdev(large), ...]`: the
  filesystem tier holds the hot set as sealed objects for passthrough and
  shared page cache, the block-device tier holds capacity. This is the
  inverse of a special allocation class: capacity on raw devices, hot files
  on a filesystem.

## Sequencing

- **[BLK-19]** The `blockdev` backend is OPTIONAL for every conformance
  level except **Redundant**. An implementation MUST NOT let the presence or
  absence of this backend change any format, identity, or protocol defined
  elsewhere.

## Interactions

- [`11-store-trait.md`](11-store-trait.md) is the interface this backend
  implements; it appears in store expressions as `blockdev(<device>)`.
- [`12-pack-format.md`](12-pack-format.md) defines the packs and indexes
  written to the log and index region.
- [`14-host-tier.md`](14-host-tier.md) is the filesystem-backed tier this
  backend is paired with on a host.
- [`15-redundancy.md`](15-redundancy.md) provides mirrors, parity, scrub,
  and resilver across several devices.
- [`17-garbage-collection.md`](17-garbage-collection.md) drives compaction
  and slab reclamation.
- [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) is the
  surface that can serve this backend's content without assembly.
