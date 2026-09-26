# 17 — Garbage collection

This file owns how a Terrane store reclaims space: what counts as a root,
how reachability is marked across every tier and region, when an unmarked
object may be swept, how packs are compacted, and why the whole procedure is
safe against writers that are committing while it runs. Terrane keeps no
reference counts. Garbage collection is mark-and-sweep from refs with a
grace window, which is the design every database-free content-addressed
store converges on, and the only one whose safety argument does not depend
on a transactional counter.

## Model

Everything in a store except refs is immutable and content-addressed. A
writer produces packs, then indexes, then a commit object, and finally moves
a ref to that commit ([`09-refs-and-commits.md`](09-refs-and-commits.md)).
Reachability therefore flows from refs: a ref names a commit, a commit names
a tree root and parents, a tree names objects and further roots, an object
names chunks, and chunks live in packs. Anything not reachable from a ref and
older than the grace window is garbage.

The collector runs in three phases, each resumable:

1. **Snapshot** the root set: every ref, its retained reflog, every tag, and
   every job ref, from every region's authority.
2. **Mark** everything reachable, walking commits, trees, manifests, index
   trees, and the attribute side table, skipping subtrees already marked.
3. **Sweep** objects that are unmarked and older than the grace window by
   tombstoning their packs, and delete tombstoned packs after a second
   window.

Compaction rewrites packs whose live fraction fell below a threshold and
merges indexes. It is the fourth phase and the only one that writes new
data.

## Roots

- **[GC-1]** The root set of a collection MUST include: the current value
  of every ref; every reflog entry of every ref that is within the ref's
  retention; every tag; and every job ref under `refs/jobs/` whose lease has
  not expired ([`32-tree-jobs.md`](32-tree-jobs.md)). *Gate:*
  `gate:gc-roots-complete`.
- **[GC-2]** The root set MUST be read from the authority of every region
  and every child of every redundant store, and the collection MUST use the
  union. A ref that is readable in one region and not another is a root.
- **[GC-3]** Retention of reflog entries is set by the `retain` property of
  [`08-properties.md`](08-properties.md) on the ref's root: `gc` keeps
  entries for the property's duration, `lease` keeps them while a lease is
  held, `ttl` keeps them for a fixed time from creation. A root with no
  retention property inherits it. The default for `refs/heads/` is a
  duration of at least the grace window plus the maximum commit duration.
- **[GC-4]** The root set MUST be snapshotted at the start of a collection
  and recorded in the collection's own object under `gc/` so that a resumed
  collection marks from the same roots. A ref moved after the snapshot is
  covered by the grace window (§Safety).

## Mark

- **[GC-5]** Marking MUST visit, from each root: the commit, every parent
  commit reachable within retention, the tree root, every tree node, every
  `tree` entry's root, every manifest, every chunk each manifest names, every
  inline chunk an entry names, every index tree of
  [`10-derived-data.md`](10-derived-data.md) named by the root's properties,
  every attribute side-table object for every object hash encountered, and
  every bundle or profile object the commit references. *Gate:*
  `gate:gc-mark-reachability`.
- **[GC-6]** Marking MUST skip any tree node, manifest, or root already
  marked in this collection. Because trees are history-independent
  ([`06-tree-format.md`](06-tree-format.md)), identical subtrees in
  different commits share nodes, and the cost of marking is proportional to
  distinct content, not to the number of refs.
- **[GC-7]** The mark set MUST be recorded as an index-shaped structure
  (sorted content hashes with a filter) in the collection's `gc/` prefix,
  written in checkpoints, so that a crashed collector resumes marking from
  its last checkpoint and never repeats a completed shard.
- **[GC-8]** Marking MUST run over the union of all regions before any
  region sweeps, because a pack may exist only in the region that wrote it
  while a commit in another region already references it (§Cross-region
  packs).
- **[GC-9]** Marking MUST NOT read bytes from packs. It needs only meta
  objects and indexes. A collector that needs a pack's chunk list reads the
  per-pack index, never the pack.

## Grace window

- **[GC-10]** Every store MUST define a grace window `G`. An object whose
  last-modified time is younger than `G` MUST NOT be swept regardless of
  reachability. *Gate:* `gate:gc-grace-window`.
- **[GC-11]** `G` MUST be strictly longer than the maximum commit duration
  `C` that clients are permitted, and clients MUST enforce `C`: a commit
  whose first pack was written more than `C` ago MUST be aborted by the
  client and restarted, never completed. The RECOMMENDED values are
  `C = 6 h` and `G = 24 h` for bucket-backed stores, shorter for host tiers.
- **[GC-12]** An implementation MUST obtain last-modified time from the
  store that holds the object (the bucket's timestamp, the slab header's
  timestamp for `blockdev`, the filesystem's for `disk`), never from a
  client-supplied value.

## Sweep

- **[GC-13]** Sweep MUST consider as candidates only objects found by
  listing the store (`LIST` on a bucket, slab-header walk on `blockdev`,
  directory walk on `disk`). Listing is used to find candidates and for
  nothing else; correctness comes from the mark set, not from the listing
  being complete or ordered.
- **[GC-14]** A candidate MUST be swept only if it is absent from the mark
  set and older than `G`. A pack MUST be swept only if every chunk and meta
  object in it is unmarked; a pack with any marked member is a compaction
  candidate, not a sweep candidate.
- **[GC-15]** Sweep MUST be two-phase. First the pack is tombstoned: its
  index entries are removed from the merged index, a tombstone object is
  written under `trash/<epoch>/<pack-id>` naming the pack, and readers stop
  resolving to it. Second, after a deletion window `D` has elapsed since the
  tombstone, the pack bytes are deleted. During `D` a tombstoned pack MUST
  be restorable by a single operation that re-adds its index entries.
  *Gate:* `gate:gc-two-phase-delete`.
- **[GC-16]** `D` MUST be at least `G`. The RECOMMENDED value is `D = G`.
- **[GC-17]** A read that resolves through a stale index to a tombstoned
  pack MUST retry through the current index before reporting an error, and
  MUST report a tombstone hit through
  [`34-observability.md`](34-observability.md) because it indicates either a
  stale reader or a marking defect.

## Compaction

- **[GC-18]** A pack whose live fraction (marked bytes over total bytes) is
  below the `compaction_threshold` property (default 0.5) MUST be a
  compaction candidate. Compaction rewrites the live members of one or more
  candidates into new packs in tree order, writes their per-pack indexes,
  swaps the merged index entries to the new locations, and tombstones the
  old packs per [GC-15].
- **[GC-19]** Compaction MUST write the new pack and index before removing
  any old index entry, so that every chunk is resolvable at every instant.
- **[GC-20]** Merged index shards MUST be rebuilt by compaction at least
  once per index epoch, dropping entries for tombstoned packs and folding in
  per-pack indexes written since the previous epoch. Readers MAY continue to
  use the previous epoch until the new one is published.
- **[GC-21]** Compaction MUST honour the same bytes-per-second limit as a
  scrub ([`15-redundancy.md`](15-redundancy.md)) and MUST be preemptible by
  foreground writes for space.

## Runner

- **[GC-22]** At most one collector MUST run against a store at a time. The
  collector MUST hold a lease object at `gc/lease` obtained by conditional
  create-if-absent, carrying an epoch and an expiry, and MUST renew it by
  conditional write before expiry. A collector whose renewal fails MUST stop
  immediately. *Gate:* `gate:gc-singleton-lease`.
- **[GC-23]** A new collector MUST use an epoch greater than the one in the
  expired lease it replaces, and every checkpoint and tombstone it writes
  MUST carry its epoch, so that a stalled collector resuming after losing
  its lease cannot tombstone with a stale mark set.
- **[GC-24]** A collector MUST be resumable: each phase records progress as
  checkpoints keyed by epoch, and a fresh collector with a higher epoch MUST
  discard checkpoints from a lower epoch except the root-set snapshot it
  chooses to reuse, which it MAY do only if that snapshot is younger than
  `G`.
- **[GC-25]** Every host tier MUST run its own collector over its local
  store with the same rules, using its pins and leases as additional roots
  ([`14-host-tier.md`](14-host-tier.md)); eviction under pressure is a
  separate mechanism and MUST NOT be confused with collection.

## Cross-region packs

A commit acknowledged in one region may name packs that so far exist only
in the region that produced them, while replication catches up
([`19-tiering-and-topology.md`](19-tiering-and-topology.md)). This is the
promisor pattern: the commit records where its packs were written.

- **[GC-26]** The collector MUST treat every replica store, in every region,
  as a sweep target, and MUST mark from the union of roots before sweeping
  any of them. A pack that is marked in any region MUST NOT be swept in any
  region.
- **[GC-27]** A commit's recorded pack locations MUST be consulted during
  mark so that a pack referenced by a commit but not yet present in the
  local index is neither treated as missing nor swept when it arrives.

## Retention properties

| Property value | Meaning |
| --- | --- |
| `retain=gc` | reflog entries kept for the store's default duration; unreachable content collected after `G` |
| `retain=lease` | the root is a root only while a lease is held; on expiry its ref is removed and its content becomes unreachable |
| `retain=ttl:<duration>` | each commit is a root for `<duration>` from its timestamp regardless of the ref moving on |
| `retain=forever` | every commit ever pointed at by the ref remains a root |

- **[GC-28]** A root's retention property MUST be evaluated against the
  commit timestamp for `ttl`, the lease expiry for `lease`, and the reflog
  entry time for `gc`, and the collector MUST be able to explain, for any
  swept object, which rule made it unreachable
  ([`34-observability.md`](34-observability.md)).

## Safety (informative)

The argument that no reachable object is ever deleted rests on four facts.

1. A writer orders its work packs, indexes, commit, ref. Until the ref moves
   nothing references the new objects, and after it moves everything is
   reachable. The only window in which reachable-to-be objects are
   unreferenced is the commit's own duration, bounded by `C`.
2. Nothing younger than `G > C` is ever swept, so an object written during a
   commit survives at least until the commit has either completed and made
   it reachable or been aborted.
3. The root set is a snapshot, but a ref that moves after the snapshot
   points at objects that are either older than the snapshot (and were
   reachable from some root at snapshot time, because the writer's fork or
   parent commit was a root) or younger than `G`.
4. Deletion is two-phase, so a defect in any of the above is recoverable
   for `D` without data loss.

Reference counts would let a store reclaim faster than `G`, at the price of
a transactional counter store that would become the one stateful dependency
the design forbids, and of drift that needs repair sweeps of its own. The
grace window costs storage for one window's worth of dead data and nothing
else.

## Interactions

- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the write
  ordering and the reflog this file depends on.
- [`12-pack-format.md`](12-pack-format.md) and
  [`13-bucket-layout.md`](13-bucket-layout.md) define packs, indexes, the
  `gc/` and `trash/` prefixes, and the conditional writes the lease uses.
- [`14-host-tier.md`](14-host-tier.md) contributes pins and leases as roots
  for host-local collection.
- [`15-redundancy.md`](15-redundancy.md) defines the children a collector
  sweeps and shares the rate limit and quarantine mechanisms.
- [`16-blockdev-backend.md`](16-blockdev-backend.md) reclaims slabs through
  compaction defined here.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) defines
  cross-region replication that [GC-26] and [GC-27] account for.
- [`20-consistency.md`](20-consistency.md) requires clients to enforce the
  maximum commit duration `C`.
- [`32-tree-jobs.md`](32-tree-jobs.md) provides job refs as roots and the
  job primitive compaction runs on.
- [`34-observability.md`](34-observability.md) receives progress,
  tombstone-hit, and explanation reports.
