# Reference — Comparisons (informative)

This document places Terrane beside three systems a reader is likely to
know: ZFS, as the storage system whose feature set Terrane most resembles;
git, as the version-control model Terrane adopts in part; and Span, the
predecessor build-cache system whose node-local cache and archive service
Terrane re-designs. It is informative. Where a row says "yes", the
requirement that makes it so is in the file named.

## Terrane and ZFS

Terrane is to ZFS what git is to a working directory: it owns history,
identity, distribution, and composition, and borrows a local filesystem for
the live working set. The table maps ZFS features to their Terrane form.

| ZFS | Terrane | Status | File |
| --- | --- | --- | --- |
| Copy-on-write, transaction groups | immutable objects; a commit is one ref compare-and-swap | yes, atomic per view | 09 |
| Snapshots | tags: immutable refs to commits | yes, free | 09 |
| Clones | branches: a fork is one ref write | yes | 07, 09 |
| Promote | fold: merge child into parent, retire child | yes; three-way merge also handles concurrent parent changes | 07 |
| Rollback | compare-and-swap the ref to an earlier commit; reflog keeps the rest | yes | 09 |
| Bookmarks | commits are retained until collected | yes | 09, 17 |
| Holds | pins on refs, objects, or chunks with grace | yes | 14, 17 |
| Send and receive, incremental | push and pull of a diff packed with its commit; content-addressed, so a receive deduplicates against the target | yes | 18, 21 |
| Datasets and property inheritance | `tree` entries with inherited properties | yes | 06, 08 |
| Delegation (`zfs allow`) | per-root write authority in capability tokens | yes | 22 |
| Checksums, scrub | BLAKE3 on every chunk, verify before admit, periodic scrub of tiers and packs | yes | 05, 14, 15 |
| Self-healing | a bad copy in one tier is quarantined and refetched from the next | yes, across tiers rather than mirrors | 14, 15 |
| Compression | zstd per chunk, level and dictionary per subtree property | yes | 05, 21 |
| Dedup | content-defined chunks plus file-level content hash, scoped by domain; the table is the index, not memory | yes, cheaper than ZFS dedup | 05, 24 |
| ARC, L2ARC | kernel page cache, disk tier, nested tiers | yes | 14, 19 |
| Quotas, reservations | per-root properties; host tiers enforce exactly; bucket tiers are eventually consistent soft limits | partial | 08, 14 |
| Encryption at rest | per-subtree property, chunk-level | design slot, later version | 25 |
| Pools, vdevs, mirror, RAID-Z, resilver | `replicated` and `striped` combinators over any children; resilver by pack | yes, at pack granularity | 15, 16 |
| ZIL, synchronous writes | writes land in a private upper; `fsync` commits only in `sync` mode | different by design | 20 |
| POSIX shared mutable semantics | not provided; the upper is a local filesystem | delegated | 20 |
| zvols | block surface, read-only in 1.0 | partial | 28 |
| ACLs, extended attributes | mode bits, ownership, xattrs as entry attributes; enforcement is the realizer's | yes for metadata | 06 |
| `zfs rewrite` (apply new properties to old data) | backfill tree jobs with completeness tracking | yes | 32 |

Three differences are intentional. First, there are no live shared writes:
ZFS is a mutable POSIX filesystem, while Terrane's shared tree changes only
by commit, and concurrent writers resolve by merge rather than by locks.
That is what makes it distributable with a bucket as the only authority.
Second, redundancy below the pack is someone else's: the bucket supplies
durability and the host filesystem supplies local redundancy, while Terrane
supplies verification, refetch, and pack-level replication and parity.
Third, quotas are exact only where one process owns the bytes.

Things ZFS does not have that Terrane does: branches with three-way merge,
content-addressed identity shared across every machine, lazy fetch of a tree
that has never been seen locally, and a namespace that is itself a value
that can be diffed.

## Terrane and git

Terrane adopts git's semantics and ref layout and rejects git's object
encoding. The line is exactly where performance lives.

### Adopted

| git | Terrane | Why |
| --- | --- | --- |
| commits with parents | commit objects; the reflog entry is a commit | three-way merge needs a merge base anyway; the graph gives ancestry checks and bisection over history |
| `refs/heads/`, `refs/tags/`, reflogs | the same names and semantics; tags are put-if-absent | familiar, and the split between mutable branches and immutable tags is exactly snapshots versus views |
| remotes, fetch, push | tiers are remotes; push is "upload packs, then compare-and-swap the remote ref" | one vocabulary for tiering and replication |
| partial clone with promisor remotes | a host tier holds refs and trees and fetches blobs lazily | git's own lazy-fetch model is the cache model |
| fast-forward, merge, merge base | fold; three-cursor merge; nearest common ancestor | a fork that adds only new keys fast-forwards with no walk |
| `git gc` grace period | sweep only objects older than a grace window | makes concurrent writes safe without locks |
| `git notes` | sidecar refs for advisory data such as prefetch profiles | keeps advisory data out of identity |

### Rejected

| git mechanism | Why not |
| --- | --- |
| whole-file blobs with a length header hash | no chunk-level dedup, no ranged reads, a full-file pass per write |
| per-directory tree objects | a flat directory with millions of entries is one object rewritten on every touch; no history-independent chunking |
| packfile delta chains, zlib | random reads walk delta chains; incompatible with presigned ranged reads and per-chunk verification |
| loose objects | millions of tiny bucket writes and lists |
| `HEAD`, index, and working-tree state in the repository | the upper is the working tree; committing state belongs to the host, not the bucket |

A git-readable projection is a surface: each git tree object is a range scan
over one directory of the prolly tree, memoized by the subtree it derives
from, and per-entry git blob digests are an optional derived attribute
computed once at commit. See
[`../30-surface-protocols.md`](../30-surface-protocols.md).

## Terrane and Span

Span is the predecessor build-cache and remote-execution system whose
archive service and node-local cache driver Terrane re-designs. The
comparison below is an inventory of what carried over, what changed, what
was dropped, and which of its known gaps Terrane closes by construction. It
is written from a survey of Span's design documents and code at the time of
writing.

### Dependencies

Span's archive service relied on a regional transactional key-value store
for object records, chunk locations, reference counts, aliases, pins, and
collection cursors; on a cache service that also carried correctness state
(replica liveness for a pending-pack reaper, several collection root sets);
on an analytical store on the collection path for recency and some roots;
and on a relational database, reached through a control-plane service, for
configuration. Terrane's authority is a bucket ([D-1] in
[`../39-decision-register.md`](../39-decision-register.md)). The open-pack
machinery (pending rows, quorum mirroring, leases, a reaper) existed only
because packs were shared across replicas; writer-owned packs remove it
([D-2]).

### Kept as-is

These mechanisms of Span's node-local cache are ported with their
parameters as starting points:

- FUSE passthrough on kernel 6.9 and later, one refcounted backing
  registration per inode, keep-cache fallback on older kernels.
- Direct presigned ranged reads: a few-millisecond micro-batching window,
  gap merging up to 256 KiB, spans up to 16 MiB, verified admission of
  unrequested bystander chunks inside a merged range, hedging after 60 ms,
  three priority lanes with singleflight.
- Verify before commit: a decompression-bomb cap, hash check, temporary
  file plus `fsync` plus rename, quarantine on mismatch, crash recovery of
  temporary files.
- Eviction: S3-FIFO with a probationary queue, pinned content never evicted,
  a five-minute release grace, reserve-then-evict to 85 percent.
- Reassembly modes `never`, `smart`, and `always` with the uniqueness
  heuristic, and a per-file plaintext content hash.
- A structural index with packed arenas and binary-search lookup, memory
  mapped, content-addressed, size-capped on disk.
- Inode policy: canonical attributes for archive-derived trees, stable
  32-bit inode allocation, alias directories sharing descendant inodes.
- A private overlay upper per lease with project quota, and copy-on-write
  child overlays stacked on a parent's merged tree.
- A prefetch scheduler with tiers and predictors (ELF `NEEDED`, shebang,
  closure graph, learned profiles, sequential) under a byte-rate cap.
- Wipe-on-unpin strategies (zero, trim, ramfs).
- A circuit breaker, retry policy, an unhealthy signal, and quiesce plus
  remount for upgrades.
- A pack-residency filter published for locality-aware scheduling.

### Kept, but changed by the design

| Span | Terrane |
| --- | --- |
| manifests and indexes fetched per object with paging; server-side index builds | a view's tree bundle; the prolly tree is the index |
| closure layout rules evaluated at mount (breadth-first over references, pin authority, exclusions, duplicate-path conflicts) | tree transforms and merge policy |
| mount grants and pinned-object tokens; trust selectors on alias reads | view-scoped capability tokens over refs; trust selectors on entry provenance |
| eager assembly by materializing files | the EROFS surface for resident trees |
| evaluation views with append-only generations | a view whose ref advances by fast-forward commits |
| sandbox pins in an embedded key-value store | a small embedded store for host-local pins and reservations only; nothing global |
| the routing ruleset engine evaluated at byte arrival | the same closed vocabulary; substitution and binding become tree transforms at checkout, guards become filters, classification is an attribute computed once per object |
| object identity as the plaintext hash, re-read at every commit | identity as the manifest hash; plaintext hashes as attributes ([D-3]) |

### Dropped

- The container-orchestrator volume driver surface, registrar, resource
  advertiser, and quota sizing from pod specifications: adopting systems
  supply their own glue.
- The legacy path that extracted archives and hard-linked them per sandbox.
- Isolation modes as Span defined them; disclosure domains replace them.
- All dependence on the key-value, cache, analytical, and relational
  stores.

### Gaps closed by design

| Span gap | How Terrane closes it |
| --- | --- |
| no collection of per-file backing files | the sealed object directory is a `disk` tier under the same eviction as chunks |
| tree leases held only in memory, lost on restart | leases are host-local durable records |
| executing through overlay-over-FUSE returned I/O errors on some paths | the EROFS surface for resident trees; passthrough on the lazy path; tracked as `RISK-11` |
| a single embedded-store writer lock stalled a fleet-wide rollout | the embedded store is off every read path |
| chunks uploaded but never committed could live in packs forever | mark-and-sweep from refs finds them; no reference-count row is needed for an object to be collectable |
| a cache outage made every replica look dead to the pending-pack reaper | there is no pending-pack reaper |
| collection roots that lived only in a cache service | roots are refs in the bucket |
| the whole object re-read at commit even when every chunk was a dedup hit | manifest-hash identity |
| an in-memory visited set proportional to the cluster during orphan marking | marking skips already-marked subtrees by hash and is sharded by key range |
| no virtual-machine story | virtiofs with DAX and the block surface |

### New in Terrane

Views as branches with merge, fold, set operations, and snapshots as tags;
tiered stores with `shared-dir`, nested hosts, and virtual-machine surfaces;
bucket-native metadata with mark-and-sweep collection; cost-routed topology;
capability tokens and one enforcement point; surfaces as the single
exposure abstraction; tree jobs for backfill and maintenance; a `no_std`
identity core that runs at the edge.
