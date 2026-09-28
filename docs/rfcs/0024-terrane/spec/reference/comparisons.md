# Reference — Comparisons (informative)

This document places Terrane beside two systems a reader is likely to
know: ZFS, as the storage system whose feature set Terrane most resembles,
and git, as the version-control model Terrane adopts in part. It is
informative. Where a row says "yes", the
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
