# 35 — Performance targets

This file owns the performance budget: the latencies, throughputs, and
resource bounds an implementation claiming the **Operations** conformance
level meets, the assumptions each budget rests on, and the gate that measures
it. Budgets are stated as targets on a reference configuration so that they
are checkable, not aspirational. A number that changes what an implementer
does belongs here; a number that does not belongs nowhere.

## Reference configuration

All budgets are measured on the reference configuration unless a budget says
otherwise:

| Component | Reference |
| --- | --- |
| Host | one NVMe device, 8 cores, kernel with FUSE passthrough support |
| Host tier | `routed[disk(NVMe), remote(gateway)]`, disk tier warm unless "cold" is stated |
| Gateway | `guard(bucket)` in the same region, presigned direct reads enabled |
| Bucket | an S3-compatible object store in the same region as the host |
| Chunking | the default profile of [`05-chunking.md`](05-chunking.md) (256 KiB min, 1 MiB target, 4 MiB max), zstd level 3 |
| Workload tree | a 400 MiB plaintext closure of about 400 chunks after dedup, about 140 MiB compressed, roughly 20,000 entries |
| Page cache | warm for "hot" budgets, dropped for "warm" and "cold" budgets |

Terms: **hot** means bytes are in the page cache; **warm** means bytes are in
the host disk tier but not in the page cache; **cold** means nothing is on
the host and every byte comes from the bucket.

## Read path

| Budget | Target | Assumption | Gate |
| --- | --- | --- | --- |
| hot read, per 4 KiB page | < 1 µs | passthrough or EROFS realizer; the kernel serves from page cache with no user-space round trip | `gate:perf-hot-read` |
| warm read, first page-in of a file | ≤ 2 ms per MiB of compressed chunk plus 0.2 ms | zstd decode at ≥ 500 MB/s single core; a 1 MiB chunk decodes in about 2 ms, a 256 KiB chunk in about 0.5 ms | `gate:perf-warm-read` |
| cold read, one coalesced span from the bucket | 30–80 ms p50, ≤ 300 ms p99 | in-region bucket; presigned ranged GET; span 1–16 MiB | `gate:perf-cold-span` |
| cold closure, first byte of the first file opened | ≤ 100 ms p50 | bundle already fetched at mount; first open needs one span | `gate:perf-cold-closure` |
| cold closure, fully resident | ≤ 1 s p50 | 140 MiB over ≥ 8 parallel spans from an in-region bucket; whole-pack reads where a pack is mostly needed | `gate:perf-cold-closure` |
| directory listing, any size, hot metadata | ≤ 50 µs per 1,000 entries | served from the mmapped index, no content fetch | `gate:perf-readdir` |

- **[PERF-1]** A hot read MUST NOT cross into user space: the read-path
  budget assumes passthrough ([`27-surface-fuse.md`](27-surface-fuse.md)) or
  the EROFS realizer ([`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md)).
  An implementation that falls back to a user-space read path MUST report it
  in exposure status and is exempt from `gate:perf-hot-read` for that
  exposure. *Gate:* `gate:perf-hot-read`.
- **[PERF-2]** A cold read of a file MUST issue at most one bucket request per
  coalesced span; span coalescing merges gaps of up to 256 KiB into spans of
  at most 16 MiB ([`21-bandwidth.md`](21-bandwidth.md)). *Gate:*
  `gate:perf-cold-span`.
- **[PERF-3]** Metadata operations (lookup, getattr, readdir, readlink) MUST
  complete without any network request once a view is mounted. *Gate:*
  `gate:perf-readdir`.

## Mount and exposure

| Budget | Target | Assumption | Gate |
| --- | --- | --- | --- |
| warm mount, tree bundle already cached | ≤ 10 ms | cost is mount syscalls: FUSE 1–5 ms, overlay 0.3–1 ms, plus index mmap | `gate:perf-warm-mount` |
| cold mount, bundle fetched | ≤ 200 ms + bundle transfer | bundle of a 20,000-entry tree is under 2 MiB compressed | `gate:perf-cold-mount` |
| fork of a view | ≤ 1 bucket round trip | one conditional write | `gate:perf-fork` |
| EROFS image generation, 20,000 entries | ≤ 100 ms | deterministic layout from the index, no content read | `gate:perf-erofs-gen` |

- **[PERF-4]** A mount MUST return as soon as the namespace is servable;
  content faults afterwards. Blocking prefetch is a ruleset action, never
  the default ([`31-routing-rulesets.md`](31-routing-rulesets.md)). *Gate:*
  `gate:perf-warm-mount`.

## Write path

| Budget | Target | Assumption | Gate |
| --- | --- | --- | --- |
| commit, cost | O(changed entries + changed tree nodes) | prolly-tree rewrite touches O(log n) nodes per changed key | `gate:perf-commit-delta` |
| commit, latency for a 10 MiB delta | ≤ 500 ms p50 in-region | chunk + hash at ≥ 1 GB/s, negotiation one batched `has`, one pack upload, one CAS | `gate:perf-commit-latency` |
| `fsync` in `sync` writer mode, single file ≤ 1 MiB | ≤ 50 ms p50 in-region | one chunk upload, one small meta pack, one CAS at home | `gate:perf-fsync-sync` |
| fold of a branch with 1,000 changed entries into a 1,000,000-entry target | ≤ 200 ms + upload | three-cursor merge visits only differing subtrees | `gate:perf-merge-delta` |
| negotiation for a commit | ≤ 1 round trip per 10,000 candidate chunks | local filter of remote index; batched `has` for residue | `gate:perf-negotiation` |

- **[PERF-5]** Commit cost MUST be proportional to the size of the delta and
  MUST NOT scale with the size of the tree beyond the O(log n) node rewrite.
  *Gate:* `gate:perf-commit-delta`.
- **[PERF-6]** Merge cost MUST be proportional to the number of tree nodes
  that differ among base, ours, and theirs; a merge MUST NOT visit a subtree
  whose three root hashes are equal or where only one side differs from the
  base. *Gate:* `gate:perf-merge-delta`. *See:*
  [`07-tree-algebra.md`](07-tree-algebra.md).

## Memory and resources

| Budget | Target | Assumption | Gate |
| --- | --- | --- | --- |
| resident memory per touched inode, FUSE worker | 200–400 B | untouched entries cost nothing; index is mmapped, not deserialized | `gate:perf-inode-memory` |
| FUSE worker RSS, 2.4 M-entry tree, 10% touched | ≤ 256 MiB heap, index mmap excluded | inode state only for touched entries | `gate:perf-worker-rss` |
| mmapped index size | ≤ 60 B per entry plus string arenas | packed fixed entries, binary search by path | `gate:perf-index-size` |
| gateway memory per connection | O(in-flight requests), not O(tree) | gateway holds no tree state for readers using presigned reads | `gate:perf-gateway-memory` |
| host tier bookkeeping write on the read path | none | pins and reservations are off the fault path | `gate:perf-no-bookkeeping-on-read` |

- **[PERF-7]** Untouched entries MUST NOT consume per-entry heap in a
  realizer; only the mmapped index and per-touched-inode state may scale with
  the tree. *Gate:* `gate:perf-inode-memory`.
- **[PERF-8]** No read-path operation MAY perform a synchronous write to a
  host-tier bookkeeping store. *Gate:* `gate:perf-no-bookkeeping-on-read`.
  *See:* [`14-host-tier.md`](14-host-tier.md).

## Throughput and scaling

| Budget | Target | Assumption | Gate |
| --- | --- | --- | --- |
| gateway metadata operations | ≥ 5,000 requests/s per core | stateless; no data bytes proxied | `gate:perf-gateway-rps` |
| bucket egress through a gateway | 0 bytes of chunk data | bulk bytes go direct via presigned reads or peers | `gate:perf-gateway-zero-copy` |
| sibling exposures of one view on one host | 1× page cache, N× only per-exposure inode state | shared backing inodes | `gate:perf-shared-page-cache` |
| nested tier with `shared-dir` | 0 bytes stored for content visible from the parent | rule of [`11-store-trait.md`](11-store-trait.md) | `gate:perf-nested-zero-dup` |
| GC mark, 100 M chunks, 10,000 refs | ≤ 1 h on the reference host | prolly-tree mark skips already-marked subtrees | `gate:perf-gc-mark` |

- **[PERF-9]** A gateway MUST NOT proxy chunk bytes when the client and the
  bucket both support presigned reads; the gateway's bandwidth is bounded by
  metadata traffic. *Gate:* `gate:perf-gateway-zero-copy`. *See:*
  [`18-protocol.md`](18-protocol.md).
- **[PERF-10]** Two exposures of the same view on one host MUST share one
  page-cache copy of every sealed object. *Gate:*
  `gate:perf-shared-page-cache`. *See:* [`14-host-tier.md`](14-host-tier.md).

## Measurement rules

- **[PERF-11]** Each `gate:perf-*` check MUST run on the reference
  configuration or a configuration whose deviations are recorded with the
  result, MUST report p50 and p99 over at least 100 samples after warm-up,
  and MUST fail when p50 exceeds the target. p99 targets are advisory unless
  a row states one. *Gate:* `gate:perf-methodology`.
- **[PERF-12]** Budgets are stated for the reference chunk profile. An
  implementation using a different profile MUST scale the warm-read budget
  by its chunk size and record the profile with the result.
- **[PERF-13]** Performance results MUST be published alongside a conformance
  claim ([`36-testing-and-conformance.md`](36-testing-and-conformance.md)).

## Informative: where the numbers come from

The hot-read and metadata budgets follow from serving through the kernel:
page-cache hits and index lookups do not involve a user-space process. The
warm-read budget is zstd decode speed. The cold budgets are in-region object
store latency times the number of spans, with parallelism bounded by the
fetcher's lanes. The commit and merge budgets follow from the prolly-tree
structure, where a change touches O(log n) nodes and a merge visits only
differing subtrees. The memory budgets follow from mapping the index rather
than deserializing it and keeping state only for touched inodes; the
2.4-million-entry figure is the size of a large system closure and is the
case that motivates the index design.

## Interactions

- [`05-chunking.md`](05-chunking.md) sets the chunk sizes the budgets assume.
- [`07-tree-algebra.md`](07-tree-algebra.md) makes the delta bounds possible.
- [`14-host-tier.md`](14-host-tier.md), [`27-surface-fuse.md`](27-surface-fuse.md),
  and [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) own
  the mechanisms behind the read and mount budgets.
- [`18-protocol.md`](18-protocol.md) and [`21-bandwidth.md`](21-bandwidth.md)
  own presigned reads, coalescing, and negotiation.
- [`34-observability.md`](34-observability.md) defines the metrics the gates
  read.
- [`36-testing-and-conformance.md`](36-testing-and-conformance.md) registers
  the gates.
