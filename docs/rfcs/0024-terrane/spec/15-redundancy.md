# 15 — Redundancy

This file owns how a Terrane store survives the loss of one or more of the
stores beneath it: the `replicated` and `striped` combinators, placement of
packs across children, verification and repair of damaged copies, scrub and
resilver, and the policies that keep refs consistent when more than one child
could answer for them. Redundancy is a combinator over stores, never a
feature of a single backend, so the same rules apply whether the children are
block devices, buckets, filesystems, or remote Terrane instances.

## Model

The unit of redundancy is the [pack](02-glossary.md#storage-vocabulary).
A pack is immutable, self-describing, and content-verified
([`12-pack-format.md`](12-pack-format.md)), which is what makes redundancy
generic: a copy of a pack can be checked without any external record, and a
lost copy can be rebuilt from any surviving copy or from parity without a
map of what the lost child held. Two combinators build redundant stores:

```text
replicated(n, ack=k)[children...]   every pack to n children, ack after k
striped(k, parity=m)[children...]   pack cut into k contiguous stripes plus
                                    m parity shards, one shard per child
```

Both implement the store interface of [`11-store-trait.md`](11-store-trait.md)
and can be nested inside `routed`, wrapped by `guard`, or used as a child of
another redundant combinator. A redundant store is selected for a subtree by
the `redundancy` property ([`08-properties.md`](08-properties.md)) on its
root, so one tree can hold public content replicated three ways and private
content mirrored across two local devices.

Reads, writes, repair, and ref handling each have one rule:

- **Writes** place a pack deterministically and acknowledge when the policy's
  durability is met.
- **Reads** go to the child that holds the needed byte range; parity or a
  second replica is consulted only when that child fails or its bytes do not
  verify.
- **Repair** is verify, quarantine, reconstruct, rewrite, in that order, and
  is the same code path for a scrub, a read-time failure, and a resilver.
- **Refs** have exactly one of two policies: a single authority child, or a
  majority quorum with epochs.

## Combinators

### `replicated`

- **[RED-1]** `replicated(n, ack=k)` MUST write every pack and every index
  object to `n` distinct children selected by placement (§Placement), and
  MUST NOT acknowledge a write until at least `k` children have durably
  stored it, where `1 <= k <= n`. *Gate:* `gate:redundancy-replicated-ack`.
- **[RED-2]** After acknowledgement, a `replicated` store MUST continue to
  write the remaining `n - k` copies in the background and MUST record the
  pack as under-replicated until they succeed. Under-replication is reported
  through [`34-observability.md`](34-observability.md) and repaired by
  resilver (§Scrub and resilver).
- **[RED-3]** A read from a `replicated` store MUST be served from one child
  holding the pack, chosen by the cost model of
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md). On a verify
  failure or a child error the read MUST fall through to another replica
  before returning an error.

### `striped`

- **[RED-4]** `striped(k, parity=m)` MUST cut each pack into `k` contiguous
  byte ranges (stripes) of equal length except the last, compute `m` parity
  shards with a systematic maximum-distance-separable code over the stripes,
  and place each of the `k + m` shards on a distinct child. Reed-Solomon over
  GF(2^8) is the RECOMMENDED code; the code identifier is recorded in the
  shard header so a reader can verify it. *Gate:*
  `gate:redundancy-striped-reconstruct`.
- **[RED-5]** Stripes MUST be contiguous ranges of the pack, never
  interleaved at block granularity. A ranged read that falls within one
  stripe MUST be served by exactly one child. *See:* §Why contiguous
  stripes.
- **[RED-6]** A `striped` store MUST NOT acknowledge a write until all
  `k + m` shards are durably stored. Partial acknowledgement is not offered
  because any lost shard immediately reduces the margin below the declared
  policy.
- **[RED-7]** When a stripe is unavailable or fails verification, the store
  MUST reconstruct it from any `k` of the surviving stripes and parity
  shards, serve the read, and schedule a rewrite of the lost shard.
- **[RED-8]** Each shard MUST carry a fixed-size header recording the pack
  identity, the shard ordinal, `k`, `m`, the code identifier, the stripe
  length, and the hash of the whole pack, so that a shard found on a child
  can be attributed and verified without any index.

### Shape of the child list

- **[RED-9]** A redundant combinator MUST refuse to start with fewer children
  than its policy needs (`n` for `replicated`, `k + m` for `striped`) unless
  configured `degraded=allow`, in which case it MUST report the degraded
  state and MUST NOT accept writes that would be acknowledged below policy.
- **[RED-10]** Children of a redundant combinator MAY be any store:
  `bucket`, `disk`, `blockdev`, `remote`, or another combinator. A `remote`
  child pointing at another Terrane instance makes the combinator a
  federation (§Federation).

## Placement

- **[RED-11]** Placement of a pack onto children MUST be deterministic given
  the pack identity and the ordered child list: rendezvous (highest random
  weight) hashing of the pack identity against each child's identity,
  weighted by the child's advertised free capacity and by locality distance
  from the writer as defined in
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md). *Gate:*
  `gate:redundancy-placement-deterministic`.
- **[RED-12]** For `replicated`, the first `n` children in rendezvous order
  hold the pack. For `striped`, the first `k + m` children hold shards in
  rendezvous order, with the `k` data stripes before the `m` parity shards.
- **[RED-13]** A reader MUST NOT depend on placement to find a pack. It MUST
  consult the index (§Index replication) and MAY use placement only as a
  hint to try children in a likely order. Placement changes when children are
  added or removed; the index does not.
- **[RED-14]** Adding a child MUST NOT move existing packs. Rebalancing is a
  tree job ([`32-tree-jobs.md`](32-tree-jobs.md)) that rewrites packs whose
  rendezvous order changed and only when an operator requests it.

## Index replication

- **[RED-15]** Per-pack indexes, merged index shards, and filters
  ([`12-pack-format.md`](12-pack-format.md)) MUST be written to every child
  of a redundant combinator regardless of the data policy. Index objects are
  small relative to packs and a child that holds an index can answer `has`
  and locate shards without a round trip.
- **[RED-16]** A child that is missing an index object present on a majority
  of its siblings MUST be repaired by copying, never by rebuilding from that
  child's packs alone, so that indexes stay identical across children.

## Verification and repair

- **[RED-17]** Every read from a child MUST verify the bytes before they are
  returned: the chunk hash for a chunk read, the pack trailer checksum and
  the pack hash for a whole-pack read, and the shard header hash for a shard
  read. A copy that fails verification MUST be quarantined on that child
  (moved out of service, never overwritten in place) and MUST NOT be served
  again until it is rewritten. *Gate:* `gate:redundancy-verify-on-read`.
- **[RED-18]** Repair MUST proceed in the order verify, quarantine,
  reconstruct, rewrite. Reconstruction uses another replica or parity; the
  rewrite MUST be written as a new object and verified before the quarantined
  copy is deleted.
- **[RED-19]** Repair MUST be idempotent and safe to run concurrently with
  reads and writes. A repair that finds the copy already rewritten MUST exit
  without change.

## Scrub and resilver

Scrub and resilver are tree jobs ([`32-tree-jobs.md`](32-tree-jobs.md)) over
the index rather than over trees. They share the job primitive's sharding,
cursors, and checkpoints, and differ only in their filter.

- **[RED-20]** A **scrub** MUST iterate every index entry, read each pack or
  shard from each child that should hold it, verify it per [RED-17], and
  repair per [RED-18]. A scrub MUST be resumable from its last cursor and
  MUST be rate-limited by a bytes-per-second property so it does not starve
  foreground reads.
- **[RED-21]** A **resilver** MUST discover loss by diffing the index against
  what each surviving child reports it holds, then reconstruct every missing
  pack or shard from survivors or parity and write it to the child selected
  by placement. A resilver MUST NOT require any record of what the lost
  child held beyond the replicated index.
- **[RED-22]** A resilver MUST prioritise packs whose remaining margin is
  smallest (fewest surviving replicas, or fewest surviving shards above
  `k`), then packs referenced by the most recently committed trees.
- **[RED-23]** Scrub and resilver progress, the set of quarantined copies,
  and the current margin of every pack MUST be observable per
  [`34-observability.md`](34-observability.md).

## Refs under redundancy

Packs are idempotent, so any child may accept a copy. Refs are not, so a
redundant combinator needs one rule for which child answers for a ref. Two
policies exist and a combinator has exactly one.

- **[RED-24]** With `refs=authority(<child>)`, the named child MUST own every
  ref operation of [`09-refs-and-commits.md`](09-refs-and-commits.md). Other
  children MUST mirror ref values asynchronously and MUST label any value
  they serve as a mirror with its lag. This policy is RECOMMENDED when one
  child is a bucket that provides conditional writes.
- **[RED-25]** With `refs=quorum`, a conditional write MUST be attempted on
  every child and MUST succeed only when a strict majority of children
  accept it with the same expected value and the same epoch. A read MUST
  consult a strict majority and return the value with the highest sequence
  among them. A writer whose epoch is lower than the epoch stored on any
  child in the majority MUST be rejected. *Gate:*
  `gate:redundancy-quorum-refs`.
- **[RED-26]** Under `quorum`, a child that was unreachable during a
  successful write MUST be brought up to date by the next read or write that
  observes its stale value, by rewriting the majority value with its
  sequence and epoch.
- **[RED-27]** A quorum with an even number of children MUST be configured
  with a tie-break child whose vote counts twice, or the combinator MUST
  refuse to start.

Quorum refs cost one round trip to a majority on every commit. That is
acceptable at the commit rates of build and cache workloads and is not the
right choice for thousands of commits per second, where a single authority
child is preferred. The choice is recorded per instance in
[`39-decision-register.md`](39-decision-register.md).

## Properties

- **[RED-28]** The `redundancy` property on a root MUST select the store
  expression that holds packs written under that root. Caches MUST be
  configured with `redundancy=none`. A root that does not set the property
  inherits it per [`08-properties.md`](08-properties.md).
- **[RED-29]** A commit MUST NOT be acknowledged until every pack it wrote
  has met the acknowledgement rule of the redundant store its root selects.
  This is the same rule as the `durability` property of
  [`20-consistency.md`](20-consistency.md), applied at the store layer.

## Federation

A redundant combinator whose children are `remote` stores pointing at other
Terrane instances is a federation: a regional warehouse spread over regional
instances, each an ordinary store. Nothing above the store layer learns that
a store is composite.

- **[RED-30]** A `remote` child of a redundant combinator MUST be treated
  exactly as any other child for placement, index replication, verification,
  scrub, and resilver. Its locality label and cost vector come from the
  remote instance's advertisement.
- **[RED-31]** A federation MUST use `refs=authority` or `refs=quorum` like
  any other redundant store, and MUST NOT let a remote child's own refs be
  confused with the federation's refs. A remote child stores federation refs
  under the federation's namespace prefix
  ([`13-bucket-layout.md`](13-bucket-layout.md)).

## Costs

The costs below are normative in the sense that an implementation MUST
report them, not that it must meet a number.

| Policy | Write amplification | Read cost on hit | Cost on failure |
| --- | --- | --- | --- |
| `replicated(n, ack=k)` | `n` | one child | fall through to another replica |
| `striped(k, parity=m)` | `(k + m) / k` | one child per stripe range | read `k` shards and reconstruct |
| `refs=authority` | 1 | one child | unavailable until the authority returns |
| `refs=quorum` | majority round trip | majority round trip | tolerates a minority of failures |

- **[RED-32]** Parity SHOULD be used for cold or bucket-backed tiers and
  replication for hot tiers, because reconstruction on failure costs `k`
  reads and a decode, which is acceptable for cold data and not for data on
  a mount's fault path.
- **[RED-33]** Cross-provider or cross-region striping MUST use contiguous
  stripes so that a cold read is bounded by one child's latency rather than
  by the slowest of `k` children.

## Why contiguous stripes (informative)

Traditional RAID interleaves small blocks across devices so that every large
read draws bandwidth from every device. That layout is wrong for Terrane
because reads are ranged reads of chunks inside packs, served by presigned
URLs or by remote instances. An interleaved layout would turn one ranged
read into `k` ranged reads to `k` children and make its latency the maximum
of their latencies. Contiguous stripes keep a chunk inside one child except
at stripe boundaries, keep presigned ranged reads efficient, and use parity
only when something is lost. Aggregate bandwidth still scales with the number
of children because different packs and different stripes land on different
children.

## Interactions

- [`11-store-trait.md`](11-store-trait.md) defines the interface the
  combinators implement and the expression grammar that names them.
- [`12-pack-format.md`](12-pack-format.md) defines the pack, shard header
  fields, and indexes this file replicates and verifies.
- [`13-bucket-layout.md`](13-bucket-layout.md) defines the namespace prefix a
  child uses for a federation's objects.
- [`16-blockdev-backend.md`](16-blockdev-backend.md) is the child most often
  combined here for local mirrors and parity sets.
- [`17-garbage-collection.md`](17-garbage-collection.md) sweeps every child
  and relies on [RED-15] to find packs on all of them.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) supplies
  locality labels and cost vectors used by placement and reads.
- [`20-consistency.md`](20-consistency.md) maps `durability` onto the
  acknowledgement rules here.
- [`32-tree-jobs.md`](32-tree-jobs.md) provides the job primitive that scrub
  and resilver use.
- [`34-observability.md`](34-observability.md) receives margin, quarantine,
  and progress reports.
