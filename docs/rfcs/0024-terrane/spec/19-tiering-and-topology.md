# 19 — Tiering and topology

This file owns how stores are arranged across machines, zones, and regions,
and how a request finds the cheapest place to be answered. It specifies
locality labels, measured cost vectors, cost-routed candidate selection,
hop accounting, zone-local peers, residency advertisement, warming, the home
region of a ref, cross-region misses, replication policies, partition
behavior, and cross-region garbage-collection coordination.

## Overview

A `tiered` store is written as an ordered list, and for a single machine the
order is a fine routing rule: page cache, then disk, then the parent. Across
a fleet the order is not enough. Two hosts in the same zone are closer to
each other than either is to the regional bucket; a bucket in another
region is farther still and costs money per byte. The tier list therefore
becomes a graph whose edges carry measured costs, and each read picks the
cheapest candidate that has the bytes rather than the first in the list.

Nothing else changes. The store interface is the same, the protocol is the
same, and a tier does not know whether the store it is talking to is a
sibling host, a gateway, or a bucket in another continent. Topology is data
attached to stores, not a new kind of store.

Three ideas carry the design:

1. **Locality labels** say where a store is. **Cost vectors** say what it
   costs to reach it from here, and they are measured, not configured.
2. **Residency** says what a store holds, as a small filter, so a peer can
   be asked only when it probably has the answer.
3. **Home** says where a ref's authority lives, so that reads can be served
   from anywhere while writes have exactly one place to serialize.

## Locality

- **[TOPO-1]** Every store in a store expression MUST carry a locality label
  `{region, zone, host}`. A backend inherits the label of the process that
  runs it unless configured otherwise; a `remote` store learns its label
  from the peer's `Capabilities` response. *Gate:* `gate:topo-labels`.
- **[TOPO-2]** Locality labels MUST be opaque strings compared for equality
  only. An implementation MUST NOT infer distance from label text; distance
  comes from measured cost. *Gate:* `gate:topo-labels`.
- **[TOPO-3]** A `bucket` backend's label MUST be the region of the bucket,
  with `zone` and `host` empty, so that a bucket is never mistaken for a
  zone-local store. *Gate:* `gate:topo-labels`.

## Cost vectors

A cost vector describes one edge from the local tier to a candidate store.

| Field | Unit | Learned from |
| --- | --- | --- |
| `latency_p50` | milliseconds | request completion times, decayed |
| `latency_p99` | milliseconds | as above |
| `bandwidth` | bytes per second | large-range transfer rates, decayed |
| `price` | currency per byte | configured per edge class, not learned |
| `health` | 0.0 to 1.0 | error rate and breaker state |

- **[TOPO-4]** A tier MUST maintain a cost vector for every candidate store
  it can reach, MUST update it from every completed request using an
  exponentially decayed estimator, and MUST NOT require a configured value
  for any field except `price`. *Gate:* `gate:topo-costs`.
- **[TOPO-5]** A tier MUST apply hysteresis when reordering candidates: a
  candidate MUST NOT displace the current best unless its estimated cost is
  lower by a configured margin (default 20 percent) for a configured number
  of samples (default 8). *Gate:* `gate:topo-costs`.
- **[TOPO-6]** A tier SHOULD exchange cost vectors with peers through
  `TierService.Costs` so that a freshly started tier can seed its estimates
  from a neighbor's view rather than from cold defaults.
- **[TOPO-7]** A tier MUST open a circuit breaker on a candidate after a
  configured failure count (default 5 within 60 seconds) and MUST probe it
  at a bounded rate until it recovers. A candidate with an open breaker MUST
  NOT be selected except as the last remaining candidate. *Gate:*
  `gate:topo-breaker`.

## Candidate selection

- **[TOPO-8]** For a content read, a `tiered` store MUST select among
  candidates by expected cost, where expected cost combines the cost vector
  with the probability that the candidate holds the content as estimated
  from its residency filter. A candidate whose filter is negative MUST be
  skipped unless no positive candidate remains. *Gate:*
  `gate:topo-selection`.
- **[TOPO-9]** The local tiers `page-cache`, `disk`, and `shared-dir` MUST
  always be consulted before any remote candidate, in that order, regardless
  of measured cost. *Gate:* `gate:topo-selection`.
- **[TOPO-10]** A `tiered` store MUST record which candidate served each
  read and MUST expose the distribution per candidate through
  [`34-observability.md`](34-observability.md).
- **[TOPO-11]** For a content write, a `tiered` store MUST write to the
  authority tier named by the root's `store` property, MUST write through
  to any tier whose `write-through` policy names the root, and MUST NOT
  write to any other tier. Selection by cost applies to reads only.
  *Gate:* `gate:topo-selection`.

## Hop accounting

- **[TOPO-12]** Every request MUST carry a hop count, incremented by each
  forwarding tier, and every response MUST carry the path of localities that
  served it, per [`18-protocol.md`](18-protocol.md). *Gate:*
  `gate:topo-hops`.
- **[TOPO-13]** A tier MUST refuse to forward a request whose hop count has
  reached the configured maximum (default 8). *Gate:* `gate:topo-hops`.
- **[TOPO-14]** A tier MUST NOT include a candidate in its selection whose
  own tier list is known to include the local tier, as learned from
  `Capabilities`, so that two tiers configured as each other's parents
  cannot forward in a cycle. *Gate:* `gate:topo-hops`.

## Zone-local peers

Hosts in a zone hold a great deal of content between them. A peer is a
candidate store like any other, reached over the same protocol, with a
residency filter that makes it cheap to know when to ask.

- **[TOPO-15]** A host tier MAY be configured with a peer discovery source
  that yields the addresses of other host tiers in its zone. Peers MUST be
  added to the candidate set as `remote` stores with the peer's locality and
  MUST NOT be added as write targets. *Gate:* `gate:topo-peers`.
- **[TOPO-16]** A host tier MUST serve content reads from peers only for
  packs it holds in full, MUST verify the caller's grants exactly as a
  gateway would, and MUST NOT forward a peer's miss to its own parents.
  A peer answers from what it has or with `NOT_FOUND`. *Gate:*
  `gate:topo-peers`.
- **[TOPO-17]** A host tier MUST bound the bandwidth and concurrency it
  spends serving peers so that serving peers never starves its own
  consumers. The defaults are 25 percent of measured uplink and 16
  concurrent streams. *Gate:* `gate:topo-peers`.

## Residency

- **[TOPO-18]** Every tier that holds content MUST maintain a residency
  filter over the pack ids it holds, MUST version it by epoch, and MUST
  serve it through `TierService.Residency`. The filter MUST be rebuilt when
  packs are admitted or evicted and MUST be republished at a bounded
  interval (default 30 seconds). *Gate:* `gate:topo-residency`.
- **[TOPO-19]** A residency filter MUST have a false-positive rate of at
  most 1 percent at the tier's configured capacity and MUST never produce a
  false negative for a pack the tier holds in full. *Gate:*
  `gate:topo-residency`.
- **[TOPO-20]** A tier MUST treat a peer's residency filter as advisory for
  selection and MUST NOT treat it as evidence of durability, retention, or
  authorization.
- **[TOPO-21]** `TierService.Where` MUST compute its histogram from the
  residency filters the server holds for tiers whose locality is known and
  MUST report the epoch of the oldest filter it used. *Gate:*
  `gate:topo-residency`.

Residency filters also serve placement. A scheduler that decides where to
run a workload can ask `Where` for the workload's view and prefer the zone
whose hosts already hold most of its packs. This specification defines the
query; the scheduling policy belongs to the adopting system.

## Warming

- **[TOPO-22]** A tier MUST accept `TierService.Warm` for a view or a pack
  list, MUST fetch the named content at the requested priority through its
  normal candidate selection, and MUST admit the content unpinned so that
  it is subject to ordinary eviction. *Gate:* `gate:topo-warm`.
- **[TOPO-23]** Warming MUST run at a priority below any consumer-driven
  read and MUST be rate-limited by a per-tier byte budget so that a warm
  request cannot degrade a consumer. *Gate:* `gate:topo-warm`.
- **[TOPO-24]** A root MAY carry a `warm` property naming localities that
  SHOULD be warmed when a commit lands on a ref beneath that root. A tier
  that observes such a commit through a watch and whose locality is named
  SHOULD issue `Warm` for the commit's new packs. *See:*
  [`08-properties.md`](08-properties.md).
- **[TOPO-25]** A tier SHOULD warm from a view's access profile, when the
  view's root names one, before warming the remainder of the view, so that
  the content consumers touch first arrives first. *See:*
  [`10-derived-data.md`](10-derived-data.md).

## Home

Every ref has a home: the authority that serializes its writes. Content is
placeless, since it is identified by its bytes and may be anywhere; refs
are not, since two writers must agree on an order.

- **[TOPO-26]** Every root MUST have an effective `home` property naming a
  region, inherited per [`08-properties.md`](08-properties.md). The home of
  a ref is the home of the root it names. *Gate:* `gate:topo-home`.
- **[TOPO-27]** `CompareAndSwapRef` for a ref MUST be executed by a tier
  whose locality region equals the ref's home and that is configured as the
  authority for that ref. Every other tier MUST forward the write or fail.
  *Gate:* `gate:topo-home`.
- **[TOPO-28]** A tier outside a ref's home MAY serve `GetRef` with
  `freshness=any` or `bounded(d)` from a mirrored copy and MUST attach the
  observed staleness. It MUST NOT serve `freshness=linearizable`. *Gate:*
  `gate:cons-ref-freshness`.
- **[TOPO-29]** Changing a root's `home` MUST be performed as a commit on
  the root under the old home's authority, after which the new home's
  authority becomes responsible. During the change both authorities MUST
  reject writes to the affected refs with `UNAVAILABLE` until the handover
  commit is visible at both. *Gate:* `gate:topo-home`.

## Cross-region misses

Content written in one region is referenced by commits immediately, before
replication has copied it anywhere. Readers elsewhere must still be able to
resolve the reference. The commit carries enough to find the bytes.

- **[TOPO-30]** Every commit MUST record, for each pack it introduces, the
  locality and store identity where the pack was written, per
  [`09-refs-and-commits.md`](09-refs-and-commits.md). *Gate:*
  `gate:topo-promisor`.
- **[TOPO-31]** A tier that misses on a pack referenced by a commit MUST
  add the commit's recorded locations to its candidate set for that read,
  even when those locations are not in its configured tier list, provided
  the caller's grants cover the read. *Gate:* `gate:topo-promisor`.
- **[TOPO-32]** A tier that fetches a pack cross-region on a miss SHOULD
  admit it to its regional authority if the root's replication policy names
  the local region, so that the second reader in the region does not repeat
  the transfer.

## Replication

- **[TOPO-33]** A root MUST have an effective `replicate` property with one
  of the values `none`, `async(regions)`, or `sync(regions)`. *Gate:*
  `gate:topo-replicate`. *See:* [`15-redundancy.md`](15-redundancy.md).
- **[TOPO-34]** Under `sync(regions)`, `CompareAndSwapRef` for a ref beneath
  the root MUST NOT acknowledge until every pack the new commit introduces is
  durable in every named region. *Gate:* `gate:topo-replicate`.
- **[TOPO-35]** Under `async(regions)`, the home authority MUST enqueue
  replication of the new commit's packs to every named region before
  acknowledging and MUST expose replication lag per region through
  [`34-observability.md`](34-observability.md). *Gate:*
  `gate:topo-replicate`.
- **[TOPO-36]** Replication MUST copy packs, per-pack indexes, and meta
  packs as immutable objects and MUST copy ref values only as mirrors that
  carry the home's sequence and epoch. A mirrored ref MUST NOT be writable.
  *Gate:* `gate:topo-replicate`.
- **[TOPO-37]** A pack MUST be replicated to a region at most once per
  destination store, regardless of how many hosts in that region requested
  it. *See:* [`21-bandwidth.md`](21-bandwidth.md).

## Partitions

- **[TOPO-38]** During a partition, a tier MUST continue to serve content
  reads and ref reads at `freshness=any` or satisfiable `bounded(d)` from
  what it holds, and MUST fail ref writes and `linearizable` reads for refs
  whose home is unreachable with `UNAVAILABLE`. *Gate:*
  `gate:topo-partition`.
- **[TOPO-39]** A tier MUST NOT elect itself the authority for a ref whose
  home is unreachable. There is no failover of home; there is only a
  handover commit per TOPO-29. *Gate:* `gate:topo-partition`.
- **[TOPO-40]** A writable exposure whose ref's home becomes unreachable
  MUST continue to accept writes into its upper and MUST report commit
  failures per [`20-consistency.md`](20-consistency.md). It MUST NOT
  discard the upper. *Gate:* `gate:topo-partition`.

## Garbage collection across regions

- **[TOPO-41]** The garbage-collection mark phase for a store that
  participates in replication MUST take as roots the union of refs from
  every region that homes a ref referencing content in the store, and MUST
  NOT sweep any pack while any region's ref set is unavailable. *Gate:*
  `gate:gc-multiregion`. *See:*
  [`17-garbage-collection.md`](17-garbage-collection.md).
- **[TOPO-42]** A pack that exists only at its writing locality per its
  commit's recorded locations MUST NOT be swept from that locality until it
  is durable at every region the root's `replicate` policy names, or the
  commit that introduced it is unreachable from every ref. *Gate:*
  `gate:gc-multiregion`.

## Interactions

- [`11-store-trait.md`](11-store-trait.md) defines `tiered`, whose ordering
  this file replaces with cost-based selection for remote candidates.
- [`18-protocol.md`](18-protocol.md) carries residency, warming, cost
  exchange, and the hop headers.
- [`20-consistency.md`](20-consistency.md) defines the freshness levels
  that home and mirrors serve.
- [`15-redundancy.md`](15-redundancy.md) defines the replication
  combinators that `replicate` policies are realized with.
- [`17-garbage-collection.md`](17-garbage-collection.md) consumes the
  cross-region root union.
- [`08-properties.md`](08-properties.md) registers `home`, `replicate`,
  `warm`, and `store`.
- [`21-bandwidth.md`](21-bandwidth.md) relies on peers, residency, and
  replicate-once.

## Informative: three hosts and two regions

```text
region eu                                region us
  zone eu-a                                zone us-a
    host h1: tiered[disk, peers(eu-a), gw-eu, gw-us]
    host h2: tiered[disk, peers(eu-a), gw-eu, gw-us]
  gw-eu: guard(bucket(eu))  home for refs/heads/master
                                           gw-us: guard(bucket(us))
```

Host `h2` opens a file that `h1` fetched a minute ago. Its candidates are
`disk` (miss), `h1` (filter positive, p50 0.4 ms), `gw-eu` (p50 12 ms),
`gw-us` (p50 140 ms, priced). It reads from `h1`. A job on `h2` commits to
`refs/heads/pr/77`, whose home is `eu`: packs go to `bucket(eu)`, the CAS
goes to `gw-eu`. A reader in `us` following `master` after the fold sees the
new commit through its mirrored ref within replication lag; on its first
miss it fetches the pack from `bucket(eu)` as recorded in the commit and, if
`master` replicates to `us`, the async copy lands shortly after and every
later reader in `us` is served locally.
