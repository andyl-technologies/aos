# 21 — Bandwidth

This file owns how Terrane keeps network traffic proportional to change:
how a sender and receiver agree on what is missing, how bytes are encoded
on the wire, how tiers avoid sending bytes at all, and how metadata traffic
stays small. Every rule here is a consequence of two earlier facts: content
is addressed by hash, so anything already held is never re-sent; and trees
are Merkle sets, so finding the difference between two of them costs time
proportional to that difference.

## Model

Bandwidth is spent at four points and each has one governing idea:

| Point | Idea |
| --- | --- |
| Negotiation | find the delta in O(log n) round trips, send O(delta) |
| Encoding | fewer bytes per chunk on the wire without changing bytes at rest |
| Avoidance | a tier that can see bytes elsewhere never fetches them |
| Metadata | trees, indexes, and refs transfer only what changed |

The control plane, meaning the wire protocol of
[`18-protocol.md`](18-protocol.md), carries negotiation, presigned reads, ref
operations, filters, and bundles. Bulk bytes travel directly between a
client and a bucket, or between peers, and never through the gateway. A
gateway's own bandwidth is therefore proportional to metadata and never to
data, which is what allows it to be stateless and small.

## Negotiation

### Trees

- **[BW-1]** A push MUST begin by naming the commit the sender forked from
  or last synchronized to. The receiver MUST treat every object reachable
  from a commit it holds as present, so that a sender whose base the
  receiver holds sends only the difference. *Gate:*
  `gate:bandwidth-negotiate-delta`.
- **[BW-2]** When no common commit is known, the sender and receiver MUST
  negotiate tree content by comparing node hashes top-down from the roots:
  a node whose hash the receiver holds is skipped with its whole subtree,
  and only the children of differing nodes are examined in the next round.
  The number of rounds is bounded by the tree height and the bytes exchanged
  by the number of differing nodes.
- **[BW-3]** Negotiation MUST NOT require the receiver to enumerate what it
  holds. The sender proposes; the receiver answers per proposal.

### Chunks

- **[BW-4]** A sender MUST restrict chunk negotiation to chunks of objects
  that appear in the tree diff between its base and its new root. Chunks of
  unchanged objects are never negotiated.
- **[BW-5]** Before asking the receiver, a sender SHOULD consult a locally
  cached approximate-membership filter over the receiver's merged index
  ([`12-pack-format.md`](12-pack-format.md)) and drop chunks the filter
  reports present. The residue MUST then be checked in one batched `has`
  request per negotiation, not one request per chunk. A false positive from
  the filter is corrected by the `has` result; a false negative is
  impossible for a filter that is current, and a stale filter costs only an
  unnecessary `has`.
- **[BW-6]** Filters MUST be fetched as deltas keyed by index generation: a
  receiver advertises its current generation, and a sender holding an
  older generation fetches only the shards that changed.
- **[BW-7]** A `has` request MUST carry at most a bounded number of hashes
  (`reference/protocol.md` fixes the bound) and a sender MUST pipeline
  batches rather than await each.

### Refs

- **[BW-8]** A consumer that needs to observe ref movement MUST use the
  watch stream of [`18-protocol.md`](18-protocol.md) rather than polling.
  A watch costs bytes only when the ref moves.

## Encoding on the wire

### Compression

- **[BW-9]** Chunks are compressed with zstd at rest per
  [`05-chunking.md`](05-chunking.md), and the wire carries the at-rest form
  so that no tier recompresses.
- **[BW-10]** A store MAY publish zstd dictionaries trained per content
  class. A chunk compressed with a dictionary MUST record the dictionary
  identifier in its codec header, and the dictionary MUST be a
  content-addressed meta object fetched once and cached. The content class
  is selected from the entry's classification attribute
  ([`10-derived-data.md`](10-derived-data.md)). Dictionaries are most
  valuable for small files where plain zstd has no context.
- **[BW-11]** A reader that lacks a referenced dictionary MUST fetch it
  before decoding and MUST NOT fail the read.

### Wire deltas

- **[BW-12]** A sender MAY encode a chunk on the wire as a delta against one
  or more chunks the receiver is known to hold (known from the negotiation
  of §Chunks). The receiver MUST reconstruct the full chunk, verify its hash,
  and store it whole. *Gate:* `gate:bandwidth-wire-delta-roundtrip`.
- **[BW-13]** Deltas MUST NOT be stored at rest. Every chunk in a pack is
  independently readable and verifiable so that ranged reads, presigned
  reads, and per-chunk verification never depend on another chunk.
- **[BW-14]** A wire delta MUST name its base chunks by hash and MUST carry
  the hash of the reconstructed chunk, so that a receiver that no longer
  holds a base rejects the delta and requests the whole chunk.

## Avoidance

- **[BW-15]** A `shared-dir` tier ([`11-store-trait.md`](11-store-trait.md))
  MUST serve a hit with no transfer and MUST NOT copy bytes into its own
  storage. Nested tiers that can see a parent's object directory therefore
  cost zero bytes for shared content.
- **[BW-16]** A host tier SHOULD advertise pack residency to its zone
  ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)) and a miss
  SHOULD be served by a zone-local peer before a bucket when the cost model
  ranks the peer lower. Egress price is a component of the cost vector, so
  intra-zone bytes are preferred automatically.
- **[BW-17]** When a read plan needs more than the `whole_pack_threshold`
  fraction of a pack (default 0.5), the tier MUST fetch the whole pack in
  one request rather than many ranges. Below the threshold, ranges MUST be
  coalesced across gaps up to `gap_merge_bytes` (default 256 KiB) into
  spans of at most `span_max_bytes` (default 16 MiB), and chunks inside a
  fetched span that were not requested MUST be verified and admitted to the
  cache unpinned rather than discarded.
- **[BW-18]** Prefetch MUST be driven by the access profile of the view
  ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)) and by static
  predictors, so that only content previous or predicted consumers touched
  is fetched. Prefetch traffic MUST run at lower priority than demand
  traffic and MUST be bounded by a bytes-per-second property.
- **[BW-19]** Cross-region replication MUST move each pack once into a
  region's authority store, after which every host in that region reads it
  regionally. Warming after a commit fans out from the regional copy, never
  from the source region per host.

## Metadata

- **[BW-20]** A bundle ([`12-pack-format.md`](12-pack-format.md)) prepared
  for a reader MUST contain only the tree nodes, manifests, and commits the
  reader reports it does not hold, determined by the negotiation of §Trees.
  A reader that already holds the previous commit of a branch receives a
  bundle proportional to the diff.
- **[BW-21]** Merged index shards MUST be published as append-only generations
  with tombstone lists so that an index refresh transfers one generation's
  delta.
- **[BW-22]** Small control messages (`has`, ref operations, presigned URL
  requests, watch events) MUST be multiplexed over one connection and MAY be
  micro-batched within a window of a few milliseconds to amortize round
  trips. The window bound is fixed in `reference/protocol.md`.

## Where bytes are deliberately spent (informative)

Verification requires a whole chunk before it is admitted, so a read of a
few bytes costs at least one chunk of transfer, bounded below by the
chunking minimum of [`05-chunking.md`](05-chunking.md). Workloads dominated
by small random reads of large files should lower the minimum for the
affected roots rather than expect partial-chunk serving. Filters and
dictionaries are fetched ahead of need and cost bytes even when unused; both
are small relative to one pack and are cached across sessions.

## Interactions

- [`05-chunking.md`](05-chunking.md) fixes the at-rest codec that the wire
  carries and the chunk minimum that bounds the smallest read.
- [`06-tree-format.md`](06-tree-format.md) provides the history-independent
  nodes that make top-down comparison correct.
- [`10-derived-data.md`](10-derived-data.md) supplies the classification
  attribute that selects dictionaries.
- [`11-store-trait.md`](11-store-trait.md) defines `shared-dir` and
  `routed`, whose behaviour [BW-15] through [BW-17] constrain.
- [`12-pack-format.md`](12-pack-format.md) defines filters, bundles, and
  index generations.
- [`18-protocol.md`](18-protocol.md) carries every negotiation message,
  `has` batching, watch streams, and presigned reads.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) supplies the
  cost model, peer residency, access profiles, and cross-region replication.
- [`27-surface-fuse.md`](27-surface-fuse.md) and
  [`14-host-tier.md`](14-host-tier.md) are the consumers whose fault paths
  drive demand and prefetch traffic.
