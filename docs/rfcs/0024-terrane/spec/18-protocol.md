# 18 — Wire protocol

This file owns the Terrane wire protocol: the network form of the store
interface defined in [`11-store-trait.md`](11-store-trait.md). It specifies
the transport, the services and their methods, negotiation, bulk transfer,
ref operations, streaming watches, filters, residency, warming, request
metadata, batching and hedging, error codes, and versioning. The message
schema is in [`reference/protocol.md`](reference/protocol.md).

## Overview

The protocol has one job: to be the store interface over a network. Every
pair of tiers that are not in the same process speak it, whether the pair is
a nested cache and its host, a host and a regional gateway, a gateway and a
gateway in another region, or an edge worker and a client in a browser. There
is no second protocol for administration, no separate replication protocol,
and no privileged path that bypasses it. A tier that can be reached at all
can be reached this way.

The protocol carries control and metadata. It does not carry bulk data
except as a fallback. Chunks travel between a client and a bucket by
**presigned read** (for downloads) or by pack upload to the authority; the
`serve` role mints the credentials after `guard` has authorized the
request, batches the questions, and moves refs. This is the single design choice that lets a gateway be
stateless and cheap: its bandwidth is proportional to the number of
requests, never to the number of bytes served.

Three properties follow from the store interface and are preserved on the
wire:

1. Immutable content is idempotent. Putting the same pack twice, or asking
   for the same range twice, is always safe.
2. Refs change only by conditional write, and the condition is carried on
   the wire as the expected previous value.
3. The client is trusted to compute identities and the server is required
   to verify them. A server never accepts an identity it has not checked.

## Transport

- **[PROTO-1]** The protocol MUST be served as ConnectRPC over HTTP/2, with
  the Connect, gRPC, and gRPC-Web wire encodings all accepted. *Gate:*
  `gate:proto-transport`. *See:* §Transport.
- **[PROTO-2]** Every method MUST be reachable with HTTP/1.1 plus JSON
  encoding for unary calls, so that a client in a browser or in a
  WebAssembly runtime without HTTP/2 streaming can use the protocol. Server
  streaming methods MAY require HTTP/2. *Gate:* `gate:proto-transport`.
- **[PROTO-3]** Messages MUST be encoded in the protobuf binary encoding on
  the binary paths and in the canonical protobuf JSON mapping on the JSON
  path. The schema in [`reference/protocol.md`](reference/protocol.md) is
  authoritative. *Gate:* `gate:proto-schema`.
- **[PROTO-4]** A server MUST accept TLS 1.3 and MUST NOT accept an earlier
  TLS version. Plain HTTP MAY be accepted on a Unix domain socket or a
  loopback address only. *Gate:* `gate:proto-transport`.
- **[PROTO-5]** Every request MUST carry a capability token as defined in
  [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  in the `Authorization` header, except `Capabilities` which MAY be called
  anonymously. *Gate:* `gate:auth-enforcement`.

## Services

The store interface has three groups of operations and the protocol has one
service per group, plus one service for tier coordination. Service names
are in the `terrane.v1` package.

| Service | Owns |
| --- | --- |
| `ContentService` | negotiation, pack upload, range reads, presigned reads, bundles, filters |
| `RefService` | ref get, conditional write, log, watch |
| `TierService` | residency, warming, cost hints, capabilities |
| `JobService` | tree-job coordination; specified in [`32-tree-jobs.md`](32-tree-jobs.md) |

- **[PROTO-6]** A tier that claims the Distribution conformance level MUST
  implement `ContentService`, `RefService`, and `TierService` in full. A tier
  MAY reject any method with `PERMISSION_DENIED` on the basis of the
  caller's grants, but MUST NOT reject a method as unimplemented.
  *Gate:* `gate:proto-conformance`.

### `ContentService`

| Method | Kind | Purpose |
| --- | --- | --- |
| `Negotiate` | unary | Given commit ancestry hints, tree roots, and hashes, return what the server lacks |
| `Has` | unary | Batched existence check by hash |
| `PutPack` | client stream | Upload one pack and its per-pack index |
| `GetRange` | server stream | Read a byte range of a pack through the server |
| `PresignRead` | unary | Mint presigned URLs for ranges of packs |
| `GetBundle` | server stream | Fetch the tree nodes, manifests, and commits a reader lacks for a root |
| `GetFilter` | server stream | Fetch the merged-index filter shards changed since a generation |
| `GetIndex` | server stream | Fetch merged-index shards changed since a generation |

### `RefService`

| Method | Kind | Purpose |
| --- | --- | --- |
| `GetRef` | unary | Read a ref, with a freshness requirement |
| `CompareAndSwapRef` | unary | Conditionally write a ref |
| `GetRefLog` | server stream | Read a ref's reflog from a sequence number |
| `WatchRefs` | server stream | Receive changes to matching refs as they happen |
| `ListRefs` | server stream | Enumerate refs matching a pattern |

### `TierService`

| Method | Kind | Purpose |
| --- | --- | --- |
| `Capabilities` | unary | Report protocol version, locality, supported features, and backend probe results |
| `Residency` | unary | Return the tier's residency filter and its generation |
| `Where` | unary | Return a locality histogram for a view's packs |
| `Warm` | unary | Request that a tier fetch a view or pack set ahead of demand |
| `Costs` | unary | Exchange measured cost vectors between peers |

## Negotiation

Negotiation determines what a receiver lacks before anything is sent. It
proceeds from the cheapest question to the most expensive and stops as soon
as the answer is complete. The three stages correspond to the three levels
of the content model: commits, trees, chunks.

- **[PROTO-7]** `Negotiate` MUST accept, in one request, any combination of
  `have_commits` (commit ids the sender knows the receiver has), `roots`
  (tree root hashes the sender intends to reference), and `hashes` (chunk or
  meta-object hashes). *Gate:* `gate:proto-negotiate`.
- **[PROTO-8]** For each `have_commits` entry the receiver has, the receiver
  MUST treat every object reachable from that commit as present and MUST NOT
  report any such object as missing. *Gate:* `gate:proto-negotiate`.
- **[PROTO-9]** For each root in `roots` the receiver MUST answer with the
  set of node hashes on the frontier it does not hold, found by top-down
  comparison, so that a sender discovers the missing subtrees in a number
  of round trips bounded by the tree height. *Gate:* `gate:proto-negotiate`.
- **[PROTO-10]** For `hashes` the receiver MUST answer with a bitmap of the
  hashes it lacks in request order. A request MUST NOT exceed 4096 hashes;
  a server MUST reject a larger request with `INVALID_ARGUMENT`.
  *Gate:* `gate:proto-negotiate`.
- **[PROTO-11]** A receiver MUST answer `Has` and the `hashes` stage of
  `Negotiate` from its index and MUST NOT probe the backing bucket per hash.
  An answer of "present" MUST mean the receiver has a committed index entry
  whose pack the receiver has not tombstoned. *Gate:* `gate:proto-negotiate`.
- **[PROTO-12]** A sender SHOULD consult a locally cached filter (§Filters)
  before `Has`, and SHOULD include in `hashes` only the filter-positive
  residue after its own tree diff. *See:* [`21-bandwidth.md`](21-bandwidth.md).

## Pack upload

- **[PROTO-13]** `PutPack` MUST stream one pack as ordered frames: a header
  frame naming the pack id, size, and pack format version; body frames of at
  most 4 MiB; and a trailing frame carrying the per-pack index. The server
  MUST verify the pack's trailer, every chunk hash, and the index against the
  body before acknowledging. *Gate:* `gate:pack-verify`. *See:*
  [`12-pack-format.md`](12-pack-format.md).
- **[PROTO-14]** A server MUST NOT make any chunk from an uploaded pack
  visible to `Has`, `Negotiate`, or reads before the pack and its index are
  durable at the server's own durability level. *Gate:* `gate:pack-verify`.
- **[PROTO-15]** `PutPack` MUST be idempotent by pack id. A retry of a pack
  the server already holds MUST succeed without re-reading the body, and the
  server MAY close the stream early with `ALREADY_EXISTS` carrying a
  successful acknowledgment. *Gate:* `gate:proto-idempotent`.
- **[PROTO-16]** A server MAY reject a `PutPack` whose declared size exceeds
  the pack size limit negotiated in `Capabilities` with
  `RESOURCE_EXHAUSTED` before reading the body.
- **[PROTO-17]** When the caller's tier owns bytes in a bucket that supports
  multipart upload, the server MAY answer `PutPack`'s header frame with a
  redirect carrying presigned multipart upload URLs, in which case the client
  MUST upload the body directly, MUST complete the multipart upload, and MUST
  then send only the trailing index frame on the stream for verification. The
  client MUST abort the multipart upload if the stream fails. *Gate:*
  `gate:proto-direct-upload`.

## Reads

Bulk reads prefer the direct path. A server that fronts a bucket mints
presigned URLs; a server that fronts a local disk or a block device proxies
ranges itself. Clients discover which applies from `Capabilities`.

- **[PROTO-18]** `PresignRead` MUST accept a list of `(pack id, offset,
  length)` triples and return one URL per contiguous span the server chooses
  to serve, together with the span's `(pack id, offset, length)` and an
  expiry. The server MAY coalesce requested ranges across gaps and MAY widen
  a span; the client MUST verify every chunk it admits regardless of whether
  it was requested. *Gate:* `gate:proto-presign`.
- **[PROTO-19]** A presigned URL MUST expire within 15 minutes of minting
  and MUST be scoped to a single object key and, where the backend supports
  it, to a byte range. *Gate:* `gate:proto-presign`.
- **[PROTO-55]** Presigned reads are minted by the `serve` role, not by
  the `guard` combinator: `serve` MUST call `PresignRead` on a child that
  reports `presign: yes` only after `guard` has authorized the read, MUST
  scope every URL to the exact byte ranges authorized, and MUST prefer a
  presigned read to proxying when the request exceeds the configured size
  threshold. *Gate:* `gate:proto-presign`.
- **[PROTO-20]** `GetRange` MUST stream the requested bytes in frames of at
  most 4 MiB and MUST be available on every tier as a fallback, including
  tiers that also offer `PresignRead`. *Gate:* `gate:proto-reads`.
- **[PROTO-21]** A client MUST NOT admit a chunk to any store until its
  plaintext hash has been recomputed and matched, per
  [`05-chunking.md`](05-chunking.md). Bytes that fail verification MUST be
  discarded and the failure reported per
  [`34-observability.md`](34-observability.md). *Gate:* `gate:chunk-verify`.
- **[PROTO-22]** A server MUST NOT serve a range from a pack that is not in
  the caller's grants, and a server MUST NOT reveal through error codes
  whether a pack exists when the caller lacks `read` on any root that
  references it. Both cases return `NOT_FOUND`. *Gate:*
  `gate:auth-enforcement`. *See:* [`25-threat-model.md`](25-threat-model.md).

## Bundles

A bundle carries the meta objects a reader needs to realize a root: tree
nodes, manifests, and the commit. It exists so that a mount never waits on a
per-node round trip.

- **[PROTO-23]** `GetBundle` MUST accept a root or commit id and a set of
  `have` node hashes or a `have_commit`, and MUST stream every node,
  manifest, and commit reachable from the requested root that the caller has
  not declared, in an order such that a node arrives after every node that
  references it or in a separate closing frame the client can resolve after
  the stream ends. *Gate:* `gate:proto-bundle`.
- **[PROTO-24]** A bundle MUST NOT include data chunks. A server MAY include
  the access profile named by the root's `prefetch` property as a final
  frame. *See:* [`19-tiering-and-topology.md`](19-tiering-and-topology.md).
- **[PROTO-25]** A bundle for a root containing `tree` entries MUST include
  the nodes of grafted roots the caller is authorized to read and MUST omit,
  without error, grafted roots the caller is not authorized to read. The
  omitted entries MUST still appear in their parent nodes, since node
  identity is content-addressed. *Gate:* `gate:auth-enforcement`.

## Refs

Ref operations are the only mutating operations the protocol carries besides
pack upload, and pack upload is idempotent. Every mutation of a ref is a
compare-and-swap.

- **[PROTO-26]** `GetRef` MUST accept a `freshness` of `any`, `bounded(d)`,
  or `linearizable`. A server MUST answer `linearizable` only from the ref's
  home authority and MUST forward or fail with `UNAVAILABLE` otherwise. A
  server answering `bounded(d)` MUST report the observed staleness bound in
  the response and MUST fail with `UNAVAILABLE` if it cannot meet `d`.
  *Gate:* `gate:cons-ref-freshness`. *See:*
  [`20-consistency.md`](20-consistency.md).
- **[PROTO-27]** `CompareAndSwapRef` MUST carry the expected current value
  (commit id, sequence, and writer epoch) or an explicit `absent` marker, and
  the new value. The server MUST apply the write only if the current value
  matches exactly, MUST return the actual current value on mismatch with
  `FAILED_PRECONDITION`, and MUST make the write durable at the ref's
  durability level before acknowledging. *Gate:* `gate:ref-cas`.
- **[PROTO-28]** `CompareAndSwapRef` MUST be forwarded by a non-home tier to
  the home authority, or rejected with `UNAVAILABLE`. A cache MUST NOT
  acknowledge a ref write it did not see the authority acknowledge.
  *Gate:* `gate:ref-cas`.
- **[PROTO-29]** A `CompareAndSwapRef` whose new commit references packs the
  home authority cannot locate through any tier named in the commit's pack
  locations MUST be rejected with `FAILED_PRECONDITION` and an error detail
  listing the missing packs. *Gate:* `gate:ref-cas`. *See:*
  [`09-refs-and-commits.md`](09-refs-and-commits.md).
- **[PROTO-30]** `GetRefLog` MUST stream reflog entries in increasing
  sequence from the requested sequence and MUST include the commit id,
  sequence, writer epoch, timestamp, and the principal that wrote each entry.
  *Gate:* `gate:ref-log`.
- **[PROTO-31]** `WatchRefs` MUST deliver every change to a matching ref in
  sequence order per ref, MUST deliver an initial snapshot of current values
  when `initial=true`, and MUST resume from a client-supplied `resume_token`
  without loss for changes still present in the reflog. *Gate:*
  `gate:ref-watch`.
- **[PROTO-32]** A watch stream that cannot guarantee gap-free delivery,
  because the reflog has been truncated past the resume point, MUST close
  with `OUT_OF_RANGE` so the client re-reads the ref. *Gate:*
  `gate:ref-watch`.

## Filters and indexes

Filters and merged-index shards are how a client avoids negotiation round
trips and how a tier learns what its peers hold. Both are versioned by
generation and fetched as deltas.

- **[PROTO-33]** `GetFilter` MUST accept a `since_generation` and stream only the
  filter shards whose generation is greater, each tagged with its shard id,
  generation,
  and false-positive rate. A client MUST treat a filter as advisory and MUST
  confirm with `Has` before assuming presence. *Gate:* `gate:proto-filter`.
- **[PROTO-34]** `GetIndex` MUST accept a `since_generation` and stream the
  merged-index shards changed since, including tombstone records, per
  [`12-pack-format.md`](12-pack-format.md). *Gate:* `gate:proto-index`.
- **[PROTO-35]** A server MUST NOT expose through `GetFilter`, `GetIndex`,
  `Has`, or `Negotiate` the existence of any chunk in a disclosure domain
  the caller cannot read. Where a chunk exists in several domains, the answer
  MUST be computed as if only the caller's readable domains existed.
  *Gate:* `gate:dom-oracle`. *See:*
  [`24-disclosure-domains.md`](24-disclosure-domains.md).

## Residency, warming, and cost

- **[PROTO-36]** `Residency` MUST return a filter over the pack ids the tier
  holds, its generation, and the tier's locality label. The filter MUST be small
  enough to embed in a heartbeat; 16 KiB is RECOMMENDED. *Gate:*
  `gate:topo-residency`.
- **[PROTO-37]** `Where` MUST return, for a view, a histogram of the
  fraction of the view's packs resident at each locality known to the
  server, computed from the residency filters the server holds. It is
  advisory. *Gate:* `gate:topo-residency`.
- **[PROTO-38]** `Warm` MUST accept a view or pack list and a priority and
  MUST return immediately with a job id; progress is observed through
  `JobService`. A tier MAY refuse with `RESOURCE_EXHAUSTED` when its
  admission budget is spent. *Gate:* `gate:topo-warm`.
- **[PROTO-39]** `Costs` MUST carry the caller's measured cost vector for
  the callee and MUST return the callee's measured cost vector for the
  caller, so that both sides converge on symmetric estimates. *See:*
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md).

## Request metadata

Every request and response carries a small set of headers that make the
tier graph observable.

| Header | Direction | Meaning |
| --- | --- | --- |
| `terrane-hop` | request | integer hop count so far; incremented at each forwarding tier |
| `terrane-path` | response | comma-separated locality labels of tiers that served the request |
| `terrane-served-by` | response | the tier kind that produced the bytes: `page-cache`, `disk`, `shared-dir`, `peer`, `bucket`, `remote` |
| `terrane-stale` | response | observed staleness of a ref read in milliseconds |
| `traceparent` | both | W3C trace context |

- **[PROTO-40]** A forwarding tier MUST increment `terrane-hop`, MUST append
  its locality to `terrane-path` on the way back, and MUST refuse a request
  whose hop count exceeds the limit advertised in `Capabilities` with
  `FAILED_PRECONDITION`, to prevent forwarding loops. *Gate:*
  `gate:topo-hops`.
- **[PROTO-41]** A server MUST propagate `traceparent` to every downstream
  request it makes on the caller's behalf, including presigned-URL minting
  and bucket calls where the backend accepts it. *Gate:* `gate:obs-trace`.

## Batching and hedging

- **[PROTO-42]** A client SHOULD coalesce `Has`, `PresignRead`, and
  `Negotiate` calls issued within a micro-batching window before sending. The
  window SHOULD be at most 2 ms on a host tier and MAY be longer on an edge
  worker. The window MUST NOT delay a request that would fill the batch
  limit. *See:* [`21-bandwidth.md`](21-bandwidth.md).
- **[PROTO-43]** A client MAY hedge an idempotent read against a second
  candidate tier after a delay derived from the first candidate's measured
  p50 latency, and MUST cancel the loser. A client MUST NOT hedge
  `CompareAndSwapRef` or `PutPack`. *Gate:* `gate:proto-idempotent`.
- **[PROTO-44]** A server MUST honor cancellation on every streaming method
  and MUST release any presigned-upload or reservation state associated with
  a cancelled stream within the grace window of
  [`17-garbage-collection.md`](17-garbage-collection.md).

## Errors

Errors use the Connect and gRPC status codes. The mapping from outcomes to
codes, and from codes to POSIX `errno` values at a surface, is normative in
[`reference/errno-mapping.md`](reference/errno-mapping.md).

- **[PROTO-45]** A server MUST use the codes in
  [`reference/errno-mapping.md`](reference/errno-mapping.md) for the outcomes
  listed there and MUST attach the structured error detail named there where
  one is defined. *Gate:* `gate:proto-errors`.
- **[PROTO-46]** A server MUST NOT distinguish "does not exist" from "not
  permitted" in any code, message, or timing that the caller can observe,
  except where the caller holds `admin` on the enclosing root.
  *Gate:* `gate:auth-enforcement`.
- **[PROTO-47]** Every error that a client can resolve by retrying MUST be
  marked so in the error detail, and a client MUST NOT retry an error not so
  marked. Retries MUST use exponential backoff with jitter and MUST respect
  a server-supplied `retry-after`. *Gate:* `gate:proto-errors`.

## Versioning

- **[PROTO-48]** The package `terrane.v1` MUST evolve only additively: new
  methods, new optional fields, new enum values with an unknown-tolerant
  default. A breaking change MUST use a new package `terrane.v2` served
  alongside `v1` for at least one minor version of the specification.
  *Gate:* `gate:proto-schema`.
- **[PROTO-49]** `Capabilities` MUST report every package version the server
  speaks, the pack format versions it accepts, the tree encoding versions it
  accepts, the maximum hop count, the maximum pack size, whether it mints
  presigned reads, whether it supports direct multipart upload, and the
  result of its backend conditional-write probe per
  [`13-bucket-layout.md`](13-bucket-layout.md). *Gate:* `gate:proto-schema`.
- **[PROTO-50]** A client MUST NOT send a pack format or tree encoding
  version the server did not advertise. A server MUST reject an
  unadvertised version with `UNIMPLEMENTED`. *Gate:* `gate:proto-schema`.
- **[PROTO-51]** A message with unknown fields MUST be accepted and the
  fields ignored. A message with an unknown enum value in a field the server
  must act on MUST be rejected with `INVALID_ARGUMENT`.

## Tier symmetry

The protocol is the same in every direction. This is stated as a requirement
because it is easy to lose: a special "replication" or "admin" path is the
first thing an implementation grows, and the first thing that breaks the
tier model.

- **[PROTO-52]** Any tier that accepts the protocol MUST accept it from any
  caller with valid grants regardless of the caller's role. There MUST NOT
  be a method, header, or flag that is honored only for a peer, a parent
  tier, or a replication process. *Gate:* `gate:proto-conformance`.
- **[PROTO-53]** A tier MUST be able to act as a client of the same protocol
  toward each store in its own tier list, so that nesting is unbounded and a
  nested instance's parent is indistinguishable from a regional gateway.
  *Gate:* `gate:topo-nesting`.
- **[PROTO-54]** The control channel MUST NOT be used to move data chunks
  except through `GetRange` and `PutPack`, and an implementation MUST report
  the fraction of bytes served through `GetRange` versus presigned reads so
  that a misconfigured deployment that proxies all data is visible.
  *See:* [`34-observability.md`](34-observability.md).

## Interactions

- [`11-store-trait.md`](11-store-trait.md) defines the operations this
  protocol carries; the two MUST stay in one-to-one correspondence.
- [`12-pack-format.md`](12-pack-format.md) defines what `PutPack` verifies
  and what `GetIndex` and `GetFilter` return.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the ref value
  that `CompareAndSwapRef` compares.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) consumes
  `Residency`, `Where`, `Warm`, `Costs`, and the hop headers.
- [`20-consistency.md`](20-consistency.md) defines the freshness levels of
  `GetRef`.
- [`21-bandwidth.md`](21-bandwidth.md) specifies how negotiation and filters
  are used to minimize bytes.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  defines the token every request carries and the grants each method checks.
- [`24-disclosure-domains.md`](24-disclosure-domains.md) constrains what
  existence answers may reveal.
- [`38-wasm-and-edge.md`](38-wasm-and-edge.md) relies on PROTO-1 and
  PROTO-2 to serve the protocol from a WebAssembly worker.

## Informative: a read and a write on the wire

A host tier opening a file it does not hold:

```text
client -> host        GetRange? no: host consults index, misses
host   -> peer        Has [h1..h8]          (2 ms window, one call)
peer   -> host        bitmap: has h1..h6
host   -> peer        PresignRead [(p, o1, l1) .. (p, o6, l6)]
peer   -> host        2 URLs (ranges coalesced across a 128 KiB gap)
host   -> peer bucket GET range .. (direct, no control channel)
host   -> gateway     PresignRead [(q, o7, l7), (q, o8, l8)]
gateway-> host        1 URL
host   -> bucket      GET range ..
host                  verify 8 chunks, admit, serve
```

A CI job committing to its branch:

```text
job    -> gateway  Negotiate {have_commits: [C_base], roots: [R_new]}
gateway-> job      frontier: 3 nodes missing; everything under C_base present
job    -> gateway  Has [chunks of files under the 3 nodes, filter residue]
gateway-> job      bitmap: 40 of 212 missing
job    -> gateway  PutPack (header) -> redirect: multipart URLs
job    -> bucket   multipart upload of one 31 MiB pack
job    -> gateway  PutPack (trailer: index) -> verified, ack
job    -> gateway  PutPack (meta pack: 3 nodes + commit)   -> ack
job    -> gateway  CompareAndSwapRef refs/heads/pr/1234 expect {C_prev, 7, e} new {C_new, 8, e}
gateway-> home     (forwarded)                              -> ok
```
