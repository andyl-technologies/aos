# 38 — WebAssembly and edge deployments

This file owns what it means to run Terrane inside a WebAssembly host at the
edge of a network: which operations belong there, which stay on native hosts,
how an edge instance and a native instance share one bucket without
translation, and what an edge implementation may claim for conformance. It
exists because the identity code has no reason to care where it runs, and an
edge worker in front of a bucket is the cheapest possible gateway.

## Overview

An edge instance is `terrane` compiled to `wasm32` with the `wasm` feature,
bound to a host that offers a fetch primitive, a time primitive, and an
object-storage binding with conditional writes. It reads trees and packs
from the bucket, serves protocol surfaces, verifies tokens, and accepts small
commits whose heavy lifting the client already did. It does not merge large
trees, run garbage collection, compact packs, or chunk gigabytes, because a
request-scoped WebAssembly host offers on the order of 128 MiB of memory,
bounded CPU per request, no threads, and no filesystem. Those jobs run as
native roles against the same bucket, and nothing about the bucket layout
tells the two apart.

```text
   client ──► edge worker ──► bucket ◄── native terrane (gc, job, serve)
              reads, auth,            packs, indexes, trees, refs
              small commits,
              protocol surfaces
```

## Host requirements

- **[EDGE-1]** An edge host MUST provide the three primitives `terrane`
  binds through `terrane-edge` ([`37-crate-structure.md`](37-crate-structure.md)
  `CRATE-13`): an HTTP fetch, a monotonic and wall clock, and an
  object-storage binding. An edge implementation MUST NOT depend on any
  other host capability for Core conformance.
- **[EDGE-2]** The object-storage binding MUST support create-if-absent and
  compare-and-swap on a single object, either through the host's native
  conditional form or through the S3-compatible `If-None-Match` and
  `If-Match` headers of [`13-bucket-layout.md`](13-bucket-layout.md). An
  edge instance MUST probe this support at startup as `BKT` requires and
  MUST refuse ref writes, not degrade silently, when it is absent. *Gate:*
  `gate:bucket-probe`.
- **[EDGE-3]** An edge instance MUST treat every request as independent. It
  MUST NOT rely on in-memory state surviving between requests for
  correctness. Caches that do survive are an optimization and MUST be
  validated against the bucket on use, by ref sequence or content hash.

## What runs at the edge

- **[EDGE-4]** An edge instance MUST support every read operation of the
  wire protocol ([`18-protocol.md`](18-protocol.md)): tree lookups from
  bundles, manifest and node fetches, ranged pack reads, filter and index
  fetches, ref reads, and watch by long poll.
- **[EDGE-5]** An edge instance MUST mint presigned bulk reads
  ([`18-protocol.md`](18-protocol.md) §bulk reads) rather than proxying pack
  bytes through itself whenever the host's storage binding can produce a
  time-limited URL. Where it cannot, the instance MAY proxy ranged reads and
  MUST bound the proxied size per request.
- **[EDGE-6]** An edge instance MUST serve the Nix binary-cache surface's
  compressed archive responses by concatenating stored per-chunk zstd frames
  in object order without decompressing, recompressing, or reassembling
  ([`30-surface-protocols.md`](30-surface-protocols.md) `NIX`). This is
  correct because a sequence of complete zstd frames is a valid zstd stream,
  and it is the reason the compressed-at-rest format uses one frame per
  chunk ([`05-chunking.md`](05-chunking.md)). *Gate:*
  `gate:nix-surface-stream`.
- **[EDGE-7]** An edge instance MUST verify capability tokens and evaluate
  grants ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md))
  in-process using `terrane-core`; it MUST NOT call out to a separate
  authorization service.
- **[EDGE-8]** An edge instance MUST accept a commit when the client has
  already chunked, hashed, and compressed the content and the commit's
  residue after negotiation fits the host's request limits. The instance
  verifies each chunk's hash and boundaries, writes packs and per-pack
  indexes, writes the commit, and performs the ref compare-and-swap, in the
  order [`17-garbage-collection.md`](17-garbage-collection.md) requires.
- **[EDGE-9]** An edge instance MUST reject, with the protocol's
  resource-limit status, a commit whose verification would exceed the host's
  CPU or memory budget, and MUST report the limit so the client can split
  the commit or route it to a native instance.
- **[EDGE-10]** An edge instance MAY perform three-way merges whose diff
  fits in memory, for example folding a small branch. It MUST estimate the
  merge's working set from node counts before starting and MUST refuse, not
  time out, when the estimate exceeds its budget.

## What stays native

- **[EDGE-11]** Garbage collection ([`17-garbage-collection.md`](17-garbage-collection.md)),
  pack compaction and merged-index construction
  ([`12-pack-format.md`](12-pack-format.md)), redundancy scrub and resilver
  ([`15-redundancy.md`](15-redundancy.md)), and backfill jobs
  ([`32-tree-jobs.md`](32-tree-jobs.md)) MUST NOT be claimed by an edge
  implementation. They are native roles run against the same bucket.
- **[EDGE-12]** Chunking of content larger than the host's per-request
  memory budget MUST happen on the client or on a native instance. An edge
  instance MAY chunk content that fits its budget.
- **[EDGE-13]** No kernel surface is available at the edge. An edge
  implementation MUST NOT claim any `Surface: <name>` level whose surface is
  owned by `terrane-fs`.

## One bucket, two runtimes

- **[EDGE-14]** An edge instance and a native instance MUST be able to
  operate on the same bucket concurrently with no translation layer and no
  ownership handoff. Every object either writes is the object the other
  reads, byte for byte, because both produce identities with the same
  `terrane-core` ([`37-crate-structure.md`](37-crate-structure.md) `CRATE-3`).
  *Gate:* `gate:edge-native-interop`.
- **[EDGE-15]** Writer epochs ([`09-refs-and-commits.md`](09-refs-and-commits.md))
  fence edge and native writers of one ref identically. An edge instance
  MUST obtain its epoch from the ref, not from host state.
- **[EDGE-16]** An edge instance MUST honor tombstones and grace windows
  ([`17-garbage-collection.md`](17-garbage-collection.md)) written by a
  native collector, and a native collector MUST treat objects written by an
  edge instance exactly as its own for marking and sweeping.

## Compression at the edge

- **[EDGE-17]** An edge implementation MUST be able to decode zstd frames
  for verification. It MAY do so with a pure-Rust decoder.
- **[EDGE-18]** An edge implementation is NOT REQUIRED to encode zstd. Where
  it does not, it MUST require clients to submit chunks already compressed in
  the at-rest format, and it MUST still verify the plaintext hash by
  decoding. The negotiation of [`18-protocol.md`](18-protocol.md) carries a
  capability flag stating whether the server compresses.
- **[EDGE-19]** Dictionary-compressed chunks ([`21-bandwidth.md`](21-bandwidth.md))
  MUST be decodable at the edge with the dictionary fetched from the bucket
  by its content hash. An edge instance MUST NOT ship dictionaries in its
  binary.

## Edge surfaces

The surfaces an edge implementation may offer, all owned by `terrane`:

| Surface | Notes |
| --- | --- |
| `api` | the wire protocol, reads and small commits |
| `browse` | browse and download with presigned redirects |
| `nix-cache` | narinfo and streamed archives, `EDGE-6` |
| `oci` | manifest and blob serving, blob upload within limits |
| `gha-cache` | cache restore and small saves |
| `reapi` | read-only capabilities and action-cache lookups; execution is out of scope everywhere |

- **[EDGE-20]** An edge surface MUST declare the same schema
  ([`26-surfaces.md`](26-surfaces.md)) as its native counterpart and MUST
  produce the same responses for the same view, apart from request-size
  limits it advertises.

## Conformance claim

- **[EDGE-21]** An edge implementation claims **Core** with the exclusions
  in `EDGE-11` and `EDGE-13` stated explicitly, **Distribution** for the
  client and server halves of the protocol it serves, **Security**, and
  `Surface: <name>` for each surface in §Edge surfaces it implements. It
  MUST NOT claim **Host**, **Redundant**, or **Operations**.
- **[EDGE-22]** The conformance suite ([`36-testing-and-conformance.md`](36-testing-and-conformance.md))
  MUST run the golden vectors and the protocol tests against an edge build
  under a request-scoped harness that enforces the memory and CPU limits of
  `EDGE-9`, so that a passing claim reflects the constrained environment,
  not a native run of the same code.

## Interactions

- [`37-crate-structure.md`](37-crate-structure.md): `terrane-core` and the
  `wasm` feature make this file possible.
- [`13-bucket-layout.md`](13-bucket-layout.md): conditional-write probing.
- [`18-protocol.md`](18-protocol.md): capability flags for compression and
  limits.
- [`30-surface-protocols.md`](30-surface-protocols.md): the Nix surface's
  streamed archive.
- [`40-risks-and-open-questions.md`](40-risks-and-open-questions.md)
  `RISK-2` tracks the zstd encoder question.

## Informative: the shape of an edge deployment

A typical edge deployment puts a worker in front of a bucket in every region
where readers are, with the bucket replicated by the storage provider and
refs homed in one region. Readers get regional latency for trees and
presigned reads; small writers such as a cache-save get a regional
round-trip plus one home-region compare-and-swap. The native roles run on a
schedule somewhere with memory to spare. The provider's own conditional
writes are the only coordination mechanism, which is exactly the property
the whole store is built on.
