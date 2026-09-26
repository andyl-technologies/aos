# 11 — Store interface and composition

This file owns the store interface: the two traits every storage backend
implements one or both of, the backends that own bytes, the combinators
that build stores from other stores, and the expression language that
configures a running instance. Everything above this layer (refs, trees, surfaces) sees only this
interface. Everything below it (buckets, disks, block devices, remote
instances) is hidden behind it.

## Overview

A store holds immutable content and, if it is an authority, a small set of
mutable refs. Content is written idempotently and read by identity. Refs
change only by conditional write. The interface is therefore two traits:
**`ContentStore`** for immutable content and **`RefStore`** for refs. A
**`Store`** implements both. Which trait a backend implements is what makes
it a cache or an authority; there is no separate rule. The contract is
deliberately narrow: because
the unit of storage is an immutable, self-describing pack
([`12-pack-format.md`](12-pack-format.md)) and the only mutable state is a
ref ([`09-refs-and-commits.md`](09-refs-and-commits.md)), a store can be a
bucket, a directory, a raw device, or another Terrane instance without the
layers above noticing.

Stores compose. A `routed` store reads from the cheapest child that has the
content and writes to the child that implements `RefStore`. A `guard` store
wraps a child with authorization and nothing else. `replicated` and
`striped` spread packs over several children. Because every combinator is
itself a store, an instance's configuration is one expression, and the same
program serves as a bucket gateway, a node-local cache, a nested cache inside
a sandbox, or an edge worker by evaluating a different expression.

## The interface

The interface is stated here in language-neutral form. A conforming
implementation exposes these operations with these semantics; names and
signatures follow the implementation language.

```text
ContentStore
  put(kind, bytes)             -> id           idempotent write of content
  get(id, range?)              -> bytes        read all or part of content
  has(ids)                     -> bitmap       membership test, batched
  list(prefix)                 -> ids          recovery and GC only

RefStore
  ref_get(name)                -> (commit_id, seq, epoch) | absent
  ref_cas(name, expect, new)   -> ok | conflict(current)
  ref_log_append(name, seq, record) -> ok | exists
  ref_log_read(name, from_seq)  -> records
  ref_watch(name)              -> stream of records

Store = ContentStore + RefStore
```

- **[STORE-32]** `ContentStore` and `RefStore` MUST be distinct interfaces.
  A backend or combinator MUST declare which it implements, and a caller
  MUST be able to hold a `ContentStore` without any ref operation being
  reachable. The **authority** of an expression is the child that
  implements `RefStore`; a cache is a child that implements only
  `ContentStore`. *Gate:* `gate:store-trait-split`.

`kind` names the identity domain of the content
([`04-content-model.md`](04-content-model.md)): data chunk, manifest, tree
node, commit, bundle, index, filter, or pack. `id` is the content hash in
that domain. `range` is a byte range within the content, used for chunk
ranges inside packs and for partial object reads.

### Immutable content

- **[STORE-1]** `put` MUST be idempotent: writing content whose identity is
  already present MUST succeed without modifying stored bytes and MUST NOT
  require the caller to check `has` first. *Gate:* `gate:store-idempotent-put`.
- **[STORE-2]** `put` MUST verify that the identity of the supplied bytes in
  the supplied `kind` equals the identity the store records. A store MUST NOT
  record content under an identity it did not compute or verify itself.
  *Gate:* `gate:store-verify-on-put`.
- **[STORE-3]** `get` MUST return bytes whose identity verifies, or an error.
  A store that detects a mismatch on read MUST NOT return the bytes and MUST
  treat the stored copy as corrupt ([`14-host-tier.md`](14-host-tier.md)
  §quarantine, [`15-redundancy.md`](15-redundancy.md) §repair).
  *Gate:* `gate:store-verify-on-get`.
- **[STORE-4]** `get` with a `range` MUST return exactly the requested byte
  range of the content, and MUST support ranges that fall within one chunk
  body inside a pack without reading the whole pack.
  *Gate:* `gate:store-ranged-get`.
- **[STORE-5]** `has` MUST be batched: one call MUST accept many identities
  and return one bit per identity, in order. A `has` result of present MUST
  mean the store can serve `get` for that identity at the time of the call;
  a catalog row alone is not presence.
  *Gate:* `gate:store-has-batched`.
- **[STORE-6]** A store MUST NOT delete immutable content except through the
  garbage-collection protocol in
  [`17-garbage-collection.md`](17-garbage-collection.md) or, for cache tiers,
  the eviction protocol in [`14-host-tier.md`](14-host-tier.md).

### Refs

- **[STORE-7]** `ref_cas` MUST be atomic compare-and-swap on the whole ref
  record: it succeeds only if the current record equals `expect` (or is
  absent when `expect` is absent), and on failure MUST return the current
  record. *Gate:* `gate:store-ref-cas`.
- **[STORE-8]** `ref_log_append` MUST be create-if-absent on `(name, seq)`.
  A second append to the same `(name, seq)` MUST fail and MUST NOT modify the
  existing record. *Gate:* `gate:store-ref-log-append-once`.
- **[STORE-9]** A store that cannot provide the atomicity in [STORE-7] and
  [STORE-8] MUST report the capability `refs: single-writer` at open time,
  and callers MUST NOT run more than one writer against its refs
  ([`13-bucket-layout.md`](13-bucket-layout.md) §conditional writes).
  *Gate:* `gate:store-capability-probe`.
- **[STORE-10]** Exactly one child of a `routed` expression implements
  `RefStore`: the **authority**. A `ref_cas` or `ref_log_append` addressed
  to the expression MUST be delivered to the authority unchanged and its
  result returned unchanged. A `ContentStore`-only child MAY serve a cached
  `ref_get` only when the caller's consistency mode permits stale reads
  ([`20-consistency.md`](20-consistency.md)).
  *Gate:* `gate:store-ref-forwarding`.

### Listing

- **[STORE-11]** `list` MUST NOT be used to determine correctness of any
  read, write, negotiation, or ref operation. It MAY be used only by
  garbage collection to form candidate sets, by recovery to rebuild indexes,
  and by scrub. An implementation MUST be correct if `list` returns a stale
  or partial result. *Gate:* `gate:store-list-not-authoritative`.

### Capabilities

Every store reports a capability set at open time so combinators and callers
can configure themselves without probing at request time.

```text
refs:        cas | single-writer | none
ranges:      yes | whole-object-only
presign:     yes | no
locality:    {region, zone, host}
durability:  local | zone | region | regions(n)
sealed:      yes | no      (can hand out sealed backing objects, see 14)
```

- **[STORE-12]** A store MUST report its capability set before serving any
  request, and MUST NOT report a capability it has not verified for its
  backend at open time. *Gate:* `gate:store-capability-probe`.

## Backends

A backend is a store that owns bytes. Five are defined.

| Backend | Owns | Traits | Typical role |
| --- | --- | --- | --- |
| `bucket` | packs, indexes, refs in an object store or a filesystem using the layout in [`13-bucket-layout.md`](13-bucket-layout.md) | `ContentStore` + `RefStore` (cas or single-writer per probe) | authority; also the on-disk form of `disk` |
| `disk` | a node-local cache: compressed chunks, sealed objects, indexes, pins ([`14-host-tier.md`](14-host-tier.md)) | `ContentStore` + `RefStore` for pool-homed refs; ref cache otherwise | node-local tier |
| `shared-dir` | nothing; a read-only view of another tier's object directory or chunk cache | `ContentStore` only | nested sandbox or guest tier |
| `blockdev` | packs, indexes, refs on raw block devices ([`16-blockdev-backend.md`](16-blockdev-backend.md)) | `ContentStore` + `RefStore` (superblock flip) | self-contained pool; capacity tier |
| `remote` | nothing locally; a client of another Terrane instance over the wire protocol ([`18-protocol.md`](18-protocol.md)) | `ContentStore`; also `RefStore` when the target is an authority | link to a peer, a parent tier, or a warehouse |

- **[STORE-13]** `bucket` over a `file://` root MUST use exactly the key
  layout of [`13-bucket-layout.md`](13-bucket-layout.md), so that a directory
  written by one instance is a valid bucket for any other, and so that a
  `disk` tier's durable state is a bucket. *Gate:* `gate:bucket-file-layout`.
- **[STORE-14]** `shared-dir` MUST answer `get` and `has` from the directory
  it views and MUST NOT write to it, cache from it, or count its contents
  against the viewing instance's reservations. A `put` to `shared-dir` MUST
  fail with `read-only`. This is the mechanism by which a nested tier stores
  nothing that a tier it can see already holds
  ([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)
  invariant on duplication). *Gate:* `gate:shared-dir-read-only`.
- **[STORE-15]** `remote` MUST expose the capability set reported by the
  instance it connects to, narrowed by the token it holds
  ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)).
- **[STORE-16]** `blockdev` and `bucket` MUST implement `RefStore` and so
  MUST be able to serve as the authority of an expression. `shared-dir` and
  a `remote` whose target is a peer cache MUST implement only
  `ContentStore`. A `remote` whose target is an authority implements
  `RefStore` by delivery to that authority. `disk` implements `RefStore`
  only for refs homed on the local pool
  ([`16-blockdev-backend.md`](16-blockdev-backend.md)).

## Combinators

A combinator is a store built from child stores. Five are defined here; the
redundancy combinators are specified in [`15-redundancy.md`](15-redundancy.md)
and summarized for completeness.

### `routed`

`routed[c1, c2, …, cn]` presents a list of children as one store. Reads are
routed to children by measured cost, not by list position; the child that
implements `RefStore` is the authority and the others are caches. Each
child is a **tier**.

- **[STORE-17]** A `get` or `has` on `routed` MUST consult children in
  ascending expected cost and return the first verified hit. The default
  cost order is list order; when children carry locality and cost vectors
  ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)) the order MUST
  be recomputed from measured cost per request class.
  *Gate:* `gate:routed-read-order`.
- **[STORE-18]** A `put` on `routed` MUST be durable at the authority before
  it is acknowledged. It MAY also be written through to cache children; a
  failure to write a cache MUST NOT fail the `put`.
  *Gate:* `gate:routed-write-authority`.
- **[STORE-19]** After a miss is served from a lower child, `routed` SHOULD
  admit the content into higher cache children subject to each child's
  admission policy. It MUST NOT admit into a `shared-dir` child.
- **[STORE-20]** A `has` on `routed` MUST return present only if some child
  returns present; a filter hit ([`12-pack-format.md`](12-pack-format.md)
  §filters) is a hint for ordering, never a presence answer.
- **[STORE-21]** Ref operations on `routed` follow [STORE-10].

### `guard`

`guard(policy)(child)` wraps a child with the single enforcement point for
authorization. It does one thing: decide, from the caller's capability
token, whether an operation on a ref or root pattern proceeds. Upload
validation is an invariant of every `put` ([STORE-2], [STORE-33]) and
presigned reads are a function of the `serve` role
([`18-protocol.md`](18-protocol.md) §bulk reads); neither is `guard`'s job.

- **[STORE-22]** `guard` MUST be the only place in an expression where
  tokens are checked; children below a `guard` MUST NOT receive tokens and
  MUST NOT perform authorization
  ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)).
  *Gate:* `gate:guard-single-enforcement`.
- **[STORE-23]** (withdrawn; validation is [STORE-33], owned by every
  store rather than by `guard`.)
- **[STORE-24]** (withdrawn; presigning is [`18-protocol.md`](18-protocol.md)
  PROTO-55, owned by the `serve` role rather than by `guard`.)
- **[STORE-33]** Every `put` of a data chunk MUST be validated against the
  chunking rules in [`05-chunking.md`](05-chunking.md) and every `put` of a
  meta object against `reference/terrane-v1.cddl` by the first store that
  admits it, before the bytes become visible to any `get`. Content that
  already exists (a dedup hit) MAY be accepted without re-validation only if
  the store verified it on its original `put`. A `routed` or `guard`
  combinator MUST NOT be relied upon to perform this validation.
  *Gate:* `gate:store-validates-uploads`.

### `cache`

`cache(policy)(child)` gives a child an admission and eviction policy without
making it a `disk`. It is how a `blockdev` or `bucket` child acts as a cache
tier rather than an authority.

- **[STORE-25]** `cache` MUST implement only `ContentStore`, MUST NOT be an
  authority, and
  MUST apply the eviction rules of [`14-host-tier.md`](14-host-tier.md)
  §eviction to the child it wraps.

### `replicated` and `striped`

`replicated(n, ack=k)[children…]` writes every pack to `n` children and
acknowledges after `k`. `striped(k, parity=m)[children…]` cuts a pack into
`k` contiguous stripes and `m` parity shards. Both are specified in
[`15-redundancy.md`](15-redundancy.md).

- **[STORE-26]** `replicated` and `striped` MUST present exactly the store
  interface; a caller MUST NOT be able to distinguish a redundant store from
  a single backend except through its capability set.

## Store expressions

An instance is configured by one store expression. The grammar is:

```text
expr     := backend | combinator
backend  := "bucket" "(" url ")"
          | "disk" "(" path ")"
          | "shared-dir" "(" path ")"
          | "blockdev" "(" devices ")"
          | "remote" "(" url ")"
combinator := "routed" "[" expr ("," expr)* "]"
          | "guard" "(" policy ")" "(" expr ")"
          | "cache" "(" policy ")" "(" expr ")"
          | "replicated" "(" n "," "ack=" k ")" "[" expr ("," expr)* "]"
          | "striped" "(" k "," "parity=" m ")" "[" expr ("," expr)* "]"
```

Every leaf and node MAY carry a locality label and cost hints
([`19-tiering-and-topology.md`](19-tiering-and-topology.md)).

- **[STORE-27]** An expression MUST have exactly one child implementing
  `RefStore` reachable through its `routed` spine, or none at all (a pure
  cache instance that delivers refs through a `remote`). An expression with two authorities MUST
  be rejected at load time. *Gate:* `gate:store-expression-validate`.
- **[STORE-28]** An expression MUST be rejected at load time if any child's
  probed capabilities are incompatible with its position: a `shared-dir` as
  authority, a `single-writer` bucket under a multi-writer `guard`, a
  `presign: no` child where the policy requires presigning.
  *Gate:* `gate:store-expression-validate`.
- **[STORE-29]** Evaluating an expression MUST NOT change the identity of any
  content. Identity is a function of bytes and kind only
  ([`04-content-model.md`](04-content-model.md)); the store that holds the
  bytes is not part of it.

### Examples

A bucket gateway (a "warehouse"), stateless and horizontally scalable:

```text
guard(policy=warehouse)(bucket(s3://region-bucket/prefix))
```

A node-local host tier fronting two gateways in priority order:

```text
routed[
  disk(/var/lib/terrane),
  remote(https://warehouse-a.example),
  remote(https://warehouse-b.example),
]
```

A nested tier inside a sandbox or a guest that can see the host's object
directory read-only and reaches the host instance for misses:

```text
routed[
  shared-dir(/run/terrane/objects),
  remote(unix:///run/terrane/host.sock),
]
```

A self-contained pool on bare devices with a small hot filesystem tier:

```text
routed[
  disk(/var/lib/terrane/hot),
  replicated(2, ack=2)[blockdev(/dev/nvme0n1), blockdev(/dev/nvme1n1)],
]
```

An edge worker:

```text
guard(policy=edge)(bucket(r2://account/bucket))
```

## Error taxonomy

Every operation returns one of a closed set of outcomes so that callers and
surfaces map them consistently
([`reference/errno-mapping.md`](reference/errno-mapping.md)).

| Outcome | Meaning |
| --- | --- |
| `ok` | The operation completed with the stated semantics. |
| `absent` | The identity or ref does not exist in this store. Not an error for `has` or `ref_get`. |
| `conflict(current)` | A `ref_cas` expectation did not hold; `current` is returned. |
| `exists` | A `ref_log_append` hit an existing `(name, seq)`. |
| `corrupt(id)` | Stored bytes failed verification; the store has quarantined or discarded them. |
| `read-only` | The store cannot accept writes (`shared-dir`, a fenced writer, a cache that is full and cannot evict). |
| `denied` | A `guard` refused the operation. Carries no detail beyond the verb and pattern that failed. |
| `unavailable(retry-after?)` | The backend is unreachable or a circuit breaker is open. |
| `capacity` | A reservation or quota would be exceeded. |
| `invalid` | Uploaded content failed validation. Carries the failing rule ID. |
| `unsupported` | The store lacks a required capability for this request. |

- **[STORE-30]** A store MUST NOT return `ok` for an operation that did not
  achieve the stated semantics, and MUST NOT return an outcome outside this
  table. Backend-specific detail is carried as an attached diagnostic, never
  as a different outcome. *Gate:* `gate:store-error-taxonomy`.
- **[STORE-31]** `unavailable` from one child of `routed` MUST NOT be
  surfaced while any other child can serve the request. Only when every
  candidate child fails is `unavailable` returned, carrying the shortest
  `retry-after` reported.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines the identity domains
  that `kind` selects.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the ref record
  that `ref_cas` swaps and the log record that `ref_log_append` writes.
- [`12-pack-format.md`](12-pack-format.md) defines how a backend stores
  content and how `get` with a range resolves inside a pack.
- [`13-bucket-layout.md`](13-bucket-layout.md) and
  [`16-blockdev-backend.md`](16-blockdev-backend.md) define the two authority
  backends.
- [`14-host-tier.md`](14-host-tier.md) defines `disk` and the eviction rules
  `cache` applies.
- [`15-redundancy.md`](15-redundancy.md) defines `replicated` and `striped`.
- [`17-garbage-collection.md`](17-garbage-collection.md) is the only path by
  which content leaves an authority.
- [`18-protocol.md`](18-protocol.md) is the wire form of this interface and
  what `remote` speaks.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) supplies the
  cost model that orders `routed` reads.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  defines the policy that `guard` enforces.

## Informative: why the interface is this small

Every design that puts a database beside an object store does so to hold
one of three things: where a chunk lives, how many references it has, or
what a name currently points at. The first is answered by self-describing
packs and their indexes, the second by mark-and-sweep garbage collection
with a grace window, and the third by conditional writes that object stores
now provide natively. With those three needs met inside the bucket, the
interface has nothing left to add, and every backend that can do idempotent
puts, ranged gets, and one conditional write can be an authority. See
[`39-decision-register.md`](39-decision-register.md) for the decision to
require conditional writes rather than an external coordinator.
