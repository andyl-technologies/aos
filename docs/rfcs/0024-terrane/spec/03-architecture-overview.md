# 03 — Architecture overview

This file describes the shape of a Terrane implementation: five layers, one
storage interface, one wire protocol, and the process model that runs them.
It is the map for every later file; it defines no format and few
requirements of its own beyond the layering rules that keep the map true.

## Overview

Terrane is five nouns, one trait, and one protocol. Everything else is
composition.

The five nouns — chunk, object, tree, commit, ref — are defined in
[`04-content-model.md`](04-content-model.md). The first four are immutable
and content-addressed; the fifth is the only mutable thing and changes only
by conditional write ([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)
INV-1, INV-2).

The one interface is the **store**, in two halves: `ContentStore` (put and
get of immutable content by identity, batched existence checks) and
`RefStore` (get, compare-and-swap, and log operations on refs). Every
backend implements one or both, every combinator takes stores and returns a
store, and every boundary between tiers speaks the same interface over the
wire. Which half a child implements is what makes it a cache or an
authority. It is defined in [`11-store-trait.md`](11-store-trait.md).

The one protocol is the wire form of that trait plus presigned bulk reads
so that bytes bypass any service. It is defined in [`18-protocol.md`](18-protocol.md).

## Layers

```text
   formats     chunker · prolly tree · commit · canonical encoding
      │        pure functions, no I/O, no operating system
      │
    store      the store trait · backends · combinators
      │        bytes in, bytes out; knows nothing of trees
      │
 repository    refs · commits · diff · merge · transform · GC · jobs
      │        version-control verbs over a store
      │
  surfaces     erofs · fuse · virtiofs · block · protocols · API
      │        a view becomes a filesystem or a service
      │
    roles      serve · realize · fuse-worker · publish · gc
               processes composing the layers, selected by configuration
```

Each layer has one job and reaches down exactly one layer.

- **Formats** ([`04`](04-content-model.md), [`05`](05-chunking.md),
  [`06`](06-tree-format.md), [`07`](07-tree-algebra.md), [`09`](09-refs-and-commits.md))
  are pure: chunking, hashing, tree construction, diff, merge, and encoding
  are functions from bytes to bytes.
- **Store** ([`11`](11-store-trait.md) through [`17`](17-garbage-collection.md))
  moves immutable bytes and performs ref operations. It does not know what a
  tree is.
- **Repository** ([`07`](07-tree-algebra.md), [`08`](08-properties.md),
  [`09`](09-refs-and-commits.md), [`10`](10-derived-data.md),
  [`17`](17-garbage-collection.md), [`32`](32-tree-jobs.md)) implements the
  version-control verbs — resolve, fork, commit, merge, tag, diff, fold —
  and policy evaluation over a store. It does not know what a mount is.
- **Surfaces** ([`26`](26-surfaces.md) through [`31`](31-routing-rulesets.md))
  expose a view. A surface reads and writes through repository verbs only.
- **Roles** are processes. A role is a configuration that selects a store
  expression, a set of exposures, and a set of background tasks.

- **[ARCH-1]** The formats layer MUST NOT perform I/O and MUST NOT depend on
  an operating system. *Gate:* `gate:formats-no-std`. *See:*
  [`37-crate-structure.md`](37-crate-structure.md).
- **[ARCH-2]** The store layer MUST NOT interpret the content it stores
  beyond the type tag needed to route meta objects and data chunks to their
  packs. It MUST NOT parse tree nodes, commits, or manifests. *Gate:*
  `gate:store-opaque`.
- **[ARCH-3]** A surface MUST perform every read and write through the
  repository layer. It MUST NOT call the store layer directly. This is
  INV-6. *Gate:* `gate:surface-layering`.
- **[ARCH-4]** The repository layer MUST NOT depend on any surface or on any
  operating-system mount facility. *Gate:* `gate:repository-portable`.
- **[ARCH-5]** Every boundary between processes or hosts MUST be the wire
  protocol of [`18-protocol.md`](18-protocol.md) or a registered surface.
  There is no second private protocol between tiers. *Gate:*
  `gate:one-protocol`.

## Store composition

A deployment is a store expression: backends and combinators arranged as a
tree. The expression grammar is in [`11-store-trait.md`](11-store-trait.md);
the examples below show the shape.

```text
warehouse:  guard(bucket(s3://…))
host:       routed[disk(/var/lib/terrane), remote(warehouse-a), remote(warehouse-b)]
nested:     routed[shared-dir(/objects), remote(host)]
edge:       guard(bucket(r2://…))
```

Reads walk a routed list in cost order; batched existence checks let a tier
answer for many identities at once; writes go to the authority, the one
child that implements `RefStore`, and write through to caches by policy. A `shared-dir` backend answers reads from
a directory another tier owns and never admits content of its own, which is
how INV-4 is realized in the common case.

- **[ARCH-6]** A store expression MUST be fully described by configuration.
  An instance MUST NOT change the shape of its expression at runtime except
  through a configuration reload that is itself logged. *Gate:*
  `gate:store-expression-static`.

## A read, end to end

```text
open("/lib/libfoo.so") on a FUSE exposure
  surface:     index lookup in the mapped tree index      local memory
               → entry → object id, chunk list
  repository:  resolve content through the view's policy  local
  store:       routed.get(chunk ranges)                    shared-dir? disk? peer? bucket?
               first tier that has them wins; ranges coalesced per pack
  surface:     assemble into a sealed object, register     one inode
               passthrough; the kernel serves pages
```

Metadata never blocks a read: the tree for a view is bundled ahead of the
exposure and mapped locally ([`12-pack-format.md`](12-pack-format.md),
[`27-surface-fuse.md`](27-surface-fuse.md)). Only content faults reach the
store, and those reach a bucket as coalesced ranged reads, not as per-chunk
service calls ([`18-protocol.md`](18-protocol.md),
[`21-bandwidth.md`](21-bandwidth.md)).

## A write, end to end

```text
commit(view)
  surface:     walk the upper                              changed paths only
  formats:     chunk, hash, build new tree nodes           O(changed entries)
  store:       has(chunks) → upload residue as packs       filters first, then one batch
               → per-pack index
  repository:  build commit → ref_cas(refs/heads/<view>, observed, new)
```

A fold into a parent branch is the same sequence with a three-way merge
between the tree step and the commit step
([`07-tree-algebra.md`](07-tree-algebra.md)). The ordering in the store step
is INV-3 and is not optional.

## Process model on a host

A host runs one binary in several processes, each with the least authority
its job needs. The names below are roles; an adopting system maps them onto
its service manager.

| Role | Authority | Network | Owns |
| --- | --- | --- | --- |
| `serve` | unprivileged | yes | the routed store, the repository, protocol and API exposures, presigned reads, filters, bundles |
| `realize` | unprivileged | no | realizer exposures: builds tree indexes, requests sealed objects, requests mounts from the broker |
| `fuse-worker` | unprivileged, one per exposure | no | one FUSE connection; asks `serve` for backing handles; never fetches |
| `publish` | unprivileged, distinct identity | no | the sealed object directory; the only writer to it |
| `gc` | unprivileged | yes | marking, sweeping, compaction, scrubbing, under a singleton lease |
| mount broker | privileged | no | mount syscalls; supplied by the host system, not by Terrane |

- **[ARCH-7]** A FUSE worker MUST NOT hold network credentials or open
  network connections. A content miss in a worker MUST be requested from the
  `serve` role over a local socket. *Gate:* `gate:worker-no-network`.
- **[ARCH-8]** Only the `publish` role MAY create, rename, or seal entries in
  the sealed object directory. Every other role receives read-only
  descriptors. *Gate:* `gate:publisher-sole-writer`. *See:*
  [`14-host-tier.md`](14-host-tier.md).
- **[ARCH-9]** Terrane roles MUST NOT perform privileged mount-namespace
  operations. A realizer requests them from a host-supplied broker over a
  local socket with passed descriptors, and the broker verifies what it
  mounts. *Gate:* `gate:no-privileged-mounts`. *See:*
  [`27-surface-fuse.md`](27-surface-fuse.md), [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md).
- **[ARCH-10]** Roles MUST be selectable by configuration of one program.
  A role MAY be absent from a build for a target that cannot support it
  (for example, realizers in WebAssembly) and MUST then fail at
  configuration time with a message naming the missing surface. *Gate:*
  `gate:role-selection`.
- **[ARCH-11]** Freezing, stopping, or killing a consumer of an exposure MUST
  NOT stop the process serving that exposure; workers run outside consumer
  control groups. *See:* [`27-surface-fuse.md`](27-surface-fuse.md).

## Deployment shapes

The same binary and the same configuration grammar produce every
deployment. Nothing above the store layer changes between them.

- **Warehouse.** `serve` in front of a bucket, stateless, scaled by adding
  replicas. Adds authorization through `guard`, upload validation at the
  store, presigned reads, index caching, and the `gc` role under a lease. Zero bytes of data pass through
  it on the read path.
- **Host.** `serve`, `realize`, workers, and `publish` over a routed store of
  local disk plus one or more warehouses in priority order.
- **Nested.** The same inside a sandbox or guest, with a `shared-dir` or
  mapped-device tier over the host's sealed object directory and a `remote`
  tier pointing at the host's `serve` role. Stores no chunk bytes of its own
  when the shared tier is present.
- **Edge.** `serve` compiled to WebAssembly with a bucket backend and
  protocol surfaces only; reads and small commits.
- **Warehouse and host on one machine.** `routed[disk, bucket]` with no
  network hop; the `serve` role exposes the protocol for nested instances.

## Interactions

- [`11-store-trait.md`](11-store-trait.md) defines the trait and expression
  grammar this file sketches.
- [`18-protocol.md`](18-protocol.md) defines the one protocol.
- [`26-surfaces.md`](26-surfaces.md) defines exposures and the surface
  interface.
- [`14-host-tier.md`](14-host-tier.md) defines the sealed object directory
  the `publish` role owns.
- [`37-crate-structure.md`](37-crate-structure.md) maps layers to crates and
  enforces ARCH-1 through ARCH-4 by dependency direction.

## Informative: why one trait and one protocol

A store that is also a client of another store is what lets tiers nest to
any depth, lets a host be a warehouse for its guests, and lets an edge
worker and a fleet share one bucket. Any second interface between tiers
would have to be maintained for every backend and every combinator; a single
trait means a combinator written once composes with every backend that will
ever exist. [`39-decision-register.md`](39-decision-register.md) records the
alternatives considered.
