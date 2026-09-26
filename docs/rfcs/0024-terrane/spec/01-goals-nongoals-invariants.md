# 01 — Goals, non-goals, and invariants

This file states what Terrane is for, what it deliberately is not, and the
small set of invariants that every other file preserves. A reader who
understands the invariants can predict how any later file resolves a design
question; a later file that would violate one is wrong, not the invariant.

## Overview

Terrane exists because several workloads that look different are the same
problem: a filesystem namespace over content-addressed bytes, with the
ability to fork the namespace, write into the fork, and fold the fork back
without copying. Build caches, sandbox root filesystems, registry storage,
virtual-machine disks, and CI artifact stores all fit that description. The
goals below say what a system that solves it once must do; the non-goals say
where it stops; the invariants say what it never trades away.

## Goals

- **[G-1]** A Terrane store MUST be operable with an object store as its only
  durable dependency. An S3- or GCS-compatible bucket with conditional
  writes, a local filesystem, or a set of raw block devices is sufficient to
  hold every chunk, object, tree, commit, ref, index, and garbage-collection
  record. No database, coordination service, cache service, or message queue
  is required for correctness. *See:* [`13-bucket-layout.md`](13-bucket-layout.md),
  [`17-garbage-collection.md`](17-garbage-collection.md).
- **[G-2]** A namespace MUST behave like a version-control branch. Forking a
  namespace, committing into the fork, tagging a snapshot, diffing two
  namespaces, and merging one namespace into another MUST cost time
  proportional to the difference between the inputs, never to their size.
  *See:* [`07-tree-algebra.md`](07-tree-algebra.md),
  [`09-refs-and-commits.md`](09-refs-and-commits.md).
- **[G-3]** Namespaces MUST compose. A root MAY be grafted beneath another
  root by reference, split out again, overlaid with precedence, filtered,
  and transformed, and the result MUST be a namespace with the same
  guarantees as its inputs. *See:* [`07-tree-algebra.md`](07-tree-algebra.md).
- **[G-4]** Bytes MUST NOT be stored more than once on a machine because of
  Terrane's own tiering. A tier that can read a chunk from a tier beneath it
  MUST serve that chunk without keeping a copy. Nested instances inside
  sandboxes and virtual machines are the motivating case. *See:*
  [`11-store-trait.md`](11-store-trait.md), [`14-host-tier.md`](14-host-tier.md),
  [`29-surface-vm.md`](29-surface-vm.md).
- **[G-5]** One program MUST serve every role. A bucket gateway, a node-local
  cache and mounter, a nested cache inside a sandbox or guest, a garbage
  collector, and an edge worker differ only in configuration and, where a
  target lacks an operating system feature, in which surfaces are compiled
  in. *See:* [`03-architecture-overview.md`](03-architecture-overview.md),
  [`37-crate-structure.md`](37-crate-structure.md),
  [`38-wasm-and-edge.md`](38-wasm-and-edge.md).
- **[G-6]** The specification and its reference implementation MUST be
  independent of any host operating system, build system, or product. Public
  protocols are adapted through surfaces; private integrations live outside
  this specification. *See:* [`00-conventions.md`](00-conventions.md) CONV-2,
  [`26-surfaces.md`](26-surfaces.md).
- **[G-7]** Every read of content MUST be verifiable by the reader from the
  identity it asked for, without trusting the tier that served it. *See:*
  [`04-content-model.md`](04-content-model.md), [`14-host-tier.md`](14-host-tier.md).
- **[G-8]** Untrusted writers MUST be able to use a store safely. A writer
  holding authority over one branch MUST be unable to affect any other
  branch, any other writer's view, or the integrity of shared content.
  *See:* [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md),
  [`23-provenance-and-trust.md`](23-provenance-and-trust.md),
  [`25-threat-model.md`](25-threat-model.md).
- **[G-9]** The hot read path MUST be served by the operating system's page
  cache from a single physical copy shared by every consumer on a host, and
  the cold read path MUST be bounded by object-store latency amortized over
  many chunks, not by per-chunk round trips to a service. *See:*
  [`14-host-tier.md`](14-host-tier.md), [`18-protocol.md`](18-protocol.md),
  [`35-performance-targets.md`](35-performance-targets.md).
- **[G-10]** Redundancy, locality, durability, consistency, trust, retention,
  and access control MUST be expressible as properties on subtree roots that
  inherit downward, so that one namespace can span storage classes without
  special cases in readers. *See:* [`08-properties.md`](08-properties.md).
- **[G-11]** Every long-running operation over a tree — garbage-collection
  marking, scrubbing, backfilling derived attributes, reindexing,
  compaction, warming, and user workloads — MUST use the same sharded,
  resumable, incremental iteration primitive. *See:* [`32-tree-jobs.md`](32-tree-jobs.md).
- **[G-12]** The core formats and algorithms MUST compile without an
  operating system (`no_std` with an allocator) so that readers and small
  writers can run in WebAssembly and embedded contexts. *See:*
  [`37-crate-structure.md`](37-crate-structure.md),
  [`38-wasm-and-edge.md`](38-wasm-and-edge.md).

## Non-goals

- **[NG-1]** Terrane is not a live, shared-writable POSIX filesystem. Writes
  land in a private upper that is local to one exposure and become visible
  to others only at a commit. Locks, sub-commit durability of in-progress
  writes, and record-granular concurrent modification of one namespace by
  several writers are provided by the host filesystem beneath the upper, not
  by Terrane. Workloads that need shared mutable state below commit
  granularity use a native live mount outside Terrane. *See:*
  [`20-consistency.md`](20-consistency.md).
- **[NG-2]** Terrane is not a job executor. It specifies how a job iterates,
  checkpoints, and follows a tree; it does not schedule, place, isolate, or
  supervise the job's process. *See:* [`32-tree-jobs.md`](32-tree-jobs.md).
- **[NG-3]** Terrane 1.0 is not a general-purpose local filesystem and does
  not replace a host filesystem for root volumes, databases, swap, or
  write-heavy interactive use. The private upper is a directory on a host
  filesystem. This is a boundary of 1.0, not of the design: a native
  mutable working tree (a log-structured, chunk-backed upper whose `fsync`
  is a small commit and whose write-ahead log plays the role of an intent
  log) is compatible with every invariant below and MAY be specified in a
  later version. Nothing in 1.0 may preclude it. *See:*
  [`40-risks-and-open-questions.md`](40-risks-and-open-questions.md).
- **[NG-4]** Terrane does not provide sub-commit consistency across regions.
  A ref has one home; readers elsewhere see a bounded-stale copy unless they
  ask home. *See:* [`19-tiering-and-topology.md`](19-tiering-and-topology.md),
  [`20-consistency.md`](20-consistency.md).
- **[NG-5]** Terrane does not define an identity provider, a group directory,
  or a relation-graph authorization service. It consumes signed identity
  claims and evaluates grants against properties stored in the tree. *See:*
  [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md).
- **[NG-6]** Terrane does not provide byte-compatible git repositories. It
  adopts git's ref layout, commit graph, and vocabulary because they are the
  right model, and it can project a view as a git tree through a surface,
  but it does not store git's object encoding. *See:*
  [`30-surface-protocols.md`](30-surface-protocols.md),
  [`reference/comparisons.md`](reference/comparisons.md).
- **[NG-7]** Terrane does not provide block-granular copy-on-write. Its unit
  of sharing is the content-defined chunk. Small random overwrites in an
  upper cost a rechunk of the affected file at commit. *See:*
  [`05-chunking.md`](05-chunking.md).
- **[NG-8]** Terrane does not own disks in 1.0's Core level. Durability and
  redundancy of a bucket or host filesystem are that backend's concern; the
  Redundant level adds Terrane-managed replication and raw-device storage
  on top of the same interface. *See:* [`15-redundancy.md`](15-redundancy.md),
  [`16-blockdev-backend.md`](16-blockdev-backend.md).

## Invariants

These six statements hold in every conforming implementation at every level.
Each later file cites the invariant it depends on rather than restating it.

- **[INV-1] Immutables are idempotent and identified by their bytes.** Every
  chunk, object manifest, tree node, commit, bundle, pack, and index is
  identified by a hash over a registered type domain and its encoded bytes.
  Writing an immutable twice is a no-op; two immutables with the same
  identity are the same bytes. No immutable is ever rewritten. *Gate:*
  `gate:identity-idempotence`. *See:* [`04-content-model.md`](04-content-model.md).
- **[INV-2] Only refs mutate, only by conditional write, only at the tier
  that owns them.** A ref changes by compare-and-swap against the value the
  writer last observed, or by create-if-absent for a new ref or log entry,
  and only at its authority. Every other tier caches refs and forwards
  writes. There is no other mutable state in a store. *Gate:*
  `gate:ref-cas-only`. *See:* [`09-refs-and-commits.md`](09-refs-and-commits.md),
  [`11-store-trait.md`](11-store-trait.md).
- **[INV-3] Commit order is packs, then indexes, then the ref; nothing
  younger than the grace window is collected.** A writer makes every pack a
  commit depends on durable, then every index for those packs, and only then
  writes the ref. Garbage collection treats every ref and retained log entry
  as a root, marks reachable content, and sweeps only unmarked content whose
  age exceeds a grace window that is strictly longer than the maximum
  permitted commit duration. A writer aborts a commit that would outlive the
  window. *Gate:* `gate:commit-order`, `gate:gc-grace`. *See:*
  [`17-garbage-collection.md`](17-garbage-collection.md).
- **[INV-4] A tier never stores what a tier it can see already serves.** If
  a store in a tiered list can read content from another store in the same
  list that it is configured to consider shared (a shared directory, a
  mapped device, or a peer with a residency guarantee), it MUST NOT admit a
  second copy of that content. New content a tier produces is staged
  privately and promoted downward, never copied upward. *Gate:*
  `gate:no-duplicate-tiers`. *See:* [`11-store-trait.md`](11-store-trait.md),
  [`14-host-tier.md`](14-host-tier.md).
- **[INV-5] A view's identity never includes how it is realized.** The
  identity of a view is a commit (or a ref resolved to one), an optional
  subtree, and the policy that filters it. Which surface exposes it, on
  which endpoint, with which kernel mechanism, and with which caches warm,
  is status, never identity. Two exposures of the same view on different
  surfaces present the same namespace. *Gate:* `gate:view-identity`. *See:*
  [`26-surfaces.md`](26-surfaces.md).
- **[INV-6] Foreign protocols enter through the repository layer, never the
  store.** A surface that speaks another protocol translates it into
  repository operations — resolve a view, read entries and content, commit
  — and inherits authorization, trust filtering, tiering, and topology by
  construction. No surface reads or writes packs, indexes, or refs directly.
  *Gate:* `gate:surface-layering`. *See:*
  [`03-architecture-overview.md`](03-architecture-overview.md),
  [`26-surfaces.md`](26-surfaces.md).

## Interactions

- [`03-architecture-overview.md`](03-architecture-overview.md) shows how the
  layers realize the invariants.
- [`04-content-model.md`](04-content-model.md) defines the identities INV-1
  relies on.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) and
  [`13-bucket-layout.md`](13-bucket-layout.md) define the conditional-write
  protocol INV-2 relies on and the backend requirements it imposes.
- [`17-garbage-collection.md`](17-garbage-collection.md) defines the grace
  window and ordering of INV-3.
- [`11-store-trait.md`](11-store-trait.md) and [`14-host-tier.md`](14-host-tier.md)
  define the shared-tier rule of INV-4.
- [`26-surfaces.md`](26-surfaces.md) defines the exposure model of INV-5 and
  INV-6.
- [`36-testing-and-conformance.md`](36-testing-and-conformance.md) defines
  the gates named here.

## Informative: how to use this file

When a later file must choose between two designs, the choice that keeps a
goal and an invariant wins over the choice that keeps only a goal. When two
goals conflict, [`39-decision-register.md`](39-decision-register.md) records
which one gave way and why. A proposal that requires weakening an invariant
is a proposal for a new major version.
