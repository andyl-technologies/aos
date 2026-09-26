# RFC-0024: Terrane — a distributed, content-addressed, branchable filesystem

- **Status:** Proposed (design-only)
- **Date:** 2026-09-25
- **Audience:** maintainers of the sandbox runtime, AOS Hub storage, Crucible,
  the Rust workspace, release and cache infrastructure, and anyone who needs a
  content-addressed store with filesystem views.
- **Specification:** [`spec/README.md`](spec/README.md) — the self-contained
  Terrane Specification, written to stand on its own and to be lifted into a
  separate repository without change.
- **AOS integration:** [`integration/`](integration/) — how AOS adopts Terrane:
  sandbox runtime slots, Hub storage, Crucible, packaging, and the phased
  implementation plan.
- **Relates to:** [RFC-0021](../0021-sandbox-runtime/README.md) (sandbox
  runtime and filesystem views), [RFC-0010](../0010-crucible/README.md)
  (Crucible and `crucible-cas`), [RFC-0004](../0004-registry-hub/README.md),
  [RFC-0012](../0012-hub-surface-topology/README.md), and
  [RFC-0023](../0023-hub-hybrid-topology/README.md) (AOS Hub storage and
  topology), [RFC-0005](../0005-ca-trust-map.md) (content-addressed closure
  validation), [RFC-0015](../0015-hermetic-cargo-artifacts.md) (Rust
  packaging), [RFC-0019](../0019-oci-containers/README.md) (OCI images).

RFC-0021 and RFC-0023 are on their own branches at the time of writing
(PR #232 and PR #374); their links above resolve once those land.

## Summary

Terrane is a content-addressed chunk store with a filesystem namespace that
behaves like a version-control branch. Bytes live in an object store (S3, GCS,
R2, a local filesystem, or raw block devices) with no database beside it. A
namespace is a persistent Merkle tree keyed by path; a view of it is a ref to
a commit; forking, merging, snapshotting, diffing, and set operations on whole
filesystems cost time proportional to what changed. Every host runs the same
binary, `terrane`, configured as a warehouse gateway, a node-local cache and
mounter, a nested cache inside a sandbox or VM, or an edge worker, and the
tiers compose so that a chunk is never stored twice on one machine.

The specification is deliberately independent of AOS. Terrane is to AOS what
ZFS is to FreeBSD: a storage system that AOS adopts, integrates, and packages,
but which has its own model, formats, protocol, and conformance levels. The
AOS-specific parts of this RFC are confined to [`integration/`](integration/).

## Motivation

AOS needs one storage substrate for several workloads that today would each
get their own:

- **Sandbox filesystem views** (RFC-0021) need an unprivileged view service
  that materializes immutable trees lazily, shares page cache across sandboxes,
  seals backing files, and never duplicates bytes between nested tiers.
- **Build and CI caches** (Nix binary caches, Bazel remote caches, GitHub
  Actions caches) need untrusted jobs to read everything a trusted baseline
  has, write results visible only to themselves, and have those results folded
  into the baseline on merge without copying anything.
- **AOS Hub** needs registry, binary-cache, and OCI storage on R2 that can be
  served from a WebAssembly worker and from native hosts alike.
- **Crucible** needs deterministic, snapshot-able VM disks and campaign state
  with content-addressed identity.

Each of these is a filesystem namespace over content-addressed bytes with
branch semantics. Terrane provides exactly that once, with a closed set of
concepts: five nouns (chunk, object, tree, commit, ref), one storage trait,
one wire protocol, and one way to expose a tree (a surface).

## Reading order

1. [`spec/01-goals-nongoals-invariants.md`](spec/01-goals-nongoals-invariants.md)
   and [`spec/03-architecture-overview.md`](spec/03-architecture-overview.md)
   for the shape of the system.
2. [`spec/04-content-model.md`](spec/04-content-model.md) through
   [`spec/10-derived-data.md`](spec/10-derived-data.md) for the model.
3. [`spec/11-store-trait.md`](spec/11-store-trait.md) through
   [`spec/17-garbage-collection.md`](spec/17-garbage-collection.md) for
   storage.
4. [`spec/18-protocol.md`](spec/18-protocol.md) through
   [`spec/25-threat-model.md`](spec/25-threat-model.md) for distribution and
   security.
5. [`spec/26-surfaces.md`](spec/26-surfaces.md) through
   [`spec/31-routing-rulesets.md`](spec/31-routing-rulesets.md) for how trees
   are exposed.
6. [`integration/`](integration/) for what AOS builds first.

## Index

### Specification

The full index, conformance levels, and versioning policy are in
[`spec/README.md`](spec/README.md).

### Integration

| File | Contents |
| --- | --- |
| [`integration/01-sandbox-runtime.md`](integration/01-sandbox-runtime.md) | RFC-0021 slots: the view service, mount broker, publisher, attachments, disclosure domains |
| [`integration/02-hub.md`](integration/02-hub.md) | AOS Hub on Terrane: R2 as a bucket, registry and OCI surfaces, the console |
| [`integration/03-packaging.md`](integration/03-packaging.md) | Nix packaging, systemd units and roles, `aos-dev` targets, workspace crates |
| [`integration/04-crucible.md`](integration/04-crucible.md) | Crucible disks and campaign state on Terrane; the `crucible-cas` seam |
| [`integration/05-implementation-plan.md`](integration/05-implementation-plan.md) | Phased task plan with requirement coverage |
| [`integration/06-decision-register.md`](integration/06-decision-register.md) | AOS-specific decisions (naming, ownership, sequencing) |

## Status notes

This RFC is design-only. No Terrane code exists in the tree at the time of
writing. The specification's own status and version are tracked in
[`spec/README.md`](spec/README.md) independently of this RFC's status, because
AOS adoption and specification maturity will move at different speeds.
