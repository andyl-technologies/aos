# Terrane Specification

- **Version:** 1.0-draft-1
- **Status:** Draft
- **Date:** 2026-09-25

Terrane is a content-addressed chunk store with a filesystem namespace that
composes like a version-control branch. This document set is the normative
specification. It is self-contained: it does not depend on, and does not
reference, any particular host operating system, build system, or product.
Adapters for public protocols (Nix binary caches, the Remote Execution API,
OCI Distribution, git, HTTP) are specified as surfaces because those protocols
are public. Integration with a specific operating system belongs outside this
directory.

## Abstract

A Terrane store holds five kinds of things. **Chunks** are content-defined
slices of bytes. **Objects** are ordered lists of chunks that make up a file.
**Trees** are persistent, history-independent Merkle maps from path to entry.
**Commits** bind a tree root to its parents and provenance. **Refs** name
commits and are the only mutable state. All five live in an object store
(an S3- or GCS-compatible bucket, a local filesystem, or raw block devices)
with no database beside it; refs change only by conditional write.

A **view** is a ref or commit together with policy. A **surface** exposes a
view through a kernel interface (FUSE, EROFS and overlayfs, a block device,
virtiofs) or a protocol (the Terrane wire protocol, Nix binary cache, REAPI,
OCI, git, HTTP). Stores compose into ordered, cost-routed **tiers**, so the
same program serves as a bucket gateway, a node-local cache and mounter, a
nested cache inside a sandbox or virtual machine, or an edge worker, and a
chunk visible from a lower tier is never stored again in a higher one.

Trees support graft, split, overlay, diff, three-way merge, filter, and map
in time proportional to the difference between inputs. Forking a namespace
costs one ref write; folding a fork back costs a merge of what changed.
Garbage collection is mark-and-sweep from refs with a grace window and needs
no reference counts. Redundancy, locality, consistency, durability, trust,
and access control are all properties on subtree roots that inherit downward.

## Conformance levels

An implementation claims one or more levels. Each level names the files whose
`MUST` requirements it satisfies.

| Level | Meaning | Files |
| --- | --- | --- |
| **Core** | Reads and writes a Terrane store in a bucket or on a filesystem: formats, chunking, trees, commits, refs, packs, bucket layout, GC roots | 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 17 |
| **Distribution** | Serves and consumes the wire protocol, tiers stores, honors topology and consistency modes | Core + 18, 19, 20, 21 |
| **Security** | Enforces capability tokens, provenance, trust selectors, disclosure domains | Core + 22, 23, 24, 25 |
| **Host** | Runs a node-local tier with sealed backing objects and eviction | Core + Distribution + 14 |
| **Redundant** | Replicated and striped stores, block-device backend | Core + 15, 16 |
| **Surface: `<name>`** | One named surface from the surface registry | Core + 26 + the surface's file |
| **Operations** | Tree jobs, migrations, observability, performance targets | Core + 32, 33, 34, 35 |

Every level requires [`36-testing-and-conformance.md`](36-testing-and-conformance.md)
for the gates it names.

## Index

### Front matter

| File | Prefix | Contents |
| --- | --- | --- |
| [`00-conventions.md`](00-conventions.md) | `CONV` | Normative keywords, requirement IDs, gates, document rules |
| [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) | `G`, `NG`, `INV` | Goals, non-goals, and the invariants everything else preserves |
| [`02-glossary.md`](02-glossary.md) | | Vocabulary |
| [`03-architecture-overview.md`](03-architecture-overview.md) | `ARCH` | Layers, the store trait, the protocol, read and write walk-throughs |

### Part I — Model

| File | Prefix | Contents |
| --- | --- | --- |
| [`04-content-model.md`](04-content-model.md) | `OBJ` | Chunk, object, tree, commit, ref; identity and digest domains |
| [`05-chunking.md`](05-chunking.md) | `CDC` | Content-defined chunking parameters, validation, compression |
| [`06-tree-format.md`](06-tree-format.md) | `TREE` | Prolly tree structure, boundary function, node and entry encoding |
| [`07-tree-algebra.md`](07-tree-algebra.md) | `ALG` | Graft, split, flatten, overlay, diff, merge, filter, map; recipes |
| [`08-properties.md`](08-properties.md) | `PROP` | Inherited properties on roots; completeness |
| [`09-refs-and-commits.md`](09-refs-and-commits.md) | `REF` | Branches, tags, reflog, commit objects, epochs, conditional writes |
| [`10-derived-data.md`](10-derived-data.md) | `DRV` | Per-object attributes, index trees, classification |

### Part II — Storage

| File | Prefix | Contents |
| --- | --- | --- |
| [`11-store-trait.md`](11-store-trait.md) | `STORE` | The store interface, backends, combinators, store expressions |
| [`12-pack-format.md`](12-pack-format.md) | `PACK` | Pack layout, indexes, filters, meta packs |
| [`13-bucket-layout.md`](13-bucket-layout.md) | `BKT` | Object-store key layout and conditional-write requirements |
| [`14-host-tier.md`](14-host-tier.md) | `HOST` | Node-local cache, sealed objects, eviction, pins, wipe |
| [`15-redundancy.md`](15-redundancy.md) | `RED` | Replication, striping with parity, placement, scrub, resilver |
| [`16-blockdev-backend.md`](16-blockdev-backend.md) | `BLK` | Raw block-device backend |
| [`17-garbage-collection.md`](17-garbage-collection.md) | `GC` | Roots, mark, sweep, grace, compaction |

### Part III — Distribution

| File | Prefix | Contents |
| --- | --- | --- |
| [`18-protocol.md`](18-protocol.md) | `PROTO` | Wire protocol, negotiation, bulk reads, watch, versioning |
| [`19-tiering-and-topology.md`](19-tiering-and-topology.md) | `TOPO` | Locality, cost routing, peers, residency, warming |
| [`20-consistency.md`](20-consistency.md) | `CONS` | Consistency model, writer and reader modes, durability, fencing |
| [`21-bandwidth.md`](21-bandwidth.md) | `BW` | Delta negotiation, wire deltas, dictionaries |

### Part IV — Security

| File | Prefix | Contents |
| --- | --- | --- |
| [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md) | `AUTH` | Capability tokens, grants, enforcement |
| [`23-provenance-and-trust.md`](23-provenance-and-trust.md) | `PROV` | Signed commits, entry provenance, trust selectors |
| [`24-disclosure-domains.md`](24-disclosure-domains.md) | `DOM` | Domains, cross-domain references, dedup scoping |
| [`25-threat-model.md`](25-threat-model.md) | `THREAT` | Adversaries, attack surfaces, mitigations |

### Part V — Surfaces

| File | Prefix | Contents |
| --- | --- | --- |
| [`26-surfaces.md`](26-surfaces.md) | `SURF` | The surface interface, schemas, exposures, plugins |
| [`27-surface-fuse.md`](27-surface-fuse.md) | `FUSE` | FUSE surface with passthrough |
| [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) | `EROFS`, `VBLK` | EROFS and overlayfs surface; block-device surface |
| [`29-surface-vm.md`](29-surface-vm.md) | `VM` | virtiofs and nested tiers in guests |
| [`30-surface-protocols.md`](30-surface-protocols.md) | `NIX`, `REAPI`, `GHA`, `GIT`, `OCI`, `WEB` | Protocol surfaces |
| [`31-routing-rulesets.md`](31-routing-rulesets.md) | `RULE` | Closed-vocabulary match-to-action rulesets |

### Part VI — Operations

| File | Prefix | Contents |
| --- | --- | --- |
| [`32-tree-jobs.md`](32-tree-jobs.md) | `JOB` | Sharded, resumable, incremental jobs over trees |
| [`33-migrations.md`](33-migrations.md) | `MIG` | Imports, layout, format, parameter, and bucket migrations |
| [`34-observability.md`](34-observability.md) | `OBS` | Logs, traces, status, completeness |
| [`35-performance-targets.md`](35-performance-targets.md) | `PERF` | Budgets and the gates that measure them |
| [`36-testing-and-conformance.md`](36-testing-and-conformance.md) | `TEST` | Gates, golden vectors, conformance suites |

### Part VII — Engineering

| File | Prefix | Contents |
| --- | --- | --- |
| [`37-crate-structure.md`](37-crate-structure.md) | `CRATE` | Crate layering, `no_std` boundary, features, `unsafe` policy |
| [`38-wasm-and-edge.md`](38-wasm-and-edge.md) | `EDGE` | WebAssembly targets and edge deployments |
| [`39-decision-register.md`](39-decision-register.md) | `D` | Load-bearing decisions and their rationale |
| [`40-risks-and-open-questions.md`](40-risks-and-open-questions.md) | `RISK` | Risks, validation spikes, open questions |

### Reference

| File | Contents |
| --- | --- |
| [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl) | Canonical CDDL for every encoded object |
| [`reference/protocol.md`](reference/protocol.md) | Wire schema for the protocol |
| [`reference/golden-vectors.md`](reference/golden-vectors.md) | Byte-exact test vectors |
| [`reference/property-registry.md`](reference/property-registry.md) | Registered properties |
| [`reference/surface-registry.md`](reference/surface-registry.md) | Registered surfaces and their schemas |
| [`reference/bucket-key-registry.md`](reference/bucket-key-registry.md) | Registered bucket key prefixes |
| [`reference/errno-mapping.md`](reference/errno-mapping.md) | How outcomes reach POSIX callers |
| [`reference/prior-art.md`](reference/prior-art.md) | Informative survey of prior systems and theory |
| [`reference/comparisons.md`](reference/comparisons.md) | Informative comparisons with ZFS, git, and a predecessor system |

## Versioning

The specification version is `MAJOR.MINOR-draft-N` until 1.0 is published.
Any change to bytes on the wire or at rest, or to the identity of any object,
requires a new media-type version for the affected object and a `MINOR`
increment. Adding a surface, property, or backend that does not change
existing identities is a `MINOR` increment. Requirement IDs are never reused.
