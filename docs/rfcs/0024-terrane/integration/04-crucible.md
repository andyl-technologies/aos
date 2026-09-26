# 04 — Crucible on Terrane

This file describes how Crucible (RFC-0010) and Crucible campaigns
(RFC-0020, branch `dplecki/crucible-campaigns`, PR #194) consume Terrane:
campaign state, corpora, checkpoints, and disk objects as trees and commits;
deterministic VM disks through the block surface; and the `crucible-cas`
seam. It also states the licensing rule that keeps Terrane on the Apache
side of the Crucible/QEMU boundary.

Requirement IDs use the prefix `CRU`.

## The seam Crucible already defines

`crates/crucible-cas` (RFC-0010 file 35) owns BLAKE3 content keys, a minimal
`DagStore` with `put`, `get`, and `has`, memory and local implementations, a
flock-based `SharedDagStore`, and a dependency-gated `InvalidationQuery`. Its
crate header names the exact seam a shared substrate must adapt behind:

```text
FUTURE_RATCHET_SEAM_INTERFACE =
  "DagStore::put,DagStore::get,DagStore::has,SharedDagStore,InvalidationQuery::evaluate"
FUTURE_RATCHET_MERGE_BAR =
  "gate:content-address,gate:replay-oracle,gate:e2e-determinism"
```

RFC-0020 `06-storage-replication-and-gc.md` goes further: campaign storage is
"one content-addressed object model implemented by a validated graph of
small storage components", with directory, memory, NVMe, and S3-compatible
leaves and composable routing, tiering, packing, verification, compression,
mirroring, promotion, and eviction layers, and "one authoritative mutable ref
backend per campaign namespace". That is the Terrane store expression and
ref model described in a different vocabulary.

- **[CRU-1]** `crucible-cas::DagStore` MUST be implemented by a thin
  adapter in `aos-terrane` over the Terrane `Store` (spec STORE-1 to
  STORE-5) and MUST pass `gate:content-address`, `gate:replay-oracle`, and
  `gate:e2e-determinism` unchanged, as the crate's merge bar requires. The
  adapter MUST NOT change any Crucible ABI or determinism contract. *Gate:*
  `checks.terrane.integration.crucible-dagstore`.
- **[CRU-2]** `SharedDagStore` (the fleet-visible store) MUST be a Terrane
  `tiered` expression whose authority is a bucket or a `blockdev` pool, with
  the campaign namespace's single mutable ref backend (RFC-0020 §06) provided
  by Terrane refs (spec REF-1 to REF-18). *Gate:*
  `checks.terrane.integration.crucible-shared-store`.
- **[CRU-3]** `InvalidationQuery::evaluate` remains Crucible logic. Terrane
  provides only the content graph it walks; the adapter MUST expose
  `DagStore::get` with ranges so that large campaign objects are not loaded
  whole (spec STORE-4). *Gate:* `checks.terrane.integration.crucible-dagstore`.

## Identity bridging

RFC-0020 defines `ContentId = H(kind domain tag, schema version, length,
plaintext)` with a `CRUCOBJE` envelope, and typed IDs such as `PageId` and
`CampaignSnapshotId` that are `ContentId`s, not locations. Terrane's identity
is BLAKE3 over a registered domain prefix and the bytes (spec OBJ-2 to
OBJ-4).

- **[CRU-4]** Crucible envelopes MUST be stored as Terrane objects whose
  plaintext is the full envelope, so that `ContentId` is a per-object derived
  attribute computed by the adapter (spec DRV-1, DRV-2) and indexed
  (`index = [crucible.content_id]`, spec DRV-12). Terrane object identity is
  never substituted for `ContentId` in Crucible records, and Crucible never
  learns pack ids or offsets (spec OBJ-23). *Gate:*
  `checks.terrane.integration.crucible-content-id`.
- **[CRU-5]** Campaign closures (RFC-0020's exact-closure manifests) MUST be
  Terrane trees keyed by role-tagged child path, so that closure verification
  is a tree walk and campaign snapshots are commits. Campaign GC roots
  (`CampaignGcRoots`) become refs and tags (spec GC-1). *Gate:*
  `checks.terrane.integration.crucible-closures`.

## Deterministic VM disks

Crucible attaches root disks to the patched QEMU through a `crucible-shmem`
virtio-blk device (`crates/crucible-qemu/src/launch.rs`
`CrucibleShmemBlockDevice`; `block_realization_gate.rs` proves the driver
opens). Determinism requires that a disk's contents be a pure function of
its identity, which is exactly the block surface's contract (spec VBLK-1:
device layout is a pure function of root hash and layout parameters).

- **[CRU-6]** A Crucible scenario's disk image MUST be a Terrane view whose
  root is the image tree, served by the block surface (spec
  `28-surface-erofs-and-block.md` §block) either as a `vhost-user-blk`
  socket consumed by QEMU or as blocks copied into the existing
  `crucible-shmem` ring by a host-side servicer. The extent map (VBLK-4) is
  computed once per root and cached in the host tier. *Gate:*
  `checks.terrane.integration.crucible-block-surface`.
- **[CRU-7]** Guest writes MUST land in a copy-on-write layer owned by
  Crucible's snapshot machinery (`crucible-device/src/block.rs` overlay codec
  and snapshot arrays), not in Terrane, because the block surface is
  read-only in 1.0 (spec VBLK-11). A checkpoint's disk delta MAY be stored as
  a Terrane object like any other campaign object. *Gate:*
  `checks.terrane.integration.crucible-block-cow`.
- **[CRU-8]** Crucible's 9P server (`crucible-device/src/ninep.rs`) MAY be
  backed by a Terrane view through the SDK for read-only source trees; where
  it is, the view MUST be `pinned` (spec CONS-28) for the life of the
  scenario. *Gate:* `checks.terrane.integration.crucible-9p`.

## Campaign workflows

RFC-0020 campaigns fork, checkpoint, replay, and reduce. Each of those is a
Terrane verb:

| Campaign operation | Terrane |
| --- | --- |
| checkpoint | commit on the campaign branch (REF-12) |
| hot fork (RFC-0020 §05) | branch fork, one ref write (ALG-32) |
| corpus promotion | fold into the parent campaign branch (ALG-33) |
| replication to another host or region | `replicate` property and warming (TOPO-33, TOPO-22) |
| retention (`CampaignCorpusRetentionPolicy`) | `retain` property and tags (PROP-9, REF-19) |
| offline maintenance transfer | pack export and import (MIG-6) |

- **[CRU-9]** RFC-0020's stated non-goal of "concurrent multi-host campaign
  execution or multi-writer campaign convergence" MUST be preserved by
  leaving campaign branches single-writer (spec REF-16, CONS-17); the
  campaigns branch MUST NOT enable `writers=many`. *Gate:*
  `checks.terrane.integration.crucible-single-writer`.

## Licensing boundary

The Crucible/QEMU boundary rules in the repository `CLAUDE.md` and RFC-0010
file 37 require the Apache-licensed host and the GPL-side QEMU and plugin to
remain separate processes whose only integration surfaces are the versioned
socket control protocol and the shared-memory data protocol.

- **[CRU-10]** Terrane crates and `aos-terrane` are Apache-side. They MUST
  NOT link QEMU, include QEMU headers, or expose QEMU callback entry points.
  The block surface reaches QEMU only through `vhost-user-blk` over a Unix
  socket or through the existing `crucible-shmem` protocol serviced by a
  Crucible host process, both of which are process boundaries. `gate:license-boundary`
  MUST include the Terrane crates in its scan. *Gate:*
  `checks.terrane.integration.license-boundary`.
- **[CRU-11]** Shared memory written by any Terrane-fed servicer MUST
  contain only block data and the protocol's own headers, never Terrane
  object identities, pack offsets, or Rust-native layouts (RFC-0010 file 13's
  rule that shared memory carries no process-private objects). *Gate:*
  `checks.terrane.gates.containers-not-in-identity` plus the ABI conformance
  gate.

## Interactions

- Spec files `04`, `11`, `17`, `20`, `28`, `33`.
- RFC-0010 files 13, 35, 37; RFC-0020 files 05, 06.
- [`05-implementation-plan.md`](05-implementation-plan.md) Phase 7.
- [`06-decision-register.md`](06-decision-register.md) AD-6.
