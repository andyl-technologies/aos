# 06 — AOS decision register

This file records the AOS-specific decisions behind adopting Terrane: the
choices that are AOS's to make rather than the specification's. The
specification's own decisions live in `spec/39-decision-register.md` with
`D-n` IDs; entries here use `AD-n` and follow the same shape. An `AD-n` entry
is recorded rationale, not a normative statement; the normative force lives in
the requirement IDs each decision affects.

```text
- **[AD-n] <one-line title>**
  - **Status:** Decided | Open
  - **Decision:** what was chosen.
  - **Rationale:** why, honestly.
  - **Alternatives considered:** what else was on the table and why it lost.
  - **Affects:** the requirement IDs / files this decision shapes.
```

## Decisions

- **[AD-1] The binary is `terrane`; the crates are `terrane-*`**
  - **Status:** Decided
  - **Decision:** The program is named `terrane` and the crates
    `terrane-core`, `terrane`, `terrane-fs`, `terrane-edge`, `terrane-cli`.
    AOS-specific glue lives in one crate, `aos-terrane`. AOS commands that
    need AOS context are subcommands of the `aos` CLI, not a second binary.
  - **Rationale:** Terrane is a standalone system that AOS adopts, the way
    FreeBSD adopts ZFS. A product prefix on the binary or the specification
    crates would contradict that and would have to be removed before the
    crates could be published or the specification lifted. The earlier
    working name `aos-terrane` for the binary was dropped for this reason.
  - **Alternatives considered:** `aos-terrane` as the binary (rejected:
    not standalone); two binaries, one per plane (rejected: spec D-16 makes
    one binary with roles the design); `chunk-store` and `chunk-warehouse`
    (rejected: the system is a filesystem with branches, not two chunk
    services).
  - **Affects:** PKG-4, spec CRATE-15, spec D-20.

- **[AD-2] The specification stays liftable**
  - **Status:** Decided
  - **Decision:** `spec/` is self-contained: it never links outside its
    directory, never names AOS, and carries its own version and conformance
    levels. It is expected to move to its own repository by `git subtree
    split` with no edits. Everything AOS-specific is under `integration/`.
  - **Rationale:** The same reason as AD-1. It also keeps the specification
    honest: a requirement that only makes sense with AOS around is an
    integration requirement, not a Terrane one.
  - **Alternatives considered:** A single RFC document set with AOS
    integration woven through each file (rejected: would make lifting a
    rewrite and would let AOS assumptions leak into formats).
  - **Affects:** spec CONV-2, spec README §Versioning, RFC-0024 README.

- **[AD-3] The MVP serves sandboxes, build caches, and CI caches together**
  - **Status:** Decided
  - **Decision:** The MVP is the trunk of
    [`05-implementation-plan.md`](05-implementation-plan.md) through T6,
    in the order T0 foundations, T1 local repository, T2 host tier, T3 wire
    protocol and buckets, T4 CI caches (`nix-cache`, `reapi`, `gha-cache`
    for Nix, Bazel, and GitHub Actions on GCP spot runners), T5 the
    RFC-0021 sandbox view service, T6 hardening and the MVP conformance
    claim. T4 and T5 share no dependency and may be worked concurrently.
    AOS Hub, the edge, and every other consumer are branches.
  - **Rationale:** The idea came from one need shared by three consumers:
    an untrusted job reads a trusted baseline, writes results only it can
    see, and has them folded in on merge without copying. Building for one
    consumer would leave the fork-and-fold core untested until later; the
    three together exercise it from T1 (merge) through T4 (surfaces) on the
    same warehouse. CI caches merge before sandboxes because they need no
    kernel work and validate the wire protocol and buckets end to end with
    stock clients; the sandbox path then adds FUSE and the RFC-0021 slots
    on a proven substrate. The Hub stays a branch because replacing its R2
    layer is a migration with a cutover, which is safer once the trunk has
    run under the CI and sandbox workloads.
  - **Alternatives considered:** Sandbox-only MVP (rejected: it never
    exercises merge, fold, or a protocol surface, and the CI need is
    immediate); Hub first (rejected: highest migration risk with the
    least-proven code); every consumer in parallel with no trunk (rejected:
    formats and interfaces would fork before they froze).
  - **Affects:** [`05-implementation-plan.md`](05-implementation-plan.md)
    trunk order, [`07-ci-caches.md`](07-ci-caches.md) CI-1 to CI-17,
    SBX-1 to SBX-21, HUB-1 to HUB-14.

- **[AD-4] ZFS keeps live workspaces in 1.0**
  - **Status:** Decided
  - **Decision:** RFC-0021's live read-only and live read-write views, and
    the storage broker's ZFS datasets and clones for sandbox workspaces,
    remain ZFS. Terrane takes immutable views, private CoW views, and
    publishable staging.
  - **Rationale:** Spec NG-1 and NG-3: Terrane 1.0 is not a live
    shared-writable POSIX filesystem. A ZFS clone gives sub-commit
    durability, locks, and record-granular writes that a Terrane overlay
    upper delegates to the host filesystem anyway. The upper of a Terrane
    exposure may itself sit on a ZFS dataset, so nothing is lost.
  - **Alternatives considered:** Terrane overlay uppers for every writable
    view (rejected for live views: needs a native mutable working tree, spec
    `40` open question); dropping ZFS from the sandbox stack (rejected: no
    replacement for live semantics in 1.0).
  - **Affects:** SBX-6, spec NG-1, NG-3, CONS-38.

- **[AD-5] Bridge RFC-0021 descriptors with a second profile, not a rewrite**
  - **Status:** Decided
  - **Decision:** Register `aos-sandbox-v1` (SHA-256 over
    `aos-sandbox-object-v1`) as a second Terrane identity profile in
    `aos-terrane`, require `hashes = [blake3, sha256]` and an SHA-256 index
    on sandbox roots, and treat the RFC-0021 portable tree as an adapter.
    Terrane's primary identity stays BLAKE3.
  - **Rationale:** Spec OBJ-8 and OBJ-9 already say a second algorithm is a
    coexisting profile. Computing SHA-256 once per object as a derived
    attribute costs one hash pass at write time and nothing at read time,
    while switching Terrane to SHA-256 would cost every chunk hash on every
    read path. RFC-0021's CBOR profile and Terrane's are the same rules, so
    the adapter re-keys rather than re-encodes.
  - **Alternatives considered:** Change RFC-0021 to BLAKE3 (rejected: its
    golden vectors, signatures, and publisher bindings are SHA-256 and
    partly implemented); make Terrane SHA-256 primary (rejected: spec D-4).
  - **Affects:** SBX-11 to SBX-14, HUB-6, spec OBJ-8, OBJ-9, DRV-6.

- **[AD-6] Terrane is Apache-side of the Crucible/QEMU boundary**
  - **Status:** Decided
  - **Decision:** All Terrane crates and `aos-terrane` are Apache-2.0 and
    reach QEMU only through `vhost-user-blk` sockets or the existing
    `crucible-shmem` protocol serviced by a Crucible host process. The
    `gate:license-boundary` scan covers them.
  - **Rationale:** The repository's boundary rule allows no Apache crate to
    link QEMU or include its headers. Both block paths are process
    boundaries with versioned protocols, so nothing changes in the boundary
    policy; the gate simply has more crates to scan.
  - **Alternatives considered:** A QEMU block driver that reads Terrane
    packs directly (rejected: it would be GPL-side code carrying Terrane
    format knowledge, and it would put pack offsets into a QEMU process).
  - **Affects:** CRU-10, CRU-11, RFC-0010 file 37.

- **[AD-7] Gates become `checks.terrane.gates.<name>`**
  - **Status:** Decided
  - **Decision:** Every specification gate is an AOS check under
    `checks.terrane.gates.` with the gate's name minus the `gate:` prefix;
    integration requirements use `checks.terrane.integration.`. KVM-requiring
    gates live under `tests/terrane/`.
  - **Rationale:** Matches how Crucible's gates are exposed
    (`checks.crucible.phase2.gates.*`) so `aos-dev list checks terrane`
    enumerates them and the registry-completeness gate can verify that every
    specification gate has a check.
  - **Alternatives considered:** A per-phase namespace like Crucible's
    (rejected: the specification's gate names are already unique and stable,
    and phases are a plan concern, not a check concern).
  - **Affects:** PKG-7, PKG-11, spec TEST-16.

- **[AD-8] Erasure coding, the block backend, and block writes wait**
  - **Status:** Decided
  - **Decision:** AOS ships the MVP trunk (T0 through T6) before any of
    `striped`, `blockdev`, or a writable block surface; those live on
    B-redundancy and B-storage. AOS's first redundancy is the bucket's own
    durability plus `replicated` across regions for the Hub.
  - **Rationale:** Spec D-18 and NG-8. No AOS workload needs raw-device
    pools in the first year, and the block surface's read-only mode already
    serves Crucible scenario disks.
  - **Alternatives considered:** Blockdev-first for on-prem warehouses
    (rejected: no on-prem deployment is planned before the Hub migration).
  - **Affects:** [`05-implementation-plan.md`](05-implementation-plan.md)
    branches B-redundancy and B-storage, spec D-18.

- **[AD-10] Trunk and branches, with freezes**
  - **Status:** Decided
  - **Decision:** The plan is a serial trunk of milestones, each leaving a
    deployable and gate-green system, plus branch worklines that fork from
    a named milestone and merge as one change. Identities, encodings,
    bucket keys, and store traits freeze at T1; the surface interface and
    exposure record at T2; the wire protocol and token format at T3.
    Branches add registry entries only. Trunk gates are the floor for
    every branch. Testing is local only: Nix checks, the AOS-built Garage
    as the S3-compatible store, VM tests on the AOS kernel; cloud probes
    are manual and recorded here.
  - **Rationale:** A stable and deployable MVP needs a spine that never
    waits on scale-out or multi-site work, and branches need frozen
    formats so they never fork identity. Local-only testing keeps every
    gate reproducible in a Nix check; the two things that cannot be
    tested locally, real GCS and real S3 conditional writes, are exactly
    the ones RISK-1 asks to probe by hand.
  - **Alternatives considered:** Numbered phases with sub-stages (the
    previous shape; rejected because it serialized branch work behind
    unrelated milestones and hid which items were scale-out); gated cloud
    integration tests (rejected: network-dependent gates are not
    reproducible in the hermetic build).
  - **Affects:** [`05-implementation-plan.md`](05-implementation-plan.md)
    §How to use this plan, PLAN-3.

## Open

- **[AD-9] Whether `aos-cache` gains a `terrane://` backend or is replaced**
  - **Status:** Open
  - **Decision:** Pending T4 results. HUB-13 keeps `aos-cache`'s
    existing backends working either way.
  - **Rationale:** The SDK already gives every AOS crate chunk-level
    negotiation; whether a Nix-compatible transfer client still needs a
    separate crate depends on how much of `apr`'s pack path survives the
    Hub migration.
  - **Affects:** HUB-13, HUB-14.
