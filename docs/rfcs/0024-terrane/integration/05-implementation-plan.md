# 05 — Implementation plan

This is the plan AOS works through, top to bottom, to adopt Terrane. It is
the ordering authority: it arranges tasks into phases, names the gate that
must be green to leave each phase, and records which specification files'
`MUST` requirements each phase covers. The specification itself carries no
checklists (spec `00-conventions.md` §Task plans); this file is where tasks
live.

## How to use this plan

- Task IDs are area-scoped and stable, `T-<AREA>-<n>`, where `<AREA>` is a
  specification prefix (spec `00-conventions.md` §Area prefixes) or one of
  the integration prefixes `SBX`, `HUB`, `PKG`, `CRU`. Re-sequencing a task
  never renumbers it.
- Every task lists the requirement IDs it satisfies and the gate or check
  that proves it. A task is done when its check is green in
  `checks.terrane.*` ([`03-packaging.md`](03-packaging.md) PKG-7).
- No task depends on a later-phase task. Formats, golden vectors, and the
  store come before anything built on them.
- A phase is done when all its tasks are checked and its exit gate is green.
  Do not start a phase before the prior phase's exit gate is green.
- **[PLAN-1]** Every `MUST` in every specification file named by a phase
  MUST be satisfied by at least one task before this RFC's status moves to
  Implemented. The coverage section at the end lists the mapping and MUST
  show no uncovered file.

## Phase 0 — Spikes

Exit gate: every spike has a recorded result in
[`06-decision-register.md`](06-decision-register.md) or spec `40`.

- [ ] **T-RISK-1** Conditional-write probe against R2, S3, GCS, a local
  `file://` root, and the S3-compatible stores AOS operates. Records which
  report `refs: cas` and which downgrade to `single-writer`. — satisfies
  RISK-1, BKT-10, BKT-11; `checks.terrane.gates.bucket-conditional-probe`.
- [ ] **T-RISK-2** zstd on `wasm32-unknown-unknown`: decode with a pure-Rust
  decoder, measure CPU per MiB under the Worker budget, and confirm that
  encode is not required at the edge. — satisfies RISK-2, EDGE-17, EDGE-18;
  `checks.terrane.gates.core-no-std`.
- [ ] **T-RISK-3** Prolly boundary variance: generate trees of 10^4 to 10^7
  entries, measure node-size distribution under TREE-21 to TREE-24, and
  confirm the size-scaled boundary probability holds the distribution within
  spec limits. — satisfies RISK-5, TREE-22, TREE-24;
  `checks.terrane.gates.tree-node-distribution`.
- [ ] **T-RISK-4** FUSE passthrough and overlay-over-FUSE exec on the AOS
  6.18 kernel: prove `FUSE_DEV_IOC_BACKING_OPEN` registration through
  `aos-mountd` and that exec of a passthrough-backed binary succeeds. —
  satisfies RISK-10, RISK-11, FUSE-13, FUSE-39;
  `checks.terrane.gates.exec-through-overlay`.

## Phase 1 — Core formats and algorithms (`terrane-core`)

Exit gate: `checks.terrane.gates.golden-vectors`,
`checks.terrane.gates.core-no-std`, `checks.terrane.gates.core-fuzz`.

- [ ] **T-PKG-1** Add `terrane-core` to the workspace with `#![no_std]`,
  workspace lints, and the AOS Rust documentation standard. — satisfies
  PKG-1, PKG-2, CRATE-1, CRATE-30, CRATE-34 to CRATE-36;
  `checks.terrane.gates.crate-graph`.
- [ ] **T-OBJ-1** Identity domains, descriptors, and the `terrane-v1`
  profile; second-profile registration hook. — satisfies OBJ-1 to OBJ-10;
  `checks.terrane.gates.identity-idempotence`,
  `checks.terrane.gates.descriptor-strict`.
- [ ] **T-CDC-1** FastCDC chunker with the seeded gear table, codec bytes,
  dictionary identities, and the receiver-side validation rules. —
  satisfies CDC-1 to CDC-20; `checks.terrane.gates.cdc-boundaries`,
  `checks.terrane.gates.chunk-codec`, `checks.terrane.gates.chunk-bomb-cap`,
  `checks.terrane.gates.zstd-concat`.
- [ ] **T-TREE-1** Deterministic CBOR encoder and decoder with limits before
  allocation; node and entry encoding; entry types including `tree`,
  `whiteout`, and `conflict`. — satisfies TREE-1 to TREE-20, TREE-25 to
  TREE-29; `checks.terrane.gates.canonical-cbor`,
  `checks.terrane.gates.tree-well-formed`.
- [ ] **T-TREE-2** Prolly-tree builder with content-defined boundaries and
  history independence. — satisfies TREE-21 to TREE-24;
  `checks.terrane.gates.tree-boundaries`,
  `checks.terrane.gates.tree-history-independence`.
- [ ] **T-ALG-1** `graft`, `split`, `flatten`, `overlay`, `diff`. — satisfies
  ALG-1 to ALG-14; `checks.terrane.gates.algebra-graft`,
  `checks.terrane.gates.algebra-diff`.
- [ ] **T-ALG-2** Three-cursor `merge` with conflict values and policies;
  `filter`, `map`, set operations; recipes and memoization; fork and fold.
  — satisfies ALG-15 to ALG-35; `checks.terrane.gates.algebra-merge`,
  `checks.terrane.gates.algebra-fork`,
  `checks.terrane.gates.merge-native-parity`.
- [ ] **T-PROP-1** Property resolution, types, boundary properties,
  completeness, commit-time requirement checks. — satisfies PROP-1 to
  PROP-27; `checks.terrane.gates.property-resolution`,
  `checks.terrane.gates.property-required-attrs`,
  `checks.terrane.gates.property-domain-reference`.
- [ ] **T-REF-1** Commit and ref record types, merge base, ancestry, ref
  name grammar. — satisfies REF-1 to REF-11, REF-24 to REF-26;
  `checks.terrane.gates.ref-names`.
- [ ] **T-DRV-1** Derived attribute records, index-tree maintenance
  algorithms, classification. — satisfies DRV-1 to DRV-20;
  `checks.terrane.gates.derived-attr-record`,
  `checks.terrane.gates.index-tree-maintenance`.
- [ ] **T-RULE-1** Ruleset IR, compiler, evaluator, and portable policy
  encoding. — satisfies RULE-1 to RULE-28;
  `checks.terrane.gates.ruleset-eval-order`,
  `checks.terrane.gates.ruleset-derived-root`.
- [ ] **T-AUTH-1** Capability token verification (Ed25519, chain, caveats,
  attenuation) in `no_std`. — satisfies AUTH-7 to AUTH-22;
  `checks.terrane.gates.auth-verify-pure`,
  `checks.terrane.gates.auth-attenuation-monotone`.
- [ ] **T-TEST-1** Golden vectors generated by the reference implementation
  and checked into `spec/reference/golden-vectors.md`; fuzz and property
  tests for every format. — satisfies TEST-1 to TEST-4, CRATE-3;
  `checks.terrane.gates.golden-vectors`, `checks.terrane.gates.core-fuzz`.

## Phase 2 — Store, packs, bucket, refs, GC (`terrane`)

Exit gate: `checks.terrane.gates.bucket-ref-cas`,
`checks.terrane.gates.gc-grace-window`, store conformance on `file://` and
one S3-compatible bucket.

- [ ] **T-STORE-1** The `Store` trait, capability sets, error taxonomy,
  `HttpClient` and `Clock` traits, `tokio` feature. — satisfies STORE-1 to
  STORE-12, STORE-30, STORE-31, CRATE-6 to CRATE-8;
  `checks.terrane.gates.store-error-taxonomy`,
  `checks.terrane.gates.runtime-agnostic`.
- [ ] **T-PACK-1** Pack writer and reader, per-pack index objects, trailer
  recovery, meta packs, tree-order emission. — satisfies PACK-1 to PACK-16;
  `checks.terrane.gates.pack-header`,
  `checks.terrane.gates.pack-self-describing`,
  `checks.terrane.gates.pack-single-writer`.
- [ ] **T-PACK-2** Merged index shards by epoch, tombstones, filters,
  bundles. — satisfies PACK-17 to PACK-28;
  `checks.terrane.gates.index-shard-epochs`,
  `checks.terrane.gates.index-filter-hint-only`,
  `checks.terrane.gates.bundle-verify`.
- [ ] **T-BKT-1** `bucket` backend over `file://` and S3-compatible APIs
  (reusing `aos-net` and `aos-hub-core` signing), key layout, mutability
  classes, conditional writes, multipart abort, startup probe. — satisfies
  BKT-1 to BKT-16; `checks.terrane.gates.bucket-key-registry`,
  `checks.terrane.gates.bucket-probe`,
  `checks.terrane.gates.bucket-multipart-abort`.
- [ ] **T-REF-2** Ref advance protocol (packs, indexes, log, CAS), epochs,
  single-writer default, tags, reflog, rollback, watch. — satisfies REF-12
  to REF-23, REF-27 to REF-31; `checks.terrane.gates.ref-advance-ordering`,
  `checks.terrane.gates.ref-epoch-fencing`, `checks.terrane.gates.ref-watch`.
- [ ] **T-STORE-2** `tiered`, `guard`, `cache`, `remote` combinators and the
  store expression parser and validator. — satisfies STORE-13 to STORE-29;
  `checks.terrane.gates.tiered-read-order`,
  `checks.terrane.gates.store-expression-validate`,
  `checks.terrane.gates.guard-validates-uploads`.
- [ ] **T-GC-1** Mark-and-sweep collector: roots, mark, grace, two-phase
  sweep, compaction, singleton lease, resumability. — satisfies GC-1 to
  GC-24, GC-28; `checks.terrane.gates.gc-roots-complete`,
  `checks.terrane.gates.gc-mark-reachability`,
  `checks.terrane.gates.gc-two-phase-delete`,
  `checks.terrane.gates.gc-singleton-lease`.
- [ ] **T-PROV-1** Commit signing and verification, entry provenance,
  selector language and profiles. — satisfies PROV-1 to PROV-25;
  `checks.terrane.gates.prov-commit-signature`,
  `checks.terrane.gates.prov-selector-profiles`.
- [ ] **T-DOM-1** Domain property semantics, cross-domain reference checks,
  dedup scoping, existence-oracle rules. — satisfies DOM-1 to DOM-11,
  DOM-16, DOM-17, DOM-20; `checks.terrane.gates.dom-reference-order`,
  `checks.terrane.gates.dom-dedup-scope`.
- [ ] **T-CRATE-1** SDK types and verbs (`Tree`, `View`, `Store`,
  `Repository`, `fork`, `commit`, `merge`, `diff`, `realize`). — satisfies
  CRATE-22 to CRATE-27; `checks.terrane.gates.feature-matrix`.
- [ ] **T-PKG-2** `pkgs/tools/terrane.nix`, workspace vendor hashes,
  nextest in the `aos` package check phase, `aos-dev` targets. — satisfies
  PKG-3 to PKG-5, PKG-11; `checks.terrane.package`.

## Phase 3 — Host tier and FUSE surface into the sandbox runtime

Exit gate: `checks.terrane.gates.fuse-passthrough`,
`checks.terrane.gates.host-crash-recovery`,
`checks.terrane.integration.viewd-role`, and RFC-0021's existing view
conformance tests passing over Terrane.

- [ ] **T-HOST-1** `disk` tier layout, verify-before-admit, quarantine,
  reassembly modes, S3-FIFO eviction, pins, reservations, exact quotas,
  wipe, two-phase delete, embedded state scope, crash recovery. — satisfies
  HOST-1 to HOST-5, HOST-10 to HOST-36, BKT-15; `checks.terrane.gates.host-eviction-s3fifo`,
  `checks.terrane.gates.host-verify-before-admit`,
  `checks.terrane.gates.host-crash-recovery`.
- [ ] **T-HOST-2** `publish` role: networkless sealer with fs-verity,
  no-replace publication, adoption on recovery. — satisfies HOST-6 to
  HOST-9, ARCH-8; `checks.terrane.gates.publisher-sole-writer`,
  `checks.terrane.gates.host-publish-sequence`.
- [ ] **T-STORE-3** `shared-dir` backend and per-domain object directories.
  — satisfies STORE-14, DOM-12 to DOM-15, HOST-27;
  `checks.terrane.gates.shared-dir-read-only`,
  `checks.terrane.gates.dom-host-isolation`.
- [ ] **T-SURF-1** Surface interface, exposure records, schema validation,
  TOML configuration, status reporting, in-process registry. — satisfies
  SURF-1 to SURF-32, CRATE-17, CRATE-28; `checks.terrane.gates.surface-interface`,
  `checks.terrane.gates.surface-schema`,
  `checks.terrane.gates.surface-status`.
- [ ] **T-FUSE-1** Structural index compiler and mmap reader. — satisfies
  FUSE-7 to FUSE-12; `checks.terrane.gates.fuse-index-roundtrip`.
- [ ] **T-FUSE-2** FUSE worker: passthrough, fallback, inode policy,
  attributes, open path, coalescing, mount options, leases, drain. —
  satisfies FUSE-1 to FUSE-6, FUSE-13 to FUSE-31, FUSE-43 to FUSE-50,
  ARCH-7, ARCH-11; `checks.terrane.gates.fuse-worker-isolation`,
  `checks.terrane.gates.fuse-passthrough`,
  `checks.terrane.gates.fuse-verify-before-serve`.
- [ ] **T-FUSE-3** Writable exposures: overlay upper, quota, commit walk,
  redirections, `.terrane` control directory, fsync binding. — satisfies
  FUSE-32 to FUSE-42, CONS-1 to CONS-13, CONS-24 to CONS-27, CONS-34 to
  CONS-37; `checks.terrane.gates.fuse-upper-isolation`,
  `checks.terrane.gates.cons-sync-fsync`,
  `checks.terrane.gates.cons-fsync-sticky`,
  `checks.terrane.gates.cons-control`.
- [ ] **T-CONS-1** Writer modes, durability levels, epoch fencing, reader
  modes with atomic `follow` switch. — satisfies CONS-14 to CONS-23, CONS-28
  to CONS-33; `checks.terrane.gates.cons-writer-modes`,
  `checks.terrane.gates.cons-fencing`,
  `checks.terrane.gates.cons-follow-atomic`.
- [ ] **T-SBX-1** `terrane serve` as `aos-viewd`, `terrane publish` as the
  publisher, worker units in `aos-view-services.slice`, no privileged
  mounts. — satisfies SBX-1 to SBX-5, PKG-8, PKG-9;
  `checks.terrane.integration.viewd-role`,
  `checks.terrane.integration.publisher-role`,
  `checks.terrane.gates.no-privileged-mounts`.
- [ ] **T-SBX-2** Attachments as exposures; view-mode mapping; durable
  attachment records; `follow` replacement through `aos-mountd`. —
  satisfies SBX-6 to SBX-8; `checks.terrane.integration.view-modes`,
  `checks.terrane.integration.attachment-record`,
  `checks.terrane.integration.follow-replace`.
- [ ] **T-SBX-3** Disclosure-domain mapping and strict placement. —
  satisfies SBX-9, SBX-10; `checks.terrane.integration.domain-map`.
- [ ] **T-SBX-4** `aos-sandbox-v1` descriptor profile, SHA-256 index on
  sandbox roots, portable-tree adapter, `ObjectSource` and
  `ImmutableFetchTransport` implementations. — satisfies SBX-11 to SBX-17;
  `checks.terrane.integration.descriptor-profile`,
  `checks.terrane.integration.object-source`,
  `checks.terrane.integration.fetch-transport`.
- [ ] **T-SBX-5** Nix store union views and nested `shared-dir` sandboxes;
  capacity and memory wiring. — satisfies SBX-18 to SBX-21;
  `checks.terrane.integration.nix-union`,
  `checks.terrane.gates.perf-nested-zero-dup`.
- [ ] **T-PKG-3** `modules/terrane/` options, unit rendering, and module
  evaluation check. — satisfies PKG-8, PKG-10;
  `checks.terrane.module-eval`.

## Phase 4 — Protocol, tiering, guard, tokens

Exit gate: `checks.terrane.gates.proto-conformance`,
`checks.terrane.gates.tier-chaos`,
`checks.terrane.gates.auth-single-enforcement`.

- [ ] **T-PROTO-1** ConnectRPC services from `spec/reference/protocol.md`:
  content, ref, tier; negotiation; `PutPack`; presigned reads; `GetRange`;
  bundles; watch; filters and index deltas; error codes; versioning. —
  satisfies PROTO-1 to PROTO-54; `checks.terrane.gates.proto-transport`,
  `checks.terrane.gates.proto-negotiate`, `checks.terrane.gates.proto-presign`,
  `checks.terrane.gates.proto-errors`.
- [ ] **T-TOPO-1** Locality labels, cost vectors with decay and hysteresis,
  cost-sorted selection, breakers, hop accounting, peers, residency filters,
  warming, home, promisor-style misses, replication, partition behavior. —
  satisfies TOPO-1 to TOPO-42, GC-25 to GC-27; `checks.terrane.gates.topo-selection`,
  `checks.terrane.gates.topo-residency`, `checks.terrane.gates.topo-partition`,
  `checks.terrane.gates.gc-multiregion`.
- [ ] **T-BW-1** Ancestry and Merkle negotiation, filtered `has`, wire
  deltas, dictionaries, whole-pack threshold, replicate-once. — satisfies
  BW-1 to BW-22; `checks.terrane.gates.bandwidth-negotiate-delta`,
  `checks.terrane.gates.bandwidth-wire-delta-roundtrip`.
- [ ] **T-AUTH-2** Issuers (OIDC device flow, workload minting, mTLS),
  `guard` enforcement, ACL properties, presigned-read minting, browser
  session exchange, revocation. — satisfies AUTH-1 to AUTH-6, AUTH-23 to
  AUTH-44; `checks.terrane.gates.auth-oidc-login`,
  `checks.terrane.gates.auth-acl-intersection`,
  `checks.terrane.gates.auth-single-enforcement`.
- [ ] **T-OBS-1** Trace propagation, hop spans, decision logs, status
  surface, metrics, blame. — satisfies OBS-1 to OBS-17;
  `checks.terrane.gates.obs-trace-propagation`,
  `checks.terrane.gates.obs-status-surface`, `checks.terrane.gates.obs-metrics`.
- [ ] **T-TEST-2** Protocol conformance client and server, tier chaos,
  security suite. — satisfies TEST-6 to TEST-8, TEST-13, TEST-14;
  `checks.terrane.gates.proto-conformance`, `checks.terrane.gates.tier-chaos`.
- [ ] **T-PERF-1** Performance harness and every `gate:perf-*` check with
  the measurement methodology. — satisfies PERF-1 to PERF-13, TEST-15;
  `checks.terrane.gates.perf-methodology` and each `checks.terrane.gates.perf-*`.

## Phase 5 — Protocol surfaces

Exit gate: `checks.terrane.gates.nix-frame-concat`,
`checks.terrane.gates.reapi-completeness`, and stock clients (`nix`,
`bazel`, the GitHub Actions cache client, a browser) exercised end to end.

- [ ] **T-NIX-1** `nix-cache` surface: schema, narinfo, zero-CPU `.nar.zst`
  streaming, index lookups, writable uploads, credential mapping. —
  satisfies NIX-1 to NIX-13; `checks.terrane.gates.nix-frame-concat`,
  `checks.terrane.gates.nix-surface-stream`.
- [ ] **T-REAPI-1** `reapi` surface with completeness checking. — satisfies
  REAPI-1 to REAPI-8; `checks.terrane.gates.reapi-completeness`.
- [ ] **T-GHA-1** `gha-cache` surface: key, version, scope semantics; fold on
  merge. — satisfies GHA-1 to GHA-8; `checks.terrane.gates.surface-schema`.
- [ ] **T-WEB-1** `browse` and `api` surfaces. — satisfies WEB-1 to WEB-7;
  `checks.terrane.gates.surface-schema`.
- [ ] **T-GIT-1** `git` surface (read-only upload-pack over memoized tree
  projections). — satisfies GIT-1 to GIT-9;
  `checks.terrane.gates.surface-schema`.
- [ ] **T-OCI-1** `oci` surface. — satisfies OCI-1 to OCI-7;
  `checks.terrane.gates.surface-schema`.

## Phase 6 — Hub on R2 and the edge

Exit gate: `checks.terrane.gates.edge-native-interop`,
`checks.terrane.integration.hub-import` against a staging Hub.

- [ ] **T-EDGE-1** `terrane-edge` crate, Worker bindings, R2 `onlyIf`
  backend, edge conformance claim. — satisfies EDGE-1 to EDGE-22, CRATE-13,
  CRATE-14, PKG-6; `checks.terrane.gates.core-no-std`,
  `checks.terrane.gates.edge-native-interop`.
- [ ] **T-HUB-1** Hub token issuer, registry branches with properties from
  Hub configuration, shared bucket, edge role. — satisfies HUB-1 to HUB-5;
  `checks.terrane.integration.hub-issuer`,
  `checks.terrane.integration.hub-registry-branch`,
  `checks.terrane.integration.hub-edge-role`.
- [ ] **T-HUB-2** SHA-256 index continuity and the per-registry import and
  cutover with rollback. — satisfies HUB-6, HUB-7, MIG-1 to MIG-7;
  `checks.terrane.integration.hub-sha256-index`,
  `checks.terrane.integration.hub-import`,
  `checks.terrane.gates.mig-import-idempotent`.
- [ ] **T-HUB-3** Hub surfaces, signing job, console over `api`, OCI
  publication, GC driver, release tags, client compatibility. — satisfies
  HUB-8 to HUB-14; `checks.terrane.integration.hub-signing`,
  `checks.terrane.integration.hub-console-api`,
  `checks.terrane.integration.hub-gc`,
  `checks.terrane.integration.hub-client-compat`.

## Phase 7 — EROFS, VM, block, redundancy, block device

Exit gate: `checks.terrane.gates.erofs-image-determinism`,
`checks.terrane.gates.block-layout-determinism`,
`checks.terrane.gates.redundancy-striped-reconstruct`,
`checks.terrane.gates.blockdev-crash-recovery`.

- [ ] **T-EROFS-1** Deterministic EROFS image generation, overlay with
  data-only lower and `verity=require`, lazy mode, `follow` replacement. —
  satisfies EROFS-1 to EROFS-15; `checks.terrane.gates.erofs-image-determinism`,
  `checks.terrane.gates.erofs-verity`.
- [ ] **T-VM-1** virtiofs export with DAX, virtio-pmem option, nested
  instances in guests, guest token attenuation. — satisfies VM-1 to VM-18;
  `checks.terrane.gates.vm-export-scope`,
  `checks.terrane.gates.vm-no-duplication`.
- [ ] **T-VBLK-1** Block surface: deterministic layout, extent map, lazy
  block reads over `vhost-user-blk`, `ublk`, or NBD, read-only. —
  satisfies VBLK-1 to VBLK-13; `checks.terrane.gates.block-layout-determinism`.
- [ ] **T-CRU-1** `DagStore` adapter, shared store, content-id indexing,
  closure trees, block surface for scenario disks, license-boundary scan.
  — satisfies CRU-1 to CRU-11; `checks.terrane.integration.crucible-dagstore`,
  `checks.terrane.integration.crucible-block-surface`,
  `checks.terrane.integration.license-boundary`.
- [ ] **T-RED-1** `replicated` and `striped` combinators, placement, verify
  and repair, scrub and resilver jobs, quorum refs, federation. —
  satisfies RED-1 to RED-33; `checks.terrane.gates.redundancy-replicated-ack`,
  `checks.terrane.gates.redundancy-striped-reconstruct`,
  `checks.terrane.gates.redundancy-quorum-refs`.
- [ ] **T-BLK-1** `blockdev` backend: superblocks, slab log, index region,
  compaction, recovery scan, hybrid with a `disk` tier. — satisfies BLK-1 to
  BLK-19, HOST-37, CRATE-9; `checks.terrane.gates.blockdev-format-roundtrip`,
  `checks.terrane.gates.blockdev-ref-cas`,
  `checks.terrane.gates.blockdev-crash-recovery`.

## Phase 8 — Jobs, migrations, imports

Exit gate: `checks.terrane.gates.job-resume`,
`checks.terrane.gates.mig-store-move`.

- [ ] **T-JOB-1** Tree job primitive: shards, cursors, checkpoints, fold,
  follow, status, cancellation, in-exposure access. — satisfies JOB-1 to
  JOB-33, DRV-11, PROP-25; `checks.terrane.gates.job-ref-lifecycle`,
  `checks.terrane.gates.job-resume`, `checks.terrane.gates.job-fold`,
  `checks.terrane.gates.job-follow`.
- [ ] **T-MIG-1** Import adapters (Nix binary cache, REAPI, GHA, OCI, git,
  `terrane-compatible`, `aos-portable-tree`), layout and profile migrations,
  chunk-parameter migrations, store moves, splits and joins, digest-profile
  coexistence. — satisfies MIG-8 to MIG-33; `checks.terrane.gates.mig-layout-merge`,
  `checks.terrane.gates.mig-store-move`,
  `checks.terrane.gates.mig-digest-coexist`.
- [ ] **T-TEST-3** Conformance claims for Core, Distribution, Security,
  Host, Redundant, each surface, and Operations, published with performance
  results. — satisfies TEST-16 to TEST-18, PERF-13;
  `checks.terrane.gates.registry-complete`.

## Coverage

| Specification file | Phase | Tasks |
| --- | --- | --- |
| 01 goals and invariants | 1–4 | every task; invariants are cross-cutting gates |
| 03 architecture | 3, 4 | T-SBX-1, T-FUSE-2, T-HOST-2, T-PROTO-1 |
| 04 content model | 1 | T-OBJ-1 |
| 05 chunking | 1 | T-CDC-1 |
| 06 tree format | 1 | T-TREE-1, T-TREE-2 |
| 07 tree algebra | 1 | T-ALG-1, T-ALG-2 |
| 08 properties | 1 | T-PROP-1 |
| 09 refs and commits | 1, 2 | T-REF-1, T-REF-2 |
| 10 derived data | 1, 8 | T-DRV-1, T-JOB-1 |
| 11 store trait | 2, 3 | T-STORE-1, T-STORE-2, T-STORE-3 |
| 12 pack format | 2 | T-PACK-1, T-PACK-2 |
| 13 bucket layout | 2, 3 | T-BKT-1, T-HOST-1 |
| 14 host tier | 3, 7 | T-HOST-1, T-HOST-2, T-BLK-1 |
| 15 redundancy | 7 | T-RED-1 |
| 16 block-device backend | 7 | T-BLK-1 |
| 17 garbage collection | 2, 4 | T-GC-1, T-TOPO-1 |
| 18 protocol | 4 | T-PROTO-1 |
| 19 tiering and topology | 4 | T-TOPO-1 |
| 20 consistency | 3 | T-FUSE-3, T-CONS-1 |
| 21 bandwidth | 4 | T-BW-1 |
| 22 authentication | 1, 4 | T-AUTH-1, T-AUTH-2 |
| 23 provenance | 2 | T-PROV-1 |
| 24 disclosure domains | 2, 3 | T-DOM-1, T-STORE-3 |
| 25 threat model | 4 | T-TEST-2 (mapping only; no `MUST`s of its own beyond residual-risk statements) |
| 26 surfaces | 3 | T-SURF-1 |
| 27 FUSE | 3 | T-FUSE-1, T-FUSE-2, T-FUSE-3 |
| 28 EROFS and block | 7 | T-EROFS-1, T-VBLK-1 |
| 29 VM | 7 | T-VM-1 |
| 30 protocol surfaces | 5 | T-NIX-1, T-REAPI-1, T-GHA-1, T-WEB-1, T-GIT-1, T-OCI-1 |
| 31 rulesets | 1 | T-RULE-1 |
| 32 tree jobs | 8 | T-JOB-1 |
| 33 migrations | 6, 8 | T-HUB-2, T-MIG-1 |
| 34 observability | 4 | T-OBS-1 |
| 35 performance | 4 | T-PERF-1 |
| 36 testing | 1, 4, 8 | T-TEST-1, T-TEST-2, T-TEST-3 |
| 37 crates | 1, 2 | T-PKG-1, T-CRATE-1 |
| 38 edge | 6 | T-EDGE-1 |
| integration 01 | 3 | T-SBX-1 to T-SBX-5 |
| integration 02 | 6 | T-HUB-1 to T-HUB-3 |
| integration 03 | 1–3 | T-PKG-1 to T-PKG-3 |
| integration 04 | 7 | T-CRU-1 |

- **[PLAN-2]** A doc lint MUST verify that every requirement ID cited by a
  task exists in the specification or in this directory, and that every
  `MUST` in the files above is cited by at least one task. The lint runs as
  `checks.terrane.plan-coverage` and MUST be green before status changes.
