# 36 — Testing and conformance

This file owns the gate registry, the test suites that back it, and the form
of a conformance claim. A gate is a named automated check; a requirement
names the gate that enforces it; a conformance level is met when every gate
its files name passes. This file is where those names resolve. It also owns
the rule from [`00-conventions.md`](00-conventions.md) [CONV-1] that every
`MUST` without a gate is listed here with a reason.

## Model

Testing follows the layering of the system. Formats are tested by golden
vectors and property tests with no I/O. Stores are tested by a backend
conformance suite run against every backend and combinator, including chaos
injection on tiers. Trees are tested by an algebra suite whose oracle is a
pure in-memory model. Realizers are tested against the kernel with
determinism checks on generated images and layouts. Protocol conformance is
tested by a client and server exercising the schema. Performance is measured
by the budgets in [`35-performance-targets.md`](35-performance-targets.md).

Every gate has a unique name, one owning suite, and a fixed set of
requirements it enforces. A gate MAY enforce requirements from several files.

## Suites

### Golden vectors

- **[TEST-1]** The golden vectors in
  [`reference/golden-vectors.md`](reference/golden-vectors.md) MUST be
  executed byte-for-byte by every implementation claiming **Core**: for each
  vector the implementation encodes the described input and compares the
  bytes and the identity, and decodes the bytes and compares the model.
  *Gate:* `gate:golden-vectors`.
- **[TEST-2]** A golden vector MUST exist for at least: one chunk boundary
  sequence per registered chunk profile, one manifest, one leaf node and one
  internal node per profile, one node boundary decision, one commit, one
  ref record, one pack with a two-entry index, one capability token, one
  descriptor of every registered media type.

### Format property tests

- **[TEST-3]** Formats MUST be fuzzed and property-tested without I/O:
  encode-decode round trips, canonical-encoding uniqueness (two encodings of
  one model are byte-identical), decoder rejection of every non-canonical
  variant, decoder limits applied before allocation, and history
  independence of trees (any insertion order yields the same root). *Gate:*
  `gate:core-fuzz`, `gate:canonical-cbor`, `gate:tree-history-independence`.

### Tree algebra conformance

- **[TEST-4]** The algebra suite MUST compare every operation of
  [`07-tree-algebra.md`](07-tree-algebra.md) against a pure model
  implemented over ordinary ordered maps: graft, split, flatten, overlay,
  diff, three-way merge including conflict values, filter, and map. The
  suite MUST include randomized three-way merge cases with a
  commutativity check for symmetric policies and a check that a merge visits
  no subtree whose three hashes agree. *Gate:* `gate:algebra-merge`,
  `gate:algebra-diff`, `gate:algebra-graft`, `gate:perf-merge-delta`.
- **[TEST-5]** The merge suite MUST include the native comparison: a delta
  extracted from an overlayfs upper, a delta extracted from a
  filesystem-snapshot diff where the platform offers one, and the pure model
  MUST all produce the same result tree for the same logical change set.
  *Gate:* `gate:merge-native-parity`.

### Store backend conformance

- **[TEST-6]** Every backend and combinator MUST pass one store conformance
  suite covering: idempotent put, ranged get, batched has, verify on put and
  get, ref create-once, ref compare-and-swap including a lost race, ref log
  append-once, list-not-authoritative behavior, and the error taxonomy.
  *Gate:* the `gate:store-*` gates in the registry.
- **[TEST-7]** The conditional-write probe MUST be tested against each
  supported object store with a positive case, a lost-race case, and a case
  where the header is silently dropped by a proxy; the last MUST cause the
  backend to be refused as a ref authority. *Gate:* `gate:bucket-probe`.
- **[TEST-8]** Chaos on tiers MUST be part of the suite: a partitioned child,
  a slow child exceeding the hedge threshold, a child returning a corrupt
  pack, a child returning a truncated span, and a child whose refs are stale.
  Each MUST produce the behavior specified in
  [`19-tiering-and-topology.md`](19-tiering-and-topology.md) and
  [`15-redundancy.md`](15-redundancy.md): reroute, quarantine, reconstruct,
  or fail closed. *Gate:* `gate:tier-chaos`.

### Crash recovery

- **[TEST-9]** The host tier MUST be crash-tested by killing the process at
  every fsync boundary of a chunk admission, a sealed-object publication, a
  pin record, and an eviction, then verifying on restart that no unverified
  bytes are servable, no sealed object is lost, and pins are never
  under-counted. *Gate:* `gate:host-crash-recovery`.
- **[TEST-10]** The block-device backend MUST be crash-tested at every point
  of a pack append, an index write, and a superblock flip, using a
  write-recording device that can replay any prefix of writes. *Gate:*
  `gate:blockdev-crash-recovery`.
- **[TEST-11]** A job branch MUST be crash-tested between checkpoint and
  fold and between two shards' cursor updates. *Gate:* `gate:job-resume`.

### Determinism of generated artifacts

- **[TEST-12]** EROFS images and block layouts generated from the same tree
  and parameters on different hosts and at different times MUST be
  byte-identical. *Gate:* `gate:erofs-image-determinism`,
  `gate:block-layout-determinism`.

### Protocol conformance

- **[TEST-13]** A reference client and server MUST exercise every method
  and every error in [`reference/protocol.md`](reference/protocol.md),
  including schema evolution cases (unknown field ignored, unknown method
  rejected, version negotiation). *Gate:* `gate:proto-conformance`.

### Security

- **[TEST-14]** The security suite MUST include: attenuation cannot widen a
  grant, a token verifies without network, a fenced writer cannot commit, a
  cross-domain reference is refused at commit, an existence oracle across
  domains returns the same answer for present and absent content, and a
  presigned URL expires. *Gate:* the `gate:auth-*`, `gate:dom-*`, and
  `gate:prov-*` gates in the registry.

### Performance

- **[TEST-15]** Every `gate:perf-*` check MUST follow the measurement rules
  of [`35-performance-targets.md`](35-performance-targets.md) [PERF-11] and
  publish p50 and p99 with the configuration used.

## Gate registry

The registry lists every gate, the file that owns its definition, and the
requirements it enforces. A gate name that appears in a requirement but not
here is a conformance error of this document.

### Front matter and model

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:algebra-diff` | 07 | ALG-12, TEST-4 |
| `gate:algebra-fork` | 07 | ALG-32 |
| `gate:algebra-graft` | 07 | ALG-1, TEST-4 |
| `gate:algebra-merge` | 07 | ALG-15, TEST-4 |
| `gate:canonical-cbor` | 00 | TREE-4, TREE-25, TREE-28, TEST-3 |
| `gate:cdc-boundaries` | 05 | CDC-1, CDC-16, CDC-6 |
| `gate:chunk-bomb-cap` | 05 | CDC-12 |
| `gate:chunk-codec` | 05 | CDC-7 |
| `gate:containers-not-in-identity` | 04 | OBJ-23 |
| `gate:derived-attr-record` | 10 | DRV-1 |
| `gate:descriptor-strict` | 04 | OBJ-6 |
| `gate:formats-no-std` | 03 | ARCH-1 |
| `gate:gc-grace` | 01 | prose in 01 |
| `gate:identity-idempotence` | 04 | prose in 01, OBJ-1, OBJ-5 |
| `gate:index-tree-maintenance` | 10 | DRV-12 |
| `gate:no-duplicate-tiers` | 01 | prose in 01 |
| `gate:no-privileged-mounts` | 03 | ARCH-9 |
| `gate:object-identity-from-manifest` | 04 | OBJ-13 |
| `gate:one-protocol` | 03 | ARCH-5 |
| `gate:property-domain-reference` | 08 | PROP-26 |
| `gate:property-required-attrs` | 08 | PROP-21 |
| `gate:property-resolution` | 08 | PROP-1 |
| `gate:publisher-sole-writer` | 03 | ARCH-8 |
| `gate:ref-advance-ordering` | 09 | REF-12 |
| `gate:ref-cas-only` | 01 | prose in 01 |
| `gate:ref-epoch-fencing` | 09 | REF-6 |
| `gate:ref-names` | 09 | REF-1 |
| `gate:repository-portable` | 03 | ARCH-4 |
| `gate:role-selection` | 03 | ARCH-10 |
| `gate:store-expression-static` | 03 | ARCH-6 |
| `gate:store-opaque` | 03 | ARCH-2 |
| `gate:surface-layering` | 03 | prose in 01, ARCH-3 |
| `gate:tree-acyclic` | 04 | OBJ-20 |
| `gate:tree-boundaries` | 06 | TREE-21 |
| `gate:tree-hardlinks` | 06 | TREE-11 |
| `gate:tree-history-independence` | 06 | TREE-24, TEST-3 |
| `gate:tree-keys` | 06 | TREE-1 |
| `gate:tree-well-formed` | 06 | TREE-17, TREE-30, TREE-4, TREE-8 |
| `gate:verify-before-admit` | 05 | OBJ-5, CDC-14 |
| `gate:view-identity` | 01 | prose in 01 |
| `gate:worker-no-network` | 03 | ARCH-7 |
| `gate:zstd-concat` | 05 | CDC-11 |

### Storage

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:blockdev-format-roundtrip` | 16 | BLK-1 |
| `gate:blockdev-ref-cas` | 16 | BLK-7 |
| `gate:bucket-create-once` | 13 | BKT-6 |
| `gate:bucket-etag-opaque` | 13 | BKT-7 |
| `gate:bucket-file-atomic-write` | 13 | BKT-13 |
| `gate:bucket-file-cas` | 13 | BKT-14 |
| `gate:bucket-file-layout` | 13 | STORE-13, BKT-3 |
| `gate:bucket-key-registry` | 13 | BKT-1 |
| `gate:bucket-multipart-abort` | 13 | BKT-9 |
| `gate:bucket-mutability-classes` | 13 | BKT-2 |
| `gate:bucket-probe` | 13 | BKT-10, MIG-25, TEST-7, EDGE-2, prose in 40 |
| `gate:bucket-ref-cas` | 13 | BKT-5 |
| `gate:bundle-verify` | 12 | PACK-24 |
| `gate:commit-order` | 12 | prose in 01, PACK-14 |
| `gate:gc-grace-window` | 17 | GC-10 |
| `gate:gc-mark-reachability` | 17 | GC-5 |
| `gate:gc-roots-complete` | 17 | GC-1 |
| `gate:gc-singleton-lease` | 17 | GC-22 |
| `gate:gc-two-phase-delete` | 17 | GC-15 |
| `gate:guard-single-enforcement` | 11 | STORE-22 |
| `gate:guard-validates-uploads` | 11 | STORE-23 |
| `gate:host-chunk-layout` | 14 | HOST-2 |
| `gate:host-eviction-s3fifo` | 14 | HOST-17 |
| `gate:host-layout` | 14 | HOST-1 |
| `gate:host-pin-durable` | 14 | HOST-22 |
| `gate:host-pin-never-evicted` | 14 | HOST-18 |
| `gate:host-publish-no-replace` | 14 | HOST-9 |
| `gate:host-publish-sequence` | 14 | HOST-7 |
| `gate:host-publisher-sole-writer` | 14 | HOST-6 |
| `gate:host-quarantine` | 14 | HOST-15 |
| `gate:host-quota-exact` | 14 | HOST-23 |
| `gate:host-reassembly-heuristic` | 14 | HOST-10 |
| `gate:host-reassembly-verify` | 14 | HOST-13 |
| `gate:host-reserve-then-evict` | 14 | HOST-19 |
| `gate:host-sealed-adopt` | 14 | HOST-4 |
| `gate:host-sealed-before-serve` | 14 | HOST-5 |
| `gate:host-sealed-immutable` | 14 | HOST-3 |
| `gate:host-single-residence` | 14 | HOST-11 |
| `gate:host-state-scope` | 14 | HOST-29 |
| `gate:host-two-phase-delete` | 14 | HOST-28 |
| `gate:host-verify-before-admit` | 14 | HOST-14 |
| `gate:host-wipe-on-release` | 14 | HOST-25 |
| `gate:index-epoch-manifest` | 13 | BKT-4 |
| `gate:index-filter` | 12 | PACK-21 |
| `gate:index-filter-hint-only` | 12 | PACK-22 |
| `gate:index-rebuild` | 12 | PACK-20 |
| `gate:index-shard-epochs` | 12 | PACK-17 |
| `gate:index-tombstones` | 12 | PACK-18 |
| `gate:pack-footer-crc` | 12 | PACK-7 |
| `gate:pack-header` | 12 | PACK-1 |
| `gate:pack-id-unique` | 12 | PACK-2 |
| `gate:pack-idx-object` | 12 | PACK-15 |
| `gate:pack-index-consistent` | 12 | PACK-4, PACK-5 |
| `gate:pack-index-sorted` | 12 | PACK-3 |
| `gate:pack-kind-domain` | 12 | PACK-6 |
| `gate:pack-meta-separation` | 12 | PACK-13 |
| `gate:pack-scan-recovery` | 12 | PACK-9 |
| `gate:pack-self-describing` | 12 | PACK-8 |
| `gate:pack-single-writer` | 12 | PACK-10 |
| `gate:pack-tree-locality` | 12 | PACK-12 |
| `gate:redundancy-placement-deterministic` | 15 | RED-11 |
| `gate:redundancy-quorum-refs` | 15 | RED-25 |
| `gate:redundancy-replicated-ack` | 15 | RED-1 |
| `gate:redundancy-striped-reconstruct` | 15 | RED-4 |
| `gate:redundancy-verify-on-read` | 15 | RED-17 |
| `gate:shared-dir-read-only` | 11 | STORE-14 |
| `gate:store-capability-probe` | 11 | STORE-12, STORE-9 |
| `gate:store-error-taxonomy` | 11 | STORE-30 |
| `gate:store-expression-validate` | 11 | STORE-27, STORE-28 |
| `gate:store-has-batched` | 11 | STORE-5 |
| `gate:store-idempotent-put` | 11 | STORE-1 |
| `gate:store-list-not-authoritative` | 11 | STORE-11 |
| `gate:store-ranged-get` | 11 | STORE-4 |
| `gate:store-ref-cas` | 11 | STORE-7 |
| `gate:store-ref-forwarding` | 11 | STORE-10 |
| `gate:store-ref-log-append-once` | 11 | STORE-8 |
| `gate:store-verify-on-get` | 11 | STORE-3 |
| `gate:store-verify-on-put` | 11 | STORE-2 |
| `gate:tiered-read-order` | 11 | STORE-17 |
| `gate:tiered-write-authority` | 11 | STORE-18 |

### Distribution

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:auth-enforcement` | 18 | PROTO-22, PROTO-25, PROTO-46, PROTO-5 |
| `gate:bandwidth-negotiate-delta` | 21 | BW-1 |
| `gate:bandwidth-wire-delta-roundtrip` | 21 | BW-12 |
| `gate:chunk-verify` | 18 | PROTO-21 |
| `gate:cons-commit-visibility` | 20 | CONS-11, CONS-12, CONS-3, CONS-4 |
| `gate:cons-control` | 20 | CONS-34, CONS-35, CONS-36, CONS-37 |
| `gate:cons-durability` | 20 | CONS-14, CONS-15, CONS-16, CONS-6 |
| `gate:cons-errors` | 20 | CONS-25, CONS-26 |
| `gate:cons-fencing` | 20 | CONS-17, CONS-18, CONS-19, CONS-20 |
| `gate:cons-follow-atomic` | 20 | CONS-29, CONS-30 |
| `gate:cons-fsync-sticky` | 20 | CONS-24 |
| `gate:cons-local` | 20 | CONS-1, CONS-2 |
| `gate:cons-multiwriter` | 20 | CONS-21, CONS-22, CONS-23 |
| `gate:cons-reader-modes` | 20 | CONS-28, CONS-31, CONS-32 |
| `gate:cons-ref-freshness` | 19 | PROTO-26, TOPO-28 |
| `gate:cons-sync-fsync` | 20 | CONS-10, CONS-27 |
| `gate:cons-table` | 20 | CONS-33 |
| `gate:cons-writer-modes` | 20 | CONS-13, CONS-7, CONS-8, CONS-9 |
| `gate:dom-oracle` | 18 | PROTO-35 |
| `gate:gc-multiregion` | 19 | TOPO-41, TOPO-42 |
| `gate:obs-trace` | 18 | PROTO-41 |
| `gate:pack-verify` | 18 | PROTO-13, PROTO-14 |
| `gate:proto-bundle` | 18 | PROTO-23 |
| `gate:proto-conformance` | 18 | PROTO-52, PROTO-6, TEST-13 |
| `gate:proto-direct-upload` | 18 | PROTO-17 |
| `gate:proto-errors` | 18 | PROTO-45, PROTO-47 |
| `gate:proto-filter` | 18 | PROTO-33 |
| `gate:proto-idempotent` | 18 | PROTO-15, PROTO-43 |
| `gate:proto-index` | 18 | PROTO-34 |
| `gate:proto-negotiate` | 18 | PROTO-10, PROTO-11, PROTO-7, PROTO-8, PROTO-9 |
| `gate:proto-presign` | 18 | PROTO-18, PROTO-19 |
| `gate:proto-reads` | 18 | PROTO-20 |
| `gate:proto-schema` | 18 | PROTO-3, PROTO-48, PROTO-49, PROTO-50 |
| `gate:proto-transport` | 18 | PROTO-1, PROTO-2, PROTO-4 |
| `gate:ref-cas` | 18 | PROTO-27, PROTO-28, PROTO-29, CONS-5 |
| `gate:ref-log` | 18 | PROTO-30 |
| `gate:ref-watch` | 18 | PROTO-31, PROTO-32 |
| `gate:topo-breaker` | 19 | TOPO-7 |
| `gate:topo-costs` | 19 | TOPO-4, TOPO-5 |
| `gate:topo-home` | 19 | TOPO-26, TOPO-27, TOPO-29 |
| `gate:topo-hops` | 19 | PROTO-40, TOPO-12, TOPO-13, TOPO-14 |
| `gate:topo-labels` | 19 | TOPO-1, TOPO-2, TOPO-3 |
| `gate:topo-nesting` | 18 | PROTO-53 |
| `gate:topo-partition` | 19 | TOPO-38, TOPO-39, TOPO-40 |
| `gate:topo-peers` | 19 | TOPO-15, TOPO-16, TOPO-17 |
| `gate:topo-promisor` | 19 | TOPO-30, TOPO-31 |
| `gate:topo-replicate` | 19 | TOPO-33, TOPO-34, TOPO-35, TOPO-36 |
| `gate:topo-residency` | 19 | PROTO-36, PROTO-37, TOPO-18, TOPO-19, TOPO-21 |
| `gate:topo-selection` | 19 | TOPO-11, TOPO-8, TOPO-9 |
| `gate:topo-warm` | 19 | PROTO-38, TOPO-22, TOPO-23 |

### Security

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:auth-acl-intersection` | 22 | AUTH-26 |
| `gate:auth-attenuation-monotone` | 22 | AUTH-14 |
| `gate:auth-attenuation-offline` | 22 | AUTH-16 |
| `gate:auth-mtls` | 22 | AUTH-4 |
| `gate:auth-oidc-login` | 22 | AUTH-2 |
| `gate:auth-single-enforcement` | 22 | AUTH-31 |
| `gate:auth-surface-commit-scope` | 22 | AUTH-36 |
| `gate:auth-token-chain` | 22 | AUTH-7 |
| `gate:auth-verify-pure` | 22 | AUTH-11 |
| `gate:auth-workload-mint` | 22 | AUTH-3 |
| `gate:dom-dedup-scope` | 24 | DOM-8 |
| `gate:dom-default-private` | 24 | DOM-1 |
| `gate:dom-existence-oracle` | 24 | DOM-16 |
| `gate:dom-host-isolation` | 24 | DOM-12 |
| `gate:dom-reference-order` | 24 | DOM-5 |
| `gate:dom-wipe` | 24 | DOM-18 |
| `gate:prov-commit-signature` | 23 | PROV-2 |
| `gate:prov-commit-verify` | 23 | PROV-4 |
| `gate:prov-entry-preserve` | 23 | PROV-8 |
| `gate:prov-fold-acceptance` | 23 | PROV-17 |
| `gate:prov-selector-profiles` | 23 | PROV-12 |

### Surfaces

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:block-layout-determinism` | 28 | VBLK-1, TEST-12 |
| `gate:erofs-image-determinism` | 28 | EROFS-1, TEST-12 |
| `gate:erofs-verity` | 28 | EROFS-7 |
| `gate:fuse-index-roundtrip` | 27 | FUSE-7 |
| `gate:fuse-object-scope` | 27 | FUSE-3 |
| `gate:fuse-passthrough` | 27 | FUSE-13 |
| `gate:fuse-upper-isolation` | 27 | FUSE-32 |
| `gate:fuse-verify-before-serve` | 27 | FUSE-26 |
| `gate:fuse-worker-isolation` | 27 | FUSE-1, FUSE-2 |
| `gate:nix-frame-concat` | 30 | NIX-6 |
| `gate:nix-surface-stream` | 30 | EDGE-6 |
| `gate:reapi-completeness` | 30 | REAPI-3 |
| `gate:ruleset-blessed-targets` | 31 | RULE-10 |
| `gate:ruleset-derived-root` | 31 | RULE-21 |
| `gate:ruleset-eval-order` | 31 | RULE-15 |
| `gate:ruleset-magic-memo` | 31 | RULE-6 |
| `gate:surface-commit-path` | 26 | SURF-16 |
| `gate:surface-interface` | 26 | SURF-1, SURF-2 |
| `gate:surface-schema` | 26 | SURF-13, NIX-4, OCI-1, REAPI-1 |
| `gate:surface-status` | 26 | SURF-27 |
| `gate:vm-export-scope` | 29 | VM-1 |
| `gate:vm-no-duplication` | 29 | VM-10 |
| `gate:vm-upload-validation` | 29 | VM-16 |

### Operations

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:blockdev-crash-recovery` | 36 | TEST-10 |
| `gate:gc-reflog-roots` | 33 | MIG-33 |
| `gate:host-crash-recovery` | 36 | HOST-32, TEST-9 |
| `gate:job-fold` | 32 | JOB-19 |
| `gate:job-follow` | 32 | JOB-23 |
| `gate:job-idempotent` | 32 | JOB-15 |
| `gate:job-memo` | 32 | JOB-16 |
| `gate:job-ref-lifecycle` | 32 | JOB-1, JOB-2 |
| `gate:job-resume` | 32 | JOB-17, JOB-3, TEST-11 |
| `gate:job-shards` | 32 | JOB-6, JOB-7 |
| `gate:job-uniform-access` | 32 | JOB-31 |
| `gate:merge-native-parity` | 36 | TEST-5 |
| `gate:mig-chunk-read` | 33 | MIG-17 |
| `gate:mig-digest-coexist` | 33 | MIG-30 |
| `gate:mig-import-branch` | 33 | MIG-1 |
| `gate:mig-import-idempotent` | 33 | MIG-3 |
| `gate:mig-import-verify` | 33 | MIG-2 |
| `gate:mig-layout` | 33 | MIG-8 |
| `gate:mig-layout-merge` | 33 | MIG-10 |
| `gate:mig-profile-identity` | 33 | MIG-14 |
| `gate:mig-profile-read` | 33 | MIG-13 |
| `gate:mig-rechunk` | 33 | MIG-18 |
| `gate:mig-reindex` | 33 | MIG-6 |
| `gate:mig-split-join` | 33 | MIG-27 |
| `gate:mig-store-move` | 33 | MIG-22 |
| `gate:obs-blame` | 34 | OBS-13 |
| `gate:obs-decision-log` | 34 | OBS-4 |
| `gate:obs-hop-latency` | 34 | OBS-2 |
| `gate:obs-metrics` | 34 | OBS-11 |
| `gate:obs-status-surface` | 34 | OBS-7 |
| `gate:obs-trace-propagation` | 34 | OBS-1 |
| `gate:perf-cold-closure` | 35 | prose in 35 |
| `gate:perf-cold-mount` | 35 | prose in 35 |
| `gate:perf-cold-span` | 35 | prose in 35, PERF-2 |
| `gate:perf-commit-delta` | 35 | prose in 35, PERF-5 |
| `gate:perf-commit-latency` | 35 | prose in 35 |
| `gate:perf-erofs-gen` | 35 | prose in 35 |
| `gate:perf-fork` | 35 | prose in 35 |
| `gate:perf-fsync-sync` | 35 | prose in 35 |
| `gate:perf-gateway-memory` | 35 | prose in 35 |
| `gate:perf-gateway-rps` | 35 | prose in 35 |
| `gate:perf-gateway-zero-copy` | 35 | prose in 35, PERF-9 |
| `gate:perf-gc-mark` | 35 | prose in 35 |
| `gate:perf-hot-read` | 35 | prose in 35, PERF-1 |
| `gate:perf-index-size` | 35 | prose in 35 |
| `gate:perf-inode-memory` | 35 | prose in 35, PERF-7 |
| `gate:perf-merge-delta` | 35 | prose in 35, PERF-6, TEST-4 |
| `gate:perf-methodology` | 35 | PERF-11 |
| `gate:perf-negotiation` | 35 | prose in 35 |
| `gate:perf-nested-zero-dup` | 35 | prose in 35 |
| `gate:perf-no-bookkeeping-on-read` | 35 | prose in 35, PERF-8 |
| `gate:perf-readdir` | 35 | prose in 35, PERF-3 |
| `gate:perf-shared-page-cache` | 35 | prose in 35, PERF-10 |
| `gate:perf-warm-mount` | 35 | prose in 35, PERF-4 |
| `gate:perf-warm-read` | 35 | prose in 35 |
| `gate:perf-worker-rss` | 35 | prose in 35 |
| `gate:registry-complete` | 36 | TEST-16 |
| `gate:tier-chaos` | 36 | TEST-8 |

### Engineering

| Gate | Owner | Enforces |
| --- | --- | --- |
| `gate:core-fuzz` | 37 | TEST-3, CRATE-33, CRATE-4 |
| `gate:core-no-std` | 37 | CRATE-1, CRATE-21 |
| `gate:crate-graph` | 37 | CRATE-19 |
| `gate:edge-native-interop` | 38 | EDGE-14 |
| `gate:exec-through-overlay` | 40 | prose in 40 |
| `gate:feature-matrix` | 37 | CRATE-28, CRATE-29, CRATE-8 |
| `gate:golden-vectors` | 37 | TEST-1, CRATE-2, CRATE-3 |
| `gate:lint` | 37 | CRATE-39 |
| `gate:negotiation-bytes` | 40 | prose in 40 |
| `gate:perf-write-path` | 40 | prose in 40 |
| `gate:routing-stability` | 40 | prose in 40 |
| `gate:runtime-agnostic` | 37 | CRATE-7 |
| `gate:tree-node-distribution` | 40 | prose in 40 |
| `gate:unsafe-audit` | 37 | CRATE-30, CRATE-31 |

- **[TEST-16]** Every `gate:` name cited anywhere in files `01` through
  `38` and in the normative reference documents MUST appear exactly once in
  the registry, and every registry row MUST name at least one citing
  requirement. *Gate:* `gate:registry-complete`.

## Ungated requirements

Per [CONV-1], `MUST` requirements that name no gate are listed here with the
reason.

| Requirement | Reason |
| --- | --- |
| G-1 to G-12 | goal and invariant statements; each is enforced through the gates of the files that realize it |
| ARCH-11 | architectural statement enforced by the layering and role gates named in 03 |
| OBJ-2, OBJ-9 to OBJ-11, OBJ-14, OBJ-15, OBJ-17, OBJ-19, OBJ-21, OBJ-22 | identity and descriptor rules exercised by `gate:identity-idempotence`, `gate:descriptor-strict`, and `gate:core-fuzz` as scenarios |
| CDC-3 to CDC-5, CDC-8, CDC-9, CDC-13, CDC-15, CDC-17 to CDC-19 | chunking and codec rules exercised by `gate:cdc-boundaries`, `gate:chunk-codec`, and `gate:core-fuzz` as scenarios |
| TREE-2, TREE-5 to TREE-7, TREE-14 to TREE-16, TREE-31, TREE-32, TREE-18, TREE-19, TREE-33, TREE-20, TREE-23, TREE-26, TREE-27, TREE-29 | encoding and well-formedness rules exercised by `gate:canonical-cbor`, `gate:tree-well-formed`, and `gate:core-fuzz` as scenarios |
| ALG-2 to ALG-11, ALG-13, ALG-14, ALG-16, ALG-17, ALG-19 to ALG-29, ALG-31, ALG-33, ALG-34 | algebra semantics exercised by the `gate:algebra-*` suite and `gate:merge-native-parity` as scenarios |
| PROP-2 to PROP-6, PROP-8, PROP-10, PROP-12, PROP-14 to PROP-20, PROP-22 to PROP-25, PROP-27, PROP-28 | property semantics exercised by `gate:property-resolution` and `gate:property-required-attrs` as scenarios |
| REF-2, REF-3, REF-5, REF-7 to REF-9, REF-11, REF-13 to REF-15, REF-17 to REF-19, REF-21, REF-23 to REF-30 | ref and commit rules exercised by `gate:ref-cas`, `gate:ref-epoch-fencing`, and `gate:ref-advance-ordering` as scenarios |
| DRV-2, DRV-4 to DRV-6, DRV-8 to DRV-11, DRV-13 to DRV-20 | derived-data rules exercised by `gate:derived-attr-record` and `gate:index-tree-maintenance` as scenarios |
| STORE-6, STORE-15, STORE-16, STORE-19, STORE-20, STORE-24 to STORE-26, STORE-29, STORE-31 | store semantics exercised by the `gate:store-*` conformance suite as scenarios |
| PACK-11, PACK-16, PACK-19, PACK-23, PACK-25, PACK-27, PACK-28 | pack and index rules exercised by the `gate:pack-*` and `gate:index-*` checks as scenarios |
| BKT-8, BKT-11, BKT-12, BKT-15, BKT-16 | bucket rules exercised by `gate:bucket-probe`, `gate:bucket-ref-cas`, and `gate:bucket-file-layout` as scenarios |
| HOST-12, HOST-16, HOST-20, HOST-21, HOST-24, HOST-26, HOST-27, HOST-30, HOST-31, HOST-33, HOST-35 to HOST-37 | host-tier behavior exercised by the `gate:host-*` checks and `gate:host-crash-recovery` as scenarios |
| RED-2, RED-3, RED-5 to RED-9, RED-13 to RED-16, RED-18 to RED-24, RED-26 to RED-31, RED-33 | redundancy behavior exercised by the `gate:redundancy-*` checks and `gate:tier-chaos` as scenarios |
| BLK-2 to BLK-6, BLK-8 to BLK-16, BLK-19 | block-device behavior exercised by `gate:blockdev-format-roundtrip`, `gate:blockdev-ref-cas`, and `gate:blockdev-crash-recovery` as scenarios |
| GC-2, GC-4, GC-6 to GC-9, GC-11 to GC-14, GC-16 to GC-21, GC-23 to GC-28 | collector behavior exercised by the `gate:gc-*` checks as scenarios |
| PROTO-24, PROTO-39, PROTO-42, PROTO-44, PROTO-51, PROTO-54 | protocol rules exercised by `gate:proto-conformance` and the other `gate:proto-*` checks as scenarios |
| TOPO-10, TOPO-20, TOPO-37 | topology behavior exercised by the `gate:topo-*` checks and `gate:tier-chaos` as scenarios |
| CONS-38 | consistency rules exercised by the `gate:cons-*` checks as scenarios |
| BW-2 to BW-8, BW-10, BW-11, BW-13 to BW-15, BW-17 to BW-22 | bandwidth rules exercised by `gate:bandwidth-negotiate-delta`, `gate:negotiation-bytes`, and `gate:bandwidth-wire-delta-roundtrip` as scenarios |
| AUTH-1, AUTH-5, AUTH-6, AUTH-8 to AUTH-10, AUTH-12, AUTH-13, AUTH-15, AUTH-17, AUTH-18, AUTH-20 to AUTH-25, AUTH-27 to AUTH-30, AUTH-32 to AUTH-35, AUTH-37 to AUTH-44 | authorization rules exercised by the `gate:auth-*` checks as scenarios |
| PROV-1, PROV-3, PROV-5 to PROV-7, PROV-9, PROV-10, PROV-13 to PROV-16, PROV-18 to PROV-20, PROV-22 to PROV-25 | provenance rules exercised by the `gate:prov-*` checks as scenarios |
| DOM-2 to DOM-4, DOM-6, DOM-7, DOM-9 to DOM-11, DOM-13 to DOM-15, DOM-17, DOM-19 to DOM-23 | domain rules exercised by the `gate:dom-*` checks as scenarios |
| THREAT-1 | residual-risk statement; reviewed, not automatically checked |
| SURF-3 to SURF-12, SURF-14, SURF-15, SURF-17 to SURF-26, SURF-28 to SURF-32 | surface interface rules exercised by `gate:surface-interface`, `gate:surface-schema`, `gate:surface-commit-path`, and `gate:surface-status` as scenarios |
| FUSE-4 to FUSE-6, FUSE-8 to FUSE-12, FUSE-14 to FUSE-25, FUSE-27 to FUSE-31, FUSE-33 to FUSE-50 | FUSE behavior exercised by the `gate:fuse-*` checks and `gate:exec-through-overlay` as scenarios |
| EROFS-2 to EROFS-6, EROFS-8 to EROFS-15, VBLK-2 to VBLK-9, VBLK-11 to VBLK-13 | image and block-layout rules exercised by `gate:erofs-image-determinism`, `gate:erofs-verity`, and `gate:block-layout-determinism` as scenarios |
| VM-2 to VM-9, VM-11 to VM-15, VM-17, VM-18 | guest rules exercised by the `gate:vm-*` checks as scenarios |
| NIX-1 to NIX-3, NIX-5, NIX-7 to NIX-13, REAPI-2, REAPI-4 to REAPI-8, GHA-1 to GHA-6, GHA-8, GIT-1 to GIT-9, OCI-2 to OCI-7, WEB-1 to WEB-3, WEB-5 to WEB-7 | protocol-surface rules exercised by `gate:surface-schema`, `gate:nix-frame-concat`, `gate:reapi-completeness`, and `gate:proto-conformance` as scenarios |
| RULE-1, RULE-2, RULE-5, RULE-7 to RULE-9, RULE-11 to RULE-14, RULE-16 to RULE-20, RULE-22 to RULE-28 | ruleset semantics exercised by the `gate:ruleset-*` checks as scenarios |
| JOB-4, JOB-8 to JOB-14, JOB-18, JOB-20, JOB-21, JOB-24, JOB-26 to JOB-30, JOB-32, JOB-33 | behavioral requirements exercised by `gate:job-resume`, `gate:job-fold`, and `gate:job-follow` as scenarios rather than as separate checks |
| MIG-4, MIG-5, MIG-7, MIG-9, MIG-15, MIG-16, MIG-19 to MIG-21, MIG-23, MIG-24, MIG-26, MIG-28, MIG-29, MIG-31, MIG-32 | covered as scenarios inside the named `gate:mig-*` checks for their migration kind |
| OBS-3, OBS-5, OBS-6, OBS-8 to OBS-10, OBS-12, OBS-14 to OBS-17 | inspected by the status and metrics gates as scenarios; log content rules are reviewed, not automatically checked |
| PERF-12, PERF-13 | reporting rules enforced by review of a conformance claim |
| CRATE-6, CRATE-9 to CRATE-11, CRATE-13 to CRATE-18, CRATE-20, CRATE-22 to CRATE-27, CRATE-32, CRATE-34 to CRATE-38, CRATE-40 to CRATE-42, CRATE-44 | crate-structure rules enforced by `gate:crate-graph`, `gate:lint`, `gate:unsafe-audit`, and `gate:feature-matrix`; the rest are reviewed |
| EDGE-1, EDGE-3 to EDGE-5, EDGE-7 to EDGE-13, EDGE-15 to EDGE-22 | edge rules exercised by `gate:edge-native-interop` and the surface gates; host limits are reviewed |
| TEST-2, TEST-6 to TEST-9, TEST-14, TEST-15 | define suites; enforced by the gates they name |

## Conformance claims

- **[TEST-17]** A conformance claim MUST name the specification version, the
  levels claimed, every surface claimed by name, the gates run with their
  results, the performance results with the configuration used, and the
  list of `SHOULD` deviations with rationale. It MUST be reproducible from a
  named commit of the implementation.
- **[TEST-18]** A claim MUST NOT include a level whose files contain any
  `MUST` whose gate failed or was not run, and MUST NOT claim a surface whose
  schema check ([`26-surfaces.md`](26-surfaces.md)) failed.

```text
Terrane conformance claim
  specification: 1.0-draft-1
  implementation: <name> <version> <commit>
  levels: Core, Distribution, Security, Host
  surfaces: fuse, erofs, nix-cache, browse
  gates: <n> passed, 0 failed, 0 skipped   (attached: results.json)
  performance: attached results with reference-configuration deviations
  deviations: <SHOULD id>: <rationale> ...
```

## Interactions

- [`00-conventions.md`](00-conventions.md) defines gates and [CONV-1].
- [`35-performance-targets.md`](35-performance-targets.md) defines the
  measurement rules for `gate:perf-*`.
- [`37-crate-structure.md`](37-crate-structure.md) owns the engineering
  gates and the fuzz and golden-vector harnesses.
- [`reference/golden-vectors.md`](reference/golden-vectors.md) and
  [`reference/protocol.md`](reference/protocol.md) are the inputs to
  `gate:golden-vectors` and `gate:proto-conformance`.
- Every other file cites gates registered here.
