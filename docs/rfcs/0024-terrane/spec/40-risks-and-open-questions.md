# 40 — Risks and open questions

This file records the places where the design rests on an assumption that
has not yet been validated, the spike or gate that will validate each one,
and the questions the specification deliberately leaves open. It is
informative ([`00-conventions.md`](00-conventions.md)): a `RISK-n` entry is
a tracked uncertainty, not a requirement. Each entry names the requirements
it would force to change if the assumption fails.

Each entry has a fixed shape:

```text
- **[RISK-n] <one-line title>**
  - **Assumption:** what the design takes for granted.
  - **If wrong:** what breaks and which requirements move.
  - **Spike:** the experiment or gate that settles it, and when it runs.
  - **Fallback:** the design change if the spike fails.
```

## Storage backends

- **[RISK-1] Conditional writes across S3-compatible stores and proxies.**
  - **Assumption:** Every supported bucket supports create-if-absent and
    compare-and-swap on a single object, and every proxy in the path passes
    the conditional headers through.
  - **If wrong:** Ref writes are unsafe under concurrency on that backend.
    `BKT` and `REF` requirements for multi-writer operation cannot be met
    there; single-writer operation remains sound.
  - **Spike:** `gate:bucket-probe` runs at startup against the
    configured bucket and performs a real create-if-absent race and a real
    compare-and-swap with a stale tag. Run against the major cloud providers,
    at least two self-hosted S3-compatible servers, and one proxy before
    1.0. Results are recorded in the conformance report.
  - **Fallback:** The instance refuses multi-writer ref operations on a
    failing backend and records the reason; operators either fix the path or
    run single-writer with an external lock. The specification already
    requires the refusal ([`13-bucket-layout.md`](13-bucket-layout.md)).

- **[RISK-2] A zstd encoder on `wasm32`.**
  - **Assumption:** Edge implementations do not need to encode zstd, because
    clients submit compressed chunks and the edge only decodes for
    verification ([`38-wasm-and-edge.md`](38-wasm-and-edge.md) `EDGE-18`).
  - **If wrong:** Some edge write path needs server-side compression, for
    example a protocol surface whose clients cannot compress. A
    production-quality pure-Rust encoder with dictionary support is not
    something the design relies on.
  - **Spike:** Enumerate every edge write path in
    `reference/surface-registry.md` and confirm each either receives
    compressed chunks or is excluded at the edge. Measure a C zstd encoder
    compiled to `wasm32` under the request budget as a contingency.
  - **Fallback:** Exclude the affected surface's write path from the edge
    conformance claim, or ship the compiled C encoder behind a feature.

- **[RISK-3] Quota exactness in a bucket-only warehouse.**
  - **Assumption:** Eventually consistent quotas computed from index sums,
    enforced as a soft limit at commit, are acceptable for a warehouse.
    Exact quotas exist only on host tiers where one process owns the bytes.
  - **If wrong:** An operator needs a hard cap on a shared bucket tier. `PROP`
    quota semantics and `HOST` reservation semantics would need a
    warehouse-side counterpart.
  - **Spike:** Model the overshoot bound as (commit rate × grace window ×
    largest commit) and confirm it against the sizes of expected deployments
    before 1.0.
  - **Fallback:** A quota ledger object per root updated by compare-and-swap
    at commit, serialized per root. It costs one extra conditional write per
    commit on roots that opt in, and it stays within [D-1].

- **[RISK-4] Block-surface writes.**
  - **Assumption:** No 1.0 workload needs a guest's block-level writes
    committed into the shared tree ([`39-decision-register.md`](39-decision-register.md)
    `D-18`).
  - **If wrong:** A guest without a virtiofs driver needs its results
    captured. `VBLK` gains a commit path requiring host-side mount and diff
    of the guest's copy-on-write device.
  - **Spike:** Survey the guest kernels and images expected in the first
    deployments for virtiofs support; run one guest with a copy-on-write
    device and measure a host-side diff at commit.
  - **Fallback:** Specify block commit as a later minor version with the
    diff-at-commit design; the layout already supports it.

## Trees and identity

- **[RISK-5] Prolly-tree boundary variance.**
  - **Assumption:** The boundary function with size-scaled probability
    ([`06-tree-format.md`](06-tree-format.md)) keeps node sizes within the
    target band, so a one-entry change touches O(log n) nodes and no node
    grows without bound.
  - **If wrong:** Long runs without a boundary produce oversized nodes,
    making small changes expensive and bundles large. `TREE` size bounds
    would need a hard cap with a non-content-defined split, which weakens
    history independence.
  - **Spike:** `gate:tree-node-distribution` builds trees from adversarial
    key sets (sequential names, identical prefixes, hash-like names) and
    asserts the node-size distribution. Runs in the conformance suite.
  - **Fallback:** Add a hard maximum with a deterministic split rule that
    remains a pure function of content, and record the change in `TREE`.

- **[RISK-6] Existence oracles under global deduplication.**
  - **Assumption:** In a globally deduplicating domain, a negotiation reply
    revealing that a chunk already exists is an acceptable side channel when
    rate-limited and confined to principals with write authority on some
    root in that domain ([`25-threat-model.md`](25-threat-model.md)).
  - **If wrong:** A deployment cannot accept that a writer learns whether
    another tenant holds a given chunk. `DOM` defaults change and `D-21`
    resolves toward per-domain buckets.
  - **Spike:** Threat-model review with the first two adopting deployments
    before the default in `D-21` is fixed.
  - **Fallback:** Per-domain dedup scoping by default, with global dedup as
    an explicit opt-in per root.

## Scale

- **[RISK-7] Index filter size at billions of chunks.**
  - **Assumption:** A compact approximate-membership filter at roughly one
    byte per chunk is small enough to hold on every host tier and refresh by
    epoch delta ([`12-pack-format.md`](12-pack-format.md),
    [`21-bandwidth.md`](21-bandwidth.md)).
  - **If wrong:** At several billion chunks the filter is several gigabytes
    per host, and refresh traffic dominates. `BW` negotiation would need a
    tiered filter or server-side negotiation for cold hosts.
  - **Spike:** Compute filter sizes for the largest expected store and
    measure epoch-delta refresh cost; run `gate:negotiation-bytes` at that
    scale.
  - **Fallback:** Per-root or per-shard filters fetched on demand, with
    server-side batched `has` as the path for hosts that hold no filter.

- **[RISK-8] Cross-region garbage-collection coordination.**
  - **Assumption:** Marking across every region before sweeping any
    ([`17-garbage-collection.md`](17-garbage-collection.md),
    [`19-tiering-and-topology.md`](19-tiering-and-topology.md)) costs an
    acceptable amount of cross-region metadata traffic and finishes within
    the grace window.
  - **If wrong:** A mark that cannot complete in time forces the grace
    window up, which delays reclamation and inflates storage. `GC` timing
    requirements move.
  - **Spike:** Simulate a three-region store with realistic ref counts and
    measure mark duration and bytes; confirm that marking reads only tree
    nodes and never packs.
  - **Fallback:** Per-region marking with a union of root sets exchanged as
    small objects, so no region walks another region's trees.

- **[RISK-9] Multipart-upload orphans on lost races.**
  - **Assumption:** A multipart pack upload whose completion loses a
    conditional-write race is aborted by the writer, and a periodic sweep
    catches the rest ([`13-bucket-layout.md`](13-bucket-layout.md)).
  - **If wrong:** Orphaned multipart uploads accumulate billable storage
    invisibly. Packs are content-addressed and never conditionally written,
    so the exposure is limited to writers that crash mid-upload.
  - **Spike:** Measure orphan accumulation under a crash-injection run of
    the writer; confirm the sweep's list-and-abort cost.
  - **Fallback:** A bucket lifecycle rule aborting incomplete uploads after
    a fixed age, recommended in `BKT` as operator guidance.

## Performance

- **[RISK-10] FUSE performance for write-heavy workloads.**
  - **Assumption:** Writes go to an upper directory on the host filesystem
    and never through the FUSE surface, so FUSE overhead applies only to
    reads of the lower tree ([`27-surface-fuse.md`](27-surface-fuse.md)).
  - **If wrong:** A workload writes through a path the overlay routes to the
    FUSE lower (for example, a copy-up storm on a huge file) and pays FUSE
    costs per operation. `PERF` write budgets would not hold.
  - **Spike:** `gate:perf-write-path` measures a copy-up-heavy build over
    an overlay whose lower is the FUSE surface, with and without the EROFS
    surface as lower.
  - **Fallback:** Prefer the EROFS surface as the overlay lower for resident
    trees; use redirections for known-hot output directories, both already
    specified as hints.

- **[RISK-11] Executing through overlay-over-FUSE.**
  - **Assumption:** With passthrough registration and a stack depth of one,
    execution of binaries through an overlay whose lower is the FUSE surface
    works on supported kernels.
  - **If wrong:** Some kernel versions return I/O errors on `execve` through
    that stack, as has been observed in other systems. `FUSE` and `EROFS`
    realizer selection rules change.
  - **Spike:** `gate:exec-through-overlay` runs a matrix of supported kernel
    versions executing static and dynamic binaries through both realizers.
  - **Fallback:** Use the EROFS surface for resident trees, and materialize
    executables into the upper on the lazy path, at the cost of copies.

- **[RISK-12] Oscillation in learned cost routing.**
  - **Assumption:** Cost vectors with decay and hysteresis
    ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)) converge
    rather than flapping between near-equal children.
  - **If wrong:** Requests alternate between tiers, defeating cache locality
    and inflating cross-zone traffic. `TOPO` ordering rules change.
  - **Spike:** Simulate two children with overlapping latency distributions
    and a third with intermittent degradation; assert bounded switching
    frequency under `gate:routing-stability`.
  - **Fallback:** Add a minimum dwell time per ordering decision and a
    switching-cost term to the cost function.

## Open questions

These are not risks to an assumption; they are choices the specification
has not made. Each is cross-referenced to its decision-register entry where
one exists.

1. **Default dedup scope.** Global versus per-domain by default;
   [`39-decision-register.md`](39-decision-register.md) `D-21`, `RISK-6`.
2. **First realizer.** FUSE first or EROFS first; `D-22`.
3. **Chunk minimum size.** Whether 256 KiB is the right floor for workloads
   dominated by small random reads, given that verification requires the
   whole chunk ([`05-chunking.md`](05-chunking.md)).
4. **Dictionary training.** Who trains per-class compression dictionaries,
   how they are versioned, and how a class is assigned to an entry before
   its content has been seen ([`21-bandwidth.md`](21-bandwidth.md)).
5. **Encryption at rest.** The per-domain key model and where keys are held
   when the guard is the only enforcement point
   ([`25-threat-model.md`](25-threat-model.md)); slated for a later minor
   version.
6. **Quorum refs.** Whether the majority compare-and-swap protocol for refs
   over redundant children ([`15-redundancy.md`](15-redundancy.md)) is worth
   specifying in 1.0 or whether a single authority child suffices for every
   early deployment.
7. **Git projection fidelity.** How much of git's semantics the git surface
   must honor beyond read-only clone and fetch, and whether per-entry git
   blob digests are computed by default or by property
   ([`30-surface-protocols.md`](30-surface-protocols.md)).
8. **Native working tree.** Whether a future version replaces the host
   filesystem under the upper with a Terrane-owned log-structured working
   tree. Explicitly out of scope for 1.0 and not precluded by any format.
