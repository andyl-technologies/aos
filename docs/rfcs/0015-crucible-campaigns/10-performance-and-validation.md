# 10 — Performance model, acceptance targets, and validation gates

Campaigns are useful only if logical width is cheap and active execution stays
bounded. Correctness gates prove equivalence among realization tiers;
performance gates prove that hot branching actually improves the cost model.

## 10.1 Cost model

For a campaign with latent possibilities `L`, admitted attempts `A`, runnable
worlds `R`, hot parent state `H`, branch deltas `D_i`, and durable unique objects
`U`, the intended resource model is:

```text
campaign metadata      O(A + observations + compact frontier projections), not O(L)
live memory            O(H + active rings + sum(D_i for live branches)), not O(R * H)
durable storage        O(U), with content and parent-delta deduplication
planner work           O(log(open expansions) + generator poll + path credit)
fork setup             O(process/page-table metadata + isolated small resources),
                       with no eager copy of guest RAM
```

Operating-system process fork may copy page tables proportional to mapped RAM,
so this RFC does not claim mathematically constant fork time. It requires that
guest RAM contents remain shared and that fork cost be dramatically below
serializing/restoring the same world.

- **[CPERF-1]** Increasing the cardinality of an unenumerated integer domain
  without admitting more proposals MUST NOT increase stored frontier size or
  daemon memory beyond constant-size domain metadata.
- **[CPERF-2]** Creating `N` idle hot children from one template MUST not copy
  `N * guest RAM`. Unique RSS and storage must be explainable as template state,
  branch-private rings/metadata, page tables, and actual dirty deltas.

## 10.2 Required metrics

The performance harness records:

```text
campaign_projection_rebuild_objects
campaign_projection_rebuild_bytes
planner_poll_ns
planner_ready_expansions
proposal_publish_bytes
attempt_queue_latency_operational

template_prepare_latency
hot_fork_child_ready_latency
world_fork_ready_latency
hot_fork_page_table_bytes
child_private_rss_before_resume
child_dirty_rss_after_work
branch_overlay_bytes
fork_failures_by_stage

exact_capture_latency
exact_capture_read_bytes
exact_capture_unique_bytes
exact_restore_latency
thin_replay_latency_and_suffix

scenarios_per_core_hour
useful_observations_per_core_hour
coverage_gain_per_attempt
finding_discovery_attempt
hot_template_hit_rate
```

Wall-clock values are operational performance metrics only. Benchmark scenario,
host profile, kernel, QEMU build, guest RAM, vCPU count, device profile, and
measurement variance are recorded.

## 10.3 Structural hot-fork acceptance

The hot-fork gate uses at least three guest RAM sizes and several sibling counts.
Before child resume it verifies:

- parent memory contents are not eagerly copied;
- every guest RAM mapping is private-COW or a validated immutable backing with
  private mappings, never an inherited writable shared mapping;
- parent and siblings have distinct writable ring and disk resources;
- child-private RSS does not scale with full guest RAM;
- dirtying a known set of guest pages increases private RSS approximately with
  the dirtied set plus bounded allocator/page-table overhead;
- parent state remains byte/fingerprint-identical after every child exits;
- repeated child creation does not leak descriptors, threads, overlays, or
  shared-memory objects;
- descendant templates preserve the same isolation and scaling shape over at
  least three branch depths;
- failed multi-node transactions publish no partial session.

- **[CPERF-3]** `gate:hot-fork-scaling` MUST fail if idle child private memory or
  disk storage grows as a full copy of guest RAM or parent disk state.

## 10.4 Latency and throughput targets

Absolute throughput depends on guest work. The gate therefore establishes a
versioned baseline and regression ratchet on a pinned reference host, consistent
with RFC-0010's performance policy. Initial engineering targets are:

- single-VM hot-fork child-ready latency below 100 ms at p95 for the reference
  small guest and substantially below exact restore;
- multi-node world-fork latency bounded by the slowest node plus orchestration,
  not the sum of serialized node restores;
- at least 5x setup-throughput improvement over fresh exact restore for a
  short sibling-branch corpus before hot fork becomes the default;
- sustained creation and retirement of at least 10,000 short children from a
  stable template without unbounded resource growth, with the useful concurrent
  population limited only by the declared host resource budget;
- no more than 10% regression in steady-state guest execution throughput when
  a non-template child runs versus the same launch profile without hot-fork
  capability armed;
- planner and queue overhead below 5% of host time for the short-branch corpus;
- campaign metadata for one million admitted lightweight attempts bounded by a
  measured compact-object/index budget established in the implementation spike,
  with paging rather than full in-memory loading.

These targets may be revised only with measured evidence and an RFC decision
update before implementation is declared complete.

- **[CPERF-4]** Hot fork MUST remain off by default until the equivalence,
  isolation, resource-leak, and minimum speedup gates all pass on the supported
  launch profile.

## 10.5 Durable checkpoint performance

The durable gate compares:

- current full artifact staging/chunking;
- direct streaming into the local object store;
- parent-relative disk and RAM delta capture;
- repeated identical and sparse-dirty captures;
- restore from local objects and a latency-injected S3-compatible test backend.

It verifies logical bytes, bytes read from source, bytes uploaded, unique stored
bytes, memory used by capture, and whole-artifact authentication. A sparse-dirty
checkpoint should read and publish changed extents plus bounded manifests rather
than duplicate full guest RAM or overlay content once the parent-delta capability
is enabled.

- **[CPERF-5]** Streaming capture MUST use bounded buffers independent of
  artifact size and preserve deterministic object identities under different
  read chunking.

## 10.6 Lazy-frontier performance

Fixtures include:

- a discrete domain of 10 alternatives;
- an integer domain with more than `2^32` legal values;
- one million dormant choice points represented by paged Merkle collections;
- progressive widening with repeated descendant feedback;
- duplicate attempt and observation delivery;
- daemon restart with all projection caches deleted;
- strict and streaming planning under shuffled worker completion.

The gate proves domain cardinality is not enumerated, generator polling is
bounded, projections paginate, and strict mode produces identical planner steps
under shuffled completion delivery.

- **[CPERF-6]** `gate:lazy-frontier` MUST include allocation instrumentation and
  fail if validating or polling a huge integral domain allocates proportional to
  cardinality.

## 10.7 Correctness gates

| Gate | Contract |
| --- | --- |
| `gate:campaign-model` | Canonical policy/snapshot/fact identities, CAS history, projection rebuild, and merge rules |
| `gate:typed-choice` | Guest and environment choices share domain validation, stable IDs, selection replay, and mismatch rejection |
| `gate:campaign-replay` | Findings replay without campaign/store and strict campaign planner steps reproduce |
| `gate:lazy-frontier` | Suspended generators resume, widen, wait, exhaust, and recover correctly |
| `gate:attempt-idempotence` | Duplicate execution/observation/credit is safe; conflicting result is detected |
| `gate:hot-fork-equivalence` | Hot child next quantum/state equals exact restore and thin replay |
| `gate:hot-fork-isolation` | Rings, sockets, disks, logs, and host continuation are sibling-private |
| `gate:hot-fork-scaling` | Fork latency/memory/storage follow the required cost shape |
| `gate:world-fork-atomicity` | Multi-node partial failure exposes no branch |
| `gate:exact-closure-streaming` | Direct and delta capture authenticate to equivalent restored state |
| `gate:campaign-store-equivalence` | Local and S3-compatible backends expose identical object/ref semantics |
| `gate:campaign-replication` | Partial/full Merkle sync, corruption rejection, and ref CAS |
| `gate:campaign-continuity-v2` | Pause/restart/restore retains graph, frontier, knowledge, pins, and accounting |
| `gate:campaign-statistics` | `P`/`Q` support and weight rules; biased campaigns cannot emit probability claims |
| `gate:license-boundary` | Existing process/license closure including all new QEMU patches |
| `gate:abi-conformance` | Versioned socket/shmem/guest choice/measurement/fork protocols |

## 10.8 Equivalence matrix

Every supported checkpoint fixture is executed from:

```text
thin replay
durable exact restore
hot child of an execution-created template
hot child of an exact-restore-created template
```

For each path the gate compares:

- first complete scheduler quantum;
- guest architectural fingerprint;
- scheduler/fault/adapter/host continuation state;
- pending ring and device operations;
- event-log canonical projection;
- selected value and effect evidence;
- final state at a bounded horizon.

The matrix covers single-node, multi-node network traffic, block and 9p I/O,
pending guest choice, pending measurement marker, active signal-driven effects,
permanently failed nodes, and a failure during fork preparation.

- **[CPERF-7]** A hot or exact path mismatch is a correctness failure. The
  implementation MUST NOT hide it by falling back after the mismatching runtime
  has become visible.

## 10.9 Negative and fault-injection tests

Tests corrupt or omit:

- domain and choice-point digests;
- policy/generator versions;
- proposal observation basis;
- campaign snapshot children;
- exact closure chunks and lengths;
- one world node's fork generation;
- one shared-memory cursor;
- one inherited writable descriptor disposition;
- one disk backing identity;
- one host continuation component;
- an S3 conditional ref write;
- duplicate/conflicting attempt observations;
- provenance components.

Every fault must fail before guest resume or campaign ref publication, preserve
the prior valid state, and produce localized evidence.

## 10.10 Benchmark publication

Benchmark baselines and host profiles are content-addressed repository fixtures.
Updating a baseline is a reviewed change with rationale. Determinism gates do
not tolerate a performance variance band; performance gates do not substitute
for exact equivalence.
