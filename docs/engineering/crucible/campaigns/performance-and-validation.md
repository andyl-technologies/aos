# Performance and validation

Campaigns are useful only if logical width is cheap and active execution stays
bounded. Correctness gates prove equivalence among realization tiers;
performance gates prove that hot forking actually improves the cost model. The
canonical gate catalog is `crucible_test_support::campaign_gates`, and each
gate is wired to a check in `tests/crucible/default.nix`.

Source: the gate catalog in
[`crucible-test-support/src/campaign_gates.rs`](../../../../crates/crucible/crucible-test-support/src/campaign_gates.rs);
the Nix wiring in
[`tests/crucible/default.nix`](../../../../tests/crucible/default.nix).

Relationship to the parent pages: [performance](../performance.md) covers
the single-run cost model and the perf-bench gate, and
[testing and gates](../testing-and-gates.md) covers the test layers, the
ordered gate catalog, and gate targets. This page covers only the
campaign-specific gates and targets.

## Cost model

For latent possibilities `L`, branch requests `B`, proposals `P`, admitted
attempts `A`, runnable worlds `R`, hot parent state `H`, branch deltas `D_i`,
and unique durable objects `U`:

```text
campaign metadata  O(B + P + A + observations + compact projections), not O(L)
live memory        O(H + active rings + sum(D_i for live branches)), not O(R * H)
durable storage    O(U), with content and parent-delta deduplication
planner work       O(log(open continuations) + source poll + path credit)
fork setup         O(process and page-table metadata + small private resources)
```

Process fork may copy page tables proportional to mapped RAM, so fork time is
not constant; the requirement is that guest RAM contents stay shared and that
fork cost is far below serializing and restoring the same world. Growing the
cardinality of an unenumerated integer domain without admitting more proposals
must not grow frontier storage or daemon memory beyond constant domain
metadata.

## Hot-fork structural acceptance

`gate:hot-fork-scaling` runs several guest RAM sizes and sibling counts and,
before child resume, verifies that:

- parent memory is not eagerly copied, and every guest RAM mapping is private
  copy-on-write or a validated immutable backing, never an inherited writable
  shared mapping;
- parent and siblings have distinct writable ring and disk resources;
- child-private RSS does not scale with full guest RAM, and dirtying a fixed
  1,024-page set grows private RSS roughly by that set plus bounded overhead
  (the production owner records `VmPTE`, `VmData`, `AnonHugePages`, and
  `/proc/PID/numa_maps` evidence);
- the parent stays byte- and fingerprint-identical after every child exits;
- repeated child creation leaks no descriptors, threads, overlays, or shared
  memory, including across three descendant template generations;
- failed multi-node transactions publish no partial session.

The gate also enforces these measured targets on the reference profile:

| Target | Limit |
| --- | --- |
| Single-VM child-ready latency (64 MiB, 1 vCPU, 20 samples) | p95 below 100 ms |
| Setup throughput versus fresh exact restore on a short sibling corpus | at least 5x |
| Steady-state guest throughput of a forked child versus the same profile restored exactly | at most 10% slower |
| Sustained whole-world child lifecycles from one template | 10,000 without unbounded growth |
| Multi-node world-fork latency | bounded by the slowest node plus orchestration |

`gate:host-clone-cost` bounds host continuation clone cost across siblings, and
`gate:world-fork-atomicity`, `gate:hot-fork-isolation`, and
`gate:hot-fork-equivalence` cover the remaining hot-fork properties.

## Campaign planner overhead

`gate:campaign-performance` requires planner and queue overhead below 5% of
guest continuation time on the short-branch corpus, measured by the production
scaling flight on a pinned reference host, and it ratchets later measurements
against a reviewed baseline. No reviewed baseline is pinned yet: only the
host profile `tests/crucible/fixtures/campaign-performance-reference-host-v1.env`
is checked in, and until
`tests/crucible/fixtures/campaign-performance-reference-baseline-v1.env`
exists the check in `tests/crucible/phase9-campaign-performance.nix` reports
`BLOCKED` with reason `versioned-reference-baseline-unmeasured` instead of
enforcing the bound. `gate:campaign-metadata-million` authenticates one
million real admissions (62,500 requests of 16) with bounded object, index,
physical-store, and peak-memory evidence. The procedure for measuring and
pinning the baseline is in
[Crucible campaign performance baseline](performance-baseline.md).
Baselines and host profiles are content-addressed repository fixtures; updating
one is a reviewed change with recorded evidence. Determinism gates never
tolerate a variance band, and performance gates never substitute for
equivalence.

### Planner cost profile

Coordinator work dominates planner time; calls into the planner component are
a small fraction of the planner stage. Acceptance's immutable reads grow with
the store because trie authentication cost grows with it, not because ancestry
is replayed. Each planner operation publishes its choice-graph and
request-exploration edits as bounded Merkle batches, so only nodes reachable
from the final batch root are stored.

To profile a small corpus on the production path, build the test without
running it:

```text
nix develop --file cargo-shell.nix -c cargo test \
  --manifest-path crates/Cargo.toml --release \
  -p crucible-daemon --test gate_campaign_metadata_million --no-run
```

Run the produced executable with an absolute protected planner path, an
absolute empty storage path, `CRUCIBLE_CAMPAIGN_STORE_PROFILE=1`, and
`CRUCIBLE_CAMPAIGN_MILLION_DIAGNOSTIC_REQUESTS=64` or `256`, selecting
`small_real_admission_corpus_exercises_the_same_path --exact --ignored
--nocapture --test-threads=1`. The production million test has no diagnostic
override. Summarize the log with the AOS-built Python:

```text
python3 tests/crucible/campaign-million-profile.py diagnostic.log
```

The summary reader bounds every line, requires successful completion, checks
consecutive step evidence, and hashes the complete ordered step IDs. A prefix
run of this kind is diagnostic evidence, not a million-admission qualification.

## Lazy-frontier performance

`gate:lazy-frontier` fixtures cover a ten-alternative discrete domain, an
integer domain of more than `2^32` values, a million dormant branch points in
paged Merkle collections, progressive widening with repeated feedback, a
three-value finite request on a huge domain (one value already admitted by a
generator), maximum-size finite requests consumed one proposal at a time,
rejection of `--all` above its ceiling, duplicate attempt and observation
delivery, restart with every projection deleted, and strict versus streaming
planning under shuffled completion. Allocation instrumentation fails the gate if
validating or polling a huge domain allocates proportionally to cardinality.

`gate:campaign-mutation-scaling` creates at least 10,000 sequential uniquely
keyed branch-request and lifecycle mutations. After the first fully validated
head, a repository may keep a bounded validation checkpoint (ancestry depth, a
conservative reachable-object bound, projected lifecycle) and validate each new
local child in time proportional to its authenticated delta. The child is
promoted only after the ref compare-and-swap succeeds; reaching a work limit
falls back to complete validation. Each successor carries an authenticated
locator for its parent transition, so exact replay of an older command is an
indexed lookup rather than a history scan. Heads first seen after restart or
import always receive complete validation, and deleting every checkpoint
preserves semantics.

## Durable checkpoint performance

`gate:exact-closure-streaming` compares direct streaming through directory and
composed store graphs, parent-relative RAM and disk delta capture, repeated
identical and sparse-dirty captures, and restore from loose and packed objects.
It checks logical bytes, bytes read, bytes uploaded, unique stored bytes,
capture memory, and whole-artifact authentication. Streaming capture uses
bounded buffers and yields identical object identities under different read
chunking.

## Correctness gates

| Gate | Contract |
| --- | --- |
| `gate:campaign-model` | Canonical policy, snapshot, and fact identities; linear history; sole-writer rejection; derivation; projection rebuild |
| `gate:campaign-component-contract` | Direct and loopback campaign, planner, and executor adapters share schemas, validation, idempotency, and results |
| `gate:branch-point-model` | Opportunities form parent-scoped branch points; finite and generated requests share lazy admission; duplicate edges deduplicate |
| `gate:typed-choice` | Guest and environment choices share domain validation, stable IDs, replay, and mismatch rejection |
| `gate:typed-choice-product-checkpoint` | A real network product preserves one pending typed selection across exact checkpoint and replay |
| `gate:campaign-replay` | Findings replay without campaign or store; strict planner steps reproduce |
| `gate:attempt-idempotence` | Duplicate execution, observation, and credit are safe; conflicts are detected |
| `gate:hot-fork-equivalence` | A hot child's next quantum and state equal exact restore and thin replay |
| `gate:hot-fork-isolation` | Rings, sockets, disks, logs, and host continuation are sibling-private |
| `gate:world-fork-atomicity` | Multi-node partial failure exposes no branch |
| `gate:campaign-store-equivalence` | Directory, memory, packed, and S3-compatible leaves meet their immutable and ref semantics |
| `gate:campaign-store-composition` | Every supported layer order preserves IDs, durability, errors, crash recovery, GC roots, and packing |
| `gate:campaign-cold-continuity` | Pause, restart, and restore retain graph, frontier, knowledge, pins, and accounting |
| `gate:campaign-statistics` | `P`/`Q` support and weight rules; biased campaigns cannot emit probability claims |
| `gate:campaign-operational-continuity` | Coordinator and executor restart, exact pause, and store outage recovery with observed guest progress |
| `gate:campaign-envoy-network-five-vm` | The packaged five-VM Envoy product completes failover and recovery through the public campaign surface |
| `gate:e2e-determinism` | Live packaged QEMU/TCG repeats one campaign under varied host profiles with byte-identical results |
| `gate:license-boundary`, `gate:abi-conformance` | Process and license closure; versioned socket, shared-memory, guest choice, measurement, and fork protocols |

### Equivalence matrix

Every supported checkpoint fixture runs from thin replay, durable exact
restore, a hot child of an execution-created template, and a hot child of an
exact-restore-created template. Each path is compared on the first scheduler
quantum, guest architectural fingerprint, scheduler, fault, adapter, and host
continuation state, pending ring and device operations, canonical event log,
selected values and effect evidence, and final state at a bounded horizon. The
matrix covers single-node and multi-node traffic, block and 9p I/O, pending
guest choices and measurement markers, active signal-driven effects,
permanently failed nodes, and a failure during fork preparation. A mismatch is
a correctness failure and is never hidden by falling back once the mismatching
runtime is visible.

### Negative tests

Fixtures corrupt or omit domain, opportunity, and branch-point digests; request
bounds, cause evidence, and duplicate-edge state; policy and generator
versions; planner invocation, artifact, state, view, and budget; snapshot
children; exact-closure chunks and lengths; a node's fork generation; a
shared-memory cursor; an inherited writable descriptor disposition; a disk
backing identity; a host continuation component; a ref write and a tier
promotion; pack index publication; conflicting observations; and provenance.
Each must fail before guest resume or ref publication, keep the prior valid
state, and produce localized evidence. Component fixtures also run campaigns
through direct and split-process clients, kill coordinator and executor
independently, repeat submits and completions at every boundary, race
cancellation against completion, and check golden wire vectors without
constructing Rust-native values.

## Release acceptance

`gate:campaign-release-acceptance` is executable and fail-closed. Its inputs
are declared in `tests/crucible/campaign-release-acceptance-contract.toml`: it
accepts only authenticated PASS results for `gate:campaign-gate-matrix`,
`gate:campaign-operational-continuity`, `gate:campaign-replay`,
`gate:hot-fork-scaling`, `gate:campaign-required-gates`, and
`gate:e2e-determinism`, and the required-gates aggregate binds each release
claim to the exact result bytes of its gate. The release manifest binds the
Crucible package, patched QEMU, plugin, guest kernel, root image, ABI, and
license-boundary identities. Missing inputs, changed digests, extra or missing
claim gates, symlinked evidence, and incompatible schemas block acceptance.
Release does not depend on operator sign-off, a destructive drill, a
long-running flight, a signer quorum, or a second physical host. Contribution
authorization and QEMU licensing remain independent release requirements.

### Same-host determinism flight

`gate:e2e-determinism` runs the packaged CLI, patched QEMU, and plugin under
TCG on the build machine. A three-VM nginx, curl, and I/O-probe fault scenario
runs under three host profiles:

1. `quiet-single-core`;
2. `randomized-worker-two-core`: randomized worker scheduling on two cores;
3. `loaded-io-stall-four-core`: CPU pressure, synchronous I/O pressure,
   wall-clock launch jitter, and bounded scheduler preemption on four cores.

The live event and execution-fingerprint streams must be nonempty and
byte-identical across profiles, and every profile must produce the same
reproduction artifact. The quiet profile's artifact is then replayed under the
hostile four-core profile and must reproduce the outcome, event stream, and
fingerprint stream exactly. Varying host scheduling, core count, launch timing,
and I/O service tests host-profile independence without a second machine.

The derivation retains raw JSONL and store-population output per profile, the
canonical comparison and artifact digests, host-pressure and preemption
evidence, the replayed artifact and transcript, and a manifest hashing the
scenario, QEMU binary and build identity, plugin, kernel, root image, results,
command journal, and artifact. Release acceptance verifies these files directly
from the derivation and never accepts an injected path.

Negative controls construct a valid evidence bundle and prove fail-closed
behavior for missing evidence, altered results, and a changed closure-manifest
digest. The native gate fails when a profile diverges, a fingerprint stream is
empty, the artifact changes, the replay applies no bounded preemption, or the
live result cannot be reproduced.
