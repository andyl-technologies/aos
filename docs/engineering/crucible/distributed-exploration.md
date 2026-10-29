# Distributed exploration

Crucible's exploration (search, fork, and coverage-guided fuzzing; see
[exploration.md](exploration.md)) can be spread across many explorer hosts
that share one content-addressed store. This page describes the store
primitives that make that possible, the shared frontier and its leases, the
four deduplication layers, the determinism boundary that keeps a fleet's
findings host-independent, and the check that proves a fleet finds exactly
what a single host finds.

Distribution adds no execution path and no state representation. A node,
checkpoint, finding, or coverage record produced on a fleet is the same
content-addressed object a single host produces, realized by the same
`instantiate` and stored under the same BLAKE3 key. Only its location
changes. Persistent, multi-run campaigns build on the same primitives and are
described in the [campaign guide](../../users/crucible/campaigns.md).

## Source map

| Concern | Location |
| --- | --- |
| Store trait and backends | `crates/crucible/crucible-store/src/lib.rs` (`DagStore`, `MemoryDagStore`, `LocalDagStore`, `SharedDagStore`) |
| Shared frontier and leases | `crates/crucible/crucible-store/src/lib.rs` (`SharedFrontier`, `FrontierClaimRequest`, `FrontierLease`, `SoftHashAffinity`) |
| Dedup index | `crates/crucible/crucible-store/src/lib.rs` (`SharedDedupIndex`, `ExpansionDedupDecision`, `CoverageAdmission`, `ReductionAdmission`) |
| Record codecs | `crates/crucible/crucible-store/src/cas/campaign_codec.rs` |
| Dependency-gated invalidation | `crates/crucible/crucible-store/src/cas/invalidation.rs` (`InvalidationQuery`) |
| Fleet search model | `crates/crucible/crucible-engine/src/model/temporal_graph/core.rs` (`TemporalGraph::search_with_work_stealing_fleet`) |
| Fleet equivalence report | `crates/crucible/crucible-engine/src/model/exploration/guidance.rs` (`FleetEquivalenceReport`) |
| Claim ordering and divergence | `crates/crucible/crucible-engine/src/model/runtime/search.rs` |
| Equivalence gate test | `crates/crucible/crucible-engine/tests/gate_fleet_equivalence.rs` |
| Distribution-metadata lint | `crates/crucible/crucible-test-support/tests/support/harness_lint/` |
| Packaged probe | `crates/crucible/crucible-store/src/bin/crucible-fleet-store.rs` |
| Package | `pkgs/tools/crucible-fleet-store.nix` |

`crucible-store` also contains the `content_store` and `content_envelope`
modules, and `crucible-store-s3` supplies an S3 transport for them. Those
modules hold the streaming blob/ref storage used by campaigns, not the fleet
primitives on this page; see the [campaign guide](../../users/crucible/campaigns.md).

## Current scope

The store crate implements every fleet primitive as a filesystem backend that
any number of processes can share, for example over a shared mount. The
engine implements the fleet search as a deterministic, in-process model over a
shared worklist, which the equivalence gate drives. There is no daemon or CLI
surface that runs a multi-host explorer today: the primitives, the model, and
the gate define and check the contract that such a runner must meet.

## The store interface

`DagStore` is the backend-agnostic content-addressed store for temporal-graph
objects. It is object-safe and has exactly three methods:

```rust
pub trait DagStore: Send + Sync {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError>;
    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError>;
    fn has(&self, key: &ContentHash) -> Result<bool, CasError>;
}
```

A key is `ContentHash::from_bytes`, the 32-byte BLAKE3 digest of the stored
bytes, rendered as 64 lowercase hex characters by `to_hex`. Because the key is
a pure function of content, no host name, path, run id, or timestamp can enter
it. The same node is the same object on every host and in every backend.

Three implementations share the trait:

| Backend | Use | Publish rule |
| --- | --- | --- |
| `MemoryDagStore` | Model tests and adapters | In-process `BTreeMap` behind a mutex |
| `LocalDagStore` | One process, one directory | Single temporary file then rename |
| `SharedDagStore` | Many writers, one directory | Unique temporary file then atomic hard link |

Every `get` re-hashes the bytes it reads. A file whose content does not hash to
its key fails with `CasError::ContentMismatch` rather than being returned. `has`
is defined as a successful `get`, so a corrupt object is not reported as
present.

### `SharedDagStore` publication

All hosts in a fleet share a single content-addressed `DagStore` backend.
`SharedDagStore` is the fleet-visible implementation. It uses the same
two-level layout as `LocalDagStore`:

```text
{root}/{first 2 hex chars of key}/{64-char hex key}
```

`put` is idempotent and convergent under concurrent writers:

1. Compute the key and read any existing object at its path. Identical bytes
   return the key at once. Different bytes fail with
   `CasError::ContentMismatch`.
2. Create the bucket directory, then write the bytes to a per-writer temporary
   file named `.{key}.{pid}.{sequence}.tmp`, opened with `create_new(true)`.
   A process-wide counter supplies `sequence`. Up to
   `SHARED_STORE_TEMP_CREATE_ATTEMPTS` (4096) names are tried.
3. Publish with `fs::hard_link(temp, path)`. Linking fails if the target
   exists, so exactly one writer creates the object.
4. If the link fails, re-read the target. Identical bytes count as success,
   because another writer won the race with the same content. Different bytes
   are a `ContentMismatch`. The temporary file is removed on every path.

The result is that sixteen writers racing to publish identical bytes leave
one object file, and no writer can replace an object with different bytes.
Content addressing makes write conflicts impossible on the hot path, so
expanding a node, storing its children, and admitting them to the frontier
need no lock and no consensus.

## The shared frontier

The search frontier is the set of checkpoints not yet expanded. A fleet
distributes work through content-addressed CLAIM/LEASE work-stealing over
the shared frontier, not by static partitioning. Symmetry and partial-order
reduction prune subtrees unpredictably, so the search tree is deeply
unbalanced. A static split strands work on one host while its peers sit
idle. Work-stealing balances load without coordination: an idle host claims
the next claimable node, expands it, and admits the children as new
frontier.

`SharedFrontier` keeps three content-keyed trees under its root:

```text
{root}/frontier/{xx}/{hash}      membership marker
{root}/claims/{xx}/{hash}        current lease record
{root}/claim-locks/{xx}/{hash}   short-lived claim mutex
```

Every path is derived from the node's `ContentHash` alone. Host id, lease
expiry, and affinity live only inside record bodies, never in a path or a key.

### Record formats

All records are line-oriented `key=value` text:

```text
format=crucible.frontier-node.v1
node=<hex>

format=crucible.frontier-lease.v1
node=<hex>
owner=<host id>
expires_at_tick=<u64>
lease_id=<hex>

format=crucible.frontier-claim-lock.v1
node=<hex>
acquired_at_tick=<u64>
expires_at_tick=<u64>
```

`lease_id` is the BLAKE3 hash of
`crucible.frontier-lease.v1\nnode=..\nowner=..\nexpires_at_tick=..\n`, so a
renewal or a peer's later claim produces a different id. Readers reject a
lease record whose `node` disagrees with its path or whose `lease_id` does not
match the recomputed hash.

### Claim protocol

`admit(node)` creates the membership marker with `create_new`. Re-admitting is
a no-op.

`claim_next(request)` validates the request and then walks
`ordered_claimable_nodes`. A request is invalid when the host id is empty or
contains a newline, when `ttl_ticks` is zero (`ttl must be greater than zero`),
or when `now_tick + ttl_ticks` overflows. For each candidate node,
`claim_next`:

1. Tries to take the claim lock by hard-linking a temporary claim-lock record
   into `claim-locks/`. If a lock exists and has not expired at `now_tick`,
   the node is skipped. If it has expired, it is removed and the attempt
   repeats. The lock is released when its guard drops.
2. Re-checks under the lock that the node is still claimable, meaning it has
   no lease record or its lease has expired.
3. Writes the new lease record to a temporary file and renames it over
   `claims/`.

`claim_next` returns `Ok(None)` when every node is leased. `renew` and
`release` take the same lock and act only if the current record still has the
caller's `lease_id` and, for `renew`, has not expired. A lost race returns
`None` or `false`, never an error.

Time is a caller-supplied logical tick (`now_tick`, `ttl_ticks`), not the host
clock. A lease expires when `expires_at_tick <= now_tick`.

### Leases are hints, not locks

A claim is a short-lived lease: a TTL-bounded hint that one host is expanding
a node. It is not a durable lock. A crashed host, a partition, or a lost
renewal lets the lease expire. The node then becomes claimable again, and a
stale claim lock left by a crashed claimer is reclaimed the same way. A peer
that re-expands the node derives byte-identical children, and `SharedDagStore`
deduplicates them on `put`. Lost or duplicated claims therefore cost only
repeated work. They can never produce a divergent node, and a dead host cannot
block the fleet.

### Soft hash-affinity

`SoftHashAffinity` lets a host prefer frontier nodes that fork cheaply from
checkpoints it already has cached. `ordered_claimable_nodes` sorts by
`(!affinity.prefers(node), node)`: preferred nodes first, then content-address
order. Soft hash-affinity is a priority hint only. It never removes a node
from the claimable set, never binds a node to a host, and never changes what a
node denotes. A fleet with affinity on and one with affinity off discover the
same findings; only the order can differ.

## Four-layer deduplication

Work-stealing repeats work by design, so deduplication keeps redundancy cheap.
The fleet deduplicates redundant work at four layers. Each layer is a
mechanism Crucible already has, read across hosts. None can change a node's
denoted state; each only avoids re-storing or re-expanding what already
exists.

| Layer | Mechanism | API |
| --- | --- | --- |
| 1. Exists-gated expansion | Skip a node already in the shared store | `SharedDedupIndex::exists_gated_expansion` returns `Expand` or `SkipExisting` |
| 2. Coverage-map admission | Admit a candidate only if it adds coverage no shared entry has | `SharedDedupIndex::admit_coverage_map` returns `CoverageAdmission` |
| 3. Reduction fingerprints | Keep one representative per symmetry or partial-order fingerprint, fleet-wide | `SharedDedupIndex::admit_reduction_fingerprint` returns `ReductionAdmission` |
| 4. Claim-set anti-redundancy | Prefer unleased nodes so two hosts rarely expand one node concurrently | `SharedFrontier::claim_next` |

`SharedDedupIndex` stores only content-keyed marker files:

```text
{root}/coverage-map/{xx}/{entry}                 coverage-map-entry.v1
{root}/coverage-fingerprints/{xx}/{fingerprint}  coverage-fingerprint.v1
{root}/reduction-fingerprints/{xx}/{fingerprint} reduction-fingerprint.v1
```

Coverage admission is a compare-and-merge over a grow-only set. Entries are
sorted and deduplicated, and each entry marker is created with `create_new`.
Newly created markers are the candidate's novel coverage, and existing ones
are its duplicates. Only after the entry markers does admission write the
candidate's fingerprint record. When that fingerprint record already existed
before the call, every entry is reported as a duplicate, but any missing entry
markers are still created. A fingerprint record left without its entry
markers is therefore repaired by the next admission of the same candidate,
and the candidate is reported as redundant.

Reduction admission keeps the first representative written for a fingerprint.
A later candidate with the same fingerprint gets back the existing
representative and is marked covered.

## Determinism boundary

Distribution makes two separate claims. Keeping them apart is what lets the
fleet be as nondeterministic as the network while reproduction stays exact.

- **Reproduction is deterministic and host-independent.** Every node,
  checkpoint, and finding is the same content-addressed object on any host.
  Each finding carries a self-contained `(def, seed, schedule)` reproduction
  artifact that replays bit-identically on one machine, with no fleet and no
  shared store. A finding that needs the fleet to reproduce is a defect.
- **Distribution and scheduling may be nondeterministic.** Which host claims
  which node, the wall-clock order of claims, the fleet size, and every
  work-stealing or affinity decision may vary between runs. This changes only
  the order in which findings are discovered.

Both claims hold because a run is a pure function of `(def, seed, schedule)`
and distribution metadata is not in that tuple. Distribution metadata (host
id, lease owner, claim order, lease and claim timestamps or ticks, lease id,
fleet size, peer count, and wall clock) must not flow into `reduce`, any
`Decision`, any content key, or any reproduction artifact. It may drive only
coordination: claims, leases, the frontier, affinity, telemetry, and
progress.

Two mechanisms enforce the boundary:

- **Static.** The `distribution-metadata-flow` rule in `gate:harness-lint`
  scans each function body. If the body mentions an identifier from
  `DISTRIBUTION_METADATA_IDENTIFIERS` together with any identifier from
  `DISTRIBUTION_METADATA_FLOW_TARGETS`, the rule reports a finding. The
  targets include `reduce`, `step`, `instantiate`, `Decision`, `ContentHash`,
  `Configuration`, `Schedule`, and the campaign artifact and ledger
  persistence functions. One exemption applies: a function whose name
  contains `claim`, `lease`, `frontier`, `affinity`, `telemetry`, or
  `progress` and whose only target is `ContentHash`. The bare identifier
  `owner` counts as metadata only in such a coordination context.
- **Runtime.** `gate:fleet-equivalence`, below, catches a leak the lint
  misses and hands the mismatch to divergence bisection.

`search_with_work_stealing_fleet` follows the same rule. Host indices appear
only in `FleetWorkClaim` records. They do not enter configurations, findings,
or artifacts.

## The fleet search model

`TemporalGraph::search_with_work_stealing_fleet` runs a fleet search
deterministically inside one process. It takes a `FleetWorkStealingConfig`:

| Field | Meaning |
| --- | --- |
| `total_budget` | `SearchBudget`, the frontier expansions shared by all hosts |
| `host_count` | Logical hosts competing for claims (zero is normalized to one) |
| `seed` | Orders claims and work stealing only |

Each claim works as follows:

1. Compute the claiming host as `fleet_claim_host_index`, a BLAKE3 hash of
   `crucible.fleet-equivalence.claim-host.v1` over the seed and claim
   sequence, reduced modulo the host count.
2. Pick the worklist candidate with the minimum `fleet_work_stealing_score`.
   The score is a hash over seed, sequence, host, depth, and frontier id,
   with ties broken by depth and then id.
3. Skip the candidate if it was already expanded. Otherwise expand it through
   the same `TemporalGraph::search` path that single-host search uses.
4. Record any failure the search oracle reports. Push each newly seen child,
   and each covered representative, onto the worklist, deduplicated by
   content address.

The run ends when the budget is spent or the worklist is empty.
`FleetWorkStealingSearchRun` returns the root, the config, the deduplicated
`explored_graph`, the ordered `claims`, the discovered failures, and
`exhausted`, which is true when the frontier emptied before the budget ran
out.

## Fleet equivalence

`gate:fleet-equivalence` is the runtime proof of the determinism boundary. An
exhaustive single-host search and a fleet search over the same scenario
family, seed, and total budget must discover the same content-addressed
finding set with byte-identical artifacts. Discovery order may differ.

`FleetEquivalenceReport::compare` turns each discovered failure into a
`FleetFindingSetEntry`:

```text
FleetFindingSetEntry {
    fingerprint,     // stable finding fingerprint
    configuration,   // where the finding was observed
    artifact,        // reproduction artifact id
    replayed_state,  // state reached by replaying the artifact
}
```

`passes()` requires all of the following:

| Field | Condition |
| --- | --- |
| `root_equal` | Both runs start from the same root |
| `budget_equal` | Both runs use the same total budget |
| `explored_graph_equal` | Both runs reach the same deduplicated graph |
| `both_exhausted` | Both runs empty the frontier before the budget ends |
| `finding_sets_equal` | Order-insensitive `BTreeSet` equality |
| `artifacts_byte_identical` | Every shared finding's artifact bytes match |

`single_discovery_order`, `fleet_discovery_order`, and
`discovery_order_equal` are kept for diagnostics only.

On failure, `divergence` names the first mismatch: `root-differs`,
`budget-differs`, `explored-graph-differs`, a non-exhaustion reason, or a
finding-set or artifact difference. It also carries a
`SearchReplayOracleBisectionRequest`. That is the divergence-bisection
localization handoff: it names the configuration where replay-oracle
bisection should begin.

`crates/crucible/crucible-engine/tests/gate_fleet_equivalence.rs` covers:

- Single-host breadth-first search against a four-host fleet, comparing
  finding sets and artifacts. It also checks that a reordered fleet can
  differ in discovery order and still pass.
- The work-stealing fleet under adversarial host conditions, run as
  independent tasks under every profile of `canonical_host_adversary_matrix`
  via `run_profiled_tasks`. The results must not depend on the profile.
- Negative controls: a finding dropped from the fleet set must localize as
  `fleet-equivalence-missing-from-fleet`, and a budget too small to exhaust
  the frontier must fail as `fleet-equivalence-not-exhausted`.

The gate is a pure check. It depends on no wall clock, core count, host
count, or network timing. A flake is treated as a determinism leak to
root-cause, not to quarantine. The Nix gate
`checks.crucible.phase7.gates.fleetEquivalence` is ordered after
`checks.crucible.phase2.gates.singleVmFingerprint`, its real-QEMU slice, and
after the shared-store, frontier-lease, dedup, and guardrail checks.
`gate:campaign-continuity` is its sibling for multi-run persistence; see
the [campaign guide](../../users/crucible/campaigns.md).

## The ratchet seam

The fleet-visible content-addressed store is the **same seam** at which a
future shared content-addressed substrate from the AOS `ratchet` engine could
slot in. That interface is exactly `DagStore::put`, `DagStore::get`,
`DagStore::has`, and `InvalidationQuery::evaluate`.

`InvalidationQuery` compares a `DependencySnapshot`, the named content hashes
recorded with a node, against the current snapshot. `evaluate` returns an
`InvalidationDecision` that lists each input whose hash changed, appeared, or
disappeared. `SharedDagStore` is the fleet backend for this same seam.
Dependency-gated invalidation is not a second substrate.

Crucible ships standalone. The seam is documented text, not a dependency, and
lives in the `crucible-store` crate documentation. No `ratchet` crate appears
in the dependency graph. Any future integration must be a thin adapter behind
the unchanged interface, and the adapter may replace these internals only
after `gate:content-address`, `gate:replay-oracle`, and
`gate:e2e-determinism` pass unchanged.

There is no separate remote checkpoint store. A remote or durable backend is
one more `DagStore` implementation. Content keys are identical across
backends, and objects are immutable, so a conflict is a `ContentMismatch`.
Garbage collection works on pins over the cache, never on identity.
Authentication belongs to the backend's transport, not to the trait. The
frontier, dedup index, and campaign store are built on the same interface,
and a new backend inherits them.

## Packaging and checks

`pkgs/tools/crucible-fleet-store.nix` builds the `crucible-fleet-store` binary
from the `crucible-store` crate hermetically from source with
`mkCargoPackage`. It reuses the Crucible controller's vendored Cargo
artifacts, links the AOS-built `sqlite`, and runs the crate's tests.
`postInstall` runs:

```text
crucible-fleet-store probe <store-root>
```

and greps its `key=value` report. The probe exercises every primitive:

- location-independent identity across two store roots;
- `CONCURRENT_WRITERS` (16) threads behind a `Barrier` publishing the same
  bytes, which must leave `object_file_count=1`;
- lease expiry and reclaim, stale claim-lock reclaim, affinity ordering
  without filtering, and byte-identical re-expansion;
- all four dedup layers, including the interrupted-admission repair;
- the campaign manifest, seeding, storage-bounding, and continuity proofs
  described in the [campaign guide](../../users/crucible/campaigns.md).

Representative report lines:

```text
backend=SharedDagStore
interface=DagStore::put,DagStore::get,DagStore::has
location_independent_roots=2
concurrent_writers=16
object_file_count=1
claim_lease=ttl-hint
claim_key=content-addressed
expired_lease=reclaimable
stale_claim_lock=reclaimable
hash_affinity=priority-only
affinity_filters_frontier=false
static_partitioning=false
dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set
coverage_map_repair=entry-markers-before-fingerprint
claim_set_anti_redundancy=unclaimed-first
```

The installed package also writes
`nix-support/crucible-fleet-store-build-info`, which records the backend and
the store interface.

Distributed exploration is wired as an AOS VM/fleet check,
`checks.fleet.crucible-distributed-continuous-exploration` in the root
`default.nix`. It runs TCG-only without
`requiredSystemFeatures = [ "kvm" ]`. It depends on `pkgs.crucible-fleet-store`,
the `crucible` suite, the native end-to-end determinism slice, the campaign
manifest, seeding, storage-bounding, and provenance checks, and these:

| Check | Proves |
| --- | --- |
| `checks.crucible.phase7.crucibleFleetStore` | The packaged probe |
| `checks.crucible.phase7.crucibleSharedDagStore` | `SharedDagStore` identity and concurrent publication |
| `checks.crucible.phase7.crucibleFrontierLeases` | Shared frontier, leases, and affinity |
| `checks.crucible.phase7.crucibleFourLayerDedup` | The four dedup layers |
| `checks.crucible.phase7.crucibleDeterminismGuardrail` | The `distribution-metadata-flow` lint rule |
| `checks.crucible.phase7.crucibleCasFleetRatchetSeam` | The documented seam and absence of a `ratchet` dependency |
| `checks.crucible.phase7.gates.fleetEquivalence` | `gate:fleet-equivalence` |
| `checks.crucible.phase7.gates.campaignContinuity` | `gate:campaign-continuity` |

Its result file records `vm_runner=tcg-only`, `kvm_required=false`, and
`shared_store_backend=SharedDagStore`. Gate wiring in general is described in
[testing-and-gates.md](testing-and-gates.md), and package composition in
[packaging.md](packaging.md).

## Performance shape

Hosts coordinate only through the shared store and a lock-free hot path, so
fleet throughput is bounded by the store's read and write bandwidth rather
than by coordination. Measured performance contracts live in
[performance.md](performance.md).
