# Distributed Workflows

Workflows are reactive DAGs executed autonomously by the cluster. A workflow
describes a sequence of steps with dependencies, triggers, and actions -- all
expressed in terms of the AOS P2P protocol. Once submitted, a workflow executes
without client involvement. The client can disconnect, reconnect, monitor
progress, and cancel at any time.

## Overview

A workflow captures a computation graph -- like a Nix build DAG -- as a set of
named steps with dependency edges. Each step has a trigger condition (an
observable event on the P2P network) and an action (an operation performed via
the P2P protocol). The workflow engine advances steps as their triggers fire,
with no central coordinator.

Execution is fully decentralized: any peer with `/aos/workflow/execute`
permission can claim and advance workflow steps. Step claiming reuses the
load-staggered first-claim pattern from job scheduling, with an affinity bonus
for peers that already hold a step's input store objects locally. This
naturally pipelines work through builders with maximum data locality.

**Deterministic control flow:** Workflow conditions must be based on
deterministic inputs only -- store hashes (content-addressed) and step
completion status. Actions CAN be non-deterministic (build jobs produce
non-deterministic outputs), but the workflow's control flow is a pure function
of its inputs. This makes workflows idempotent: given the same store state,
the same workflow spec produces the same execution plan.

## Gossipsub Topics

| Topic | Message | Scope |
|---|---|---|
| `aos/workflows/announce` | `WorkflowPost` | Global |
| `aos/workflows/active/{workflow_id}/state` | `WorkflowStateMessage` | Per-workflow |

The `announce` topic is used for workflow creation, cancellation, and
discovery. Per-workflow state topics carry step-by-step state changes and
periodic state snapshots. Nodes subscribe to state topics only for
workflows they are tracking.

## DHT Records

| Key | Value | TTL |
|---|---|---|
| `aos:workflow:run:{workflow_id}` | Provider record | Workflow lifetime |

Peers tracking a workflow call `start_providing` on this key. New joiners or
reconnecting clients use `get_providers` to find peers with the workflow's
history.

## Stream Protocols

| Protocol | Request | Response | Purpose |
|---|---|---|---|
| `/aos/workflow/state/1.0.0` | `WorkflowInfoRequest` | `WorkflowInfoResponse` | Fetch point-in-time workflow state snapshot |
| `/aos/workflow/log/1.0.0` | `WorkflowLogRequest` | stream of `WorkflowTransition` | Fetch or tail the ordered transition log |

---

## Workflow Specification

A `WorkflowSpec` defines the computation graph. The spec is serialized as a
protobuf and stored as a store object. The `workflow_id` IS the store hash of
the serialized spec.

```
WorkflowSpec {
    nonce: uint64                    // deduplication
    creator: PeerId
    deadline: uint64                 // epoch us; workflow must complete by this time
    expiration: uint64               // epoch us; workflow state deleted after this time
    ucan: string                     // client's authorization token (scopes permissions)
    steps: [WorkflowStep]
}
```

Before announcing a workflow, the client must publish the serialized
`WorkflowSpec` to the store (`start_providing`). The `WorkflowPost{create}`
message references only the store hash:

```
WorkflowPost {
    oneof action {
        WorkflowCreate create        // spec_hash (the workflow_id)
        WorkflowCancel cancel
    }
}
```

This design solves GossipSub message size limits (specs can be arbitrarily
large) and the spec is a store object like any
other, fetched via the standard store protocol. The `nonce` field ensures
distinct IDs for repeated submissions of the same graph.

### Bounded Workflow Size

Each daemon specifies workflow limits in its configuration:

```toml
[workflows]
max_steps = 10000          # max total steps per workflow
max_depth = 500            # max steps through longest path
max_concurrent = 100       # max concurrent active workflows
```

Workflows exceeding limits are rejected at announcement time. The longest path
(critical path depth) bounds the transition log size. These limits are enforced
locally by each daemon when it fetches and validates a workflow spec.

### Periodic State Sync (Replaces not_before)

Instead of a fixed `not_before` delay, workflow state consistency is maintained
through periodic state synchronization. Each participating node computes a
deterministic sync offset:

```
sync_offset = hash(peer_id XOR workflow_id) % sync_window
```

The default `sync_window` is 60 seconds. At its offset time within each
window, the node publishes a full `WorkflowStateSnapshot` to the per-workflow
state topic:

```
WorkflowStateSnapshot {
    workflow_id: string
    publisher: PeerId
    timestamp: uint64                // epoch us
    step_states: map<string, StepState>
}
```

The first node to publish a snapshot in a given window "wins" -- other nodes
see the snapshot arrive and skip their own publication for that window. If a
node has progressed past the received snapshot (i.e., it has transitions the
snapshot does not reflect), it publishes the missing transitions as deltas
after receiving the stale snapshot.

### Two-Phase Catch-Up

When a peer receives a snapshot ahead of its local state (either as a late
joiner or after a reconnection), catch-up is two-phase:

**Phase 1: Snapshot apply (fast path).** The peer applies the snapshot's
`step_states` directly to `steps_db` in WorkflowDB. It now knows which steps
are completed, running, ready, etc., and can immediately participate — claiming
ready steps, observing readiness, advancing the workflow. The peer compares
`state_hash` against its own computed state to verify consistency. This happens
within one sync window (~60s).

**Phase 2: Transition backfill (async).** The peer requests missing transitions
via `/aos/workflow/log/1.0.0` from a peer found through `get_providers` on
`aos:workflow:run:{workflow_id}`. It requests transitions after its last known
timestamp. As transitions arrive, they are written to `transitions_db`. The
peer is operationally current after phase 1 but cannot serve
`/aos/workflow/log/1.0.0` requests until phase 2 completes.

**DHT advertisement timing:** a peer should NOT call `start_providing` on
`aos:workflow:run:{workflow_id}` until phase 2 completes. This prevents clients or
other peers from requesting the log from a peer with gaps. After backfill is
done, the peer advertises itself as a full tracker.

This eliminates the race condition on topic creation without adding a fixed
startup delay — new peers catch up via the next periodic snapshot rather than
needing all transitions from the beginning.

### Steps

Each step has a unique ID within the workflow, a type, dependencies, and
optional parameters:

```
WorkflowStep {
    id: string                       // unique name within the workflow (e.g., "build-gcc")
    action: StepAction               // what to do when the step becomes ready
    deps: [string]                   // step IDs that must complete before this step is ready
    timeout: optional uint64         // microseconds; step-level timeout from claim time
}
```

The optional `timeout` field specifies a per-step timeout in microseconds. If
the step is not completed within `timeout` microseconds from when it was
claimed, the claim lease expires and the step reverts to `ready` for another
executor to pick up. If no `timeout` is set, the step uses the workflow's
`deadline` as its implicit timeout.

### Step Actions

Nine step types are available, all returning either `StoreRef` (deterministic)
or `Promise<StoreRef>` (must flow through `await`):

- `input` — required store object (must exist before start)
- `fetch` — download FOD from upstream URLs
- `build` — hermetic Nix build from .drv
- `match` — exhaustive pattern matching with decision table (replaces `decision`)
- `read` — read historical Statute state at a fixed state root
- `run` — execute non-idempotent job, returns Promise (Statute-claimed)
- `await` — resolve a Promise into a StoreRef (universal promise resolver)
- `record` — write a StoreRef to Statute as a transition point
- `observe` — watch another workflow's transition point, returns Promise

See [workflow-spec.md](workflow-spec.md) for formal semantics, type system,
and validation rules.

---

## Workflow State

Each step progresses through a state machine:

```
pending -> ready -> claimed -> running -> completed
                                       -> failed
                            -> (timeout expired -> ready)
pending -> skipped (if a dependency failed or a decision short-circuits)
```

- **pending**: waiting for dependencies to complete.
- **ready**: all dependencies are `completed`; eligible for claiming.
- **claimed**: an executor has claimed this step (with a lease).
- **running**: the executor is performing the action.
- **completed**: the action succeeded; result is available.
- **failed**: the action failed; dependent steps are `skipped`.
- **skipped**: a dependency failed or a decision step short-circuited this
  branch.

When a step's timeout (or the workflow deadline) elapses after a claim, the
step reverts to `ready`. The timed-out claim remains in the transition log but
is superseded.

The overall workflow state is derived from its steps:
- **pending**: no steps have started yet.
- **running**: at least one step is ready, claimed, or running.
- **completed**: all steps are `completed` or `skipped` with no failures.
- **failed**: at least one step `failed`.
- **cancelled**: client published a cancel.
- **expired**: deadline exceeded.

---

## WorkflowDB (LMDB)

Workflow state is persisted in an LMDB database at `db/workflow.mdb` with four
sub-databases:

| Sub-database | Key | Value |
|---|---|---|
| `workflows_db` | `workflow_id` | `WorkflowRecord {spec_hash, status, created_at, deadline, expiration}` |
| `steps_db` | `(workflow_id, step_id)` | `StepState {status, executor, claimed_at, result, timeout}` |
| `transitions_db` | `(workflow_id, timestamp_us, executor_peer_id)` | `WorkflowTransition` |
| `workflow_deps_db` | `workflow_id` | `[awaited_workflow_ids]` |

The `workflow_deps_db` tracks cross-workflow dependencies introduced by
`await_workflow` steps. On workflow announcement, the daemon extracts all
`await_workflow` actions from the spec, records the dependency edges, and
performs a topological sort of the cross-workflow dependency graph. Circular
`await_workflow` dependencies are rejected -- the daemon refuses to track the
workflow and does not call `start_providing` on its DHT key.

### GC Pinning

All store hashes referenced by active (non-terminated) workflows are pinned
against garbage collection. Pinning is closure-based: **pin the workflow spec
store object, and its `store_db` refs transitive closure covers everything.**

The workflow spec protobuf contains store hashes as literal strings. Reference
scanning on ingest finds all of them and records them in `store_db` refs. The
spec's closure automatically includes all FOD sources, derivation hashes,
expected output hashes, decision check hashes, and dependent workflow spec
hashes (since `workflow_id` = store hash of the spec). No per-step tracking
is needed.

Cross-workflow pinning is also automatic: if W2's spec references W1's
workflow_id (a store hash), W1's spec is in W2's closure, and W1's referenced
objects are transitively included.

Pins are released when the workflow reaches a terminal state (`completed`,
`failed`, `cancelled`, `expired`). See [workflow-spec.md](workflow-spec.md)
for the full pinning model.

---

## Transition Log

The transition log is the authoritative record of a workflow's execution. Each
transition is a state change applied to a single step:

```
WorkflowTransition {
    workflow_id: string
    sequence: uint64                 // per-executor local counter (deduplication only)
    step_id: string                  // named step within the workflow
    transition: StepTransition       // ready, claimed, running, completed, failed, skipped
    executor: PeerId
    timestamp: uint64                // wall clock (epoch us)
    causal_deps: [bytes]            // hashes of transitions this one causally depends on
    result: Option<StepResult>       // output store hashes, error info, etc.
    hash: bytes                      // hash(workflow_id, step_id, transition, executor, timestamp, causal_deps)
}
```

### Ordering

Transitions use `(timestamp_us, executor_peer_id)` as the canonical ordering
key. Since clocks are well-synchronized (NTP gives <10ms skew in same-region
clusters), timestamps provide a reliable global ordering.

The `sequence` field is a per-executor local counter used only for
deduplication -- it allows a receiver to detect and discard duplicate
deliveries from the same executor. It is NOT used for ordering.

**Canonical linearization:** all nodes sort transitions by
`(timestamp_us, executor_peer_id)`. Transitions with the same timestamp from
different executors get a deterministic order via the peer ID tie-break. All
nodes with the same set of transitions produce the same canonical order.

**Causal dependencies** reference transition hashes (not sequence numbers).
When an executor completes step A and claims step B (which depends on A), the
claim transition for B lists A's completion transition hash in `causal_deps`.
This creates a DAG of transitions that mirrors the workflow's dependency
structure, without relying on any global counter.

### Consistency

The log provides **eventual consistency**. All nodes that receive the same set
of transitions compute the same workflow state. There is no requirement that
all nodes have the same log at the same instant -- they converge as gossipsub
delivers transitions and periodic state snapshots reconcile gaps.

### Conflict Resolution

When two executors claim the same step simultaneously, both publish `claimed`
transitions. Resolution: lowest `(timestamp_us, executor_peer_id)` wins. The
loser's claim remains in the log but is superseded. This is identical to the
job first-claim model.

### Split-Brain Behavior

Network partitions are an accepted limitation. During a partition, executors
on both sides may independently claim and execute the same step. After the
partition heals, duplicate step executions are resolved by the canonical
`(timestamp_us, executor_peer_id)` ordering -- the "winner" transition is
kept, and the duplicate is logged but superseded.

The store objects produced by the duplicate execution are valid
(content-addressed) and are not treated as errors. They may be used by other
workflows or garbage-collected naturally when no longer referenced.

---

## Execution Model

### Step Claiming

When a step becomes ready (all deps completed), executors independently
compute a claim delay:

```
step_claim_delay = base_delay - local_input_affinity + load_penalty
```

- **base_delay**: 50-200ms random jitter (prevents thundering herd).
- **local_input_affinity**: bonus based on fraction of the step's input
  closure already present in the local store (via `store_db` refs walk). A builder
  that just produced the previous step's output has near-zero delay.
- **load_penalty**: penalty for high current load (same model as job claiming).

The fastest executor publishes a `claimed` transition. Others see the claim and
stand down.

### Speculative Claiming

An executor that completes step A can speculatively claim step B (if B becomes
ready as a result of A's completion) in the same gossipsub message:

```
// Single message to the state topic:
[
    { step_id: "build-gcc", transition: completed, result: { outputs: [...] } },
    { step_id: "build-llvm", transition: claimed, causal_deps: [hash_of_gcc_complete] },
]
```

Other executors receive both transitions atomically and see that "build-llvm"
is already claimed. The claiming executor starts the next build with zero
latency -- the previous output is already local, and the reservation token from
the completed job skips the job claim phase.

**Speculative claims MUST validate ALL dependencies.** If step B depends on
steps [A, C] and A just completed but C has not, B CANNOT be speculatively
claimed. The executor must verify that every dependency listed in `B.deps` is
in the `completed` state before issuing a speculative claim. This prevents
invalid claims that would need to be rolled back.

**This creates natural build pipelines:** for a chain like gcc -> llvm -> rust,
all three builds may execute on the same builder with zero inter-node transfer
and zero scheduling latency between steps.

### Per-Step Timeout and Lease Expiry

Step claims have a timeout duration. The timeout is determined by:

1. The step's own `timeout` field, if set.
2. Otherwise, the time remaining until the workflow's `deadline`.

If the timeout elapses without a `completed` or `failed` transition, the step
reverts to `ready` and another executor picks it up. The timed-out executor's
transitions remain in the log but are superseded by the new claim.

### Reservation Token Integration

When a build job completes, the builder offers a reservation token (see
[jobs.md](jobs.md#slot-reservation)). If the next workflow step is another
build on the same builder, the workflow executor presents the reservation
token in the `JobStartRequest`, skipping the job claim phase entirely.

The full pipeline latency between chained builds becomes:
- ~0ms for the workflow step claim (speculative, batched with completion)
- ~0ms for the job claim (reservation token)
- ~5ms for the `JobStartRequest` stream setup
- Input fetch time (zero if previous output is local)

### Job-Workflow Linkage

The `JobPost` message should include optional `workflow_id` and `step_id`
fields so that if an executor crashes, other executors can match `JobExit`
messages back to workflow steps. Without this linkage, a crash between
publishing the job and recording the job-to-step mapping would leave the
workflow step stuck in `running` until its timeout expires, even though the
job completed successfully.

**Design note:** the actual protobuf field additions are specified in
[protocol.md](protocol.md). This section documents the motivation and
intended usage only.

---

## Inter-Workflow Signaling

Workflows can depend on other workflows via `await_workflow` steps:

```
{ id: "wait-for-toolchain",
  action: await_workflow {
      workflow_id: "hash-of-toolchain-build",
      step_id: "final-output"    // optional: wait for specific step
  },
  deps: [] }
```

The executor subscribes to the target workflow's state topic and watches
for the referenced step (or the overall workflow) to reach `completed`. If the
target is already complete (checked via `/aos/workflow/state/1.0.0`), the step
completes immediately.

### Cycle Detection

Cross-workflow dependencies are tracked in `workflow_deps_db`. When a new
workflow is announced, the daemon extracts all `await_workflow` step actions,
adds the edges to the dependency graph, and performs a topological sort. If
adding the new workflow would create a cycle (A awaits B, B awaits C, C awaits
A), the workflow is rejected. The daemon logs the cycle and does not track the
workflow.

### Multi-Stage Pipelines

This enables multi-stage pipelines:

```
Workflow "build-toolchain" (gcc -> llvm -> rust)
  | await_workflow
Workflow "build-packages" (100 packages in parallel)
  | await_workflow
Workflow "run-tests" (test suite)
```

Each workflow is independently cancellable, monitorable, and has its own
deadline/expiration.

---

## Nix Build Example

Building a Nix package as a workflow. The client evaluates the flake locally
to produce the full derivation DAG, then submits it:

1. **Client evaluates the flake.** `nix-instantiate` / flake eval produces the
   derivation DAG with all FOD sources and build steps.

2. **Client constructs the workflow store object:**
   - `input` steps for each `.drv` file (must be uploaded before submission).
   - `fetch` steps for FOD sources (upstream mirror URLs + content hash).
   - `build` steps for each derivation (references the `.drv` by store hash).
   - `decision` steps to skip derivations whose outputs already exist.

3. **Client publishes the workflow store object** via the standard store
   protocol (`start_providing`). The store hash becomes the `workflow_id`.

4. **Client submits the workflow** by publishing `WorkflowPost{create(spec_hash)}`
   to `aos/workflows/announce`.

5. **Executors fetch the workflow store object** and begin evaluating step
   readiness. FOD fetch steps download source tarballs from upstream mirrors.
   Decision steps check the store for existing outputs. Build steps whose
   inputs are all available get claimed by nearby executors. Late-joining
   executors catch up via the periodic state sync within one sync window.
   store for existing outputs. Build steps whose inputs are all available get
   claimed by nearby executors. Late-joining executors catch up via the
   periodic state sync within one sync window.

7. **Builds pipeline through the cluster.** Each builder that completes a step
   speculatively claims the next, creating natural pipelines along the
   dependency chain. Parallel branches execute on different builders.

8. **Client disconnects.** The workflow continues autonomously.

9. **Client reconnects later.** Queries `/aos/workflow/state/1.0.0` to get
   current state. Fetches final outputs from the store.

### Example Workflow Graph

```
provide(gcc-src)  provide(llvm-src)  provide(rust-src)
       |                |                  |
   build-gcc        await(gcc)          await(llvm)
       |                |                  |
       +----> build-llvm <---------+       |
                    |                      |
                    +------> build-rust <--+
                                 |
                            final-output
```

Steps like `await(gcc)` are `decision` steps using `store_object_exists` --
they check whether gcc's output is already available in the store and skip
the build if so.

---

## Client Operations

### Submit

1. Serialize the `WorkflowSpec` as a protobuf.
2. Publish the serialized spec to the store (`start_providing`). The store
   hash is the `workflow_id`.
3. Publish `WorkflowPost{create(spec_hash)}` to `aos/workflows/announce`.

### Monitor

Subscribe to `aos/workflows/active/{workflow_id}/state` for live
updates. Or poll via `/aos/workflow/state/1.0.0` for the current state
snapshot.

### Cancel

Publish `WorkflowPost{cancel(workflow_id, ucan)}` to `aos/workflows/announce`.
Executors stop claiming new steps. Running steps complete naturally (or are
killed at the executor's discretion). The workflow transitions to `cancelled`.

### List

List known workflows by reading Statute state under the workflow mount path
(e.g., `{mount_path}/runs/`), filterable by status.

### Catch-Up (Reconnection)

Clients and executors use the same two-phase model:

1. **Subscribe** to `aos/workflows/active/{workflow_id}/state` for live
   updates. The next periodic snapshot (within one sync window) provides
   the current state — the peer can begin participating immediately.
2. **Fast state** via `/aos/workflow/state/1.0.0` for the spec hash and
   current step states (if the peer can't wait for the next snapshot).
3. **Backfill** via `/aos/workflow/log/1.0.0` for the full transition
   history (from a specific timestamp for incremental catch-up). This is
   async — the peer is functional after step 1 or 2.
4. Transitions received between the info/log fetch and the subscription
   are reconciled via transition hashes (skip already-seen transitions).

Clients typically only need steps 1-2 (they want current state, not full
history). Executors that intend to serve as full trackers (providing
`/aos/workflow/log/1.0.0` to others) must complete step 3 before calling
`start_providing` on `aos:workflow:run:{workflow_id}`.

### Workflow Submission via Statute

Workflows are submitted by writing to a workflow mount's argument keys in
Statute. The client writes the workflow spec store hash to the mount path
(e.g., `{mount_path}/definition`), and the mount handler validates and
announces the workflow. This replaces the previous `/aos/workflow/run/1.0.0`
stream protocol.

See [workflow-validation.md](workflow-validation.md) for the full validation
model. Validation completes before any store writes or gossipsub
messages -- if it fails, no side effects occur.

**Dual-path model:** Statute captures durable boundaries (record/await steps)
as transactions. GossipSub carries idempotent transitions (claims,
completions, speculative execution) for low-latency executor coordination.
The GossipSub transitions do not need consensus since all step types outside
of record/await are idempotent.

### Reactive Mounts

Workflows can also be defined as reactive mounts in Statute. The workflow definition lives
at `{mount_path}/definition` within a workflow mount. When read dependencies
change (detected via merkle tree delta between blocks), the mount
automatically creates new workflow runs.

This eliminates the need for explicit workflow submission for event-driven
use cases. See [mounts.md](mounts.md) for the reactive mount model.

Workflow runs created by reactive mounts are stored at
`{mount_path}/runs/{workflow_id}/`, with transitions recorded at
`{mount_path}/runs/{workflow_id}/transitions/`. This replaces the previous
static `/workflows/state/{workflow_id}` path convention.

---

## Failure Handling

- **Step failure**: the step is marked `failed`. Dependent steps are marked
  `skipped`. Independent branches continue executing. The workflow overall is
  `failed` once all branches are resolved.
- **Step timeout**: the step claim expires. The step reverts to `ready`
  and another executor picks it up. The timed-out claim's transitions remain
  in the log but are superseded.
- **Executor crash**: the step timeout (or workflow deadline) triggers lease
  expiry. The step reverts to `ready` and another executor picks it up. No
  data is lost -- the transition log is distributed to all tracking peers via GossipSub.
  If the crashed executor had submitted a job for a `submit_job` step, the
  job-workflow linkage fields in `JobPost` allow other executors to match
  the `JobExit` back to the workflow step.
- **Deadline exceeded**: all `pending` and `ready` steps are marked `skipped`.
  Running steps are allowed to complete (up to a grace period) or are cancelled.
  The workflow transitions to `expired`.
- **Workflow expiration**: after the `expiration` time, peers unsubscribe from
  the state topic, stop providing the DHT record, release GC pins, and
  garbage-collect the workflow's transition log from the WorkflowDB.
- **Split-brain / partition**: duplicate step executions are resolved by
  canonical ordering after partition heal. See [Split-Brain Behavior](#split-brain-behavior).
- **Cross-workflow cycle detection is per-daemon.** Each daemon independently
  checks its local `workflow_deps_db` for cycles. In a decentralized system,
  a cycle that spans multiple daemons (W1 on daemon1 awaits W2, W2 on daemon2
  awaits W1) may not be detected. Affected workflows will hang at their
  `await_workflow` steps until their deadlines expire. This is an accepted
  limitation — global cycle detection would require consensus, conflicting
  with the coordination-free design. Operators should review cross-workflow
  dependencies before submission.

---

## Permissions

| Capability | Purpose |
|---|---|
| `/aos/workflow/create` | Submit workflows to `aos/workflows/announce`. |
| `/aos/workflow/execute` | Claim and advance workflow steps. Publish transitions. |
| `/aos/workflow/read` | Subscribe to workflow topics. Query info/log/list protocols. |
| `/aos/workflow/cancel` | Cancel a workflow (typically restricted to creator or admin). |

The workflow's `ucan` field scopes what the workflow is allowed to do. However,
executors use their own UCAN permissions to submit jobs and interact with the
protocol. The workflow's token is not a private key -- it is a capability
delegation that limits the workflow's scope (e.g., which job types it can
create, which store objects it can reference).

Dependency: `/aos/workflow/execute` requires `/aos/job/create`,
`/aos/store/read`, and `/aos/workflow/read`.

---

## Protocol

```protobuf
// --- Workflow Announcement ---

// GossipSub topic: aos/workflows/announce
// Workflow creation and cancellation. The spec itself is a store
// object (workflow.json); the announce message references it by hash.
message WorkflowPost {
    string workflow_id = 1;        // = store hash of the WorkflowSpec store object
    string ucan = 2;              // authorization chain

    oneof delta {
        WorkflowCreate create = 3; // new workflow announced
        WorkflowCancel cancel = 4; // workflow cancelled
    }
}

message WorkflowCreate {
    string spec_hash = 1;         // store hash of the WorkflowSpec store object
    string creator = 2;           // PeerId of the submitting client
}

// --- Workflow Specification (stored as workflow.json) ---

// The workflow blueprint. Stored as a JSON-encoded protobuf in a
// store object. The workflow_id is the store hash of this object.
// All store hashes embedded in the spec (output_hash, input, fetch
// URLs) are found by reference scanning and recorded in store_db refs,
// enabling closure-based GC pinning.
message WorkflowSpec {
    uint64 nonce = 1;             // deduplication nonce
    uint64 deadline = 3;          // epoch microseconds; must complete by this time
    uint64 expiration = 4;        // epoch microseconds; state deleted after this time
    repeated WorkflowStep steps = 7; // the workflow DAG
}

// A single step in the workflow DAG. Each step has a unique ID,
// an action to perform, and dependencies on other steps.
message WorkflowStep {
    string id = 1;                // unique name (e.g. "build-gcc", "src-linux")
    StepAction action = 2;        // what to do when this step is ready
    repeated string deps = 3;     // step IDs that must complete first
    optional uint64 timeout = 4;  // per-step timeout (microseconds from claim time)
}

message StepAction {
    oneof action {
        InputStep input = 1;
        FetchStep fetch = 2;
        BuildStep build = 3;
        MatchStep match = 4;         // exhaustive pattern matching
        ReadStep read = 5; // read historical Statute state
        RunStep run = 6;             // non-idempotent, Statute-claimed
        AwaitStep await = 7;         // resolve Promise → StoreRef
        RecordStep record = 8;       // write transition point to Statute
        ObserveStep observe = 9;     // watch another workflow's transition
    }
}

message MatchStep {
    map<string, MatchCondition> conditions = 1;
    repeated MatchCase cases = 2;
}

message MatchCondition {
    oneof condition {
        string store_object_exists = 1;
    }
}

message MatchCase {
    map<string, bool> when = 1;      // condition values to match
    repeated string activate = 2;    // step IDs to activate
}

message ReadStep {
    bytes state_root = 1;            // Statute state root (must exist before start)
    string key = 2;                  // Statute key to read
}

message RunStep {
    string spec_hash = 1;           // RunSpec job spec (#StoreRef)
}

message AwaitStep {
    string source = 1;              // step ID of run or observe step
}

message RecordStep {
    string source = 1;              // step ID whose output to record
    string transition = 2;          // transition point name
}

message ObserveStep {
    string workflow_id = 1;         // target workflow
    string transition = 2;          // transition point to watch
}

// Declare a required store object that must exist before the workflow
// starts. Validated at submission time — rejected if no providers.
// Completes immediately at runtime (the object already exists).
message InputStep {
    string store_hash = 1;       // store hash that must exist
}

// Download a content-addressed object (FOD) from upstream mirrors.
// Creates a FetchSpec job internally. If the output already exists
// in the store, completes immediately without downloading.
message FetchStep {
    string output_hash = 1;      // expected store hash of the output
    repeated string urls = 2;    // mirror URLs in priority order
    string hash = 3;             // expected content hash (SRI format)
}

// Submit a hermetic Nix build. Creates a BuildSpec job from the
// referenced .drv store object. If the output already exists in
// the store, completes immediately without building.
message BuildStep {
    string drv_hash = 1;         // store hash of the .drv (must exist as store object)
    string output_hash = 2;      // expected output store hash (computed from .drv)
}


message WorkflowCancel {
    string reason = 1;
    uint64 cancelled_at = 2;      // epoch microseconds
}

// --- Per-Workflow State Topic ---

// GossipSub topic: aos/workflows/active/{workflow_id}/state
// Envelope for all messages on the per-workflow state topic.
message WorkflowStateMessage {
    oneof message {
        WorkflowTransition transition = 1; // individual step state change
        WorkflowStateSnapshot snapshot = 2; // periodic full state
    }
}

// A state change applied to a single workflow step.
// Forms an ordered log that all trackers converge on.
message WorkflowTransition {
    string workflow_id = 1;
    uint64 sequence = 2;          // per-executor local counter (dedup only)
    string step_id = 3;           // which step changed
    StepTransition transition = 4; // new state
    string executor = 5;          // PeerId that made this change
    uint64 timestamp = 6;         // epoch microseconds (canonical ordering key)
    repeated bytes causal_deps = 7; // hashes of transitions this depends on
    optional StepResult result = 8; // step output (for completed steps)
    bytes hash = 9;               // transition hash (for dedup + causal refs)
}

// Periodic full state snapshot. Published by one peer per sync window.
// Late joiners apply the snapshot to catch up immediately.
// NOTE: State snapshots are NOT cryptographically signed. They are treated as
// hints for fast catch-up, not as authoritative state. Peers that receive a
// snapshot verify it against the transition log — if the snapshot's
// `state_hash` does not match the state computed from known transitions, the
// snapshot is discarded and the peer falls back to log-based catch-up. A
// malicious snapshot publisher cannot corrupt workflow state; it can only
// cause a temporary mismatch that is detected and corrected.
message WorkflowStateSnapshot {
    string workflow_id = 1;
    string publisher = 2;         // PeerId
    uint64 timestamp = 3;
    WorkflowStatus status = 4;    // overall workflow status
    map<string, StepState> step_states = 5; // current state per step
    uint64 transition_count = 6;  // total transitions applied
    bytes state_hash = 7;         // hash of serialized state (consistency check)
}

enum StepTransition {
    STEP_READY = 0;
    STEP_CLAIMED = 1;
    STEP_RUNNING = 2;
    STEP_COMPLETED = 3;
    STEP_FAILED = 4;
    STEP_SKIPPED = 5;
}

message StepResult {
    repeated string output_hashes = 1; // store hashes produced
    optional string error = 2;        // error message (for failed steps)
    optional string job_id = 3;       // associated job ID
}

enum WorkflowStatus {
    WORKFLOW_PENDING = 0;
    WORKFLOW_RUNNING = 1;
    WORKFLOW_COMPLETED = 2;
    WORKFLOW_FAILED = 3;
    WORKFLOW_CANCELLED = 4;
    WORKFLOW_EXPIRED = 5;
}

message StepState {
    StepTransition status = 1;
    optional string executor = 2;
    optional uint64 claimed_at = 3;
    optional StepResult result = 4;
}

// --- Workflow Stream Protocols ---

// Stream protocol: /aos/workflow/state/1.0.0
// Fetch the point-in-time workflow state snapshot. Each peer may have
// a different view of progress (from GossipSub).
message WorkflowInfoRequest {
    string workflow_id = 1;
}

message WorkflowInfoResponse {
    oneof result {
        WorkflowInfo info = 1;
        StreamError error = 2;    // 404=not found
    }
}

message WorkflowInfo {
    string spec_hash = 1;        // store hash of the WorkflowSpec
    WorkflowStatus status = 2;   // overall status
    map<string, StepState> step_states = 3; // per-step states
    string creator = 4;          // PeerId of the creator
}

// Stream protocol: /aos/workflow/log/1.0.0
// Fetch or tail the workflow transition history.
message WorkflowLogRequest {
    string workflow_id = 1;
    optional uint64 after_sequence = 2; // resume from this point
    bool follow = 3;                    // keep streaming new transitions
}
// Response is a stream of WorkflowTransition messages.

```

---

## Relationship to Other Docs

- [protocol.md](protocol.md) -- protobuf definitions for workflow messages,
  including `JobPost` workflow linkage fields.
- [jobs.md](jobs.md) -- job lifecycle, claiming, reservation tokens.
- [scheduling.md](scheduling.md) -- claim delay computation, affinity bonus.
- [store.md](store.md) -- store object availability checks, store watcher
  interface.
- [permissions.md](permissions.md) -- workflow UCAN capabilities.
- [mounts.md](mounts.md) -- mount affinities control store object retention.
- [../../tla/Workflows.tla](../../tla/Workflows.tla) -- TLA+ formal specification: step DAG execution, speculative claiming, lease expiry, workflow termination.
