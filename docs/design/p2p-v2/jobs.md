# Job Lifecycle

Jobs are generic containers for executing work within a cluster. A job
encompasses any containerized task -- builds, login shells, services -- and
progresses through a well-defined lifecycle coordinated via CRDT state
transitions on GossipSub.

## Activation Types

A job's container behavior is determined by the `ActivationType` in its
`ContainerSpec`:

**ACTIVATION_NONE** -- mount the view, run an entrypoint. No special
activation. Used for interactive shells and simple one-off commands.

**ACTIVATION_SYSTEMD_V1** -- run systemd as PID 1 with an activation script
that installs units and services. Used for long-running service containers.

**ACTIVATION_DERIVATION** -- parse a `.drv`, exec the builder, capture output
from an OverlayFS writable layer. Network access disabled. Used for builds.

All containers receive a `ViewSpec` defining the FUSE view (transitive closure
of store objects). See [containers.md](containers.md) for the full container
orchestration model and [view.md](view.md) for view semantics.

## State Diagram

```
         create
  [none] -------> [posted]
                    |
            claim   |  (one or more peers)
                    v
                 [claimed]
                    |
         start RPC  |  (creator picks best claim)
                    v
                 [starting]
                    |
            start   |
                    v
                 [running] ---> [errored]
                    |                |
              exit  |                |
                    v                v
                 [exited]       [reclaimable]
                                (after DHT expiry)

  Any state except [exited] can transition to [cancelled] via cancel.
```

All transitions are published as `JobPost` CRDT deltas on the cluster's
`aos/cluster/{cluster_ident}/jobs/announce` GossipSub topic.

## Lifecycle Phases

### 1. Create

The job creator publishes a `JobPost` with a `create(JobSpec)` delta. This
announces the job to all peers in the cluster. The `JobSpec` contains:

- A nonce (prevents replay).
- An absolute epoch deadline (microseconds since epoch) by which the job must
  complete. Peers reject claims after the deadline has passed. Running jobs
  that exceed the deadline are killed.
- A container spec: activation type, view spec (store hashes defining the FUSE
  view), and optional derivation hash for build jobs.
- A node selector: required system architecture, features, and peer labels.
- Resource limits: max memory, CPU cores, and scratch disk.
- Network mode: `NETWORK_NONE` (required for builds) or `NETWORK_HOST` (for
  service containers).

The job is now visible to all cluster members subscribed to the jobs announce
topic.

### 2. Claim (Load-Staggered First-Claim)

Eligible peers that are willing and able to run the job publish `JobPost`
messages with a `claim(JobClaim)` delta. Each claim contains:

- `peer_id` -- the claiming peer's identity.
- `start_ucan` -- a UCAN granting the job identity holder permission to execute
  on this peer (see Two-Phase Start below).

Multiple peers may claim the same job. Claims are not binding -- they are
offers.

**Load-staggered claiming.** Rather than collecting claims over a fixed window
and then picking the best, claiming uses a load-proportional delay. Each peer
knows the load of every other peer from periodic `LoadReport` messages on
GossipSub. When a peer receives a `JobPost{create}`, it computes a claim delay
based on its relative load position among eligible peers:

```rust
fn claim_delay(&self, job: &JobSpec) -> Duration {
    let my_load = self.current_load_fraction();

    let mut peer_loads: Vec<f64> = self.load_reports.values()
        .filter(|r| r.system == job.node_selector.system)
        .map(|r| r.usage.cpu_fraction)
        .collect();
    peer_loads.sort();

    let my_rank = peer_loads.iter()
        .position(|&l| l >= my_load)
        .unwrap_or(peer_loads.len()) as f64 / peer_loads.len().max(1) as f64;

    // 50ms (lowest load) to 500ms (highest load)
    Duration::from_millis((50.0 + my_rank * 450.0) as u64)
}
```

The lowest-loaded eligible peer delays ~50ms before claiming; the
highest-loaded delays ~500ms. The creator picks the **first valid claim** that
arrives -- there is no collection window. This naturally routes jobs to the
least-loaded eligible peer without a central scheduler.

See [scheduling.md](scheduling.md) for the full claim delay computation
including load ranking, affinity bonus, confidence penalty, urgency factor, and
failure avoidance.

### 3. Start (RPC)

The creator picks the first valid claim that arrives (see load-staggered
claiming above) and opens a `/aos/job/start/1.0.0` stream to the selected
claimant with a `JobStartRequest` containing:

- `job_ucan` -- delegates the job identity to the claimant's peer, so the
  claimant can sign as the job.
- `start_ucan` -- the same start authorization the claimant provided in its
  claim, echoed back.
- `reservation` -- an optional `ReservationToken` if the creator is using a
  reservation from a previous job (see [Slot Reservation](#slot-reservation)).

The claimant validates both UCANs and starts the container.

### Creator Offline Fallback

The two-phase start handshake is the normal path. If the creator goes offline
after posting a job, two fallback behaviors prevent jobs from hanging
indefinitely:

- **Start timeout**: if no start call is made within `job_exec_timeout_ms` (from
  `ClusterConfig`) after the first claim, the first claimant (lowest peer_id
  among claimants with the earliest timestamp) auto-starts. The claimant
  generates its own `job_ucan` delegation as a self-signed fallback and proceeds
  with container startup.
- **Claim deadline**: if no claims arrive before the job's deadline, the job
  expires. The creator (or any observing peer) may publish a
  `JobPost{delta: error(JobError)}` with `ERROR_SOURCE_TIMEOUT` to record the
  expiry as a terminal state.

### 4. Start

Once the container is running, the claimant publishes `JobPost{delta:
start(JobStart)}` to the cluster. The job is now in the running state.

### 5. Running

While the job runs, it maintains liveness by refreshing a DHT record at
`aos:cluster:{cluster_ident}:job:{job_ident}:state` with a short TTL (see Liveness below). The job container
has its own PeerId and can participate in libp2p directly -- fetching store
content, publishing provider records, or communicating with other jobs.

### 6. Terminal States

- **exit** -- normal completion. The claimant publishes `JobPost{delta:
  exit(JobExit)}`.
- **error** -- the job failed. The claimant publishes `JobPost{delta:
  error(JobError)}`.
- **cancel** -- the creator (or authorized peer) cancels the job. Published as
  `JobPost{delta: cancel(JobCancel)}`. Valid from any non-terminal state.

## Lifecycle Message Fields

### JobStart

Published by the claimant when the container is running.

```protobuf
message JobStart {
    string peer_id = 1;       // PeerId of the executing peer.
    string machine_id = 2;    // Stable machine identifier (sd-id128) of the host.
    uint64 started_at = 3;    // Microseconds since epoch when the container started.
    string job_identity = 4;  // PeerId derived from the job's ephemeral keypair.
}
```

- `peer_id` -- the claimant daemon's PeerId (matches the `peer_id` from the
  accepted `JobClaim`).
- `machine_id` -- the systemd `machine-id` of the host. Stable across daemon
  restarts and useful for correlating jobs that ran on the same physical or
  virtual machine.
- `started_at` -- wall-clock timestamp when the container's PID 1 was exec'd.
  Used by the creator to measure claim-to-start latency and enforce deadlines.
- `job_identity` -- the PeerId derived from the job's ephemeral keypair. Other
  peers use this to verify DHT liveness records and GossipSub messages from the
  running job.

### JobExit

Published by the claimant when the container exits normally.

```protobuf
message JobExit {
    int32 exit_code = 1;                // Process exit code (0 = success).
    uint64 duration_ms = 2;             // Wall-clock duration from start to exit.
    repeated StoreOutput outputs = 3;   // Store objects produced (build jobs only).
    optional ReservationToken reservation = 4;  // Slot reservation for follow-up jobs.
}

message StoreOutput {
    string store_hash = 1;   // Content address of the output store object.
    string name = 2;         // Output name (e.g. "out", "dev", "lib").
    uint64 nar_size = 3;     // Size of the output in NAR-serialized bytes.
}
```

- `exit_code` -- the container's PID 1 exit code. Zero indicates success. For
  build jobs, a non-zero exit code means the build failed and `outputs` will be
  empty.
- `duration_ms` -- milliseconds elapsed between the `started_at` timestamp in
  `JobStart` and the container exit. Useful for scheduling heuristics and build
  time estimation.
- `outputs` -- for `ACTIVATION_DERIVATION` jobs, the store objects written to
  the overlay during the build. Each output has a content-addressed `store_hash`
  that other peers can use to fetch the result via the store transfer protocol.
  For other activation types, this field is empty.
- `reservation` -- an optional `ReservationToken` offering the job creator a
  reserved slot on this builder for a follow-up job. See
  [Slot Reservation](#slot-reservation) below.

### JobError

Published by the claimant (or the creator on crash detection) when the job
fails unexpectedly.

```protobuf
message JobError {
    string message = 1;           // Human-readable error description.
    int32 exit_code = 2;          // Process exit code, if the container exited.
    string phase = 3;             // Lifecycle phase where the error occurred.
    uint64 duration_ms = 4;       // Wall-clock duration from start to failure.
    ErrorSource source = 5;       // What produced the error.
}

enum ErrorSource {
    ERROR_SOURCE_CONTAINER = 0;   // The container process itself failed.
    ERROR_SOURCE_RUNTIME = 1;     // The container runtime (systemd-nspawn) failed.
    ERROR_SOURCE_LIVENESS = 2;    // DHT liveness record expired (crash detected).
    ERROR_SOURCE_TIMEOUT = 3;     // Job exceeded its deadline.
}
```

- `message` -- free-form error string. For container errors, typically the last
  line of stderr or the OOM kill reason. For liveness errors, a string like
  "DHT liveness record expired after {ttl}ms".
- `exit_code` -- the container exit code if the container actually exited. Zero
  when the error is a liveness timeout or runtime failure where no exit code is
  available.
- `phase` -- which lifecycle phase the error occurred in: `"starting"` (container
  failed to launch), `"running"` (container crashed mid-execution), or
  `"unknown"` (crash detected via DHT expiry with no further detail).
- `duration_ms` -- milliseconds elapsed from `started_at` to the error. Zero if
  the container never started.
- `source` -- categorizes the error origin for programmatic handling by the
  creator (e.g., retry on `LIVENESS` or `TIMEOUT`, do not retry on `CONTAINER`
  with exit code 1).

### JobCancel

Published by the creator or an authorized peer to terminate a job.

```protobuf
message JobCancel {
    string cancelled_by = 1;   // PeerId of the peer requesting cancellation.
    string reason = 2;         // Human-readable cancellation reason.
    uint64 cancelled_at = 3;   // Microseconds since epoch.
}
```

- `cancelled_by` -- the PeerId of the peer that initiated the cancellation.
  Must match the issuer of the UCAN attached to the `JobPost` delta. Typically
  the job creator, but any peer with the appropriate `/aos/job/announce`
  capability scoped to the `cancel` operation may cancel.
- `reason` -- free-form string explaining why the job was cancelled. Examples:
  "superseded by newer build", "user requested", "dependency failed".
- `cancelled_at` -- wall-clock timestamp of the cancellation request. Used to
  order concurrent cancel and exit deltas (if both arrive, the earlier timestamp
  wins in CRDT merge).

### JobState

Active job state stored in the DHT liveness record at `aos:cluster:{cluster_ident}:job:{job_ident}:state`.
Refreshed periodically by the running container with a short TTL.

```protobuf
message JobState {
    string job_id = 1;          // The job's unique identifier.
    string peer_id = 2;         // PeerId of the executing peer.
    uint64 refreshed_at = 3;    // Microseconds since epoch of last refresh.
    JobPhase phase = 4;         // Current lifecycle phase.
    ResourceUsage usage = 5;    // Current resource consumption.
}

enum JobPhase {
    JOB_PHASE_STARTING = 0;
    JOB_PHASE_RUNNING = 1;
    JOB_PHASE_STOPPING = 2;
}
```

- `refreshed_at` -- the timestamp of the most recent DHT record refresh. Peers
  compare this to the record's TTL to determine liveness.
- `phase` -- the container's current phase. `STARTING` while the init process
  is launching, `RUNNING` during normal execution, `STOPPING` during graceful
  shutdown (e.g., after receiving a cancel signal).
- `usage` -- current resource consumption, reusing the `ResourceUsage` message
  from the LoadReport protocol (cpu_fraction, memory_used_bytes,
  disk_used_bytes). Allows the creator to monitor job resource usage without
  streaming logs.

## Two-Phase Start Handshake

The two-phase design exists because two separate authorization proofs are
needed:

**start_ucan (claimant provides)**: "I authorize this job to execute on my
resources." The claimant creates this UCAN when it claims the job. It grants
the job identity holder the `/aos/job/start` capability scoped to this specific
job. This proves the claimant consents to run the workload.

**job_ucan (creator provides)**: "I delegate the job's identity to you." The
creator holds the job identity (it created the job and its keypair). When it
selects a claimant, it delegates this identity via UCAN so the claimant can
sign DHT records and GossipSub messages as the job. This proves the creator
authorized this specific peer to act as the job.

Both UCANs are presented in the `JobStartRequest`. The claimant validates the
`job_ucan` chain (creator -> claimant) and the creator has already validated the
`start_ucan` chain (claimant -> job identity). Neither party can act
unilaterally: the claimant cannot start without the job identity delegation, and
the creator cannot force execution without the claimant's start authorization.

## Job Identity

Each job gets its own PeerId, backed by a unique keypair generated at job
creation time. This identity is:

- Created by the job creator as part of `JobSpec` construction.
- Delegated to the executing peer via `job_ucan` in the `JobStartRequest`.
- Injected into the job container via systemd secrets, making the keypair
  available to the containerized process.

This per-job identity enables the container to participate in libp2p as a
first-class peer:

- Publish and refresh its own DHT liveness record at `aos:cluster:{cluster_ident}:job:{job_ident}:state`.
- Sign `JobPost` state transitions (start, exit, error).
- Open stream protocols to fetch store content or stream logs.
- Advertise provider records for store objects it produces (build jobs).

The job's PeerId is distinct from the host peer's PeerId. Other peers in the
cluster see the job as a separate participant.

## Build DAG Management

The protocol does not manage build dependency graphs. DAG management is the
client's responsibility:

1. The client evaluates the full dependency graph for a build target.
2. It identifies leaf jobs (those with no unbuilt dependencies) and submits
   them as `JobPost{delta: create}` messages.
3. It watches the jobs announce topic for `exit` deltas on submitted jobs.
4. When a job completes, the client checks which previously-blocked jobs now
   have all dependencies satisfied and submits those.
5. This continues level by level until the root target completes.

This is a topological traversal: the client maintains the DAG, the cluster
executes individual jobs. The cluster has no knowledge of inter-job
dependencies.

Multiple leaf jobs can be submitted concurrently for parallel execution across
cluster peers. The degree of parallelism is controlled by the client (how many
jobs it submits at once) and the cluster (how many peers claim and execute
jobs).

## Slot Reservation

When a builder completes a job, it MAY include a `ReservationToken` in the
`JobExit` message. This token is a short-lived (~30 second) offer to the
original job creator: "I have a slot available for you -- skip the claiming
phase and call `/aos/job/start` directly."

### ReservationToken

```protobuf
message ReservationToken {
    string builder_peer_id = 1;
    string creator_peer_id = 2;
    uint64 valid_until = 3;          // epoch micros, ~30s from now
    bytes signature = 4;             // builder signs (creator_peer_id, valid_until)
}
```

The token is signed by the builder's key and scoped to the original creator's
PeerId. The builder includes it in `JobExit.reservation` when it has capacity
for another job and wants to offer the slot to the same creator.

### Reservation Flow

If the creator has a follow-up job in the DAG (a newly-unblocked dependency),
it can skip GossipSub announcement and claiming entirely:

1. Creator receives `JobExit` with a `ReservationToken`.
2. Creator has a pending job ready to submit.
3. Creator opens `/aos/job/start/1.0.0` directly to the builder and sends a
   `JobStartRequest` with the `reservation` field set.
4. Builder verifies: token is signed by me, not expired, `creator_peer_id`
   matches the caller, I still have capacity.
5. If valid, the builder starts the job immediately.
6. If the creator does not use the token within the validity window (~30s),
   the slot returns to the general scheduling pool.

### Comparison

```
First job (no reservation):
  JobPost{create} → GossipSub → claims arrive → pick first → exec → build → exit+reservation

Subsequent jobs (with reservation):
  Creator has reservation → /aos/job/start directly → build → exit+new reservation → ...
```

| Path | Overhead | Round-trips |
|---|---|---|
| Normal (GossipSub + claim) | ~1.6s | GossipSub broadcast + claim delay + start stream |
| Reservation | ~0.8s | Direct start stream only |

The reservation path eliminates the GossipSub round-trip and claim collection
delay, roughly halving per-job scheduling overhead. For deep build DAGs with
many sequential dependencies, this compounds significantly.

### Benefits

- **Reduced latency**: ~0.8s overhead per job instead of ~1.6s.
- **Chunk store locality**: the previous job's inputs are warm in the builder's
  local chunk store cache. Subsequent jobs in the same DAG often share large
  portions of their input closure, so keeping them on the same builder avoids
  redundant content transfers.
- **Chain scheduling**: a builder completing one job in a DAG can immediately
  start the next, forming a pipeline. Each `JobExit` offers a new reservation
  token, so the creator can chain jobs on the same builder as long as the DAG
  has sequential dependencies.

### Fallback

If the reservation is invalid, expired, or the builder is now at capacity, the
`JobStartRequest` is rejected with a `JobError`. The creator falls back to normal
GossipSub job submission: it publishes `JobPost{create}` and waits for
load-staggered claims as usual. Reservation is purely an optimization -- the
protocol is correct without it.

## Liveness and Crash Detection

While a job is running, the job container refreshes a DHT record at
`aos:cluster:{cluster_ident}:job:{job_ident}:state` with a short TTL. This serves as a heartbeat:

- **Healthy job**: the record exists in the DHT and is periodically refreshed
  before TTL expiry.
- **Crashed job**: the container stops refreshing. The DHT record expires when
  its TTL elapses.

Peers monitoring the job (the creator, other cluster members) can query this
DHT key. If the record is absent, the job is presumed dead.

The DHT record is signed by the `JobIdentity`, so only the running job can
refresh it. A peer crash or container failure naturally results in the record
expiring.

## Crash Recovery

When a job's DHT liveness record expires and no terminal delta (exit, error,
cancel) has been published to the JobPost CRDT, the job is in a failed state:

1. The DHT record at `aos:cluster:{cluster_ident}:job:{job_ident}:state` expires (no refresh from the
   crashed container).
2. The creator detects the missing liveness record.
3. The creator may publish `JobPost{delta: error(JobError)}` to record the
   failure in the CRDT.
4. The creator can then create a new job for the same work, restarting the
   claim/exec cycle.

The job is not "reclaimed" in place -- a new job with a new identity is
created. The original job's CRDT record remains as a historical entry with its
error state.

## JobPost CRDT Merge Semantics

`JobPost` is a CRDT: all peers in the cluster observe the same state
transitions through GossipSub, and concurrent or reordered messages converge to
a consistent view.

**Monotonic phase ordering**: the lifecycle phases form a total order (create <
claim < start < exit/error/cancel). A delta is only valid if it advances the
job's phase forward. A `claim` delta received after an `exit` delta is
discarded. This monotonicity ensures convergence regardless of message delivery
order.

**Multiple claims**: the `claim` phase is special -- multiple claim deltas are
valid for the same job (different peers offering to execute). The CRDT
accumulates all claims. The `start` delta (which follows the creator's start RPC)
resolves which claim was selected.

**Generation for crash recovery**: each `JobPost` carries sufficient
identification (cluster ID, job ID, nonce) to distinguish a retried job from
the original. If a job crashes and the creator submits a new job for the same
work, it is a distinct CRDT instance with a different job ID. The original
job's CRDT converges to its error state independently.

**Tie-breaking rules**: when two deltas target the same phase with the same
timestamp, deterministic tie-breaking ensures all peers converge to the same
state:

- **Same phase, same timestamp**: the delta with the lower `job_id`
  (lexicographic comparison) wins. This provides a total order across all peers
  without coordination.
- **Multiple claims, same timestamp**: the claim with the lowest `peer_id`
  (lexicographic) wins for ordering purposes. Since multiple claims are
  accumulated (not conflicting), this ordering affects only which claim is
  considered "first" for start timeout fallback.

**Consistency**: because GossipSub delivers to all cluster members and the
phase ordering is monotonic, all peers eventually agree on the current state of
every job. No coordination beyond message delivery is needed for consistency.

## Build Input Delivery

When a build job is posted, the creator must ensure that the builder daemon can
fetch all required inputs before the build begins. The flow is:

1. **Creator provides inputs.** The creator (CI runner, developer) calls
   `start_providing` on the DHT for the `.drv` file and all its input store
   objects before posting the `JobPost{delta: create}`. This ensures the DHT has
   provider records pointing to the creator for every input.

2. **Builder resolves the closure.** If the `JobStartRequest` included a
   manifest (the creator's hint), the builder uses it directly — no manifest
   fetch needed for the root object. The manifest's `references` and `closure`
   fields provide the transitive dependency tree. For any `ClosureHint` entries
   with empty references (frontier nodes where the creator lacked local
   knowledge), the builder fetches those manifests to discover their deps.

3. **Builder fetches missing content.** The builder checks which manifests and
   chunks from the resolved closure are already local. All missing content is
   fetched in parallel — manifests from providers, chunks batched across
   multiple providers. As new manifests arrive (for frontier nodes), they may
   reveal additional dependencies, which are fetched immediately. The builder
   streams `JobStartStatus{progress}` back to the creator during this phase.

4. **Builder creates a FUSE view.** The builder creates a view from the
   `ViewSpec` (see [view.md](view.md)) — all inputs must be fully local before
   the build starts. The FUSE mount blocks until every manifest and chunk is
   fetched.

5. **Builder mounts OverlayFS.** A writable upper layer is created on top of
   the read-only FUSE view. The merged mount is bind-mounted as `/nix/store`
   inside the container.

6. **Builder spawns the container.** The `.drv` file specifies the builder
   executable (e.g., `/nix/store/{hash}-bash/bin/bash`) and its arguments. The
   daemon reads these from the parsed `.drv` and passes them to
   `systemd-nspawn` as the container's init command.

## Job Record Lifecycle

Job CRDT records are local state maintained by each peer, not persisted in the
DHT. The DHT holds only the short-lived liveness heartbeat at
`aos:cluster:{cluster_ident}:job:{job_ident}:state`.

### Active Jobs

While a job is active (any phase from `posted` through `running`), `JobPost`
deltas accumulate in each peer's local CRDT state as they arrive via GossipSub.
All subscribed peers maintain a consistent view of the job's current phase.

### Completed Jobs

Jobs in a terminal state (`exited`, `errored`, `cancelled`) are retained in
local CRDT state for a configurable duration (default: 24 hours). This
retention window allows:

- Observability tools to query recently completed jobs.
- Late-arriving deltas (e.g., a `JobExit` that was delayed in transit) to be
  merged into the existing record rather than creating an orphaned entry.

After the retention period, the job record is pruned from local state.

### DHT Heartbeat Records

The DHT liveness record at `aos:cluster:{cluster_ident}:job:{job_ident}:state` expires naturally via its
short TTL after the job completes (the container stops refreshing). No explicit
cleanup is needed.

### Late-Joining Peers

A peer that joins the cluster after a job has completed will not see that job's
CRDT record unless it arrives within the retention window of a peer that still
holds the record and a protocol-level state sync occurs. Completed jobs are
ephemeral observations, not durable history.

## Container Exec

The `/aos/job/exec/1.0.0` stream protocol allows executing a command inside a
running job's container, similar to `docker exec`. This is useful for debugging,
inspection, and interactive access.

### Flow

1. Client opens `/aos/job/exec/1.0.0` stream to the builder hosting the job.
2. Sends `JobExecRequest` with command, TTY preference, and optional env/user.
3. Builder verifies: job exists, is RUNNING, requester has `/aos/job/exec`
   capability.
4. Builder uses `nsenter` to spawn the process in the container's namespaces
   (mount, PID, network, user).
5. Stream becomes bidirectional `ExecFrame` multiplexing:
   - daemon to client: stdout, stderr, exit
   - client to daemon: stdin, window resize, signals
6. When the process exits, daemon sends `ExecExit` frame and closes the stream.

### PTY Mode (tty=true)

- Daemon allocates a pseudoterminal in the container.
- stdout and stderr are merged through the PTY.
- Terminal control sequences (colors, cursor movement) pass through.
- `WindowResize` frames propagate SIGWINCH to the PTY.
- Interactive shells work naturally: bash, zsh, etc.

### Non-PTY Mode (tty=false)

- stdout and stderr are separate frame types.
- No terminal processing -- raw byte streams.
- Good for scripted commands: `aos exec {job_id} cat /etc/config`

### Use Cases

- **Debug a failed build**: container retained on failure, exec into it to
  inspect state.
- **Interactive shell**: `aos exec {job_id} bash -l`
- **One-off inspection**: `aos exec {job_id} ls -la /build/output/`
- **Live debugging**: exec into a running build to check progress.

## Stream Protocol Error Handling

Stream protocols used by the job system include error responses for fault
reporting:

- **`/aos/job/start/1.0.0`**: the `JobStartStatus` message already handles errors
  via its `oneof result { JobStart started = 1; JobError failed = 2; }`.
- **`/aos/job/log/1.0.0`**: responses are wrapped in `LogResponse`, which is a
  `oneof { LogEvent event = 1; StreamError error = 2; }`. A `StreamError` with
  code 404 is returned if the `job_id` in the `LogRequest` is unknown to the
  serving peer.
- **`/aos/job/exec/1.0.0`**: the builder sends an `ExecFrame` with an `ExecExit`
  on normal termination. If the job is not found or not running, the builder
  resets the stream with a protocol-level error before any frames are exchanged.
