# Job Lifecycle

Jobs are generic containers for executing work within a cluster. A job
encompasses any containerized task -- builds, login shells, services -- and
progresses through a well-defined lifecycle coordinated via CRDT state
transitions on GossipSub.

## Container Types

A job runs one of two container types, determined by its `JobSpec`:

**BuilderSpec** -- a build container with a writable store overlay for creating
new store objects. Network access is disabled and the container runs under
isolation equivalent to the nix sandbox. The output is one or more new store
objects written to the overlay.

**ProfileContainer** -- a profile container that runs a login shell, long-running
service, or other profile-based workload. Network access follows the profile
configuration (none or host NAT).

Both container types run a single container based on the referenced profile.
See [containers.md](containers.md) for the full container orchestration model,
including init processes, activation, OverlayFS setup, and output registration.

## State Diagram

```
         create
  [none] -------> [posted]
                    |
            claim   |  (one or more peers)
                    v
                 [claimed]
                    |
          exec RPC  |  (creator picks best claim)
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
- A container spec: either `BuilderSpec` (derivation path, writable store
  overlay, network disabled) or `ProfileContainer` (profile store hash).
- A node selector: required system architecture, features, and peer labels.
- Resource limits: max memory, CPU cores, and scratch disk.
- Network mode: `NETWORK_NONE` (required for builds) or `NETWORK_HOST` (for
  profile containers).

The job is now visible to all cluster members subscribed to the jobs announce
topic.

### 2. Claim

Eligible peers that are willing and able to run the job publish `JobPost`
messages with a `claim(JobClaim)` delta. Each claim contains:

- `peer_id` -- the claiming peer's identity.
- `exec_ucan` -- a UCAN granting the job identity holder permission to execute
  on this peer (see Two-Phase Exec below).

Multiple peers may claim the same job. Claims are not binding -- they are
offers.

### 3. Exec

The creator evaluates all received claims and picks the best one. "Best" is
determined by the creator; the protocol does not prescribe a selection
algorithm. This is not first-come-first-served.

The creator then opens a `/aos/job/exec/1.0.0` stream to the selected
claimant and sends an `ExecRequest` containing:

- `job_ucan` -- delegates the job identity to the claimant's peer, so the
  claimant can sign as the job.
- `exec_ucan` -- the same exec authorization the claimant provided in its
  claim, echoed back.

The claimant validates both UCANs and starts the container.

### Creator Offline Fallback

The two-phase exec handshake is the normal path. If the creator goes offline
after posting a job, two fallback behaviors prevent jobs from hanging
indefinitely:

- **Exec timeout**: if no exec call is made within `job_exec_timeout_ms` (from
  `ClusterConfig`) after the first claim, the first claimant (lowest peer_id
  among claimants with the earliest timestamp) auto-executes. The claimant
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
`aos:job:{job_ident}` with a short TTL (see Liveness below). The job container
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
- `outputs` -- for `BuilderSpec` jobs, the store objects written to the overlay
  during the build. Each output has a content-addressed `store_hash` that other
  peers can use to fetch the result via the store transfer protocol. For
  `ProfileContainer` jobs, this field is empty.

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

Active job state stored in the DHT liveness record at `aos:job:{job_ident}`.
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

## Two-Phase Exec Handshake

The two-phase design exists because two separate authorization proofs are
needed:

**exec_ucan (claimant provides)**: "I authorize this job to execute on my
resources." The claimant creates this UCAN when it claims the job. It grants
the job identity holder the `/aos/job/exec` capability scoped to this specific
job. This proves the claimant consents to run the workload.

**job_ucan (creator provides)**: "I delegate the job's identity to you." The
creator holds the job identity (it created the job and its keypair). When it
selects a claimant, it delegates this identity via UCAN so the claimant can
sign DHT records and GossipSub messages as the job. This proves the creator
authorized this specific peer to act as the job.

Both UCANs are presented in the `ExecRequest`. The claimant validates the
`job_ucan` chain (creator -> claimant) and the creator has already validated the
`exec_ucan` chain (claimant -> job identity). Neither party can act
unilaterally: the claimant cannot start without the job identity delegation, and
the creator cannot force execution without the claimant's exec authorization.

## Job Identity

Each job gets its own PeerId, backed by a unique keypair generated at job
creation time. This identity is:

- Created by the job creator as part of `JobSpec` construction.
- Delegated to the executing peer via `job_ucan` in the `ExecRequest`.
- Injected into the job container via systemd secrets, making the keypair
  available to the containerized process.

This per-job identity enables the container to participate in libp2p as a
first-class peer:

- Publish and refresh its own DHT liveness record at `aos:job:{job_ident}`.
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

## Liveness and Crash Detection

While a job is running, the job container refreshes a DHT record at
`aos:job:{job_ident}` with a short TTL. This serves as a heartbeat:

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

1. The DHT record at `aos:job:{job_ident}` expires (no refresh from the
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
accumulates all claims. The `start` delta (which follows the creator's exec RPC)
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
  considered "first" for exec timeout fallback.

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

2. **Builder fetches the derivation.** The builder daemon that claims and
   executes the job:
   a. Parses the `.drv` path from `JobSpec.container.builder.derivation`.
   b. Fetches the `.drv` via `get_providers` on `aos:store:{drv_hash}`, then
      requests the manifest via `/aos/store/manifest/1.0.0`, then fetches chunks
      via `/aos/store/chunk/1.0.0`. The `.drv` is a store object like any other.
   c. Parses the `.drv` to discover the input closure (all build-time
      dependencies -- the transitive set of store objects needed for the build).

3. **Builder fetches the input closure.** For each input store object in the
   closure, the builder follows the same provider discovery, manifest fetch,
   chunk fetch sequence. Inputs may be fetched from the creator, from other
   peers that hold the objects, or from a configured registry.

4. **Builder creates a FUSE view.** The builder creates a closure view (see
   [fuse.md](fuse.md)) in **eager mode** -- all inputs must be fully local
   before the build starts. The FUSE mount blocks until every manifest and chunk
   is fetched.

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
`aos:job:{job_ident}`.

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

The DHT liveness record at `aos:job:{job_ident}` expires naturally via its
short TTL after the job completes (the container stops refreshing). No explicit
cleanup is needed.

### Late-Joining Peers

A peer that joins the cluster after a job has completed will not see that job's
CRDT record unless it arrives within the retention window of a peer that still
holds the record and a protocol-level state sync occurs. Completed jobs are
ephemeral observations, not durable history.

## Stream Protocol Error Handling

Stream protocols used by the job system include error responses for fault
reporting:

- **`/aos/job/exec/1.0.0`**: the `ExecResult` message already handles errors
  via its `oneof result { JobStart started = 1; JobError failed = 2; }`.
- **`/aos/job/log/1.0.0`**: responses are wrapped in `LogResponse`, which is a
  `oneof { LogEvent event = 1; StreamError error = 2; }`. A `StreamError` with
  code 404 is returned if the `job_id` in the `LogRequest` is unknown to the
  serving peer.
