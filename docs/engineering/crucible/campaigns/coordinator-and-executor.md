# Coordinator, planner, and executor

Crucible implements one single-host campaign coordinator and one local
executor. It does not implement distributed scheduling, but the boundary
between campaign policy and host execution is a real interface, so the local
implementation does not acquire hidden process, filesystem, or QEMU
assumptions.

```text
users and automation
        |
        v
CampaignService
        |
        v
coordinator --------------> PlannerEngine
        |                   (pure planning transition)
        | ExecutorService
        v
local executor
        |
        +----> Crucible sessions and QEMU worlds
        +----> content store
```

These are logical components, not mandatory process boundaries. The daemon may
compose them in one process with direct in-process clients, but the same typed
operations are also exposed over versioned local transports, and conformance
tests run the same campaign through both paths and compare canonical results.

## Authority

| Component | Owns | Must not own |
| --- | --- | --- |
| Coordinator | Campaign reference, canonical validation, policy activation, planning order and accounting, attempt admission, result incorporation, retention intent | QEMU, host resources |
| Planner engine | Pure proposal calculation from an immutable planning basis | Reference writes, clocks, I/O, executor selection, store access |
| Local executor | Host resource admission, materialization choice, QEMU lifecycle, hot fork, checkpoint capture, operational telemetry | Branch values, policy, guidance, the campaign reference |
| Content store | Immutable bytes, conditional refs, placement receipts, tiering | Planning, result interpretation, execution |
| QEMU and plugin | Guest execution and GPL-side fork and checkpoint mechanisms | Campaigns, storage policy, objectives, guidance |

Only the coordinator advances a campaign reference. An executor may publish
immutable object bodies and return their IDs, but those objects become campaign
facts only after the coordinator authenticates every referenced body,
recomputes the child configuration and observation identities, and publishes a
snapshot. Physical materialization is executor-owned and never changes the
semantic attempt or configuration.

## Message model

The transport-independent message schema is authoritative. Rust types
implement it; they do not define it through native layout, `serde` defaults,
or enum representation. Messages have explicit versions, fixed-width integers,
bounded collections, stable error classes with retry meaning, and golden
vectors. Large or sensitive content travels by authenticated ID only: control
messages never embed RAM pages, disk extents, VMState, descriptors,
credentials, or host paths. Compatibility is negotiated by explicit versions
and capabilities, never by version ordering alone.

The campaign service, the local executor, and the planner each use a versioned
Unix-stream frame carrying the byte-identical canonical component messages
(`crucible_daemon::campaign_loopback`, `crucible_daemon::executor_loopback`,
`crucible_daemon::planner_loopback`). A frame is a magic, a message kind, and
a length-prefixed canonical body. A JSON projection exists for debugging and
CLI output only.

### Submission authority

Planner and debugger submissions use strict canonical messages:

```text
PlannerSubmissionV1  = version | expected_snapshot | proposal |
                       measured_usage | planner_tag
DebuggerSubmissionV1 = version | expected_snapshot | debug_session |
                       branch_request | debugger_tag
```

Each tag is a domain-separated keyed BLAKE3 authenticator over the preceding
fields (`crucible_campaign::authority`). Planner and debugger keys are
separate nonzero 256-bit operational credentials, configuration fails closed
if they are equal, and the keys never enter campaign objects, exports, logs, or
messages. Authentication proves which supervised component supplied the bytes;
it does not make their claims authoritative. Every submission still passes the
ordinary owner validation, and operator requests enter through an already
authenticated campaign-service principal. Only explicit operator discovery and
canonical observations can add the graph membership that any branch request
requires.

## Campaign service

`crucible_campaign::CampaignService` is the user-facing contract. Its
operations (`CampaignServiceOperation`) cover listing, creation, derivation,
status, snapshot and graph reads, choice, frontier, request-attempt, report,
and finding queries, attempt explanation, savepoints, trace and planner-ranking
reads, lifecycle and budget commands, pins, discovery and branch submission,
runtime attachment, and read-only debug sessions. Every read is bound to one
exact snapshot and returns proof-bearing pages; mutations carry a command ID
and expected snapshot so retries are idempotent.

## Lazy frontier

The frontier is a pull-based collection of suspended candidate sources. The
durable store never serializes a closure, trait object, or VM stack. It stores
the closed generator specifications, bounded immutable branch requests, stable
IDs, immutable proposals and observations, and optional authenticated
projection caches. A continuation is recomputed as a pure fold: a static
sampler's cursor is its first unissued ordinal, and an adaptive sampler's
partition comes from the observation set. Deleting every projection and
restarting reconstructs an equivalent frontier.

```text
claimable work = admitted attempts
               - completed observations
               - explicit non-modeled terminal dispositions
               - currently live local reservations
```

Readiness derives from semantic facts and policy only. Reservations affect
local claimability, never whether an attempt exists. Frontier APIs paginate,
and page size, RPC chunking, and restart boundaries never change a
deterministic planner result. Selecting across a large frontier is itself a
suspended computation: the coordinator serves a snapshot-bound scan ordered by
stable continuation key, the planner may answer `ContinueScan`, and a changed
snapshot restarts the scan instead of mixing pages from different views.

Admitted-but-unreserved attempts, in-flight attempts, live QEMU worlds, paused
hot children, and dirty-memory bytes have independent backpressure limits.
Reaching one pauses proposal issuance or demotes materializations; it never
prunes semantic branches or reports domain exhaustion.

```text
resource slot opens
  -> supervisor selects one ready source
  -> planner polls its iterator or generator once
  -> publish proposal, admit or reuse semantic attempt
  -> executor reserves the attempt locally
  -> executor chooses a realization (hot / exact / thin)
  -> run, publish observation
  -> coordinator credits the path and updates projections
```

### Feedback

Every attempt carries its branch path. On canonical completion the
coordinator credits the observation to the expansion state at each branch
point on that path (see [continuation state](data-model.md#continuation-state)).
No in-memory search stack is needed.

## Daemon runtime

The relevant `crucible-daemon` modules:

| Module | Responsibility |
| --- | --- |
| `campaign_bootstrap` | Durable directory storage, strict policy, managed endpoint, and listener ownership |
| `campaign_server`, `campaign_loopback`, `campaign_endpoint` | The authenticated local campaign listener, its transport, and the socket namespace |
| `campaign_policy` | The immutable Unix-identity and operation-grant policy |
| `campaign_attachment`, `campaign_runtime_control` | Binding a planner and executor to a named campaign; runtime attachment messages |
| `campaign_runtime` | One long-lived thread per attached campaign driving the supervisor step machine |
| `planner_process`, `planner_loopback` | Killable supervision of the out-of-process canonical planner |
| `executor_supervisor`, `executor_pool`, `executor_worker`, `executor_service`, `executor_server`, `executor_loopback` | The local executor |
| `assignment_ledger` | Crash-safe executor idempotency and attempt runtime state |
| `repository_admission` | The read-only semantic boundary used to validate assignments |

### Supervisor and runtime

`crucible_campaign`'s `CampaignSupervisor` composes the planner and executor
drivers over one repository. Each step reloads the exact lifecycle projection
and performs at most one component operation. Running campaigns give
already-admitted work priority; one empty executor scan enables at most one
planner invocation, keeping the ready buffer bounded. Paused campaigns never
page new work. `Drain` polls only held reservations, `CancelAndRetry` cancels
or releases one reservation per step, and `ExactCheckpoint` requests one exact
execution checkpoint per step and keeps that reservation through durable
publication.

`campaign_runtime` gives each attached campaign one fixed thread. It continues
immediately only when the previous step allows another bounded operation,
otherwise it sleeps until an explicit progress wake or a fallback poll
(configurable from 1 ms to 60 s, default 100 ms). Even a continuous progress
chain pauses for at least 1 ms after 256 operations. Shutdown is sticky. A
repository, planner, or executor failure terminates the runtime visibly rather
than looping.

At most 256 campaigns may be attached. `crucible serve` accepts an explicit
campaign set or `--campaign-runtime-all`, and `crucible campaign attach`
adds an existing campaign at runtime through an authorized operation. All
campaigns attached to one packaged-executor pool share its exact compatibility
profile, and each distinct scenario gets its own baked-genesis entry. The
daemon authenticates the complete scenario catalog (at most 128 MiB of record
bodies) before acquiring QEMU resources.

### Planner process

The daemon never runs the pure planner on an authority-bearing thread. It
starts the packaged `crucible` executable in a hidden worker mode, exchanges
one bounded canonical `PlannerRequest` over pipes under a cancellation and
deadline boundary, and kills the process group on cleanup. The child returns
an unauthenticated `PlannerStepProposal`; measured fuel and authority stay with
the parent, which recomputes accounting and validates the transition.

## Attempt reservations

Reservations are volatile operational hints owned by one daemon incarnation,
keyed by `(attempt, daemon epoch, worker slot, generation)`. Restart discards
them under the old epoch, and every admitted attempt without a canonical
observation becomes claimable again. Claimable work is projected directly from
one authenticated snapshot by scanning the accounting root and removing
attempts that have an observation or a terminal disposition. The continuation
token carries the snapshot identity; a head advance rejects the old token.

The authoritative observation index maps `AttemptId` to `ObservationId` by
conditional create. Repeating the same pair is idempotent. A different
observation for a completed attempt is retained as determinism-defect evidence
and is never chosen by arrival time. A crash after publishing an observation
but before releasing a reservation causes at worst a duplicate execution.

The coordinator-owned executor driver consumes at most one accounting page and
one checked executor exchange per call. `Backpressure` and `UnavailableInput`
release the lease so the next scan uses a fresh assignment ID. `Unauthorized`
requires local reconfiguration and never fabricates a campaign fact. Because
the deployment has exactly one eligible executor, a stable `Incompatible`
response closes the ordinal with `AttemptClosed(PermanentlyIncompatible)`.

## Executor service

The executor contract is a set of traits in `crucible_campaign` with direct and
loopback implementations:

| Trait | Operations |
| --- | --- |
| `ExecutorService` | `submit_attempt` |
| `ExecutorStatusService` | `get_attempt_execution` |
| `ExecutorControlService` | `checkpoint_attempt_execution`, `cancel_attempt_execution` |
| `ExecutorResumeService` | `resume_attempt_execution` |
| `ExecutorCapabilityService` | `describe_executor`, `watch_capacity` |

An assignment binds an operational `AssignmentId` and daemon epoch (nonzero
128-bit values) to the lineage, attempt, nonzero CPU, resident-memory, and
execution-quantum ceilings, a writable-disk allowance, and a retention intent
(discard, retain on modeled failure, or retain always). The attempt record is
itself the execution specification; there is no second spec identity. Start
modes are execute, materialized-start capture, savepoint capture, and
selected-savepoint start. An `AttemptExecutionScope` is either `semantic` or a
savepoint capture bound to its request fact, and it is carried explicitly in
every status, checkpoint, and cancel request. These fixed-field messages are
strictly decoded and limited to 4 KiB. Every response repeats the assignment,
epoch, and attempt and carries a digest of the complete request, which
untrusted adapters must verify.

### Worker pool

`LocalExecutorWorkerPool` creates 1 to 256 fixed worker threads at startup and
never grows. Assignment replay and epoch checks run under a short supervisor
actor; repository-backed admission validation runs outside it and is rechecked
before acceptance. Guest execution, candidate preflight, and immutable
publication happen outside the actor. Retryable worker failure requeues the
same execution; retryable publication failure retries only that phase without
re-running the guest. A caught panic poisons the executor incarnation and
cancels active work. Shutdown is sticky, cancels active work, and releases
resources only after workers acknowledge exit.

### Assignment ledger

`assignment_ledger` separates immutable assignment replies from mutable
per-attempt runtime state. Records are directly addressed by assignment or
attempt identity, bounded, checksummed, strictly decoded, and published by an
fsynced staging file plus atomic link or rename. Restart accepts only current
records and fails closed on any other shape. A new daemon epoch may replace a
stale `running` record. Completion and cancellation are conditional idempotent
transitions: an exact replay succeeds, the opposite terminal outcome reports
the winner, and a different second observation is a determinism conflict.

Exact checkpoint capture runs through persisted `checkpoint-requested`,
`checkpoint-publishing`, and `paused` states. The executor stages every
expected root before immutable writes, retains source and replacement roots for
GC and restart, and releases capacity only after durable pause. See
[hot fork and checkpoints](hot-fork-and-checkpoints.md).

## Recovery

After restart the coordinator reconstructs claimable work from the snapshot.
The executor discards stale process handles, reconciles surviving processes
under a new epoch, inventories authenticated materializations, and accepts
idempotent resubmission. No durable worker lease is required. Deleting every
reservation, process handle, watch, capacity report, and placement receipt
leaves enough canonical state to recover the campaign and resubmit incomplete
attempts.
