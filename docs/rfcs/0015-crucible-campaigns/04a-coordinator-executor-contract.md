# 04a — Component contracts and local executor boundary

RFC-0015 implements one single-host campaign coordinator and one local Crucible
executor. It does not implement distributed scheduling. It nevertheless treats
the boundary between campaign policy and host execution as a production
interface from the first implementation, so local mode does not acquire hidden
Rust, process, filesystem, or QEMU assumptions that a later coordinator would
have to reverse.

The contract follows a Unix-style decomposition:

```text
users and automation
        |
        v
CampaignService
        |
        v
CampaignCoordinator --------> PlannerEngine
        |                       pure planning transition
        | ExecutorService
        v
LocalExecutor
        |
        +----> Crucible sessions and QEMU worlds
        |
        +----> ContentStore
```

These are logical components, not mandatory process boundaries. The initial
Rust implementation may compose them in one daemon and use an allocation-free
in-process client. It must also expose the same typed operations over the
versioned RPC transport and pass one conformance suite through both paths.

The dependency-free semantic center is the `crucible-campaign` crate. It owns
portable IDs, canonical campaign objects, the pure projector and planner
contracts, and no QEMU or transport implementation. `crucible` adapts those
types to scenario execution, `crucible-api` owns wire DTOs and adapters, and
`crucible-daemon` owns the sole-writer actor and local executor. Existing
campaign manifests, search worklists, adaptive-search structs, and explicit
fork queues are migration inputs; none remains a second authority after its
campaign-service adapter lands.

## 04a.1 Authority and ownership

| Component | Owns | Must not own |
| --- | --- | --- |
| `CampaignCoordinator` | Campaign ref, canonical validation/encoding, policy activation, planning order and accounting, attempt admission, result incorporation, retention intent | QEMU handles, host placement internals, storage credentials |
| `PlannerEngine` | Pure proposal calculation from an immutable planning basis | Campaign ref writes, clocks, I/O, executor selection, QEMU or store access |
| `LocalExecutor` | Host resource admission, materialization choice, QEMU lifecycle, hot fork, checkpoint capture, operational telemetry | Branch values, campaign policy, guidance, campaign ref updates |
| `ContentStore` | Immutable bytes, conditional mutable refs, placement receipts, tier promotion and eviction | Campaign planning, result interpretation, QEMU execution |
| QEMU/plugin | Guest execution and GPL-side fork/checkpoint mechanisms | Campaigns, storage policy, objectives, guidance |

Only the coordinator may advance a campaign ref. An executor may receive a
restricted immutable-object write capability, publish object bodies, and return
their IDs, but never receives a mutable-ref capability. Those objects become
campaign facts only after the coordinator authenticates every referenced body,
recomputes the child configuration and observation identities, validates their
structure, and publishes a snapshot. A store never interprets a branch request,
proposal, observation, or finding.

- **[CCOMP-1]** Campaign coordination, pure planning, host execution, content
  storage, and QEMU execution MUST be distinct interfaces even when the initial
  implementation composes them in one process.
- **[CCOMP-2]** Exactly one coordinator instance is the writer for one campaign
  ref in this RFC. Executors and planner engines MUST NOT advance that ref.
- **[CCOMP-3]** Physical materialization selection is executor-owned and MUST
  NOT alter the semantic attempt or configuration presented by the coordinator.

## 04a.2 Deployment compositions

The supported deployment is:

```text
crucible CLI -> local CampaignService
                    |
              one coordinator
                    |
              one local executor
                    |
              local QEMU worlds
```

The coordinator and executor may be linked into one daemon, connected through a
Unix socket, or exercised as two local processes by the conformance harness.
Those forms are semantically equivalent. An out-of-process local test is not a
distributed campaign: it proves that no in-process handle leaked into the
contract.

A future system may implement `CampaignService` itself and invoke
`ExecutorService` on more than one host. That system owns placement,
authentication between hosts, membership, failover, partitions, and any
distributed consensus. None of those behaviors or their implementation is
defined by this RFC.

- **[CCOMP-4]** The release conformance suite MUST run the same local campaign
  through direct in-process and out-of-process loopback adapters and compare
  canonical snapshots, attempts, observations, and findings.
- **[CCOMP-5]** Multi-host placement, membership, leader election, network
  partition handling, and remote page serving are explicit non-goals of this
  RFC.

## 04a.3 Normative message model

The transport-independent message schema is authoritative. Rust request types
and traits implement that schema; they do not define it through native layout,
`serde` defaults, or compiler-specific enum representation. The message model
specifies:

- protocol and method versions;
- fixed-width integer and canonical identifier encodings;
- required, optional, and reserved fields;
- unknown-field and unknown-variant behavior;
- bounded collection and byte-string lengths;
- stable error classes and retry meaning;
- capability negotiation;
- golden request, response, event, and rejection vectors.

The external campaign-service binding follows RFC-0010's HTTP/2
gRPC/Connect-style transport. The single-host executor conformance binding is a
smaller versioned Unix-stream frame carrying the byte-identical canonical
component messages; adopting a language framework is not a prerequisite for
the local executor boundary. A JSON projection is provided for debugging and
CLI structured output; canonical campaign object bytes retain their own codec.
Large artifacts do not travel in control messages.

Local-only acceleration may use a negotiated ancillary Unix-socket operation
to pass an already validated descriptor. Such an operation is optional, never
appears in canonical objects, and always has a content-ID fallback. It does not
cross the Apache/GPL QEMU boundary unless that separate protocol explicitly
defines it.

- **[CCOMP-6]** Wire schemas and conformance vectors, rather than Rust-native
  types, MUST be the normative cross-component contract.
- **[CCOMP-7]** Every direct client method and RPC method MUST share one
  command/result vocabulary, validation path, error taxonomy, and authorization
  rule.
- **[CCOMP-8]** Control messages MUST refer to large or sensitive content by
  authenticated ID. They MUST NOT embed RAM pages, disk extents, opaque VMState,
  native descriptors, credentials, or host paths.
- **[CCOMP-9]** Compatibility MUST be negotiated by explicit versions and
  capabilities. Version ordering alone MUST NOT imply compatibility.

Planner and debugger submission authorization uses strict, bounded canonical
component messages in the initial direct adapter and the future loopback RPC:

```text
PlannerSubmissionV1 = version | expected_snapshot | proposal |
                      measured_usage | planner_tag
DebuggerSubmissionV1 = version | expected_snapshot | debug_session |
                       branch_request | debugger_tag
```

Each tag is keyed BLAKE3 over all preceding canonical fields with a distinct
message domain. Planner and debugger keys are separate nonzero 256-bit
operational credentials: possessing one never permits producing the other's
tag. Configuration fails closed if both roles are supplied the same key
material. The keys are coordinator configuration and MUST NOT enter campaign
objects, snapshots, exports, logs, or the messages themselves. The coordinator
strictly decodes and authenticates a submission before any immutable-object write, then
independently applies the ordinary planner or branch owner validation. The tag
therefore proves which supervised component supplied exact bytes; it does not
make their semantic claims authoritative.

The operator direct adapter runs inside an already authenticated
`CampaignService` principal context. It accepts only operator-caused requests;
the debugger adapter accepts only a request whose cause names the authenticated
debug session. The raw repository owner mutations are coordinator-internal.
Explicit operator choice discovery and canonical observations are the only
paths that can add the graph membership required before any authority submits a
branch request. An RPC adapter must decode these same canonical messages and
call the same public authority adapter, rather than translating into a more
privileged internal mutation.

- **[CCOMP-23]** Planner, debugger, and operator submissions MUST enter through
  authority-specific adapters. Planner and debugger messages MUST use distinct
  operational keys, bind the exact expected snapshot and payload, and fail
  authentication before publishing any object or changing the campaign ref.
- **[CCOMP-24]** Direct and RPC adapters MUST strictly decode and authenticate
  the same canonical submission bytes before invoking the same semantic owner
  path. Component authentication MUST NOT grant authority over accounting,
  campaign facts, refs, execution, or choice-knowledge membership.

## 04a.4 Campaign service

`CampaignService` is the sole user-facing campaign API and is equally usable by
the CLI, an in-process caller, and a future external coordinator implementation:

```text
CreateCampaign        GetCampaign          ApplyCampaignCommand
GetSnapshot           QueryGraph           QueryFrontier
QueryChoices          SubmitBranchRequest  DeriveCampaign
QueryFindings         ExplainObject        WatchCampaign
```

Every mutation carries an idempotent command ID and expected snapshot ID.
`WatchCampaign` is a resumable convenience stream; the campaign ref and
immutable objects remain authoritative. A stale or lost watch cursor therefore
cannot lose campaign state.

- **[CCOMP-10]** The CLI MUST target `CampaignService` through a client
  abstraction and MUST behave identically whether the endpoint is embedded,
  local RPC, or a compatible future implementation.
- **[CCOMP-11]** Administrative executor and store operations MUST remain
  separate from ordinary campaign commands so placement and backend drivers do
  not leak into campaign authoring or result identity.

## 04a.5 Pure planner engine

The initial planner is a Rust implementation over the closed, versioned
generators in §03. The extension boundary is a bounded pure transition:

```rust,illustrative
pub struct PlannerRequest {
    pub policy: CampaignPolicyId,
    pub policy_artifact: PolicyArtifactId,
    pub invocation: PlannerInvocationId,
    pub planner_state: PlannerStateId,
    pub input_view: CampaignViewId,
    pub input_bundle: CampaignPlanningBundle,
    pub scan_page: PlanningScanPage,
    pub budget: PlanningBudget,
    pub engine: PlannerEngineId,
}

pub struct PlannerStepProposal {
    pub invocation: PlannerInvocationId,
    pub next_state: PlannerState,
    pub usage_claim: PlanningUsage,
    pub explanation: GuidanceEvidence,
    pub disposition: PlannerProposalDisposition,
}

pub enum PlannerProposalDisposition {
    ContinueScan { cursor: PlanningScanCursor },
    Issue {
        selected: PlanningScanPosition,
        branch_requests: Vec<BranchRequest>,
        proposals: Vec<Proposal>,
    },
    NoWork,
}
```

The coordinator supplies a bounded immutable view resolved from
`input_view`. Direct invocation borrows the same typed bundle that the RPC
adapter encodes canonically; an engine never receives an ID without the bounded
language-neutral data needed to interpret it. The bundle contains only objects
reachable through the declared planning view and is limited by object count,
bytes, depth, and planner fuel. The coordinator evaluates or invokes the engine,
validates every returned domain/value/reference and budget, computes accounting
itself, then records the accepted `PlannerStep`. `PlanningUsage` is retained as
diagnostic planner output but never substitutes for coordinator accounting.
The accepted step replaces by-value outputs with authenticated IDs and uses the
corresponding closed `PlannerDisposition`; only its `Issue` variant names a
selected source or semantic outputs.
Accepted steps retain both the untrusted planner `usage_claim` and distinct
coordinator accounting for output counts, admitted/deduplicated attempts, input
objects, input bytes, and deterministic fuel. The coordinator advances only the
snapshot's non-semantic `coordination_root` for `ContinueScan` and `NoWork`, so
the next invocation resumes the byte-identical planning view. The transition is
an exact three-index update: step identity, invocation result, and current
planner head. Reusing an invocation with different result bytes is a
determinism failure; importing extra or missing coordination entries fails
closed. `Issue` is accepted only at EOF for an authoritative selected source.
One snapshot transition then preserves the existing sole-writer contracts by
inserting exact planner-caused requests, finite proposals, deterministically
derived selections/paths/attempts, execution-basis or additional-cause
admissions, coordinator accounting, and the three coordination indexes. Local
publication and imported-snapshot validation use the same owner projection;
extra, missing, cross-invocation, or selection-mismatched facts fail closed.
Local acceptance MUST complete a read-only semantic preflight of the output,
coordinator accounting, next-state engine continuity, and prospective step
before publishing any output body or Merkle node; imported validation MUST
remain read-only. Repeated generated requests share validation by
generator/domain pair, and all cache misses together MUST visit at most
1,000,000 generator records in one projection pass.
Loading an accepted `Issue` requires its authoritative snapshot;
the standalone step object cannot prove admission or deduplication roots.
Planner code cannot issue commands directly. A future engine implemented in
another language is a supervised replaceable component identified by its
artifact, engine, protocol, and parameter versions.

`PolicyArtifactId` binds the canonical policy artifact or built-in engine
identity, dependency lock, planner ABI, engine version, arguments, and any
source or compiled artifact required to reproduce it. `PlannerState` is bounded
portable data. It is never a language stack, closure, heap, actor/process,
native trait object, or runtime continuation. Repeating one invocation must
return byte-identical canonical output; disagreement is a planner-determinism
failure.

A globally ordered frontier need not fit in one bundle. The coordinator serves
snapshot-bound pages in canonical continuation-key order. The invocation ID
commits to the exact prior cursor, page limit, ordered request positions, EOF
bit, and sum of canonical served request-body bytes. The input bundle contains
exactly those served request bodies in that scan segment and their authenticated
interpretation dependencies, with no additional scan candidate. On acceptance
and imported snapshot validation, the coordinator owner recomputes the page
from the named view. `ContinueScan` is valid only before EOF and must return the
last served position; `NoWork` is valid only at EOF. Coordinator accounting
must equal the committed served object and byte counts. The coordinator derives
the next page start from durable planner history: `None` for the first page or
after a semantic-view change, and exactly the prior `ContinueScan` cursor for a
same-view continuation. It rejects reopening a same-view scan after `NoWork`.
Portable planner state carries the scan cursor, best candidate and score
evidence accumulated so far, immutable view identity, and remaining fuel. The
engine may suspend with
`ContinueScan`; changing page size or RPC chunking must yield the same eventual
selection and evidence. A page from another view, a skipped key, or a cursor
replay with different bytes is rejected.

- **[CCOMP-12]** A planner step MUST be a deterministic function of its named
  engine and artifact, policy, planner state, complete planning view, explicit
  budget, and canonical bounded input bundle. Pagination and transport chunking
  MUST NOT alter the result of a completed snapshot-bound scan.
- **[CCOMP-13]** The planner MUST NOT read wall time, worker completion arrival
  order outside the recorded mode, host load, store placement, credentials, or
  other undeclared I/O while producing canonical output.
- **[CCOMP-14]** The coordinator MUST validate planner output independently;
  invoking a planner does not grant authority to publish facts, calculate
  authoritative accounting, advance refs, or execute work.
- **[CCOMP-15]** Embedding a general-purpose user campaign language or accepting
  arbitrary in-process planner callbacks is outside this RFC. The first engine
  is the closed Rust implementation.

## 04a.6 Local executor service

`ExecutorService` is implemented and tested in this RFC even though it has one
local implementation:

```text
DescribeExecutor      WatchCapacity
SubmitAttempt         GetAttemptExecution
WatchExecutions       CancelExecution
QueryMaterializations EnsureMaterialization
RetainExactClosure    EvictMaterialization
GetHealth
```

The first bounded assignment messages are:

```text
SubmitAttemptRequestV1 = version | assignment_id | daemon_epoch | lineage_id |
                         attempt_id | resource_limits | retention_intent

resource_limits = maximum_vcpus | maximum_resident_bytes |
                  maximum_disk_bytes | maximum_execution_quanta

SubmitAttemptResponseV1 = version | assignment_id | daemon_epoch | attempt_id |
                          request_digest | disposition
```

The canonical `AttemptId` names the immutable `Attempt` record and is itself
the execution specification; the protocol deliberately does not create a
second `AttemptSpecId` semantic authority. `CampaignLineageId` supplies the
compatibility basis the executor must authenticate. CPU, resident-memory, and
execution-quantum ceilings are nonzero; a zero writable-disk allowance is
valid. Retention is one of discard, retain on modeled failure, or retain
always. These fixed-field messages are strictly decoded and limited to 4 KiB.

`AssignmentId` and the daemon epoch are nonzero 128-bit operational values.
The response repeats the assignment, epoch, and attempt and carries a
domain-separated digest over every canonical request field. An untrusted
adapter must reject a response whose digest does not match its exact request,
including resource and retention fields. `SubmitAttempt` returns one of:

```text
accepted(execution ID)
already-running(execution ID)
already-completed(observation ID)
rejected(incompatible | backpressure | unavailable-input | unauthorized |
         conflicting-assignment)
```

Exact retry of one assignment ID and byte-identical request reproduces its
original response. Reusing that ID with any changed canonical field returns
`conflicting-assignment`; it is never a transport error or a cached response
from the prior request. Retrying transient backpressure or unavailable input
uses a fresh assignment ID. Incompatible, unauthorized, and conflicting
assignments require changed compatibility, authority, or caller state rather
than a blind retry.

The implementor-facing Rust `ExecutorService` trait implements this same vocabulary.
Incompatibility, backpressure, unavailable input, and authorization are normal
protocol outcomes rather than transport errors. A coordinator-facing
`ExecutorClient` wraps both direct and future RPC services and rejects a
response that does not bind the complete request; raw service invocation is not
a coordinator path. The repository then authenticates the named lineage and
attempt closure for every outcome. Before accepting `already-completed`, it
also loads the full observation closure, requires its `AttemptId` to equal the
request, and requires the attempt start and observed child to belong to the
named lineage's exact `ScenarioArtifactId`, not merely the same semantic
`ScenarioDefId`. The repository-backed admission adapter and strict loopback
transport consume these exact canonical bytes and validators. The local worker
now resolves one accepted request into an immutable `AttemptExecutionInput`:
exact lineage and scenario artifact, attempt, branch path, starting
configuration, and, for a branch, the selection/opportunity/domain tuple
authenticated together. An execution-model adapter receives that value and
returns an `ObservationCandidate` bundle. The concrete QEMU/session adapter
remains the next implementation checkpoint.

The bounded loopback binding is:

```text
ExecutorLoopbackFrameV1 = magic[8] | kind:u8 | reserved[3] |
                          body_length:u32be | canonical_body[body_length]

kind = submit-attempt-request(1) | submit-attempt-response(2)
magic = "CRUCEX01"
```

The body limit is 4 KiB and is checked before allocation. Reserved bytes must
be zero, message kind is directional, canonical decoding is strict, and the
client authenticates the response against the exact request. The frame carries
no paths, descriptors, large artifacts, credentials, native layout, or QEMU
objects. Direct and loopback adapters invoke the same `ExecutorService` and
checked-client validation path. Both directions have configurable nonzero
absolute operation deadlines, capped at one hour; progress does not reset a
deadline, so partial/drip headers and bodies or a peer that stops reading cannot
pin a connection indefinitely. Any framing, semantic, I/O, or service error
shuts down both stream directions before the server returns.

The single-host daemon persists two bounded operational record families:

```text
AssignmentRecordV1 = magic | request_bytes | response_bytes | checksum

AttemptStateRecordV2 = magic | lineage_id | attempt_id |
                       execution_basis_digest |
                       (running | publishing | completed | canceled) |
                       daemon_epoch | execution_id | observation_id? |
                       checksum
```

Each record is at most 16 KiB, carries a domain-separated checksum, and strictly
decodes all embedded component messages and typed IDs. Immutable assignment
records are addressed directly by `AssignmentId` and published by fsynced
staging plus an atomic hard link. Mutable attempt-state records are addressed
directly by a domain-separated digest of `(CampaignLineageId, AttemptId)` and
use an fsynced atomic replacement under one nonblocking directory writer lock.
Their execution-basis digest commits to that pair plus the complete resource
limits and retention intent, but excludes assignment and daemon-epoch
identities. Restart therefore reads only requested and active IDs; it does not
load assignment history into memory. The in-memory ledger implements the
identical trait only for fake components and tests.

The bounded local supervisor persists `running` before publishing `accepted`.
If response publication is indeterminate, it retains and queues the prepared
work before returning the service error, so a response that became visible can
never name an abandoned execution. Exact assignment replay reads the immutable
first response. A fresh assignment for the same lineage-qualified attempt
returns `already-running` in the current epoch or `already-completed` only when
its execution-basis digest is exact. A changed resource or retention contract
is `incompatible`; another lineage owns independent runtime state even when its
content-addressed `AttemptId` is equal. Stale/canceled state is replaceable.
Completed operational state is reauthenticated against the exact request before
reuse: temporarily unavailable input yields `unavailable-input`, while a
present but incompatible completion is discarded and reexecuted because the
ledger is acceleration rather than campaign truth. Authorization failure yields
`unauthorized` without discarding the completion or starting replacement work.
Hard slot, aggregate vCPU,
resident-memory, and writable-disk limits plus a per-execution quanta ceiling
produce stable `incompatible` or `backpressure` outcomes without unbounded
queues.

Result handoff is an ordered operational transaction. Guest execution consumes
one non-cloneable dispatch token and receives semantic input separately from an
operational context containing only resource ceilings, retention intent, and a
cancellation signal. Candidate preflight runs without borrowing the supervisor
actor. A short actor CAS changes `running` to
`publishing(observation_id)` before the first immutable bundle write. Immutable
publication runs outside the actor, followed by a short
`publishing -> completed` CAS. Publishing and completed observation IDs are
streamed by the ledger as authenticated GC roots without materializing history.

After restart, a complete publishing observation is reauthenticated and
promoted without guest execution. If its closure is incomplete, a fresh daemon
may recover publication under a new execution identity, but the committed
observation ID remains fixed. Version 2 readers accept legacy version 1
running/completed/canceled records; new writes use version 2.

The local Crucible execution adapter owns two nested payload schemas. Scenario
payload version 1 is the strict `ScenarioDefForm` compact-binary V5 encoding;
configuration payload version 2 is the strict `Schedule` compact-binary V2
encoding. Before VM launch the adapter decodes both, authenticates the exact
scenario-artifact reference, reconstructs `Configuration`, and requires its
re-derived `ScenarioDefId` and `ConfigurationId` to equal the campaign record.
Unsupported nested schemas and identity drift fail before execution.

Schedule V2 adds the single canonical campaign-selection decision envelope.
The envelope contains only strict `Selection` canonical bytes and is globally
dependent for reduction until its typed producer proves narrower locality. It
contains no callback, native pointer, QEMU object, or consumer closure. Compact
schedule V1 is rejected at this boundary instead of being silently interpreted
through the new decision taxonomy. General execution-model readers retain
selection-free Schedule V1 for legacy reproduction and continuation envelopes.
Checkpoint V4 carries selection decisions; selection-free Checkpoint V3 remains
readable, while a selection tag under V3 is rejected.

Before selection resolution, the adapter linearly preflights a maximum of
4,096 selection decisions and 256 MiB of conservative aggregate prefix-byte
work for campaign-branch provenance. Prefix-byte work is encoded schedule bytes
multiplied by campaign-branch selection count, bounding repeated cloning and
hashing of variable-sized decisions. The adapter returns immediately after that
scan when no selections exist. Repository resolution and prefix authentication
begin only after both bounds pass, preventing canonical maximum-sized schedules
from turning persistent schedule-prefix construction into quadratic work. The
repository resolves the accepted IDs as one batch with a 128 MiB aggregate
unique-canonical-record-body limit; identical selections and shared
opportunity/declaration/domain dependencies are decoded once and reused.

A mutable compare-and-swap error may be commit-indeterminate because rename
precedes directory fsync. The supervisor reloads the exact state, and a
successful directory reload re-fsyncs its containing directory before it can
confirm the transition. Confirmed `running` retains the bounded work
reservation; confirmed completion or cancellation releases it even while the
original I/O error is reported. An untracked same-epoch running record has no
published assignment response and is safely replaced on retry. Immutable
assignment lookup similarly re-fsyncs the parent before treating an existing
record as a durable exact replay.

Admission is a required read-only executor boundary that authenticates the
attempt closure and host compatibility before capacity reservation. Its
immutable local profile must exactly match the lineage's Crucible version, QEMU
build identity, complete protocol-version map, scenario schema, and exact
closure schema. The repository exposes that exact immutable request validator
separately from
response validation, and the supervisor accepts it through a narrow admission
trait rather than receiving campaign mutable-ref authority.
`AllowAllAttemptAdmission` exists only for already-authenticated compositions
and component tests; it is not a production trust boundary. The production
repository adapter maps missing, temporarily unavailable, or poisoned input to
`unavailable-input`, preserves backend authorization failure as `unauthorized`,
and maps corrupt or semantically incompatible closure data to `incompatible`.

An `AssignmentId`, `ExecutionId`, executor identity, coordinator epoch, retry
count, PID, materialization tier, and wall time are operational. They never
enter `AttemptId`, `ConfigurationId`, `ObservationId`, or finding identity. A
completion returns content IDs for the observation, child configuration,
optional exact closure, and an operational report.

The coordinator does not trust those IDs: it reads and authenticates the
objects, recomputes all derived identities, validates that the observation is a
legal result of the admitted attempt, and only then incorporates it. An executor
may capture an exact closure but cannot claim archival durability. The
coordinator asks the store layer to ensure the complete closure under a named
durability policy before publishing a durable pin or successful hibernation.

The repository executor handoff is deliberately phased. First it validates the
complete in-memory child-configuration, measurement, property, coverage,
newly-discovered opportunity-body, and observation bundle plus every
already-published dependency. An invalid bundle writes nothing. After the
durable publishing root exists, it publishes immutable content-addressed
objects without advancing a campaign ref. Only the coordinator may subsequently
incorporate the authenticated observation through the snapshot owner
transaction. Partial immutable writes remain recoverable under the publishing
root and cannot create campaign meaning.

The supervisor actor takes at most one queued assignment through a linear token
and releases its mutable state before guest execution, candidate preflight, and
immutable publication. Long guest or storage work never holds the borrow needed
by service or cancellation handling. Retryable execution failure requeues the
same reservation once; retryable result-storage failure retains and republishes
the already-produced candidate without rerunning the guest. Stable failure is
explicitly canceled or quarantined. Pending locators remain bounded by admitted
capacity.

Cancellation races are explicit. A canonical completion produced before the
executor accepted cancellation remains eligible for ordinary validation. A
candidate returned after accepted cancellation is discarded before immutable
publication unless another independently owned diagnostic policy retained it;
it is never admitted as modeled completion by this path. Cancellation never
becomes a modeled timeout or failure.
Durable cancellation keeps CPU, memory, and disk charged until the physical
worker acknowledges exit, so a non-cooperative guest cannot oversubscribe hard
aggregate capacity.

An attempt explicitly declares `Discover` or `Branch` start semantics.
`Discover` realizes an existing configuration until a pending choice or modeled
terminal outcome; it is how a campaign first learns dynamic guest
opportunities. `Branch` realizes a parent at a known opportunity and applies
exactly one typed selection. The executor cannot infer one form from missing
fields or synthesize an edge for discovery.

Delivery is at-least-once. The executor avoids duplicate local work when it can,
but a coordinator retry or daemon crash may repeat an attempt. Equal canonical
results deduplicate; conflicting results are determinism failures and are never
arbitrarily selected.

- **[CCOMP-16]** An executor MUST validate every attempt, capability,
  compatibility requirement, resource ceiling, and referenced object before
  guest execution, including the explicit discovery-versus-branch start form.
- **[CCOMP-17]** Executor completion MUST publish immutable result objects
  before advertising their IDs, MUST validate the complete candidate before its
  first bundle write, MUST durably bind an in-progress publication root to the
  exact lineage, attempt, execution basis, and expected observation before that
  write, MUST NOT advance campaign refs, and MUST NOT advance virtual time while
  required input content is unavailable. Final observation incorporation
  belongs to the coordinator.
- **[CCOMP-18]** Cancellation, process loss, backpressure, and unavailable
  storage are operational outcomes. Only modeled evidence may produce a
  canonical modeled failure or reward.
- **[CCOMP-19]** Retry of one `AttemptId` MAY execute more than once but MUST be
  safe, bounded, observable, and idempotent at canonical result admission.

## 04a.7 Capability and locality reporting

`DescribeExecutor` reports protocol versions, host architecture, admitted QEMU
profiles, exact-closure schemas, fork capabilities, resource ceilings, and
reachable store namespace IDs. `WatchCapacity` reports bounded operational
availability and coarse materialization locality. Capability and locality may
influence placement but not proposal generation or modeled results.

The local coordinator may prefer an executor already holding a hot or exact
parent. It submits the same attempt regardless of that preference. The executor
alone chooses hot fork, exact restore, or thin replay and reports the realized
tier as operational telemetry.

The local Crucible runner receives an authenticated branch parent, the resolved
selection closure, and the exact canonical schedule prefix formed by appending
that selection. It revalidates campaign-branch provenance against the parent
before runner invocation. A successful runner returns the immutable observation
candidate separately from `hot-fork`, `exact-restore`, or `thin-replay`
telemetry; the adapter strips that telemetry before canonical candidate
publication.

- **[CCOMP-20]** Capability reports MUST distinguish immutable compatibility
  facts from volatile capacity and locality hints, and consumers MUST treat
  stale hints as rejection/retry rather than semantic failure.
- **[CCOMP-21]** Materialization and store locality MAY affect where and how an
  attempt runs but MUST NOT affect which value the campaign proposes.

## 04a.8 Recovery and conformance

After restart, the coordinator reconstructs claimable work as admitted attempts
without canonical observations. The executor discards stale process handles,
reconciles any surviving local processes under a new daemon epoch, inventories
authenticated materializations, and accepts idempotent resubmission. No durable
worker lease is required for the single-host implementation.

The directory assignment ledger retains publishing and completed observations and exact first
responses across restart. A fresh daemon epoch may replace a stale `running`
record, while an accepted cancellation prevents a late worker completion from
becoming the attempt's completed runtime state. Completion and cancellation are
conditional, idempotent state transitions: an exact replay succeeds, the
opposite terminal outcome reports the winner, and a different second
observation is a determinism conflict.

The component conformance harness includes:

- identical direct and loopback-RPC campaign executions;
- golden schema vectors and malformed/oversized message rejection;
- retry before acceptance, during execution, and after result publication;
- daemon death at every publication boundary;
- duplicate and conflicting completion handling;
- capability mismatch and stale-capacity rejection;
- large-object rejection on the control plane;
- a fake executor and fake coordinator usable without QEMU;
- QEMU-backed equivalence through the ordinary executor implementation.

- **[CCOMP-22]** Deleting all operational reservations, process handles,
  watches, capacity reports, and placement receipts MUST leave enough canonical
  state to recover the campaign and safely resubmit incomplete attempts.
