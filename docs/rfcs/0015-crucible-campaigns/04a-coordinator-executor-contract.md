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

The RPC binding follows RFC-0010's HTTP/2 gRPC/Connect-style transport. A JSON
projection is provided for debugging and CLI structured output; canonical
campaign object bytes retain their own codec. Large artifacts do not travel in
control messages.

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
    pub scan_page: Option<PlanningScanPage>,
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
snapshot-bound pages in canonical continuation-key order. Portable planner
state carries the scan cursor, best candidate and score evidence accumulated so
far, immutable view identity, and remaining fuel. The engine may suspend with
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

`SubmitAttempt` names an immutable `AttemptSpecId`, canonical `AttemptId`,
idempotent operational `AssignmentId`, coordinator epoch, bounded resource
requirements, and retention intent. It returns one of:

```text
accepted(execution ID)
already-running(execution ID)
already-completed(execution-result ID)
rejected(incompatible | backpressure | unavailable-input | unauthorized)
```

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

Cancellation races are explicit. A canonical completion produced before the
executor accepted cancellation remains eligible for ordinary validation. A
completion produced after accepted cancellation is retained as operational
diagnostic content unless the coordinator still has an independently valid
admission for it. Cancellation never becomes a modeled timeout or failure.

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
  before advertising their IDs and MUST NOT advance virtual time while required
  input content is unavailable.
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
