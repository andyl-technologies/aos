# 04a — Component contracts and local executor boundary

RFC-0017 implements one single-host campaign coordinator and one local Crucible
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
ListCampaigns
GetSnapshot           QueryGraph           GetGraphObject
QueryFrontier          GetFrontierObject    QueryChoices
GetChoiceObject        PinCampaign
SubmitBranchRequest    DeriveCampaign       QueryFindings
ExplainObject          ExplainAttempt       WatchCampaign
GetPlannerRankings
```

Every operator-command mutation of an existing campaign carries an idempotent
command ID and its expected snapshot ID. An exhaustive-policy branch instead
uses its exact content-addressed request as the idempotency boundary. Creation
uses the canonical campaign name as its idempotency boundary and carries
expected name absence.
Repeated `WatchCampaign` calls form a resumable coalesced watch; the campaign
ref and immutable objects remain authoritative. A stale or lost watch cursor
therefore cannot lose campaign state.

The strict service checkpoint defines principal-aware `ListCampaigns`, `CreateCampaign`,
`DeriveCampaign`, `GetCampaign`, `GetSnapshot`, `WatchCampaign`,
`ApplyCampaignCommand`, `QueryGraph`, `GetGraphObject`, and
`QueryChoices`, `QueryFrontier`, `QueryFindings`, `GetFindingObject`,
`ExplainAttempt`, `GetPlannerRankings`, `GetFrontierObject`, `GetChoiceObject`,
`PinCampaign`, and `SubmitBranchRequest` messages. All use
canonical schema version 1 and a 64 MiB outer bound:

```text
CreateCampaignRequestV1 = version | principal | campaign |
                          CampaignLineageV1 | CampaignPolicyV1
CreateCampaignResponseV1 = version | request_digest | genesis_snapshot |
                           lineage | active_policy | replayed

DeriveCampaignRequestV1 = version | principal | source_campaign |
                          source_snapshot | target_campaign |
                          optional CampaignPolicyV1
DeriveCampaignResponseV1 = version | request_digest | source_snapshot |
                           new_snapshot | active_policy | replayed

GetCampaignRequestV1 = version | principal | campaign
GetCampaignResponseV1 = version | request_digest | snapshot | lineage |
                        active_policy | lifecycle_state

ListCampaignsRequestV1 = version | principal | optional after_campaign | limit
CampaignListEntryV1 = campaign | snapshot | lineage | active_policy |
                      lifecycle_state
ListCampaignsResponseV1 = version | request_digest |
                          entries[CampaignListEntryV1] |
                          optional next_after_campaign | visited_refs

GetCampaignSnapshotRequestV1 = version | principal | campaign | snapshot
GetCampaignSnapshotResponseV1 = version | request_digest | snapshot |
                                CampaignSnapshotV2

WatchCampaignRequestV1 = version | principal | campaign |
                         optional after_snapshot
WatchCampaignResponseV1 = version | request_digest | snapshot | lineage |
                          active_policy | lifecycle_state | advanced

CampaignGraphEntryV1 = key | object
MerkleScanProofV1 = node_count:u64 |
                    nodes[node_id | canonical MerkleNodeV1 envelope bytes]
QueryCampaignGraphRequestV1 = version | principal | campaign | snapshot |
                              optional after_key | limit
QueryCampaignGraphResponseV1 = version | request_digest | snapshot |
                               CampaignSnapshotV2 |
                               entries[CampaignGraphEntryV1] |
                               optional next_after | MerkleScanProofV1

QueryCampaignFindingsRequestV1 = version | principal | campaign | snapshot |
                                 optional after_signature_key | limit
QueryCampaignFindingsResponseV1 = version | request_digest |
                                  CampaignSnapshotV2 |
                                  findings[FindingV1] |
                                  optional next_after_signature_key |
                                  MerkleScanProofV1
GetCampaignFindingObjectRequestV1 = version | principal | campaign | snapshot |
                                    finding_id | object_kind
GetCampaignFindingObjectResponseV1 = version | request_digest |
                                     CampaignSnapshotV2 | FindingV1 |
                                     FindingObjectV1 | MerkleLookupProofV1
FindingObjectV1 = 0 ObservationV1 |
                  1 latest ObservationV1 |
                  2 ReproductionArtifactV1 |
                  3 minimized ReproductionArtifactV1

ExplainCampaignAttemptRequestV1 = version | principal | campaign | snapshot |
                                  AttemptId
ExplainCampaignAttemptResponseV2 = version | request_digest |
                                   CampaignSnapshotV2 | AttemptV1 |
                                   AttemptAdmissionV1 | BranchPathV2 |
                                   optional SelectionV2 | optional ProposalV1 |
                                   optional PlannerStepV4 |
                                   optional ObservationV1 |
                                   MerkleLookupProofV1 attempt_proof |
                                   MerkleLookupProofV1 admission_proof |
                                   optional MerkleLookupProofV1 proposal_proof |
                                   optional MerkleLookupProofV1 planner_step_proof |
                                   MerkleLookupProofV1 observation_proof

GetCampaignPlannerRankingsRequestV1 = version | principal | campaign |
                                      snapshot | PlannerStepId
GetCampaignPlannerRankingsResponseV1 = version | request_digest |
                                       CampaignSnapshotV2 | PlannerStepV4 |
                                       RetainedPlannerRequestV1 |
                                       MerkleLookupProofV1

Response version 2 requires a planner step and proof exactly when the selected
proposal names a planner invocation. The proof resolves
`coordination.planner-invocation-result(invocation)` under the anchoring
snapshot. The step MUST name that invocation, proposal policy, and guidance
view; its selected branch point and source MUST equal the proposal, and its
issued-proposal set MUST contain the exact proposal ID. Operator, exhaustive,
and debugger proposals carry neither field. Response version 1 remains
structurally readable for offline compatibility but does not carry
planner-decision evidence; the version-20 loopback endpoint writes only version
2.

MerkleLookupProofV1 = node_count:u64 |
                      nodes[node_id | canonical MerkleNodeV1 envelope bytes]
GetCampaignGraphObjectRequestV1 = version | principal | campaign | snapshot |
                                  graph_key
GetCampaignGraphObjectResponseV1 = version | request_digest |
                                   CampaignSnapshotV2 |
                                   canonical ObjectEnvelopeV1 bytes |
                                   MerkleLookupProofV1

CampaignChoiceEntryV1 = ChoiceOpportunityId
QueryCampaignChoicesRequestV1 = version | principal | campaign | snapshot |
                                optional after_opportunity | limit
QueryCampaignChoicesResponseV1 = version | request_digest |
                                 CampaignSnapshotV2 |
                                 entries[CampaignChoiceEntryV1] |
                                 optional next_after |
                                 MerkleLookupProofV1 |
                                 MerkleScanProofV1

ContinuationStateV1 = 0 Ready |
                      1 WaitingForFeedback(completed_visits:u64 |
                                           required_visits:u64) |
                      2 Open | 3 Exhausted | 4 Closed
ContinuationProjectionV1 = version | BranchRequestId | BranchPointId |
                           ContinuationStateV1
QueryCampaignFrontierRequestV1 = version | principal | campaign | snapshot |
                                 optional after_request | limit
QueryCampaignFrontierResponseV1 = version | request_digest |
                                  CampaignSnapshotV2 |
                                  projections[ContinuationProjectionV1] |
                                  optional next_after |
                                  MerkleLookupProofV1 |
                                  MerkleScanProofV1
GetCampaignFrontierObjectRequestV1 = version | principal | campaign |
                                     snapshot | BranchRequestId
GetCampaignFrontierObjectResponseV1 = version | request_digest |
                                      CampaignSnapshotV2 |
                                      ContinuationProjectionV1 |
                                     BranchRequestV1-or-V2 |
                                      MerkleLookupProofV1 |
                                      MerkleLookupProofV1

CampaignChoiceObjectKindV1 = 0 (Declaration) | 1 (Domain)
CampaignChoiceObjectV1 = kind | SelectableDeclarationV1-or-ChoiceDomainV1
GetCampaignChoiceObjectRequestV1 = version | principal | campaign | snapshot |
                                   opportunity | CampaignChoiceObjectKindV1
GetCampaignChoiceObjectResponseV1 = version | request_digest |
                                    CampaignSnapshotV2 | ChoiceOpportunityV1 |
                                    CampaignChoiceObjectV1 |
                                    MerkleLookupProofV1

ApplyCampaignCommandRequestV1 = version | principal | campaign |
                                ControlRequestV1
ApplyCampaignCommandResponseV1 = version | request_digest | prior_snapshot |
                                 new_snapshot | replayed

PinCampaignRequestV1 = version | principal | campaign | PinRequestV1
PinCampaignResponseV1 = version | request_digest | prior_snapshot |
                        new_snapshot | replayed

SubmitCampaignBranchRequestV1 = version | principal | campaign |
                                expected_snapshot | BranchRequestV1-or-V2
SubmitCampaignBranchResponseV1 = version | request_digest | prior_snapshot |
                                 new_snapshot | branch_request | replayed

CampaignServiceErrorResponseV1 = version | request_digest | failure
```

The closed `failure` encoding is:

```text
0 Unauthorized
1 AuthorizationUnavailable
2 NotFound
3 AlreadyExists
4 Stale(expected_snapshot, current_snapshot)
5 CommandReuse
6 ConcurrentUpdate
7 InvalidTransition(CampaignState)
8 InvalidRequest
9 BackendUnauthorized
10 ResourceExhausted
11 Unavailable
12 IntegrityFailure
13 ProtocolViolation
```

Every implementation derives the same closed retry disposition:

| Disposition | Failure tags | Required caller action |
|---|---|---|
| `RetryAfterBackoff` | 1, 10, 11 | Retry the same canonical request only after authorization/backend/capacity recovery and bounded backoff. |
| `RefreshCampaign` | 4, 6 | Read the authoritative head, reconcile the returned state, and construct a new request; do not blindly replay changed intent. |
| `Reauthenticate` | 0, 9 | Refresh or correct caller/storage credentials before retrying. |
| `OperatorAction` | 2, 3, 7 | Require explicit user/operator resolution of the missing/existing campaign or illegal lifecycle action. |
| `DoNotRetry` | 5, 8, 12, 13 | Do not repeat the request; correct the idempotency conflict, invalid data/software, repository integrity failure, or framing/canonical/response-contract violation. |

The Rust contract exposes this derivation as
`CampaignServiceFailure::retry_disposition`; other-language implementations
MUST produce the same result. Internal canonical or authenticated repository
failures map to `IntegrityFailure`, never `InvalidRequest`, because all service
methods receive already-decoded strict request values. `ProtocolViolation` is
reserved for a peer's framing, canonical-body, or response-contract failure and
never reports repository corruption.

`principal` is a nonempty UTF-8 string of at most 512 bytes whose bytes are
ASCII alphanumeric or one of `.`, `_`, `-`, `/`, and `:`. `campaign` is a
nonempty UTF-8 string of at most 512 bytes in the repository reference-name
profile: slash-separated segments are 1 through 255 bytes, neither `.` nor
`..`, and contain only ASCII alphanumeric bytes or `.`, `_`, and `-`.
Decoders reject every value outside these exact profiles.

Stable failures are also bound to the semantics of the requested operation.
Every operation permits tags 0, 1, 8, 9, 10, 11, 12, and 13.
`CreateCampaign` additionally permits 3; `DeriveCampaign` additionally permits
2, 3, and 6; `GetCampaign`, `GetSnapshot`, and `WatchCampaign` additionally
permit 2;
`QueryGraph`, `GetGraphObject`, `QueryChoices`, `QueryFrontier`,
`QueryFindings`, `GetFindingObject`, `ExplainAttempt`, `GetFrontierObject`, and
`GetChoiceObject`, `GetPlannerRankings`
additionally permit 2 and 4;
`ApplyCampaignCommand` permits 2, 4, 5, 6, and 7; `PinCampaign` permits
2, 4, 5, and 6; and `SubmitCampaignBranch` permits 2, 4, 5, and 6. For every
snapshot-preconditioned
operation,
`Stale.expected_snapshot` MUST equal that exact request's snapshot precondition,
and `Stale.current_snapshot` MUST differ from `Stale.expected_snapshot`. A tag
outside the operation's allowed set or an invalid `Stale` basis is
`ProtocolViolation`; a loopback client rejects the response and poisons the
connection.

For command responses, `prior_snapshot` is the accepted command's precondition.
For branch responses, it is the snapshot that first accepted the immutable
`BranchRequest`. An exact request replay is resolved by `BranchRequestId` before
outer snapshot staleness, so a later service call may use another expected
snapshot while receiving the original acceptance pair with a response digest
bound to that later call.

The response digest covers every canonical request byte, including the
principal, campaign name, snapshot precondition, and semantic payload. The
checked client rejects a response from another request before exposing it. The
exact language-neutral derivations are:

```text
get_request_digest =
  H("crucible.campaign-service.get-campaign.v1", GetCampaignRequestV1)
list_request_digest =
  H("crucible.campaign-service.list-campaigns.v1", ListCampaignsRequestV1)
get_snapshot_request_digest =
  H("crucible.campaign-service.get-campaign-snapshot.v1",
    GetCampaignSnapshotRequestV1)
watch_request_digest =
  H("crucible.campaign-service.watch-campaign.v1", WatchCampaignRequestV1)
query_graph_request_digest =
  H("crucible.campaign-service.query-campaign-graph.v1",
    QueryCampaignGraphRequestV1)
query_findings_request_digest =
  H("crucible.campaign-service.query-campaign-findings.v1",
    QueryCampaignFindingsRequestV1)
get_finding_object_request_digest =
  H("crucible.campaign-service.get-campaign-finding-object.v1",
    GetCampaignFindingObjectRequestV1)
explain_attempt_request_digest =
  H("crucible.campaign-service.explain-campaign-attempt.v1",
    ExplainCampaignAttemptRequestV1)
get_planner_rankings_request_digest =
  H("crucible.campaign-service.get-campaign-planner-rankings.v1",
    GetCampaignPlannerRankingsRequestV1)
get_graph_object_request_digest =
  H("crucible.campaign-service.get-campaign-graph-object.v1",
    GetCampaignGraphObjectRequestV1)
query_choices_request_digest =
  H("crucible.campaign-service.query-campaign-choices.v1",
    QueryCampaignChoicesRequestV1)
query_frontier_request_digest =
  H("crucible.campaign-service.query-campaign-frontier.v1",
    QueryCampaignFrontierRequestV1)
get_frontier_object_request_digest =
  H("crucible.campaign-service.get-campaign-frontier-object.v1",
    GetCampaignFrontierObjectRequestV1)
get_choice_object_request_digest =
  H("crucible.campaign-service.get-campaign-choice-object.v1",
    GetCampaignChoiceObjectRequestV1)
create_request_digest =
  H("crucible.campaign-service.create-campaign.v1", CreateCampaignRequestV1)
derive_request_digest =
  H("crucible.campaign-service.derive-campaign.v1", DeriveCampaignRequestV1)
apply_request_digest =
  H("crucible.campaign-service.apply-campaign-command.v1",
    ApplyCampaignCommandRequestV1)
pin_request_digest =
  H("crucible.campaign-service.pin-campaign.v1", PinCampaignRequestV1)
branch_request_digest =
  H("crucible.campaign-service.submit-branch-request.v1",
    SubmitCampaignBranchRequestV1)
```

Here `H(domain, value)` is the campaign BLAKE3 domain derivation over the exact
canonical request bytes, using the same length-framed domain construction as
other `CampaignHash` derivations. The principal identifier is operational and
never enters immutable campaign
state. A conforming direct adapter closes over an authenticated caller
capability; a transport adapter authenticates its peer or an exact-request
proof. Authorization receives the exact request digest and fails before any
repository read or write. Treating the self-asserted principal text alone as
authentication is non-conforming. The repository-backed adapter then invokes
the existing `head`/lifecycle, `apply_control`, and cause-specific operator or
exhaustive-policy branch owner paths, preserving their idempotence and CAS
rules. Planner and debugger causes remain confined to their authority-specific
adapters.

`ListCampaigns` requires an explicit all-campaign grant; an exact-name grant
never confers namespace discovery. A page contains at most 256 heads in strict
canonical campaign-name order, resumes after an exclusive campaign-name
cursor, and inspects at most 65,536 ref entries. Each returned ref target is
loaded as an exact typed snapshot and its complete authenticated head closure
and lifecycle projection are validated before the response is constructed.
`next_after` is either absent at the scanned view's EOF or equals the final
returned name. The response is a coalesced mutable-ref view rather than an
immutable cross-page transaction: later creation may appear on a resumed page,
while immutable returned head bindings remain authenticated.

Creation carries the complete by-value lineage and policy. Large scenario and
genesis configuration artifacts and the exact transitive generator closure do
not travel in this control message: a verifier-backed immutable content-import
capability MUST publish their exact content IDs first. Scenario/configuration
semantic IDs are re-derived by the execution-model adapter; generator IDs are
canonical-content-derived. Missing imported input produces `Unavailable`;
forged or mismatched imported content fails closed. The daemon's narrow Crucible
importer implements this precondition without exposing campaign refs or
accepting caller-asserted semantic IDs. Generator traversal is bounded to 4,096
unique records and 128 MiB of aggregate canonical generator bodies. Validation
streams one authenticated record at a time and does not republish imported
generators. The local daemon exposes that narrow capability only in a pre-bind
startup phase: repeatable `--campaign-import-manifest PATH` inputs use the
strict `crucible.campaign-import` version-1 TOML schema, carry at most 4,096
scenario/schedule or generator entries in aggregate across the complete
startup, and name only absolute, canonical, exact-owner regular files with no
group/other write bits. The manifest is at
most 1 MiB and each referenced compact/canonical body is read within the 32-MiB
artifact ceiling. Imports execute one body at a time under the repository's
exclusive state lock; every manifest must succeed before the managed service
socket is bound. The option is unavailable in read-only mode. Successfully
published immutable bodies remain safe, idempotent content-addressed input if a
later manifest entry fails; no campaign ref or service endpoint is created by
the import phase. The campaign name is the creation idempotency boundary, and
the complete canonical request binds the individual response digest. An idempotent
retry is recognized when the authenticated named campaign's retained genesis
has the same lineage and policy, even after later mutations, and returns the
original genesis snapshot. A different lineage or policy under an existing name
returns `AlreadyExists`.

```toml
schema = "crucible.campaign-import"
version = 1

[[configuration]]
scenario = "/absolute/path/scenario.bin"
schedule = "/absolute/path/schedule.bin"

[[generator]]
specification = "/absolute/path/generator.bin"
```

Unknown fields, zero entries, duplicate configuration pairs, duplicate
generator paths, relative paths, dot components, symlinks, non-regular files,
owner mismatch, and group/other-writable files are rejected. Configuration
entries decode ScenarioDefForm compact binary V5/V6/V7 and Schedule compact
binary V1/V2. Scenario V5 is accepted only with implicit empty measurement and
selectable components; scenario V6 is accepted only with an empty selectable
component. New imports normalize to current V7 bytes and publish campaign
scenario payload V3 plus configuration payload V2 after semantic identity
re-derivation; retained scenario payloads V1 and V2 remain readable. Generator entries
decode the current strict canonical `CandidateGeneratorSpec` and must appear
after any child generator records on which they depend. A manifest path and
every named path are at most 4,095 bytes.

Derivation authenticates and authorizes both source and target names before any
repository access. The requested source snapshot must occur in the authenticated
named source ancestry. The source ref is never changed. The target ref advances
from absence to a new audited `CampaignDerived` successor whose parent is the
exact source snapshot. Omitting the policy preserves the source policy; a
supplied policy is activated atomically and must match the source scenario and
campaign mode and name an already imported bounded generator closure. Target
name plus the exact derivation basis is the idempotency boundary: an exact retry
returns the original derived snapshot after later target mutations or restart,
while another basis under the same target returns `AlreadyExists`. Replay uses
only that target history's founding derivation edge; an inherited ancestor
locator cannot satisfy it. Imported validation enforces the same 4,096-record
and 128-MiB generator limits and deduplicates repeated immutable policy checks
within one ancestry pass. Immutable source authentication and generator
preflight occur before acquiring the repository mutation lock; target absence
is rechecked under that lock before publication.

`GetSnapshot` first authenticates the named campaign's current head, then walks
bounded immutable parent links to the exact requested ID. It accepts current or
historical snapshots only from that named history; an extant snapshot from
another campaign is `InvalidRequest`. The response carries the canonical
snapshot body and the checked client reconstructs its envelope identity before
exposing it. This operation grants complete snapshot metadata and all root IDs,
but not any object body named by those IDs. The local `campaign snapshot`
porcelain renders that exact body. `campaign compare` performs two independent
checked `GetSnapshot` reads and compares lineage, active policy, parent,
transition, and all nine roots. It reports direct adjacency only when one body
names the other as its parent; it does not infer ancestry from IDs or bypass the
named-history membership check.

`WatchCampaign.after_snapshot` is an advisory, coalesced cursor. The response
always describes one authenticated current head and its lifecycle projection.
`advanced` is true exactly when `after_snapshot` is absent or differs from that
head; the returned snapshot becomes the next cursor. An unknown, stale, or
skipped cursor therefore returns the current head without an ancestry scan, and
losing intermediate watch responses loses no authoritative campaign state.
Repeated bounded calls form the initial resumable watch; a blocking streaming
adapter may layer over the same messages later.

`QueryGraph` reads one ascending page from the graph Merkle root of the exact
current snapshot named by the request. `limit` is in `1..=256`. The optional
exclusive `after_key` MUST be an entry in that same root; arbitrary or
cross-root cursors are `InvalidRequest`. Each response contains at most `limit`
fixed-size key/content-ID pairs. A non-EOF `next_after` equals the last returned
key and is valid only for the same snapshot. If the named campaign head differs
from `snapshot`, the service returns a request-bound `Stale`; cursor resolution
and page traversal do not scan ancestry or mix entries from another root. The
repository may still rebuild its required authenticated-head validation
checkpoint after restart or cache eviction before serving the page.

The response carries the exact canonical snapshot body. A checked client
reconstructs its snapshot envelope, requires that identity to equal the
request's `snapshot`, and derives the graph root only from that authenticated
body. `MerkleScanProofV1` contains every and only Merkle-node envelope visited
while authenticating the optional cursor and scanning `limit + 1` entries. The
lookahead proves both a continuation and EOF. The verifier checks content IDs,
record kinds, child tables, depths, complete ancestor prefixes, subtree counts,
strict order, the exact returned entries, and the exact `next_after`; it rejects
missing, corrupt, duplicate, or unvisited extra nodes. A proof carries at most
16,513 unique nodes, each envelope is at most 64 KiB, and their aggregate bytes
are at most 60 MiB. These bounds also keep the complete response within the
64-MiB component-message limit.

Because snapshot identity is a flat content hash, authenticating `roots.graph`
also discloses the complete snapshot body: parent, lineage, active policy,
transition, and all nine root IDs. `QueryCampaignGraph` authorization therefore
MUST grant that complete snapshot metadata capability as well as the returned
graph object IDs and Merkle-node envelopes. An authorizer that may not disclose
any other root ID MUST deny this operation. The operation does not grant any
object body named by those IDs; object reads remain separately authorized, so
sensitive checkpoint content is not carried in this response.

`QueryCampaignFindings` applies the same current-head, authenticated-snapshot,
minimal-proof, exact-node-set, range, lookahead, and EOF rules to
`roots.findings`. Its exclusive cursor is the deterministic signature-index
key, and `limit` is in `1..=4`. For signature cluster key `c`, that key is
`H("crucible.campaign-map-key.v1", u64be(len("findings.signature")) ||
"findings.signature" || c)`. Each proof leaf value MUST equal the content ID
reconstructed from the complete corresponding `FindingV1` body, and its key
MUST equal the body signature's derived cluster key transformed by that exact
formula. The checked client rejects substitution, reordering, false EOF,
foreign snapshots, and unused proof nodes before exposing a finding.

This operation intentionally grants the complete anchoring snapshot metadata,
the returned canonical finding bodies and IDs, and the Merkle metadata needed
to authenticate them. Evidence, observation, reproduction, checkpoint, and
other child object bodies named by a finding remain separately authorized. The
four-entry bound leaves room for four independently bounded 4-MiB finding
bodies and at most 385 visited 64-KiB proof nodes under the 64-MiB
component-message limit.

`GetCampaignFindingObject` is the separately authorized dependency-body
capability used by finding explanations. The request names one exact finding
ID and one closed object kind: representative observation, latest occurrence,
original reproduction, or minimized reproduction. The response carries the
complete anchoring snapshot and finding, an exact minimal lookup proof from
`roots.findings`, and only the requested typed child. A checked reader MUST
reconstruct the snapshot and finding IDs, derive the signature-index key using
the formula above, authenticate exact finding membership, require the response
kind and child ID to match the request and finding field, and require a returned
reproduction fingerprint to equal the finding signature fingerprint. A missing
optional minimized reproduction is an invalid request, not an absent generic
object read. The operation grants the returned finding plus one child body; it
does not grant evidence bodies, checkpoint bytes, or any other child closure.

`ExplainCampaignAttempt` is the separately authorized provenance view for one
exact attempt in the current authenticated snapshot. Two minimal accounting
lookup proofs bind the complete `AttemptV1` body and its unique execution-basis
`AttemptAdmissionV1`; a third proof binds the execution-basis `ProposalV1` in
the exploration root for branch attempts, and an observations-root proof binds
either the canonical `ObservationV1` or authenticated absence. The response
also carries the exact content-addressed `BranchPathV2` and, for a branch,
`SelectionV2`. A checked reader reconstructs every typed ID, requires the
attempt path and optional observation path to agree, requires the admission to
name that attempt and be the execution basis, and requires a branch selection,
proposal, campaign-branch origin, branch point, edge, domain, and value to
agree. Discovery attempts reject all branch-only provenance. A reached-stop
observation MUST equal the attempt stop condition; other terminal failure
outcomes remain valid completions.

The exact membership keys are `H("crucible.campaign-map-key.v1",
u64be(len(namespace)) || namespace || u64be(len(id)) || id)` with the canonical
typed content-ID string as `id` and namespaces `accounting.attempt`,
`accounting.attempt-execution-basis`, `exploration.proposal`, and
`observations.attempt`, respectively. Every lookup proof is minimal and rejects
unused nodes. Authorization grants the complete snapshot metadata plus these
specific attempt, admission, path, selection, optional proposal, and optional
observation bodies; it grants no arbitrary accounting, exploration,
observation-evidence, checkpoint, or content-store read.

`GetCampaignGraphObject` is that separate graph-body capability. It accepts one
exact current-snapshot graph key and returns only a strict
`ConfigurationArtifact` or `ChoiceOpportunity` envelope. The response
reconstructs the requested snapshot identity, proves that key's exact value
with a minimal Merkle lookup path, and requires the returned envelope's content
identity to equal that value. Presence and absence proofs carry at most 65
unique nodes, each at most 64 KiB, and at most 4,259,840 aggregate proof bytes.
The operation does not expose arbitrary content IDs or any non-graph record
kind.

`QueryChoices` reads the snapshot graph's nested discovered-choice index. New
genesis snapshots anchor one canonical empty choice-index Merkle root; every
explicit or observation-driven discovery updates that root in the same
snapshot transition as the authoritative and branch-point-scoped graph keys.
Imported legacy version-2 snapshots without this optional index remain valid,
but the query fails closed with `InvalidRequest` until an explicit complete
migration is implemented. Ordinary discoveries preserve the unindexed legacy
shape rather than synthesizing a partial index. The exclusive cursor is a
`ChoiceOpportunityId`, `limit` is in
`1..=8`, and the result contains IDs only. The separately authorized
`GetGraphObject` call uses `CampaignChoiceEntryV1`'s deterministic graph key to
return the strict opportunity envelope. Declaration and domain bodies are not
flat graph entries and therefore cannot be fetched through that capability.

Like `QueryGraph`, this response carries the complete anchoring snapshot body;
`QueryCampaignChoices` authorization therefore grants visibility of its parent,
lineage, policy, transition, and all nine root IDs. It grants discovered choice
IDs and the Merkle metadata required for the two proofs, but not opportunity or
dependency bodies.

The response first proves the fixed choice-index anchor in the authenticated
snapshot graph with `MerkleLookupProofV1`, then proves the exact page, cursor,
and EOF inside that nested root with `MerkleScanProofV1`. Each nested key is the
opportunity content digest and each value is that exact opportunity ID; checked
clients reject key/value drift, substitution, false EOF, missing nodes, or
unused extra nodes. The eight-entry limit bounds the scan proof to at most 641
64-KiB nodes; together with the 65-node lookup proof and message overhead, the
complete response remains below the 64-MiB component-message bound.

`QueryFrontier` reads the snapshot exploration root's nested continuation
index. New genesis snapshots anchor one canonical empty index, and the owner
updates it atomically with request issue, proposal, disposition admission, and
atomic planner-issue transitions. Imported validation recomputes each exact
state change from the authoritative request, proposal, and accounting roots.
Legacy snapshots without the anchor remain readable, but this query returns
`InvalidRequest`; ordinary mutations never create a partial legacy index.

The exclusive cursor is a `BranchRequestId` and `limit` is in `1..=8`. The
response carries the complete anchoring snapshot body, so authorization grants
visibility of the parent, lineage, policy, transition, and every root ID. It
also grants the returned `ContinuationProjectionV1` bodies and the minimal
Merkle metadata for a fixed-anchor lookup plus exact nested page proof. It does
not grant branch-request or other object bodies, which remain separately
authorized. Each nested key is the request content digest and each value is the
exact typed projection ID. Checked clients reconstruct every projection ID,
require its body request to match that key, and replay the cursor, `limit + 1`
lookahead, and exact used-node sets to reject substitution or false EOF. The
same 65-node lookup and 641-node page-proof bounds as `QueryChoices` keep the
complete message below 64 MiB.

Finite requests are reported as `Ready`, `Open`, `Exhausted`, or `Closed` from
their owner-projected source and disposition state. Generated requests are
reported `Open` at this checkpoint; deterministic generated enumeration and
feedback-driven readiness remain open and MUST replace that conservative state
before generated work is advertised as executable.

`GetFrontierObject` is the separately authorized body read for one exact
`BranchRequestId` returned by `QueryFrontier`. The response repeats the
authenticated projection and returns the strict `BranchRequestV1` or
`BranchRequestV2` body. The
first minimal lookup proof authenticates the fixed frontier-index anchor; the
second authenticates the request-keyed projection ID inside that index. A
checked client reconstructs both the projection and request content IDs,
requires their request and branch-point fields to agree, and rejects unrelated
or substituted bodies. The body is bounded to 32 MiB and each proof to 65
64-KiB nodes, keeping the complete response below 64 MiB. This operation grants
the complete snapshot metadata, one projection, and one request body; it grants
no arbitrary exploration-root or content-store read.

`GetChoiceObject` is the separately authorized dependency read for one exact
graph-authenticated opportunity, including opportunities returned by
`QueryChoices`. The requested snapshot may be the current head or an exact
authenticated ancestor in that named campaign; this permits an idempotent
mutation retry to reconstruct the same semantic request after later head
advances. Its lookup proof authenticates the opportunity under the
deterministic authoritative graph key and the response
reconstructs that opportunity's exact content identity. The closed selector
then permits only the declaration or effective domain named by that body. The
checked client reconstructs the returned dependency's typed content ID and
requires it to equal the corresponding opportunity field. The response carries
the complete anchoring snapshot body and therefore grants the same full
snapshot-metadata visibility as the other proof-bearing graph operations, but
it grants no arbitrary content-store read.

An exhaustive branch request uses `BranchRequestCause::ExhaustivePolicy` with
the exact active policy from that authenticated snapshot, implementation-
version 2 `all`, and a proposal budget equal to the Boolean or discrete
domain's exact cardinality. Local acceptance and imported-successor validation
require the named policy to be active, its explorer to be `Exhaustive`, its
choice policy to select that exact generator, and the cardinality to be no
greater than `maximum_cardinality`. A non-`all` generator, another domain
family, a partial or excessive proposal budget, or an over-ceiling domain is
rejected before immutable request or Merkle publication.

The checked local porcelain exposes these proof-bearing reads through
`campaign graph-object`, `campaign choice-object`, and
`campaign frontier-object` as exact graph configuration/opportunity, choice
declaration/domain, and frontier-request views in table, Markdown, JSON, and
JSONL. `campaign explain` composes one declaration read and one frontier-request
read at the same named snapshot, then requires the request opportunity and
domain to equal the graph-authenticated opportunity and declaration domain
before rendering legality, producer, cause, budget, stop, and continuation
state. This composition grants only the union of those two existing operation
capabilities and introduces no generic object read. `campaign explain-finding`
similarly composes the finding object's representative-observation and
original-reproduction reads and requires their exact configuration-artifact
basis to agree. `campaign explain-attempt` uses the single proof-bearing
attempt capability to render the immutable start, path, execution cause,
admission ordinal, branch selection and proposal, optional completion, and the
coordinator-accepted planner step with its exact fixed-point guidance terms and
resource accounting. The planner-step proof is bound to the proposal's exact
invocation in the anchoring coordination root. Arbitrary non-graph object reads
remain open. `campaign rankings` begins at one accepted planner step,
authenticates that exact step through `coordination.planner-step(step)` under
the requested snapshot's coordination root, reloads the step's complete
retained request, and recomputes every PUCT score from its by-value policy and
owner-built guidance. Each response carries one bounded step/request page and
returns the step's optional parent; the CLI follows at most 64 pages, charges at
most 128 MiB of aggregate canonical response bytes, and applies the packaged
planner's score/edge/position order across all returned candidates. Traversal
stops before a parent whose policy, engine, policy artifact, or planning view
differs, because scores from another interpretation basis are not comparable.
Exact branch-point and branch-request filters run only after proof and retained-
request validation. An optional top-result cap is in `1..=65_536` and truncates
only after global best-first ordering; the version-2 CLI report retains the
exact filter basis and pre-truncation matching count. With `--policy-groups`,
the client does not stop at the first incompatible parent. It authenticates
pages up to the same 64-page and 128-MiB limits, partitions them into
consecutive policy epochs, and then partitions each epoch into exact
policy/engine/policy-artifact/planning-view bases. The version-1 policy-ranking
report records each epoch's step range, pages, and match count. Candidates are
ordered and `--top` is applied independently inside each exact basis; scores
from different views or interpretation artifacts are never compared. All
filters remain post-proof, and a page-limited result returns the exact next
parent step.
The proof
key uses the membership-key derivation above with namespace
`coordination.planner-step` and the planner step's canonical underlying
`ContentId` string.
The strict
local transport frames exactly one canonical request or response as:

```text
CampaignLoopbackFrameV20 = "CRUCCS20" | kind:u8 | reserved[3] |
                          body_length:u32be | canonical_body[body_length]
kind = 1 (GetCampaignRequestV1) |
       2 (GetCampaignResponseV1) |
       3 (ApplyCampaignCommandRequestV1) |
       4 (ApplyCampaignCommandResponseV1) |
       5 (SubmitCampaignBranchRequestV1) |
       6 (SubmitCampaignBranchResponseV1) |
       7 (CampaignServiceErrorResponseV1) |
       8 (CreateCampaignRequestV1) |
       9 (CreateCampaignResponseV1) |
      10 (DeriveCampaignRequestV1) |
      11 (DeriveCampaignResponseV1) |
      12 (WatchCampaignRequestV1) |
      13 (WatchCampaignResponseV1) |
      14 (QueryCampaignGraphRequestV1) |
      15 (QueryCampaignGraphResponseV1) |
      16 (GetCampaignSnapshotRequestV1) |
      17 (GetCampaignSnapshotResponseV1) |
      18 (GetCampaignGraphObjectRequestV1) |
      19 (GetCampaignGraphObjectResponseV1) |
      20 (QueryCampaignChoicesRequestV1) |
      21 (QueryCampaignChoicesResponseV1) |
      22 (GetCampaignChoiceObjectRequestV1) |
      23 (GetCampaignChoiceObjectResponseV1) |
      24 (QueryCampaignFrontierRequestV1) |
      25 (QueryCampaignFrontierResponseV1) |
      26 (GetCampaignFrontierObjectRequestV1) |
      27 (GetCampaignFrontierObjectResponseV1) |
      28 (PinCampaignRequestV1) |
      29 (PinCampaignResponseV1) |
      30 (QueryCampaignFindingsRequestV1) |
      31 (QueryCampaignFindingsResponseV1) |
      32 (GetCampaignFindingObjectRequestV1) |
      33 (GetCampaignFindingObjectResponseV1) |
      34 (ExplainCampaignAttemptRequestV1) |
      35 (ExplainCampaignAttemptResponseV2) |
      36 (GetCampaignPlannerRankingsRequestV1) |
      37 (GetCampaignPlannerRankingsResponseV1) |
      38 (ListCampaignsRequestV1) |
      39 (ListCampaignsResponseV1) |
      40 (AttachCampaignRuntimeRequestV1) |
      41 (AttachCampaignRuntimeResponseV1)
```

Loopback frame versions 1 through 19 are rejected rather than reinterpreted
under the expanded kind table.

The canonical body is at most 64 MiB, so the complete frame is at most 64 MiB
plus its 16-byte header. Both peers enforce nonzero finite absolute read/write
deadlines, reject unknown kinds, nonzero reserved bytes, trailing/noncanonical
bodies, and cross-request responses, and shut down both stream directions after
any framing, canonical, or I/O error. A request-bound semantic service failure
uses kind 7 and leaves the connection reusable. One
connection serializes complete exchanges so concurrent local callers cannot
interleave frames; a concurrent caller receives an immediate retryable
connection-busy transport error rather than waiting outside the operation
deadline. The loopback binding is not an alternate control plane: it invokes
the same authorized `CampaignService`, and the checked client performs the same
response binding and stable failure mapping as direct calls.

The frame itself does not authenticate a Unix peer. The initial daemon adapter
reads Linux `SO_PEERCRED` before request decoding, passes exact PID/UID/GID to a
mandatory operational principal resolver, and binds the resolved principal
into the per-connection repository authorizer. Every request principal MUST
equal that resolved identity before repository access; substitution returns
`Unauthorized`. Peer-credential or resolver failure closes the connection
without dispatch. A raw connected stream plus the self-asserted `principal`
field remains insufficient and non-conforming. Production listener policy must
configure the credential-to-principal resolver and the ordinary per-operation
authorizer; neither mapping enters campaign state.

The daemon listener accepts either an explicitly embedded pre-bound descriptor
or a managed filesystem endpoint behind a fixed pool of `1..=256` connection
workers and a bounded
`1..=1024` pending-socket queue. A full queue closes the newly accepted socket
without decoding it. Each connection serves `1..=65,536` complete requests
(4,096 by default) before reconnecting through listener admission. Each worker
resolves `SO_PEERCRED` exactly once per connection, then serves complete frames
until that ceiling, clean peer close, or the first protocol/response-contract/
I/O failure. Request authorization failures retain the ordinary request-bound
semantic error behavior. The resolver MUST be a bounded, nonblocking lookup
over immutable local deployment policy; external identity I/O does not run in
a connection worker. Sticky shutdown stops acceptance,
interrupts every active socket, discards queued sockets, and joins every worker
before returning. Partial worker-start failure joins every worker already
started; a caught worker invariant panic makes shutdown sticky and fails the
listener owner. The accept loop observes shutdown at a configured interval from
1 ms through 1 s. Accepted, capacity-rejected, cleanly completed,
peer-rejected, and protocol-failed connection counts are operational telemetry
and never enter campaign identity.

The immutable local policy maps at most 4,096 exact effective
`(uid,gid)` pairs to canonical campaign principals and retains at most 65,536
principal/operation/scope grants. PID is diagnostic only and MUST NOT select a
principal because process IDs are reusable. A grant scope is either one exact
canonical campaign name or all campaign names; there are no string globs or
implicit operation groups. Duplicate identity selectors, duplicate grants, and
grants naming an unbound principal reject the complete policy. An empty policy
is an explicit deny-all value. Missing peer bindings and missing grants return
`Unauthorized`; the in-memory policy performs no external lookup and therefore
cannot turn a denial into an availability result.

The registered `crucible.campaign-local-policy` version-1 deployment format is
strict UTF-8 TOML bounded to 1 MiB before parsing:

```toml
schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = 1000
group_id = 1000
principal = "operator"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"
```

Unknown fields, schema versions, operation labels, or noncanonical principals
and campaign names reject the complete policy. `campaign = "*"` is the only
wildcard. The closed operation labels are `create-campaign`,
`derive-campaign`, `get-campaign`, `get-campaign-snapshot`, `watch-campaign`,
`query-campaign-graph`, `query-campaign-findings`,
`get-campaign-finding-object`, `explain-campaign-attempt`,
`get-campaign-planner-rankings`, `get-campaign-graph-object`,
`query-campaign-choices`, `query-campaign-frontier`,
`get-campaign-frontier-object`, `get-campaign-choice-object`,
`apply-campaign-command`, `pin-campaign`, `submit-branch-request`, and
`attach-campaign-runtime`.

The production filesystem endpoint accepts one absolute pathname of at most
107 bytes, with no NUL or dot components. Its existing parent must be a real
directory with the configured exact UID/GID and no group/other write bits. A
stable owner-only regular lock file is opened without following a final
symlink and held under an exclusive nonblocking `flock` for the listener
lifetime. Under that lock, bootstrap may remove only a preexisting Unix socket
owned by the same configured UID/GID; every other stale-path type or owner fails
closed. After bind, the socket's exact type, owner, configured permission bits,
and device/inode are retained. Graceful teardown removes only that exact socket
after acceptance and workers stop; crash recovery leaves a same-owner stale
socket for the next locked incarnation. The endpoint directory and its
ancestors are an operator-owned namespace: non-cooperating same-credential
renames remain outside this local deployment contract.

The same deployment owner requires an existing absolute state directory and
regular policy file, each owned by the daemon's exact effective UID/GID with no
group/other write bits. Both paths are free of NUL/dot components and at most
4,095 bytes. Policy open uses `O_NOFOLLOW`, authenticates the opened inode, and
reads at most the 1-MiB policy ceiling before any repository or socket write.
An optional `--campaign-component-authority` path uses the same absolute path
profile and names an exact-owner mode-`0600` regular file opened with
`O_NOFOLLOW` before repository state is opened. Its fixed version-one binary
form is exactly 72 bytes:

```text
"CRUCCA01" | planner-key[32] | debugger-key[32]
```

Both 256-bit keys are nonzero and byte-distinct. They are operational secrets,
never campaign objects, logs, exports, or transport fields. When present, the
daemon constructs the repository with those exact planner and debugger
authorities; malformed, exposed, replaced, zero, or equal key material fails
before any state-directory or socket mutation. Omitting the file leaves the
control/query service usable but does not authorize planner or debugger
component acceptance; runtime attachment therefore rejects the profile before
executor I/O when the file is omitted.
The state root retains a stable owner-only exclusive lock across the complete
listener lifetime, creates or validates private `objects/` and `refs/`
subdirectories, and rejects a second cooperating daemon even if it names a
different socket. Its directory identity is rechecked before the path-backed
stores become reachable. `crucible serve` enables this composition only when
`--campaign-socket`, `--campaign-state`, and `--campaign-policy` are supplied
together; `--campaign-component-authority` is valid only with that profile,
and `--campaign-socket-mode` is octal and defaults to `600`. A startup-fixed
single-host attachment set is enabled either by repeating paired
`--campaign-runtime NAME` and `--campaign-executor-socket PATH` arguments in
the same order or, for one packaged endpoint, by passing
`--campaign-runtime-all`. The latter authenticates one stable repository-ref
page and fails closed when the catalog is empty or requires more than the
reviewed 256 entries; it never silently truncates. The daemon accepts 1 through
256 unique existing campaign names, requires the writable component-authority
profile, sorts the prepared attachments by canonical campaign name before
starting them, and gives each campaign the packaged canonical planner worker
plus its checked executor connection. Before publishing an attachment's fixed
four-object planner basis,
the daemon connects to its absolute dot-free executor path whose socket inode
is exact-owner mode `0600`, authenticates the connected peer's effective
UID/GID with `SO_PEERCRED`, rechecks the path identity, performs
`DescribeExecutor`, and requires the executor's exact lineage compatibility,
resource ceiling, and slot ceiling. Every attachment is prepared before any
runtime thread starts. The reviewed default serves
at most 1,024 planner positions and 16 MiB per planner invocation, scans at
most 1,024 attempts per executor step, and caps admitted worker slots at 256.
Termination of any attached runtime stops the shared service and joins the
complete bounded set before repository ownership is released. One packaged
local QEMU executor may own the complete bounded attachment set when every
campaign has the same exact executor compatibility profile. Before opening its
Linux host owner it loads, aggregate-charges at most 128 MiB of canonical
scenario-artifact bodies, and semantically decodes every distinct scenario.
It then captures one native baked genesis per scenario and installs a closed
promotion catalog keyed by exact World/scenario identity. All workers and
campaigns share one aggregate capacity owner and endpoint. The embedded
deployment owner may also retain a weak post-bind attachment capability. It
exposes neither repository nor component-
authority access, rejects read-only or authority-free profiles before executor
I/O, and reserves a unique campaign plus one of the same 256 attachment slots
before bounded executor/repository preparation. Preparation runs without the
registry mutex; installation succeeds only while the exact service incarnation
still accepts attachments. Shutdown closes admission, waits for every bounded
preparation already in flight, requests cancellation for every installed
runtime before joining any one, and retains the repository lock through the
final join. A caller must supply an already connected and authenticated local
executor stream or the daemon's exact endpoint capability. The latter shares
startup's bounded pathname, secure parent namespace, exact socket owner/mode,
before/after device-and-inode, and `SO_PEERCRED` checks. Connect itself is
nonblocking under a 30-second absolute default deadline and a one-hour hard
configuration ceiling. The connector is invoked only after the registry
reserves the campaign and slot.

The public-operator attachment checkpoint defines a separate daemon-
operational component-message basis. It is not a campaign semantic record and
its endpoint path MUST NOT enter any snapshot, artifact, modeled event, or
content identity:

```text
AttachCampaignRuntimeRequestV1 = version:u32be | principal:string |
    campaign:string | executor_endpoint:bytes
AttachCampaignRuntimeResponseV1 = version:u32be | request_digest:[u8;32] |
    campaign:string | disposition:u8 | attached_runtime_count:u32be
disposition = 1 (Attached) | 2 (Replayed)
string = length:u32be | utf8[length]
bytes = length:u32be | octets[length]
```

Both bodies are at most 4 KiB. `principal` and `campaign` use the existing
campaign-service grammars. `executor_endpoint` is an absolute, dot-free,
NUL-free Linux pathname-socket address of at most 107 bytes. The complete
request binding is
`H("crucible.campaign.attach-runtime-request.v1", canonical_request_bytes)`.
The response MUST repeat that digest and campaign exactly; its count is in
`1..=256`. `AttachCampaignRuntime` is a distinct per-campaign policy operation
and is always denied by read-only service mode. The closed bodies, digest, and
authorization label are implemented and registered in this checkpoint. The
authenticated local listener verifies the kernel-resolved principal and exact
per-campaign grant before runtime-registry reservation or executor I/O. One
accepted request installs the runtime; an exact replay returns `Replayed` and
the current count without reconnecting to the executor. A concurrent exact
request returns retryable unavailability while preparation is in flight, and a
different endpoint for the same campaign returns nonretryable command reuse.
`crucible campaign ... attach CAMPAIGN --executor-socket PATH` is the checked
operator porcelain. One daemon-packaged executor may serve the bounded explicit
set or the complete `--campaign-runtime-all` startup catalog when every member
shares the same exact compatibility profile and endpoint. The configured set
is canonicalized before QEMU host-resource acquisition; its distinct scenarios
form the closed 128 MiB native baked-genesis catalog described above. Attempt
admission and dynamic runtime attachment through that endpoint both require an
exact scenario already present in the startup catalog. A dynamic attachment
naming another independently authenticated executor uses that executor's
capability scope. Automatic allocation across multiple incompatible-profile
packaged pools and live expansion of a native scenario catalog remain future
work.

SIGINT,
SIGTERM, lifecycle-server failure, or CampaignService failure shuts down both
services and joins the campaign workers before releasing either lock.
`--read-only` also wraps the campaign authorizer and denies Create, Derive,
ApplyCommand, Pin, SubmitBranch, and AttachCampaignRuntime even if the policy
file grants them.
Repeatable pre-bind import manifests require the complete local campaign
profile and conflict with `--read-only`; the prepared repository owner is
consumed by endpoint binding, so this bootstrap API cannot retain import
authority after serving begins. `crucible campaign validate-import` performs
the same strict file and semantic checks without opening a socket or repository
and requires a self-contained dependency-ordered generator set. It retains one
body at a time plus bounded derived identities and emits no campaign content.

Structured operational diagnostic routing remains open. The pre-bound
constructor remains useful for embedded/test deployments, but constructing it
without equivalent path ownership and parsed policy does not make an endpoint
production-authorized.

The stable error envelope preserves authorization, stale/conflict, invalid
transition, resource, availability, and integrity meaning across direct and
loopback calls without exposing backend paths or private diagnostics. The
nested CLI and remaining service operations are still open.

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

The initial strict component messages refine the illustrative request above by
carrying every direct invocation object by value:

```text
PlannerRequestV1 = version | expected_snapshot | invocation | engine |
                   policy_artifact | policy | planner_state | input_view |
                   input_bundle
input_bundle = sorted(ContentId, canonical ObjectEnvelope bytes)

PlannerResponseV1 = version | request_digest | PlannerSubmissionV1 |
                    response_authentication_tag
request_digest = H("crucible.campaign.planner-request-digest.v1",
                   canonical PlannerRequestV1 bytes)

PlannerLoopbackFrameV1 = magic[8] | kind:u8 | reserved[3] |
                         body_length:u32be | canonical_body[body_length]
kind = planner-request(1) | planner-response(2)
magic = "CRUCPL01"
```

Requests and responses are each limited to 64 MiB. The source-interpretation
bundle contains at most 65,536 non-Merkle campaign envelopes, orders them by
content identity, rejects duplicates and unrelated objects, and must contain
the exact `BranchRequest` body for every served scan position. The adapter
recomputes the sum of those canonical request-body bytes and requires it to
equal `PlanningScanPage.input_bytes`. Direct engine dependencies reachable from
the by-value engine, artifact, policy, state, view, or served requests may be
included once.

Planner engines advertising `canonical-frontier-offers-v1` additionally
require, for every served position, the exact `ContinuationProjectionV1`
envelope authenticated by the expected snapshot's nested frontier index. For an
engine that does not also advertise `canonical-frontier-puct-v1`, the least
Ready position on the page has exactly one `ProposalV1` candidate-offer
envelope and every other position has none. An offer names the served request,
branch point, domain, active policy, exact invocation, input view, and next
one-based ordinal, and contains the owner-computed next legal value. Extra,
missing, duplicate, cross-invocation, or non-Ready offers fail closed. The
coordinator recomputes the projection and offer from the expected snapshot
before acceptance. Offer envelopes need not exist before evaluation; after
complete read-only output preflight, acceptance publishes them as retained-
request children before publishing the request. Rejection therefore remains
zero-write, while accepted requests remain closure-complete and restart-
auditable.

The built-in `crucible-canonical-frontier` implementation version 1 is a closed
pure engine for this capability. It considers only `Ready` offers, chooses the
least `PlanningScanPosition`, and carries that small exact position/domain/
value/ordinal tuple in `canonical-frontier-planner` state version 1 across
pages. It returns `ContinueScan` before EOF, `Issue` at EOF when an offer
exists, and `NoWork` at EOF otherwise. When issuing a carried offer, it
reconstructs the proposal under the final invocation; the coordinator
independently recomputes the same source ordinal and value. This establishes a
complete executable planner/frontier loop without granting repository or
Merkle authority to the engine. The first invocation requires the exact empty
state, and local acceptance plus imported/restart validation rerun this built-in
pure transition and compare its complete next state, usage claim, evidence, and
disposition.

The same engine name at implementation version 2 additionally advertises
`canonical-frontier-puct-v1`. Every Ready position has one exact offer and one
`PlannerCandidateGuidanceV2`; non-Ready positions have neither. The guidance
body is bounded to 64 KiB and encodes, in order:

```text
schema_version = 2
input_view: CampaignViewId
policy: CampaignPolicyId
position: PlanningScanPosition
domain: ChoiceDomainId
domain_semantics: ChoiceDomainSemanticId
value: ChoiceValue
ordinal: u64
edge: BranchEdgeId
statistics: PuctEdgeStatistics
novelty_events: u64
objective_reward_micros: i64
finding_events: map<FindingKind, u64>  # at most three positive entries
```

Its envelope children are the exact input view, policy, served request, and
domain. `edge` MUST derive from the branch point, semantic domain, and value;
the novelty count MUST agree with the Boolean statistic; the objective field
MUST equal the bounded owner projection in RFC 03; and the reward sum MUST equal
the saturating addition of that signed field and the by-value policy's
configured closed finding weights times occurrence counts. Completed edges
reuse exact authenticated statistics and their earliest execution-basis source
weights. An unseen offered edge is the sole prospective addition to the
completed set, with zero visits/reward/novelty/objective/findings, exact RFC 03
normalization over completed weights plus its BranchRequest-v2 explicit weight
or implicit weight one, and fairness reserved. Schema-v1 bodies omit
`objective_reward_micros`, remain canonical
with neutral objective reward, and are accepted through identity-preserving
historical recomputation; new request construction emits v2.

The owner computes one batch per page. Aggregate credited observations and
credit/path bodies retain the RFC 03 65,536-record/128-MiB limits; the canonical
observation and finding roots are each scanned at most once; unique decoded
choice-domain bodies are capped at 128 MiB; and distinct prospective raw
weights charge at most 1,000,000 completed-edge normalization visits. Version
2 ranks higher exact total
first, then lower `BranchEdgeId`, then lower `PlanningScanPosition`, carries the
winner across pages in `canonical-frontier-puct-planner` state version 1, and
issues only at EOF. Acceptance publishes guidance envelopes with offers only
after complete zero-write preflight and recomputes/reruns the exact transition
on restart and import. Version 1 remains canonically replayable. Bounded
model-resolved finite masses are retained in branch-request schema v3 and
exact-checked against the opportunity's model ID. Schema v4 additionally
retains an exact model ID and generator ID for modeled generated sources. The
first closed adapter maps standardized uniform app-random integer models to
permuted-integer implementation version 17, supports power-of-two cardinality
through `2^64`, caps emitted candidates by the request's `u64` proposal budget,
and uses raw prior weight one. The repository authenticates and replays the
model/generator/domain contract before local publication and during restart or
import. Other opaque non-finite scenario-model families remain an
implementation-plan gate. Explicit finite weights and uniform defaults are
owner-derived here.

The initial coordinator retention profile is deliberately narrower than the
version-1 wire format: an accepted request body is at most 32 MiB and its bundle
contains at most 65,529 objects. Seven fixed retained-envelope children name
the expected snapshot, invocation, engine, policy artifact, policy, planner
state, and input view; every bundle object is one additional child. A valid
32-to-64-MiB wire request, or a wire bundle above the retained child limit, can
be evaluated by the component protocol but cannot be admitted by this store
profile. Rejection occurs before campaign mutation and does not redefine the
wire schema.

The response authentication tag covers the response version, request digest,
and complete already-authenticated submission under a distinct
domain-separated planner authority tag. `PlannerResponseV1` therefore binds the complete request, not only the
`PlannerInvocationId`. This prevents a cached response from being replayed
across byte-distinct interpretation bundles for the same invocation. The
supervised authority adapter requires a distinct deterministic execution
supervisor.
The pure engine returns only its semantic proposal and cannot supply the
accepted fuel measurement. The adapter derives input and output counts from the
request and proposal, obtains fuel only from the supervisor, and validates
invocation, next-state engine, page disposition, exact measured counts, and all
budget dimensions before producing `PlannerSubmissionV1`. A production planner
authority MUST use a supervisor that owns evaluation, enforces deterministic
fuel and finite wall-clock bounds, observes cancellation, and can terminate an
over-budget or hung engine; the in-process fake supervisor and one-request
loopback server are conformance fixtures, not production supervision. Planner
fuel claims in the proposal remain untrusted diagnostics. The checked
coordinator client verifies the request digest and planner authority again.

The built-in `crucible-canonical-frontier` planner has an initial single-host
production supervisor. The authority-bearing parent starts the packaged
`crucible` executable with the exact private argument
`__crucible-campaign-planner-worker-v1`, clears its environment, and exchanges
one `crucible.planner.process-frame` version 1 request. Its 16-byte header is
`CRUCPP01`, one byte of kind (`1 request`, `2 proposal`, or `3 rejection`),
three zero reserved bytes, and a big-endian `u32` body length. Request and
proposal bodies use the existing canonical component schemas and are at most
64 MiB; rejection text is at most 4 KiB and captured standard error is at most
64 KiB. The configured executable is an absolute protected regular file whose
device and inode are checked before and after spawn under the local
operator-owned executable namespace contract.

The parent owns a finite 1-ms-to-60-s wall deadline, sticky cancellation,
bounded concurrent pipe drains, deterministic input-page fuel measurement,
proposal validation, and the planner authority key. Deadline or cancellation
kills and reaps the child before the call returns. The child owns no repository
or planner authority and can return only an unauthenticated proposal. This
private process protocol is distinct from the planner loopback component
adapter: loopback proves direct/RPC message equivalence, while the process
supervisor supplies killability and parent-owned metering for this built-in
engine. Attaching that supervisor to the long-lived campaign coordinator loop
remains an implementation-plan gate.

Direct and Unix-loopback paths use the same checked client. The loopback transport uses nonzero absolute
read/write deadlines capped at one hour, checks the body bound before
allocation, and shuts down both stream directions after any framing, canonical,
service, or I/O failure.

The checked client returns `PlannerResponseV1` rather than discarding its
request digest. Repository acceptance takes the exact checked request/response
pair, verifies both planner authority tags and exact request binding before any
write, retains the canonical request in a distinct content-addressed record,
and records both its ID and digest in `PlannerStep` schema v4. Import and restart
validation reload every retained child, compare the by-value basis to the
stored invocation records, recompute the digest, and require the request's
expected snapshot to be the exact parent transition. Invocation replay with a
different request ID or digest is therefore a deterministic result conflict,
and an accepted step remains auditable against its complete interpretation input.
The component transport alone is not authority to accept a planner step.

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
For a non-genesis selected source, path derivation appends the selected edge to
the lowest `BranchPathId` ordering-key member of the exact parent
configuration's authenticated path set. That member must be scoped version 2;
the pure planner does not carry or choose this owner-only prefix.
Local acceptance MUST complete a read-only semantic preflight of the output,
coordinator accounting, next-state engine continuity, and prospective step
before publishing any output body or Merkle node; imported validation MUST
remain read-only. Repeated generated requests share validation by
generator/domain pair, and all cache misses together MUST visit at most
1,000,000 generator records in one projection pass.
Loading any accepted schema-v4 step requires its authoritative snapshot because
the standalone object cannot prove its retained request's snapshot precondition.
An `Issue` additionally requires snapshot-owned admission and deduplication roots.
Planner code cannot issue commands directly. A future engine implemented in
another language is a supervised replaceable component identified by its
artifact, engine, protocol, and parameter versions.

`PolicyArtifactId` binds the canonical policy artifact or built-in engine
identity, dependency lock, planner ABI, engine version, arguments, and any
source or compiled artifact required to reproduce it. `PlannerState` is bounded
portable data. It is never a language stack, closure, heap, actor/process,
native trait object, or runtime continuation. Repeating one complete
`PlannerRequestV1` must return byte-identical canonical output; disagreement is
a planner-determinism failure.

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
The single-host coordinator implements that rule in a bounded
`CampaignPlannerDriver`. Construction requires the checked client and
repository to share the exact planner authority, requires the engine,
`PolicyArtifact`, and initial `PlannerState` to name one engine, and caps one
page at 10,000 source positions. Before every call the driver authenticates the
current head and reconstructs state and cursor from its planner-head entry; it
retains no process-local resume cursor as authority. An unchanged view already
settled by a terminal disposition is returned without reinvoking the component.
A semantic-root change restarts at `after=None` while preserving the exact
portable next state required by planner ancestry. The driver holds no
repository mutation guard while `PlannerService::plan` runs. A concurrent head
advance therefore completes normally and causes request acceptance to return
`Stale`, rather than allowing component latency to serialize unrelated owner
mutations.
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
WatchExecutions       CheckpointAttemptExecution
CancelAttemptExecution
QueryMaterializations EnsureMaterialization
RetainExactClosure    EvictMaterialization
GetHealth
```

The first bounded assignment messages are:

```text
SubmitAttemptRequestV2 = version | assignment_id | daemon_epoch | lineage_id |
                         attempt_id | resource_limits | retention_intent

resource_limits = maximum_vcpus | maximum_resident_bytes |
                  maximum_disk_bytes | maximum_execution_quanta

SubmitAttemptResponseV2 = version | assignment_id | daemon_epoch | attempt_id |
                          request_digest | disposition

GetAttemptExecutionRequestV2 = version | daemon_epoch | lineage_id | attempt_id |
                               execution_id | execution_basis_digest

GetAttemptExecutionResponseV2 = version | daemon_epoch | attempt_id | execution_id |
                                request_digest | disposition

ResumeAttemptExecutionRequestV2 = version | assignment_id | daemon_epoch |
                                  lineage_id | attempt_id | prior_execution_id |
                                  exact_checkpoint_id | resource_limits |
                                  retention_intent

ResumeAttemptExecutionResponseV2 = version | assignment_id | daemon_epoch |
                                   attempt_id | prior_execution_id |
                                   exact_checkpoint_id | request_digest |
                                   disposition

CheckpointAttemptExecutionRequestV2 = version | daemon_epoch | lineage_id |
                                      attempt_id | execution_id |
                                      execution_basis_digest

CheckpointAttemptExecutionResponseV2 = version | daemon_epoch | attempt_id |
                                       execution_id | request_digest | disposition

CancelAttemptExecutionRequestV2 = version | daemon_epoch | lineage_id | attempt_id |
                                  execution_id | execution_basis_digest

CancelAttemptExecutionResponseV2 = version | daemon_epoch | attempt_id | execution_id |
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
already-paused(execution ID, exact-checkpoint ID)
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

`GetAttemptExecution` is the read-only completion-poll operation. Its request
digest is
`H("crucible.campaign.get-attempt-execution-request.v2", canonical_request)`;
the response repeats the exact epoch, attempt, and execution and is rejected if
any echo or the digest differs. Its closed disposition vocabulary is
`running | checkpoint-requested | checkpoint-publishing(exact-checkpoint ID) |
paused(exact-checkpoint ID) | completed(observation ID) | canceled |
not-current`. The executor returns `running` for exact durable `running` or
observation-`publishing` state,
`checkpoint-publishing(promoted)` for the internal replay-validation
`checkpoint-promoting(source,promoted)` state,
`completed` only for exact durable completion, and `canceled` only for exact
durable cancellation. Absence or any epoch, lineage, attempt, execution, or
execution-basis mismatch is `not-current`. This operation reads the direct
lineage-qualified attempt-state record and MUST NOT create an assignment record.

`CheckpointAttemptExecution` is the exact-basis, idempotent pause request. Its
request digest is
`H("crucible.campaign.checkpoint-attempt-execution-request.v2",
canonical_request)`. Its closed disposition vocabulary is `requested |
already-requested | publishing(exact-checkpoint ID) |
paused(exact-checkpoint ID) | already-completed(observation ID) |
already-canceled | not-current`. The executor MUST persist
`checkpoint-requested` before signaling the running worker. Once capture has
produced a complete candidate root, it MUST persist
`checkpoint-publishing(root)` before the first campaign-CAS immutable write. It
transitions to `paused(root)` only after the complete root closure has durable
placement; only then may it release the process-local execution reservation. A
retry returns the exact durable phase and root. A different root for the same
execution is a stable conflict and MUST NOT replace the staged root.

A newly captured `paused(raw)` root carries `NotRun` replay-oracle evidence and
is not resumable. Replay validation runs outside supervisor ownership under one
attempt process/resource guard. After a matching fat/thin comparison, the
executor prepares the deterministic replacement without writes and CASes the
version-5 operational record to
`checkpoint-promoting(raw,promoted)` before the first replacement put. Both
roots are GC roots in that phase. The promoted root reuses the exact VMState
child and may differ from the raw root only by its authenticated matching
replay-oracle metadata. After all replacement objects have durable placement,
the executor CASes to `paused(promoted)`. A restart authenticates both complete
roots and this exact relationship before finishing the CAS without rerunning
QEMU; an incomplete replacement retains the raw root and reruns the same bound
validation/publication or is explicitly reverted only after stable failure.
Resume is `not-current` while promotion is staged and can begin only from the
final `paused(promoted)` root.

The local executor owns a fixed promotion-worker set distinct from semantic
attempt workers. Startup streams durable raw/staged work into a deduplicated
compact queue of at most 65,536 attempt keys before returning a service handle;
larger inventories fail closed. Every newly committed raw pause is enqueued
after releasing supervisor ownership. A fixed promotion worker owns at most one
key and one cancellation incarnation at a time. Repository authentication,
guarded replay comparison, and immutable publication occur outside the actor;
only stage, reconcile, and revert borrow it. Retryable phases retain their
linear token and never rerun the semantic attempt. Shutdown cancels in-flight
comparison, and an interrupted or stably failed incomplete publication restores
the retained raw root before releasing its token. The shared host resource
owner, not the process-local queue, remains authoritative for aggregate QEMU
capacity when semantic and promotion workers overlap.

`ResumeAttemptExecution` is the idempotent admission request for a fresh local
execution incarnation from one exact durable `paused(root)` state. Its request
digest is
`H("crucible.campaign.resume-attempt-execution-request.v2",
canonical_request)`. The request carries the new assignment and daemon epoch,
the semantic lineage and attempt, and the exact prior execution and checkpoint
that must still own the paused state. Resource limits and retention form the
same assignment-neutral execution basis used by `SubmitAttempt`; resume MUST
reject a changed basis rather than silently run the checkpoint under different
operational terms. Its closed disposition vocabulary is
`accepted(new execution ID) | already-running(new execution ID) |
already-completed(observation ID) | already-canceled | not-current |
rejected(incompatible | backpressure | unavailable-input | unauthorized |
conflicting-assignment)`. The response repeats the assignment, new daemon
epoch, attempt, prior execution, checkpoint, and exact request digest. Absence
or any paused-root, prior-execution, lineage, attempt, or basis mismatch is
`not-current` and MUST NOT launch a guest. Exact retry reproduces the same new
execution incarnation. After restart, an admitted resume remains bound to the
same checkpoint and cannot degrade to an ordinary execution from the attempt's
starting configuration.

`CancelAttemptExecution` is the idempotent mutation for the same exact
execution basis. Its request digest is
`H("crucible.campaign.cancel-attempt-execution-request.v2", canonical_request)`;
the response repeats the exact epoch, attempt, and execution and is rejected if
any echo or the digest differs. Its closed disposition vocabulary is
`canceled | already-canceled | already-completed(observation ID) | not-current`.
The executor compares epoch, lineage-qualified attempt, execution ID, and
execution-basis digest before signaling cancellation. A mismatch is
`not-current` and MUST NOT signal another incarnation. Durable cancellation is
semantic-neutral: the coordinator releases its volatile reservation, while the
executor continues charging physical capacity until the worker acknowledges
exit. `already-completed` is independently authenticated and incorporated by
the observation owner.

The implementor-facing Rust executor traits implement submit, status,
checkpoint, cancellation, and resume with this vocabulary. Resume admission is
wired through the durable supervisor, bounded worker pool, strict loopback, and
campaign driver. The durable attempt record retains the exact resume request
basis and input checkpoint through every later phase, and the worker receives
that checkpoint only as operational context. A worker MUST restore that exact
authenticated root or fail before guest work. The QEMU runner now routes a
resumed execution only through the guarded session's exact-root operation,
never consults the ordinary exact-cache/thin-replay store for that execution,
accepts only the attempt's pre-selection or post-selection configuration, and
requires the session's returned binding to echo the same immutable root ID. It
rejects a mismatched root, non-resume operation, or non-exact realization
before modeled guest work. For a branch, the live driver applies the selection
exactly once when
resuming the pre-selection parent and skips that application when resuming the
post-selection boundary; a resumed attempt cannot traverse the edge twice. The
checkpoint store and pinned run-directory transaction implement the
complete-root, streamed-VMState materialization primitive for that operation.
The guarded replay-validation session, source-bound promotion preparation,
linear publication phases, version-5 ledger transition, restart
reauthentication, and final paused-root CAS are implemented. Concrete
run-directory ownership, the guarded real-node launcher, the production
process guard, and invocation of this composition by the full QEMU flight
remain required; a raw `NotRun` root is not admitted merely because it
materialized successfully.
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
ExecutorLoopbackFrameV5 = magic[8] | kind:u8 | reserved[3] |
                          body_length:u32be | canonical_body[body_length]

kind = submit-attempt-request(1) | submit-attempt-response(2) |
       describe-executor-request(3) | executor-description(4) |
       watch-capacity-request(5) | capacity-report(6) |
       get-attempt-execution-request(7) | get-attempt-execution-response(8) |
       cancel-attempt-execution-request(9) |
       cancel-attempt-execution-response(10) |
       checkpoint-attempt-execution-request(11) |
       checkpoint-attempt-execution-response(12) |
       resume-attempt-execution-request(13) |
       resume-attempt-execution-response(14)
magic = "CRUCEX05"
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

The local executor listener authenticates Linux `SO_PEERCRED` before decoding
the first component frame and admits only one startup-fixed effective
`(uid,gid)` identity. PID never selects authority. It uses
`1..=256` fixed connection workers, retains at most `1..=1,024` accepted
sockets outside those workers, and serves `1..=65,536` complete exchanges on
one connection before closing it after the last response. Defaults are four
workers, sixteen queued sockets, and 4,096 exchanges. A full queue closes the
new socket without decoding it. Sticky shutdown stops acceptance, closes every
active and queued socket, and joins every connection worker before returning
accepted, capacity-rejected, completed, peer-rejected, protocol-failed, and
service-failed counters. It accepts either an already-bound socket or a managed
filesystem endpoint that applies the same canonical-path, exact-owner,
non-group/other-writable parent, same-owner stale-socket, configured-mode, and
exact-inode conditional-teardown rules as the campaign endpoint. Distinct
lifetime lock files let both endpoints share one secure directory without
sharing namespace authority. The managed endpoint guard remains owned until
listener join. One coupled local-service owner obtains the listener's component
service only from its exact semantic worker pool. Sticky service shutdown first
closes assignment admission and signals active execution cancellation, then
interrupts socket work; listener exit always shuts down and joins every
semantic worker. Conversely, terminal completion of all semantic workers closes
the listener, and a poisoned worker result takes precedence over an ordinary
listener stop. Dropping an owner before serving performs the same synchronous
worker join before releasing the endpoint namespace. The strict packaged
deployment now wires that owner to the concrete fresh/thin-replay QEMU worker;
exact-resume worker selection remains separate and fail-closed.

Selection-bearing Crucible configuration artifacts also carry an executor-
derived, process-local signal-fault replay plan. The executor MUST resolve the
complete selection closure before launch and MUST reject a configuration when
any standardized signal-fault selection is not followed by its exact optional
producer override, when a raw signal-fault override lacks such a selection, or
when more than 4,096 promoted events are retained. Plan entries MUST be in
target-schedule order, name exact configuration prefixes, and have
nondecreasing virtual-time frontiers. The production lifecycle installs every
finite search override before QEMU launch, caps progress at the next frontier,
and admits the selection and override only through the typed signal-fault
branch method after exact parent/time equality. Candidate injection MUST also
prove that the signal runtime consumed the exact choice ID, candidate digest,
and candidate index. Sentinel injection MUST instead prove that the scheduler
recorded the matching unmodified runtime frontier with the exact choice ID,
candidate digest, and candidate count. It MUST NOT widen the generic raw-
override method to accept selections.

For live discovery, the production lifecycle MUST compare against the frontier
history length captured before the scheduler call and MUST expose only a newly
recorded frontier whose parent configuration and virtual time still equal the
current scheduler boundary. It returns that frontier without advancing another
node; decisions already settled at the same pre-quantum boundary remain in the
result. One result admits at most 4,096 frontiers and 128 MiB of unique canonical
choice-record material. The modeled attempt publishes those records only when
they cause its exact `NextChoice` stop. If another stop policy continues
execution, the frontier is not retained in the later observation and MUST NOT
be re-emitted from scheduler history. An already admitted replay branch at that
boundary is injected instead of being rediscovered.

The fresh executor MUST enable this live-promotion mode only for an exact
`NextChoice` attempt, and only after the admitted start configuration has been
materialized exactly. Frontiers encountered while materializing that start
remain replay-only evidence and MUST NOT pause or publish retrospectively.
Terminal, marker, time, and event-count attempts MUST NOT pause merely because
an authored finite signal-search frontier was recorded. Their scheduler may
retain that frontier as replay evidence, but it grants no campaign discovery or
publication authority.

An execution with pending promoted branches is not exact-checkpoint-ready.
Fresh materialization consumes the complete plan before the modeled driver may
request capture. A process restart discards the process-local plan and rebuilds
it from the durable attempt and immutable authenticated campaign records; it
does not trust or serialize an unresolved typed plan as an exact-checkpoint
continuation.

The single-host daemon persists two bounded operational record families:

```text
AssignmentRecordV1 = magic | request_bytes | response_bytes | checksum

AttemptStateRecordV6 = magic | lineage_id | attempt_id |
                       execution_basis_digest |
                       execution_origin(initial |
                         exact-checkpoint(assignment_id, request_digest,
                           prior_execution_id, exact_checkpoint_id)) |
                       (running | observation-publishing |
                        checkpoint-requested | checkpoint-publishing | paused |
                        checkpoint-promoting(source, promoted) |
                        completed | canceled) |
                       daemon_epoch | execution_id |
                       observation_id? | output_exact_checkpoint_id? |
                       source_exact_checkpoint_id? |
                       promotion_basis?(resource_limits, retention_intent) |
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
The version-6 attempt-state reader retains strict read compatibility for
versions 1 through 5. Only versions 5 and 6 may encode
`checkpoint-promoting`; version 6 additionally retains the exact resource and
retention basis in `paused` and `checkpoint-promoting` records. A legacy pause
without that basis remains a durable GC root but cannot launch a new guarded
comparison after restart. A legacy staged pair remains discoverable because a
complete replacement can be authenticated and reconciled without QEMU.

`checkpoint-publishing` and `paused` records are durable GC roots for their
exact output checkpoint IDs. `checkpoint-promoting` retains both its raw source
and expected replacement. Every phase of a resumed incarnation also retains
its exact input checkpoint as a GC root until that incarnation reaches durable
retirement. Restart replaces a stale checkpoint-requested execution
with a new-epoch recovery execution and keeps the checkpoint request signal
sticky. It likewise preserves the exact expected root while recovering stale
checkpoint publication; a regenerated candidate MUST have that ID and cannot
silently substitute a different checkpoint. An already-paused exact basis is
replayed without starting guest work. The executor never releases the active
reservation merely because capture was requested or a root was staged.
Restart discovery streams lineage-qualified attempt records and emits only raw
pauses with a complete version-6 promotion basis plus every staged pair; it
does not materialize the operational ledger in memory. Immutable checkpoint
authentication and guarded replay happen after supervisor ownership is
released.

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

The local Crucible execution adapter owns nested payload schemas. Scenario
payload versions 1, 2, and 3 are respectively the strict `ScenarioDefForm`
compact-binary V5, V6, and V7 encodings; configuration payload version 2 is the
strict `Schedule` compact-binary V2 encoding. Before VM launch the adapter decodes both, authenticates the exact
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

Scenario V7 owns the complete bounded selectable declaration component. Its
identity commits to non-default ceilings even when the declaration map is
empty. Before a fresh white-box node launch, the production lifecycle projects
only that node's guest declarations into the sealed `CRUCSCP2` catalog plan,
including exact domain/default/tag bytes, required/optional presence, and the
scenario request ceilings. Black-box nodes receive no guest-selectable plan.
Until the exact selectable continuation is composed into the production
checkpoint, selectable-enabled exact restore fails before process launch rather
than silently installing a cold catalog.

At each paused guest selectable request, the modeled daemon driver resolves the
node-local name against that exact V7 component, decodes an optional strict
narrowed domain, rejects any widening or default exclusion, and derives the
language-neutral guest opportunity coordinates from RFC 02. A `NextChoice`
attempt retains the complete declaration/domain/opportunity discovery without
replying. Other discovery execution records and returns the declared default.
Thin start replay consumes an authenticated default, locked, or campaign-branch
selection only when the reconstructed opportunity and domain match; branch
replay also re-derives the edge from the exact current parent before publishing
the reply. No request sequence, reply address, repository callback, or native
QEMU value enters the semantic identity or selection engine.

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
For an accepted semantic `Exact` pin, the local executor/maintenance owner
separately selects one authenticated `ExactCheckpointId` whose modeled
configuration equals the pin target. That operational selection is bound to the
latest accepted pin fact and enters GC only while that fact remains the current
exact projection. It does not enter campaign semantic identity or grant the
executor campaign-ref authority. RFC 06 defines the journal, bounds, and
plan/apply fences.

The repository executor handoff is deliberately phased. First it validates the
complete in-memory child-configuration, measurement, property, coverage,
newly-discovered choice records, and observation bundle plus every
already-published dependency. Each discovery carries its exact
`SelectableDeclarationV1`, `ChoiceDomainV1`, and `ChoiceOpportunityV1`; the
repository requires their content-derived IDs and copied semantic contract to
agree before publication. One candidate carries at most 65,530 discoveries and
at most 128 MiB of unique canonical declaration, domain, and opportunity
bodies. Shared records are charged once. An invalid bundle writes nothing.
After the durable publishing root exists, the repository publishes those
immutable content-addressed records without advancing a campaign ref. Only the
coordinator may subsequently incorporate the authenticated observation through
the snapshot owner transaction. Partial immutable writes remain recoverable
under the publishing root and cannot create campaign meaning. This
self-contained handoff lets a dynamic producer introduce a new choice contract
without receiving ambient repository or mutable-ref authority.

The single-host coordinator uses a bounded `CampaignExecutorDriver` to connect
the snapshot claim projection to this component protocol. It retains at most
the configured `AttemptQueue` reservation count, scans at most 10,000
accounting entries per step, and performs no component call while holding the
repository mutation owner. A completed response is independently authenticated
against the exact request and then admitted by the snapshot owner. Retryable
running-status polls use the exact read-only `GetAttemptExecution` basis and
therefore do not grow the immutable assignment ledger; transport and
response-validation failures retain that query. Retryable
`backpressure` and `unavailable-input` responses release the current lease and
retry under a fresh assignment ID, as required by the immutable response
ledger. `unauthorized` is a local configuration/authority stop and creates no
semantic fact. In this one-executor deployment only, stable `incompatible`
means no eligible executor remains and atomically publishes the exact
`AttemptClosed(PermanentlyIncompatible)` ordinal disposition. That transition
is replayable before staleness, excludes the attempt from future claim pages,
and conflicts with modeled observation publication.

The supervisor actor takes at most one queued assignment through a linear token
and releases its mutable state before guest execution, candidate preflight, and
immutable publication. Long guest or storage work never holds the borrow needed
by service or cancellation handling. Retryable execution failure requeues the
same reservation once; retryable result-storage failure retains and republishes
the already-produced candidate without rerunning the guest. Stable failure is
explicitly canceled or quarantined. Pending locators remain bounded by admitted
capacity.

The single-host daemon composes that phase protocol with a startup-fixed
`LocalExecutorWorkerPool`. It creates at most 256 workers and never more than
the advertised execution-slot ceiling. Submit first performs exact ledger
replay/epoch preflight under the actor, releases it for repository-backed
semantic admission, and rechecks assignment identity before final admission.
Thus closure authentication cannot block concurrent capacity or cancellation
operations. A worker owns one non-cloneable queued token; retryable execution
failure requeues it, while retryable preflight/publication/completion failure
retains the later phase token and cannot invoke the model again. Shutdown is
sticky, cancels in-flight work, drains queued tokens without launching them,
and retains charged capacity until each physical worker acknowledges exit.
Caught component panic poisons the incarnation and fail-closes new submissions
while the exact active execution is durably canceled.

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

The initial canonical capability messages are:

```text
DescribeExecutorRequestV1 = version
ExecutorDescriptionV1 = version | daemon_epoch | immutable_capability_set
immutable_capability_set = compatibility_profile | host_architecture |
                           sorted_qemu_profiles | sorted_materialization_paths |
                           maximum_slots | per_attempt_resource_ceiling |
                           sorted_store_namespace_ids

WatchExecutorCapacityRequestV1 = version | daemon_epoch | capability_digest |
                                 after_sequence?
ExecutorCapacityReportV1 = version | daemon_epoch | capability_digest |
                           sequence | available_slots | available_vcpus |
                           available_resident_bytes | available_disk_bytes |
                           sorted_exact_or_hot_locality
```

The immutable set MUST include the thin-replay correctness fallback. A locality
entry may name only exact restore or hot fork; thin replay is not cached
locality. The local service refuses to start when advertised daemon identity,
slots, CPU, memory, disk, or per-execution quanta differ from the supervisor's
enforced configuration. A capacity response MUST match the exact description,
use a fresh strictly increasing daemon-epoch-scoped sequence greater than the
caller's cursor, remain within configured ceilings, and advertise only a
supported materialization tier. Recomputing a response always allocates a new
sequence, including when a lagging client polls, so one `(daemon_epoch,
capability_digest, sequence)` never identifies conflicting report bodies.
Sequences observed by one client need not be contiguous: other clients may
consume intervening numbers, and intermediate advisory capacity states may
coalesce before the next poll.
Direct and Unix-loopback clients apply the same checks. The loopback frame
remains version 1 and assigns new explicit message-kind tags; unknown tags fail
closed.

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

The first production-facing QEMU adapter realizes the authenticated starting
configuration through the existing single `instantiate_qemu_vm` path. Exact
snapshot admission reports `exact-restore`; ancestor or baked-genesis replay
reports `thin-replay`. It can be instantiated only with an attempt-scoped live
session created from the admitted CPU, resident-memory, writable-disk, and
execution-quantum ceilings plus the cancellation signal. That session owns the
live backend capability used by the typed post-materialization driver, checks
cancellation during blocking operations and between bounded quanta, and runs a
mandatory kill-and-reap cleanup path after success, failure, or cancellation.
The driver never receives the raw live backend and resource boundary as
separable capabilities. A session-owned facade charges exactly one admitted
execution quantum before each realization-replay or live-backend advance; an
exhausted or canceled charge prevents guest progress and remains an operational
failure even when the narrow backend method reports through its backend-error
channel. The reusable counter charges exactly through the admitted nonzero
ceiling and leaves its state unchanged on exhaustion.
The realization executor owns replacement and VMState authority; the driver
receives a narrow mutable live-backend facade that excludes generic snapshot,
restore, shutdown, and process-replacement operations. The driver also receives
only an operational-boundary view of the resource guard, never its release or
quarantine authority. Every blocking launch, restore, replay, and shutdown call
receives the exact guard so cancellation and resource ownership remain active
while the call is in progress, not only before and after it. The session
exact-binds the originating resource, retention, and cancellation context,
shuts down the backend under the guard before releasing it, and repeats each
incomplete cleanup phase from its drop backstop. A failed reap retains or
transfers direct-child and cgroup authority into supervisor-owned quarantine;
the limits stay active and another attempt cannot use that executor until reap
is attested.
An error from a guarded realization call triggers a separate failed-realization
reap attestation that covers children launched before active-backend
installation. A concrete launcher retains the nonduplicable child handle when
its synchronous cleanup cannot attest reap, rejects another launch while that
authority remains installed, and lets the guarded replay session transfer the
child into the attempt resource guard before cancellation checks or the
realization error escape. The session then quarantines the guard and poisons
the executor. Cleanup failure takes precedence over an earlier modeled failure
so the supervisor cannot mistake quarantined capacity for a normally finished
slot.
Checkpoint-store lookups receive the same cancellation signal, must bound their
blocking work, and are cancellation-checked before, during, and after each
call.

The QEMU process layer provides a sealed child-side primitive and the first
operator-delegated Linux cgroup-v2 authority needed by the concrete host guard.
The authority creates exactly one named child below a pinned unified cgroup-v2
root, fails closed unless `cpu`, `memory`, and `pids` are exposed and delegated,
installs exact `cpu.max`, `memory.max`, disabled-swap, and `pids.max` controls,
and mints the otherwise-unconstructible child contract from fresh
`cgroup.procs` and sticky nonblocking eventfd descriptors. It holds one
nonblocking exclusive lock on the delegated child namespace across root,
configured-group, and failed-setup cleanup authorities; a valid delegation MUST
not grant a non-cooperating writer access to that same namespace. A child
forked while an authority is live inherits the close-on-exec lock description
until `exec`; replacement-owner acquisition therefore treats a transient busy
result after final local release as a fail-closed handoff and retries within its
supervised startup deadline. Once a child directory exists, every setup error
retains its pinned cleanup authority, and a failed release returns that
authority instead of dropping it. The authority
retains independent `cgroup.kill` and `cgroup.events` access for
cancellation/reap supervision, derives the exact PID/start-time/executable
identity from the owned direct child, authenticates that process generation
before and after a fixed-memory membership scan bounded to 65,536 tasks, and
retains the nonduplicable direct-child wait handle in a must-reap authority.
That authority rechecks the recorded generation before force-kill and preserves
the handle on every reap error. A failed realization can consume its active
node, discard modeled channels/backend authority, and surrender that child into
the authenticated must-reap authority. The retained child also carries the
unforgeable watcher-lifecycle token, so a removed and recreated cgroup at the
same path cannot claim it. Every other pseudo-file read is byte-bounded.
The cgroup authority pins parent and child directory
identities instead of trusting mutable paths and removes the child under the
namespace lock only after `populated 0` is observed and its named identity is
reauthenticated. The CPU controller caps aggregate CPU time; exact virtual-CPU
count is separately checked against the validated launch command. The child
writes itself into the cgroup, checks cancellation without consuming it, and
installs a per-file `RLIMIT_FSIZE` defense before `exec`. It then clears every
supplementary group and switches its real, effective, and saved user/group IDs
to configured non-root values. Admission requires both IDs to differ from every
real, effective, and saved supervisor user/group identity and its bounded
supplementary-group set. `no_new_privs` is set before the credential switch so a
later `exec` cannot regain privilege. Guarded spawn refuses implicit `qemu-img`
work and requires an already-provisioned non-symlink VMState container. Before
revalidating the prepared authority or allocating child descriptors, it checks
the launch command's exact vCPU, guest-memory, and minimum writable-byte
baseline against the ceilings sealed into the child contract. The writable
ceiling also supplies a conservative per-file `RLIMIT_FSIZE`; a separate
attempt-owned filesystem quota remains required to enforce the aggregate. The
delegated hierarchy MUST NOT grant those child credentials an independent write
path back to its controls.

Public prepared-run-directory construction first admits the command's exact
resource profile against the sealed child contract, then opens the directory
without following its final path component, retains the exact regular VMState
inode, and treats the original path as diagnostic only. The process contract
and prepared directory share one private lifecycle token in addition to the
numeric resource basis; a directory admitted for another attempt is rejected
even when both attempts have identical ceilings. Exact-checkpoint
materialization likewise requires that contract before path access. The
authority stores that complete basis;
guarded spawn requires an exact match before revalidation or descriptor
allocation, preventing a directory admitted for one ceiling from being reused
under another. Guarded spawn requires that pinned authority,
reauthenticates the named VMState entry before allocating child descriptors, and
then, after cgroup placement and sticky-cancellation admission, uses `fchdir`
plus a second `openat`/`fstat` identity check immediately before dropping child
credentials and executing QEMU. Renaming or replacing the external diagnostic
path therefore cannot redirect the child. The descriptor does not make the
directory namespace immutable after that check; the production quota/run-
directory owner MUST exclude concurrent namespace mutators until QEMU has
opened every relative artifact.

Retained-template hot fork uses a distinct birth-time form of the same process
contract because a post-`fork` write to `cgroup.procs` would leave an
uncontained execution window. Before the fork request, the host imports the
target attempt's pinned cgroup-directory descriptor and sticky cancellation
eventfd through standard QMP descriptor transfer. QEMU authenticates the exact
cgroup device/inode, eventfd identity, nonzero file-size ceiling, and retained
template generation, then retains them as a one-shot process-contract
generation. The fork request binds that thirteenth generation. On Linux the
source main-loop coordinator MUST create the child with
`clone3(CLONE_INTO_CGROUP)` against the retained directory, so its first
instruction is charged to the target cgroup. Before descriptor-table or runtime
reconstruction, the child MUST poll the non-consuming cancellation event and
install the exact `RLIMIT_FSIZE`; cancellation or either failure exits without
guest admission. A known fork outcome consumes the generation exactly once;
the source closes its retained descriptor duplicates only through an exact
release operation. An indeterminate exchange retains the complete source and
stage for recovery.

The daemon-side target owner opens a pidfd for the reported child and requires
that pidfd to name the same live PID before and after deriving the
PID/start-time/executable identity and performing the bounded target-cgroup
membership proof. The pidfd is kill authority, not direct-child wait authority:
the source QEMU remains the kernel parent, retains one bounded generation/status
record, performs `waitpid`, and releases that record only after daemon
reconciliation. The daemon MUST retain the pidfd identity, target cgroup owner,
aggregate attempt filesystem quota, sticky cancellation hook, execution-quantum
counter, source child-status generation, and private child channels as one
attempt authority; it MUST NOT synthesize `std::process::Child` from the numeric
PID or split the process owner from the target's complete resource guard.
The daemon reconciliation owner also binds the lineage-qualified `AttemptId`
and process-local `ExecutionId`. It admits modeled execution only after the
sole diagnostic reader is serviced and the private child QMP endpoint
authenticates the complete retained generation basis. A successful fork
transfers the sole branch-private diagnostic reader
into that same linear owner while the source retains the ordered writers. The
owner performs one nonblocking diagnostic drain as its own bounded step before
every source-parent status query. The live-child capability also drains before
every cancellation check and scheduler-quantum charge; modeled guest progress
outside that capability is nonconforming. Diagnostic I/O or cumulative
capacity failure is terminal and quarantines the indivisible owner before any
later status observation. Reconciliation is otherwise monotonic and performs
at most one bounded operation per step: observe source-parent status, release
child-private resources, prove
the target cgroup empty, reconcile an authoritative observation/cancellation/
terminal-failure outcome, release the exact source status, and finally release
the QEMU-owned process-contract descriptors. An observation is invalid if the
private child was never admitted. A backend error retains the current phase for
exact retry; dropping any incomplete owner kills through the pidfd and transfers
the indivisible process-and-filesystem guard to quarantine. The executor
reservation remains associated with this state until the semantic outcome is
supplied. The worker execution
context carries the exact lineage-qualified attempt and process-local
execution incarnation as operational, non-modeled data. After a successful
modeled result, the fixed worker pool supplies the durable observation,
checkpoint, cancellation, or rejected-result disposition through a bounded
post-execution callback and does not dispatch another assignment on that
worker until the retained owner reports complete. A runner that returns an
execution error MUST instead finish or quarantine its operational incarnation
before returning, so supervisor requeue cannot overlap the failed QEMU owner.

The hot-fork runner boundary is linear. It rejects exact-resume work and any
child whose lineage-qualified attempt/execution incarnation differs from the
worker reservation. QEMU realization can mint a prepared source capability
only after the active node, its exact realized configuration, its unified
event-log prefix, and the complete retained-template resource transaction have
all been authenticated. Preparation failure leaves those authorities installed
in the realization executor. A fixed worker factory exact-binds one such source
to one lineage and paused configuration. It admits the target resource guard
before consuming the source slot, transfers exactly one source-and-target
lifecycle into the runner, and leaves that slot empty until the originating
factory recovers the source after durable semantic reconciliation. A foreign
factory, configuration, lineage, or execution incarnation fails closed before
source reuse.

A modeled driver receives only the admitted private child, non-releasing
operational boundary, branch-private clone of the exact event-log prefix, and
branch-local host continuation. Driving and result sealing are separate phases
at one exact paused boundary. The runner then terminates the child, polls the
source-owned status under a finite configured cadence, proves target-resource
release, and retains the source lifecycle until the worker supplies its durable
semantic disposition. Retryable source-template recovery returns the unchanged
lifecycle token. Dropping a pending runner transfers that token to the
factory's nondroppable quarantine owner. An execution error has no durable
semantic disposition; after target cleanup the runner MUST quarantine the
remaining source lifecycle rather than fabricating `Failed` and releasing the
source status. The fixed factory's current fail-closed sink retains at most one
unrecoverable authority per configured worker for the daemon process lifetime;
an orderly daemon owner can instead take an idle source for explicit shutdown.
A bounded pool may retain at most 256 such fixed workers across exact
lineage/configuration keys. Duplicate workers for one key are selected in
stable insertion order to provide bounded parallelism. A returned lifecycle
binds the pool incarnation, exact key, and stable per-key slot; only that pool
can route successful recovery back to the source. Missing keys fail without
touching a worker, all matching busy slots report retryable backpressure, and
foreign or terminal lifecycles move to the pool's nondroppable quarantine.
Demotion can remove only a source whose fixed factory proves idle and returns
the complete factory/source authority to the caller for orderly reap or durable
fallback. Removal leaves a stable tombstone while sibling children exist, so
their recovery coordinates cannot shift; a later same-key insertion may reuse
that slot only after the old idle authority has been transferred. Hotness
scoring and pressure selection are enforced by a single managed-pool owner. It
binds every fallback to an exact checkpoint or thin configuration-artifact
identity, preflights all fallback identities and exact victims before the first
transfer, and requires the demotion sink to reauthenticate the planned fallback
and attest source reap before accounting release. It restores a failed source
authority at its exact coordinate and reconciles any earlier successful
releases when a multi-victim plan fails partway through. Explicit
operator, shutdown, and source-invalidation demotions use the same ordering.
Every attempted child start consumes the owner's process-wide monotonic-time
fork-rate admission before source-pool routing. A concrete production demotion
sink and fallback router, the atomic world-continuation installer, modeled
private-child driver, and real QEMU campaign flight remain required before hot
fork is advertised.

Exactly one attempt-owned watcher blocks on the same sticky eventfd, and child
contracts cannot be minted before that watcher is live. Terminal cancellation
and ordinary finalization first make the event readable and then publish the
terminal lifecycle state; a signal failure still publishes terminal state
before returning. The watcher closes new child minting and issues `cgroup.kill`
plus bounded `cgroup.events` checks at one fixed 10 ms cadence until the group is
empty. This common terminal path prevents a stop request from disarming a
racing cancellation or pre-exec child. Ordinary control failures retry at that
bounded cadence while retaining the pinned namespace and control authority. A
caught invariant panic enters a non-reentrant parked quarantine with the same
authority. A bounded caller wait returns the still-live watcher on timeout for
retry or quarantine. Dropping an unjoined watcher also latches terminal closure
and leaves its worker retaining authority until empty, fail-closed.

The crate-internal process layer now has a nondroppable quarantine worker that
accepts only retained direct children, an optional not-yet-joined watcher, and
a configured cgroup carrying the same watcher-lifecycle token. It makes sticky
cancellation visible, repeatedly kills the group, synchronously reaps every
nonduplicable direct child, joins the watcher when present, and removes the
authenticated empty cgroup. Ordinary host failures
retry at the fixed kill cadence. An invariant panic is caught once and parks
with every remaining authority retained; dropping the observation handle does
not stop cleanup. A startup error returns every untransferred authority, and an
ignored error deliberately leaks them rather than invoking bounded destructor
cleanup.

A crate-internal attempt-process owner now starts the one watcher before
minting its sealed child contract and retains that complete state through the
attempt lifetime. Normal finish joins the terminal watcher before removing the
authenticated empty cgroup. A failed realization can retain a bounded set of
nonduplicable direct-child handles even when `/proc` identity authentication
itself failed; quarantine then force-kills the exact owned children while the
cgroup watcher covers every group member. Dropping an unfinished owner transfers
its group, optional watcher, and retained children to the nondroppable worker.
Startup, watcher, and removal failures return or retain their authority for
retry, and an unrecoverable worker-start failure leaks it fail-closed.
The public process-only facade also implements the hot-fork child-owner
boundary. It admits at most one child, pins the reported live generation with a
pidfd, performs the exact cgroup proof through the retained internal owner, and
returns a linear identity/kill authority. Failure leaves group-wide kill and
source-QEMU reap ownership intact for quarantine.

The process-local cancellation incarnation supports lock-free boundary polling,
a bounded blocking wait, and exactly one registered attempt-resource callback.
Cancellation publishes the blocking-wait predicate while holding the same
mutex used to register a condition-variable wait, then wakes all waiters before
releasing that mutex. This ordering prevents a waiter from observing the old
predicate and losing the wake immediately before it blocks.
Cancellation invokes that callback synchronously after making the process-local
state sticky; registration after cancellation invokes it before returning.
Registration and cancellation may race, so the callback is idempotent. A
poisoned wait primitive is interpreted as cancellation rather than leaving a
process guard dormant. The attempt-process owner can duplicate a narrow signal
that only publishes the sticky eventfd transition and terminal watcher state;
it cannot change limits, inspect membership, or release the cgroup. Once that
signal fires, the owner refuses to lend its child contract even while the
watcher is still killing and reaping existing members.

The daemon now provides the concrete composition around one indivisible host-
resource owner. That owner MUST jointly bind the sealed child contract and the
aggregate writable quota for VMState, overlays, logs, and every other child-
mutable artifact; callers cannot pair separate process and quota authorities.
The wrapper verifies the owner's exact admitted resource basis, registers its
independent sticky signal with the exact cancellation incarnation, and charges
one checked quantum before guest progress. Normal finish unregisters the signal
and releases the host owner only after reap. Any failed reap transfers the same
process and filesystem authority to quarantine, and dropping a live wrapper
performs that transfer. A pre-canceled or mismatched installation is rolled back
before the factory returns an error.

The QEMU host crate now contains both the crate-internal ext4 project-quota
transaction and its daemon-incarnation storage owner. The transaction accepts
pinned filesystem and fresh run-directory descriptors plus an exclusively
allocated nonzero project ID, requires active project quotas and a completely
unused quota record, installs equal hard and soft block/inode limits,
synchronizes and reads back the quota, then assigns the directory's project ID
and inheritance flag. The generic quota interface counts 1,024-byte blocks, so
a non-aligned admitted byte ceiling is rounded down and can never be exceeded.

The storage factory validates and exclusively locks one private, empty,
supervisor-owned mode-`0700` ext4 root before allocation. It uses a bounded
operator-reserved project-ID range and a fixed-width daemon-incarnation name
sequence. One allocation creates and pins the child, installs quota, transfers
the directory to the configured non-root QEMU user/group that is distinct from
every supervisor credential, authenticates quota usage and ownership, and
synchronizes the parent before exposure. A dirty root
at daemon restart fails closed instead of silently reclaiming an old attempt.
Release is ordered after process reap. A descriptor-relative cleanup pass
deletes at most the configured inode ceiling of named entries, capped at 65,536,
without following symlinks or crossing the run-directory filesystem. It keeps
only the current directory descriptor open, authenticates every ascent and
named child identity, and synchronizes directories from the leaves upward.
The resulting empty directory is restored to its original project attributes
before the zero-use quota record is cleared, synchronized, and read back; the
exact named inode is then removed and its parent synchronized before the
project ID returns to the pool. Every partial create, cleanup, or release error
retains the pinned directory, shared root-lock description, cleanup bound,
quota state, and project-ID lease for monotone exact retry. Dropping an
unfinished owner leaks that authority and keeps the ID reserved fail-closed. A
nondroppable Linux host owner now pairs that storage authority with the exact
cgroup process owner under one public sealed facade. Normal finish proves
process reap before artifact cleanup. Any process or storage error transfers
both retained owners to a detached worker; ordinary failures retry with bounded
backoff, while an invariant panic parks the worker without dropping authority.
Partial setup never exposes a child contract and either cleans the storage
owner asynchronously or retains lower-level setup authority fail-closed. The
combined owner now admits each exact launch profile before creating a fresh
fixed-width monotone generation directory and empty VMState destination through
its retained attempt-root descriptor. It applies and reads back the child
ownership/mode policy, synchronizes the child and attempt root, and issues a
descriptor-pinned prepared authority without exposing a raw storage descriptor.
All generations inherit the same project ID and share the attempt's aggregate
block/inode quota. The owner retains only the next generation ordinal; kernel
inode enforcement and bounded cleanup own every completed or partial child.
Invocation by guarded launch, baked/thin image
provisioning, and a real ext4 project-quota enforcement VM gate remain mandatory
before this host owner is selected by the production executor.

The packaged production executor now selects this authority after capturing
and admitting baked genesis but before binding its endpoint. The guarded
launch/session path transfers retained pre-install and active-node
children into the abstract attempt guard, and the daemon guard composes
cancellation, quantum accounting, descriptor-pinned preparation, and
all-or-quarantine cleanup around the concrete combined Linux host owner. A
production lifecycle now accepts and retains one object-safe node-launch
authority. Initial fresh/exact materialization and every modeled crash/restart
replacement pass through that same authority; whole-world debugger replay must
obtain an independent authority from it or fail closed. The authoritative
lifecycle binds the exact node, positive generation, launch profile, and one of
three preparation operations in the same request: fresh overlay creation,
authenticated exact overlay/VMState materialization, or replacement cloning
from the prior generation. The launcher performs that preparation before it
spawns the child. The lifecycle itself no longer creates a generation
directory, invokes `qemu-img`, copies exact artifacts, or clones replacement
artifacts before the authority sees the request. A fresh process request cannot
be paired with exact/replacement preparation, and an exact process request
cannot be paired with fresh preparation. Exact preparation carries the complete
authenticated per-node checkpoint-manifest identity, not only snapshot
metadata, and lends each retained artifact through a fixed-memory streaming
reader that checks its declared length and content identity. A guarded launcher
can therefore stream VMState into its already-pinned linear destination and bind
that inode to the complete checkpoint root without replacing or reopening it.
The lifecycle therefore has neither a
pre-spawn writable-storage bypass nor a later direct-spawn bypass around the
attempt guard. Every successful launch returns the live node together with a
linear lease naming the exact scheduler `NodeId` and positive process
generation. The lifecycle retains active and staged leases
separately. A staged replacement cannot displace the active lease; the active
lease is released only after the old child is attested reaped, and the staged
lease becomes active only with the backend replacement commit. Failed staging
reaps the staged child before releasing its lease, while lease-release failure
is latched as a quarantine error: later shutdown attempts cannot attest
aggregate release or reclaim capacity. Final shutdown
asks all retained nodes to reap, releases each exact generation lease, and only
then asks the aggregate launch authority to finish. A failed attestation stays
observable and transfers the remaining authority to quarantine. Construction
failure, unwind, or abandonment before those explicit finishes must perform the
same fail-closed transfer from the lease and authority drop paths. The daemon's
attempt-generation owner now enforces this join around one resource guard. It
retains at most one latest generation integer per bounded scenario node plus
at most the active lease and one staged successor per node, rejects a third,
stale, or reused identity, and releases the guard only when every exact lease
finished. Dropping a lease or requesting
aggregate finish with a live lease permanently transfers the guard to
quarantine; exact retry continues to report that terminal outcome. The packaged
non-campaign lifecycle uses the existing launcher through the default
authority and no-op generation leases. The campaign worker must still provide
the Linux attempt-owned multi-generation implementation and must not select
that default. The daemon now provides an attempt-owned lifecycle adapter for
fresh, retained exact, and local replacement generations. It admits the launch
resource profile before creating a generation directory. Fresh preparation
runs both adjacent `qemu-img` invocations under the attempt cgroup, sticky
cancellation, file ceiling, pinned directory, child credentials, parent-death
rule, and fixed absolute deadline, then synchronizes and reauthenticates their
named inodes. Retained exact preparation streams and authenticates both the
writable root overlay and VMState through descriptor-pinned linear transactions
and binds both to the complete checkpoint-manifest identity. Local replacement
resolves the supplied source path only against the retained prior-generation
capability, reflinks both writable files inside the same project quota, and
binds them to the authenticated paused replacement snapshot. Every mode then
invokes only its guarded live-node entry point. A failure with no remaining
child rolls back the pending generation fence so the exact lifecycle request
can retry. A failed synchronous reap instead transfers the direct QEMU or
image-tool child into the aggregate owner and makes that owner terminal and
quarantined. The production lifecycle now requires every injected launch
authority to admit and charge each scheduler quantum before any scheduler,
host-fault, or guest state advances, and to recheck the same authority before
returning the outcome. The campaign launcher maps those hooks to the exact
attempt-wide cancellation, host-enforcement, and execution-quanta guard; the
packaged non-campaign launcher explicitly supplies no-op hooks rather than
inheriting an optional accounting default. A modeled-quantum failure and a
racing post-quantum enforcement failure are reported together. Operational
admission and post-quantum failures carry a closed `retryable`, `canceled`, or
`terminal` class through the lifecycle and scheduler boundaries; callers MUST
NOT recover that class by parsing diagnostic text, and the post-quantum class
takes precedence when both modeled and enforcement failures occur.
The daemon's fresh campaign-lifecycle factory now rejects an exact-resume root,
validates the reconstructed scenario identity and bounded VM-node count,
installs the exact admitted resource and cancellation incarnation, and transfers
that guard into the multi-generation launcher before lifecycle construction.
A mismatched guard is released before rejection; construction failure transfers
the installed guard to quarantine. The worker's exact-origin router sends a
durable paused-root incarnation only to its resume runner and a rootless
incarnation only to its fresh runner while preserving retry, cancellation, and
terminal classification. The fresh runner gives its modeled driver only a
narrow drive-and-evidence facade: the driver cannot invoke lifecycle shutdown,
release generation leases, or access node-launch authority. It returns a
pending modeled result, then the runner performs final event drain, process
reap, generation-lease release, and aggregate guard release before supplying
the drained dense event-log suffix to result sealing. Driver failure still
runs that cleanup. A cleanup or quarantine failure takes terminal precedence
over an otherwise retryable or canceled driver result while retaining both
diagnostics. The fresh runner independently rejects any exact-resume root before
calling even an injected lifecycle factory. It also rejects a non-genesis
target before resource installation when its schedule contains a legacy
app-random value, an explorer override, or a typed selection outside the
standardized app-random model/branch contract. For every admitted discovery or
selected-branch target, the runner derives an immutable per-node replay plan
from the already repository-resolved schedule before launch. Control-protocol
v2 passes that bounded canonical plan as a sealed third `Setup` descriptor. Each
entry binds the node-local draw ordinal, canonical stream, full seeded raw draw,
selected value, and exact `SelectionId`; before any launch the lifecycle
requires the aggregate plan entries and scheduler selection set to contain the
same exact selection identities and rejects foreign or white-box-disabled nodes.
The plugin serves a substitution only
after the live ordinal, stream, and draw agree and the selected value fits the
live width. The scheduler independently keys the decoded selection by the exact
configuration after the raw `RngDraw`, reconstructs the live opportunity/domain
including the request width, and applies the origin-specific campaign replay
validator before committing it. A plugin value, stale plan, foreign parent, or
wrong selection therefore fails before the requested prefix can be accepted.
The runner starts the fresh process at scenario genesis and performs exact
prefix replay under
the attempt's cancellation and execution-quanta guard. Every newly appended
decision MUST equal the corresponding requested decision; replayed event
history is retained under the same 1,000,000-entry and 64-MiB bounds used by
result sealing. Divergence, early terminal state, cancellation, or quantum
exhaustion fails closed and still tears down the lifecycle. The runner MUST NOT
substitute seed changes or a post-hoc schedule append for a `CampaignBranch`
selection.
The daemon-packaged executor now selects the concrete fresh driver, the
version-four exact-resume driver, and one concrete packaged replay-oracle
factory per semantic worker in a fixed worker pool with a shared aggregate
resource owner and disjoint stable worker recovery roots. The exact-origin
router never sends a retained root through fresh reconstruction. An
independently admitted debugger world remains open; no unsupported mode falls
back to the packaged authority. The
concrete modeled driver accepts an already-materialized authenticated discovery
child or selected branch child and advances only empty-control scheduler quanta. It
checks cancellation and the exact-checkpoint request before and after each
quantum, preserves the scheduler's typed retry/cancel/terminal failure class,
and transfers a winning request at an exact capture-ready boundary to the
runner-owned checkpoint capability rather than constructing an observation.
An unsafe boundary continues under the sticky request until capture becomes
safe or the attempt reaches a terminal verdict. It stops on the first exact
requested choice, named guest marker, virtual-time deadline, modeled event-count
boundary, or scenario terminal verdict. A terminal verdict takes precedence
over a coincident checkpoint request, and no modeled stop is accepted while a
network output remains globally uncommitted.

Once capture owns paused nodes, the lifecycle checks the same execution
cancellation between live-node operations and between fixed one-MiB file-hash,
native-persistence, portable-validation, and campaign-CAS stream chunks. A
winning cancellation is a typed canceled disposition, not retryable storage
unavailability. It aborts unpublished preparation but MUST still delete each
owned QMP snapshot and resume each formerly running node before resource
authority can be released. A staged native closure may leave only unreachable
content-addressed objects for bounded GC; the campaign assignment root is not
published until no-write authentication completes and the exact expected root
is durably staged.

The driver retains at most 1,000,000 dense scheduler entries, at most 64 MiB of
their aggregate canonical identity material, and admits at most 1,000,000
property-by-event evaluation visits. It deduplicates at most 65,530
self-contained discovered-choice bundles by exact opportunity identity, shares
equal declaration/domain values by content identity, and enforces the candidate
format's 128 MiB aggregate unique-record bound while discoveries arrive. After
runner-owned shutdown, it appends the final dense event suffix under the same
bounds before any semantic result is built. The complete retained log is checked by the offline
assertion evaluator under the scenario's white-box and final-quiescence policy;
`Violated` and `NeverReachedFail` become failed campaign properties,
`Passed`/`Satisfied` become passed properties, and other non-failing terminal
states remain inconclusive. Any failed property takes the observation stop;
otherwise the exact requested or terminal stop is retained. Each unique basic
block or named coverage point becomes the campaign coverage identity carrying
the bytes of
`H("crucible.scheduler.event-log.coverage-observation.v1", canonical point)`;
event position and duplicate hits do not perturb the grow-only identity. The
driver reconstructs and exact-checks the scenario artifact, encodes the final
schedule as the child artifact, and binds child, path, attempt, property,
coverage, empty initial measurement set, and discoveries into one
`ObservationCandidate`. Scenario-declared measurement definitions, retained raw
event-log evidence, and objective aggregation remain the separate T-CAM-3 work;
this driver does not synthesize undeclared metrics. A concrete exact-resume
adapter obtains prepared generation directories from the guard, streams and
authenticates the durable exact-root artifacts into pinned inodes, constructs
root-bound real-node launchers, restores the complete production
scheduler/evidence continuation, and exposes only the guarded live facade to
the modeled driver. The runner rejects retained log suffixes, performs final
drain and teardown itself, and reports `ExactRestore` only after sealing. The
guarded fresh lifecycle now provides the baked-genesis bootstrap capture: at
exact scenario genesis it executes no modeled quantum, captures through the
same bounded version-four native store, tears every process down, and admits
the result only when its exact World live-node set authenticates. This
read-only capability grants neither campaign publication nor replay admission
by itself. Fresh exact-cache and packaged thin-image materialization remain
separate optimization choices from campaign semantics. A concrete node-specific
factory prepares the authenticated fat and baked artifact pairs in disjoint
pinned generations and returns the guarded real-node comparison session.
Packaged startup captures the baked source before endpoint binding, installs one
fixed promotion owner per semantic worker, and advertises exact restore only
after that nonempty owner set exists. A
process-only Linux facade
now validates a daemon-incarnation
namespace, non-root child IDs, task and finish bounds before acquiring the
delegated root;
it creates fixed-width unique child names, exposes only the sealed contract and
sticky signal, and completes or quarantines the underlying owner. A partial
setup poisons that allocator and retains authority fail-closed rather than
allowing another launch. Raw cgroup controls and quarantine implementation
remain crate-internal, and the process facade cannot be used as a complete
resource guard until the process/storage composition lands.

Every validated `QemuLaunchCommand` also exposes a stable operational resource
baseline derived from its fixed `-smp`, guest RAM, exact-VMState virtual size,
and root-overlay presence. Executor admission MUST reject before spawn when the
admitted vCPU, resident-memory, or aggregate writable-byte ceiling is below
that baseline. Guest RAM is only the minimum resident baseline; the concrete
guard MUST retain QEMU/plugin overhead within the same admitted maximum, and a
root overlay consumes only the quota remaining after the VMState minimum.

The realization executor owns one unified event log resumed from the realized
runtime offset. Replay requires the caller's runtime offset to equal that
installed offset before any backend work; the modeled driver receives only a
read-only view of the same log, and a successful candidate commits its exact
current offset. It is accepted only after a paused observation-boundary drain
appends no new event and the sealed offset equals that commitment. Shutdown
performs a final drain before its reap ladder; any event beyond the sealed
boundary invalidates the candidate while still releasing the reaped resource
guard.

Exact-checkpoint pause uses a separate executor-owned capability, never the
modeled live-backend facade. The lifecycle owner supplies a materialized
scheduler `Checkpoint`; capture first verifies that its identity and
configuration equal the installed configuration, seals the executor-owned
event log, and then requires the checkpoint's exact event-log offset and node
instruction count to match the live boundary before QEMU VMState or host-I/O
capture begins. Success leaves QEMU paused. Failure after sealing also closes
further modeled progress and retains the session for guarded reap or
quarantine. A successful capture returns authenticated `QemuVmSnapshot`
metadata, the complete `SingleSchedulerCheckpoint` from that same paused
boundary, and a reopenable, byte-stable VMState source. The compatibility
session reaps QEMU, invokes the pool-owned no-write preparation and durable-root
handoff, and returns one opaque prepared result; the supervisor continues
charging the execution reservation until durable pause. The real-node executor
now supplies the underlying ordered primitive: after
paused metadata capture it performs final drain and exact reap, rejects any
sealed event-log change, synchronizes and reauthenticates the retained VMState
inode, and yields only a bounded positional reader that survives artifact
unlink without carrying directory or mutation authority. The daemon wraps that
reader as a reopenable CAS source with an independent positional cursor per
open. The guarded live session now performs that conversion itself, records the
successful capture as the backend reap attestation, and releases only the host
resource guard during `finish`; it cannot accidentally issue a second shutdown
or hand modeled code the opaque source. That compatibility path prepares a
no-write, content-addressed version-three single-node root over canonical
snapshot metadata, the scheduler continuation, and streamed opaque VMState;
stages that exact root in the assignment ledger before the first immutable
write; publishes all three children before the root; and requires exact durable
placement receipts.

The complete production lifecycle separately exports its version-four
multi-node manifest and exact object inventory through a bounded read-only
streaming capability. The daemon's version-four exact store authenticates the
complete production continuation, maps every native object identity to a typed
CAS object through bounded 4,096-entry child-index pages, binds exact scenario,
configuration, production identity, counts, and aggregate bytes in the root,
and publishes manifest, objects, and indexes before that root. Loading yields a
lazy portable source; the production installer then runs the complete
scenario-aware semantic restore in private storage before launch. The packaged
fresh runner now honors the sticky request at a safe boundary, captures this
complete source closure, exact-checks its scenario against the admitted
lineage, prepares the version-four campaign root without campaign-CAS writes,
and uses a pool-owned callback to persist `checkpoint-publishing(root)` while
the production lifecycle is still live. Only then does it shut down the
lifecycle, return the opaque prepared token, publish children and root, and
reconcile durable pause. The handoff callback is absent from modeled input,
cannot be minted by an external model, and never releases capacity before the
runner attests teardown.

The version-four installation boundary observes the exact attempt cancellation
before and between at-most-one-MiB source reads, destination writes, semantic
validation reads, and durable publication operations. It reconstructs the
complete configuration and scheduler continuation and binds them to the
effective attempt start: the discovery configuration or a branch's validated
post-selection configuration MUST be an exact schedule prefix. A later
campaign-branch `Selection` in the restored suffix belongs to another attempt
and is rejected before the native destination closure is published. This proof
grants no QEMU process or replay-oracle authority by itself. The production
resume driver composes it with the attempt resource guard only after the same
admission proves every live snapshot carries source-bound `Match` evidence.

Production capture itself uses the lifecycle store's independent bounded
native catalog to retain a reopenable source closure. That private capture
layer may place its native objects before campaign-root staging, but it grants
no campaign-CAS reachability and remains subject to the scenario-authored
checkpoint count and byte ceilings. The assignment-ledger ordering above
governs every campaign-CAS put. After campaign-CAS publication, the packaged
owner crash-safely renames, synchronizes, removes, and synchronizes the
attempt-local catalog before the final paused-state CAS. Abort and promotion
revert retain the cleanup token until retirement completes. On restart, the
exclusive ledger owner authenticates its retained checkpoint-root inventory
before retiring stale worker and promotion namespaces. This cleanup never
permits an unstaged campaign root to become visible and never touches the
separate baked-genesis source catalog.

The version-four portable closure now supports source-bound replay-oracle
promotion without destination writes. Preparation completely reauthenticates
the raw closure, requires one check bound to every live node's exact raw
snapshot, regenerates only the corresponding `NotRun` to `Match` snapshot
objects, and derives the promoted target-manifest and closure identities from
those semantic snapshot identities. All other modeled continuation and
artifact objects are reused lazily. The daemon wraps this replacement in the
same linear `checkpoint-promoting(raw,promoted)` phase used by the compatibility
path, publishes the complete replacement only after staging both roots, and can
reauthenticate the exact complete root pair after restart before the final
paused-root CAS. A foreign source check, copied manifest identity, missing
node, changed artifact, or non-matching oracle transition fails before writes.
The production preparation boundary authenticates the raw attempt root, retains
compact live-node descriptors plus read-only capabilities for their exact
overlay and VMState manifests, and decodes one raw snapshot at a time. Each
artifact capability streams from the authenticated chunk sequence with fixed
temporary memory, offers the caller's attempt operational boundary around every
bounded I/O quantum, and rechecks exact length and content identity; it exposes
no path, mutable-store, or campaign-ref authority. The node-specific oracle owner
receives that complete target and MUST finish or quarantine each guarded
fat/thin comparison before minting the complete no-write replacement.
A fixed bounded worker set now schedules that comparison from every newly
paused execution and from the durable raw/staged inventory after restart. The
generic production adapter retains one node-specific replay factory per worker,
retries only classified availability failures, restores incomplete staged work
to its raw root, and never holds supervisor ownership across repository,
comparison, or publication work. The ordinary guarded lifecycle now constructs
the adapter's independent baked-genesis source candidate at exact scenario
genesis and admits only a complete version-four native closure with exactly the
World live-node set. Constructing the packaged node-specific materializer and
real-node replay factory over that source is now implemented: a shared compact
catalog avoids complete-closure rescans, one target snapshot is decoded at a
time, and every artifact stream observes the exact attempt guard. Packaged
startup installs one such promotion owner per semantic worker. The packaged
capability set is derived from that fixed owner set: a nonempty set advertises
`ExactRestore` and reports its installed count. Attempt and promotion native
catalog retirement uses the durable ordering above.

Concrete production-loop process reconstruction and exact-resume modeled-driver
selection are implemented: a resume-only installer rejects `NotRun` before
native publication or resource installation, the guarded lifecycle restores the
complete version-four loop, and the packaged worker routes retained roots only
to the exact-resume runner. Native-catalog cleanup uses the crash-safe
attempt-owned retirement protocol above. The packaged
executor installs the concrete replay owners during startup and advertises exact
resume only after that installation succeeds.
Version-two roots
remain readable for legacy authentication but are incomplete campaign continuations and MUST be
rejected by attempt resume before VMState materialization. The
ledger preserves requested, publishing, and paused phases across restart; the
worker result and publication APIs use linear captured, opaque-prepared,
staged, and published tokens. A campaign-CAS storage or compare-exchange error
therefore never requires rerunning QEMU or repeating a completed capture.
The campaign supervisor issues the exact checkpoint request and retains its
reservation until the executor reports durable pause. Attempt resume takes the
exact root retained in that execution's durable paused origin, authenticates
the complete immutable root, and requires its configuration to equal either
the attempt's pre-selection boundary or its post-selection boundary before any
destination write. The legacy version-three path exact-checks the scheduler
frontier, scheduler-state projection, future decision-RNG cursors, event-log
offset, and retained event-log segment set. The version-four path instead
installs and restores the complete production scheduler, trigger/assertion,
fault/network, lifecycle, overlay, VMState, generation, and service-state
closure. In either case the modeled driver receives authenticated continuation
separately from the QEMU live capability; it cannot silently restart scheduler
state from a reduced runtime projection. Exact-pin
hibernation instead loads the selected root under
the exact-pin inventory fence, releases that fence, and reauthenticates the
recorded pin fact against the current semantic projection. Both operations
use the same pinned run-directory transaction: the compatibility path streams
its single VMState child, while version four installs every target's exact
overlay and VMState artifacts from the validated production closure. A
destination becomes unlaunchable before its first truncate, accepts no more
than the declared/admitted bytes, and becomes
eligible for exact restore only after authenticated EOF, exact length, file
sync, retained-inode validation, and binding to the selected
`ExactCheckpointId` root, which covers either the legacy single-node triple or
the complete version-four production closure.
Cancellation, corruption, a short copy, or a dropped writer leaves
the authority unready; a later exact retry must replace it completely. Guarded
spawn separately requires the same launch-resource ceiling and exact snapshot
basis. The exact-root launcher is not an unguarded realization launcher: it can
enter production resume only with the attempt guard's sealed child-process
contract, and production replay admission rejects missing or mismatched oracle
evidence before invoking it. Before child launch, both the exact-target and
thin-base launchers require authenticated VMState and, when the launch profile
uses one, a writable-root overlay carrying one common artifact binding. Exact
target, thin-catalog, and in-attempt replacement bindings use distinct hash
domains, so a valid artifact pair from one role cannot satisfy another. A
merely provisioned file, mixed pair, short stream, or foreign binding remains
unlaunchable. The compatibility v2/v3 owner authenticates the
exact selected raw root, runs the fat/thin comparison, promotes only a
source-bound match into a new root that reuses the single VMState child, and
durably replaces the selection. The version-four owner applies the same
source-bound rule independently to every live-node snapshot, reuses unchanged
chunked overlay and VMState objects, and authenticates the raw/promoted closure
pair on restart. No version-four root may become resume-eligible merely
because its CAS closure is complete. The comparison session owns one
process/resource guard, uses
disjoint launch capabilities for target and thin base, reaps each generation
before replacement, and finishes before promotion writes. Any realization or
cleanup failure quarantines the guard and leaves the raw root selected. The
nondroppable child/cgroup/watcher worker now exists crate-internally, and the
exact-resume adapter transfers both failed-launch and active-node child
authority into the attempt guard before returning a failed realization. The
concrete packaged comparison factory and its full real-node flight remain
mandatory before the packaged executor may advertise exact restore and before
the full campaign/QEMU gate may claim completion.

Coverage-enabled warm restore uses the ABI-v21 logical-time restore generation
as its exact reset transaction. Before acknowledging that generation, the
paused plugin clears every per-vCPU novelty-scoreboard entry, its process-local
coverage map, and setup-era producer-ring entries. After observing the exact
acknowledgement and confirming native QEMU pause, the host requires an empty
ring and clears its consumer sequence, coordinate, and novelty state. Only then
may the restored node become authoritative. Any partial reset fails the
realization and reaps the fresh child. Coverage-aware modeled-driver execution,
projection into canonical campaign coverage evidence, and the full packaged
real-node flight remain part of the later full-flight gate. Other setup-era
observations are discarded at the same pre-authoritative boundary.
Only errors explicitly classified as store or executor unavailability are
retryable; coarse store/executor failures and invalid checkpoints, ancestry,
authorization, replay-oracle evidence, or ready-point policy fail terminally.
The retained-template audit also requires QEMU's version-1 monitor inventory to
remain identical around process capture and to contain at most 256 records. The
only supported parent profile is one stable OOB-enabled I/O-thread QMP monitor,
zero HMP monitors, zero suspended or negotiating monitors, and no queued request
or partial JSON parser state. A busy parser makes the report incomplete. This
profile is revalidated when the private child-QMP endpoint is staged, and its
exact positive lifecycle generation is bound into the sealed resource plan,
one-shot child runtime status, and authenticated private-channel query. A
changed or foreign generation fails closed. The inventory and binding remain
observational prerequisites and do not satisfy the separate child monitor
reconstruction or fork authority.
Template contract version 20, resource-stage version 10, and child-QMP version
4 additionally retain the exact admitted `MonitorQMP`, monitor `IOThread`, and
dispatcher coroutine with that generation as one QEMU-private ownership basis.
Staging revalidates the complete profile and exact objects immediately before
commit and on an idempotent restage; release clears the basis. QAPI exposes only
whether the basis is bound, never its process-private pointers. This closes an
ownership prerequisite for future monitor reconstruction but still does not
dispose or recreate a monitor, invoke `fork(2)`, release input, or acknowledge
readiness bit 7 or 8.
Template contract version 21, resource-stage version 11, and child-QMP version
5 additionally retain the exact inherited `Chardev` and require that it remain
the admitted monitor's connected GMainContext-capable frontend with backend
disconnect and add-client operations. QAPI exposes only
`monitor-disposition-bound`. This authenticates the concrete endpoint owner and
operations that a future child transition must consume; it still does not call
those operations or advance either readiness bit.
Template contract version 22, resource-stage version 12, and child-QMP version
6 additionally bind the exact supported connected Unix-socket backend:
frontend, address, channel, socket, listener, read and HUP sources,
`GMainContext`, and a positive monotonic connection generation. Staging rejects
non-Unix and non-listening endpoints, TLS, telnet, TN3270, WebSocket, reconnect
and connect-task state, queued descriptor transfers, replay mode, and
non-GMainContext dispatch. Commit and restage compare that private basis under
the chardev write lock, and disconnect or reconnect invalidates its generation.
Only `monitor-socket-resources-bound` crosses QAPI. No source is removed and no
socket, monitor, dispatcher, or private endpoint is reconstructed in this
checkpoint; `fork(2)`, input release, and readiness bits 7 and 8 remain open.

The subsequent private child transition consumes that exact held socket basis,
replaces the inherited JSON parser, and resets capability negotiation. It now
also requires the copied dispatcher to be idle, retires it by waking it once
with dispatcher shutdown asserted, waits for its normal coroutine exit, and
installs one fresh dispatcher before any replacement input is released. This
transition now also binds the exact source monitor-I/O-thread identity and
contexts, proves that copied worker is absent from the child process, refreshes
its initialization semaphore, and starts one replacement worker over the
retained quiescent contexts. At that checkpoint it does not emit the one child
greeting, release input, reconstruct the global child-thread registry, invoke
`fork(2)`, admit guest work, or acknowledge readiness bit 7 or 8.

A following pair of child-only operations now closes the greeting/input
primitive while preserving the resource-transaction boundary. The first enters
through a guarded synchronous bottom half on that exact replacement IOThread,
revalidates the complete held protocol and socket basis, and emits exactly one
QMP open event while replacement input remains held. The child runtime may then
report its complete state with both greeting-sent and input-held asserted. Only
after the complete child resource transaction commits may the owner invoke the
second operation. It flushes the greeting, returns `-EAGAIN` without mutation
while any greeting bytes remain buffered, and otherwise attaches exactly one
read and HUP source. Input therefore cannot dispatch before the greeting has
been accepted by the replacement socket. These operations remain unwired to
the fork owner. Child-QMP contract version 7 now binds the exact concrete
monitor callback and private monitor basis into the one-shot reinitializer at
staging. That callback composes held socket, protocol, dispatcher, monitor
IOThread, and greeting reconstruction, and the resource transaction no longer
accepts a substitute runtime after descriptor mutation starts. Production fork
invocation, post-commit input release, guest admission, and readiness bits 7
and 8 remain open.

An explicit QEMU-internal registry transaction now supplies the thread and
registered-`QemuMutex` part of that future fork owner. It holds both registries
across one fork, rejects in-flight QEMU thread starts and any nonquiescent
registered mutex, preserves the exact parent registry on release, and rebuilds
the immediate child's registry around only the surviving coordinator. It is a
bounded internal prerequisite, not a fork command or a complete subsystem
barrier: raw/library locks, all remaining subsystem reinitializers,
host-continuation pairing, and guest admission remain required before readiness
bit 8 can be acknowledged.

The explicit runtime transaction now composes RCU outside that registry
transaction. It closes new reader, callback, and reader-registry admission and
requires the exact coordinator reader plus callback/drain state to be quiescent
before acquiring the inner registry. Parent release preserves both exact
registries. Immediate-child reconstruction first makes the QEMU thread registry
authoritative, then drops vanished RCU readers, rebinds the coordinator reader,
resets the proven-empty callback state, reopens admission, and starts one fresh
callback worker before returning. Any pre-fork acquisition failure rolls the
outer RCU barrier back.

Template contract version 24, resource-stage version 13, and fork-result schema
version 2 expose the composed transaction through the public
`crucible-hot-fork` QMP command. Its request binds the exact fourteen template,
resource, process, runtime, descriptor, monitor, and branch-private console
generations. QEMU revalidates that basis on the source main loop, forks once,
preserves the parent template, and completes the supported descriptor, runtime,
plugin, private child-QMP, and child-console dispositions in the immediate
child. Its schema-version-2
parent response returns the positive child PID even when parent disposition
fails. Child-QMP contract version 8 acknowledges readiness only after the
resource plan, descriptor disposition, child runtime, plugin endpoints,
greeting, and replacement input are complete. Child-console contract version 1
retains an independently duplicated nonblocking Unix stream by standard-QMP
descriptor name and Linux `SO_COOKIE`; it binds the exact source console,
sealed child plan, and one-shot chardev reinitializer, and acknowledges its
disposition only after replacement input is active. The response alone never admits
the child: the executor MUST retain direct-child authority and authenticate the
private child QMP and console channels against the same generations before
treating it as live.
An explicit pre-fork QMP rejection is safe to retry on the parent connection;
any other transport or response failure is fork-indeterminate and poisons that
connection. The daemon-side process guard, resource accounting,
direct-child/quarantine lifecycle, private-channel promotion, and campaign
observation integration remain mandatory before the executor may report
`hot-fork`.

The Rust node boundary enforces that rule with a linear launch token. A caller
cannot provide a raw generation tuple to the daemon launch boundary. The node
brackets exact QMP queries for every retained child contribution with an
unchanged prepared-template report, matches them to its linear host-side ring,
endpoint, diagnostic, console, and process-contract authorities, and constructs
the request only from that authenticated basis. A successful result contains
the exact parent response, one nonduplicable
child-process authority, the single branch-private QMP endpoint, the sole
bounded diagnostic reader, and the branch-private console continuation; the
node cannot return success with only a PID. The source console reader is
duplicated into retry-safe private host state
before the QMP fork, but its original endpoint is consumed only after a known
successful ownership transfer. The returned host continuation owns the child
observation spool, and attaching it to the child node cannot expose source
console bytes. Explicit pre-fork rejection retains the
reusable source owner, while an indeterminate exchange, a failed parent
disposition, endpoint transfer failure, or process-retention failure
quarantines the source. The Linux host-resource facade now delegates child-
process retention only while it still owns both the live cgroup and aggregate
filesystem quota. The composed attempt guard carries that delegation together
with sticky cancellation and quantum accounting; the process-only owner is not
an accepted reconciliation target. The daemon reconciliation launch derives
that request internally and consumes the launch token without exposing a
PID-only success state and retains the source, complete target guard, private QMP and
console channels, exact attempt/execution basis, and semantic publication disposition
through ordered cleanup. It lends modeled execution only the child QMP channel
and a non-releasing operational boundary, so modeled code cannot finish the
guard early. The worker-pool post-execution contract now carries that exact
basis and durable disposition through bounded cleanup before worker reuse.
Concrete hot-fork runner construction, complete private-channel driving, and
modeled candidate production remain open.

The source QEMU now reserves the request's unique nonzero child-process
generation in a fixed 4,096-record table before forking. The version-1
`crucible-hot-fork-child-process(query|release, generation)` protocol binds that
generation to the exact positive child PID and reports `running`, normal exit
plus its `u8` code, or signal termination plus its nonzero `u8` signal. Each
operation performs at most one nonblocking `waitpid(pid, WNOHANG)` while the
record is running. Final status remains retained and immune to PID reuse until
explicit release; release fails while running. No ambient child watcher is
installed or inherited across subsequent forks.

The daemon MUST pair that parent-owned record with exact child-generation
cgroup/pidfd retention before admitting the child, use the independent process
authority to observe or terminate it, and query the source QEMU until final
wait status is retained. Only after branch reconciliation may it release the
reaped record. Branch-resource transfer and this daemon composition remain
required. A daemon MUST NOT synthesize a direct-child wait handle from the
numeric PID.

The driver owns selection application, stop-boundary execution, and candidate
construction but never assignment or daemon-epoch identity. This adapter
cannot report `hot-fork` until it is composed with the QEMU-owned protocol and
the daemon-side lifecycle obligations above and their conformance gates pass.

- **[CCOMP-20]** Capability reports MUST distinguish immutable compatibility
  facts from volatile capacity and locality hints, and consumers MUST treat
  stale hints as rejection/retry rather than semantic failure.
- **[CCOMP-21]** Materialization and store locality MAY affect where and how an
  attempt runs but MUST NOT affect which value the campaign proposes.

## 04a.8 Recovery and conformance

After restart, the coordinator reconstructs claimable work as admitted attempts
without canonical observations or explicit non-modeled terminal dispositions.
The executor discards stale process handles,
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
