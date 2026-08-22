# 04a — Component contracts and local executor boundary

RFC-0016 implements one single-host campaign coordinator and one local Crucible
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
GetSnapshot           QueryGraph           GetGraphObject
QueryFrontier          GetFrontierObject    QueryChoices
GetChoiceObject        PinCampaign
SubmitBranchRequest    DeriveCampaign       QueryFindings
ExplainObject          ExplainAttempt       WatchCampaign
```

Every operator-command mutation of an existing campaign carries an idempotent
command ID and its expected snapshot ID. An exhaustive-policy branch instead
uses its exact content-addressed request as the idempotency boundary. Creation
uses the canonical campaign name as its idempotency boundary and carries
expected name absence.
Repeated `WatchCampaign` calls form a resumable coalesced watch; the campaign
ref and immutable objects remain authoritative. A stale or lost watch cursor
therefore cannot lose campaign state.

The strict service checkpoint defines principal-aware `CreateCampaign`,
`DeriveCampaign`, `GetCampaign`, `GetSnapshot`, `WatchCampaign`,
`ApplyCampaignCommand`, `QueryGraph`, `GetGraphObject`, and
`QueryChoices`, `QueryFrontier`, `QueryFindings`, `GetFindingObject`,
`ExplainAttempt`, `GetFrontierObject`, `GetChoiceObject`, `PinCampaign`, and
`SubmitBranchRequest` messages. All use
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
ExplainCampaignAttemptResponseV1 = version | request_digest |
                                   CampaignSnapshotV2 | AttemptV1 |
                                   AttemptAdmissionV1 | BranchPathV2 |
                                   optional SelectionV2 | optional ProposalV1 |
                                   optional ObservationV1 |
                                   MerkleLookupProofV1 attempt_proof |
                                   MerkleLookupProofV1 admission_proof |
                                   optional MerkleLookupProofV1 proposal_proof |
                                   MerkleLookupProofV1 observation_proof

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
                                      BranchRequestV1 |
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
                                expected_snapshot | BranchRequestV1
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
`GetChoiceObject`
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
generators. The campaign name is the creation idempotency boundary, and the
complete canonical request binds the individual response digest. An idempotent
retry is recognized when the authenticated named campaign's retained genesis
has the same lineage and policy, even after later mutations, and returns the
original genesis snapshot. A different lineage or policy under an existing name
returns `AlreadyExists`.

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
authenticated projection and returns the strict `BranchRequestV1` body. The
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
admission ordinal, branch selection and proposal, and optional completion.
Arbitrary non-graph object reads and aggregate proposal-ranking views remain
open. The strict local transport frames exactly one
canonical request or response as:

```text
CampaignLoopbackFrameV16 = "CRUCCS16" | kind:u8 | reserved[3] |
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
      35 (ExplainCampaignAttemptResponseV1)
```

Loopback frame versions 1 through 15 are rejected rather than reinterpreted
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
`get-campaign-graph-object`,
`query-campaign-choices`, `query-campaign-frontier`,
`get-campaign-frontier-object`, `get-campaign-choice-object`,
`apply-campaign-command`, `pin-campaign`, and `submit-branch-request`.

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
The state root retains a stable owner-only exclusive lock across the complete
listener lifetime, creates or validates private `objects/` and `refs/`
subdirectories, and rejects a second cooperating daemon even if it names a
different socket. Its directory identity is rechecked before the path-backed
stores become reachable. `crucible serve` enables this composition only when
`--campaign-socket`, `--campaign-state`, and `--campaign-policy` are supplied
together; `--campaign-socket-mode` is octal and defaults to `600`. SIGINT,
SIGTERM, lifecycle-server failure, or CampaignService failure shuts down both
services and joins the campaign workers before releasing either lock.
`--read-only` also wraps the campaign authorizer and denies Create, Derive,
ApplyCommand, Pin, and SubmitBranch even if the policy file grants them.

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
envelope authenticated by the expected snapshot's nested frontier index. The
least Ready position on the page has exactly one `ProposalV1` candidate-offer
envelope; every other position has none. The offer names the served request, branch point, domain,
active policy, exact invocation, input view, and next one-based ordinal, and
contains the owner-computed next legal value. Extra, missing, duplicate,
cross-invocation, or non-Ready offers fail closed. The coordinator recomputes
the projection and offer from the expected snapshot before acceptance. Offer
envelopes need not exist before evaluation; after complete read-only output
preflight, acceptance publishes them as retained-request children before
publishing the request. Rejection therefore remains zero-write, while accepted
requests remain closure-complete and restart-auditable.

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
disposition. Exact fixed-point PUCT term arithmetic is implemented as a pure
bounded primitive. Owner-built reward/novelty/finding projections and the
planner version that uses those terms for ranking remain an implementation-plan
gate.

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
`checkpoint-publishing(root)` before the first immutable write. It transitions
to `paused(root)` only after the complete root closure has durable placement;
only then may it release the process-local execution reservation. A retry
returns the exact durable phase and root. A different root for the same
execution is a stable conflict and MUST NOT replace the staged root.

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
ExecutorLoopbackFrameV4 = magic[8] | kind:u8 | reserved[3] |
                          body_length:u32be | canonical_body[body_length]

kind = submit-attempt-request(1) | submit-attempt-response(2) |
       describe-executor-request(3) | executor-description(4) |
       watch-capacity-request(5) | capacity-report(6) |
       get-attempt-execution-request(7) | get-attempt-execution-response(8) |
       cancel-attempt-execution-request(9) |
       cancel-attempt-execution-response(10) |
       checkpoint-attempt-execution-request(11) |
       checkpoint-attempt-execution-response(12)
magic = "CRUCEX04"
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

AttemptStateRecordV3 = magic | lineage_id | attempt_id |
                       execution_basis_digest |
                       (running | observation-publishing |
                        checkpoint-requested | checkpoint-publishing | paused |
                        completed | canceled) |
                       daemon_epoch | execution_id |
                       observation_id? | exact_checkpoint_id? |
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

`checkpoint-publishing` and `paused` records are durable GC roots for their
exact checkpoint IDs. Restart replaces a stale checkpoint-requested execution
with a new-epoch recovery execution and keeps the checkpoint request signal
sticky. It likewise preserves the exact expected root while recovering stale
checkpoint publication; a regenerated candidate MUST have that ID and cannot
silently substitute a different checkpoint. An already-paused exact basis is
replayed without starting guest work. The executor never releases the active
reservation merely because capture was requested or a root was staged.

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
For an accepted semantic `Exact` pin, the local executor/maintenance owner
separately selects one authenticated `ExactCheckpointId` whose modeled
configuration equals the pin target. That operational selection is bound to the
latest accepted pin fact and enters GC only while that fact remains the current
exact projection. It does not enter campaign semantic identity or grant the
executor campaign-ref authority. RFC 06 defines the journal, bounds, and
plan/apply fences.

The repository executor handoff is deliberately phased. First it validates the
complete in-memory child-configuration, measurement, property, coverage,
newly-discovered opportunity-body, and observation bundle plus every
already-published dependency. An invalid bundle writes nothing. After the
durable publishing root exists, it publishes immutable content-addressed
objects without advancing a campaign ref. Only the coordinator may subsequently
incorporate the authenticated observation through the snapshot owner
transaction. Partial immutable writes remain recoverable under the publishing
root and cannot create campaign meaning.

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
not grant a non-cooperating writer access to that same namespace. Once a child
directory exists, every setup error retains its pinned cleanup authority, and a
failed release returns that authority instead of dropping it. The authority
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
inode, and treats the original path as diagnostic only. The authority stores
that resource basis;
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
accepts only a direct child, watcher, and configured cgroup carrying the same
watcher-lifecycle token. It makes sticky cancellation visible, repeatedly kills
the group, synchronously reaps the nonduplicable direct child, joins the
watcher, and removes the authenticated empty cgroup. Ordinary host failures
retry at the fixed kill cadence. An invariant panic is caught once and parks
with every remaining authority retained; dropping the observation handle does
not stop cleanup. A startup error returns every untransferred authority, and an
ignored error deliberately leaks them rather than invoking bounded destructor
cleanup.

This authority is not yet the production guard. The guarded launch/session
path now transfers a retained pre-install child into the abstract attempt
guard, but the concrete guard must still compose that handoff and active-node
failure handoff into the nondroppable cgroup owner. Aggregate filesystem quota,
concrete guard composition of the execution-quantum counter, exclusive
run-directory namespace ownership through QEMU artifact open, and that final
session wiring remain mandatory before the guarded path may launch a campaign
QEMU. Until then the cgroup and quarantine authorities remain crate-internal.

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
metadata plus a reopenable, byte-stable VMState source. The session reaps QEMU
before handing that linear capture to the worker pool; the supervisor continues
charging the execution reservation until durable pause. The daemon then
prepares a no-write, content-addressed root over canonical snapshot metadata and
the streamed opaque VMState child, stages that exact root in the assignment
ledger before the first immutable write, publishes both children before the
root, and requires exact durable placement receipts. The
ledger preserves requested, publishing, and paused phases across restart; the
worker result and publication APIs use linear captured, prepared, staged, and
published tokens, so a storage or compare-exchange error never requires
rerunning QEMU or repeating a completed capture.
The campaign supervisor issues the exact checkpoint request and retains its
reservation until the executor reports durable pause. On resume, the daemon
loads the selected exact-checkpoint root under the exact-pin inventory fence,
releases that fence, reauthenticates the recorded pin fact against the current
semantic projection, and streams the VMState child through a pinned
run-directory transaction. The destination becomes unlaunchable before its
first truncate, accepts no more than the declared/admitted bytes, and becomes
eligible for exact restore only after authenticated EOF, exact length, file
sync, retained-inode validation, and binding to the aggregate snapshot
metadata plus VMState child through the selected `ExactCheckpointId` root.
Cancellation, corruption, a short copy, or a dropped writer leaves
the authority unready; a later exact retry must replace it completely. Guarded
spawn separately requires the same launch-resource ceiling and exact snapshot
basis. The exact-root launcher is not an unguarded realization launcher: it can
enter production resume only with the attempt guard's sealed child-process
contract, and production replay admission rejects missing or mismatched oracle
evidence before invoking it. The durable owner now authenticates the exact
selected raw root, runs the fat/thin comparison, promotes only a source-bound
match into a new root that reuses the VMState child, and durably replaces the
selection. The comparison session owns one process/resource guard, uses
disjoint launch capabilities for target and thin base, reaps each generation
before replacement, and finishes before promotion writes. Any realization or
cleanup failure quarantines the guard and leaves the raw root selected. The
nondroppable child/cgroup/watcher worker now exists crate-internally; concrete
failed-launch/active-node handoff into it and the complete pause/restart/resume
flight remain mandatory before the full campaign/QEMU gate may claim
completion.

Coverage-enabled warm restore remains fail-closed in this implementation slice.
Boot-barrier priming occurs before `loadvm`, while the current QEMU plugin emits
each coverage-map index at most once for the process. Draining priming events
would both contaminate the resumed log and permanently hide later post-restore
coverage. A conforming coverage-enabled implementation therefore MUST reset the
producer novelty bitmap, producer ring, and host consumer state together at an
authenticated paused restore generation before installing the authoritative
event log. That versioned QEMU/shared-memory reset transaction, coverage-aware
live advancement, and projection into canonical campaign coverage evidence
remain part of the modeled-driver/full-flight gate. Coverage-free realization
discards other setup-era observations before authoritative installation.
Only errors explicitly classified as store or executor unavailability are
retryable; coarse store/executor failures and invalid checkpoints, ancestry,
authorization, replay-oracle evidence, or ready-point policy fail terminally.
The driver owns selection application, stop-boundary execution, and candidate
construction but never assignment or daemon-epoch identity. This adapter cannot
report `hot-fork`; only the future QEMU-owned fork protocol may do so after its
conformance gates pass.

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
