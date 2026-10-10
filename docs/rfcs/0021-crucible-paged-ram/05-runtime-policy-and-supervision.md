# Runtime policy, admission, and supervision

This chapter specifies operational control of guest-RAM residency and the host
latency budgets needed to execute, fingerprint, checkpoint, and transfer a VM
under that control. The capitalized requirement words have the meanings defined
in this RFC's [goals and invariants](00-goals-and-invariants.md). Every schema and
configuration example below is **proposed**; none describes a currently available
CLI or a shipped configuration surface.

The policy changes where the host preserves guest bytes and how long it waits
for host operations, while preserving guest capacity and memory semantics.
For deterministic QEMU-SIM and qualified deterministic gem5 profiles it leaves
virtual clocks, instruction/service accounting, event ordering, and canonical
results unchanged. The declared nondeterministic KVM profile instead obeys
[chapter 14.5](14-implementation-profiles.md#145-proposed-nondeterministic-quantized-kvm-profile):
clock holds, remaining execution budget, input custody, and window closure are
explicit, without promising repeatable hardware interleavings. Insufficient
resources or expired host budgets remain operational failures in every profile.

## Identity and policy ownership

**[POLICY-1]** Host RAM policy MUST be an operational object separate from the
immutable authored `CampaignPolicy`, scenario definition, execution
configuration, and guest RAM identities. Its values, revisions, application
times, host measurements, and update history MUST NOT be inputs to canonical
RAM identity, authored guest events, modeled deadlines, or checkpoint semantic
identity. For deterministic modes they MUST NOT affect canonical event ordering
or execution fingerprints. KVM policy changes MUST preserve PROFILE-5 and
PROFILE-6's admitted clock, budget, and publication contract; this separation
MUST NOT be described as deterministic hardware execution. Authenticating an
operational control request does not make its fields modeled state.

The logical format defined in
[logical RAM and the Merkle format](02-logical-ram-and-merkle-format.md) uses
BLAKE3-256 `PageDigest`, `RegionTreeDigest`, and `RamRootDigest` identities. They
describe page bytes, positioned region trees, and the complete logical RAM
roster, respectively. `PolicyRevision`, `ReservationRevision`, daemon epochs,
process generations, and backing-file generations are operational identities;
none is a RAM hash input. A status response can report both kinds of identity
without deriving one from the other.

The existing assignment request already binds admitted resource ceilings into
its request and assignment identities. This RFC does not authorize rewriting a
stored request to disguise a resource change. The live policy normally operates
inside those ceilings. A requested ceiling increase requires a separate
authenticated reservation amendment, described below, while the original
assignment request remains immutable.

**[POLICY-2]** Authority MUST distinguish executor-wide defaults, retained-template
policy, per-attempt aggregate containment, and per-node policy. An update to a
default MUST NOT silently affect existing nodes. An update to a template MUST NOT
silently change a child's private residency target. A campaign-wide convenience
operation MUST expand to explicit generation-bound updates and report their
individual dispositions; it MUST NOT claim atomic application across machines.

The executor owns admission and emergency containment. The QEMU-side RAM manager
owns residency transitions for a node's arena. The template owner owns shared
immutable pages and their backing lifetime. A child owns its private changes.
The host coordinates these authorities through the versioned process protocols;
it never follows a QEMU pointer or links QEMU structures into Apache host code.

## Policy modes and achievable targets

**[POLICY-3]** A policy MUST distinguish a desired resident target from a guaranteed
resident mode. An executor MUST reject an unsupported guarantee rather than
silently implement it as advisory reclaim. All modes MUST retain the complete
guest address space and preserve every logical byte independently of residency.

The proposed modes are:

| Mode | Behavior | Admission and completion condition |
| --- | --- | --- |
| `managed` | Maintain a best-effort page cache around the requested target | Reserve its allowed peak and compulsory working set; report convergence separately |
| `disk-oriented` | Give every preserved page disk backing and minimize avoidable residency | Reserve backing, metadata, emergency fault buffers, and unavoidable process memory |
| `resident-required` | Keep all logical guest RAM resident after activation | Reserve full RAM, prefault it, and successfully establish the advertised residency-lock capability |

`disk-oriented` does not promise zero physical memory. CPU and device accesses,
dirty writeback, hashing, mapping metadata, and the pager need physical pages.
The manager computes an effective floor and reports its reasons. A target of
zero expresses a desire to evict everything safely evictable, not permission to
discard data or make the pager unable to service the next fault.

`resident-required` is stronger than permitting RAM-sized RSS. Prefaulting alone
does not prevent later host reclamation. A backend advertising this mode must
identify its locking mechanism, kernel and privilege constraints, and complete
reserved accounting. Failure to lock all required pages leaves the transition
uncompleted and reports an operational refusal. An operator can instead choose
`managed` with a full-RAM target when a strict guarantee is unnecessary.

**[POLICY-12]** A `resident-required` child MUST receive its own admitted peak,
prefault, and residency-lock establishment before that mode becomes active. Linux
memory locks are not inherited across `fork`; a parent's successful activation
MUST NOT be accepted as proof of the child's guarantee. Private copy-on-write
growth MUST remain covered by the child's reserved and locked allocation policy.
Failure to establish the child's guarantee MUST produce an operational refusal
or cleanup of the staged child, never an unannounced downgrade to `managed`.

**[POLICY-4]** Policy validation MUST reject a target above logical RAM capacity,
invalid ranges, overflow, unsupported backend behavior, and insufficient backing
or resident admission. It MUST enforce the compulsory manager working set before
applying any reduction. Lowering backing capacity below live preserved contents
MUST NOT delete those contents or convert cold RAM to zero pages.

The proposed host-local TOML projection is illustrative:

```toml
# Proposed operational configuration; not current Crucible CLI syntax.
[host_ram]
mode = "managed"
resident_target_bytes = 268435456
eviction_preference = 80           # Integer 0..100; backend policy, not vm.swappiness.
writeback_bytes_per_second = 67108864
maximum_paging_io_in_flight = 16
prefetch = "none"                 # none or bounded-on-increase

[host_ram.latency.quantum]
poll_interval_ms = 50
progress_timeout_ms = 120000
total_timeout_ms = 600000

[host_ram.latency.checkpoint_capture]
poll_interval_ms = 50
progress_timeout_ms = 120000
total_timeout_ms = 1800000
```

The eviction preference selects the manager's treatment of cold pages and
background reclaim; it is not a host-global sysctl. Its endpoints do not imply
that active pages can never be evicted or that memory limits stop applying.
Background writeback and prefetch are bounded to avoid turning a resource update
into an uncontrolled campaign-wide I/O burst.

**[POLICY-5]** A higher target MUST permit an already running node to use its newly
admitted working set without reboot or guest cooperation. Prefetch, when enabled,
MUST remain bounded and cancellable. A lower target MUST initiate safe background
writeback and eviction without altering guest bytes. Transition completion MUST
be observed, not inferred from successful acceptance of a control request.

## Proposed control and status schemas

The proposed schema below defines required semantic fields. The final codec must
use bounded, canonical, language-neutral encodings with explicit tags, integer
widths, and lengths; the compact notation does not authorize Rust-native layout.
Durations are unsigned host monotonic allowances. `OptionalDuration` has explicit
`Absent` and `Milliseconds(u64)` alternatives; configured present allowances
must be nonzero, while observed remaining time may be zero after expiry.
Policies contain a fixed roster of operation classes, not arbitrary names.
Integers use big-endian encoding; enum tags are one byte. Strings use a `u32`
byte length followed by UTF-8, and fixed identifiers use their declared canonical
widths. The enclosing message begins with a `u32` schema version and has a
4-KiB maximum canonical size. Principal and node names use the existing bounded
name contracts. Unknown tags, unsupported versions, overflowing durations,
trailing bytes, and noncanonical encodings are rejected before mutation.

```text
HostRamPolicyV1 = {
  mode: Managed | DiskOriented | ResidentRequired,
  resident_target_bytes: u64,
  eviction_preference: u8,                 // 0..100
  writeback_bytes_per_second: u64,         // nonzero
  maximum_paging_io_in_flight: u32,         // nonzero
  prefetch: None | BoundedOnIncrease,
  latency: FixedOperationBudgetRosterV1
}

NodePolicyTargetV1 = {
  daemon_epoch: DaemonEpoch,
  execution: ExecutionId,
  node: NodeId,
  node_generation: u64,
  ram_arena_generation: u64
}

TemplatePolicyTargetV1 = {
  daemon_epoch: DaemonEpoch,
  template: RetainedTemplateIdentity,
  template_owner_generation: u64,
  ram_arena_generation: u64
}

RamPolicyTargetV1 = Node(NodePolicyTargetV1) |
                    RetainedTemplate(TemplatePolicyTargetV1)

PolicyControlAdmissionLimitsV1 = {
  maximum_unique_updates_per_target: u64,
  maximum_history_disk_bytes_per_target: u64,
  maximum_history_disk_bytes_per_executor: u64,
  maximum_index_cache_bytes_per_executor: u64,
  maximum_requests_per_second_per_principal: u32,
  maximum_request_burst_per_principal: u32
}

UpdateHostRamPolicyRequestV1 = {
  principal: OperationalPrincipal,
  target: RamPolicyTargetV1,
  expected_policy_revision: u64,
  idempotency_key: bytes[32],
  policy: HostRamPolicyV1,
  reservation_amendment: None | ReservationAmendmentV1
}

UpdateHostRamPolicyResponseV1 = {
  request_digest: bytes[32],
  target: RamPolicyTargetV1,
  disposition: Accepted | Replayed | RevisionConflict |
               NotCurrent | Unsupported | AdmissionRefused |
               HistoryCapacityRefused | RateLimited | Unavailable,
  policy_revision: u64,
  reservation_revision: u64,
  transition: None | TransitionId,
  accepted_policy: None | HostRamPolicyV1
}

HostRamStatusV1 = {
  target: RamPolicyTargetV1,
  observation_sequence: u64,
  policy_revision: u64,
  reservation_revision: u64,
  requested_policy: HostRamPolicyV1,
  applied_policy: HostRamPolicyV1,
  effective_resident_target_bytes: u64,
  effective_floor_bytes: u64,
  limitation_reasons: BoundedReasonSet,
  private_resident_bytes: u64,
  shared_resident_bytes_observed: u64,
  preserved_backing_bytes: u64,
  private_dirty_bytes: u64,
  writeback_pending_bytes: u64,
  convergence: Stable | Applying | Evicting | Prefetching |
               Blocked | Failed | Quarantined,
  accepted_unique_update_count: u64,
  remaining_unique_update_capacity: u64,
  history_disk_bytes: u64,
  transition: None | TransitionId,
  outer_caps: BoundedOuterCapStatusList,
  outstanding_operations: BoundedOperationStatusList
}
```

`shared_resident_bytes_observed` is an observation, not an independent reservation
charged once per child. Shared ownership accounting is reported separately at
the template/executor scope. Counts of bytes are page-accounting measurements;
they must identify whether they include partial pages, metadata, or file cache.
For a template target, private fields describe the template owner's arena rather
than a child's changes. The template identity selects an already authenticated
retained source; naming it does not permit modifying its logical contents.

`ExecutionId` already identifies a local execution incarnation in
[the execution contract](../../../crates/crucible-campaign/src/execution.rs).
`node_generation` MUST identify the authenticated process/runtime incarnation
within that execution and MUST advance on restart or replacement without reuse.
It is not a semantic node identifier. `ram_arena_generation` independently
rejects operations against a replaced mapping/topology owner. Exhausted
generation counters MUST refuse replacement rather than wrap to an old target.

**[POLICY-6]** Requests MUST authenticate the operator, exact target and expected
revision before application. Responses MUST bind the entire accepted request
using a domain-separated operational request digest. Reusing an idempotency key
with different canonical bytes MUST be rejected. Replaying the same accepted
request MUST return its original acceptance and revision, not create another
transition. Idempotency records MUST be scoped to the target incarnation and
retained for its complete authority lifetime.

**[POLICY-11]** Idempotency records MUST use a bounded disk-backed index and
history with an explicitly admitted bounded memory cache. Executors MUST enforce
nonzero per-target accepted-update counts, per-target and aggregate history disk
quotas, and authenticated request-rate and burst bounds. Admission MUST reserve
space for the request, response, journal records, index growth, and reconciliation
before accepting a unique update. Exhaustion MUST return `HistoryCapacityRefused`
before policy mutation; rate exhaustion MUST return `RateLimited`. Existing keys
MUST NOT be silently forgotten, evicted from durable history, or reinterpreted as
new updates to make capacity available.

The proposed `PolicyControlAdmissionLimitsV1` belongs to executor operational
administration, not guest policy; callers cannot raise these bounds through an
ordinary node update. Cache eviction is permitted because the authenticated
disk-backed index remains authoritative. A known-key replay can still succeed
after unique-update capacity is exhausted, subject to request-rate admission.
History capacity refusals do not consume a unique-update slot or change the
policy revision. A target's history may be retired only after its authority
lifetime ends and stale requests can no longer select it. Status exposes consumed
and remaining history capacity so long-running campaigns can plan update rates.

After authorization and current-incarnation checks, idempotency lookup precedes
the expected-revision comparison. This lets a lost-response retry recover its
original acceptance even when later updates advanced the revision. The response
contains the originally accepted revision; clients obtain current convergence
through a separate status observation. New requests still require the current
expected revision.

**[POLICY-7]** Policy revisions MUST advance monotonically without wraparound.
Node, arena, execution, or daemon generation mismatches MUST return `NotCurrent`;
a current target with a different expected policy revision MUST return
`RevisionConflict`. Failure to authenticate ownership MUST fail closed. Updating
a retired child MUST never affect its replacement, even when a node name or
filesystem path has been reused.

A target-specific successor update may supersede the previous desired target
while physical convergence is in progress. Its revision is distinct, and status
must report the superseded transition. Existing writes are drained or reconciled
against page-content generations before their buffers are released. Cancellation
of a transition is not cancellation of data preservation.

**[POLICY-8]** Status MUST distinguish requested policy, applied policy, effective
target, current measured residency, and convergence. It MUST report a coherent
policy and ownership revision, or explicitly return unavailable. Acceptance means
the authorized target has been committed; it MUST NOT be presented as proof that
all pages have moved or that a strict resident guarantee has activated.

The status producer takes short ownership snapshots and validates their revisions
around measurements. It does not scan all RAM or wait for a quantum to finish.
Pressure, fault, I/O, and latency metrics remain operational evidence with bounded
cardinality and retention. They cannot influence semantic fingerprints or make a
campaign finding.

## Admission and reservation amendment

**[RESOURCE-1]** Admission MUST reserve guest-page residency, compulsory QEMU and
plugin memory, pager fault buffers, Merkle and dirty-tracking metadata, transient
hash/checkpoint/transfer buffers, and relevant file cache. Disk admission MUST
cover complete preserved backing entitlement, private child changes, checkpoints,
overlays, and publication staging. CPU, descriptors, tasks, storage I/O slots, and
writeback/prefetch limits MUST be admitted independently of resident bytes.

A small current working set does not justify omitting backing entitlement for
future dirty pages. Content deduplication can reduce actual storage use, but it
does not establish that the guest will never write unique data. Metadata and
manager buffers must remain serviceable under the smallest supported target.
Storage capacity and storage throughput are separate resources: enough free bytes
do not prove adequate latency or fault-service capacity.

**[RESOURCE-7]** The initial pager that removes mappings only at a coherent paused
boundary MUST reserve the worst-case resident peak between such boundaries. In
the absence of an enforceable access bound, that reservation MUST cover full guest
RAM and other admitted working memory. An individual fault MUST NOT wait for the
next guest boundary to free space when servicing that fault is itself required
to reach the boundary. Insufficient fault-safe admission MUST produce a typed
host resource failure before unsafe allocation or deadlock.

The boundary-only backend can reduce paused residency and measured average usage,
but does not establish an arbitrary guest's bounded low execution peak. A guest
can touch all RAM during one uninterrupted interval. Reusing its resident target
as a hard peak would make the last fault wait for a boundary the blocked guest
can never reach. Claiming a smaller bound requires a qualified backend with
fault-safe resource suspension or concurrent removal that has proved its
coordination with all CPU and device users. Merely adding a pager thread does
not supply that proof. Until that capability is qualified, the executor MUST
advertise the initial peak limitation and refuse an incompatible low-peak mode
rather than over-admit campaigns.

**[RESOURCE-2]** Shared templates MUST have an explicit owner for both resident
pages and backing objects. The executor MUST count shared physical allocations
once in aggregate while reserving each child's independently reachable private
growth. A template or child lease MUST retain its share of authority until the
last required reference is released or transferred to quarantine.

Linux charges an instantiated shared page to its originating cgroup; migrating a
child does not move that charge. Parent and child memory controls therefore
cannot be treated as complete logical RAM accounting. A per-node manager enforces
the guest-page target, while an attempt cgroup enforces the aggregate emergency
ceiling. The retained source has separate containment and shared ownership. A
template reduction cannot reclaim a page in a way that invalidates a child
mapping or its immutable snapshot.

**[RESOURCE-3]** A reservation amendment MUST bind its prior reservation revision,
requested resource vector, execution incarnation, and policy update. The
supervisor MUST reserve increases before making them available to the manager,
and MUST release reductions only after authenticated convergence and ownership
reconciliation. Immutable submitted resource ceilings and authored campaign
policy MUST remain unchanged.

The proposed amendment vector includes resident peak, preserved backing peak,
metadata and staging allowances, paging I/O concurrency, and applicable CPU/task
allowances. Its exact codec is part of the coordinated resource-contract cutover.
A policy update inside an existing reservation needs no amendment. An amendment
cannot enlarge executor capacity; it competes with other attempts using the
ordinary admitted capacity owner.

The transaction is deliberately longer lived than one control exchange:

1. Validate credentials, generations, expected revisions, backend capabilities,
   and the request's canonical identity.
2. Compute peak transition requirements, including simultaneous old backing and
   new backing or temporarily locked resident pages. Reserve that peak under the
   executor actor, then durably record the accepted transition intent.
3. Publish the new policy revision to the exact host owner and manager. Install
   required containment headroom before increasing memory or I/O use. Perform
   physical transitions outside the actor and allocator mutexes.
4. Collect generation-bound application acknowledgements and observed convergence.
   Retain old and new reservation obligations until each released resource is
   demonstrably unreachable or safely preserved elsewhere.
5. Record final effective policy and reservation ownership; release surplus
   capacity and advance the advertised capacity sequence.

**[RESOURCE-4]** Any application ambiguity MUST retain the maximum outstanding
reservation and reconciliation authority. A failure before application MAY roll
back a newly reserved increase only after proving no manager acquired it. A
failure after application MUST reconcile actual ownership, revert safely with a
new acknowledged transition, or quarantine the owner. A lost response MUST NOT
cause a repeated request to allocate another reservation.

Transitions can fail because of disk exhaustion, unsupported locking, host
pressure, I/O errors, or process termination. These are operational dispositions.
They do not invalidate a previously authenticated RAM root solely because a
target was unreachable. They also do not authorize continuing after actual RAM
preservation has become uncertain.

**[RESOURCE-5]** Restart recovery MUST authenticate outstanding processes,
templates, backing objects, journals, and reservations before admitting new work.
A new daemon epoch MUST reject control messages for the previous epoch. Persisted
host policy MAY supply a desired policy for a recovered or resumed owner, but
application requires fresh admission and acknowledgement; a checkpoint's logical
RAM root MUST NOT imply host resources were retained.

Operational transition journals contain request identities, old/new revisions,
reservation deltas, owner generations, and acknowledgement phases. They belong
outside semantic campaign records. Recovery does not reset reservations merely
because the daemon's in-memory map is empty. Unauthenticated leftovers close
admission for the affected capacity and move to explicit reconciliation.

**[RESOURCE-6]** Capacity advertisements MUST reflect reservations and outstanding
transition peaks rather than instantaneous RSS. Paging capability and backing
capacity MUST be advertised distinctly from available execution slots. Worker
count, vCPU/task limits, and the existing maximum worker bound remain separate
constraints; reducing RAM residency MUST NOT bypass them.

## Granular host latency budgets

**[TIME-1]** All host deadlines MUST remain operational monotonic allowances. They
MUST NOT advance guest time, alter modeled operation latency, truncate a virtual
event budget, or produce a guest timeout. Expiration MUST be classified as host
infrastructure failure with operation and policy provenance.

The proposed budget tuple is:

```text
OperationBudgetV1 = {
  poll_interval_ms: u64,              // nonzero; responsiveness only
  progress_timeout_ms: OptionalDuration,
  total_timeout_ms: OptionalDuration
}

OperationStatusV1 = {
  operation_id: OperationId,
  operation_class: FixedOperationClass,
  started_policy_revision: u64,
  applied_policy_revision: u64,
  completed_work_units: u64,
  outstanding_work_units: u64,
  progress_kind: FixedProgressKind,
  state: Running | WaitingForBacking | Canceling | Completed | Failed,
  effective_deadline: None | EffectiveDeadlineStatusV1
}

EffectiveDeadlineStatusV1 = {
  remaining_ms: u64,                 // zero if elapsed; original clocks retained
  limiting_sources: BoundedDeadlineSourceList
}

DeadlineSourceV1 = ClassProgress(policy_revision: u64) |
                   ClassTotal(policy_revision: u64) |
                   Outer(cap_id: bytes[32], cap_revision: u64)

OuterCapStatusV1 = {
  target: OuterCapTargetV1,
  cap_class: Assignment | Preparation | ServiceShutdown | Operator,
  cap_revision: u64,
  allowance: OptionalDuration,
  remaining_ms: OptionalRemainingTimeV1,
  state: Armed | Expired | Canceled | Completed
}

OptionalRemainingTimeV1 = Absent | Milliseconds(u64)
```

The fixed budget roster follows the operation-class order in the table below,
with separate entries for fingerprint initialization and update, checkpoint
capture and publication, and transfer and preparation. It cannot omit an entry
or supply duplicate classes. Optional budgets encode `Absent` as tag zero and a
present `u64` allowance as tag one. Status lists carry bounded `u32` counts and
MUST reject allocation requests beyond their schema ceilings. Invalid or
unrepresentable host durations are refused rather than saturated into accidental
infinite waits.

`remaining_ms` in `OuterCapStatusV1` uses a distinct status type: `Absent`
means no deadline and `Milliseconds(0)` means elapsed. The nonzero rule applies
to configured allowances, not observed remaining time. Its tags are zero and
one, respectively, with the same big-endian `u64` payload convention. Positive
remaining time is rounded up to milliseconds so zero denotes expiry rather
than rounding. Effective-deadline status
binds the coherent policy/cap revisions used in evaluation and names every
limiting source when deadlines tie. Counts and aggregate status size remain
bounded by the public codec; admission refuses a supervision topology that
cannot be represented. Status does not expose host-native clock structures.

- **[TIME-9]** Setup, page-in, writeback, fingerprint, checkpoint, fork/rearm,
  restore, transfer, and cleanup phases MUST have a finite applicable progress,
  total, or independently supervised outer allowance. Configuring both class
  allowances as absent MUST be refused unless a finite applicable outer cap
  establishes bounded resolution or failure. Validation MUST apply at launch,
  live update, phase entry, and outer-cap amendment. An expiring execution cap
  MUST NOT eliminate cleanup's independent finite budget. Deliberately unlimited
  guest execution MAY remain separately configurable; it MUST NOT remove these
  infrastructure-phase requirements.

**[TIME-2]** Poll expiration MUST only yield a control-plane opportunity, check
cancellation and ownership, and continue waiting when other budgets permit.
Meaningful-progress timeout MUST measure lack of the operation's specified
progress. Total timeout MUST measure elapsed operation time including stalls and
retries. Progress MUST NOT reset or extend an explicitly bounded total duration.

| Operation class | Meaningful progress | Required additional considerations |
| --- | --- | --- |
| Setup/handshake | A validated protocol phase completes | Transport reads must not extend the phase indefinitely |
| Quantum completion | A validated logical execution boundary completes | Page traffic and heartbeats are not quantum progress |
| Page-in | The requested page generation is installed and authenticated | Reserve emergency buffers; bound retry and queue waits |
| Dirty writeback | The intended page generation becomes safely preserved | A stale completion cannot clear a newer dirty generation |
| Fingerprint initialization/update | Required leaves or subtrees complete for the selected boundary | Initial full-tree work has a separate budget from incremental work |
| Checkpoint quiescence | Required owners reach the coherent pause boundary | Pager completion must not depend on a parked guest worker |
| Checkpoint capture/publication | Required pages/objects or durable publication phases complete | Distinguish copying from durable completion |
| Restore | Authenticated regions/device phases become usable | Partial state cannot be released as runnable |
| Fork/rearm | Each specified barrier or placement phase completes | Parent, child, and pager readiness are distinct phases |
| Transfer/preparation | Missing objects are authenticated and final ownership phases complete | Transport activity alone does not establish a restorable VM |
| Cancellation/reap | Required owners stop and release or quarantine authority | Outstanding I/O may outlive an initial cancellation request |

**[TIME-3]** Paging telemetry MUST NOT be used as a substitute for guest execution
progress. Repeated faults, eviction/reload cycles, responsive heartbeats, and
retrying the same failed read MUST NOT renew a quantum's progress budget. Each
operation MUST define monotonic completed-work units or an explicit finite phase
transition. If safe progress is unobservable, the implementation MUST use a total
limit rather than fabricate a liveness proof.

Slow productive scans need different allowances from thrashing execution. A
fingerprint operation can count required leaves completed for one frozen view;
hashing unrelated pages cannot renew it. A transfer can count unique required
objects authenticated, not repeatedly resent bytes. A page-in completes once for
the requested content generation. The quantum may remain stalled despite those
successful page-ins and must retain its own independent supervision.

**[TIME-4]** Runtime budget updates MUST explicitly define their effect on already
running operations. This RFC applies accepted new class budgets to current
operations while retaining each operation's original start and last meaningful
progress coordinates. A shortened allowance that has already elapsed MUST
trigger operational cancellation on the next supervision evaluation. An
increased allowance MAY extend the class deadline, but MUST NOT undo a terminal
failure or revive canceled work.

The manager wakes the supervisor when a revision is applied; a blocked command
cannot defer observing it until guest execution resumes. Reports retain both the
starting and latest applied revision. Updating only future operations is not
sufficient for the requested live tuning behavior.

**[TIME-5]** A class budget update MUST NOT implicitly relax an outer assignment,
preparation, service-shutdown, or operator cap. The effective deadline is the
earliest applicable cap. Relaxing an outer cap requires a separately authorized,
explicit operational update naming that cap and revision; absent such an update,
the original cap remains binding. Modeled campaign bounds are never adjustable
through this host-policy interface.

The existing authored timeout policy can therefore continue to supply an
absolute host watchdog. A disk-oriented policy with a longer checkpoint budget
does not override it. Operators must see the remaining limiting cap in status,
so an accepted paging policy is not mistaken for permission to run beyond the
assignment allowance.

### Explicit outer-cap amendments

Outer-cap mutation is a separate operational transaction, not an implicit field
of `UpdateHostRamPolicyRequestV1`. It does not rewrite the authored assignment,
campaign policy, or any modeled bound. The proposed records are:

```text
OuterCapTargetV1 = {
  daemon_epoch: DaemonEpoch,
  owner: Execution(ExecutionId) | Service(service_instance_id: bytes[32]),
  owner_generation: u64,
  cap_id: bytes[32]
}

AmendOuterCapRequestV1 = {
  principal: OperationalPrincipal,
  target: OuterCapTargetV1,
  expected_cap_revision: u64,
  idempotency_key: bytes[32],
  allowance: OptionalDuration
}

AmendOuterCapResponseV1 = {
  request_digest: bytes[32],
  target: OuterCapTargetV1,
  disposition: Accepted | Replayed | RevisionConflict | NotCurrent |
               Terminal | AdmissionRefused | HistoryCapacityRefused |
               RateLimited | Unavailable,
  accepted_cap_revision: None | u64,
  accepted_allowance: None | OptionalDuration
}
```

The target selects an existing cap with one supervisor owner; it cannot create
or relabel a cap. The cap's class, original monotonic start, and clock-incarnation
binding are immutable. A new allowance is measured from that original start,
not from request arrival. Removing a deadline requires explicit authority and
passes TIME-9 validation for every affected phase. Authentication failure has
no mutation effect and is reported through the control protocol's existing
authorization error contract.
An accepted or replayed response carries the original accepted revision and
allowance; a refusal carries neither. Current cap state is a separate status
observation, so an old successful receipt cannot be mistaken for a live deadline.

The transaction is `validated -> journaled/applied -> acknowledged`, or a typed
refusal without mutation. Expiry, cancellation, completion, and amendment use
the same supervisor-owned atomic ordering. Before accepting a new revision,
the owner evaluates the old cap against the current monotonic clock. If that
cap has elapsed or the owner is terminal, expiry or terminal disposition wins;
an increased allowance cannot rescue already expired work merely because a
watcher has not yet run. An accepted shorter allowance that is already elapsed
records the amendment and enters cancellation in the same ordered transaction.

- **[TIME-10]** Outer-cap amendments MUST authenticate exact owner incarnation,
  cap identity, and expected revision. Revisions MUST increase without reuse.
  The request digest, idempotency history, history admission, and replay ordering
  MUST satisfy POLICY-6 and POLICY-11 through an independently charged outer-cap
  owner history. Known-key retry MUST return the original accepted response
  without reapplying it, including after later expiry. Conflicting bytes MUST
  be rejected. Acceptance MUST preserve original elapsed-time coordinates,
  durably bind the new allowance and revision, and wake every affected watcher.
  No caller-local timeout update may leave another watcher on an obsolete cap.
  Amendment MUST NOT resurrect terminal cancellation or released authority.
- **[TIME-11]** Restart recovery MUST reconcile accepted cap amendments and
  terminal decisions before resuming affected authority. It MUST retain the
  original elapsed-time basis when a trustworthy same-clock incarnation can
  establish it. If elapsed time or ordering cannot be recovered safely, the
  owner MUST remain unavailable or enter containment with independently bounded
  cleanup; restarting a full allowance is forbidden. Operational journals,
  clocks, cap revisions, and deadline provenance MUST remain outside semantic
  checkpoint identity. Status MUST report coherent cap identities/revisions,
  remaining allowances, and the effective limiting source for each operation.

Journal recovery must distinguish accepted-but-unacknowledged amendments from
refused requests. A failure to establish whether an amendment committed leaves
the owner held until reconciliation; it does not authorize whichever deadline
is more convenient. The codec and supervisor implementation must specify the
durable commit/expiry ordering under PLAN-2 before this control is enabled.

**[TIME-6]** Every inherited finite wait MUST be audited at cutover. The audit MUST
include QMP commands and jobs, plugin setup, quantum awaits, checkpoint quiescence,
hashing, fork placement/rearm barriers, remote preparation/restore, materializer
publication, transport exchanges, shutdown escalation, and process reap. An
internal fallback MUST NOT silently defeat the selected operation budget.

The current production constructors sometimes copy one remaining assignment
watchdog into every async policy field. Those constructors must be replaced by
composition of class policy and outer caps. The GPL-side fork implementation's
internal child-placement timeout must receive an explicit applicable budget.
Finite transport framing limits can remain short when exchanges acknowledge
long operations asynchronously; a synchronous response blocked behind RAM work
cannot retain an unrelated short command deadline.

## Responsiveness, cancellation, and cleanup

**[POLICY-9]** Policy updates, cancellation, operational status, and supervision
MUST remain available while a guest quantum, QMP handler, or RAM operation waits
for backing I/O. Their control paths MUST NOT depend on that blocked thread,
completion of a guest instruction, or a parked fork-barrier participant. The
executor actor MUST hold only short admission/state locks; paging, reclaim,
locking, hashing, and storage waits run outside them.

An independent pager-control channel acknowledges revision application. QMP
may report a completed guest boundary later, but it is not the sole route for
changing an already stalled arena's host policy. Status can report an unavailable
submeasurement while still returning authenticated cancellation and policy state.
Fork lifecycle coordination must retain this service without relying on inherited
AIO, RCU, or plugin worker threads that are parked or absent in the child.

Strict placement completion has a bounded, revision-bound receipt on pager
control schema version 6. Its enclosing authenticated frame identifies the
owner and arena incarnations. The receipt identifies the applied policy
revision, immutable topology generation, and nonreused placement epoch. A
pending transition advances the requested revision without advancing the
applied revision or replacing an earlier verified receipt. Only completion
under the same original operation and matching pending generation publishes a
new applied revision; a superseded completion cannot acknowledge a newer request.

A `ResidentRequired` receipt reports the deduplicated, page-rounded span bytes
actually verified locked. Aggregate process `VmLck`, successful prefaulting,
and acceptance of a lock request do not establish this guarantee. The receipt
remains tied to the retained lock ownership until verified unlock or arena
teardown. A failed downgrade retains custody of any uncertain remaining locks.

A `DiskOriented` receipt reports the complete authenticated logical page and
byte totals at a coherent preservation cut, together with the native independent
writer generation at that cut. This is historical preservation evidence:
subsequent resident guest writes are allowed, and the receipt does not claim
continuous write-through or that backing contains every later write. A new
complete preservation walk under writer exclusion produces a new placement
epoch. The independent writer generation includes every registered writer;
fault-service write-protection counters alone cannot substitute for it.

**[TIME-7]** Cancellation MUST stop admission of new pager work, publish sticky
cancellation to current and future children, and drain or retain outstanding
operations under owned cleanup authority. Page buffers, backing files, file
descriptors, reservations, and shared-template references MUST remain owned until
completion or authenticated quarantine transfer. A cleanup deadline expiring MUST
NOT release resources that a process or I/O completion can still access.

Kernel or storage waits may remain outstanding after a kill request. Quarantine
retains both process and backing enforcement, including accounting for pinned
buffers and outstanding operations. Reap, page-I/O disposition, and backing
reference reconciliation precede reservation release. Repeated cleanup attempts
are idempotent. A returning completion must validate its owner and content
generation before touching state; a canceled older write cannot modify a newly
reused arena.

**[TIME-8]** Infrastructure failure evidence MUST identify the operation class,
applied policy and reservation revisions, limiting deadline, ownership generation,
and bounded paging diagnostics. It MUST distinguish OOM containment, backing
exhaustion, I/O failure, lack of progress, total duration expiry, and cleanup
quarantine. Host wall-clock values and observations MUST remain outside guest
fingerprints and replayable finding evidence.

## Source integration map and cutover

These locations describe the current system; the proposed contracts above are
implemented through a coordinated replacement, without compatibility adapters,
old-format converters, or a second execution path.

| Existing source | Required integration |
| --- | --- |
| [AttemptResourceLimits](../../../crates/crucible-campaign/src/execution.rs), around line 300 | Extend the resource contract with backing, metadata, staging, and paging admission dimensions; preserve immutable original assignment requests |
| [CampaignAttemptTimeoutPolicy](../../../crates/crucible-campaign/src/policy/campaign.rs), around line 182 | Preserve modeled bounds and distinguish the existing outer watchdog from live host-local class budgets |
| [Fresh resource admission](../../../crates/crucible-daemon/src/qemu_campaign_lifecycle/resource_admission.rs), around line 43 | Replace full-RAM resident baseline with policy-aware resident plus compulsory-memory and backing admission |
| [Supervisor reservation state](../../../crates/crucible-daemon/src/executor_supervisor/state.rs), around line 103 | Add exact revisioned amendments and transition-peak accounting |
| [Executor availability](../../../crates/crucible-daemon/src/executor_supervisor.rs), around line 830, and [capability reports](../../../crates/crucible-daemon/src/executor_capability.rs), around line 174 | Advertise updated reservations and paging capabilities without observing semantic ordering |
| [Hot-fork pool](../../../crates/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/pool.rs), around line 704 | Account shared source ownership, child private growth, and live transition obligations |
| [Linux cgroup](../../../crates/crucible-qemu/src/linux_cgroup.rs), around line 834 | Replace unconditional swap prohibition where supported; add authenticated aggregate containment and separate update authority |
| [Linux host owner](../../../crates/crucible-qemu/src/linux_attempt_host.rs), around line 274, and [daemon resource guard](../../../crates/crucible-daemon/src/qemu_resource_guard.rs), around line 59 | Own manager/backing lifecycle, update capabilities, and quarantine with the existing process/storage authority |
| [Executor transport](../../../crates/crucible-daemon/src/executor_loopback.rs), around line 7 | Introduce bounded request-bound policy and reservation operations and status responses |
| [Operational runtime control](../../../crates/crucible-daemon/src/campaign_runtime_control.rs), around line 37 | Provide an explicit authorized operational facade; do not mutate authored campaign policy |
| [Packaged executor status](../../../crates/crucible-daemon/src/packaged_qemu_executor/status.rs), around line 73 | Extend coherent revision snapshots with target/effective/current/convergence and limiting-cap observations |
| [Async policy](../../../crates/crucible-qemu/src/async_driver.rs), around line 25, and [production policy construction](../../../crates/crucible-qemu/src/supervision/node_step_gate/support.rs), around line 396 | Separate polling, meaningful progress, and total budgets by operation class |
| [Fresh watchdog composition](../../../crates/crucible-daemon/src/qemu_campaign_lifecycle.rs), around line 2012, and [hot-fork composition](../../../crates/crucible-daemon/src/qemu_hot_fork_world_factory.rs), around line 921 | Stop replacing every operation budget with the same assignment remainder |
| [Assignment watchdog](../../../crates/crucible-daemon/src/supervision.rs), around line 68, and [worker completion](../../../crates/crucible-daemon/src/executor_worker.rs), around line 1264 | Retain outer-cap provenance, cancellation, and expiry-wins reconciliation |
| [Checkpoint pause](../../../crates/crucible-qemu/src/node/exact_snapshot/capture.rs), around line 415 | Use the quiescence class rather than a shared QMP duration |
| [Remote preparation](../../../crates/crucible-daemon/src/qemu_campaign_lifecycle/remote_observation_resume.rs), around line 156, and [materializer polling](../../../crates/crucible-daemon/src/packaged_qemu_executor/exact_pin_materializer.rs), around line 392 | Compose preparation/publication allowances with remaining outer caps |
| [QMP failure handling](../../../crates/crucible-qemu/src/node.rs), around line 2437 | Preserve infrastructure classification and attach class/paging evidence |
| [Worker pool](../../../crates/crucible-daemon/src/executor_pool.rs), around line 66 | Keep worker maximum separate; audit shutdown wait and cleanup ownership |

**[POLICY-10]** Cutover MUST update the host control codec, executor capability and
resource contracts, daemon status schema, QEMU manager protocol, and all policy
construction sites together. A peer advertising an old contract MUST be refused
before execution or resource mutation. There MUST NOT be legacy fallback behavior
that silently ignores runtime updates, disables admission dimensions, or uses an
old timeout policy for a new paging mode.

Validation is specified in [validation and performance](10-validation-and-performance.md).
At minimum it must exercise live increases and decreases, stale-generation and
revision races, lost responses, crash recovery at every transaction phase,
resource-convergence failures, strict-residency activation refusal, outer-cap
precedence, productive slow scans, repeated-page thrashing, and cancellation while
storage is stalled. All successful configurations must preserve the same logical
RAM roots and canonical guest execution as the fully resident reference.
