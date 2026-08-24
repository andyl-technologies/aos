# Decisions and open questions

This document collects the architectural decisions made by RFC-0016. The
normative details remain in the topical documents; this index makes the major
tradeoffs reviewable without reconstructing them from the whole RFC.

## Resolved decisions

### D-1: A campaign is a named reference to an immutable snapshot

A campaign's durable identity is a small mutable reference. The reference
points to an immutable `CampaignSnapshot`, which in turn names immutable
policy, fact-log, frontier, index, and retention objects by digest. Advancing a
campaign creates objects first and atomically moves the reference last.

This gives readers a consistent view, makes archival transfer content-addressed, and
allows every historical campaign state to be retained or reconstructed.

Rejected: a mutable database row per branch. That representation obscures
causality, makes partial archival difficult, and couples correctness to one
database engine's transaction boundary.

### D-2: Scenario mechanism and campaign policy are separate

The scenario defines the reproducible world: machines, devices, workloads,
signals, properties, measurements, checkpoints, and available choices. The
campaign policy defines how that world is explored: objectives, proposal
generators, widening, selection, budgets, retention, and realization
preferences.

The same scenario may therefore be replayed exactly, sampled statistically, or
searched adaptively without changing its meaning.

Rejected: embedding scheduler state or search heuristics in the scenario. That
would make replay depend on an optimization algorithm rather than on recorded
choices.

### D-3: Durable facts are authoritative; indexes and frontiers are projections

Proposals, attempts, claims, observations, measurements, findings, pins, and
policy transitions are immutable facts. The runnable frontier, score tables,
Pareto sets, and user-facing indexes are deterministic projections over those
facts and the pinned policy implementation.

A projected object may be cached and content-addressed, but it can be rebuilt
and checked. This distinction is the basis for crash recovery and replica
convergence.

Rejected: treating the daemon's in-memory queue as campaign truth.

### D-4: Executors receive attempts, not semantic nodes

A semantic branch node describes a reproducible state and path. An `AttemptId`
describes one execution of a proposal from that node. Reservations and retries
are keyed by attempt, so a crashed executor cannot corrupt node identity and an
operator can distinguish duplicate execution from duplicate discovery.

### D-5: Guest and environment exploration use one typed choice protocol

All adjustable behavior is represented by a typed selectable. Initial domains
are Boolean, finite discrete, bounded integer, and structured choice groups.
Continuous-looking controls such as latency, loss, and backoff are encoded as
bounded integer quantities with explicit units and proposal generators.

The environment uses adapters to apply network, disk, timing, scheduling, and
memory choices. A guest uses the same protocol to publish application-level
alternatives and receive a selection. This shares provenance, replay,
minimization, and search semantics across both sides of the VM boundary.

Rejected: separate fuzzing engines for infrastructure faults and guest
decisions. Their independent histories could not describe an interacting path.

### D-6: Choice-instance identity is semantic and stable

A selectable declaration has a stable definition identifier. Each dynamic
encounter derives a `ChoiceOpportunityId` from the definition, semantic parent,
occurrence, and phase. A selection records both identifiers, the chosen value,
and the proposal evidence.

Raw addresses, process IDs, wall-clock timestamps, and iterator memory layouts
never contribute to semantic identity.

### D-7: Target model, proposal distribution, and realized choice are distinct

The campaign records:

- the target model `P`, which says what population or probability law a result
  describes;
- the proposal distribution `Q`, which says how the scheduler chose the next
  candidate; and
- the realized selection, which is the exact replay input.

Adaptive proposal probabilities never silently redefine the modeled
population. Weighted estimators record the required `P/Q` evidence, and search
claims remain distinct from statistical claims.

### D-8: Large domains widen progressively at branch points

A branch point exposes only a bounded number of candidates initially. Additional
candidates are materialized as visits and information justify them, using the
policy's pinned widening rule and candidate generator. This permits integral
domains and large products without pretending to enumerate them.

Rejected: exhaustively expanding a branch before any child runs. That consumes
storage and scheduler memory while delaying useful feedback.

### D-9: Guided selection is deterministic given campaign facts

The initial guided policy uses fixed-point PUCT-style scoring, deterministic
tie-breaking, explicit novelty and risk terms, and recorded objective
normalization. Multi-objective survivor barriers use exact signed, unsigned,
and reduced-rational values and arbitrary-precision reduced weighted rewards.
They declare Pareto-top-`K`, lexicographic, or weighted-top-`K` primary order
plus explicit breadth-first and novelty reserves.

Breadth-first capacity is reserved first, novelty capacity second, and the
primary objective order fills the remainder. Configuration identity breaks
every otherwise-equal order. Pareto and lexicographic comparison have fixed
component-visit ceilings; weighted ordering has a conservative
operand-byte-visit ceiling. Reward numerator, denominator, accumulated
arithmetic work, and aggregate decision evidence are independently bounded.
Each decision retains the exact evaluated set, rule, selected set, and one
deterministic explanation per candidate.

Floating-point implementation details, worker completion order, and map
iteration order must not alter strict-mode decisions.

### D-10: Strict and streaming modes make feedback timing explicit

Strict mode advances at deterministic policy barriers and is suitable for
reproducible search experiments and CI. Streaming mode incorporates committed
observations as they arrive and is suitable for maximum throughput. Both
produce exact replay paths, but only strict mode promises the same explored
tree from the same inputs and budget.

The mode is campaign policy and is visible in claims and status output. One
campaign ref cannot activate a policy with another mode: mode selects the
observation-fold contract, so such an experiment derives a new campaign rather
than reinterpreting an existing admission sequence.

### D-11: Expansion state is lazy and persistent

Each branch point has snapshot-bound, paged campaign-local expansion state
containing owner-derived request, proposal, admission, and observation roots,
statistics, and compact source continuations: generator kind and version,
finite-source cursor, deterministic seed, widening counters, and policy-local
statistics. Candidates become proposals only when demanded by capacity or
feedback, and proposals become admitted children only through authenticated
admission dispositions.

These continuations are serializable state machines, not language closures or
native function pointers. They can be resumed after coordinator restart and
submitted again to the local executor through either supported adapter.

### D-12: Execution has hot, exact, and thin realization tiers

The scheduler may realize a branch through:

1. a hot on-host QEMU template, optimized for high-rate forking;
2. an exact durable checkpoint closure, optimized for replay, hibernation, and
   migration; or
3. a thin recipe, optimized for low storage when deterministic recomputation is
   acceptable.

The semantic branch is independent of the selected tier. A failed or
unsupported optimization falls back without changing the path.

### D-13: Hot fork is an explicit QEMU protocol and initially TCG-only

The GPL-side QEMU process owns thread quiescence, fork-safety checks, child
reinitialization, and device support. The Apache host requests a prepared fork
through the versioned control protocol; it never reaches into QEMU internals.

The initial supported mode is software emulation. KVM state and host-kernel
virtualization resources are excluded until an independently specified and
validated realization exists.

Rejected: sending `fork(2)` to an arbitrary multithreaded emulator. That is not
a safe VM snapshot mechanism.

### D-14: The hot template remains immutable and every child is isolated

The prepared parent does not resume scenario execution. Each child receives
private control and observation endpoints, private run directories, private
overlay disks, fresh host resource identities, and reset protocol epochs.
Read-mostly guest RAM begins as operating-system copy-on-write pages and is
copied only when parent or child writes it.

No writable observation ring, control socket, or disk overlay is shared among
siblings.

### D-15: Multi-machine scenarios fork atomically at the world boundary

The host prepares every member VM and the virtual environment at the same
logical boundary. It publishes a child world only after every member has forked
and all child resources are rebound. Failure discards the partial child set.

Rejected: independently forking machines while virtual time or packet delivery
continues. Such a child would not correspond to a single scenario state.

### D-16: Exact checkpoint closures remain the portable interchange

Hot fork is deliberately host-local and ephemeral. The exact closure includes
all VM, environment, control-plane, continuation, disk, and identity state
needed for portable restore. Durable closure export is the bridge to
hibernation, long-lived midpoint debugging, archival, and offline maintenance
transfer.

### D-17: Durable storage is a composable content-store graph

Directory and S3-compatible storage are initial leaf drivers behind separate
immutable-blob and mutable-ref traits. Verified, routed, tiered, cached,
mirrored, packed, compressed, encrypted, quota, and metrics layers compose into
an acyclic operational store graph. Large memory and disk state is represented
by manifests over logical pages or extents whose IDs do not depend on physical
pack geometry or backend placement.

Drivers and composition layers never define campaign semantics. Archival
transfer moves authenticated logical objects and advances the one authoritative
destination ref with compare-and-swap.

### D-18: One mutable ref and one coordinator are the synchronization boundary

All objects are uploaded and verified before a campaign ref is advanced. A
reader either observes the old complete snapshot or the new complete snapshot.
Exactly one coordinator owns that ref. An unexpected CAS conflict is a stale
command or ownership defect, not an invitation to merge concurrent histories.
Deriving another campaign creates another ref sharing immutable objects.

### D-19: The local executor contract is implemented; network fanout is not

The supported scheduler is a single coordinator using one local executor and
cheap QEMU forks. `CampaignService`, the pure `PlannerEngine`, and
`ExecutorService` are normative language-neutral component contracts with
direct and local RPC adapters. Attempts, results, snapshots, manifests, and
continuations contain IDs rather than process pointers or filesystem paths.

This RFC implements the local transport and conformance boundary but not
multi-host placement, membership, cross-node admission, leader election,
partitions, remote page service, or cluster consensus. Those are owned by a
future system that can be written independently of the local executor.

### D-20: Campaigns are first-class user-facing objects

The `crucible campaign` porcelain owns creation, running, semantic branching,
campaign derivation, inspection, comparison, steering, hibernation, export,
replay, and garbage-collection workflows. Existing one-run and corpus commands
remain useful and may be
implemented as bounded campaign policies.

A user sees a decision graph with evidence and measurements, not a directory of
opaque worker jobs.

### D-21: Findings are self-contained and replayable

A finding pins the scenario, policy, path, exact selections, relevant
observations, properties, measurements, provenance, and the best available
realization. Failure preservation is part of committing the finding, not an
optional cleanup step after the branch exits.

### D-22: Hot forking is correctness-gated and optional

Performance does not weaken determinism, isolation, or the license/process
boundary. Differential gates compare hot-fork children with exact restores,
including guest-visible state, protocol epochs, properties, measurements, and
replay. Unsupported devices or failed quiescence select exact restore instead
of best-effort forking.

### D-23: Manual real-usage acceptance is release-blocking

Automated equivalence, determinism, ABI, storage, and performance gates remain
mandatory but do not prove operability. Each phase gains a manual flight, and
release requires an independent operator, destructive recovery drill,
finding-to-debug handoff, and long-running realistic product campaign with a
reviewed evidence bundle.

Rejected: treating the worked example as a demo performed only by the feature
author, or accepting a green CI result as evidence that retention, recovery,
explanation, debugging, and cleanup are usable and safe.

### D-24: Branch points unify explicit and adaptive alternatives

The user-facing and temporal-graph concept is a `BranchPoint`, identified by a
parent configuration and typed `ChoiceOpportunity`. Adaptive expansion is not a
different kind of graph node; `ExpansionState` is campaign-local knowledge
attached to that branch point.

Both an explicit branch and adaptive exploration publish `BranchRequest`
facts. They then use the same proposal, attempt, observation, scheduling,
storage, replay, and explanation machinery.

Rejected: parallel “explicit fork” and “search expansion” graph models. They
would disagree about deduplication, provenance, and replay while describing the
same semantic selection.

### D-25: An explicit branch is a bounded finite candidate source

The finite request is normally low-cardinality, but the selectable domain need
not be. Selecting three latency values from a billion-value integral domain is
a valid three-way explicit branch. A generated request represents exhaustive
iteration, sampling, mutation, or progressive widening.

Both forms remain lazy. Publishing a 100-value request creates a persistent
source, not 100 scheduler jobs or QEMU children. Finite requests are additive to
existing generated sources. A policy revision or derived campaign is required
to replace future exploration rules.

### D-26: Request provenance does not multiply semantic edges

Planner, operator, debugger, and exhaustive-policy causes belong to branch
request and proposal facts. The semantic edge is uniquely keyed by branch point,
domain, and selected value. When several causes propose the same value, the UI
shows every cause on one edge and execution deduplicates by semantic attempt
identity.

An operator or debugger proposal used as the attempt's immutable execution
basis is an intervention. It may guide later adaptive work only when policy says
so, and it does not enter statistical estimators unless the statistical design
explicitly models and weights it. Later duplicate causes do not reclassify the
execution.

### D-27: Branch, derive, hot fork, and debug mutation are distinct

`branch` admits semantic values at a branch point. `derive` creates a new named
campaign ref whose first owned snapshot is an audited successor of the exact
source snapshot, sharing immutable semantic roots without changing the source
ref. `hot fork` is a QEMU realization
optimization. A valid debugger selection is a debugger-caused semantic branch;
an arbitrary memory/register mutation is a non-canonical derived session.

A checkpoint need not contain a choice opportunity, and a branch point need not
have a checkpoint or support hot fork. Conflating these operations would make
cache state affect the temporal graph.

### D-28: Planning is a pure versioned component transition

The complete pre-step `CampaignSnapshotId`, policy, planner engine identity, and
explicit planning budget form the planner input. Validated branch requests,
proposals, accounting, and explanation form its output. The coordinator records
the accepted step in a child snapshot. The first planner is the closed Rust
implementation; arbitrary callbacks and a general-purpose embedded campaign
language are deferred.

This makes campaign planning usable through a language-neutral component
contract without serializing native closures or granting a plugin authority
over refs, executors, QEMU, clocks, or stores.

### D-29: Durable coordination is outside semantic planner input

Planner-step replay indexes and the current portable planner head live in a
dedicated authenticated `coordination_root`. The root is part of snapshot
identity and closure traversal but excluded from `CampaignPlanningView`.
Therefore persisting `ContinueScan` cannot perturb the view identity whose next
page it resumes. Snapshot schema v2 makes this ninth root explicit and rejects
the former layout rather than overloading exploration, accounting, or pins.

### D-30: Planner scan outcomes bind an exact served page

`PlannerInvocation` schema v2 includes a required `PlanningScanPage`: the
authoritative prior position, requested limit, ordered served positions, EOF
bit, and canonical served request-body byte count. The coordinator recomputes
that page from the immutable planning view before accepting a result and when
validating an imported successor. `ContinueScan` must name the last served
position of a non-EOF page; `NoWork` requires EOF. This makes skipped keys,
premature EOF, and planner-claimed input accounting non-authoritative. The
authenticated planner head derives the only permitted start: `None` for a first
or changed-view page, or the exact prior same-view continuation cursor. A
completed same-view scan cannot be reopened.

### D-31: Planner Issue composes existing sole-writer owners atomically

An accepted finite-source `Issue` is one `PlannerAdvanced` snapshot transition,
not a sequence of separately visible request, proposal, and admission facts.
The coordinator inserts planner-caused requests and selected-source proposals,
derives each selection, the canonical cumulative path, and semantic attempt, then
assigns execution-basis or additional-cause admission in proposal order. The
result updates exploration, accounting, and coordination roots together and
records exact admitted/deduplicated counts. Imported successors replay the same
projection from authenticated output IDs and reject any root or invocation
mismatch. A pure preflight validates the complete batch, accounting, next-state
engine, and prospective step before local publication. Imported recomputation
writes nothing. Repeated generator graphs are cached by generator/domain pair
under an aggregate one-million-record validation budget per projection.
History-dependent generated enumeration remains fail-closed rather than
acquiring a planner-only bypass. Direct admission uses the observation-owned
configuration-to-path index to authenticate cumulative non-genesis prefixes;
planner `Issue` deterministically selects the lowest member from that same exact
set and requires it to be scoped version 2. Standalone loading of every
schema-v4 step fails closed because retained request-snapshot ownership is
transition-scoped; an `Issue` also depends on admission and deduplication
authority in snapshot roots. Authoritative loading names the snapshot whose
complete ancestry and coordination membership are validated.

### D-32: Validated immutable parents seed incremental local validation

Complete ancestry and closure validation establishes a process-local checkpoint
for an immutable snapshot ID, including ancestry depth, conservative
reachable-object work, and projected lifecycle state. A sole-writer repository
transaction that has authenticated its inputs and applied its exact owner delta
may prepare a child from that checkpoint without rewalking unchanged closure,
but promotes it only after the authoritative ref CAS succeeds. Canonical depth
and closure limits are enforced on both full and incremental paths. Relative to
exact parent-authenticated roots and owner-index members, every incremental
child authenticates and charges the complete closure newly reachable relative
to those parent anchors, including pre-published generator, policy, artifact,
or other graphs that were not reachable from the parent, plus a conservative
upper bound for newly constructed owner-index nodes. The cache retains only a
bounded current frontier; eviction is always semantically safe and any lookup
that races with eviction revalidates the immutable head.

Branch-request and mutation-command membership are authenticated Merkle
indexes. In addition, each successor's coordination root indexes its parent's
accepted mutation result. The current head answers its own replay directly and
every older command, request, proposal, admission, or planner invocation names
its exact original result snapshot through that accumulated index. Unique
mutation, lifecycle validation, and exact replay therefore do not scan snapshot
history.

Imported transition validation computes expected Merkle roots through a
non-persisting canonical overlay over changed trie paths; validation never
publishes intermediate nodes. Complete closure verification shares authenticated
subtree positions across persistent historical roots, so structurally shared
maps are not rescanned from their root for every snapshot version.

This cache is optional acceleration state. It is neither serialized nor trusted
across repository instances. Imported heads, restarted heads, and any head not
reached through an exact local transaction receive complete fail-closed
validation before promotion. Immutable blob semantics and active-ref GC
protection are prerequisites: a backend that mutates or removes reachable
objects violates the storage contract rather than silently invalidating a
semantic checkpoint.

### D-33: Observation publication is an exact first-result owner transition

One authenticated `ExecutionBasis` admits an `AttemptId`; it does not make a
caller-provided result authoritative. The coordinator validates the complete
modeled observation closure and conditionally creates the attempt-to-observation
mapping. The first canonical mapping owns graph, corpus, coverage, and
accounting folds. Later distinct results are retained only in a deterministic
conflict index, while exact replay returns the originally committed transition.
Strict campaigns fold canonical observations by global admission ordinal.
Imported transitions recompute all five root deltas without writing, and local
publication advances the mutable ref last. Before local publication writes any
observation or owner-index object, one read-only multi-root preflight validates
all newly supplied evidence and discovered-choice closures. Full choice-domain
records are transient during that walk; a bounded cache retains only compact
digests of successfully validated declaration/domain reference contracts and is
shared across ancestry and closure validation.

Coverage is stored as a grow-only set of immutable projection records rather
than one mutable union value. The semantic union remains deterministic and
rebuildable from those records, while each projection preserves its exact
derivation evidence and content identity.

### D-34: Component identity and semantic authority are separate

The coordinator accepts planner and debugger output through versioned canonical
messages authenticated with separate operational keys. The planner credential
cannot authorize a debugger request and the debugger credential cannot
authorize a planner result. Keys never enter content-addressed state, exports,
or logs. Direct and loopback-RPC compositions decode the same messages and call
the same adapter; raw owner mutations remain coordinator-internal.

Authentication identifies the supervised producer of exact bytes, but it does
not make those bytes campaign truth. The coordinator still recomputes planner
pages and accounting, validates every output closure, requires debugger session
and request-cause agreement, and applies exact snapshot owners. Likewise, a
published choice body is not branchable merely because it exists. It becomes
authoritative only through an exact discovery fact or canonical observation,
and branch acceptance requires that graph membership.

### D-35: Claimable work is rebuilt from snapshots; leases are epoch-local

The durable attempt frontier is the authenticated difference between admitted
attempt membership and canonical observation membership. It is projected by a
bounded, snapshot-bound scan rather than stored as a mutable queue. A cursor
from an older snapshot is rejected, and changing page size changes only scan
suspension boundaries, not the sequence obtained at EOF.

Worker reservations are bounded process-local acceleration state. They bind an
immutable `AttemptId` to one daemon epoch, worker slot, and generation, but none
of those operational fields enters campaign identity or recovery. A restarted
daemon chooses a fresh nonzero epoch, rebuilds claimable attempts from the
current snapshot, and may duplicate unfinished execution; canonical
observation conditional-create remains the semantic idempotence boundary.

### D-36: The attempt record is the executor's immutable specification

`SubmitAttempt` names the canonical `AttemptId` and its campaign lineage rather
than introducing a second `AttemptSpecId` that could drift from campaign
semantics. Resource ceilings, retention intent, assignment, execution, and
daemon-epoch identities remain operational fields in a bounded component
message and never alter the attempt or its modeled result.

The executor response commits to a domain-separated digest of every canonical
request field in addition to repeating the assignment, epoch, and attempt.
This makes an assignment retry exact and prevents a syntactically valid
response from being replayed after resource or retention inputs change. Normal
executor refusal is a stable protocol outcome; failure to produce a response
is a separate transport or service error.

Coordinators never call an implementor-facing service without the checked
client wrapper used by both direct and RPC compositions. The wrapper rejects a
cross-request response, and repository validation separately authenticates the
attempt and lineage plus any claimed completed observation. Exact assignment
replay returns the original response. Changed bytes under the same assignment
return a non-retryable conflict; transient backpressure or unavailable input is
retried under a fresh assignment so the original response remains immutable.

### D-37: Executor idempotency is direct-addressed durable operational state

The single-host executor does not rebuild an in-memory assignment table by
scanning daemon history. It stores one immutable, checksummed, bounded record
under each `AssignmentId` and one conditionally replaced runtime-state record
under each domain-separated `(CampaignLineageId, AttemptId)` key. The runtime
record commits to an execution-basis digest over that pair, the complete
resource limits, and retention intent. Directory publication uses fsynced
staging plus atomic link/rename under an exclusive writer lock; a memory
implementation exists only behind the same trait for conformance tests and fake
components.

The attempt state becomes `running` before an `accepted` response can become
visible. An indeterminate response publication never rolls that state back:
the prepared execution remains bounded and queued, so a visible response cannot
refer to abandoned work. A new daemon epoch may replace stale running or
canceled state. A fresh assignment reuses running or completed state only for
the exact execution basis; resource/retention changes fail as incompatible and
the same `AttemptId` in another lineage remains independent. A completed
observation is returned only after read-only reauthentication against that
request. Temporary input absence yields `unavailable-input`; semantic mismatch
discards the operational completion and permits reexecution. Authorization
failure yields `unauthorized` without discarding or reexecuting it. Cancellation
and completion use exact execution-bound conditional transitions, and
conflicting second observations fail rather than selecting a winner.

Mutable publication errors are reconciled by reloading the exact record. A
directory reload re-fsyncs the containing directory before confirming a state
that may have become visible after rename. Confirmed running work remains
reserved, while confirmed completion/cancellation releases capacity even when
the original I/O error is returned. Existing immutable assignment lookup also
re-fsyncs its directory before declaring an exact replay durable. Capacity is
bounded by slots and aggregate vCPU, resident-memory, and writable-disk limits,
plus a per-execution deterministic-quanta ceiling.

This ledger is operational acceleration, not campaign truth. Deleting it may
duplicate unfinished execution but cannot change canonical attempts,
observations, findings, or campaign refs. The supervisor receives a read-only
admission validator and no mutable campaign-ref authority. That adapter carries
an immutable executor profile and requires exact lineage agreement on the
Crucible/QEMU identities, complete protocol map, scenario schema, and exact
closure schema before admission.

### D-38: Local executor loopback uses a minimal versioned Unix frame

The single-host executor conformance adapter carries the same strict canonical
`SubmitAttempt` bodies as direct invocation in a fixed 16-byte Unix-stream
header: eight versioned magic bytes, one directional message kind, three zero
reserved bytes, and one big-endian body length. The body is rejected above 4
KiB before allocation. Both server and client strictly decode it, and the client
authenticates every response against its exact request. Configurable nonzero
absolute read/write deadlines (at most one hour) bound partial, drip-progress,
and non-reading peers, and the server shuts down both directions before
returning any protocol, service, or I/O error.

This is a language-neutral local RPC binding, not a second semantic schema and
not a distributed transport. It carries no host paths, descriptors, native
layouts, large artifacts, credentials, or QEMU objects. A long-lived server may
repeat the one-exchange function on a connection and closes that connection on
any framing, service, or semantic error. The external campaign-service API may
still use RFC-0010's HTTP/2 gRPC/Connect-style binding; local executor completion
does not depend on adopting a language framework.

### D-39: Executor result publication is an immutable candidate handoff

The execution model returns a complete `ObservationCandidate` containing the
child configuration, modeled evidence, and newly discovered opportunity bodies
beside the observation that names them. A linear dispatch token prevents one
charged reservation from launching twice. Repository preflight runs outside the
supervisor actor and authenticates every dependency and cross-object ID before
any bundle write. A short actor CAS then records
`Publishing(expected_observation_id)` in the durable lineage-qualified attempt
ledger; that record is a streamed GC root and restart locator. Immutable
publication runs outside the actor, followed by a short completion CAS. The
coordinator separately owns snapshot incorporation.

Retryable guest failure requeues one bounded reservation. Once a candidate
exists, retryable storage failure retains and republishes that candidate without
rerunning the model; stable failure is canceled or quarantined. Restart promotes
a complete publishing candidate or reexecutes an incomplete one while requiring
the exact previously committed observation ID. Cancellation keeps physical
resource charges until the worker acknowledges exit.

This preserves the executor's ability to publish immutable content without
granting it campaign mutation authority and gives direct and loopback paths the
same canonical completion boundary.

## Deliberately rejected representations

The following patterns are outside the design even if they appear convenient
for a prototype:

- one pre-created scheduler job for every possible branch;
- eager job creation for every value in an explicit finite request;
- in-memory closures as persisted frontier entries;
- a planner plugin that performs unrecorded I/O or publishes campaign facts
  directly;
- separate explicit-fork and adaptive-expansion data models;
- mutable branch rows whose last writer wins;
- a shared writable QCOW2 overlay, shared observation ring, or shared control
  socket among fork children;
- runtime mutation of scenario definitions to encode a chosen value;
- a score whose result depends on floating-point accident or candidate arrival
  order in strict mode;
- claims of exhaustive coverage for a progressively widened domain without a
  separately proven finite closure;
- treating a hot process image as the only durable representation of a branch;
  and
- linking the Apache host against QEMU to accelerate the fork path.

## Open questions to resolve by measurement

These questions tune the implementation; none permits weakening the invariants
above.

### OQ-1: Which QEMU subsystems form the first supported fork profile?

The first prototype must inventory all threads, file descriptors, timers,
backends, accelerators, and devices present in the representative scenario.
The answer should be an allowlisted capability profile with a fail-closed
prepare operation. Candidate exclusions include devices whose host backends
cannot be rebound safely.

Evidence required: repeated differential tests and sanitizer/stress runs across
at least the networking campaign in the worked example.

### OQ-2: Which child reinitialization strategy has the best safety/latency tradeoff?

Possible implementations include `pthread_atfork`-style preparation,
QEMU-owned stop-the-world orchestration around `fork`, or a narrower dedicated
template mode that avoids creating unsupported threads before the branch
boundary. The RFC fixes the observable protocol and safety condition, not the
internal GPL-side mechanism.

Evidence required: fork latency distribution, failure behavior at every
prepare stage, file-descriptor audit, and long stress runs with sibling churn.

### OQ-3: What memory and disk chunk geometry minimizes total campaign cost?

The exact store needs defaults for RAM extent size, disk extent size,
compression, zero detection, digest batching, and pack size. Small extents
deduplicate well but increase metadata and object requests; large extents do
the reverse.

Evidence required: checkpoint, restore, migration, storage amplification, and
garbage-collection benchmarks over representative dirty-page distributions.

### OQ-4: When should the scheduler materialize an exact closure from a hot template?

Candidates include elapsed age, accumulated child count, memory pressure,
finding severity, migration intent, and predicted future reuse. The decision
must be policy-visible and must never evict the only replayable representation
of a committed finding.

Evidence required: host memory pressure and total time-to-result under wide and
deep campaign shapes.

### OQ-5: What are the default widening and guided-search constants?

The widening coefficient/exponent, PUCT exploration constant, novelty weight,
beam width, and objective normalization need usable defaults. They remain
explicit policy fields so experiments can pin and report them.

Evidence required: offline replay of recorded campaign facts plus controlled
benchmark campaigns with known rare and high-value regions.

### OQ-6: What should be the default policy barrier in strict mode?

Options include a fixed proposal batch, completion of all siblings opened by a
planner step, or a bounded logical-time epoch. The barrier must preserve
determinism without forfeiting most local parallelism.

Evidence required: reproducibility under deliberately permuted worker completion
orders and throughput comparison with streaming mode.

### OQ-7: Which capability profile is required for each initial store leaf?

The immutable and ref contracts require different capabilities. Directory and
S3-compatible leaves vary in durable flush, conditional requests, multipart
resume, range read, and repair enumeration. Those differences must be captured
by leaf capabilities and the composition conformance suite rather than leaked
into campaign logic.

Evidence required: backend tests against the supported local emulator and at
least one production-compatible service.

### OQ-8: Which operational events belong in canonical campaign history?

Semantic observations and selections are canonical; CPU utilization and queue
latency are ordinarily operational. Some executor-capability facts may affect
admission or explain performance. The implementation must finalize the small,
versioned coordinator/executor boundary without making those facts planning
inputs.

Evidence required: replay and audit exercises showing which facts are needed to
explain a result without making worker scheduling part of scenario identity.

## Resolution ownership

Ownership names subsystem roles rather than individuals so the plan remains
valid across staffing changes:

| Question | Responsible area | Resolving tasks |
| --- | --- | --- |
| OQ-1 | QEMU fork/profile maintainers | T-CAM-6.1, T-CAM-6.2 |
| OQ-2 | QEMU fork/profile maintainers | T-CAM-6.2 through T-CAM-6.5 |
| OQ-3 | Campaign store and performance harness maintainers | T-CAM-5.3 through T-CAM-5.5, T-CAM-6.6 |
| OQ-4 | Campaign supervisor and retention maintainers | T-CAM-4.5, T-CAM-5.6, T-CAM-7.5 |
| OQ-5 | Exploration-policy maintainers | T-CAM-4.1 through T-CAM-4.3 |
| OQ-6 | Campaign projector/supervisor maintainers | T-CAM-4.5, T-CAM-4.6 |
| OQ-7 | Campaign store maintainers | T-CAM-5.1, T-CAM-5.5, T-CAM-5.7 |
| OQ-8 | Campaign model, API, and operations maintainers | T-CAM-0.3, T-CAM-1.1, T-CAM-3.4 |

## Review exit criterion

The RFC is ready for implementation review when every resolved decision is
accepted or replaced explicitly, and every open question has an owner,
measurement plan, and phase in the implementation plan. Implementation may
change numeric defaults based on those measurements. It must return to RFC
review before changing the semantic identity model, the fact/snapshot model,
the choice protocol, fork isolation, exact-closure portability, or the
Crucible/QEMU process boundary.
