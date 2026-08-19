# Decisions and open questions

This document collects the architectural decisions made by RFC-0015. The
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
normalization. Multi-objective campaigns maintain a deterministic Pareto set
and may use beam admission as a separate, declared policy.

Floating-point implementation details, worker completion order, and map
iteration order must not alter strict-mode decisions.

### D-10: Strict and streaming modes make feedback timing explicit

Strict mode advances at deterministic policy barriers and is suitable for
reproducible search experiments and CI. Streaming mode incorporates committed
observations as they arrive and is suitable for maximum throughput. Both
produce exact replay paths, but only strict mode promises the same explored
tree from the same inputs and budget.

The mode is campaign policy and is visible in claims and status output.

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
campaign ref sharing immutable objects. `hot fork` is a QEMU realization
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
