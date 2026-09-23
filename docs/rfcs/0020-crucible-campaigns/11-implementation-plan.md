# 11 — Implementation plan and merge gates

This RFC was initially published for review without implementation. Its
implementation now continues in the same draft pull request so requirements,
gates, and code evolve together. Checked tasks have executable evidence in the
tree; manual and production gates remain unchecked until their recorded flights
are accepted. No partial phase becomes the default campaign path until its
listed gates pass.

## 11.1 Sequencing principles

1. Preserve the existing `Configuration = (ScenarioDef, Schedule)` identity.
2. Land canonical codecs and offline model gates before daemon or QEMU behavior.
3. Add typed choices before adaptive candidate generation.
4. Add lazy local campaigns before hot QEMU forking.
5. Keep exact restore/thin replay as correctness fallbacks while hot fork is
   developed and gated.
6. Implement separate immutable-blob and mutable-ref traits, then directory
   leaves, composition layers, packing, and an S3-compatible leaf through one
   conformance suite.
7. Implement the language-neutral campaign/planner/local-executor contracts
   with direct and loopback-RPC adapters; do not implement multi-host fanout.
8. All QEMU-side code remains in the QEMU patch/plugin GPL scope with source and
   license-ledger updates.
9. Begin manual developer flights with the first vertical slice. No phase is
   described as usable and no campaign or hot-fork path becomes a default until
   its §14 operator evidence is accepted.

## 11.2 Phase 0 — RFC review and executable contracts

- [ ] **T-CAM-0.1** Review and accept the campaign vocabulary, three-plane
  boundary, scenario/campaign split, `ChoiceOpportunity`/`BranchPoint`/
  `ExpansionState` separation, branch/derive/hot-fork terminology, and strict
  versus streaming claims.
- [ ] **T-CAM-0.2** Resolve the measured QEMU fork spike questions in §12 without
  weakening the fail-closed capability contract.
- [ ] **T-CAM-0.3** Freeze requirement-to-gate mapping and assign every new wire
  format a schema/version owner.
- [x] **T-CAM-0.4** Add a repository traceability check ensuring every
  `CAM`/`CMOD`/`SEL`/`GUIDE`/`LAZY`/`CCOMP`/`HFORK`/`CSTORE`/`CAPI`/`CMEAS`/`CSEC`/`CPERF`/`CMAN`
  requirement is covered by a task and gate.
- [ ] **T-CAM-0.5** Tabletop the realistic lifecycle, finding handoff,
  destructive recovery matrix, dogfood flight, evidence manifest, and owner
  sign-offs from §14.

**Exit:** the RFC and manual-flight design are accepted and the implementation
delta remains disabled.

## 11.3 Phase 1 — Canonical campaign model

Primary crates: `crucible-campaign`, `crucible`, `crucible-cas`, and codec-only
API types.

- [x] **T-CAM-1.1** Implement `CampaignLineage`, `CampaignPolicy`,
  `CampaignSnapshot`, `CampaignPlanningView`, planner engine/artifact/state and
  invocation identities, stable IDs, canonical binary encoding, and strict
  TOML authoring DTOs.
- [x] **T-CAM-1.2** Implement immutable campaign facts, persistent Merkle
  sets/maps, snapshot ancestry, and content-reference walking.
- [x] **T-CAM-1.3** Extend the existing campaign manifest roots with graph,
  exploration, observations, pins, and accounting while retaining corpus,
  coverage, findings, genesis, and provenance.
- [x] **T-CAM-1.4** Implement CAS snapshot advancement, conflict diagnostics,
  policy activation, budget grants, pause/resume/seal commands, and idempotent
  command IDs.
- [x] **T-CAM-1.5** Implement full projection rebuild and sampled cached-
  projection verification.
- [x] **T-CAM-1.6** Add schema corruption, authoring-order canonicalization,
  stale-command, single-writer ownership, crash-window, and provenance-lineage
  tests.
- [ ] **T-CAM-1.7** Run the §14 Phase 1 offline model flight: create, inspect,
  derive, reject a stale command, pause, resume, and audit linear snapshot
  ancestry using only public object/API surfaces, and publish its evidence
  bundle.

**Gates:** `gate:campaign-model`, `gate:content-address`,
`gate:campaign-cold-continuity` model tier.

`gate:campaign-model` is an isolable `crucible-campaign` target. Its public-
surface flight covers canonical authoring order, linear control, stale-command
rejection, derivation, and restart reconstruction; the same gate runs the full
crate suite for corrupt closure, lost-CAS, cached-projection, and provenance
regressions. Phase 1's operator flight and evidence bundle remain separately
open as T-CAM-1.7.

**Manual gate:** accepted §14 Phase 1 campaign-model flight.

## 11.4 Phase 2 — Typed choice model and guest protocol

Primary crates: `crucible`, `crucible-protocol`, `crucible-shmem`,
`crucible-guest`, `crucible-qemu-plugin`, and QEMU launch integration.

- [x] **T-CAM-2.1** Implement Boolean, discrete, and integer domains; stable
  alternatives; units/scales; landmarks; choice groups; constraints; limits;
  domain hashing; and validation.
- [x] **T-CAM-2.2** Implement `SelectableDeclaration`, `ChoiceOpportunity`,
  `ChoiceClassId`, `BranchPoint`, `ChoiceValue`, `Selection`, and canonical
  schedule encoding with branch-point identity separated from materialization.
- [x] **T-CAM-2.3** Normalize genuine explorable decisions through the selection
  envelope and reject every noncurrent schedule artifact before interpretation.
  Current schedule decoding rejects every schema other than V2 before decision
  decoding, and campaign selections use the strict canonical envelope. Live
  World-network outcomes and bounded preemption branches now use parent-bound
  campaign selections as their branch identities; raw RNG draws and preemption
  records remain only as causal consumer evidence after the selection.
- [x] **T-CAM-2.4** Implement versioned register/request/reply guest messages and
  typed Rust guest helpers with complete negative decode and allocation tests.
- [x] **T-CAM-2.5** Freeze guest selectable catalogs at setup, validate scenario
  expectations, support bounded narrowed runtime offers, and checkpoint pending
  requests exactly.
- [x] **T-CAM-2.6** Adapt RFC-0014 Boolean outcome, transition, and parameter
  search surfaces to publish environment choice opportunities without weakening
  typed effect adapters.
- [x] **T-CAM-2.7** Route application randomness through the integer selectable
  model and remove the parallel raw-width exploration path.
- [ ] **T-CAM-2.8** Integrate the actual network product guest with discrete and
  integral choices, exercise a pending selection across checkpoint/replay, and
  complete the §14 Phase 2 guest flight without internal protocol tooling.

**Gates:** `gate:typed-choice`, `gate:typed-choice-product-checkpoint`,
`gate:abi-conformance`, `gate:e2e-determinism`, `gate:license-boundary`.

**Manual gate:** pending §14 Phase 2 signed operator flight.

The canonical choice model completes T-CAM-2.1 and T-CAM-2.2. Boolean,
stable-ID discrete, and signed/unsigned 64-bit integer domains validate exact
cardinality, step alignment, units and rational scales, defaults, landmarks,
narrowing, and bounded canonical decoding. Finite and constrained Cartesian
groups bind canonical member order to exact declarations and admit a value only
after every member and relational constraint validates. Exact domain identities
retain presentation and landmarks while semantic identities intentionally omit
those non-semantic fields. Declarations, opportunities, class identities,
semantic branch points and edges, origin-bearing selections, and Schedule V2's
strict selection envelope are content addressed and replay validated before
application. `gate:typed-choice` runs the complete campaign model suite, its
focused public gate, and the execution-model Schedule V2 envelope test.

`nix-build -A checks.crucible.phase4.packagedCampaignChoiceVm --no-out-link`
runs the public packaged campaign flight against the current QEMU and plugin.
The real guest registers discrete and integral choices, the campaign answers
the discrete request, and captures the pending integral request in an exact
checkpoint. The daemon restarts before the reply and must expose the same
opportunity, branch point, parent, and integral domain. Submitting the reply
then realizes the selected guest in a fresh QEMU, and a second daemon/QEMU
restart proves exact resume and forward progress. This automated prerequisite
does not close the independent §14 operator gate.

The version-1 selectable ABI is now a pure, architecture-independent codec in
`crucible-protocol` with closed register/request/reply kinds, a 4,608-byte
aggregate bound, checked dense byte ranges, exact request/reply sequence
binding, a zero-filled mutable reply reservation, and a closed typed rejection
vocabulary. `crucible-guest` emits immutable setup registrations and validates
that a reply exactly occupies the lent request buffer without a stale sequence
or dirty tail. Golden vectors, every-truncation decoding, malformed range and
reserved-field cases, and allocation-before-bound regressions run under
`gate:abi-conformance`. This completes only T-CAM-2.4: catalog freezing,
scenario/declaration reconciliation, host doorbell dispatch, narrowed-domain
authority, and pending-request checkpoint ownership remain T-CAM-2.5.

The GPL-side plugin now also exposes a policy-free selectable callback core. It
decodes register/request messages at the exact trap coordinate, delegates them
to a typed catalog/decision authority, rejects guest-owned replies and stale
service replies, and writes one zero-padded reply through the existing
same-icount guest-input capability. This does not complete T-CAM-2.5: the live
runtime still needs to supply and persist the launch-authenticated inputs. The
plugin-side catalog state now enforces nonzero scenario ceilings under hard
4,096-declaration/1,000,000-request caps, exact required/optional declaration
matching, strictly advancing sequences, no late registration, and one
incarnation-bound pending request retained until an exact-sequence reply. The
live dispatcher now consumes that launch-authenticated plan, reconciles raw
guest registrations, freezes before publishing `setup_complete`, retains an
exact request without touching its zero-filled reply reservation, and requests
native VMStop. It preallocates cold-priming and restored catalog incarnations
over one shared declaration allocation, then swaps the exact continuation once
at the logical-restore boundary before acknowledgement. The live plugin now
publishes one bounded, versioned pending-request record through the existing
lossless marker ring after retention and VMStop request; the mapped host adapter
reconstructs the exact request, trap coordinate, and guest virtual reply target
without granting it semantic authority. Deferred requests use a 4,576-byte
nested-request profile so the 32-byte transport header cannot overflow the
4,608-byte marker entry. The current ABI includes a VM-local one-entry reply ring: the
host publishes only an exact-sequence reply that fits the retained reservation
at the current paused icount, and the plugin revalidates sequence/vCPU/icount,
zero-pads the guest reservation, writes it before resume, and charges completion
only afterward. The production node set now retains each drained request under
its exact `NodeId` until reply publication succeeds, preserving ownership across
multi-node drain failures, and exposes that node-qualified token through the
production lifecycle and daemon modeled-driver facade. Daemon-side scenario
schema V7 now owns canonical typed declarations and nonzero per-node/world
ceilings. Fresh production launch derives each white-box node's sealed catalog
plan from that exact scenario component; selectable-enabled exact restore fails
closed until its continuation exists. The daemon now resolves node-qualified
requests against the scenario, validates bounded narrowed domains, derives the
stable runtime opportunity, stops discovery without replying, applies exact
defaults for deterministic continuation, and consumes authenticated campaign
selections at the matching thin-replay boundary. Durable checkpoint composition
remains required to complete T-CAM-2.5.
The process-neutral `CRUCSCP3` catalog-plan codec freezes the sealed
descriptor body, including exact expectations, limits, registered identifiers,
sequence watermarks, completed counters, and a complete pending request/trap
coordinate plus its guest virtual reply target. Noncurrent catalog encodings are
rejected before plugin activation. The plugin
catalog converts cold/restored plans bidirectionally and creates a fresh token
incarnation on restore, so prior-process tokens cannot complete a restored
pending request. The canonical `CRUCSUP2` composite now
length-frames the independently versioned app-random and selectable plans for
the control-protocol v3 setup profile. The third descriptor hands off the
complete composite; the plugin decodes only that current profile and transfers the
selectable continuation into the pinned live catalog owner. The host launch
profile retains and hashes the exact composite for any selectable-enabled node,
uses it in fresh and exact node setup. Negotiation below v3 fails before setup.

The application-random path validates typed `BackendRngEvidence` against the
scheduler-owned scenario and seeded stream, then records canonical `RngDraw`
and `Selection` decisions. One exact-parent branch operation consumes those
validated records and emits only `CampaignBranch` selections. Model samples and
typed replacements consume the scenario draw cap, and checkpoint relaunch
recovers per-node positions from the authoritative named-stream cursor. Raw
app-random schedule decisions are rejected by current runtime admission.

RFC-0014 search choices now retain their typed candidate meaning across the
runtime frontier. Outcome searches publish Boolean domains. Transition and
parameter searches publish stable discrete alternatives derived from their
canonical object or typed-value identities, with an explicit unmodified
alternative where the model can produce a value outside the branch list. The
campaign adapter reconstructs and authenticates those records before emitting
the original finite override index consumed by the unchanged typed effect
adapter. Index-only and unknown candidate tags fail closed in runtime override
decoding and campaign promotion; there is no alternate domain beside the typed
path. Current fault-runtime checkpoints require the typed override identity and
reject every noncurrent checkpoint at admission.

The public static `crucible-guest` product client now constructs discrete and
unsigned-integral registrations and requests from the L1 protocol-owned
`ChoiceDomain` and `ChoiceValue` representation. A cross-codec conformance test
requires those bytes to match the coordinator's campaign-semantic decoder
without giving the in-guest crate an L3 dependency. The actual
network-product initramfs registers a required recovery-policy choice and a
required stepped retry-quanta choice, blocks on both through the supported
guest CLI, and makes the returned values change a guest-originated Ethernet
frame. `checks.crucible.phase4.packagedCampaignChoiceVm` drives that guest
through the public campaign executor, answers a discrete request, and captures
a subsequent pending integral request in an exact checkpoint. It restarts the
daemon while that request remains unanswered, proves the opportunity, branch
point, parent, and domain are unchanged, and supplies the integral reply. The
selected guest runs in a fresh QEMU/plugin process; a second daemon/QEMU
restart then proves exact resume and post-resume progress. Together with the
production checkpoint-manifest version-9 codec tests, this is the automated
prerequisite for T-CAM-2.8. The task remains unchecked until the §14 Phase 2
operator flight records its required human acceptance evidence.

## 11.5 Phase 3 — Measurements and objectives

Primary crates: `crucible`, `crucible-guest`, `crucible-qemu-plugin`, and
`crucible-api`.

- [x] **T-CAM-3.1** Add scenario measurement definitions, boundary selectors,
  cohort rules, metric types, exact aggregations, and canonical stop outcomes.
  The pure scenario-owned v1 definition component now provides bounded static
  boundary selectors, validated node cohorts, typed metric sources and values,
  exact aggregation declarations, deterministic ordering, and scenario-v6
  identity/serialization under its sole current schema. The pure
  bounded v1 replay evaluator now authenticates dense scheduler entries,
  resolves compound/cohort boundaries and modeled timeouts, retains canonical
  satisfying evidence, and recomputes exact integer, rational, histogram, and
  delta aggregates. Campaign measurement-set v2 retains the exact verified
  evaluation/definition identities and payload behind a model-specific verifier.
  Every production result constructor now requires the complete raw replay-leaf
  set explicitly and rejects missing, duplicate, or unowned leaves. The
  publication path independently normalizes guest samples, derives every
  model-owned source from the authenticated dense scheduler log, merges them
  under common bounds, and retains the exact log, terminal state, definition
  identity, and stop evidence needed to reproduce each aggregate used by an
  objective or finding.
- [x] **T-CAM-3.2** Add guest measurement begin/sample/end and semantic-marker
  protocol messages with scenario validation and limits.
  Doorbell protocol v3 now provides four byte-exact bounded kinds, seven closed
  typed value forms, canonical rational/vector/detail validation, guest CLI
  producers, and typed observational event-catalog projection. The fresh QEMU
  campaign driver enforces declared measurement/metric/source/type/cohort and
  exact marker-instance contracts, bounds simultaneous instances, requires a
  balanced begin/sample/end lifecycle, and feeds normalized guest samples into
  the verified measurement evaluator. ABI, malformed-message, typed event,
  exact-instance, and driver lifecycle regressions cover the boundary.
- [x] **T-CAM-3.3** Derive model-owned network, storage, scheduler, icount, and
  virtual-time metrics from canonical events.
  The pure bounded projector now authenticates the dense scheduler log, derives
  every closed v1 model source from exact typed event fields, fails closed on
  malformed source events, and merges replay-identical model samples with the
  independently validated guest stream before common windowing and exact
  aggregation. Source, replay, malformed-event, visit-bound, and end-to-end
  driver regressions pin the projection and retained evaluation.
- [x] **T-CAM-3.4** Implement observation, objective-evaluation, Pareto,
  lexicographic, top-`K`, fairness-reserve, and explanation records.
  The canonical bounded observation, verified-evaluation measurement-set v2,
  property-verdict-set, and coverage-projection record layer now feeds exact
  signed, unsigned, and reduced-rational objective values. Arbitrary-precision
  reduced reward arithmetic, Pareto/lexicographic/weighted top-`K` ranking,
  breadth-first and novelty reserves, and complete selected/filtered/dominated/
  pruned explanations are content-addressed and replay-validated. The Crucible
  adapter authenticates its exact model evaluation before projecting numeric
  aggregates. Candidate, aggregate-evidence-byte, Pareto-work, scalar-work,
  magnitude, and encoded-record bounds fail closed before unbounded work or
  publication, and repository publication preflights the complete dependency
  union before its first write.
  Exact-arithmetic, input-order, reserve, filtering, work-bound, model-adapter,
  failure-atomicity, load, and idempotent-replay regressions cover the contract.
  The integrated Phase 3 measurement/finding flight remains open under
  T-CAM-3.6.
- [x] **T-CAM-3.5** Extend finding artifacts and retention policy with exact
  pre/post-failure pins and measurement/evidence closure.
  Canonical bounded finding signatures, clusters, exact observation-owned
  measurement/evidence child closures, and self-contained reproduction records
  are implemented. Schema-v2 findings retain independently bounded
  pre-failure, last-successful-measurement, post-failure, and additional exact
  checkpoint roles. The daemon authenticates at most 4,096 exact candidates
  and deterministically selects nearest event boundaries with content-address
  tie-breaking. Crucible minimization is bounded by 4,096 candidates and
  128 MiB of conservative candidate-copy work; its seed/bounds, dense candidate
  history, observed fingerprints, accepted result, and final replay state are
  retained in verifier-backed reproduction schema v2. The repository preflights
  original/artifact bases before writes, atomically clusters occurrences and
  role sets, and revalidates the complete contract on import/restart. Paged
  proof-authenticated finding and finding-object queries are implemented. The
  integrated Phase 3 flight remains open under T-CAM-3.6.
- [ ] **T-CAM-3.6** Have an independent reviewer cross-check guest convergence
  markers, model-derived traffic evidence, measurement windows, objective
  ranking, and one known finding in the §14 Phase 3 flight.
  The automated prerequisite now runs exact selectors for all model-owned
  sample sources, mixed guest/model raw-evidence replay, and an objective driven
  only by the verified retained publication. The task remains open for the
  independent operator flight and review record.

**Gates:** `gate:campaign-model`, `gate:campaign-replay`, guest protocol
extensions under `gate:abi-conformance`.

**Manual gate:** accepted §14 Phase 3 measurement/finding flight.

## 11.6 Phase 4 — Lazy local campaign supervisor

`checks.crucible.phase4.projectQuotaVm` now exercises the production
`crucible-linux-resource` API against real ext4 inside a disposable Firecracker
guest. Unprivileged writers encounter both hard-byte and hard-inode quota
limits; a nonempty release retains its exact authority, and emptied/released
projects can be reused. The host needs KVM, not an ext4 mount or quota changes.
The 2026-09-04 flight passed.
This isolates storage enforcement; complete packaged-QEMU resource/recovery
and operator flights remain separate requirements.

`checks.crucible.phase4.qemuHostOwnerVm` additionally exercises the combined
production cgroup/project-quota owner with real QEMU and its guarded image
helper. The 2026-09-04 flight passed twice through a single project-ID slot,
checking exclusive namespace acquisition, unprivileged child credentials,
installed CPU/memory/task limits, sticky cancellation, direct-child reap, and
removal of both the attempt cgroup and storage tree.
The first flight exposed missing `CONFIG_CFS_BANDWIDTH` in the AOS kernel;
the standard kernel now enables CPU bandwidth and built-in project-quota
support. The check uses that standard kernel without a test-only override.
It verifies limit installation, not CPU-pressure or OOM stress, and does not
close the campaign-level execution, recovery, or independent operator gates.

`checks.crucible.phase4.packagedCampaignVm` now exercises public CLI scenario,
lineage, and policy compilation, verified import, campaign creation, and two
production service startups with native baked-genesis capture. The 2026-09-04
flight passed.
It exposed and now covers independent configuration-payload/checkpoint-closure
versions and private debugger sockets surviving guarded directory rebinding.
The campaign head survives restart unchanged and the executor endpoint is
removed on each orderly shutdown. The extended 2026-09-04 flight also passed
public attempt-budget grant, start, first discovery admission, authenticated
`terminal-success` explanation, and guarded executor shutdown.
The coordinator now derives the unique empty-path genesis discovery for an
otherwise empty frontier; cold validation recomputes its grant, lifecycle,
ordinal, and exact accounting delta. The flight also exposed skipped genesis
entrypoints: initial observation records had already moved evaluation past
genesis. Production now fires entrypoints before those records and evaluates
conditional events afterward. No-backend regressions cover terminal entrypoints,
dependent events, and non-repetition.

The subsequent 2026-09-04 flight also passes delayed completion after real guest
execution, with all three cases passing.
Packaged CLI execution now defaults to a 1,000,000-instruction rendezvous,
preserving explicit interval overrides and the existing non-packaged default.
The delayed scenario completes at the first rendezvous after baked genesis;
the public explanation authenticates its terminal result and unchanged
decision-free configuration.
The subsequent exact-time single-VM flight passes a compound `At`/`After`/`Timer`
completion between rendezvous. Production projects rising and falling
time-predicate edges from durable event-graph state and currently armed timers
into a dedicated exact scheduler cap, independent of signal-fault cadence.
Unrepresentable coordinates fail closed instead of rounding an equality
predicate. A separate possible-activation projection preserves quiescence
semantics for bookkeeping-only edges. Time-dependent events do not consume
one-shots, update edge truth, or latch `Once` while a leading node's observation
is ahead of the shared frontier. Unit coverage includes independent fault
deadlines, repeatable pulses, timer replacement/cancellation, overflow, stale
caps, skewed evaluation, and reconstruction from portable trigger state.

The two-VM extension exposed an invalid uniqueness requirement on immutable
QEMU snapshot content in portable checkpoint manifests. Distinct nodes may
share identical snapshot bytes; their separate target manifests authenticate
node ownership, artifacts, counters, and fault continuation. The content
uniqueness check is removed, while duplicate node identities and foreign-node
target authentication remain rejected and covered by regressions.
The first five packaged VM flights pass, including the compound exact-time
completion across two VMs. The flight's explanation read refreshes only an
explicit stale-head response under its original deadline, because completion
feedback may advance the campaign between status and snapshot-bound query.
Other query or execution errors remain failures.

The sixth packaged flight passes `At(0)` and `After(0)` followed by a timer at
logical time 3. Baked-ready physical counters already map to logical time zero;
the new flight exercises that existing origin through real packaged execution.

Inactive scheduler nodes no longer constrain the live frontier or contribute
stale vCPU quiescence blockers. Removing a lagging node publishes the frontier
its peers have already reached. With no active node, the host clock can advance
to its next trigger, signal-fault, or topology evaluation without issuing a
backend RUN, still respecting branch and terminal time caps. Reactivation
preserves physical counters and remaining native timer durations while joining
the current frontier. Overflow and duplicate identities reject an activity
batch before publication. Regressions cover serial/concurrent/checkpoint
equivalence, nonzero initial inactive clocks, and future topology activation.

The full affected test sweep now passes. The standalone core sweep passes 967
tests, including the source-size guard.
Focused module splits separate lifecycle construction, repository dispatch,
channel contracts, QMP command encoding, thread-inventory decoding, and
hot-fork ownership tests. All six formerly oversized files now fit the default
source limits, and three obsolete debt exceptions are removed; no limit was
increased or test skipped. The production API suite passes 255 unit tests,
including restored trigger settlement with no active node; the QEMU suite
passes 611 unit tests with one existing ignored test. Affected integrations
and strict Clippy checks also pass.

The terminal `checks.crucible.phase7.gates.signalFaultSystem` gate consumes one
current production-QEMU equivalence flight for network, block, 9p, and node
behavior. Its exact source boundary precedes the event with a live queue
reservation that extends through the event coordinate and an occupied volatile
block cache. The shared event powers down that queue's routed forwarder, loses
the declared volatile block cache, and permanently fails one QEMU node at one
authenticated coordinate. A bounded 9p read fault reaches the guest, and the
guest has already completed the HTTP 200, block, and 9p application checks. The
same flight then powers off every remaining node, observes the inactive world
without a backend RUN, boots one node, and observes resumed guest progress.
Locked fresh replay, exact restore, and hot-fork children must reproduce the
fault evidence and continuation fingerprints from that pre-event boundary.

This flight required event-binding deadlines to remain schedulable without a
running VM, failed-node checkpoint counters to retain their scheduler-owned
origins, and the atomic QEMU integration to tolerate the virtio-net announcement timer removed
by exact restore. The patch does not recreate migration announcements. Canonical
source regeneration and the focused source-attribution check pass; the generic
boot probe is non-discriminating, so the reactivation flight supplies
the behavioral evidence. After retaining nested launch diagnostics, the full
packaged shared-cause check passes both the original flight and the added Boot
flight, including fresh-process inactive restore. An earlier invocation failed
at live-node assembly without retaining its underlying cause; the later pass
does not establish the cause of that transient failure.

These flights do not prove guest-choice branching, the full public
checkpoint-pause recovery workflow, or hot-fork acceptance.
The hot-fork world inventory now retains the paused process and physical clock
of a powered-off node, and world assembly requires that source's child rather
than omitting it as if permanently failed. Capture accepts a settled committed
lifecycle journal while still rejecting unfinished journal owners, staged
replacements, cleanup failures, and incomplete transaction phases. Six new API
regressions cover those ownership distinctions; the full API suite passes 265
tests. The reactivation flight additionally checks the real inactive world's
source-process distinction before its exact checkpoint. The production world
factory now forks and adopts powered-off children with their retained service
state, including them in atomic assembly and source reconciliation. The
flight alone does not prove branch-private disk handoff.
Longer diagnostic execution also stalled waiting for a post-device control
acknowledgement and returned cleanup-pending on shutdown; the short successful
flight does not close that liveness investigation.

The production hot-fork handoff now provisions a distinct target run directory
with pinned VMState and root-overlay files for each child. QEMU copies the
frozen source's writable overlay into the target, and the host authenticates
the child-file proof and named directory before lifecycle adoption. The
supervisor-owned mode-`0700` attempt root prevents the child from replacing its
generation directory entry afterward. Lifecycle generation ownership uses that
path under the parent-ownership constraint. Exact checkpoint capture instead
opens the root overlay through the retained directory descriptor and checks its
inode before reading bytes, so a child-side symlink or regular-file replacement
cannot substitute the source artifact.

Repository-wide gate maintenance restores campaign-model phase ordering and
per-layer coverage, with negative checks for every required public repository
and recovery proof. Rustdoc, checklist consistency, and bounded-wait/test-rerun
classification checks pass. The license-boundary source suite passes, but the
complete packaged license-boundary check remains blocked by controller
engineering-hygiene size/boundary findings. Nondeterminism confinement now passes:
canonical-planner, hot-pool admission, hot-child wait, QMP, and image-helper clocks
are private operational supervision capabilities, with no raw host timestamp
export from those lifecycle interfaces. The complete harness-lint suite passes
25 tests, alongside 259 API, 462 daemon, and 612 QEMU unit tests (the latter two
retain one subprocess fixture ignored by direct execution). Strict affected-crate
Clippy passes. A watchdog regression now establishes the real process stop before
expiring the production watchdog wait, removing a controller-startup timing race
without weakening the direct-resume or completion/disarm assertions. Hot-checkpoint
resource accounting, pressure plans, scoring, pool errors, and Linux fork
reconciliation now occupy focused modules with their existing public paths and
ownership scope retained. The refactor passes the full daemon suite, strict
Clippy, and warning-free documentation without increasing size exemptions. The
remaining engineering-hygiene findings
are separate from the passing standalone source-size guard above; no complete
packaging or release-gate closure is claimed.

A sweep of every `checks.crucible` attribute, evaluated under `tryEval` on
this branch and on a detached `origin/master` worktree, separated the gates
this branch had broken from the ones master already fails. The branch's share
is repaired: version literals follow the bumped shmem ABI, event-kind
catalog, golden-vector, block-wire, plugin-API, and doorbell-frame constants;
the package-set gates know the campaign, Linux resource, S3 store, and debug
gateway crates and read RFC-0020 spec-index references; gates whose needles
moved into split modules read the module tree through
`_rust-module-source.nix`; the RFC-0010 11.3 patch catalog carries a row for
every shipped patch with manifest-matching classes and tokens; and the
control-plane and single-scheduler boundary gates follow 04a's daemon-hosted
executor. Four failures found on master too were fixed here because they
blocked evaluation outright: the phase-0 aarch64 kernel source import, the
phase-1 workspace build's missing `gdb`, and the phase-0 S12/S14 checks that
copied a developer's whole cargo target directory into the store.
The sweep started from 107 failing attributes on the branch against 66 on master before master's evaluation aborted in its phase 7 packaging checks. After the repairs the branch fails 56: 54 that master fails too, among them the eleven `phase1.spatial*` gates whose model items exist in neither tree, the engineering-hygiene file-size findings, and the phase 6 debug and triage gates that name an ADV-28 wording neither chapter carries; the reproduction-artifact format gate, whose inputs are byte-identical to master's; and `referenceIntegrity`, which only reports that those checks do not evaluate. Twelve gates master fails now pass here. The shared failures are master debt and stay out of this branch's scope.

Building `checks.crucible.phase2.gates.typedChoice` on a quiet host then
exercised the packaged `crucible-controller` test run behind the
license-boundary gate, which fails on this branch for four harness gates and
two timeouts. Three of the four were this branch's: the QMP client had grown
to 3,066 lines past the source-size guard, and its public hot-fork surface now
lives in `qmp/hot_fork_stages.rs` and `qmp/hot_fork_coordinator.rs`; the
flaky-is-failing lint had no baseline rows for the flights' bounded process
polls; and the phase-plan harness rejected the source-set lifecycle
registration for lacking explicit task ids. The three `ten_thousand_*`
repository scale tests take several minutes each in release, so nextest's
default two-minute budget timed them out deterministically; a per-test
override now gives them ten. The fourth gate, the engineering-hygiene size
findings, fails on master too and stays open, so the packaged
license-boundary gate remains red for that reason alone.

The live-network adversary now prepares both its controller and independent
resume watchdog before the caller publishes guest work. A readiness handshake
removes thread creation from the publication-to-first-stop interval; the
two-second safety clock starts only when the pending-work barrier is released,
not during guest priming. Completed work still fails first-stop certification,
with the effective ceiling, completed coordinate, and frame counts retained in
the error instead of guest payloads. Regressions cover priming beyond the
watchdog interval, cancellation before release, and completed-boundary
diagnostics. All 615 QEMU unit tests pass, with one existing ignored subprocess
fixture, and strict Clippy passes. The updated real-QEMU network flight passes
all six stops, pending-work overlap, exact retained retry, fresh-process restore,
matching network evidence, and orderly exit. A diagnostic-only flight before
the startup change also passed, so these results do not establish the cause of
the earlier intermittent first-stop failure. The complete packaged network
gate also passes, including the production two-VM hostless link, loss branch,
exact restore, and packet/fault-decision continuation. The archived integration
gate also passed at this checkpoint. Validation of later changes
and the separate longer-run acknowledgement/cleanup investigation remain open.

Current campaign snapshots carry a childless aggregate budget ledger. Genesis starts empty; every successor authenticates exact grant and
spending deltas. New proposals and unique attempts require aggregate allowance,
in addition to request-local limits. Additional causes do not spend another
attempt, and exact retries spend neither resource. Owner preflight rejects
unfunded issuance before publishing its work; final head acceptance and cold
validation independently check the ledger. A forged grant total or an
unbudgeted successor fails closed.

`CampaignRepository::budget_projection` reads the mandatory current version-2
indexed ledger after head authentication. Additive `u64` grants sum exactly in
`u128`; missing or non-version-2 ledgers fail closed. Planner drivers bound
invocation output by available allowance, return a waitable budget-blocked
outcome, and avoid reinvoking on an unchanged blocked head. A later grant
permits a fresh invocation.

Canonical engine version 8 and PUCT engine version 6 advertise the versioned
`canonical-frontier-budget-v1` capability. Every Ready offer retains its exact
owner-computed aggregate allowances and semantic new-attempt cost, including
unaffordable offers. Both engines scan through EOF and choose only affordable
candidates; a convergent cause can therefore pass a canonical or higher-ranked
PUCT candidate that needs an unfunded attempt. Current portable state retains
blockers across pages and empty EOF.
Acceptance and cold validation recompute eligibility before trusting it;
missing records, inflated allowances, and forged deduplication costs fail
closed before publication.

Campaign regressions exercise both engines with wide and single-position
pages, reconstruct the owner after each accepted page, restore portable state
from retained objects, verify additional-cause accounting, and resume new
attempts after a grant. A checked-client driver regression separately proves
cross-page restart and unchanged-head call suppression without settling the
blocked frontier. A mutation-scale flight completes 10,000 real grant,
branch-request, proposal, and admission transitions: 2,500 separately funded
proposals converge on one execution basis. Every iteration checks exact ledger
totals; cold validation, deep grant/proposal/admission retries, and rejection of
a valid unfunded next proposal preserve the final ledger and publish no retry
or rejected work. These are repository and planner results, not evidence for
the separate real-QEMU child-lifecycle, pressure, or dogfood stress gates.

This increment passes 246 campaign unit tests and both integration tests, 255
API unit tests, 269 CLI tests, and 459 daemon tests with one existing ignored
test. Strict affected-crate Clippy and the source-size guard pass. All six
packaged campaign VM cases also pass with the budget-aware planner build;
their execution scope remains the six flights described above.

Canonical engine version 8 and PUCT engine version 6 consume
owner-authenticated request-local attempt allowances. They pass capped new
attempts, settle a frontier blocked only by local caps, and retain eligibility
for a convergent cause without charging another attempt. An aggregate grant
does not reset the local cap. The owner rejects an inflated local allowance
before publishing objects.

Version-2 budget ledgers authenticate a mandatory nested request-spending Merkle map.
Each request's spent allowance is the exact entry count of its execution-basis
map, so admission and candidate projection avoid a campaign-history scan.
Successors update only newly admitted execution bases. Cold validation
reconstructs the same roots and rejects a forged index even when aggregate
totals are unchanged. Any schema other than version 2, or a ledger without the
request-spending map, fails closed before a transition can publish.

The distinct-request scale flight exposed two unrelated history-wide scans in
planner invocation preparation. New campaigns now maintain an authenticated
ordered position index in their exploration root; request transitions update
its branch-point/schema/digest order, and cold validation rejects omitted or
forged positions. Invocation preparation also reuses already-authenticated head
roots instead of rewalking the retained graph for each page, while still
checking new dependencies and the complete closure bound.

The request-local-cap increment passes all 253 campaign unit tests and both
integration tests across the complete unit/integration sweep and focused scale
runs. The three non-ignored 10,000-mutation flights cover mixed request/control
transitions, convergent budget spending, and 2,500 distinct capped requests.
The distinct-request flight checks at most 66 backend reads for each indexed
cap lookup, at most 16,384 reads per 64-position invocation page, exact
aggregate and request-local accounting, complete frontier settlement, and final
cold validation. A separate current-schema regression compares indexed pages
at widths 1, 3, and 7 and rejects noncurrent keys and a forged index without
validation writes. Request-local regressions cover both engines,
single-position/wide pages, restart, local-cap settlement, grant behavior,
convergent causes, and forged eligibility. API, CLI, and daemon suites pass
255, 269, and 459 tests respectively, with one existing ignored daemon test;
strict affected-crate Clippy and the source-size guard also pass. These are
repository/planner scale results, not real-QEMU lifecycle or pressure evidence.
All six packaged campaign VM cases also pass with the indexed request-budget
and ordered-frontier build; their execution scope remains unchanged.

Primary crates: `crucible`, `crucible-cas`, `crucible-api`, and
`crucible-daemon`.

- [x] **T-CAM-4.1** Implement bounded finite and versioned generated
  `CandidateSource` forms plus generator specs for all/discrete, boundary,
  stratified, logarithmic, permuted, progressive integer, corpus mutation, and
  model-bound uniform integer permutation through the full unsigned 64-bit
  app-random domain.
- [x] **T-CAM-4.2** Implement branch request/cause, branch-edge deduplication,
  discovery-versus-branch attempt starts, immutable attempt execution basis,
  global admission ordinal, authenticated branch path, additional-cause
  association, proposal, attempt, observation, credit, input-only planner
  invocation, coordinator-accepted planner step/accounting, branch-point
  `ExpansionState`, and per-source portable continuation state.
  Canonical records and repository owner transitions now cover every listed
  basis. Proposal admission assigns one global ordinal, deduplicates an exact
  execution basis while retaining later causes, and authenticates scoped path
  prefixes; strict observations commit in that global order. Planner Issue
  accepts only an exact served input page, atomically publishes its step,
  proposals, admissions, and accounting, and preserves replay identity.
  Branch-request, proposal, admission, observation, credit, expansion, and
  continuation transitions are recomputed during import and restart, with
  local/replay/convergence regressions covering each owner boundary.
- [x] **T-CAM-4.3** Implement progressive-widening exact rational rules,
  interval refinement, deterministic PUCT, coverage/rarity/assertion/objective
  guidance, and path backpropagation. New branch paths now retain exact
  branch-point/edge segments under schema version 2. Current observation and
  branch-point credits survive replay and restart and drive exact completed-visit counts;
  schema-v4 observation transitions additionally retain every cumulative path
  under its exact child configuration, and direct non-genesis admission
  authenticates its prefix against that nested index after restart/import.
  Atomic planner `Issue` chooses the lowest authenticated parent path, requires
  it to be scoped version 2, derives the cumulative attempt, and recomputes the
  same owner rule after convergence and restart. The exact fixed-point PUCT
  term arithmetic, including staged rounding, integer square root, input
  invariants, and saturation, is implemented and conformance-tested. The
  progressive-widening `0`, `1/2`, and `1` exponent owner is also implemented
  with exact irrational comparison, initial allocation, visit-floor, ceiling,
  and overflow semantics. The repository now also rebuilds a bounded exact
  `BranchEdgeId` visit partition from idempotent observation credits and scoped
  path segments, with restart equality and duplicate-credit protection. A
  policy-bound projection normalizes one-million-micro proposal prior mass exactly,
  reserves fairness for the least-visited canonical edge, folds globally unique
  coverage identities from the exact canonical observation set under explicit
  root/observation/identity/byte bounds, folds owner-verified finding
  occurrences through three closed positive policy-guidance signals under
  finding-root/occurrence/body bounds, folds exact owner-published objective
  evaluations through a 65,536-record/128-MiB shared batch, and
  derives the active policy's exact edge scores with restart equality. Canonical
  PUCT engine version 6 consumes those completed/prospective explicit,
  modeled-finite, or uniform-prior, novelty, finding-reward, and fairness terms
  from exact owner-built guidance for every Ready offer. It carries the best score across pages,
  publishes guidance only after zero-write preflight, and reruns identically on
  restart/import. The request projector batches unique branch points, scans the
  canonical observation/finding roots once, charges 65,536 aggregate credits,
  128 MiB of credit/path bodies, 65,536 unique objective evaluations and 128
  MiB of their deduplicated evaluation/observation/property basis bodies, 128
  MiB of unique choice-domain bodies, and unique prior-provenance records within
  the existing visit-projection byte cap. Branch-request schema v9 contains
  bounded positive explicit finite weights and finite masses bound to the exact
  model named by the opportunity; the owner selects the earliest
  credited execution basis per semantic edge and normalizes completed plus one
  prospective offer with exact edge-ordered remainder distribution. Uniform
  and generated sources remain weight one. Schema-v9 request identities are
  the sole current encoding for every supported source form.
  Prospective bases are shared by branch point/raw weight and
  capped at 1,000,000 completed-edge visits per planner page.
  Progressive-integer implementation version 16 uses the exact prefix and visit
  gates while ranking remaining intervals by inverse-frequency rarity, finding
  reward, unique coverage, objective reward, landmarks, endpoint PUCT-score
  difference, interval size, and lower offset. It uses the exact active policy
  and planning view, batches branch-point projections under the established
  guidance bounds, preserves the already-proposed value set, and revalidates
  identically after restart/import. Branch-request schema v9 and generator
  implementation version 17 resolve standardized uniform
  app-random models into a request-keyed, budget-bounded power-of-two integer
  permutation. Exact model/generator/domain validation, zero-write mismatch
  rejection, `2^64` closed-versus-exhausted semantics, and restart replay are
  covered. The standardized model surface is therefore complete: uniform
  application randomness is the only currently registered non-finite model
  family. A future opaque family requires its own concrete adapter and
  versioned portable generator contract, but does not leave this task open.
  Local issue and restart/import replay reject any substituted value or
  noncurrent implementation version before writes.
- [x] **T-CAM-4.4** Replace checkpoint-once frontier authority with branch-point
  source continuations, an attempt-level rebuildable queue, and volatile
  daemon-epoch reservations.
  The repository checkpoint now provides snapshot-bound, bounded accounting
  scans that authenticate canonical attempt membership, exclude completed
  observations, remain page-size independent to EOF, and rebuild identically
  through a fresh repository. Its bounded process-local reservation table is
  idempotent per worker slot, rejects stale epoch/generation releases, and
  restarts empty under a fresh daemon epoch. These owner primitives are
  integrated by the T-CAM-4.5 supervisor. The reward/novelty-sensitive
  generator versions described below completed under T-CAM-4.3. The repository
  also maintains a compact snapshot-authenticated continuation projection for
  each request and serves bounded proof-bearing frontier pages. Finite request,
  proposal, and admission transitions are owner-recomputed during import.
  Implementation-version 2 `all`
  generators over Boolean and discrete domains use the same exact ordinal and
  continuation fold as finite sources. Implementation-version 3
  `boundary_integer` adds a bounded exact static integer ordering, and
  implementation-version 4 `stratified_integer` adds a checked constant-space
  ordinal mapping capped at 4,096 strata. Implementation-version 5
  `log_integer` adds an at-most-65-value exact rounded-power ordering for
  strictly positive domains. Implementation-version 7 `weighted_categorical` adds exact
  request-keyed integer-weight sampling without replacement over at most 256
  discrete alternatives, including bounded rejection sampling and restart
  replay. Implementation-version 8 `ordered_mixture` recursively schedules
  executable finite children by exact weighted virtual finish time, suppresses
  duplicate values while advancing their provenance, and enforces 512-value,
  8,192-work-unit, and 64-level bounds. Implementation-version 10
  `mutate_near_corpus` derives exact
  retained completed integer selections at the request's branch point, emits
  canonical lower-then-upper legal-step neighbors, and uses the immutable
  request's exact previously proposed value set as its portable continuation so
  corpus growth cannot reinterpret prior proposals. It enforces 4,096-credit,
  4,096-distance, 4,096-proposal, 65,536-work-unit, 128-MiB canonical credit-
  body, and existing 4,096-ID/128-MiB selection-resolution bounds during local
  acceptance, import, and restart. It waits for another completed credit when
  the current retained corpus has no unproposed mutation and closes only at its
  proposal budget. Implementation-version 16 `progressive_integer` uses the
  exact stratified prefix, checked visit thresholds, 4,096-strata/proposal
  bounds, and observation-driven frontier wakeups through a branch-point
  request index. It ranks intervals by inverse-frequency rarity, finding reward,
  unique coverage, objective reward, landmarks, endpoint PUCT-score difference,
  interval size, and lower offset. Planner input construction batches those snapshot-bound
  projections, and owner validation rejects a substituted value or noncurrent
  implementation before writes and replays the selected value after restart.
  Static continuation projection remains valid after modeled
  observations exist: it
  binds the exact observation root and projects exact completed visits from
  canonical branch-point credit sets. The independent exact PUCT arithmetic and
  guidance projection are consumed only by the current canonical frontier
  engine. Other generated
  requests remain conservatively `Open` and fail closed when proposal or
  expansion semantics are requested. Noncurrent snapshots remain unindexed and
  queries fail closed rather than constructing a partial index.
- [x] **T-CAM-4.5** Implement `CampaignSupervisor`, `CampaignProjector`,
  `ProposalPlanner`, `AttemptQueue`, and a bounded local `WorkerPool`.
  A coordinator-owned `CampaignPlannerDriver` now reconstructs the exact
  portable state and same-view `ContinueScan` cursor from the authenticated
  planner head before each bounded component call, suppresses reinvocation of
  a terminal unchanged view, verifies exact repository/client planner
  authority and engine/artifact/state configuration before writes, and holds no
  repository mutation ownership across component execution. Restart and
  concurrent-head-change regressions cover cursor continuity and stale
  acceptance.
  The standalone bounded `AttemptQueue` reservation primitive and the daemon's
  single-host `LocalExecutorSupervisor` are implemented. The latter enforces
  exact assignment replay, aggregate slot/CPU/memory/disk capacity, a bounded
  pending queue, durable completion/cancellation races, and restart replacement
  of stale executions. The local worker now resolves repository-authenticated
  attempt inputs behind an execution-model trait, publishes a completely
  preflighted immutable observation-candidate bundle without advancing campaign
  state, and returns results to the supervisor actor for durable completion or
  bounded retry without holding supervisor state during guest execution.
  A coordinator-owned `CampaignExecutorDriver` now pages authenticated
  claimable attempts into exact bounded reservations, derives one deterministic
  assignment per lease, then polls its exact execution through the read-only
  status operation without growing assignment history. It retains the exact
  submit or status request across commit-indeterminate failure and invokes the
  checked direct/RPC executor boundary
  without repository mutation ownership, authenticates and incorporates
  completed observations, and rebuilds from semantic roots after restart.
  Retryable executor rejection rotates the assignment identity, authorization
  failure remains operational, and the sole eligible local executor's stable
  incompatibility closes the exact admission ordinal through the imported-
  validated `AttemptClosed` owner transition.
  A startup-fixed `LocalExecutorWorkerPool` now creates at most 256 workers and
  never more than the supervisor's advertised execution slots. Its cloneable
  checked service keeps repository-backed admission, guest execution,
  candidate preflight, and immutable publication outside the short supervisor
  actor. Linear phase tokens preserve execute-once semantics across retryable
  publication/ledger failure; sticky shutdown cancels in-flight work, drains
  queued work without launching it, and releases capacity only after worker
  exit. Blocked-guest, blocked-admission, queued-shutdown, retry, and caught-
  panic regressions exercise the responsive bounded owner.
  A fixed local executor listener now lends cloneable pool-service handles to
  at most 256 connection workers, retains at most 1,024 pending sockets, and
  caps one connection at 65,536 complete requests. It authenticates one exact
  effective UID/GID through Linux `SO_PEERCRED` before decoding component
  bytes, rejects excess or foreign sockets, distinguishes protocol from service
  failure telemetry, interrupts active connections on sticky shutdown, and
  joins every connection worker before returning. Its managed endpoint retains
  a separate lifetime namespace lock and exact socket inode until join while
  reusing the campaign endpoint's path, owner, mode, stale-recovery, and safe
  teardown contract. Campaign and executor sockets can coexist in one secure
  directory without sharing namespace authority. A coupled executor-service
  owner can obtain its component service only from the exact fixed semantic
  pool; service shutdown closes admission, cancels active attempts, interrupts
  connections, and joins both worker domains. Terminal semantic worker
  completion closes the listener, and worker poison takes precedence over an
  ordinary listener result. The unserved-owner drop backstop also joins the
  semantic pool before releasing the endpoint namespace. The daemon now also
  composes the concrete fresh/thin-replay QEMU worker, shared aggregate host
  allocator, disjoint stable per-worker recovery roots, durable assignment
  ledger, managed endpoint, runtime, and campaign service from one strict
  owner-only deployment file. Exact checkpoint objects are published through
  the exact composed campaign store retained by that service owner; no second
  checkpoint-backend path can diverge from campaign closure authentication or
  physical GC inventory. Worker count is fixed at startup and
  cannot exceed the admitted slot ceiling.
  A bounded `CampaignSupervisor` now composes one planner driver and one
  executor driver over the same repository, reloads exact lifecycle intent on
  every step, and performs at most one component operation. Running execution
  drains before one planner invocation is enabled; paused campaigns issue no
  new work. Drain polls only held reservations, cancel-and-retry cancels one
  exact execution or releases one unaccepted lease per step, and exact-
  checkpoint issues one exact-basis checkpoint request per step while retaining
  the reservation through publication and durable pause.
  A daemon-owned `CampaignRuntime` now gives that step machine one fixed
  long-lived thread, sticky shutdown, explicit progress wakeups, and a startup-
  bounded 1 ms through 60 s fallback poll for asynchronous executor progress.
  It continues immediately only after an outcome that can make another bounded
  transition, inserts an interruptible 1 ms fairness pause after at most 256
  immediate operations, reports terminal component failures to its join owner,
  and does not add a second modeled-work queue. The daemon bootstrap now
  attaches a startup-fixed set of 1 through 256 unique explicitly named
  existing campaigns to packaged canonical planner workers and matched
  authenticated local executors. It negotiates each executor
  description/lineage/resources basis before publishing that attachment's
  planner basis, prepares and sorts the complete set by canonical campaign
  name before any runtime starts, starts only after the CampaignService
  endpoint is acquired, and couples any runtime failure or process shutdown to
  listener shutdown and complete worker join. One packaged local QEMU executor
  may now own the fixed workers and aggregate capacity for either multiple
  explicitly named campaigns or the complete authenticated
  `--campaign-runtime-all` startup catalog. Discovery uses one stable page and
  fails closed outside 1 through 256 campaigns. The complete set is
  canonicalized and authenticated before host-resource acquisition; every
  lineage must share the exact compatibility profile. Distinct scenario
  artifacts are charged under a 128 MiB aggregate canonical-body bound,
  decoded before host acquisition, and each receives one native baked genesis
  in a closed exact World/scenario promotion catalog. Attempt admission plus
  post-bind attachment through that endpoint require membership in the startup
  scenario catalog. Attachments naming another authenticated executor use that
  executor's own scope.
  The authenticated service now enumerates campaign refs through an explicit
  all-campaign grant using bounded stable ref pages and validates every returned
  head closure. The nested CLI follows those checked pages under explicit page,
  entry, and response-byte budgets and emits resumable structured or human
  reports. The required strict version-two packaged `operations` profile binds
  listener/backlog/request limits, accept and runtime polling, reconnect-stable
  exchange deadlines, planner page/byte/fuel bounds, executor scan work, and
  per-campaign coordinator slots before host acquisition. Automatic allocation
  across multiple incompatible-profile packaged pools and live native-catalog
  expansion are intentionally outside this task: the §04a.4 attachment
  contract declares both future work, and §04a.2 defines one local executor as
  the supported deployment.
  The QEMU realization executor now exposes only a borrowed already-realized
  live-backend facade without generic VMState/process authority, and the daemon
  composes that capability with a pre-launch exact resource guard and mandatory
  teardown session. Guarded executor methods receive the guard during every
  blocking realization operation; failed reap transfers enforcement to
  quarantine instead of releasing it, including a failed launch before active
  backend installation. The Linux process layer now has a sealed pre-`exec`
  primitive that validates cgroup-v2 and sticky cancellation descriptors,
  places the child before QEMU executes, applies a per-file size backstop, and
  refuses implicit image-tool provisioning on the guarded spawn path.
  The Linux authority now creates one exact child below a pinned
  operator-delegated unified cgroup-v2 root, fails closed unless CPU, memory,
  and process controllers are delegated, installs exact
  CPU-rate/memory/no-swap/task ceilings, mints the
  sealed child contract, and retains cgroup kill/event authority for future
  cancellation and reap supervision. Root, configured-group, and failed-setup
  cleanup owners retain one exclusive delegated-namespace lock and pinned
  parent/child identities; setup and release errors return the remaining
  authority instead of dropping it. A concurrently forked child may retain the
  close-on-exec lock description until `exec`, so replacement acquisition
  remains fail closed and retries the transient handoff within its startup
  deadline. Process membership is fixed-memory and bounded to 65,536 tasks.
  The authority derives PID/start-time/executable
  identity from its owned direct child and checks that exact process generation
  on both sides of the scan. It then retains the nonduplicable direct-child wait
  handle in a must-reap authority that rechecks identity before force-kill and
  preserves the handle on every reap error. Failed realizations can consume the
  active node, discard modeled channels/backend authority, and surrender the
  child into that must-reap authority. The retained child carries the
  unforgeable watcher-lifecycle token, rejecting a removed/recreated cgroup at
  the same path. All other cgroup pseudo-file reads are byte-bounded.
  Production child contracts require a configured non-root user and group
  distinct from every real, effective, saved, or supplementary supervisor
  credential; the pre-exec path clears supplementary groups and installs all
  real, effective, and saved IDs after cgroup attachment, with `no_new_privs`
  set first. The delegated hierarchy must not grant those child credentials a
  separate write path to its controls. Exactly one persistent watcher must be
  live before child minting. Cancellation or ordinary finalization makes the
  sticky event readable before publishing terminal state, closes minting, and
  kills and checks the group at a fixed 10 ms cadence until empty. Ordinary
  control failures retry at that cadence with complete authority retained;
  caught invariant panics enter a non-reentrant parked quarantine. A bounded
  wait returns the live watcher on timeout, and dropping an unjoined watcher
  latches closure while its worker retains authority until empty.
  Public guarded preparation now rejects before run-directory access unless the
  command's fixed vCPU, guest-memory, and minimum writable-byte requirements fit
  the exact ceilings sealed into the child contract. The resulting pinned
  authority retains both that basis and the contract's private attempt-
  lifecycle token. Guarded spawn rejects a changed command, resource profile,
  ceiling, or equal-limit contract from another attempt before revalidation or
  descriptor allocation. Exact-checkpoint materialization now requires the
  same contract before path access.
  The writable ceiling also supplies a conservative per-file limit; aggregate
  enforcement now has a crate-internal ext4 project-quota transaction and
  daemon-incarnation storage owner. The owner locks a dedicated private empty
  ext4 root, allocates from a bounded operator-reserved project-ID range, creates
  fixed-width unique child names, installs synchronized/read-back hard block and
  inode limits, assigns the inheritable project ID, transfers exact mode-`0700`
  ownership to the non-root QEMU identity that is distinct from every
  supervisor credential, and synchronizes the parent before exposure.
  Non-aligned byte ceilings round down to the kernel's 1,024-byte
  quota unit. After process reap, descriptor-relative cleanup removes at most
  the configured ceiling of 65,536 named entries without following symlinks or
  crossing filesystems, uses a constant number of open directory descriptors,
  authenticates ascent and child identities, and synchronizes from leaves to
  root. Normal release then restores the empty directory, clears and
  reauthenticates a zero-use quota record, removes the exact named inode,
  synchronizes the root, and only then recycles the project ID. Partial create,
  cleanup, and release failures retain the directory, shared root lock, cleanup
  bound, quota, and ID lease for exact retry; a dirty restart root and an
  unfinished drop both fail closed. A public sealed Linux host facade now pairs
  the exact process and storage owners. It installs storage before exposing a
  process contract, proves reap before synchronous storage cleanup, and
  transfers both retained owners to a nondroppable detached worker with bounded
  retry and panic parking. The combined owner now admits the launch profile and
  creates, owns, and synchronizes fresh monotone generation directories plus
  their empty exact-VMState destinations through its retained attempt-root
  descriptor before lending descriptor-pinned prepared authorities. Every
  generation stays under the one aggregate project quota; issuance retains only
  the next ordinal, while the inode quota bounds allocation and cleanup. Raw
  storage descriptors remain sealed. The production executor selection and
  ext4 enforcement gate are completed by the guarded composition below.
  A prepared run-directory authority now pins the directory and exact regular
  VMState inode without following final symlinks. Guarded spawn reauthenticates
  the entry before allocation, changes directory by descriptor after cgroup and
  cancellation admission, and repeats the inode check immediately before
  credential drop and `exec`; replacement of the diagnostic path therefore
  cannot redirect launch. The production owner must still exclude concurrent
  namespace mutation until QEMU has opened every relative artifact.
  A crate-internal nondroppable process-quarantine worker now accepts only
  lifecycle-matched retained children, an optional not-yet-joined watcher, and
  a cgroup; it retries ordinary cleanup failures, parks with authority after an
  invariant panic, and remains live
  after its observation handle is dropped. A crate-internal attempt-process
  owner now starts the watcher before contract minting, joins and removes the
  group on normal finish, retains bounded raw child handles even when process-
  identity authentication failed, and transfers unfinished state to that
  worker from `Drop`. Concrete launchers retain an unreaped pre-install child
  and reject relaunch; the guarded replay session transfers that authority into
  its abstract attempt guard before returning the realization error. The exact
  process-local cancellation incarnation now supports a bounded blocking wait,
  publishes its predicate under the waiter-registration mutex before waking
  every guard, and fails closed after synchronization poison. The regression
  serializes cancellation against wait registration so the lost-wake ordering
  is deterministic. The process owner can lend a narrow sticky-event signal
  and refuses child-contract access after it fires. The daemon now registers
  exactly one synchronous idempotent resource callback on that incarnation and
  composes it with exact quantum accounting plus an indivisible
  process/filesystem host owner. Exact-limit mismatch and pre-cancellation roll
  back before admission;
  failed reap and live-owner drop transfer the complete host authority to
  quarantine. Linux composition of failed-child and active-node handoff into
  the cgroup owner now has a sealed process-only facade: it validates its
  daemon-incarnation namespace and operational bounds before root access,
  creates unique fixed-width child names, exposes no raw cgroup controls, and
  poisons itself while retaining authority after partial setup. Aggregate
  filesystem-quota reservation, exact run-directory binding, and nondroppable
  process/storage quarantine are now composed by the concrete Linux host owner.
  Descriptor-pinned multi-generation exact-VMState destination preparation and
  its daemon guard capability are now composed by that owner. The concrete
  exact-resume adapter obtains that authority from the guard, streams and
  authenticates the durable root into the pinned inode, installs a root-bound
  real-node launcher, and transfers failed-launch or active-node child authority
  back to the guard on failure. The canonical production lifecycle now retains
  one injected node-launch authority across initial fresh/exact launch,
  modeled crash/restart replacement, and whole-world debugger replay; a replay
  must obtain an independent authority or fail closed. This removes the
  lifecycle's direct-spawn bypass seam while keeping the packaged ordinary
  lifecycle behind an explicit default authority. The same exact
  node-generation request now also moves generation-directory creation,
  `qemu-img` overlay creation, authenticated restore-artifact materialization,
  and replacement cloning behind the launcher before process spawn; the
  lifecycle rejects fresh/exact preparation-kind mismatches before invoking
  it. Exact preparation now lends the complete per-node checkpoint-manifest
  identity and fixed-memory authenticated artifact streams, so the Linux
  launcher writes the retained VMState through its pinned linear transaction
  instead of replacing the inode by path. Each launch now returns a linear lease
  bound to the exact scheduler node and positive process generation. Active and
  staged replacement leases remain disjoint; old leases
  release only after reap attestation, staged leases become active only with
  backend commit, and abort reaps before lease finish. A lease-release failure
  latches quarantine and prevents later aggregate release. Explicit shutdown reaps
  the nodes, finishes every exact generation lease, and then asks the authority
  to attest aggregate release, while failed finish or abandonment transfers
  remaining authority to quarantine. The daemon now provides the bounded join
owner for that contract: it retains one latest generation per scenario node,
rejects stale/reused generation identities, tracks at most the active linear
lease and one staged successor per node, rejects a third generation, and
quarantines the one attempt guard if any lease is dropped or aggregate finish
races a live generation. A daemon lifecycle adapter now implements fresh,
  retained exact, and local replacement generations. Fresh image tools run
  under the same cgroup, cancellation, quota, pinned directory, credential,
  parent-death, and deadline contract; retained exact artifacts stream into
  linear pinned destinations and bind to the complete checkpoint manifest;
  local replacement resolves the retained prior generation and reflinks both
  writable artifacts under the same quota. All three modes launch only through
  guarded entry points. No-process failures roll back the pending generation
  fence for exact retry; an unreaped QEMU or helper child is retained before the
  aggregate owner is quarantined. Every injected production lifecycle launcher
  must now explicitly admit and charge a scheduler quantum before modeled state
  can advance and recheck the retained authority before returning its outcome.
  The daemon launcher binds those calls to the attempt cancellation, host-limit,
  and exact quantum guard, while the packaged non-campaign launcher declares
  its no-op behavior explicitly. Concurrent modeled and post-boundary failures
  remain jointly observable, and an explicit retryable/canceled/terminal class
  survives both lifecycle and scheduler boundaries without diagnostic-text
  parsing. The daemon now composes fresh campaign lifecycle
  construction with that launcher: it rejects exact-resume roots, validates the
  scenario identity and VM-node bound before resource allocation, exact-checks
  the installed limits and cancellation incarnation, and quarantines the guard
  if lifecycle construction fails. An exact-origin worker router now keeps
  fresh execution and durable paused-root resume on disjoint runners without
  collapsing their failure classifications. The fresh runner now lends only
  bounded drive/evidence operations to its modeled driver, retains shutdown
  authority, always performs final drain and process/resource cleanup, and
  passes the drained event-log suffix to a distinct result-sealing phase.
  Cleanup failure takes terminal precedence while retaining an earlier driver
  diagnostic, and the runner itself rejects exact-resume roots before lifecycle
  construction. The fresh runner now reconstructs non-genesis discovery starts
  whose schedules contain only deterministic producer decisions and the
  standardized app-random model/branch selection. Before launch it derives a
  bounded per-node producer plan from the repository-resolved target and sends
  it through the current-version sealed third `Setup` descriptor. Lifecycle
  construction first requires the plugin-plan and scheduler-selection identity
  sets to match exactly and rejects plans for missing or white-box-disabled
  nodes. The plugin
  exact-checks node-local draw ordinal, canonical stream, full seeded raw draw,
  and that the selected value fits the live width; the scheduler separately
  validates the exact `SelectionId`, opportunity, domain, provenance, live
  request width, and post-draw parent. It starts at scenario genesis, advances
  under the attempt's exact cancellation and execution-quanta guard, requires
  every newly appended decision to equal the requested prefix, and retains
  replayed event history under the same observation bounds before lending the
  exact target to the modeled driver. Divergence, early terminal state,
  cancellation, or quantum exhaustion still performs runner-owned teardown.
  Noncurrent app-random values, explorer overrides, and selections outside this
  exact app-random contract are rejected before installing resources. A
  concrete modeled driver now projects an already-materialized exact discovery
  or selected-branch child, preserves typed scheduler failures, stops at the
  requested choice/marker/time/event or terminal boundary, rejects uncommitted
  network output, and retains dense event state
  under exact 1,000,000-entry/64-MiB-material bounds plus choice state under the
  canonical 65,530-record/128-MiB bounds with shared immutable contracts. Its post-shutdown seal incorporates the final drained
  suffix, runs bounded offline property evaluation, derives
  duplicate-insensitive per-point coverage identities, reconstructs the exact
  scenario and child artifacts, and emits a complete `ObservationCandidate`.
  It deliberately emits no undeclared measurements; measurement definitions,
  raw event-log evidence, and objective aggregation remain T-CAM-3 work.
  The packaged daemon selects this fresh concrete driver and fixed-worker
  composition. It routes only a retained version-nine descriptor closure
  through the concrete exact-resume driver. That driver restores direct-plus-
  delta RAM and device state from authenticated descriptors, restores the
  complete scheduler and evidence continuation, rejects a retained-log suffix,
  performs final drain, and reports `ExactRestore` only after sealing. Versions
  two through eight are rejected during decode and cannot reach runtime launch.
  Fresh exact-cache remains a
  separate optimization. Packaged startup captures the baked source, installs
  one fixed replay-oracle promotion owner per semantic worker, and advertises
  exact restore only after that owner set exists.
  The driver now observes a sticky checkpoint request at
  each operational boundary, lets a terminal verdict win a coincident request,
  and transfers a nonterminal request only after the lifecycle reports an exact
  capture-ready boundary. Real-node exact-checkpoint capture is now an
  executor-owned, guard-retaining operation. It seals and exact-binds
  configuration, node icount, event-log continuation, the writable-root
  overlay, direct-plus-delta RAM layers, and device state. The real-node
  executor completes final drain and reap before synchronizing and
  authenticating the bounded descriptor artifacts. The daemon adapts those
  artifacts into a reopenable CAS source with one independent positional
  cursor per open. The guarded session turns that source into the linear
  captured-checkpoint token, records successful capture as its backend reap
  attestation, and releases only the still-installed host guard during
  finalization. The pool-owned root handoff runs before the session returns its
  opaque prepared result. The daemon prepares and durably publishes a
  registered version-nine exact-checkpoint root over canonical snapshot
  metadata, the complete scheduler continuation, writable-root overlay, RAM
  layers, and device state, with no writes during preparation and
  children-before-root durable receipts. The executor now persists
  checkpoint-requested, checkpoint-publishing, paused, and raw-root
  checkpoint-promoting ledger states, stages
  the exact root before campaign-CAS writes, preserves it as a restart/GC root,
  recovers the expected root across daemon epochs, and releases capacity only
  after durable pause. The live driver now returns its same-boundary scheduler
  checkpoint,
  the session converts a winning sticky request into a guarded exact capture,
  and the fixed pool carries that linear capture through no-write preparation,
  root staging, immutable publication, and durable pause without rerunning the
  guest. Exact-pin resume now reauthenticates the selected current exact pin
  and complete checkpoint, while operational attempt resume authenticates the
  exact root retained by the durable execution origin and accepts only the
  attempt's pre-selection or post-selection configuration. Both materialize
  sealed, rewound, length-bounded descriptor inputs and record a root binding
  only after authenticated EOF and full seal verification; interruption leaves guarded
  launch fail-closed. Every noncurrent production manifest is rejected before it can
  resume a campaign attempt. The complete
  production lifecycle checkpoint store now
  also lends a read-only portable closure capability: it authenticates the
  version-nine production manifest and exact sorted object inventory under the
  scenario's aggregate checkpoint bound, keeps overlay, RAM, and device-state
  artifacts chunked, and reauthenticates each object while streaming without
  exposing its directory. A matching production-store installer accepts that narrow source
  interface, authenticates and semantically restores the complete closure in a
  private bounded store before publishing any destination object, then installs
  immutable objects idempotently and commits the manifest last. Campaign CAS
  now retains that complete closure under exact-root version four: a canonical
  production-manifest leaf and typed production-object leaves are covered by
  bounded 4,096-entry index envelopes, and the root binds the exact scenario,
  configuration, production identity, counts, and aggregate bytes. Preparation
  authenticates native and CAS identities without writes; publication places
  all leaves and indexes before the root; loading reconstructs a lazy portable
  source for the production semantic installer. Concrete packaged capture and
  ledger handoff are now wired into the fixed pool: the runner captures the
  complete source, validates its lineage scenario, prepares the version-four
  root, persists `checkpoint-publishing(root)` through a pool-owned callback
  while the lifecycle remains live, then shuts down and returns an opaque phase
  token for campaign-CAS publication and durable pause. The callback never
  releases the aggregate reservation before teardown, and its phase cannot be
  forged by an external model. Native overlay/VMState hashing and persistence,
  portable closure opening/validation, and campaign-CAS identity/publication
  streams now observe the exact execution cancellation between fixed one-MiB
  I/O chunks and between node/object operations. Cancellation remains typed,
  never retries as storage availability, and still runs mandatory QMP snapshot
  deletion/resume cleanup before the lifecycle can release its guard. The
  native lifecycle catalog remains a separate scenario-bounded capture layer.
  Production runtime restore now accepts only a version-nine closure with the
  complete writable-root overlay, direct-plus-delta RAM layers, dense device
  state, and scheduler and host-I/O continuation. Admission checks the aggregate
  transient byte ceiling before creating a destination, authenticates every
  artifact, seals and rewinds its descriptor, and launches QEMU through the
  guarded descriptor restore command. No runtime path materializes or loads a
  monolithic VMState file. Every noncurrent production manifest is rejected during
  manifest decoding, before process launch.
  Replay-oracle promotion uses disjoint descriptor-backed exact and thin launch
  authorities under one attempt process guard. The selected checkpoint, topology,
  continuation, and content identities are rechecked before either generation is
  launched, and each generation is reaped or transferred to quarantine before
  immutable promotion. A fixed promotion-worker set owns a deduplicated compact
  queue bounded at 65,536 attempt keys, restores incomplete publication to the
  retained raw root, and never reruns semantic execution while retrying storage
  publication.
- [x] **T-CAM-4.6** Implement strict and streaming commit modes, restart
  recovery, duplicate/conflict handling, backpressure, pagination, and
  projection rebuilding; implement snapshot-bound paged planner scans whose
  result is chunk-size independent; reject stale, oversized, timed-out,
  cancelled, and nondeterministic planner invocations.
  Exact observation publication now covers execution-basis authentication,
  strict global-admission order, stale-safe replay, deterministic conflict
  retention, exact root deltas, imported recomputation, and final-CAS safety;
  Executor restart recovery now uses direct-by-ID, bounded, checksummed,
  single-writer directory records and preserves exact responses, completed
  observations, and cancellation races without loading history. Bounded
  campaign-supervisor scheduling plus drain and cancel-and-retry pause policies
  are implemented. The guarded live session can now capture a basis-checked
  exact snapshot while retaining the paused process and resource guard;
  exact request/response, durable handoff, root-before-write phase tokens,
  restart root preservation, GC enumeration, captured-result propagation, and
  paused-capacity replacement are implemented. Exact-pin selection
  reauthentication and fail-closed version-nine descriptor materialization are
  implemented. Strict v2 resume request/response messages now bind a fresh
  assignment to the exact prior execution, checkpoint, and unchanged execution
  basis. Durable supervisor, worker, loopback, and campaign-driver resume wiring
  is implemented, including restart recovery and GC retention of the resume
  input root. The QEMU attempt runner now bypasses ordinary exact-cache and
  thin-replay lookup for resumed work, delegates the retained root to the
  guarded live session, requires the returned immutable root ID to match, and
  rejects a non-resume, foreign-configuration, non-exact realization, missing
  scheduler continuation, or mismatched scheduler configuration, frontier,
  state, future decision-RNG cursor, event-log offset, or retained segment set
  before modeled guest execution. The complete
  scheduler continuation now survives capture, immutable publication, restart
  materialization, and the typed session-to-driver handoff. The complete-root
  attempt materializer and session trait handoff are implemented. Guarded
  raw-root replay-oracle validation,
  source-bound no-write preparation, linear source/replacement root staging
  and publication, version-6 ledger persistence of the exact
  resource/retention promotion basis, streaming restart discovery, restart
  reauthentication, explicit incomplete-promotion revert, and the final paused-root CAS are
  implemented without holding the supervisor actor across QEMU or store work.
  The fixed 65,536-entry promotion queue and fixed promotion worker set now
  schedule both newly paused and restart-discovered phases with exact-key
  deduplication, classified retry, cancellation, and bounded reporting.
  The crate-internal quota/run-directory owner and its public sealed composition
  with the process owner are implemented, including reap-before-storage release
  and nondroppable combined quarantine. The owner now lends fresh monotone,
  admitted descriptor-pinned generation directories and exact checkpoint
  inputs through the daemon guard under one aggregate quota.
  The guarded exact-resume adapter now invokes the real-node launcher only after
  root materialization through the attempt-owned directory. The packaged worker
  selects that resume adapter without fresh fallback, restores the complete
  event prefix and quiescence boundary, and retains runner-owned shutdown and
  result sealing. Fresh exact-cache is deliberately excluded: §04a.7 defines
  it as a separate optimization choice, while CCOMP-3 and CCOMP-21 require only
  that executor-owned materialization preserve the semantic attempt and
  proposal. The packaged production operational profile uses the bounded
  current-only deployment contract described in T-CAM-4.5.
  Native-catalog cleanup is implemented through the crash-safe attempt-owned
  retirement and restart reconciliation described in T-CAM-4.5. `NotRun` is
  still fail-closed. Packaged startup installs
  the fixed replay-oracle owners and advertises `ExactRestore` only after that
  owner set exists. The fixed worker
  pool and its
  linear observation/checkpoint
  publication/reconciliation paths are implemented.
  The repository owner now also implements the core schema-v5 pin transaction:
  graph-scoped target validation, exact command replay and reuse rejection,
  pins/accounting/coordination root projection, tombstoned unpin intent, and
  imported-history recomputation. The principal-aware user-facing service,
  versioned loopback, and exact-precondition `pin`/`unpin` CLI binding are now
  implemented. A bounded, snapshot-bound repository visitor now authenticates
  the current projection and its exact thin configuration/scenario artifacts;
  the daemon composes those records with a separately held, exclusive
  assignment-ledger fence that streams observation and checkpoint roots under
  one restart-stable generation. A bounded, checksummed, restart-safe
  single-writer exact-pin journal now authenticates one complete checkpoint
  against the current exact pin fact and modeled configuration. GC consumes it
  under the authoritative ref and selection fences, rejects missing or stale
  current selections, and revalidates the exact root manifest before apply.
  Packaged startup now rebuilds the bounded checkpoint catalog from its durable
  ledger, owns that journal for the executor lifetime, receives every later
  paused root through bounded backpressure, and periodically reconciles pins
  accepted before or after checkpoint publication. Offline GC derives and
  locks the same canonical journal path.
- [x] **T-CAM-4.7** Implement hierarchical per-event promotion and existing
  minimization integration.
  The execution-model bridge now normalizes one bounded, homogeneous
  signal-fault runtime frontier into exact campaign declaration, typed Boolean
  or discrete domain, and opportunity records. It reauthenticates those records
  and a campaign branch selection to reconstruct the exact selection plus
  optional override prefix. Transition and parameter domains include the
  unmodified-result alternative. Campaign attempt
  decoding recognizes this standardized adapter, reconstructs up to 4,096
  nested promoted events in exact schedule order, and retains one opaque
  validated replay plan. The fresh production lifecycle installs all finite
  signal overrides before launch, stops at each exact parent/time frontier,
  proves the exact producer choice through a consumed override or matching
  unmodified runtime frontier, injects only the typed selection-plus-optional-
  override prefix, prevents checkpoint capture while a prefix remains, and
  reconstructs the plan from immutable input after restart. Live publication
  now snapshots frontier history before each quantum, admits only newly recorded
  frontiers still at the exact current parent/time boundary, and returns a
  zero-node-progress result bounded to 4,096 frontiers and 128 MiB of unique
  canonical choice material. The modeled driver retains that discovery only
  when it causes the exact `NextChoice` stop; later-stop observations cannot
  retrospectively publish it, and a queued replay branch suppresses duplicate
  discovery. Promotion is attempt-scoped: the fresh runner enables it only
  for `NextChoice` after exact start materialization, so historical prefix
  frontiers remain replay-only. Terminal, marker, time, and event-count
  executions pass through finite authored search frontiers without campaign
  pauses. Automatic finding preparation now selects a deterministic terminal
  window of at most 64 decisions, anchors it at the latest campaign branch in
  that suffix when present, and keeps every preceding decision as an
  authenticated immutable prefix. Both minimization and verification replay
  the same candidate sequence, preserve the target signature, and retain the
  selected schedule length, start, end, basis, seed, candidate bounds, and every
  replay outcome in the current minimization policy and transcript.
- [ ] **T-CAM-4.8** Complete the §14 Phase 4 local operator flight through lazy
  widening, additive finite branching, edge deduplication, live status,
  explanation, bounded pressure, pause/restart/resume, steering, and graceful
  stop.
  The automated prerequisite now proves exact selection of the bounded
  interesting window, immutable-prefix confinement, deterministic rerun, and
  signature-preserving shrink. The task remains open for the complete operator
  flight and acceptance record.
- [x] **T-CAM-4.9** Implement the authoritative language-neutral
  `CampaignService`, pure `PlannerEngine`, and local `ExecutorService` schemas;
  provide direct and loopback-RPC adapters, golden vectors, fake components,
  capability negotiation, idempotent assignment, and component conformance.
  The repository checkpoint now provides strict canonical planner/debugger
  submission messages with separate operational keys, public authority-specific
  direct adapters, zero-write authentication failure, and an exact replayable
  choice-discovery owner required before branching. The planner component now
  has strict 64-MiB request/response wire messages, by-value invocation inputs, a
  sorted content-addressed source-interpretation bundle, exact request-digest
  response binding, a mandatory adapter-owned execution-supervisor contract,
  supervised authority signing, checked direct clients,
  golden vectors, fake engines, and a versioned Unix-loopback adapter with
  finite absolute deadlines, close-on-error behavior, and direct/loopback
  equivalence. The coordinator now supplies capability-gated, snapshot-owner-
  recomputed continuation projections for every served source. Built-in
  current `crucible-canonical-frontier` implementation receives an offer and
  exact bounded PUCT guidance for every Ready source, ranks the owner-derived
  score across pages, and is the packaged daemon default. Accepted offer
  envelopes become retained-request children after zero-write semantic
  preflight, and import/restart recompute the same source ordinal and value.
  Any other implementation version is rejected. The planner runs behind a
  versioned one-request process protocol:
  a parent-owned supervisor measures deterministic page fuel, enforces a
  finite exchange deadline and sticky cancellation, and multiplexes bounded
  nonblocking pipes through EOF. Cleanup signals the dedicated process group
  before reaping the authority-free direct child. A separate one-second cleanup
  wait returns an explicit pending failure while one retained reaper retries;
  another evaluation cannot overlap that unfinished child. Pipe inheritance,
  blocked input, cancellation, unwind, and cleanup-retention regressions cover
  the failure boundaries. The generic
  daemon-owned long-lived coordinator runtime is implemented. Process startup
  can now attach a bounded fixed set of up to 256 such runtimes to unique
  explicitly named existing campaigns, each with the packaged planner and a
  matched authenticated local executor. An embedded owner may also attach a
  runtime after bind through a weak bounded capability: it reserves the unique
  name and slot before I/O, prepares outside the registry mutex, fails closed
  across concurrent shutdown, and cannot retain the repository lock after the
  service owner exits. Shutdown waits for bounded in-flight preparation and
  cancels the complete installed set before joining it. Startup and live
  attachment now share one exact executor connector that brackets connect with
  secure-parent, socket owner/mode/inode, and `SO_PEERCRED` authentication under
  a finite absolute connect deadline. A separate registered version-1 daemon-
  operational message now binds principal, campaign, and the bounded executor
  path under one digest, exact response, and distinct read-write-only policy
  operation without admitting the path into campaign identities. The
  authenticated listener now routes that request only after peer-principal and
  per-campaign policy checks; the bounded registry provides exact replay without
  repeated executor I/O, and `crucible campaign attach` reports attachment or
  replay status. Startup can now share one fixed packaged-executor pool among
  an explicit bounded campaign set or the complete authenticated one-page
  startup catalog. The pool admits one exact compatibility profile and a
  bounded closed native catalog containing every distinct scenario selected at
  startup; the same executor remains available to compatible post-bind
  attachments only when their scenario is already catalogued. Attachments
  naming another executor remain independently scoped. This task's production
  deployment is the startup-fixed compatible pool defined by §04a.2.
  Multi-profile allocation and live scenario-catalog expansion are future
  deployment variants under §04a.4, while opaque non-finite priors fail closed
  unless a current typed adapter interprets them. The first
  `CampaignService` checkpoint now provides
  strict principal/name types, 64-MiB canonical request/response messages for
  bounded by-value creation, authenticated current-head reads,
  lifecycle/budget/policy control, and additive operator branch submission,
  exact response-digest binding, a
  checked direct client, raw golden vectors, and a repository adapter that
  requires exact-request authentication/authorization before repository
  access. Creation loads and validates an exact imported transitive generator
  closure and replays
  the authenticated genesis for a semantically identical named retry in
  constant time from validation checkpoints after later mutations. The daemon
  now provides a narrow Crucible verifier-backed immutable artifact importer;
  large scenario/configuration bytes remain outside the campaign control
  message and are re-derived before publication. The daemon's local-service
  bootstrap now has an exclusive prepared-repository state that applies strict,
  bounded, exact-owner version-1 import manifests before socket bind; binding
  consumes that import authority, and read-only service mode rejects it. The
  same bootstrap can now authenticate an optional exact-owner mode-`0600`,
  fixed-size version-1 planner/debugger authority bundle before state open and
  construct the repository with distinct operational keys; omission explicitly
  leaves component acceptance unavailable until start/runtime attachment is
  composed. Stored
  generator closure validation streams within 4,096-record and 128-MiB
  aggregate-body bounds and does not rewrite imported records. Atomic
  name-based derivation now creates
  an audited successor of an exact authenticated source snapshot, optionally
  activates a compatible imported policy, leaves the source ref unchanged, and
  exactly replays the original derived snapshot after later target mutations,
  cache eviction, restart, or a same-basis CAS race. A supplied policy must
  preserve the source campaign mode. Cross-mode derivation is rejected before
  publication; there is no mode-migration format or compatibility path.
  Focused repository tests cover exact derivation replay, cold reconstruction,
  source immutability, and rejection of every mode change. This automated slice does not complete the
  Phase 1 manual model flight or the Phase 8 operator-acceptance flight.
  Canonical bounded finding
  and self-contained reproduction records now have a verifier-backed Crucible
  importer and an atomic occurrence-clustering owner with restart validation.
  Frontier, finding, attempt, and planner-ranking explanations plus creation,
  start, runtime attachment, and bounded filtered/aggregated views are exposed
  through the checked CLI. The CLI wiring uses the
  checked local Unix-stream client for authenticated `status`, one-shot
  resumable `watch`, exact immutable pages of graph keys, discovered choice
  opportunities, and continuation states, and exact-command,
  snapshot-preconditioned `resume`, `pause`, `stop`/`seal`, `unseal`, additive
  budget, and policy steering. Every mutation reports its prior/new snapshots,
  command ID, and replay status through the common table, Markdown, JSON, and
  JSONL renderers. A bounded
  coalesced `WatchCampaign`
  operation returns one exact current-head cursor and lifecycle projection,
  including stale/unknown-cursor recovery without ancestry work. A bounded
  `QueryGraph` page exact-binds the current snapshot and one authenticated
  graph-root key cursor, rejects a changed head, and returns at most 256 content
  IDs with the exact snapshot body and a minimal bounded Merkle proof. Checked
  clients replay the cursor, complete ancestor prefixes, range, and one-entry
  lookahead to authenticate exact continuation or EOF without fetching object
  bodies or scanning ancestry for cursor/page resolution beyond the
  repository's required authenticated-head checkpoint rebuild. The local
  graph-object read separately authorizes one exact graph key, authenticates
  its value with a fixed-depth minimal Merkle lookup proof, and exposes only
  strict configuration-artifact or choice-opportunity envelopes. A bounded
  `QueryFrontier` page authenticates a fixed exploration-root index anchor,
  exact request-ordered continuation projection bodies, continuation or EOF,
  and full snapshot metadata within the same proof/message bounds as the
  choice-index query. A separately authorized `GetFrontierObject` call proves
  one exact projection membership and returns only its strict branch-request
  body; it cannot read arbitrary exploration or content-store objects.
  A nested choice index is anchored in the graph root and updated atomically by
  explicit and observation-driven discovery. `QueryChoices` pages at most eight
  opportunity IDs with one exact anchor proof and one exact range/EOF proof;
  noncurrent heads fail closed and ordinary mutations never create a partial
  index. A separate current choice-object read authenticates the
  opportunity's authoritative graph membership at one exact named-history
  snapshot and returns only its exact declaration or effective domain;
  arbitrary non-graph reads remain unavailable.
  `QueryFindings` returns at most four complete canonical finding records from
  the authenticated findings root with an exact range/EOF proof and
  signature-key/body identity validation; the checked CLI renders their stable
  class, fingerprint, representative observation, occurrence count, and
  reproduction IDs without granting child-object reads. A separately
  authorized finding-object lookup proves one exact finding membership and
  returns only its representative/latest observation or original/minimized
  reproduction dependency. The checked `explain-finding` composition reads the
  representative observation and original reproduction, then verifies their
  exact finding, fingerprint, and configuration-artifact basis before rendering
  the handoff identities.
  A proof-bearing attempt explanation authenticates the semantic attempt and
  execution-basis admission in accounting, its optional branch proposal in
  exploration, its planner invocation result in coordination, and its canonical
  completion or absence in observations. The checked CLI renders the exact
  path, cause, admission ordinal, selection, proposal, completion, accepted
  planner step, fixed-point guidance terms, and coordinator accounting without
  granting arbitrary record reads.
  The local
  Unix-stream binding
  now dispatches all thirty-four current success messages plus one stable
  request-bound error envelope under a version-17, 64-MiB-body,
  absolute-deadline frame.
  `QueryCampaignGraph` authorization covers the complete anchoring snapshot
  metadata and all root IDs; bodies named by those IDs retain separate access
  control.
  `GetCampaignSnapshot` authenticates named-history membership and returns an
  exact identity-checked current or historical snapshot body under that same
  metadata capability.
  Protocol, canonical, I/O, and poisoned-lock failures shut down the connection;
  semantic failures keep it reusable, and concurrent exchanges receive a
  retryable busy error instead of queuing outside those deadlines. Direct and
  loopback clients now expose the same closed authorization/conflict/transition/
  resource/availability/integrity failure vocabulary. A connected-stream
  repository adapter now reads Linux `SO_PEERCRED`, resolves exact PID/UID/GID
  through a mandatory deployment policy, and binds the result to every claimed
  request principal before repository access. A bounded listener over either
  an embedded pre-bound socket or a managed filesystem endpoint now caps
  connection workers at 256 and its
  pending queue at 1,024, caps one connection at 65,536 requests, resolves peer
  identity once per connection, rejects excess sockets, interrupts active
  streams on sticky shutdown, and joins every worker before returning
  operational counters. An immutable local policy now maps at most 4,096 exact
  effective UID/GID pairs (never PID) to principals and retains at most 65,536
  exact operation plus campaign/all-campaign grants, rejecting ambiguity and
  unreachable grants. The registered strict version-1 TOML policy is bounded
  to 1 MiB before parsing and rejects unknown fields, versions, and operation
  labels. Managed listener bootstrap validates a canonical 107-byte Linux
  pathname, exact-owner non-group/other-writable parent, owner-only lifetime
  namespace lock, same-owner stale socket, configured socket mode, and
  exact-inode conditional teardown. The parent tree remains operator-owned
  deployment state. A durable bootstrap now opens the strict policy before
  mutation, holds one exact-owner state-root lock across private directory blob
  and ref backends, excludes a second socket incarnation, and reopens that state
  after restart. The existing `crucible serve` process exposes the socket,
  state, policy, and octal-mode profile as all-or-none flags. Optional paired
  runtime-name/executor-socket flags attach the packaged planner to one existing
  campaign only after exact-owner socket and `SO_PEERCRED` authentication plus
  executor-description negotiation. CampaignService/runtime failure and
  SIGINT/SIGTERM trigger shared shutdown and worker join. Process read-only mode
  also denies every campaign mutation after policy resolution. The listener now
  routes validated service failures by public operation, exact request digest,
  and stable failure, plus closed path-free connection-failure categories, to
  an optional deployment-owned diagnostic sink; sink failure is isolated from
  serving and diagnostics never enter semantic state or transport responses.
  The current creation porcelain accepts only canonical current-schema lineage
  and policy records whose closure is already imported, and its optional start
  submits a separate exact-genesis, idempotent lifecycle command. Message
  framing or listener construction alone is not authentication.
  Checked
  request/response acceptance now retains the
  exact canonical request in a content-addressed envelope (32-MiB and 65,529
  bundle-object initial store profile) and commits both its ID and digest in
  planner-step schema v4. The executor
  checkpoint now provides strict 4-KiB canonical `SubmitAttempt`, execution
  status, exact-checkpoint, and cancellation request/response messages,
  nonzero operational assignment/execution/epoch IDs,
  explicit resource and retention fields, exact-request digest binding, stable
  retry/conflict outcomes, golden vectors, malformed-input rejection, an
  implementor-facing service trait, and one checked coordinator client for
  direct and RPC use. Repository validation authenticates the attempt and
  lineage for every response and the complete observation/attempt/lineage
  correspondence before accepting `already-completed`. The daemon now provides
  a trait-based memory/directory assignment ledger, fsynced immutable response
  publication, lineage-qualified conditional attempt state, exact
  resource/retention execution-basis deduplication, bounded aggregate and
  per-execution-quanta admission, reauthenticated completed-state reuse,
  idempotent running/checkpoint-requested/checkpoint-publishing/paused/
  completed/canceled transitions, commit-indeterminate publication recovery,
  restart and GC-root conformance tests, a production repository
  admission/completion adapter with an exact immutable executor profile, and a
  strict 4-KiB versioned Unix-loopback binding with finite deadlines,
  close-on-error behavior, direct/loopback equivalence, and hostile/partial
  frame tests. The repository candidate handoff and generic worker driver now
  use non-cloneable dispatch and phase tokens, keep semantic model input free
  of assignment and daemon identities, preflight the complete candidate before
  writes, and carry each newly discovered declaration, domain, and opportunity
  through a self-contained handoff bounded to 65,530 discoveries and 128 MiB
  of unique canonical choice records. The narrow executor store publishes that
  validated immutable bundle without gaining repository or mutable-ref
  authority. The supervisor persists a lineage-qualified `publishing` root
  before immutable publication, streams publishing/completed roots to GC,
  recovers exact expected results across restart, keeps cancellation resources
  charged until worker exit, and reconciles publication without holding the
  supervisor actor or rerunning the guest. Snapshot incorporation remains
  coordinator-only. A
  strict Crucible execution adapter now decodes versioned scenario/schedule
  payloads, re-derives semantic IDs before runner invocation, and exposes a
  typed runner boundary for operational hot/exact/thin selection. Branch input
  revalidates provenance against its exact parent, carries the selected
  canonical prefix, and keeps the runner's realized tier as operational
  telemetry outside immutable candidate bytes. The execution
  model now retains a validated campaign `Selection` as one canonical Schedule
  V2 decision with strict binary/serde decoding, content-address participation,
  event-log projection, and conservative reduction semantics. The daemon's
  exact/thin QEMU runner now invokes the existing authenticated realization
  coordinator through a mandatory attempt-scoped resource/cancellation session,
  classifies exact versus replay telemetry, delegates typed
  selection/stop/candidate work through the session's live-backend capability,
  and tears the session down on every exit. The live-node composition now
  installs and verifies the exact guard before launch authority is returned,
  exact-binds the cancellation incarnation, lends the driver only narrow live
  operations and a read-only unified event log through a session-owned facade
  that charges one guard quantum before every realization-replay or live
  advance. Backend-shaped charge errors retain their operational
  cancellation/resource classification.
  Replay exact-binds the caller's offset to that single log before backend
  work; candidate acceptance binds the driver's exact log offset and requires
  an unchanged paused-boundary seal plus an unchanged final shutdown drain. The
  session releases the guard only after reap attestation, and cleanup tracks
  backend and guard phases separately on explicit finish and drop. Normal
  shutdown receives that same guard, so a failed direct-child reap can retain
  or transfer its exact authority before quarantine. Only
  explicitly typed availability failures retry; deterministic realization
  failures terminate.
  Canonical `DescribeExecutor` and cursor-bound `WatchCapacity` messages now
  separate immutable compatibility/ceiling facts from daemon-epoch-scoped
  availability and exact/hot locality. Checked direct and Unix-loopback clients
  reject stale epochs, capability drift, non-advancing sequences, capacity
  above immutable ceilings, and unsupported locality. The local supervisor
  facade refuses startup unless advertised ceilings exactly equal enforced
  slots, CPU, memory, disk, and execution-quanta limits. The concrete host
  resource guard's Linux cgroup/quota owner and the current-ABI paused-restore
  reset of the plugin coverage novelty bitmap/ring plus host consumer state are
  implemented. Coverage-aware modeled-driver execution, canonical coverage
  projection, the production out-of-process campaign composition, and the
  component-conformance matrix complete T-CAM-4.9. Coverage system/scaling
  evidence and hot-fork realization/equivalence are tracked by their Phase 6
  and Phase 7 gates; the remaining Phase 4 acceptance work is the manual
  operator flight in T-CAM-4.8. The reset fails closed before authoritative
  execution on any producer, acknowledgement, native-pause, or consumer
  mismatch.
- [x] **T-CAM-4.10** Replace repeated full-history validation on local owner
  mutations with bounded immutable validated-head/lifecycle checkpoints and
  authenticated membership and result-locator indexes; promote only after ref
  CAS, retain full fail-closed validation for imported or restarted heads, and
  exercise 10,000 mixed request/control mutations plus deep exact replay.

**Gates:** `gate:branch-point-model`, `gate:lazy-frontier`,
`gate:attempt-idempotence`, `gate:campaign-replay`,
`gate:campaign-statistics`, `gate:campaign-component-contract`,
`gate:control-responsiveness`, `gate:campaign-mutation-scaling`,
`gate:harness-lint`.

**Manual gate:** accepted §14 Phase 4 local campaign flight.

## 11.7 Phase 5 — Composable content stores and durable closure efficiency

Primary crates: `crucible-cas` and `crucible-api` lifecycle/checkpoint code.

- [x] **T-CAM-5.1** Introduce separate streaming `ImmutableBlobBackend` and
  conditional `MutableRefBackend` traits, capability and error models, and
  migrate current campaign/exact-closure persistence behind them.
- [x] **T-CAM-5.2** Implement canonical object envelopes, domain-separated
  logical IDs, child-reference walking, persistent Merkle collections, partial
  closure traversal, and typed corruption diagnostics.
- [x] **T-CAM-5.3** Remove full-file staging copies from the normal exact-closure
  publish/materialize path; stream with bounded buffers and preserve sparse
  extents where valid.
- [x] **T-CAM-5.4** Implement immutable disk backing plus child overlay
  manifests and content-deduplicated changed-object storage.
- [x] **T-CAM-5.5** Implement and validate an acyclic store-composition graph
  with verified, routed, tiered, read-through, write-through, write-back,
  compressed, encrypted, quota, metrics, and namespaced layers, including a
  durable GC-protected transfer journal for write-back operation.
- [x] **T-CAM-5.6** Implement packed logical-object storage with crash-safe
  index generations, range authentication, concurrent-reader-safe repacking,
  logical/physical accounting, and page/extent IDs independent of pack layout.
- [x] **T-CAM-5.7** Implement directory and S3-compatible leaf backends through
  the same conformance harness, including conditional refs, multipart
  interruption, corruption, credential expiry, and latency/failure injection.
- [ ] **T-CAM-5.8** Complete the §14 Phase 5 exact-pause/restart/resume, backend
  outage, credential expiry, corruption, tier promotion/eviction, repacking,
  archival transfer/import, incompatible restore, retention, and plan/apply GC
  flights across multiple derived refs and active publication/transfer/write-
  back roots.
- [x] **T-CAM-5.9** Implement metadata/findings/debug/executable/mirror closure
  policies, durability receipts, pins, sensitive-export reporting, resumable
  missing-object transfer, and offline maintenance transfer. Do not implement
  demand paging or worker fanout.

The admitted graph checkpoint currently provides bounded acyclic validation,
exact kind routing, logical verification, ordered tiers and promotion,
source-authoritative read-through caching, write-through mirroring, and
path-free saturating synchronous operation/byte/error/elapsed-nanosecond counters
plus deferred stream opens, authenticated completions, partial abandonments,
failures, delivered bytes, and open/read elapsed nanoseconds over memory,
durable directory, durable compressed-directory, durable encrypted-directory,
durable compressed-encrypted-directory, and packed leaves. The
compressed-directory leaf streams a fixed private Zstandard representation
below plaintext identity, enforces a per-object plaintext bound before source
or decoder work, authenticates complete plaintext for range reads, survives
restart, and participates in generation-bound physical inventory and deletion.
The encrypted-directory leaf now streams fixed 64-KiB AES-256-GCM chunks below
the same plaintext identity, derives per-object/chunk nonces from a separately
supplied key capability, binds exact length/key generation/ordinal/final state
as associated data, authenticates the full plaintext even for range reads, and
participates in the same restart-safe physical inventory/deletion boundary.
Graph schema v4 includes only the non-secret key ID and object bound; secret
bytes are absent from graph identity, descriptions, receipts, and disk headers.
A checksummed, keyed-verifier state under the inventory lock pins one exact
key generation to the physical root before any object operation, so a wrong
secret cannot create a mixed-key directory.
The compressed-encrypted-directory leaf now supplies the required fixed
compression-before-encryption order as one streaming physical placement. It
uses a distinct v1 grammar and nonce/AAD domains, never persists an
intermediate unencrypted frame, validates the bounded compressed length before
decoding, and authenticates the complete decompressed plaintext for every read.
Graph schema v5/tag 14 identifies this placement without serializing secret
material; older graph bodies remain byte-for-byte stable when the new node is
absent.
The graph now also admits a restart-safe aggregate logical-quota node around
one exclusively owned physical leaf. A durable dirty/clean state transaction
repairs commit-indeterminate puts and deletes from a bounded fenced child
inventory, and graph administration exposes the quota boundary rather than a
deletion-capable child escape. Tests cover count/byte rejection, idempotent
puts, GC reclamation, clean restart, dirty restart recovery,
independent-instance admission serialization, and fail-closed
shared/non-leaf/path admission.
The graph now also admits a version-six durability-policy node. It requires an
exact policy entry for every object kind that can reach it, counts only
distinct named durable placements in the child receipt, and rejects a put
whose evidence does not meet the configured minimum. A policy that forbids
pending downstream transfer fails graph admission when its child advertises
deferred writes; explicitly deferred classes retain the write-back journal as
their GC-protected operational root. The requirement and its per-kind mapping
enter graph configuration identity, while receipts and placement decisions
remain outside logical object identity. Tests cover restart-stable identity,
missing and extraneous policy entries, duplicated receipt names, insufficient
placement count, nondurable children, and explicit write-back admission.
Read-through falls through only on exact
absence,
treats promotion as non-semantic, and never reports cache durability as
authoritative source durability. Durable write-back now requires durable
streaming staging/destination children, acknowledges only after staging plus a
checksummed bounded journal append, survives restart, flushes idempotently in
canonical order, and exposes the exact pending set behind a shared/exclusive
lifecycle fence. GC planning includes those IDs in the canonical root manifest;
apply reacquires and holds the fence, rejects a changed set before deletion, and
therefore cannot collect a children-before-journal publication. Tests cover
restart, torn-tail recovery, corrupt-journal rejection, count/byte limits,
durable-child and non-overlapping-path admission, lifecycle exclusion,
single-pass staging authentication, transfer completion, and stale GC plans.
The graph now also admits a version-seven namespaced authorization node. It
binds one bounded slash-separated deployment namespace into graph identity,
resolves the corresponding non-serializable authorization capability before
construction succeeds, and checks every exact `contains`, `read`, and `put`
before the child observes the object ID. Graph admission requires the namespace
boundary to be the graph's sole root boundary, so an unprotected cache, mirror,
or sibling path cannot act first. Deferred write-back transfer and pending-root
inventory recheck the same capability before reading or moving an ID. Missing
or mismatched capabilities fail closed, credentials and mutable policy remain
absent from identity and introspection, and the separate physical
administration capability does not expose the authorizer. Tests cover namespace
grammar, capability mismatch and duplication, denial before child access, all
three operation classes, identity sensitivity, and path-free introspection.
The graph now also admits a version-eight authenticated object-profile boundary.
It binds a non-secret policy ID into graph identity and resolves a separate
profiler capability that derives exact kind, length, sensitivity,
reconstructibility, and retention role from authenticated bytes or an opaque
content-ID kind. The concrete campaign profiler validates record-specific
envelopes and applies the closed v1 mapping without caller hints. Full-object
profile derivation precedes child puts and returned reads, `contains` proves
authenticated presence, and deferred transfer plus pending-root inventory
repeat the same validation. Profile and namespace boundaries compose only as
the unary root prefix. Tests cover policy grammar/capability binding, identity
sensitivity, buried-boundary rejection, wrong-kind profiler output, range
reads, denied puts, and combined namespace/profile operation.
The graph now also admits a version-nine physical-quota boundary. It
exclusively owns one persistent leaf, commits the external binder policy plus
exact project/byte/inode limits to identity, and transfers the leaf's physical
administration capability so GC cannot bypass the boundary. The safe graph
contract checks a bound guard before ordinary and administrative operations;
the concrete Apache host-resource binder pins an ext4 directory incarnation,
authenticates inherited project assignment and exact kernel hard limits, and
checks current usage without granting quota mutation to the repository. The
same raw project-quota primitive remains shared with QEMU attempt storage.
Tests cover capability mismatch/duplication, exact binding, restart, exhaustion
before child access, deletion, identity sensitivity, exclusive ownership, and
logical-plus-physical composition.
The graph now also admits a version-ten S3 immutable leaf. Its canonical node
commits an exact non-secret endpoint-policy identity, bucket, prefix, maximum
logical-object length, and multipart geometry. The separately supplied client
capability must match that endpoint identity. The leaf authenticates sources
before and during multipart upload, conditionally completes without replacing
an existing content-addressed key, authenticates full and range reads, and
fails closed when multipart cleanup cannot be confirmed. The concrete
`crucible-s3-store` AWS SDK adapter adds bounded queue, active-operation, and
retained-command-byte admission, one absolute deadline over each SDK/stream operation, explicit
credential/availability/protocol error classes, and conditional completion. Tests cover multipart
round trip, range authentication, exact replay, corruption, interruption,
cleanup failure, credential expiry, capability mismatch, graph identity, queue
bounds, command deadline, stream interruption, and bounded restart-resumable
orphan cleanup. Graph administration now retains a separate S3 cleanup
capability that lists and idempotently aborts at most 1,000 unfinished uploads
per call with an exact provider continuation; it validates a whole page as
canonical keys before the first effect and is independent of committed-object
administration. An explicit strong S3 object-administration capability now
fences publication, scans at most 65,536 exact committed keys in 1,000-key
pages, charges one absolute list-plus-metadata deadline, and authenticates a
persistent ETag-CAS/read-back monotonic generation across restart and ABA.
Planned deletion advances that generation, conditionally deletes the exact
provider version, and confirms absence. Exact namespace lifecycle admission
forbids ordinary/admin bypass, external writers, and provider-retained object
versions. The optional S3 ref backend now uses fixed domain-separated hashed keys
with exact name/target bodies, provider ETag CAS with read-back evidence,
strongly consistent bounded listing, one process-wide lifecycle per exact
namespace, and one absolute deadline across a complete remote scan. Its
exclusive `RefStoreAdmin` fence blocks publications and mutations, streams the
validated namespace, and verifies one ETag-CAS/read-back persistent monotonic
inventory generation across the scan for global-GC root fencing. The AWS SDK
adapter exposes those primitives only through an explicit conformant-service
wrapper. Tests cover maximum ref names, stale conflicts, cross-instance races,
malformed bodies, false committed versions, strict provider pages,
non-resetting scan deadlines, publication and mutation exclusion,
restart-stable generations, and same-value ABA. S3 committed-object
inventory/deletion is implemented at the graph capability boundary and now
runs through the daemon's canonical plan/journal/restart/apply path. The
integration regression proves retained-object authentication, unreachable-only
deletion, and stale-generation rejection after a concurrent publication.
Directory and S3 blob/ref implementations now also invoke the same reusable
persistent-leaf conformance harness for authenticated full/range/empty I/O,
replay, fenced inventory and deletion, ordered ref pagination, stale CAS, and
ABA generation behavior; backend-specific fault suites remain additive. The AWS
SDK adapter's ignored environment-gated integration test runs those exact
routines against one exclusively owned unversioned live-service namespace and
cleans its unique prefix after success. This completes T-CAM-5.7's backend and
fault-conformance implementation. The managed local daemon now also accepts a
consumed durable immutable/ref store capability: it checks both halves before
locking state, retains the same exact-owner lifecycle without creating default
leaf directories, and restarts over a reconstructed composed graph. The CLI's
strict version-two repository-store deployment exposes the complete local and
remote graph vocabulary, protected encryption-key and S3 credential files,
static namespace policy, campaign object profiling, Linux physical-quota
binding, and separate durable local or strong-CAS remote refs. Its exact-kind,
unknown-field, permission, no-default-leaf, wrong-key restart, and noncurrent-schema
rejection regressions are executable. The managed service retains the graph's
exact separately returned physical/multipart administration and a second
ref-inventory view through shutdown, rejects foreign graph authority, and
exposes neither to ordinary service/runtime components. The current schema
also binds exact HTTPS S3 endpoint capabilities, bounded SDK workers,
owner-only reloading credential files, S3 leaves, and optional strong-CAS
remote refs. It
validates exact endpoint membership, multipart geometry, and segment-disjoint
graph/ref namespaces before secret I/O; retains worker, multipart/object, and
ref administration through shutdown; and treats strong-CAS conformance as an
operator-owned deployment assertion rather than an inferred provider property.
Focused regressions cover noncurrent-schema rejection, capability mismatch and ordering,
insecure endpoints, credential expiry, namespace overlap, physical
administration retention, and construction without network I/O. The managed
service now optionally schedules one joined fixed-cadence worker with separate
global write-back, round-robin S3-node, and per-node unfinished-upload bounds.
Configuration fails before deployment I/O, idle waits are interruptible,
successful cursors resume by exact node ID, and the first backend failure or
worker panic visibly stops the CampaignService. The worker cannot borrow
committed-object/ref delete authority; destructive GC still requires exact
ledger, pin, publication, and transfer roots. The prepared service now exposes
one lifetime-borrowed GC boundary only before endpoint bind. The shipped
`crucible store gc` porcelain acquires that stopped-owner state lock, derives
the non-substitutable `STATE/executor-ledger`, persists or exactly reopens the
non-substitutable `STATE/exact-pin-materializations` owner, persists or exactly
reopens the bounded external GC journal during non-destructive plan, and
revalidates every generation before apply. The packaged executor rebuilds a
65,536-root checkpoint catalog from its ledger, authenticating schema-v4
production closures. It receives
later paused roots through bounded backpressure and, after the authoritative
promotion CAS, replaces each raw source with its replay-validated promoted root
without waiting for restart. It reprojects up to 65,536 current exact pins on a
fixed cadence outside the supervisor actor. A missing current-fact selection
fails GC closed. Adjacent read-only porcelain
reports the exact admitted graph and streams one requested content ID through
deferred EOF authentication without borrowing ref or delete authority. It also
delegates physical verification to the separately held `StoreGraphAdmin`,
which enforces global aggregate work bounds while authenticating each physical
leaf under its own opening/closing generation sandwich and returns typed,
path-free aggregate placement evidence. The boundary rejects partial, short,
long, or deferred-failure streams, inventory/opened-length disagreement,
backend-identity disagreement, and generation drift without retaining a fence
after failure.
The CLI renders that evidence without reimplementing the administration
protocol. A hermetic
public-process flight now generates and validates the worked-network fixture,
imports it before endpoint bind, creates and starts the campaign through the
checked Unix service, authenticates live logical and physical store views,
stops the owner, plans and applies deletion of authenticated orphan/import
debris, and proves the retained scenario and exact running head survive service
restart. Automatic deployment discovery and the representative-product outage,
credential, transfer, repack, and operator flights remain open under Phase 5
and T-CAM-5.8.
Policy-aware GC derives per-kind `Required` and `ReadThroughCache` roles
through transparent wrappers, binds each physical basis to a persisted storage
identity, and evicts a reachable read-through placement only when a unique,
independent required placement authenticates to EOF between matching inventory
generations. Apply recomputes reachability and graph roles, authenticates the
required source again, acquires paired physical fences in identity order, and
advances a rolling post-delete cache basis while retaining all root fences.
The plan and candidate codecs admit only their current policy-aware schemas.
Wrapped-cache, same-path alias, strict codec, and forged swapped-role
regressions cover the boundary.
Tiered composition now carries independent readable, writable, and
promote-on-lower-read roles for every ordered child. Admission requires at
least one reader and writer, rejects roleless tiers and promotion into an
unreadable child, and verifies conditional creation for every write or
promotion target. Writes return the combined authenticated placement receipt
from every writable tier, while reads skip write-only archive tiers and promote
only into explicitly selected preceding tiers. Focused unit and composition
gate coverage exercises separate cache, primary, and archive roles.

The packed leaf now provides immutable bounded multi-object pack files, a
checksummed persistent logical index with monotonic generations, full logical
authentication after range extraction, exact logical/physical accounting, and
a separately held logical-inventory/deletion fence. Repack is an explicit
canonical plan/apply operation bound to the backend configuration, persistent
instance, exact index generation and digest, and pre-apply accounting. Apply
publishes and verifies all replacement packs before the atomic index switch,
records the applied plan for restart-safe indeterminate-commit replay, and only
then removes superseded names. Open readers pin old inodes. Explicit
stopped-owner maintenance authenticates the retained generation before it
reclaims unindexed complete packs, while missing or malformed referenced packs
fail closed. Tests cover one-object-to-multi-object pack identity stability,
authenticated range reads, concurrent old-generation readers, restart replay,
stale and corrupt plans, sparse logical deletion, pack-before-index recovery,
index corruption, referenced-pack loss, empty objects, accounting, graph
admission, and physical configuration mismatch. The remaining representative
composed-tier, S3, global-GC, archival, and operator flights are tracked by
T-CAM-5.8 rather than weakening this completed leaf contract.

The memory, directory, compressed-directory, encrypted-directory,
compressed-encrypted-directory, and packed
blob leaves now expose separately held, exclusive administrative fences for physical logical-object
inventory. A logical-quota node exclusively owns one such leaf's fence and
re-exports the same generation under its quota boundary so GC deletion updates
the durable aggregate accounting. The memory and directory ref leaves
separately fence the complete authoritative ref namespace. Object inventory
streams exact placements under a
backend-instance generation and supports idempotent deletion of an already
planned candidate. Ref inventory streams exact name bindings under its own
monotonic generation; every accepted replacement advances it, so same-value ABA
is distinct across restart. Directory generations use registered checksummed v1
state records and advance durably before cooperating mutation. Tests cover
restart, object and ref ABA, early visitor failure, malformed/oversized input,
valid staging-prefix names, and mutation exclusion while fenced. Store-graph
administrative composition, the now-implemented fenced operational-ledger root
snapshot, and a strict registered v2 plan header now compose store-graph,
root-manifest, candidate-manifest, blob, ref, and ledger hashes/generations into
one immutable identity. Complete manifest/reachability planning,
interruption-safe global-GC apply/recovery, composed store-graph administration,
and stopped-owner production maintenance are implemented. The remaining work is
the representative backend, failure, and operator evidence tracked by
T-CAM-5.8; it does not weaken the separately completed packed-leaf T-CAM-5.6
contract.

The production exact-closure checkpoint now holds every running QEMU node
paused while it authenticates and streams the live generation's direct-plus-
delta RAM layers, device state, and allocated overlay extents directly into
bounded content chunks. It publishes
the closure before deleting transient QMP snapshots and resuming the originally
running nodes, and it no longer copies either artifact through an additional
full-file staging tree. Version-seven overlay capture requires supported
`SEEK_DATA`/`SEEK_HOLE` semantics, canonicalizes allocated all-zero chunks back
to holes, and stores only the remaining changed chunks in ordered sparse extent
manifests. RAM and device streams remain dense authenticated chunk sequences.
Restore uses fixed buffers, recreates omitted overlay ranges as holes in a new
staging file, publishes each destination atomically, seals and rewinds every
input descriptor, and leaves no partial destination after corrupt or missing
input. Version-nine targets bind the actual immutable root-image byte identity
and reject a different backing before QEMU launch. Every noncurrent production
manifest is rejected during decode and cannot reach
runtime launch. This completes the bounded
changed-overlay storage portion of T-CAM-5.4. Production RAM capture also
bounds retained chains at eight layers: the ninth capture becomes a complete
direct capture with one layer and no parent-closure provenance. The old lease
remains rollback authority through durable publication, and successful
reconciliation retires its ancestor leases. Existing QEMU coverage proves an
eight-layer reconstruction equals a direct probe; lifecycle coverage proves
the production rebase identity and ownership transition.

**Gates:** `gate:campaign-store-equivalence`, `gate:campaign-store-composition`,
`gate:exact-closure-streaming`, `gate:campaign-cold-continuity`.

**Manual gate:** accepted §14 Phase 5 storage and destructive-recovery evidence.

The split immutable-blob and mutable-ref contracts now own all campaign
repository persistence. Both memory and durable-directory leaves pass the same
streaming identity, conditional-create, conditional-ref, bounded range-read,
namespace-scan, corruption, restart, and failure-atomicity tests. Production
exact checkpoints also cross that immutable seam: the daemon authenticates a
native version-nine closure, streams every object into domain-separated CAS
placements, publishes bounded canonical index pages and the exact root last,
then reloads the authenticated closure through
`ExactCheckpointStore::load_attempt_checkpoint` and its semantic decoder. The
durable operational ledger retains that
root across restart without granting the immutable backend mutable-ref
authority. This completes T-CAM-5.1.

Campaign record kinds and schema versions are registered and wrapped in one
strict canonical envelope whose typed children are sorted, role-bound, and
included in its domain-separated logical identity. Persistent Merkle maps and
sets authenticate point, bounded-page, and exact proof traversal; generic and
record-specific closure walkers enforce complete or deliberately partial
reachability with typed missing, corrupt, kind, schema, bound, and semantic
diagnostics. Schema inventory, canonical round-trip, malformed-envelope,
Merkle prefix-confusion, false-EOF, unused-proof-node, imported-closure, and
restart regressions provide executable evidence for T-CAM-5.2.

## 11.8 Phase 6 — QEMU hot-fork spike

Primary scope: atomic QEMU patch and the minimal GPL plugin support required for
the public protocol. The spike is not a production feature.

- [ ] **T-CAM-6.1** Inventory every thread, mutex, RCU/AIO context, bottom half,
  timer, block backend, descriptor, mapping, and plugin resource in the supported
  deterministic TCG launch profile.
- [ ] **T-CAM-6.2** Prototype `PrepareForkTemplate` and a QEMU-owned coordinator
  that proves all registered subsystems quiescent before process fork.
- [ ] **T-CAM-6.3** Prototype child reinitialization, new QMP/control channels,
  ring remapping, and a fresh branch-private disk overlay.
- [ ] **T-CAM-6.4** Inventory every memory mapping, reject writable shared guest
  RAM, prototype safe `MADV_DONTFORK` reconstruction for eligible scratch state,
  and measure transparent-huge-page, NUMA, allocator, and page-table effects.
- [ ] **T-CAM-6.5** Prove the parent remains unchanged and compare the child's
  first complete quantum with exact restore and thin replay across increasing
  guest RAM sizes.
- [ ] **T-CAM-6.6** Measure latency, page-table/private RSS, descriptor/thread
  leaks, and speedup against exact restore. Record the chosen supported profile
  and any rejected subsystem.
- [ ] **T-CAM-6.7** Stress at least 10,000 child lifecycles, deep template
  promotion, and resource-pressure fallback without unbounded growth.
- [ ] **T-CAM-6.8** Produce QEMU patch license/source-ledger updates and public
  protocol documentation.
- [ ] **T-CAM-6.9** Complete the §14 Phase 6 lab audit of quiescence, memory
  mappings, descriptors, private rings/disks, dirty-page growth, resource leaks,
  rejection paths, and exact/thin fallback using the representative product.

The current QEMU 11.1.1 artifact implements the complete supported-profile
fork transaction. Its QEMU-owned coordinator closes thread, mutex, RCU,
AioContext, AIO handler, bottom-half, timer, block graph, descriptor, mapping,
and plugin admission; authenticates the exact paused/device-flush boundary;
and advertises readiness only while every retained proof remains valid. Unknown
schemas, incomplete inventories, mutable or aliased source resources, external
threads, unclassified subsystem owners, generation drift, and contradictory
proofs fail before `fork(2)`.

The child transaction installs fresh QMP, control, diagnostics, console, plugin
ring, VMState, disk-overlay, network, 9p, and host-continuation resources. It
reinitializes the supported internal workers, discards inherited process-local
registrations, authenticates the parent and child process generations, and
releases guest execution only after the complete branch-private resource set is
installed. The parent remains a paused immutable template. Failed or ambiguous
launches publish no world and retain every process and resource authority for
rollback or quarantine.

The daemon reserves aggregate resources and then launches all running nodes on
scoped concurrent workers. One atomic assembly authenticates every child against
the same source continuation and includes permanently failed and non-VM nodes
before it yields an executable lifecycle. The sequential per-node launcher and
the standalone Phase 6 stress executable were removed; the atomic whole-world
owner is the only production path.

A reconstructed child can be re-adopted at an exact paused boundary and promoted
to a descendant template. Promotion consumes inherited staging state, assigns a
fresh parent generation, re-runs the complete template barriers, and retains the
full ancestor authority chain until final retirement. Native acceptance covers
three adjacent process generations and rejects direct grandchild reuse of an
ancestor identity.

The production scaling gate exercises 64, 256, and 512 MiB guests, concurrent
multi-node launch, exact-restore and genesis-replay equivalence, private-memory
and page-table accounting, NUMA and huge-page observations, and source thread
and descriptor baselines. The production owner also drives 10,000 complete
child lifecycle iterations with bounded private-dirty growth. Manager stress
holds a four-template ceiling across 10,000 pressure admissions, verifies exact
coldest-source demotion and authenticated fallback roots, and keeps the retained
set bounded.

The supported profile is deterministic TCG with one round-robin vCPU per node,
the aggregate fingerprint plugin protocol, raw read-only roots, branch-private
writable overlays, deterministic network links, and first-class block and 9p
subnodes. Unsupported profiles fail before source preparation. Exact/thin
fallback, source demotion, durable retention, restart recovery, cgroup and quota
ownership, and terminal quarantine all use the same packaged-executor
composition.

The atomic patch is reproducible from the pinned upstream base and is retained as
one deterministic DCO-signed-off QEMU commit, patch, and thin bundle. QEMU file
creation/removal is checked against `LICENSES.md`; the public QMP, control, and
shared-memory protocols remain the only Apache/GPL integration surfaces.

T-CAM-6.9 remains a manual representative-product lab audit. Hot fork remains
non-default until that evidence and the Phase 7 dogfood gate are accepted.

**Exit:** the automated structural, equivalence, scaling, isolation, ABI, and
license gates accept the frozen artifact. Product enablement still requires the
manual Phase 6 and Phase 7 evidence recorded below.

## 11.9 Phase 7 — Production hot fork and multi-node worlds

- [ ] **T-CAM-7.1** Complete the closed QEMU subsystem capability registry,
  quiescence acknowledgements, child resource disposition, sandboxing, and
  rollback paths.
- [ ] **T-CAM-7.2** Implement immutable template lifecycle, template identity,
  child readiness authentication, and invalidation rules.
- [ ] **T-CAM-7.3** Implement copy-on-write host continuation clones and exact
  pairing with each QEMU child.
- [ ] **T-CAM-7.4** Implement atomic multi-node world fork with failed-node and
  non-VM I/O-node semantics.
- [x] **T-CAM-7.5** Integrate `HotCheckpointManager`, hotness scoring,
  resource/cgroup limits, demotion to exact/thin, and fallback diagnostics.
  The current managed owner binds each fallback to an exact
  `ExactCheckpointId` or thin `ConfigurationArtifactId`, performs read-only
  fallback and victim preflight before transfer, rechecks fallback validity at
  the demotion boundary, and releases accounting only after the sink attests
  source reap. The concrete sink authenticates exact checkpoints or resolved
  thin replay bases and consumes a fixed prepared-QEMU source into attested
  reap or terminal quarantine. The composed durable owner now roots candidates
  before installation, retains demotions as cold exact/thin roots, fences GC,
  and reconstructs the catalog conservatively after restart. The packaged
  executor binds that owner to the current Linux cgroup/project-quota process
  guard, source and child lifecycle factories, authenticated demotion sink,
  keyed shutdown diagnostics, and restart cleanup for both hot-source native
  namespaces. The real-QEMU equivalence, isolation, leak, and scaling matrix is
  tracked separately by T-CAM-7.6.
- [ ] **T-CAM-7.6** Add the complete equivalence, isolation, negative,
  resource-leak, and scaling matrix from §10.
  The canonical native isolation gate now includes HFORK-10's negative matrix:
  it deliberately omits or aliases the private ring, QMP/control,
  console/diagnostics, writable disk/backing, network, 9p, and host-continuation
  identity through the production whole-world factory. Every case proves an
  explicit no-child rejection before readiness, resume, or world publication,
  exact source-process identity preservation, target cleanup, and zero partial
  adoption. The production owner now also contains the equivalence, three-size
  RAM, concurrent multi-node latency, ten-thousand-lifecycle leak, and supported
  profile scaling matrix. T-CAM-7.6 remains unchecked until those frozen-artifact
  flights execute successfully.
- [ ] **T-CAM-7.7** Complete the §14 Phase 7 atomic multi-machine,
  massive-parallelism, deep-template, pressure, operator-handoff, and 24-hour
  dogfood flight with a final process/descriptor/memory/disk/store audit.

**Gates:** `gate:hot-fork-equivalence`, `gate:hot-fork-isolation`,
`gate:hot-fork-scaling`, `gate:world-fork-atomicity`,
`gate:license-boundary`, `gate:abi-conformance`.

**Manual gate:** accepted §14 Phase 7 dogfood evidence; hot fork remains
non-default before this gate.

## 11.10 Phase 8 — User-facing porcelain

Primary crates: `crucible-cli`, `crucible-api`, and `crucible-daemon`.

- [x] **T-CAM-8.1** Implement campaign create/validate/start/pause/resume/stop,
  budget, steer, semantic `branch`, campaign `derive`, status, and watch. The
  checked local client now exposes canonical create/derive inputs and exact
  finite or already-imported generated operator branch requests in addition to
  lifecycle control. Exhaustive `--all` authenticates the exact current
  opportunity domain, derives the canonical version-2 generator and
  cardinality budget, and is owner-checked against the active exhaustive policy
  before publication. The initial repeatable daemon-startup import manifest now
  admits dependency-ordered compact scenario/schedule pairs and canonical
  generator bodies through the narrow verifier-backed importer before endpoint
  bind. Offline `campaign validate-import` now applies the same strict file and
  configuration checks, requires a self-contained dependency-ordered generator
  set, streams one body at a time, and reports exact derived identities without
  opening repository state. `campaign create --start-command COMMAND` now
  submits a separate idempotent `Resume` against the exact returned genesis
  snapshot and reports both checked results; creation and start are deliberately
  retry-safe rather than atomic. The standalone `campaign start` command now
  applies the same exact-preconditioned, idempotent `Resume` transition while
  retaining `start` as the reported operator intent. Operator branch porcelain
  now resolves an exact declaration name, selectable ID, or semantic tag
  through the proof-bearing choice index and separately authorized
  opportunity/declaration/domain reads.
  Up to sixteen repeated predicates form a conjunction; resolution scans to
  authenticated EOF under a 4,096-opportunity ceiling and rejects absent or
  ambiguous matches before publication. Strict offline policy authoring now
  compiles a bounded, deny-unknown-fields version-two TOML schema through the
  same public typed constructors used by canonical decoding, rejects duplicate
  semantic keys before output, and durably creates one non-overwriting binary
  policy record while reporting its exact content identity. The adjacent strict
  lineage compiler binds semantic scenario/genesis identities to their exact
  imported artifacts and current execution-compatibility identity through the
  same bounded non-overwriting path. Canonical scenario authoring now consumes
  the engine's complete strict current-schema TOML, derives an empty genesis
  schedule plus both semantic and verifier-backed artifact identities, and
  atomically installs a new bounded scenario/schedule/import-manifest directory
  without opening repository state. Non-genesis configuration authoring now
  admits a nonempty byte-canonical Schedule V2, rejects noncurrent, empty, or unresolved-
  selection inputs, independently verifies the derived configuration artifact,
  and installs the same bounded no-replace import bundle. Strict offline
  decision authoring now compiles bounded `delivery-order`, `rng-draw`,
  `override`, and both `preemption` forms into a byte-checked canonical Schedule
  V2 without exposing noncurrent app-random or repository-authenticated selection
  construction. Policy authoring now resolves exact selectable
  IDs and bounded all-tags predicates through an exact matching canonical
  scenario, rejects absent/ambiguous/drifted selectors before output, and emits
  the unchanged stable-name canonical policy identity. The documented
  `campaign validate` porcelain now has two non-ambiguous trust boundaries:
  `--policy FILE` performs a bounded offline canonical decode/re-encode and ID
  derivation, while `validate NAME` authenticates the current named head through
  the existing request-bound checked service and reports its exact lifecycle
  projection.
- [x] **T-CAM-8.2** Implement graph/frontier/choices/findings/explain/compare
  queries with branch-point/source/provenance views, pagination, and versioned
  JSON. Snapshot-bound graph/frontier/choices/findings traversal is exposed
  through the checked local client in table, Markdown, JSON, and JSONL. One
  page remains the default; an explicit page budget follows at most 256 pages
  while admitting at most 65,536 aggregate entries and 128 MiB of aggregate
  canonical response bytes. Each page is independently proof- and
  request-validated before accumulation, repeated cursors fail closed, and the
  version-2 report preserves the start/resume cursor, authenticated EOF, and
  exact page/byte accounting. Exact graph configuration/opportunity bodies, choice
  declaration/domain dependencies, and frontier branch requests are also
  exposed through their separately authorized proof-bearing operations with
  semantic source, budget, continuation, and provenance fields. Exact historical
  snapshot inspection and two-snapshot comparison use independently checked
  named-history reads and report policy, transition, direct-parent, and all-root
  changes. The first explanation operation joins an authenticated choice
  declaration to an authenticated frontier request and fails closed unless
  their opportunity and domain agree before reporting legality, producer,
  cause, budget, stop, and continuation state. A proof-bearing findings page
  returns complete canonical clusters in signature-key order and renders their
  stable failure and reproduction projection. A second explanation operation
  composes separately authorized observation and reproduction reads for one
  exact indexed finding, rejects cross-finding/configuration/fingerprint drift,
  and renders its causal, evidence, occurrence, stop, and replay basis.
  Exact attempt/execution-basis/proposal/completion explanation now also proves
  the coordinator-accepted planner step for planner-issued proposals and
  renders its fixed-point guidance decomposition and accounting. Aggregate
  ranking now has a public owner-independent per-request projection: it
  revalidates each retained offer/guidance pair against the by-value policy,
  recomputes the decomposed fixed-point score, and returns best-first order with
  the exact packaged-planner edge/position tie-break. The proof-bearing
  `GetCampaignPlannerRankings` query authenticates one accepted step under the
  current snapshot's coordination root, returns its complete retained request,
  and exposes the parent step as the next page. CLI `campaign rankings` follows
  at most 64 such pages under a 128 MiB aggregate response-byte budget and
  applies the same deterministic comparator across all candidates, stopping at
  a policy/engine/artifact/view boundary. Exact branch-point and source filters
  run after proof validation, and an at-most-65,536 top-result cap runs after
  global best-first ordering; the versioned machine report retains the filter
  basis and pre-truncation match count. `--policy-groups` now continues across
  policy changes under the same page/byte/cycle bounds, emits consecutive
  policy epochs, and nests separately ordered exact
  policy/engine/policy-artifact/planning-view bases. It preserves each epoch's
  step range and pre-truncation count, applies filters only after proof
  validation, and applies the top-result limit per comparable basis rather than
  comparing incompatible scores. Focused CLI coverage executes every graph,
  choice, frontier, and finding page branch through the checked client; common
  aggregation regressions prove authenticated EOF, cursor-cycle rejection, and
  aggregate byte bounds.
- [x] **T-CAM-8.3** Complete pin/unpin by consuming its authenticated semantic
  projection in generation-bound GC retention plans. Snapshot-bound semantic
  and operational root inventory plus the exclusive generation-bound memory,
  directory, compressed-directory, encrypted-directory,
  compressed-encrypted-directory, and packed
  physical-leaf inventory/delete,
  authoritative-ref
  inventory, and operational-ledger inventory primitives plus the canonical
  bounded plan identity are implemented. The daemon now constructs the
  canonical root and physical-candidate manifests, authenticates their complete
  logical closure,
  produces a non-destructive plan across an ordered set of physical leaves,
  persists the exact plan/manifests and phase in a durable external journal, and
  excludes campaign children-before-ref publication with a shared/exclusive ref
  lifecycle fence. `StoreGraph::build_with_admin` now returns a separate,
  non-cloneable maintenance capability containing every current physical leaf
  in canonical node-ID order; the ordinary graph retained by the repository has
  no administrative escape. The graph and administrative value share one
  registered canonical configuration identity, and public GC plan/apply derive
  both that identity and the exact physical capability set from the
  administrative value rather than accepting independently supplied inputs.
  Exact-generation single-host physical-leaf apply now revalidates every root
  and physical basis, deletes under the leaf fence, and leaves interrupted
  journals recovery-required. One restart regression applies that path to a
  compressed-directory leaf, and another applies it to an encrypted-directory
  leaf with a separately reconstructed key capability. A third applies the
  same restart boundary to a compressed-encrypted leaf. All three prove
  inventory/candidate accounting uses authenticated plaintext lengths, delete
  only the unreachable physical placement, and reauthenticate the retained
  plaintext after reopening every durable component. A further regression
  applies it to a sparse packed leaf and proves
  logical deletion retains the live object and shared pack. Exact-pin
  materialization selection is now
  restart-safe, exact-configuration/fact-bound, and consumed by both planning
  and apply; stale records cease to root checkpoint closures after unpin.
  Policy-aware v2 planning and apply now evict reachable read-through cache
  placements only across unique, physically independent cache/source
  identities with graph-derived roles, EOF-authenticated required bytes, and
  paired exact-generation fences. Public generation-bound GC plan/apply,
  generation-bound packed repack plan/apply, and bidirectional archive
  transfer/inspection now cover the current GC, packed transform,
  export/import, and push/pull/synchronization porcelain without compatibility
  aliases. Direct authenticated `campaign debug` now binds a snapshot finding
  proof to the cheapest complete retained exact-state closure, admits it through
  the shared lifecycle plane as an exclusive read-only session, and relays only
  observation-safe GDB packets. The packaged public-process regression now
  carries one semantic exact pin through materialization, offline GC plan/apply,
  public unpin, and a new plan that rejects the stale selection. Independent
  operator acceptance remains separately tracked by T-CAM-8.6.
  `campaign replay` now authenticates one snapshot-bound finding
  reproduction, requires its current payload schema and semantic binding, and
  invokes the pure replay oracle without a temporary artifact.
- [x] **T-CAM-8.4** Route existing run/search/fuzz/save/resume/fork/replay/triage
  through common branch-request and campaign primitives and remove parallel
  explicit-fork/search-expansion state models. The non-interactive local-QEMU
  `run` path, including `--watch`, now executes through the authenticated
  scenario-default campaign owner. Watch records name the exact campaign and
  snapshot and pair that head with the scheduler evidence captured at the same
  incorporation boundary; the CLI retains them under the owner's fixed bound
  until its synchronous backend result is rendered. Campaign-produced replay
  uses the same owner, and unsupported decision kinds are rejected before
  execution. `campaign triage` enumerates one exact snapshot through
  `CampaignService`, authenticates each retained finding's membership,
  occurrence objects, and segmented native replay evidence, and derives the
  triage input from those proofs. Top-level `triage` is exact campaign
  porcelain; the former caller-supplied ledger command and standalone
  finding-triage fixture are removed. Standard
  local production-QEMU virtual-time saves now reach the requested stop through
  that campaign owner, replay the accepted attempt once through scoped exact
  capture, authenticate the Ready request/resolution, source attempt, stop,
  configuration, physical closure, and scheduler evidence, and remove the
  temporary physical closure before returning. They export the version-6
  handle and version-3 logical DAG closure index described below, so current
  resume and fork readers consume the result without native exact-resume
  acceleration. Campaign-backed
  marker saves now use the same exact-capture owner with a named-boundary stop.
  They export a version-6 handle with a campaign-marker-event proof containing
  the retained, canonically recomputable scheduler event and a required,
  digest-bound campaign replay closure. Campaign virtual-time saves use the same
  v6 closure contract. Export authenticates the canonical closure against the
  exact schedule before durable writes, stores it as a content-addressed object,
  and retains it through the opaque reference in local checkpoint closure-index
  v3. Readers accept only the current version-6 campaign handle and
  closure-index v3. Any other handle or closure-index schema, typed schedules
  missing a closure, unsupported session-run producers, tampered closure bytes, and
  missing referenced objects fail before execution.

  Standard non-interactive local-QEMU resume now uses the campaign owner for
  version-6 handles and bare checkpoint hashes backed by
  closure-index v3. Delivery-order, random-draw, preemption, and typed
  guest Selection schedules authenticate the logical source and replay closure,
  capture and restore the exact source, continue to quiescence, virtual-time, or
  terminal completion, apply replayed guest replies through the live selectable
  boundary, and replay-validate the descendant checkpoint. Standard unattended
  unchanged local-QEMU fork targeting virtual time or stopped completion uses
  the same continuation owner and projects its source and terminal proof through
  the fork contract. Its reproduction artifact retains the authenticated replay
  closure and rematerializes the full schedule through campaign replay.
  Remote fat-checkpoint resume carries the required versioned replay-closure
  envelope for every admitted current schedule. The envelope identity binds the exact
  scenario, configuration, checkpoint bytes, schema version, size, and
  canonical closure. A newly started daemon reconstructs and authenticates the
  closure after ordinary checkpoint validation and before backend or session
  allocation, then retains the existing interactive, watch, stop, and cleanup
  controls. Missing, noncurrent, or mismatched closure envelopes fail before
  allocation; resume does not select another execution path as a fallback.
  Typed public branching now uses the common `campaign branch` request, while
  property stops, quiescence and property saves, and production-QEMU search and
  fuzz use the same guarded campaign owner. Direct campaign finding replay uses
  the authenticated CampaignService dependency proof and pure oracle. Direct
  campaign debug session allocation uses the same shared lifecycle registry,
  retains its exact checkpoint and finding proof for the session lifetime, and
  releases its exact idempotence reservation when the lifecycle removes the
  session. Campaign debug can now explicitly fork that authenticated restore
  into a private writable derivative. The shared actor records and validates
  the non-canonical branch proof before lifecycle access changes, and the CLI
  reports the exact branch and reusable session identity. Long-lived campaign
  debug sessions now persist their complete open request and authenticated
  finding proof in a bounded current-only inventory under the campaign state
  owner. Startup reauthenticates the proof, artifacts, and exact checkpoint and
  readmits each session to the shared registry; explicit lifecycle destroy
  removes its durable entry. The repository owner lock excludes concurrent
  daemon recovery, and the common lifecycle list/destroy surface supplies
  administrative inventory and cleanup. Recovery returns to the authenticated
  canonical checkpoint read-only; non-canonical branch mutations remain
  ephemeral and require another explicit fork after restart. The
  built-in fault family now resolves through the same backend route
  as every other family: production QEMU executes every generated iteration
  through the guarded campaign owner and retains its campaign completion,
  coverage, finding, reproduction, and control-plane proof; test-double builds
  exercise the ordinary local-double family runner rather than a separate
  example-report dispatcher.
- [x] **T-CAM-8.5** Publish user documentation and the worked network campaign
  as an executable fixture. The public Crucible guide now documents the
  shipped single-host campaign surface: strict offline import, managed daemon
  ownership, authenticated creation and inspection, lifecycle mutations,
  proof-bearing explanations, restart rules, and packaged local execution. The
  `campaign fixture worked-network` command now emits an owner-only canonical
  scenario/configuration, lineage, policy, and dependency-ordered generator
  import set. It revalidates the manifest before success, and an automated
  blank-repository flight imports the complete set and creates the campaign
  through the checked service API. The generated control-plane fixture omits
  product kernel/root-image references; the actual supported product build and
  full QEMU flight remain mandatory under T-CAM-8.6 and §14.
- [ ] **T-CAM-8.6** Have an operator who did not implement the feature complete
  the §14 standard lifecycle, finding-to-debug handoff, steering, retention, and
  cleanup flights using only public documentation and porcelain.

**Gates:** CLI/API contract tests, `gate:campaign-cold-continuity`,
`gate:campaign-replay`, and existing control-responsiveness gates.

**Manual gate:** `gate:campaign-operator-acceptance` with accepted §14 Phase 8
evidence.

## 11.11 Phase 9 — Final integration and release criteria

The local executor now distinguishes stopping admission from completing worker
cleanup. Its service waits at most thirty seconds for semantic workers (or
returns immediately for permanent retention), reports `CleanupPending`, and
leaves reservations, phase tokens, ledger/repository authority, and endpoint
ownership with unfinished workers. Regression coverage verifies endpoint reuse
is rejected until cleanup completes and completion is not announced before an
execution model's destructor returns. This does not satisfy the real recovery
or operator-sign-off gates below.

The automated Phase 9 surface exposes the self-contained finding replay at
`checks.crucible.phase9.gates.campaignFindingPortability` and validates the
signed release-evidence schema at
`checks.crucible.phase9.gates.campaignReleaseAcceptanceContract`. The final
`checks.crucible.phase9.gates.campaignReleaseAcceptance` composition remains a
red release blocker unless the caller supplies the four signed manual evidence
bundles and an external trusted-signers file through the root
`crucibleCampaignReleaseEvidence` argument. When supplied, it composes those
inputs with the current gate matrix, operational-continuity and portability
results, production hot-fork scaling gate, Crucible package, release manifest,
and the separately exposed acceptance-contract validator. It never substitutes
a source-tree fixture for manual evidence.

- [ ] **T-CAM-9.1** Run all existing Crucible determinism, replay, signal-fault,
  ABI, QEMU, package, and license gates with campaigns disabled and enabled.
- [ ] **T-CAM-9.2** Run performance baselines and prove the hot path meets the
  required scaling shape and minimum speedup.
- [ ] **T-CAM-9.3** Prove coordinator/executor restart, exact pause, backend-
  neutral archival and offline maintenance transfer, and fast midpoint
  debugging.
- [ ] **T-CAM-9.4** Prove all findings remain self-contained and reproduce on one
  host with no campaign daemon or shared store.
- [ ] **T-CAM-9.5** Verify no prohibited native pointers, QEMU structures,
  callbacks, Rust-native layouts, host paths, or distribution metadata cross the
  process/storage boundaries.
- [ ] **T-CAM-9.6** Update canonical user docs only after implementation behavior
  passes the full gate set.
- [ ] **T-CAM-9.7** Run the complete 72-hour §14 release-candidate dogfood,
  destructive recovery, exact-pause/maintenance transfer, finding handoff, GC,
  cleanup, defect-disposition, and cross-owner sign-off flight.

**Manual gates:** `gate:campaign-operator-acceptance`,
`gate:campaign-destructive-recovery`, and `gate:campaign-dogfood`.

## 11.12 Implementation completion definition

This RFC is implemented only when:

- typed environment and guest choices use one selection model;
- explicit finite branches and generated exploration use one branch-point,
  request, edge, and lazy expansion model with provenance-preserving dedup;
- large integral domains are explored lazily with feedback and progressive
  widening;
- campaign pause/restart reconstructs the complete frontier and knowledge;
- local campaigns pull bounded attempts with deterministic replay evidence;
- direct and loopback-RPC coordinator/executor paths produce identical facts;
- exact closures stream through a validated composable store graph;
- hot fork is either production-gated for its declared TCG profile or explicitly
  rejected and removed from the completion claim;
- user-facing campaign commands operate on the one snapshot model;
- an independent operator completes the public lifecycle and another
  investigator reproduces a finding solely from its exported bundle;
- destructive process, host, store, credential, pressure, hot-fork, and GC drills
  preserve the last authenticated state and require no private repair;
- the realistic 72-hour dogfood flight sustains useful parallelism, steering,
  exact pause and archive transfer, handoff, and clean resource accounting;
- every required gate is green with no alternate compatibility runtime.

## 11.13 Initial requirement traceability

Phase 0 freezes this mapping at individual-requirement granularity. The initial
area mapping ensures that no part of the RFC is merely aspirational:

| Requirements | Primary phases | Primary gates |
| --- | --- | --- |
| `CAM-1..14` | 1–9 | campaign model, replay, continuity, ABI, license boundary, manual acceptance |
| `CMOD-1..30` | 1, 2, 4 | campaign model, content address, attempt idempotence, continuity |
| `SEL-1..21` | 2 | typed choice, ABI conformance, end-to-end determinism |
| `GUIDE-1..32` | 3, 4 | lazy frontier, campaign statistics, campaign replay |
| `LAZY-1..48`, `LAZY-54` | 4 | lazy frontier, attempt idempotence, campaign replay |
| `CCOMP-1..24` | 0, 4, 8 | component contract, control responsiveness, attempt idempotence, ABI conformance |
| `HFORK-1..24` | 6, 7 | hot-fork equivalence/isolation/scaling, world-fork atomicity, ABI/license |
| `CSTORE-1..28` | 1, 5 | store equivalence, store composition, exact-closure streaming, continuity |
| `CAPI-1..14` | 8 | CLI/API contracts, continuity, campaign replay |
| `CMEAS-1..14` | 3, 8 | campaign model, replay, ABI conformance |
| `CSEC-1..12` | 1–9 | license boundary, ABI conformance, isolation, store equivalence |
| `CPERF-1..9` | 4–7, 9 | branch-point model, lazy frontier, hot-fork scaling/equivalence, exact-closure streaming |
| `CMAN-1..22` | 0–9 | operator acceptance, destructive recovery, dogfood, campaign replay |

The executable traceability check required by T-CAM-0.4 must expand every range,
name at least one implementing task and test for each requirement, reject stale
IDs in either direction, and remain part of the completion gate.
