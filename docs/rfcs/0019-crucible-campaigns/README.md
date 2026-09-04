# RFC-0019: Crucible campaigns, adaptive exploration, and hot forking

- **Status:** Proposed. Implementation is landing incrementally in this draft
  pull request behind non-default library and test surfaces; no campaign or
  hot-fork path is enabled as a supported default before its listed gates.
- **Date:** 2026-08-18
- **PR:** [#194](https://github.com/andyl-technologies/aos/pull/194)
- **Depends on:** [RFC-0010](../0010-crucible/README.md) and
  [RFC-0014](../0014-signal-driven-fault-model/README.md), including RFC-0014's
  exact production checkpoint closure and stable fault-opportunity identities.
- **Audience:** Crucible scenario authors, `crucible-*` crate maintainers, QEMU
  patch and plugin maintainers, campaign operators, storage-backend authors,
  and developers of guest applications that expose white-box choices or
  measurements.

This RFC defines a **campaign** as a persistent, adaptive exploration of one
Crucible scenario lineage. A campaign may stop at a deterministic midpoint,
retain that state as a hot or durable checkpoint, explore a small and changing
subset of a vast choice space, feed descendant observations back into the
exploration policy, and revisit an earlier checkpoint to admit additional
branches. It unifies systematic search, probabilistic sampling,
coverage-guided fuzzing, performance optimization, manual branching,
hibernation, and failure retention over the same content-addressed temporal
graph. The supported deployment is one coordinator and one local executor;
their language-neutral contract is implemented now without implementing
multi-host scheduling.

The core model is intentionally small:

```text
Scenario says what may happen.
Campaign says what is worth trying.
Schedule says what did happen.

CampaignRef -> immutable CampaignSnapshot
                    |
                    +-- scenario lineage and active policy
                    +-- temporal graph
                    +-- branch points and lazy expansion state
                    +-- observations, corpus, coverage, and findings
                    +-- retention pins and accounting
                    +-- non-semantic coordination progress
```

Every object under the named campaign reference is immutable and content-
addressed. The frontier is a derived projection of branch-point facts, not a
directory of mutable VM processes. QEMU processes, exact checkpoint files,
local copy-on-write mappings, and daemon work queues are realizations and
caches. They affect cost, never branch identity.

## Problem

RFC-0010 established the deterministic execution model, temporal graph,
guided exploration, content-addressed campaign storage, and a shared-work
foundation. RFC-0014 adds exact cross-process checkpoint closures and stable,
typed signal-fault opportunities. Those foundations are necessary but do not
yet provide the cohesive production model required for extremely wide,
feedback-directed campaigns:

- the current search frontier enumerates a finite set of concrete decisions
  and conceptually expands a frontier checkpoint once;
- guest-controlled exploration is exposed primarily as random values rather
  than typed integral and discrete selectables;
- environmental parameter selection and guest application selection have
  different authoring and runtime surfaces;
- adaptive guidance chooses broad search strategies but does not yet own a
  uniform typed candidate-generation model;
- a large integral domain cannot be enumerated and requires lazy sampling,
  progressive widening, and feedback from descendants;
- the current durable exact checkpoint path authenticates and chunks complete
  artifacts but does not provide a cheap live on-host fork of a paused QEMU
  world;
- the existing shared frontier reserves checkpoint nodes, while progressive
  widening must revisit one checkpoint many times and therefore needs
  idempotent attempt-level work;
- the campaign manifest does not yet name the exploration facts, lazy frontier,
  objectives, measurements, pins, and accounting needed to stop and resume a
  complete adaptive campaign.

Without a single model for those concerns, search, fuzzing, optimization,
manual branching, debugging, and external coordinator implementations would
grow separate control planes and subtly different replay semantics.

## Design thesis

A campaign is a **named reference to an immutable snapshot of accumulated
exploration knowledge**. That snapshot names an append-only set of facts and
content-addressed projections. From it, Crucible can derive every open branch
point and its expansion state, regenerate every candidate source, reproduce
every branch, restore every retained checkpoint, and explain every adaptive
planning decision.

```text
                     immutable CampaignPolicy
                              |
Scenario -> ChoiceOpportunity -> BranchPoint -> BranchRequest
                                            |          |
                                            +-> Proposal -> Attempt
                                                           |
                                                    Observation -> Finding
                              |
                    content-addressed facts
                              |
                  deterministic projections
                /             |             \
        temporal graph   lazy frontier   campaign knowledge
                \             |             /
                       CampaignSnapshot
                              ^
                              |
                    one CAS-updated ref
```

The coordinator submits bounded `Attempt` objects to the local executor. Neither
component enumerates the entire state space, and the executor does not own
campaign policy. The executor materializes each attempt
from the cheapest correct realization: a paused hot-fork template, a durable
exact closure, or thin replay. Descendant observations update campaign
knowledge and may make an ancestor branch point eligible to yield more
candidates from its expansion state.

## Branching and expansion are one model

A protocol producer exposes a typed `ChoiceOpportunity`. When execution reaches
it, the pair `(parent ConfigurationId, ChoiceOpportunityId)` identifies a
`BranchPoint`. The campaign attaches `ExpansionState` to that semantic point:
branch requests, candidate sources, proposals, observations, statistics, and
suspended continuations.

An explicit branch is therefore the small finite case of ordinary expansion. A
request for `{0, 20 ms, 500 ms}` may target an integer domain with billions of
legal values. Progressive widening at the same point uses a generated source.
Both are additive and lazily pulled under the same budgets. If they propose the
same value, their causes remain auditable, one semantic edge is reused, and any
attempt with identical remaining semantic inputs deduplicates.

This use of **branch** is distinct from deriving a new named campaign, QEMU
**hot fork** realization, and non-canonical debugger mutation. A checkpoint is
not automatically a branch point, and a branch point does not require a hot-
fork-capable checkpoint.

## Relationship to RFC-0010 and RFC-0014

This RFC preserves RFC-0010's identity and determinism contracts:

- a configuration remains exactly `(ScenarioDef, Schedule)`;
- temporal-graph edges remain recorded deterministic decisions;
- `instantiate` remains the one semantic realization operation;
- materialization and executor placement never enter configuration identity;
- every finding remains reproducible without a campaign, daemon, worker pool, or
  shared store.

It refines three RFC-0010 control-plane decisions:

1. A search frontier is no longer just the set of checkpoints not yet expanded.
   It is the projection of **open branch points and their expansion
   continuations**, and one configuration may yield additional attempts
   repeatedly.
2. Local execution assignments are keyed by immutable `AttemptId`, not only by
   checkpoint identity. A parent configuration may have many independently
   executable attempts over its lifetime.
3. The persistent campaign head names a complete `CampaignSnapshot`, including
   graph, exploration, observation, pin, and accounting roots. The existing
   corpus, coverage, findings, genesis, and provenance roots remain part of that
   snapshot.

RFC-0014's `FaultOpportunity` becomes an environment-originated
`ChoiceOpportunity`. Pairing it with the semantic parent configuration creates
a campaign `BranchPoint`. Its typed domain adapter still owns effect validation,
composition, and application. This RFC adds the shared selection and campaign
layer above those adapters; it does not replace signal evaluation or turn typed
effects into arbitrary callbacks.

## Goals

- **[CAM-1]** Provide one persistent campaign model for systematic search,
  probabilistic sampling, coverage-guided mutation, progressive widening,
  performance optimization, manual branching, and failure minimization.
- **[CAM-2]** Expose environment, scheduler, workload, and guest application
  degrees of freedom as one typed choice-opportunity and branch-point model with
  integral and discrete domains.
- **[CAM-3]** Keep model probability, exploration proposal probability, and the
  realized recorded selection distinct and auditable.
- **[CAM-4]** Represent the frontier lazily so an enormous latent state space
  requires storage proportional to admitted work and observations, not to every
  possible child.
- **[CAM-5]** Permit descendant feedback to revisit an immutable ancestor and
  admit more candidates without mutating or merging VM state.
- **[CAM-6]** Make a campaign fully pausable, resumable, branchable, derivable,
  inspectable, archivable, transferable, and garbage-collectable from its content-addressed
  snapshot.
- **[CAM-7]** Make the common on-host branch path share paused QEMU memory pages,
  immutable disk state, log prefixes, and host continuation state copy-on-write.
- **[CAM-8]** Preserve a portable durable exact closure for hibernation,
  midpoint debugging, failure retention, and offline maintenance transfer.
- **[CAM-9]** Bound runnable branches by host resources while allowing millions
  of dormant logical continuations and pending possibilities.
- **[CAM-10]** Define a user-facing campaign file, CLI, daemon API, event stream,
  status model, and artifact format that all project the same underlying data.
- **[CAM-11]** Keep the Apache host and GPL QEMU/plugin in separate processes
  with only versioned socket and shared-memory protocols across the boundary.
- **[CAM-12]** Implement a language-neutral coordinator/planner/local-executor
  contract whose in-process and local RPC adapters are semantically equivalent,
  without implementing multi-host scheduling.
- **[CAM-13]** Require independent, evidence-backed manual acceptance,
  destructive recovery drills, and long-running realistic dogfood campaigns in
  addition to automated conformance before campaigns or hot fork become
  defaults.
- **[CAM-14]** Treat explicit operator branching and adaptive expansion as
  candidate sources attached to the same branch point, while keeping campaign
  derivation and QEMU hot forking as distinct operations.

## Non-goals

- The first implementation does not build a multi-host campaign coordinator,
  remote page server, post-copy migration system, or network fanout service.
- This RFC does not embed a general-purpose campaign programming language or
  accept arbitrary in-process planner callbacks. A bounded pure planner
  contract permits a separately reviewed future engine.
- The first implementation does not estimate real-world failure probability
  from a guidance-biased bug-hunting campaign. Statistically valid estimation
  requires the explicit probability rules in
  [`03-exploration-and-guidance.md`](03-exploration-and-guidance.md).
- This RFC does not merge live mutable VM states or concurrent campaign-writer
  histories. `derive` creates another named ref sharing immutable facts and
  graph objects; selection between branches is never a VM-state merge.
- This RFC does not let guest-provided code, closures, scripts, native pointers,
  or QEMU-private structures enter canonical choice or campaign data.
- This RFC does not make every latent choice a live process or even a stored
  temporal-graph node. A child becomes a graph node only after its attempt
  produces a canonical configuration.
- This RFC does not permit host wall time, completion arrival order, executor
  capacity, or
  cache placement to affect an individual run's state or reproduction artifact.
- This RFC does not promise that arbitrary multithreaded QEMU state is safe to
  `fork(2)`. Hot forking is admitted only through the explicit quiescence,
  reinitialization, isolation, and equivalence gates in
  [`05-hot-fork-and-checkpoints.md`](05-hot-fork-and-checkpoints.md).

## Non-negotiable invariants

1. **One execution identity.** A branch is identified only by its scenario and
   recorded schedule. Campaign and materialization metadata are not inputs.
2. **One mutable campaign ref.** A user-visible campaign name points to one
   immutable snapshot. All durable objects below it are content-addressed.
3. **Typed choices.** Every selected value validates against a versioned,
   hashed domain. Replay rejects a changed domain or choice-opportunity
   identity.
4. **Recorded adaptation.** Every proposal names the policy and observation
   snapshot that caused it. Adaptive decisions are explainable after the fact.
5. **Lazy admission.** Possibility does not imply materialization. Only admitted
   proposals and completed configurations consume graph storage.
6. **Reader-only guidance.** Feedback chooses future work; it never mutates a
   realized configuration or feeds unrecorded data into `reduce`.
7. **Exact arithmetic.** Canonical domains, probabilities, scores, rewards, and
   ordering use integers, rationals, or fixed-point values, never native floating
   point.
8. **Idempotent work.** Repeating an attempt after a crash produces the same
   canonical child or the same localized divergence and is safe to deduplicate.
9. **Cache independence.** Hot forks, exact closures, thin replay paths, local
   affinities, and evictions are interchangeable realizations of the same
   configuration.
10. **Fail-closed compatibility.** Scenario, policy, checkpoint, QEMU, plugin,
    guest protocol, and store schema mismatches are rejected before execution.
11. **Process-license boundary.** QEMU fork coordination and QEMU state
    extraction remain GPL-side; the Apache host sees only public versioned
    protocol data and opaque authenticated artifacts.
12. **Self-contained findings.** Every finding exports the scenario, seed,
    recorded schedule, evidence, and required artifact identities needed for
    single-host reproduction without campaign state.
13. **Human-operable release.** Green automated gates do not waive a failed
    operator, recovery, finding-handoff, or dogfood flight. Manual acceptance
    uses only supported interfaces and retains reviewable evidence.

## Reading order

1. [`00-goals-and-invariants.md`](00-goals-and-invariants.md) fixes vocabulary,
   scope, and the determinism boundary.
2. [`01-campaign-data-model.md`](01-campaign-data-model.md) defines campaign
   lineages, policies, snapshots, branch points, requests, facts, graph
   objects, projections, and lifecycle.
3. [`02-selectables-and-choice-protocol.md`](02-selectables-and-choice-protocol.md)
   defines typed integral and discrete selectables shared by guest and
   environment producers.
4. [`03-exploration-and-guidance.md`](03-exploration-and-guidance.md) defines
   finite and generated candidate sources, explicit branches, probabilistic
   exploration, progressive widening, MCTS/PUCT, beam and Pareto selection,
   guidance, and statistical validity.
5. [`04-lazy-frontier-and-daemon.md`](04-lazy-frontier-and-daemon.md) defines
   persistent iterators, attempt scheduling, feedback, daemon ownership,
   backpressure, and local recovery.
6. [`04a-coordinator-executor-contract.md`](04a-coordinator-executor-contract.md)
   defines the language-neutral campaign, planner, and local-executor component
   contracts shared by direct and RPC clients.
7. [`05-hot-fork-and-checkpoints.md`](05-hot-fork-and-checkpoints.md) defines
   single- and multi-node QEMU hot forks, host continuation cloning, durable
   checkpoints, hibernation, and migration.
8. [`06-storage-replication-and-gc.md`](06-storage-replication-and-gc.md) defines
   content-store traits, pluggable leaf backends, tiering, routing, packing,
   pinning, archival transfer, and garbage collection.
9. [`07-user-experience-and-apis.md`](07-user-experience-and-apis.md) defines the
   campaign file, CLI, daemon API, views, steering, and compatibility with
   existing commands.
10. [`08-observability-measurement-debugging.md`](08-observability-measurement-debugging.md)
   defines barriers, measurements, properties, metrics, selection evidence,
   retained failure state, and debugger branches.
11. [`09-security-compatibility-and-operations.md`](09-security-compatibility-and-operations.md)
    defines trust, bounds, sensitive state, provenance, upgrades, and operational
    failure handling.
12. [`10-performance-and-validation.md`](10-performance-and-validation.md)
    defines cost models, required metrics, conformance gates, and acceptance
    targets.
13. [`11-implementation-plan.md`](11-implementation-plan.md) sequences the
    implementation intended to follow this documentation review.
14. [`12-decisions-and-open-questions.md`](12-decisions-and-open-questions.md)
    records resolved decisions and the few questions intentionally left for
    measured implementation spikes.
15. [`13-worked-network-campaign.md`](13-worked-network-campaign.md) walks one
    network-disruption campaign from scenario authoring through adaptive
    branching, selection, hibernation, and reproduction.
16. [`14-manual-validation-and-dogfooding.md`](14-manual-validation-and-dogfooding.md)
    defines independent operator acceptance, realistic dogfood, destructive
    recovery, evidence bundles, and release-blocking manual gates.
17. [`schema-registry.tsv`](schema-registry.tsv) assigns each wire and object
    schema its version owner, storage domain, and compatibility gates.

## Requirement prefixes

| Prefix | Area |
| --- | --- |
| `CAM` | Whole-campaign goals and invariants |
| `CMOD` | Campaign data model and lifecycle |
| `SEL` | Selectables, choice domains, and guest/environment protocol |
| `GUIDE` | Candidate generation, guidance, probability, and optimization |
| `LAZY` | Lazy frontier, continuations, daemon, attempts, and feedback |
| `CCOMP` | Coordinator, planner, executor, language-neutral wire contract, and component conformance |
| `HFORK` | Hot QEMU fork and multi-node world cloning |
| `CSTORE` | Content stores, tiering, routing, packing, archival transfer, pinning, and garbage collection |
| `CAPI` | User-facing schema, CLI, API, and event stream |
| `CMEAS` | Measurement, observability, findings, and debugging |
| `CSEC` | Security, compatibility, provenance, and operations |
| `CPERF` | Performance targets and validation gates |
| `CMAN` | Manual validation, dogfooding, usability, and operator acceptance |

The capitalized words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** have their RFC-2119/RFC-8174 meanings. All illustrative code and schema
blocks are labeled; field tables and explicit requirements are normative.
