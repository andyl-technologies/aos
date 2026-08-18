# RFC-0015: Crucible campaigns, adaptive exploration, and hot forking

- **Status:** Proposed. This initial review checkpoint is documentation-only.
  Implementation is planned in this RFC's draft pull request after design
  review; no campaign or hot-fork implementation is enabled by this document.
- **Date:** 2026-08-18
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
coverage-guided fuzzing, performance optimization, manual forks, hibernation,
failure retention, and eventual multi-host work distribution over the same
content-addressed temporal graph.

The core model is intentionally small:

```text
Scenario says what may happen.
Campaign says what is worth trying.
Schedule says what did happen.

CampaignRef -> immutable CampaignSnapshot
                    |
                    +-- scenario lineage and active policy
                    +-- temporal graph
                    +-- lazy expansion frontier
                    +-- observations, corpus, coverage, and findings
                    +-- retention pins and accounting
```

Every object under the named campaign reference is immutable and
content-addressed. The frontier is a derived projection of durable facts, not a
directory of mutable VM processes. QEMU processes, exact checkpoint files,
local copy-on-write mappings, and daemon work queues are realizations and
caches. They affect cost, never branch identity.

## Problem

RFC-0010 established the deterministic execution model, temporal graph,
guided exploration, content-addressed campaign storage, and future fleet
distribution. RFC-0014 adds exact cross-process checkpoint closures and stable,
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
- the existing shared frontier leases checkpoint nodes, while progressive
  widening must revisit one checkpoint many times and therefore needs
  idempotent attempt-level work;
- the campaign manifest does not yet name the exploration facts, lazy frontier,
  objectives, measurements, pins, and accounting needed to stop and resume a
  complete adaptive campaign.

Without a single model for those concerns, search, fuzzing, optimization,
manual forking, debugging, and future distributed execution would grow separate
control planes and subtly different replay semantics.

## Design thesis

A campaign is a **named reference to an immutable snapshot of accumulated
exploration knowledge**. That snapshot names an append-only set of facts and
content-addressed projections. From it, Crucible can derive every open
expansion, regenerate every candidate stream, reproduce every branch, restore
every retained checkpoint, and explain every adaptive planning decision.

```text
                     immutable CampaignPolicy
                              |
Scenario -> ChoicePoint -> Proposal -> Attempt -> Observation -> Finding
    |            |             |          |            |
    +------------+-------------+----------+------------+
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

Workers pull bounded `Attempt` objects. They do not enumerate the entire state
space and do not own campaign policy. A local daemon materializes each attempt
from the cheapest correct realization: a paused hot-fork template, a durable
exact closure, or thin replay. Descendant observations update campaign
knowledge and may make an ancestor expansion eligible to yield more candidates.

## Relationship to RFC-0010 and RFC-0014

This RFC preserves RFC-0010's identity and determinism contracts:

- a configuration remains exactly `(ScenarioDef, Schedule)`;
- temporal-graph edges remain recorded deterministic decisions;
- `instantiate` remains the one semantic realization operation;
- materialization and worker placement never enter configuration identity;
- every finding remains reproducible without a campaign, daemon, fleet, or
  shared store.

It refines three RFC-0010 control-plane decisions:

1. A search frontier is no longer just the set of checkpoints not yet expanded.
   It is the projection of **open expansion continuations**, and one
   configuration may yield additional attempts repeatedly.
2. Fleet claims are keyed by immutable `AttemptId`, not only by checkpoint
   identity. A parent configuration may have many independently claimable
   attempts over its lifetime.
3. The persistent campaign head names a complete `CampaignSnapshot`, including
   graph, exploration, observation, pin, and accounting roots. The existing
   corpus, coverage, findings, genesis, and provenance roots remain part of that
   snapshot.

RFC-0014's `FaultOpportunity` becomes an environment-originated
`ChoicePoint`. Its typed domain adapter still owns effect validation,
composition, and application. This RFC adds the shared selection and campaign
layer above those adapters; it does not replace signal evaluation or turn typed
effects into arbitrary callbacks.

## Goals

- **[CAM-1]** Provide one persistent campaign model for systematic search,
  probabilistic sampling, coverage-guided mutation, progressive widening,
  performance optimization, manual branching, and failure minimization.
- **[CAM-2]** Expose environment, scheduler, workload, and guest application
  degrees of freedom as one typed choice-point model with integral and discrete
  domains.
- **[CAM-3]** Keep model probability, exploration proposal probability, and the
  realized recorded selection distinct and auditable.
- **[CAM-4]** Represent the frontier lazily so an enormous latent state space
  requires storage proportional to admitted work and observations, not to every
  possible child.
- **[CAM-5]** Permit descendant feedback to revisit an immutable ancestor and
  admit more candidates without mutating or merging VM state.
- **[CAM-6]** Make a campaign fully pausable, resumable, forkable, inspectable,
  replicable, and garbage-collectable from its content-addressed snapshot.
- **[CAM-7]** Make the common on-host branch path share paused QEMU memory pages,
  immutable disk state, log prefixes, and host continuation state copy-on-write.
- **[CAM-8]** Preserve a portable durable exact closure for hibernation,
  midpoint debugging, failure retention, maintenance migration, and future
  worker-host distribution.
- **[CAM-9]** Bound runnable branches by host resources while allowing millions
  of dormant logical continuations and pending possibilities.
- **[CAM-10]** Define a user-facing campaign file, CLI, daemon API, event stream,
  status model, and artifact format that all project the same underlying data.
- **[CAM-11]** Keep the Apache host and GPL QEMU/plugin in separate processes
  with only versioned socket and shared-memory protocols across the boundary.
- **[CAM-12]** Permit a future multi-host executor to consume the same attempt
  and observation contracts without making network fanout part of the initial
  implementation.

## Non-goals

- The first implementation does not build a multi-host campaign coordinator,
  remote page server, post-copy migration system, or network fanout service.
- The first implementation does not estimate real-world failure probability
  from a guidance-biased bug-hunting campaign. Statistically valid estimation
  requires the explicit probability rules in
  [`03-exploration-and-guidance.md`](03-exploration-and-guidance.md).
- This RFC does not merge two live mutable VM states. Campaign merge is union of
  immutable facts and graph objects; selection between branches is not a VM
  state merge.
- This RFC does not let guest-provided code, closures, scripts, native pointers,
  or QEMU-private structures enter canonical choice or campaign data.
- This RFC does not make every latent choice a live process or even a stored
  temporal-graph node. A child becomes a graph node only after its attempt
  produces a canonical configuration.
- This RFC does not permit host wall time, worker arrival order, fleet size, or
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
   hashed domain. Replay rejects a changed domain or choice-point identity.
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

## Reading order

1. [`00-goals-and-invariants.md`](00-goals-and-invariants.md) fixes vocabulary,
   scope, and the determinism boundary.
2. [`01-campaign-data-model.md`](01-campaign-data-model.md) defines campaign
   lineages, policies, snapshots, facts, graph objects, projections, and
   lifecycle.
3. [`02-selectables-and-choice-protocol.md`](02-selectables-and-choice-protocol.md)
   defines typed integral and discrete selectables shared by guest and
   environment producers.
4. [`03-exploration-and-guidance.md`](03-exploration-and-guidance.md) defines
   probabilistic exploration, progressive widening, MCTS/PUCT, beam and Pareto
   selection, guidance, and statistical validity.
5. [`04-lazy-frontier-and-daemon.md`](04-lazy-frontier-and-daemon.md) defines
   persistent iterators, attempt scheduling, feedback, daemon ownership,
   backpressure, and future worker contracts.
6. [`05-hot-fork-and-checkpoints.md`](05-hot-fork-and-checkpoints.md) defines
   single- and multi-node QEMU hot forks, host continuation cloning, durable
   checkpoints, hibernation, and migration.
7. [`06-storage-replication-and-gc.md`](06-storage-replication-and-gc.md) defines
   local and S3-compatible stores, Merkle replication, pinning, cache tiers,
   leases, and garbage collection.
8. [`07-user-experience-and-apis.md`](07-user-experience-and-apis.md) defines the
   campaign file, CLI, daemon API, views, steering, and compatibility with
   existing commands.
9. [`08-observability-measurement-debugging.md`](08-observability-measurement-debugging.md)
   defines barriers, measurements, properties, metrics, selection evidence,
   retained failure state, and debugger branches.
10. [`09-security-compatibility-and-operations.md`](09-security-compatibility-and-operations.md)
    defines trust, bounds, sensitive state, provenance, upgrades, and operational
    failure handling.
11. [`10-performance-and-validation.md`](10-performance-and-validation.md)
    defines cost models, required metrics, conformance gates, and acceptance
    targets.
12. [`11-implementation-plan.md`](11-implementation-plan.md) sequences the
    implementation intended to follow this documentation review.
13. [`12-decisions-and-open-questions.md`](12-decisions-and-open-questions.md)
    records resolved decisions and the few questions intentionally left for
    measured implementation spikes.
14. [`13-worked-network-campaign.md`](13-worked-network-campaign.md) walks one
    network-disruption campaign from scenario authoring through adaptive
    branching, selection, hibernation, and reproduction.

## Requirement prefixes

| Prefix | Area |
| --- | --- |
| `CAM` | Whole-campaign goals and invariants |
| `CMOD` | Campaign data model and lifecycle |
| `SEL` | Selectables, choice domains, and guest/environment protocol |
| `GUIDE` | Candidate generation, guidance, probability, and optimization |
| `LAZY` | Lazy frontier, continuations, daemon, attempts, and feedback |
| `HFORK` | Hot QEMU fork and multi-node world cloning |
| `CSTORE` | Durable storage, replication, pinning, and garbage collection |
| `CAPI` | User-facing schema, CLI, API, and event stream |
| `CMEAS` | Measurement, observability, findings, and debugging |
| `CSEC` | Security, compatibility, provenance, and operations |
| `CPERF` | Performance targets and validation gates |

The capitalized words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** have their RFC-2119/RFC-8174 meanings. All illustrative code and schema
blocks are labeled; field tables and explicit requirements are normative.
