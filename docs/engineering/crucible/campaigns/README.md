# Crucible campaigns

A **campaign** is a persistent, adaptive exploration of one Crucible scenario
lineage. It can stop at a deterministic midpoint, retain that state as a hot or
durable checkpoint, explore a small and changing subset of a very large choice
space, feed descendant observations back into its exploration policy, and later
revisit an earlier configuration to admit more branches. Systematic search,
probabilistic sampling, coverage-guided mutation, optimization, manual
branching, exact pause, archive transfer, and failure retention all operate on
the same content-addressed temporal graph.

This directory describes how campaigns are implemented. Operating instructions
live in the user guide, [Operating lazy campaigns](../../../users/crucible/campaigns.md).

```text
Scenario says what may happen.
Campaign says what is worth trying.
Schedule says what did happen.

CampaignName -> immutable CampaignSnapshot
                    |
                    +-- lineage and active policy
                    +-- temporal graph
                    +-- branch points and lazy expansion state
                    +-- observations, corpus, coverage, and findings
                    +-- retention pins and accounting
                    +-- non-semantic coordination progress
```

Every object below the named reference is immutable and content addressed. The
frontier is a derived projection of branch-point facts, not a directory of
mutable VM processes. QEMU processes, exact checkpoint files, copy-on-write
mappings, and daemon work queues are realizations and caches: they affect cost,
never identity.

## Pages

| Page | Contents |
| --- | --- |
| [Data model](data-model.md) | Identities, policy, snapshot roots, facts, branch points, requests, proposals, attempts, observations, lifecycle |
| [Choice protocol](choice-protocol.md) | Typed selectables, domains, groups, opportunity identity, selection records, the guest selectable wire protocol |
| [Exploration and guidance](exploration.md) | Candidate sources and generators, PUCT tree search, guidance signals, beam and Pareto survival, statistical mode, minimization |
| [Coordinator and executor](coordinator-and-executor.md) | Component authority, lazy frontier, daemon runtime, attempt reservations, executor service, recovery |
| [Hot fork and checkpoints](hot-fork-and-checkpoints.md) | Realization tiers, the QEMU hot-fork protocol, child isolation, world fork, exact closures, pause and transfer |
| [Storage](storage.md) | Content envelope, blob and ref backends, composition graph, durability, transfer, retention, garbage collection |
| [Observability and findings](observability-and-findings.md) | Measurements, event streams, findings, reproduction artifacts, explanation |
| [Security and operations](security-and-operations.md) | Trust domains, resource admission, license boundary, compatibility, authorization, failure handling |
| [Performance and validation](performance-and-validation.md) | Cost model, gated performance targets, correctness gates, release acceptance, measurement records |
| [Schema registry](schema-registry.md) | The registry of versioned campaign and process-boundary formats |
| [Worked network fixture](worked-network-fixture.md) | The executable five-router reference campaign |

## Vocabulary

| Term | Meaning |
| --- | --- |
| Scenario | Immutable world, fault/signal plan, properties, measurements, seed, and selectable declarations defining legal modeled behavior. |
| Configuration | One temporal-graph node, identified by `(ScenarioDef, Schedule)`. |
| Selectable declaration | A reusable typed domain and application contract exposed by a scenario producer. |
| Choice opportunity | One stable runtime occurrence at which a producer offers a selectable declaration. |
| Branch point | The pair `(parent configuration, choice opportunity)` from which alternate selections create child configurations. |
| Selection | The concrete value chosen at one choice opportunity and recorded in the schedule. |
| Policy | Immutable rules for proposing candidates, prioritizing paths, ranking outcomes, fairness, and retention. |
| Branch request | An operator, planner, debugger, exhaustive, or scenario-default request to admit values from one bounded candidate source at a branch point. |
| Proposal | One legal candidate value emitted by a branch request. |
| Attempt | An idempotent executable unit: instantiate a start configuration, optionally apply a selection, and run to a stop condition. |
| Branch edge | The unique semantic edge for `(branch point, selected value)`, independent of how many requests proposed it. |
| Observation | The canonical outcome of a completed attempt: child configuration, measurements, property verdicts, coverage, and discovered opportunities. |
| Expansion state | Requests, proposals, observations, statistics, and suspended candidate sources attached to one branch point. |
| Frontier | Ready, waiting, and open continuations plus admitted attempts not yet completed. |
| Finding | A stable failure signature with a self-contained reproduction artifact and optional retained exact checkpoints. |
| Materialization | A hot process, exact durable closure, or replay path that makes one configuration cheap to instantiate. |
| Lineage | The scenario, genesis, and provenance boundary within which graph and checkpoint reuse is valid. |

## Three planes

```text
MODELED EXECUTION PLANE
  scenario + recorded schedule -> configuration/state
  deterministic, replayable, content-addressed

CAMPAIGN KNOWLEDGE PLANE
  proposals + observations + policy -> future work
  adaptive and persistent, never part of configuration identity

OPERATIONAL PLACEMENT PLANE
  executor reservations + CPU/RAM + cache locality -> where/when work runs
  opportunistic, host-dependent, never part of modeled state
```

Data from the campaign or placement planes reaches modeled execution only as a
validated `Selection` recorded in the schedule. Wall time, executor identity,
process IDs, reservation state, completion arrival order, cache inventory, and
store placement never enter a scenario, decision, configuration ID, checkpoint
identity, canonical event-log projection, or reproduction artifact.

"Probability" has three distinct meanings that are kept apart throughout:

1. **Model probability `P`** belongs to the scenario (for example a one-percent
   per-frame loss process).
2. **Proposal probability `Q`** belongs to the campaign and allocates a finite
   exploration budget (for example oversampling boundary values).
3. **Recorded selection** belongs to the schedule and states exactly what
   happened on one branch.

A guidance-biased campaign can report that it found a bug, but its sample
frequency is not a modeled failure probability. Reports label every estimate as
descriptive, guidance-biased, or statistically weighted. See
[statistical mode](exploration.md#statistical-mode).

## Invariants

1. **One execution identity.** A branch is identified only by its scenario and
   recorded schedule. Campaign and materialization metadata are not inputs.
2. **One mutable reference.** A campaign name points to one immutable snapshot;
   advancing it is a compare-and-swap performed by exactly one coordinator.
3. **Typed choices.** Every selected value validates against a versioned,
   hashed domain. Replay rejects a changed domain or opportunity identity.
4. **Recorded adaptation.** Every proposal names the policy and planning view
   that caused it, so adaptive decisions are explainable after the fact.
5. **Lazy admission.** Possibility does not imply materialization. Only
   admitted proposals and completed configurations consume graph storage.
6. **Reader-only guidance.** Feedback chooses future work; it never mutates a
   realized configuration.
7. **Exact arithmetic.** Domains, probabilities, scores, rewards, and ordering
   use integers, reduced rationals, or fixed-point values, never native
   floating point.
8. **Idempotent work.** Repeating an attempt produces the same canonical child
   or a localized determinism conflict, and is safe to deduplicate.
9. **Cache independence.** Hot forks, exact closures, and thin replay are
   interchangeable realizations of one configuration.
10. **Fail-closed compatibility.** Every decoder admits only its current
    version; scenario, policy, checkpoint, QEMU, plugin, guest protocol, and
    store mismatches are rejected before execution.
11. **Process-license boundary.** QEMU fork coordination and state extraction
    stay in the GPL-side QEMU process; the Apache host sees only versioned
    protocol data and opaque authenticated artifacts.
12. **Self-contained findings.** Every finding exports what is needed to
    reproduce it on one host without campaign state.

"No finding" means no finding in the recorded explored set. Except for a finite
domain explicitly exhausted under a bounded horizon, a campaign makes no
completeness claim, and reports distinguish property filtering, Pareto
domination, budget pruning, retention eviction, and genuine exhaustion.

## Four uses of "branch"

| Operation | Meaning |
| --- | --- |
| Branch | Admit semantic selections at a branch point. An explicit low-cardinality branch is a finite candidate source. |
| Derive | Create a new named campaign from an existing snapshot, sharing immutable objects. |
| Hot fork | Realize already-admitted semantic branches by QEMU process-level copy-on-write. |
| Debug branch | Apply a declared selection as a canonical debugger-caused branch, or record an arbitrary mutation as a non-canonical debug session. |

A checkpoint is a reusable realization of a configuration, not a branch point.
A branch point exists only when a typed choice opportunity is known at a parent
configuration, and it need not be hot-fork eligible: exact restore or thin
replay can realize the same edge.

## Crate map

| Crate | Campaign responsibility |
| --- | --- |
| `crucible-campaign` | Portable identities, canonical records and codecs, Merkle maps, repository transitions, the pure planner, campaign and executor service contracts. It has no QEMU or transport implementation. |
| `crucible-store` | Content envelope, immutable blob and mutable ref backends, the store composition graph, packing, quotas, and administration fences. |
| `crucible-engine` | Execution-model adapters: scenario selectables, signal-fault search choices, measurements, reproduction and minimization. |
| `crucible-daemon` | The coordinator runtime, campaign listener and policy, local executor (supervisor, worker pool, assignment ledger), planner process supervision, hot checkpoints, exact checkpoint store, GC, and transfer. |
| `crucible-control-api`, `crucible-control-client`, `crucible-control-server` | Native wire DTOs and the RPC transport adapters. |
| `crucible-qemu-protocol`, `crucible-qemu-shmem` | Permissive process-boundary formats: guest selectable messages, catalog and setup plans, shared-memory layout. |
| `crucible-qemu-host` | QMP command vocabulary, including the hot-fork and checkpoint commands and their typed response parsers. |
| `crucible-guest` | Guest-side selectable registration and request helpers over the doorbell transport. |
| `crucible-cli` | The `crucible campaign` and `crucible serve` surfaces, import manifests, fixtures, and reports. |
| `crucible-test-support` | The campaign gate catalog and the schema registry. |
