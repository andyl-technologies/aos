# 07 — User-facing campaign schema, CLI, and APIs

The user should experience one coherent object: a campaign that can be created,
run, watched, steered, paused, branched, derived, inspected, reproduced, and
replicated.
CLI, daemon RPC, structured output, and a future graphical view are projections
of the same campaign snapshot and command model.

## 07.1 Authoring split

Two files have separate responsibilities:

```text
network-recovery.scenario.toml
  system topology and immutable artifacts
  signals, fault bindings, and legal choice domains
  workload
  properties
  measurements and stop markers

network-recovery.campaign.toml
  candidate-generation policies
  path guidance
  objectives and survivor selection
  fairness/diversity
  campaign mode
  retention
```

The scenario is executable by itself with default selections. The campaign
references scenario declaration IDs; it cannot create an out-of-domain value or
an undeclared effect.

- **[CAPI-1]** Scenario validation MUST detect unresolved campaign selectors,
  incompatible generator/domain pairs, unknown metrics/properties, and
  impossible stop conditions before campaign creation.
- **[CAPI-2]** Canonical campaign identity MUST be insensitive to TOML table and
  list order wherever order has no declared meaning.

## 07.2 Campaign schema

```toml
schema = "crucible.campaign.v1"
scenario = "./network-recovery.scenario.toml"
seed = "5d7f1dd4..."
mode = "streaming"

[explorer]
kind = "tree-search"
tree_policy = "puct"
progressive_widening = true

[explorer.puct]
exploration_weight_micros = 1250000

[explorer.widening]
k = { numerator = 2, denominator = 1 }
alpha = { numerator = 1, denominator = 2 }
initial_children = 3
maximum_children = 64

[fairness]
breadth_first_percent = 10
novelty_reserve = 8

[[choice_policy]]
selector = "environment.network.loss-bps"

[choice_policy.generator]
kind = "progressive-integer"
initial = ["default", "boundaries", "landmarks", "stratified"]
maximum_children = 32

[[choice_policy]]
selector = "product.network.recovery-policy"

[choice_policy.generator]
kind = "categorical-ucb"
initial = "all"

[[objective]]
measurement = "recovery.latency-ns"
goal = "minimize"
weight_micros = 1000000

[[objective]]
measurement = "recovery.packets-lost"
goal = "minimize"
weight_micros = 500000

[[guidance]]
signal = "coverage"
weight_micros = 250000

[[guidance]]
signal = "rarity"
weight_micros = 100000

[[stage]]
id = "first-disruption"
branch_at = { choice_class = "uplink-disruption" }
stop_at = { measurement = "recovery" }

[stage.survivors]
kind = "pareto-top-k"
keep = 64
novelty_reserve = 8

[retention]
findings = "all"
survivors = "thin"
hot_hubs = "adaptive"
exact_checkpoints = ["findings", "user-pins"]
```

Choice selectors match stable selectable IDs or bounded tag predicates. A
policy may define a default for unmatched optional selectables. Required
selectables without a matching policy use the scenario default only if the
campaign explicitly admits defaults; otherwise validation fails.

## 07.3 CLI lifecycle

```text
crucible campaign create NAME --scenario SCENARIO --policy POLICY
crucible campaign validate NAME|POLICY
crucible campaign start NAME [--workers N] [--memory SIZE]
crucible campaign pause NAME [--active drain|checkpoint|retry]
crucible campaign resume NAME
crucible campaign stop NAME [--seal]
crucible campaign budget NAME add ATTEMPTS
crucible campaign steer NAME --policy POLICY
crucible campaign derive NAME@SNAPSHOT NEW_NAME [--policy POLICY]
```

`create` stores canonical scenario/policy objects and creates the first snapshot
and named ref. `start` attaches local execution resources and changes desired
state through a recorded command. `pause` stops new proposals/leases and applies
the selected active-attempt behavior. `stop --seal` prevents accidental future
budget grants until an explicit unseal command.

Operational flags such as `--workers` and `--memory` are daemon attachment
configuration and do not alter policy identity.

Semantic alternatives use a separate command:

```text
crucible campaign branch NAME --at CONFIG --point SELECTOR \
  --values VALUE[,VALUE...] [--attempts N]
crucible campaign branch NAME --at CONFIG --point SELECTOR \
  --all [--attempts N]
```

`branch` publishes an additive `BranchRequest` with an operator cause and a
bounded finite candidate source. The values are validated against the choice
opportunity at the named parent; they are pulled lazily under budget and do not
immediately create VMs. `--all` is accepted only for a proven finite domain
below the configured exhaustive-cardinality ceiling. A request may target one
value to follow a path or several values to branch it. It does not disable an
existing generated source at that branch point.

`derive` creates a new named campaign ref that shares immutable objects with
the source snapshot and can activate a different future policy. It neither
creates a branch edge nor QEMU-forks a process. **Hot fork** remains the daemon's
QEMU realization detail. `fork` may remain a deprecated CLI alias for `branch`
during migration, but structured APIs, stored facts, help, and new documentation
use the distinct terms.

- **[CAPI-3]** Every mutating CLI command MUST print the prior and new campaign
  snapshot IDs and emit an equivalent structured result.
- **[CAPI-4]** Retrying a command with the same command ID MUST be idempotent.

## 07.4 Inspection

```text
crucible campaign status NAME [--json]
crucible campaign watch NAME [--after CURSOR]
crucible campaign graph NAME [--around CONFIG] [--depth N]
crucible campaign frontier NAME [--state ready|waiting|open]
crucible campaign choices NAME [SELECTOR]
crucible campaign inspect NAME@SNAPSHOT
crucible campaign compare NAME CONFIG_A CONFIG_B
crucible campaign findings NAME
crucible campaign explain NAME PROPOSAL|ATTEMPT|CONFIG|FINDING
```

A concise status view includes:

```text
network-recovery @ 9f7c2e1  running  mode=streaming

configurations       184211    ready sources          913
open branch points      7842    attempts running        32
durable checkpoints     146    hot fork hubs            11
unique findings           4    Pareto survivors         64

coverage gain          +8.3%   consumed attempts    201338
```

`choices` shows choice opportunities and their branch points, domain, finite and
generated sources, admitted values, visit counts, reward/metric summaries,
interval partitions, prior/proposal distributions, and why each continuation is
ready or waiting. `explain` follows causal links from request cause, policy, and
observation basis through proposal, immutable execution basis or additional-
cause association, branch edge, selection, execution evidence, and reward
credit.

- **[CAPI-5]** Human output MAY evolve, but JSON/CBOR structured schemas are
  versioned and include full content IDs rather than display abbreviations.
- **[CAPI-6]** Status MUST distinguish latent/open continuations, admitted
  attempts, running worlds, stored graph nodes, and materialized checkpoints.

## 07.5 Retention, replay, and debugging

```text
crucible campaign pin NAME CONFIG [--tier thin|exact] [--reason TEXT]
crucible campaign unpin NAME CONFIG
crucible campaign replay NAME FINDING|CONFIG [--check]
crucible campaign debug NAME FINDING|CONFIG
crucible campaign export NAME --mode metadata|findings|debug|executable|mirror
crucible campaign import BUNDLE [--name NAME]
```

`debug` restores a retained exact closure when present or realizes the nearest
valid ancestor. Debugger writes create a non-canonical branch. `replay` uses the
self-contained scenario/schedule artifact and does not require the original
campaign.

## 07.6 Store and replication porcelain

```text
crucible campaign push NAME STORE [--mode MODE]
crucible campaign pull STORE/NAME [--mode MODE] [--name LOCAL_NAME]
crucible campaign sync NAME STORE [--mode MODE]
crucible campaign gc NAME --plan
crucible campaign gc NAME --apply PLAN_ID
```

`push` and `pull` display object counts and bytes by semantic metadata,
reproduction artifact, exact VM state, disk, log, and trace classes. Sensitive
closure warnings occur before transfer. `gc` is always plan then apply; the plan
names its input snapshot and becomes stale if the ref moves.

## 07.7 Existing commands as campaign sugar

The existing command concepts remain useful but use one implementation:

| Existing command | Campaign interpretation |
| --- | --- |
| `run` | Temporary campaign with one default path and no widening |
| `search` | Campaign with systematic frontier and candidate policy |
| `fuzz` | Campaign with sampled/mutational generator and corpus retention |
| `save` | Run to a stop condition and add an exact pin |
| `resume` | Instantiate a pinned configuration and continue |
| `fork` | Deprecated alias for `branch`: issue a bounded finite request at a declared branch point |
| `replay` | Instantiate a recorded scenario/schedule artifact |
| `triage` | Project and minimize the campaign findings ledger |

- **[CAPI-7]** These commands MUST call the same campaign/execution primitives
  rather than maintain separate search, fuzz, or branch state models.

## 07.8 Daemon API

The daemon exposes versioned resources:

```text
CampaignService
  CreateCampaign
  GetCampaign
  ApplyCampaignCommand
  GetSnapshot
  QueryGraph
  QueryFrontier
  QueryChoices
  SubmitBranchRequest
  DeriveCampaign
  QueryFindings
  ExplainObject
  WatchCampaign

ExecutionWorkerService                reserved for future remote workers
  ClaimAttempt
  RenewAttempt
  GetAttempt
  PublishObservation
  PublishOperationalFailure
  ReleaseAttempt
```

All mutation requests carry command ID, expected snapshot ID, and authenticated
principal. CAS conflict responses return the current head and enough detail to
retry or ask the user to resolve a policy conflict.

`WatchCampaign` uses a resumable event cursor over snapshot advances and
operational telemetry. Canonical facts are fetched by object ID; the watch
stream itself is not authoritative and may coalesce status updates.

- **[CAPI-8]** Losing a watch stream MUST lose no campaign state. Reconnecting
  from a stale cursor returns the current snapshot and subsequent events.
- **[CAPI-9]** Read-only clients MUST be able to inspect metadata replicas
  without permission to fetch sensitive exact-checkpoint objects.

## 07.9 Policy steering

Steering creates a new immutable policy and activation fact. The user sees a
diff of:

- choice selectors and generators;
- priors and probability mode;
- guidance/objective weights;
- fairness and survivor rules;
- stop conditions;
- retention policy.

Existing attempts finish under the policy that issued them unless the user
explicitly cancels them. New proposals use the newly active policy.

An additive operator branch request is not policy steering. It adds one finite
source while leaving the active policy and existing generated continuations
intact. If an operator wants future work to come only from a different set of
sources, they activate a new policy or derive an independent campaign.

- **[CAPI-10]** A steering command MUST reject a new policy that cannot interpret
  the lineage's existing choice schemas or observation metrics.

## 07.10 Graphical presentation

A future UI needs no separate backend model. It renders:

- a Git-like temporal DAG with branch selections on edges;
- branch-point diamonds showing finite/generated sources, untried/admitted
  values, request causes, and widening state;
- metric/Pareto plots at measurement barriers;
- coverage and finding overlays;
- materialization badges (`hot`, `exact`, `thin`);
- a causal explanation panel for every planner decision;
- campaign history as immutable snapshot revisions.

The UI may request bounded subgraphs and aggregations. It never downloads guest
RAM merely to draw the graph.

```text
Configuration C0
       |
       ◇ recovery.hold_down_us
       ├── 0 us -------> C1  policy
       ├── 20 ms ------> C2  operator + policy
       ├── 500 ms -----> C3  operator
       └── ... generated continuation waiting for feedback
```

The edge for `20 ms` appears once even though two request causes proposed it.
Selecting the diamond reveals both proposal facts and the single semantic edge.
Materialization badges belong to configurations/attempts; the diamond itself is
not evidence of a hot checkpoint.

- **[CAPI-11]** CLI, RPC, and structured schemas MUST distinguish `branch`,
  `derive`, QEMU `hot fork`, and canonical or non-canonical debug branches.
- **[CAPI-12]** `branch` MUST report its request ID, validated cardinality,
  deduplicated existing edge count, remaining lazy candidates, budget, and prior
  and new campaign snapshot IDs without claiming that all requested values are
  running.
- **[CAPI-13]** Branch-point inspection MUST expose every candidate source and
  request cause, while rendering a duplicate selected value as one semantic
  edge with multiple provenance records.
