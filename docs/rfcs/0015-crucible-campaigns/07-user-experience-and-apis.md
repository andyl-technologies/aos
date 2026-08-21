# 07 — User-facing campaign schema, CLI, and APIs

The user should experience one coherent object: a campaign that can be created,
run, watched, steered, paused, branched, derived, inspected, reproduced,
archived, and restored.
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
crucible campaign create NAME --lineage LINEAGE.bin --policy POLICY.bin
crucible campaign validate NAME|POLICY
crucible campaign start NAME [--workers N] [--memory SIZE]
crucible campaign pause NAME --expected SNAPSHOT --command COMMAND \
  [--active drain|checkpoint|retry]
crucible campaign resume NAME --expected SNAPSHOT --command COMMAND
crucible campaign stop NAME --expected SNAPSHOT --command COMMAND [--seal]
crucible campaign unseal NAME --expected SNAPSHOT --command COMMAND
crucible campaign budget NAME --expected SNAPSHOT --command COMMAND \
  add ATTEMPTS [--proposals PROPOSALS]
crucible campaign steer NAME --expected SNAPSHOT --command COMMAND --policy POLICY
crucible campaign derive SOURCE --snapshot SNAPSHOT TARGET [--policy POLICY.bin]
```

The current `create` command accepts strict canonical `CampaignLineage` and
`CampaignPolicy` bodies. Their verifier-backed scenario/configuration artifacts
and transitive generator closure must already be imported by the daemon's
narrow immutable importer; large artifacts never travel through the control
message. It creates the first snapshot and named ref or exactly replays the
authenticated genesis basis. `derive` similarly names one exact authenticated
source snapshot and may activate an already imported compatible canonical
policy. `start` attaches local execution resources and changes desired state
through a recorded command. `pause` stops new proposals/reservations and applies
the selected active-attempt behavior. `stop --seal` prevents accidental future
budget grants until an explicit unseal command.

Operational flags such as `--workers` and `--memory` are daemon attachment
configuration and do not alter policy identity.

The current lifecycle-mutation porcelain implements `create`, `derive`,
`resume`, `pause`, `stop`, `unseal`, additive `budget`, and `steer` over the same
checked local campaign-service client as status/watch. `--command` is the caller's exact
64-character lowercase hexadecimal idempotency key and `--expected` is the
exact snapshot precondition; neither is generated or silently refreshed by the
CLI. An exact retry therefore returns the original transition, while command
reuse or a stale
precondition remains visible. Every successful format includes campaign,
operation, command ID, prior snapshot, new snapshot, and replay status. Create
and derive report their exact lineage/policy or source basis, accepted snapshot,
and replay status. Start's local resource attachment, verifier-backed import and
validation porcelain, and richer manifest authoring remain open.

Semantic alternatives use a separate command:

```text
crucible campaign branch NAME --expected SNAPSHOT --command COMMAND \
  --branch-point BRANCH_POINT --parent CONFIGURATION_ARTIFACT \
  --opportunity OPPORTUNITY --domain DOMAIN --value VALUE [--value VALUE ...] \
  [--proposals N] [--attempts N] [--stop CONDITION]
```

The current `branch` command publishes an additive finite `BranchRequest` with
an exact operator command cause. Values use the closed `true`, `false`,
`i64:N`, `u64:N`, or `discrete:ALTERNATIVE_ID` grammar. Stop conditions use
`next-choice`, `terminal`, `boundary:NAME`, `virtual-time-ns:N`, or `events:N`.
The request carries exact parent-artifact, opportunity, domain, and semantic
branch-point IDs so repository admission can authenticate the complete basis;
selector resolution and generated `--all` authoring remain richer future
porcelain over the same record. The values are validated against the choice
opportunity at the named parent; they are pulled lazily under budget and do not
immediately create VMs. `--all` is accepted only for a proven finite domain
below the configured exhaustive-cardinality ceiling. A request may target one
value to follow a path or several values to branch it. It does not disable an
existing generated source at that branch point.

`derive` creates a new named campaign ref whose first owned snapshot is an
audited successor of the exact source snapshot. It shares the source's immutable
semantic roots, leaves the source ref unchanged, and can atomically activate a
compatible future policy. The returned source and new snapshot IDs make that
edge explicit. It neither creates a branch edge nor QEMU-forks a process. **Hot
fork** remains the daemon's QEMU realization detail. `fork` may remain a
deprecated CLI alias for `branch`
during migration, but structured APIs, stored facts, help, and new documentation
use the distinct terms.

- **[CAPI-3]** Every mutating CLI command MUST print the prior and new campaign
  snapshot IDs and emit an equivalent structured result.
- **[CAPI-4]** Retrying a mutation of an existing campaign with the same command
  ID MUST be idempotent. Creation is idempotent by canonical campaign name and
  an exact lineage/policy basis; derivation is idempotent by target name and the
  exact source-snapshot/policy basis.

## 07.4 Inspection

```text
crucible campaign status NAME [--json]
crucible campaign watch NAME [--after CURSOR]
crucible campaign graph NAME --snapshot SNAPSHOT [--after HASH] [--limit N]
crucible campaign choices NAME --snapshot SNAPSHOT [--after OPPORTUNITY] [--limit N]
crucible campaign frontier NAME --snapshot SNAPSHOT [--after REQUEST] [--limit N]
crucible campaign graph-object NAME --snapshot SNAPSHOT --key HASH
crucible campaign choice-object NAME --snapshot SNAPSHOT --opportunity ID --kind declaration|domain
crucible campaign frontier-object NAME --snapshot SNAPSHOT --request ID
crucible campaign snapshot NAME --snapshot SNAPSHOT
crucible campaign compare NAME --left SNAPSHOT --right SNAPSHOT
crucible campaign explain NAME --snapshot SNAPSHOT --opportunity ID --request ID
crucible campaign findings NAME
```

The read-only porcelain implements `status`, a one-shot resumable `watch`, and
one immutable page of `graph`, `choices`, or `frontier` over the authenticated
local campaign-service Unix socket. Every command requires the socket path and
the principal expected from the daemon's peer policy, validates strict
request-bound responses through the checked client, and renders table,
Markdown, pretty JSON, or JSONL through the common CLI output selector. `watch
--after` returns the latest coalesced head and an `advanced` flag; callers repeat
it with the returned snapshot cursor to follow a campaign without treating the
transport as authoritative state. Each page command instead requires an exact
immutable snapshot and accepts only the cursor type returned by that operation:
a graph key hash, choice-opportunity ID, or branch-request ID. The output echoes
the exact snapshot and next cursor. Graph pages carry and verify the bounded
Merkle proof specified below before rendering; choice and frontier pages verify
their snapshot-bound nested-index proofs through the same checked client.
Snapshot inspection and comparison independently validate every requested
historical snapshot against the named campaign. The initial `explain` operation
joins one authenticated choice declaration with one authenticated frontier
request, rejects a mismatched opportunity or domain, and reports exact legality,
producer, cause, budget, stop, and continuation fields. The lifecycle mutations
described in §07.3 and exact-precondition `pin`/`unpin` commands use that same
transport; findings, proposal/attempt/finding explanations, and rich
filtered/aggregated inspection remain open.

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

The current service checkpoint implements the first authenticated `choices`
and `frontier` pages. `choices` returns discovered opportunity IDs from a
snapshot-bound nested Merkle index and separately authorizes each requested
opportunity body. A distinct choice-object operation returns only the exact
declaration or effective domain named by an authenticated opportunity.
`frontier` returns each request's exact branch point and owner-projected
`ContinuationState` from an independently verified exploration-root index.
An independently authorized frontier-object read returns the exact
`BranchRequest` body named by one projection without granting a general
exploration-root read.
Finite readiness, open proposal, exhaustion, and closure are represented;
implementation-version 2 `all` sources over Boolean and discrete domains report
the same exact states, as do implementation-version 3 `boundary_integer`
sources and implementation-version 4 `stratified_integer` sources with at most
4,096 strata. Implementation-version 5 `log_integer` sources over strictly
positive integer domains report those states for their at-most-65-candidate
rounded-power order. Implementation-version 6 `permuted_integer` sources report
the same states while walking up to `2^64 - 1` legal values without
materialization. Implementation-version 7 `weighted_categorical` sources
report them for an exact request-keyed without-replacement order over at most
256 weighted discrete alternatives. Implementation-version 8
`ordered_mixture` reports the same states for at most 512 deduplicated values
from recursively executable finite children under its exact depth and work
bounds. Implementation-version 9 `progressive_integer` additionally reports
`WaitingForFeedback(completed_visits, required_visits)` between its bounded
initial strata and each exact visit-gated largest-gap refinement; it reports
`Closed`, rather than `Exhausted`, when the request budget truncates the domain.
A mixture containing any suspended child remains conservatively `Open`. Other
generated sources remain `Open` until their deterministic enumerator and
feedback owner land. Rich admitted-value, reward, interval, and
explanation views and CLI rendering remain open.

The local repository API exposes the same validation boundary at object scale.
Typed loads authenticate scenario/configuration artifacts, opportunities,
groups, and planner invocations. A selection load returns a resolved aggregate
containing its exact opportunity and domain; raw structural selection decoding
is not a public trusted-state API. Model-sampled selections additionally pass
the selected model implementation's pure replay verifier before execution.

- **[CAPI-5]** Human output MAY evolve, but language-neutral JSON/CBOR and RPC
  schemas are versioned, define unknown-field behavior and bounds, include full
  content IDs rather than display abbreviations, and have raw golden vectors.
- **[CAPI-6]** Status MUST distinguish latent/open continuations, admitted
  attempts, running worlds, stored graph nodes, and materialized checkpoints.

## 07.5 Retention, replay, and debugging

```text
crucible campaign pin NAME CONFIG --expected SNAPSHOT --command ID [--tier thin|exact] [--reason TEXT]
crucible campaign unpin NAME CONFIG --expected SNAPSHOT --command ID [--reason TEXT]
crucible campaign replay NAME FINDING|CONFIG [--check]
crucible campaign debug NAME FINDING|CONFIG
crucible campaign export NAME --mode metadata|findings|debug|executable|mirror
crucible campaign import BUNDLE [--name NAME]
```

`debug` restores a retained exact closure when present or realizes the nearest
valid ancestor. Debugger writes create a non-canonical branch. `replay` uses the
self-contained scenario/schedule artifact and does not require the original
campaign.

## 07.6 Store, durability, and archival porcelain

```text
crucible campaign hibernate NAME --durability DURABILITY
crucible campaign export NAME --to STORE [--mode MODE]
crucible campaign import BUNDLE|STORE/NAME [--name NAME]
crucible campaign restore NAME --from STORE

crucible store list
crucible store status STORE
crucible store verify STORE
crucible store ensure CONTENT_ID --in STORE
crucible store gc STORE --plan
crucible store gc STORE --apply PLAN_ID
```

Campaign commands name configured logical stores and durability policies, never
drivers, buckets, endpoints, or local paths. A deployment may bind `archive` to
a directory, S3-compatible backend, or composed store graph. Export and import
display logical and physical byte counts by metadata, reproduction artifact,
exact RAM, disk, log, and trace classes. Sensitive closure warnings occur before
transfer. Store GC is always plan then apply; the plan names its logical roots,
physical inventory basis, and policy version and becomes stale if they move.

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

- **[CAPI-7]** These commands MUST call `CampaignService` and the same campaign
  primitives rather than maintain separate search, fuzz, branch, local-daemon,
  or future-endpoint state models.

## 07.8 Component APIs

The coordinator exposes the sole user-facing campaign service:

```text
CampaignService
  CreateCampaign
  GetCampaign
  ApplyCampaignCommand
  GetSnapshot
  QueryGraph
  QueryFrontier
  GetFrontierObject
  QueryChoices
  GetChoiceObject
  PinCampaign
  SubmitBranchRequest
  DeriveCampaign
  QueryFindings
  ExplainObject
  WatchCampaign

PlannerEngine
  Step

ExecutorService
  DescribeExecutor
  WatchCapacity
  SubmitAttempt
  GetAttemptExecution
  WatchExecutions
  CheckpointAttemptExecution
  CancelExecution
  QueryMaterializations
  EnsureMaterialization
  RetainExactClosure
  EvictMaterialization
  GetHealth
```

`CampaignService` is the CLI endpoint. The initial coordinator invokes one
local executor through either the direct or loopback-RPC adapter. Planner and
executor services are component seams, not additional user control planes;
their authority and idempotency rules are defined in
[`04a-coordinator-executor-contract.md`](04a-coordinator-executor-contract.md).

The direct service contract implements strict request-bound `CreateCampaign`,
`DeriveCampaign`, `GetCampaign`, historical `GetSnapshot`, coalesced
`WatchCampaign`, snapshot-bound
`QueryGraph`,
`ApplyCampaignCommand`, semantic `PinCampaign`, and operator
`SubmitBranchRequest`
messages over the semantic repository owner. Creation carries the complete
bounded lineage/policy basis and exactly replays the authenticated
genesis for a semantically identical named retry after later mutations. It is
preceded by a narrow execution-model verifier-backed import of the large
scenario/configuration artifacts and generator closure named by the request;
those immutable objects do not travel in the campaign control message.
Derivation creates an audited successor rooted at an authenticated snapshot in
the named source history, authorizes both names, leaves the source unchanged,
and exactly replays by target name after later target mutations or restart. The
initial nested CLI now exposes authenticated current status, one-shot resumable
watch, exact-precondition lifecycle mutation, and semantic pin/unpin mutation;
resource attachment and remaining paged inspection are still required before
the service is complete. Repeated bounded `WatchCampaign`
calls provide
the initial resumable, coalesced current-head stream. The bounded versioned
Unix-stream loopback binding is now
implemented with a request-bound stable error envelope preserving authorization,
conflict, transition, resource, availability, and integrity meaning. The
daemon's authenticated repository adapter now reads
Linux `SO_PEERCRED`, resolves exact PID/UID/GID through a mandatory operational
principal mapper, and rejects a different self-asserted request principal
before repository access. A bounded daemon listener now owns an already-bound
nonblocking socket, uses at most 256 fixed connection workers and 1,024 queued
sockets, serves at most 65,536 requests per connection, resolves credentials
once per connection, rejects excess connections, and joins all workers after
sticky shutdown interrupts their active streams.
Its immutable typed policy maps at most 4,096 exact effective UID/GID pairs to
principals and at most 65,536 exact operation plus campaign/all-campaign grants;
PID never selects authority. Production bootstrap must still create and
permission the socket path and parse that policy from deployment
configuration; framing or the listener alone is never authentication.

All mutation requests carry an authenticated principal. Mutations of an
existing campaign also carry command ID and expected snapshot ID; creation
instead carries expected absence of its canonical name. CAS conflict responses
return the current head and enough detail to retry or ask the user to resolve a
policy conflict.

`WatchCampaign` uses an optional last-seen snapshot cursor. Each response
returns the current authenticated snapshot, lineage, policy, lifecycle state,
and whether that snapshot differs from the cursor. Unknown or stale cursors
return the current head, so implementations may coalesce intermediate advances.
Canonical facts are fetched by object ID; the watch stream itself is not
authoritative and may coalesce status updates.

`GetSnapshot` returns an exact current or historical snapshot only after
authenticating the current named head and proving the requested ID occurs in
that bounded immutable ancestry. The checked client reconstructs the snapshot
identity from the returned canonical body. Authorization grants the complete
snapshot metadata and all root IDs, but not the bodies those IDs name.

`QueryGraph` pages only the graph root of one exact current snapshot. Its
exclusive key cursor is valid only when it names an entry in that root, and a
head advance returns `Stale` so callers restart from the newly observed
snapshot. Pages carry at most 256 key/content-ID pairs plus the exact snapshot
body and a bounded, minimal Merkle scan proof. The client authenticates the
snapshot identity, complete ancestor prefixes, cursor, range, one-entry
lookahead, and exact EOF/continuation before exposing any entry. This operation
authorizes the complete snapshot metadata, including all root IDs, because the
flat snapshot identity cannot selectively prove only the graph root. Object
bodies remain separate; later explanation or object-read operations apply
their own authorization.

`GetGraphObject` is the separately authorized body read for one exact graph
key. It returns only a strict configuration-artifact or choice-opportunity
envelope, together with the complete anchoring snapshot metadata and a bounded
minimal Merkle lookup proof. The checked client proves exact key membership and
envelope identity before exposing the body. It cannot name arbitrary store
content or fetch checkpoint/evidence objects through the graph capability.

- **[CAPI-8]** Losing a watch stream MUST lose no campaign state. Reconnecting
  from a stale cursor returns the current snapshot and subsequent events. Graph,
  frontier, choice, and finding pagination cursors MUST bind the queried
  snapshot and reject or explicitly restart after a head change.
- **[CAPI-9]** Read-only clients MUST be able to inspect a metadata-only archive
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
