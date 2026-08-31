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
crucible campaign policy compile POLICY.toml --output POLICY.bin
crucible campaign create NAME --lineage LINEAGE.bin --policy POLICY.bin \
  [--start-command COMMAND]
crucible campaign validate NAME|POLICY
crucible campaign start NAME --expected SNAPSHOT --command COMMAND
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
message. A read-write local daemon accepts one or more
`--campaign-import-manifest PATH` options at startup. Each strict version-1
manifest names dependency-ordered exact-owner scenario/schedule pairs and
canonical generator bodies; the daemon verifies and imports them under the
exclusive repository lock before it binds the CampaignService socket. It
may be checked first without a daemon or repository:

```text
crucible campaign validate-import MANIFEST [MANIFEST ...]
```

Offline validation applies the same exact-owner, path, per-file, aggregate
entry, canonical-codec, scenario/configuration semantic-identity, and
unresolved-selection checks as startup import. It additionally requires every
generator dependency to occur earlier in the supplied manifest sequence, so
the result is self-contained rather than depending on previously imported
repository state. It streams one body at a time and reports the exact derived
configuration and generator identities in every supported output format.
The command intentionally takes neither `--socket` nor `--principal`.
The same offline boundary provides `campaign policy compile`. Its strict
version-one TOML schema names the exact scenario semantic ID, 32-byte lowercase
hexadecimal seed, campaign mode, one closed explorer variant, ordered choice
generator references, objectives, guidance weights, stop conditions, fairness,
retention, and default-admission intent. The compiler admits at most 16 MiB,
rejects unknown fields and duplicate semantic keys, constructs the public typed
policy values so every canonical invariant is shared with repository decoding,
and only then durably installs a new canonical binary record without replacing
an existing path. It reports the exact content-derived `CampaignPolicyId`.
Referenced generators remain separately verifier-imported immutable records;
the authoring file does not bypass the dependency-ordered import closure.
`create` then creates the first snapshot and named ref or exactly replays the
authenticated genesis basis. With `--start-command`, the client immediately
submits a separate `Resume` command whose precondition is the exact genesis
snapshot returned by that checked creation response. The two mutations are not
atomic: if creation succeeds and start fails, repeating the same command safely
replays creation and retries the idempotent start command. Version 2 of the CLI
campaign-acceptance report retains both checked results by nesting the start
command, prior snapshot, resulting snapshot, and replay bit under the creation
result. `derive` similarly names one exact authenticated source snapshot and
may activate an already imported compatible canonical policy. A runtime-capable
local daemon also receives
`--campaign-component-authority FILE`, the strict owner-only version-one
planner/debugger authority bundle specified in §04a. The current control-only
service may omit it. Repeating paired `--campaign-runtime NAME` and
`--campaign-executor-socket PATH` arguments attaches the packaged canonical
planner and one authenticated local executor to each of at most 256 unique
existing campaigns; the two argument lists are paired in command-line order.
With a packaged executor, `--campaign-runtime-all` instead selects the complete
authenticated local campaign catalog from one stable page and fails closed if
the catalog is empty or exceeds 256 campaigns.
Attachment fails closed unless the component authority is present and the
service is writable. In packaged-executor mode every repeated executor path
MUST name the same managed endpoint. The daemon authenticates the complete
campaign set in canonical name order before acquiring QEMU host resources and
admits it only when every lineage has the same exact compatibility profile. It
charges and decodes at most 128 MiB of distinct canonical scenario-artifact
bodies before host acquisition, captures one native baked genesis for each,
and routes promotion by exact World/scenario identity. Those campaigns share
one fixed worker/capacity pool and endpoint. The advertised durable-store namespace is
derived from the deployment state root rather than an arbitrarily first
campaign, so argument reordering or adding a compatible campaign does not
change locality identity. A scenario absent from the startup catalog requires
a restart with the enlarged catalog or another executor pool.
After bind, an authorized local operator can attach another existing campaign:

```text
crucible campaign --socket CAMPAIGN_SOCKET --principal PRINCIPAL \
  attach CAMPAIGN --executor-socket EXECUTOR_SOCKET
```

The endpoint is validated before connecting to the campaign service. A
successful response reports `attached` or `replayed`, the exact request digest,
and the live attached-runtime count. Exact replay performs no second executor
connection; changing the endpoint for an already attached campaign is a
nonretryable command-reuse conflict.
`start` changes desired state through the same recorded `Resume` transition as
`resume`, but reports the operator's initial-start intent distinctly. Both
require the exact expected snapshot and an idempotency key. `pause` stops new
proposals/reservations and applies the selected active-attempt behavior. `stop
--seal` prevents accidental future budget grants until an explicit unseal
command.

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
and replay status. Start's local resource attachment and richer manifest
authoring remain open.

Semantic alternatives use a separate command:

```text
crucible campaign branch NAME --expected SNAPSHOT --command COMMAND \
  --branch-point BRANCH_POINT --parent CONFIGURATION_ARTIFACT \
  --opportunity OPPORTUNITY --domain DOMAIN --value VALUE [--value VALUE ...] \
  [--proposals N] [--attempts N] [--stop CONDITION]
crucible campaign branch NAME --expected SNAPSHOT --command COMMAND \
  --branch-point BRANCH_POINT --parent CONFIGURATION_ARTIFACT \
  --selector NAME|name:NAME|id:SELECTABLE_ID|tag:TAG [--selector SELECTOR ...] \
  [--instance INSTANCE] \
  [--selector-scan-limit N] --value VALUE [--value VALUE ...] \
  [--proposals N] [--attempts N] [--stop CONDITION]
crucible campaign branch NAME --expected SNAPSHOT --command COMMAND \
  --branch-point BRANCH_POINT --parent CONFIGURATION_ARTIFACT \
  --opportunity OPPORTUNITY --domain DOMAIN --generator GENERATOR \
  --proposals N [--attempts N] [--stop CONDITION]
crucible campaign branch NAME --expected SNAPSHOT \
  --branch-point BRANCH_POINT --parent CONFIGURATION_ARTIFACT \
  --opportunity OPPORTUNITY --domain DOMAIN --all \
  [--attempts N] [--stop CONDITION]
```

The ordinary `branch` forms publish an additive finite or generated
`BranchRequest` with an exact operator command cause. Values use the closed
`true`, `false`, `i64:N`, `u64:N`, or `discrete:ALTERNATIVE_ID` grammar. Stop conditions use
`next-choice`, `terminal`, `boundary:NAME`, `virtual-time-ns:N`, or `events:N`.
The request carries exact parent-artifact, opportunity, domain, and semantic
branch-point IDs so repository admission can authenticate the complete basis.
`--generator` names one already imported canonical generator and requires an
explicit nonzero proposal budget; it is mutually exclusive with finite values.
It is an explicit operator intervention, while planner and exhaustive-policy
causes additionally require the generator selected by the active choice policy.
`--all` is a content-idempotent exhaustive-policy request rather than an
operator-command request, so it does not accept `--command`. It authenticates
the exact named-history snapshot and effective domain, derives implementation-
version 2 `all`, and sets the proposal budget to the domain's exact cardinality.
The owner accepts it only for a Boolean or discrete domain, when that generator
is selected by the active exhaustive policy and the cardinality is within the
policy's configured ceiling; every mismatch fails before request publication.
The selector form resolves one opportunity through the exact snapshot's
proof-bearing choice index and separately authorized opportunity and declaration
bodies. A bare selector and `name:` match the declaration name, `id:` matches
the exact content-addressed selectable declaration, and `tag:` matches one
exact semantic tag. `--instance` optionally restricts the stable runtime
instance. Between one and sixteen repeated `--selector` values form a
conjunction, so operators can bind an exact declaration and require its
expected semantic tags without widening the match. Resolution scans to
authenticated EOF before accepting a match, rejects zero or multiple matches,
and examines at most 256 opportunities by default or an explicit
`--selector-scan-limit` within `1..=4096`. The selected
effective domain is then fetched and exact-checked against the opportunity;
`--opportunity` and `--domain` remain the unambiguous low-level form. Richer
policy-file selector expressions remain future porcelain over the same records.
Finite values are validated against the choice
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
crucible campaign list [--after NAME] [--limit N] [--pages N]
crucible campaign status NAME [--json]
crucible campaign watch NAME [--after CURSOR]
crucible campaign graph NAME --snapshot SNAPSHOT [--after HASH] [--limit N] [--pages N]
crucible campaign choices NAME --snapshot SNAPSHOT [--after OPPORTUNITY] [--limit N] [--pages N]
crucible campaign frontier NAME --snapshot SNAPSHOT [--after REQUEST] [--limit N] [--pages N]
crucible campaign graph-object NAME --snapshot SNAPSHOT --key HASH
crucible campaign choice-object NAME --snapshot SNAPSHOT --opportunity ID --kind declaration|domain
crucible campaign frontier-object NAME --snapshot SNAPSHOT --request ID
crucible campaign snapshot NAME --snapshot SNAPSHOT
crucible campaign compare NAME --left SNAPSHOT --right SNAPSHOT
crucible campaign explain NAME --snapshot SNAPSHOT --opportunity ID --request ID
crucible campaign findings NAME --snapshot SNAPSHOT [--after HASH] [--limit N] [--pages N]
crucible campaign explain-finding NAME --snapshot SNAPSHOT --finding ID
crucible campaign explain-attempt NAME --snapshot SNAPSHOT --attempt ID
```

The read-only porcelain implements namespace-wide `list`, `status`, a one-shot
resumable `watch`, and bounded immutable-page traversal for `graph`, `choices`,
`frontier`, or `findings` over the authenticated local campaign-service Unix
socket. Every command requires the socket path and
the principal expected from the daemon's peer policy, validates strict
request-bound responses through the checked client, and renders table,
Markdown, pretty JSON, or JSONL through the common CLI output selector. `list`
requires the service's explicit all-campaign grant; an exact-name grant does not
permit namespace discovery. It follows stable campaign-name pages from an
optional exclusive `--after` cursor and renders each authenticated current head,
lineage, policy, and lifecycle projection. Because mutable refs may change
between calls, this is a coalesced inventory rather than an immutable
cross-page transaction. `watch --after` returns the latest coalesced head and an
`advanced` flag; callers repeat it with the returned snapshot cursor to follow a
campaign without treating the transport as authoritative state. Each immutable
page command instead requires an exact snapshot and accepts only the cursor type
returned by that operation: a graph key hash, choice-opportunity ID,
branch-request ID, or finding signature-index hash. One page remains the
default. `--pages` accepts
`1..=256`; traversal also admits at most 65,536 aggregate entries and 128 MiB
of aggregate canonical response bytes. Every response is independently checked
against its exact request (and, for immutable page operations, exact snapshot)
before its entries are accumulated, and a repeated cursor fails closed. The
version-1 list report retains its starting campaign-name cursor, page and byte
usage, authenticated entries, completion status, and exact resume cursor or
observed EOF. The version-2 immutable-page report
retains the starting cursor, per-page limit, page budget, pages and bytes
consumed, authenticated entries, completion status, and either exact resume
cursor or authenticated EOF. Graph pages carry and verify the bounded
Merkle proof specified below before rendering; choice and frontier pages verify
their snapshot-bound nested-index proofs through the same checked client.
Snapshot inspection and comparison independently validate every requested
historical snapshot against the named campaign. The initial `explain` operation
joins one authenticated choice declaration with one authenticated frontier
request, rejects a mismatched opportunity or domain, and reports exact legality,
producer, cause, budget, stop, and continuation fields. The lifecycle mutations
described in §07.3 and exact-precondition `pin`/`unpin` commands use that same
transport. `explain-finding` joins two separately authorized proof-bearing reads
of one exact indexed finding: its representative observation and original
reproduction artifact. It rejects a mismatched finding, dependency kind,
configuration artifact, or reproduction fingerprint before reporting the
stable signature, causal identities, occurrence projection, modeled stop,
evidence-set IDs, replay configuration, and payload profile.
`explain-attempt` performs one separately authorized proof-bearing read and
reports the immutable attempt start and path, execution-basis cause and ordinal,
branch selection and proposal provenance when present, plus a proved canonical
completion or proved absence. `rankings --snapshot SNAPSHOT --step STEP` follows
the accepted planner step's authenticated parent chain and renders a globally
best-first view of every PUCT candidate served by those bounded retained
requests. `--pages` is limited to 64 and the client stops after 128 MiB of
canonical responses; a returned `next_step` continues a deliberately truncated
query. The chain also stops at a different policy, engine, policy artifact, or
planning view rather than comparing scores from incompatible bases. Optional
`--branch-point` and `--source` filters accept exact canonical IDs and are
applied only after every returned page passes proof and retained-request
validation. `--top` keeps at most 65,536 candidates after the packaged
best-first comparator runs; the version-2 machine report echoes all filters and
the pre-truncation matching count. `--policy-groups` instead continues through
policy changes up to the same page and byte ceilings. It emits consecutive
newest-to-oldest policy epochs in
`crucible.cli.campaign-policy-rankings.v1`. Each epoch reports its policy,
step range, page count, and pre-truncation match count, then nests one or more
exact policy/engine/policy-artifact/planning-view bases. Only candidates within
one such basis are compared and ranked. `--top` applies independently after
best-first ordering in each exact basis; no total score is compared across
planning views or other incompatible bases. Filters still run only after every
page passes proof and retained-request validation, and `next_step` continues a
page-limited grouped query.

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
declaration or effective domain named by an authenticated opportunity at an
exact current or historical snapshot in the named campaign.
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
Implementation-version 10 `mutate_near_corpus` reports `Ready` only while the
exact retained completed-selection basis yields an unproposed bounded mutation,
and otherwise waits for another credit. Implementation-version 11
`progressive_integer` reports the same thresholds as version 9 while its next
midpoint is selected by exact owner-derived endpoint PUCT feedback.
Implementation-version 12 reports those same thresholds while prioritizing
authenticated producer-landmark intervals and selecting the nearest
lower-midpoint landmark before ordinary midpoint refinement.
Implementation-version 13 reports the same thresholds while prioritizing exact
owner-verified endpoint mean objective-reward discontinuity before version
12's interval terms.
Implementation-version 14 reports the same thresholds while prioritizing exact
owner-verified endpoint mean globally unique coverage-identity discontinuity
before version 13's interval terms.
Implementation-version 15 reports the same thresholds while prioritizing exact
owner-verified endpoint mean active-policy-weighted finding-reward
discontinuity before version 14's interval terms.
Implementation-version 16 reports the same thresholds while prioritizing exact
owner-verified endpoint mean inverse-frequency coverage-rarity discontinuity
before version 15's interval terms.
A mixture containing any suspended child remains conservatively `Open`. Other
generated sources remain `Open` until their deterministic enumerator and
feedback owner land. Rich admitted-value and interval explanation views and CLI
rendering remain open.

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

crucible store status STORE
crucible store ensure CONTENT_ID --in STORE
crucible store verify STORE
crucible store gc --state STATE --policy POLICY --store STORE --journal JOURNAL plan
crucible store gc --state STATE --policy POLICY --store STORE --journal JOURNAL apply
```

Campaign commands name configured logical stores and durability policies, never
drivers, buckets, endpoints, or local paths. A deployment may bind `archive` to
a directory, S3-compatible backend, or composed store graph. Export and import
display logical and physical byte counts by metadata, reproduction artifact,
exact RAM, disk, log, and trace classes. Sensitive closure warnings occur before
transfer. Store GC is always plan then apply; the plan names its logical roots,
physical inventory basis, and policy version and becomes stale if they move.
`store status` authenticates the strict deployment and reports its exact graph
configuration ID, root, admitted kinds, node kinds, and non-secret capability
profile without reading object bytes. `store ensure` parses one canonical
content ID before deployment I/O, streams the complete logical object through
the admitted root, and reports success only after deferred whole-object
authentication reaches EOF. `store verify` visits physical leaves in canonical
node-ID order, accepts at most 65,536 placements and 128 GiB of summed logical
bytes, streams every placement through the exact physical backend to
authenticated EOF, and reports success only when a closing inventory fence
reproduces the opening generation, count, logical-byte total, and backend
identity. Its report discloses aggregate per-backend evidence, not object IDs
or delete authority. Store discovery remains open rather than guessing a
deployment registry.
The current single-host command is an offline deployment-owner operation:
`STORE` is the strict composed-store file, it acquires the same state lock as
`serve`, derives the only admissible ledger as `STATE/executor-ledger`, and
persists the complete plan/manifests/phase in `JOURNAL`. It accepts no caller-
selected ledger or exact-pin path. Until the packaged exact-pin materialization
owner is wired, a live exact semantic pin makes planning fail closed before
journal creation.

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
The loopback executor component now has a bounded fixed-worker listener over an
already-bound Unix socket. It authenticates one startup-fixed effective
user/group identity through `SO_PEERCRED`, bounds queued sockets and requests
per connection, and joins all connection workers on shutdown. Filesystem
endpoint ownership uses a distinct lifetime lock and the same exact owner,
stale-recovery, mode, and conditional-teardown rules as the campaign socket;
both sockets may share one secure directory without sharing authority.
The daemon can now own the single-host packaged QEMU executor through a strict
deployment file and the explicit or all-campaign runtime selector. That composition
selects the concrete fresh/thin-replay worker, a fixed worker pool, durable
ledger/checkpoint stores, resource ownership, and the authenticated loopback
endpoint as one lifecycle; it does not create a second user-facing service.
The endpoint advertises exact restore only after one promotion owner per fixed
worker has received the complete authenticated native scenario catalog.

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
initial nested CLI now exposes explicitly authorized campaign enumeration,
authenticated current status, one-shot resumable watch, exact-precondition
lifecycle mutation, and semantic pin/unpin mutation. The daemon now owns the
strict 4-KiB operational request/response contract, distinct policy label,
authenticated listener route, and CLI porcelain for dynamic runtime
attachment. Remaining paged inspection is still required before the service is
complete. Repeated bounded
`WatchCampaign` calls provide
the initial resumable, coalesced current-head stream. The bounded versioned
Unix-stream loopback binding is now
implemented with a request-bound stable error envelope preserving authorization,
conflict, transition, resource, availability, and integrity meaning. The
daemon's authenticated repository adapter now reads
Linux `SO_PEERCRED`, resolves exact PID/UID/GID through a mandatory operational
principal mapper, and rejects a different self-asserted request principal
before repository access. A bounded daemon listener now owns either an
explicitly embedded pre-bound socket or a managed production socket, uses at
most 256 fixed connection workers and 1,024 queued
sockets, serves at most 65,536 requests per connection, resolves credentials
once per connection, rejects excess connections, and joins all workers after
sticky shutdown interrupts their active streams.
Its strict registered version-1 TOML policy is bounded to 1 MiB before parsing,
maps at most 4,096 exact effective UID/GID pairs to
principals and at most 65,536 exact operation plus campaign/all-campaign grants;
PID never selects authority. The managed endpoint pins one exact-owner,
non-group/other-writable parent directory, holds a lifetime namespace lock,
recovers only same-owner stale sockets, verifies the configured socket mode,
and removes only the exact bound inode after listener shutdown. The directory
and its ancestors remain operator-owned deployment state. Framing or the
listener alone is never authentication.

The initial combined daemon process is started with an existing secure state
directory and policy file:

```text
crucible serve --listen 127.0.0.1:0 --trusted-unauthenticated-bind \
  --campaign-socket /run/crucible/campaign.sock \
  --campaign-state /var/lib/crucible/campaign \
  --campaign-policy /etc/crucible/campaign-policy.toml \
  --campaign-store /etc/crucible/campaign-store.toml \
  --campaign-maintenance-interval-ms 30000 \
  --campaign-maintenance-write-back-transfers 64 \
  --campaign-maintenance-s3-nodes 8 \
  --campaign-maintenance-s3-uploads 128 \
  --campaign-component-authority /etc/crucible/campaign-authority.bin \
  --campaign-runtime-all \
  --campaign-executor-socket /run/crucible/executor.sock \
  --campaign-packaged-executor /etc/crucible/packaged-executor.toml \
  --campaign-socket-mode 600
```

The socket, state, and policy paths are an all-or-none profile. Without
`--campaign-store`, the daemon uses the state directory's `objects` and `refs`
children. With that option, the strict version-one deployment selects a local
composed immutable graph and separate durable ref directory without creating
those default children. The daemon uses its exact effective UID/GID as the
filesystem and peer-policy owner, takes one durable repository lock before
opening the socket, and stops the lifecycle and campaign services plus the
attached campaign runtime as one signal-driven lifecycle.
The executor socket is an absolute, dot-free, exact-owner mode-`0600` Unix
socket in an exact-owner, non-group/other-writable directory. Startup and the
embedded post-bind owner share one endpoint capability that authenticates the
parent identity, socket owner/mode and before/after inode, and exact peer
UID/GID before capability negotiation or planner/executor work. The connector
uses a nonblocking absolute 30-second default deadline rather than allowing a
full executor backlog to pin attachment indefinitely. Restart reopens the same
object/ref directories while stale-socket recovery remains exact-owner
conditional. Embedded deployment owners may instead supply one consumed
repository-store capability containing a durable conditionally creating
immutable backend or composed graph and a durable conditional-ref backend.
Preparation authenticates policy and component authorities before taking the
same state-root lifetime lock, then retains the supplied capabilities without
creating the default `objects` or `refs` directories or exposing the resulting
repository. Restart reconstructs the exact external capabilities and reuses the
same state-root lock. A volatile blob or ref implementation fails admission.
The shipped `crucible serve` profile now binds local directory, compressed,
encrypted, packed, verified, routed, tiered, read-through, write-through,
write-back, durability-policy, metrics, logical/physical quota, namespaced, and
campaign-profile nodes through the version-one file. The version-two profile
also binds exact HTTPS S3 endpoints, bounded SDK workers, reloading owner-only
credential files, S3 graph leaves, and an optional strong-CAS remote ref
namespace. It checks the exact endpoint capability set and segment-disjoint
physical namespaces before credential I/O, retains graph/ref maintenance
authority through shutdown, and never exposes that authority to the campaign
service. The strong-CAS flag is an operator conformance attestation rather than
automatic service discovery. The optional fixed-cadence maintenance flags lend
only bounded write-back and unfinished-upload capabilities to one joined
worker; exact bounds fail before deployment-file I/O, backend failures stop the
service visibly, and committed-object/ref deletion authority remains withheld.
The separate `crucible store gc ... plan|apply` owner takes the same state lock,
uses the canonical packaged-executor ledger, and reports exact durable journal
and generation-bound apply outcomes. A hermetic live-service fixture and the
realistic operator flight remain open.

The separately hosted or daemon-packaged executor endpoint has one coupled
lifecycle owner: a shutdown closes assignment admission, signals active
attempts, interrupts connections, and joins both connection and semantic
workers. Terminal semantic worker failure closes the listener instead of
leaving an apparently live but unusable socket. Dropping the unserved owner
retains the socket namespace until the same semantic join completes. In
daemon-packaged mode a strict version-one deployment file fixes aggregate
capacity, worker count, cgroup/run roots, project-ID range, child credential,
checkpoint ceiling, and exact compatibility profile before the endpoint is
exposed. One pool may serve up to 256 explicitly selected or automatically
discovered campaigns only when their exact compatibility profile is identical.
Its closed startup catalog contains one native baked genesis per distinct exact
scenario; admission rechecks catalog membership for every attempt, and
post-bind attachment through the packaged endpoint rejects an uncatalogued
scenario before executor connection. A
post-bind attachment naming another independently authenticated executor keeps
that executor's own capability scope. Fixed workers receive stable disjoint
run-state roots. The concrete fresh/thin-replay and promoted exact-resume paths
are selected; hot-fork execution remains fail-closed and open.
`--read-only` applies to both APIs and cannot be bypassed by a mutation grant in
the campaign policy.

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
- **[CAPI-14]** Policy-aggregated ranking inspection MUST authenticate every
  retained planner page before grouping, preserve consecutive policy epochs,
  and rank candidates only within an exact policy, engine, policy-artifact, and
  planning-view basis. Filters MUST precede grouping, and a top-result limit
  MUST apply independently after deterministic ordering in each comparable
  basis.
