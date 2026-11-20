# Operating a campaign

This page covers creating a campaign, driving its lifecycle, inspecting
and explaining its progress, and branching, with a summary of every
`campaign` subcommand. It is part of
[Operating lazy campaigns](campaigns.md).

## Create and inspect a campaign

Creation records refer to artifacts already admitted by the verified importer.
The lineage and policy arguments are canonical binary records:

```sh
./result/bin/crucible campaign \
  --socket /run/user/1000/crucible/campaign.sock \
  --principal operator \
  create network-recovery \
  --lineage ./worked-network-fixture/lineage.bin \
  --policy ./worked-network-fixture/policy.bin \
  --start-command "$START_COMMAND" \
  --format json
```

`--start-command` is optional. When present, creation is followed by a separate
idempotent start against the exact returned genesis snapshot; the version-2
acceptance report contains both results. The two mutations are retry-safe but
not atomic, so retry the same create/start inputs if creation succeeds and the
start response is indeterminate. Save exact IDs from JSON instead of scraping
tables.

Enumerate the authenticated current heads visible to a principal with an
explicit all-campaign grant:

```sh
./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator list --limit 32 --pages 8 --format json
```

An exact-name policy grant does not permit namespace discovery. Listing follows
stable campaign-name pages and returns the exact resume cursor when the page
budget ends before observed EOF. It admits at most 256 pages, 65,536 aggregate
entries, and 128 MiB of canonical responses. Campaign refs may change between
pages, so the result is a coalesced inventory rather than an immutable
cross-page snapshot; every returned head and lifecycle projection is still
authenticated independently.

Status and watch authenticate one exact head and lifecycle projection:

```sh
./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status network-recovery --format json

./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator watch network-recovery \
  --after "$SNAPSHOT" --format json
```

`watch` is advisory and coalescing: sequence gaps do not imply lost immutable
history. Use `snapshot` for an exact historical body.

Derive a new name from one authenticated current or historical snapshot with
the source policy or an explicitly supplied compiled policy:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  derive network-recovery --snapshot "$SNAPSHOT" network-recovery-revised \
  --policy ./revised-policy.bin --format json
```

The supplied policy must have the same campaign mode as the source policy, and
a statistical campaign must preserve the exact active policy. Derivation never
converts between strict, streaming, and statistical modes. `campaign steer
--policy` on an existing campaign name has the same exact-mode rule.

Derivation shares the exact immutable history reachable from the selected
source snapshot and leaves the source name unchanged. Retry the exact same
source snapshot, target name, and policy after an indeterminate result.

## Run, pause, and resume

Every mutation against an existing campaign carries the exact expected
snapshot and an idempotent command identity. Generate a new command identity
for a new intent; retry the same bytes with the same identity after an
indeterminate transport result.

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  start network-recovery --expected "$SNAPSHOT" --command "$START_COMMAND"

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  resume network-recovery --expected "$SNAPSHOT" --command "$COMMAND"

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  pause network-recovery --expected "$NEXT" --command "$PAUSE_COMMAND" \
  --active drain
```

`start` and `resume` apply the same checked lifecycle transition. Use `start`
for the first transition from a newly created campaign and `resume` after a
pause; their reports preserve that operator intent.

With a packaged runtime attached, a Running campaign with an empty frontier
needs an attempt grant before it can discover its first choice:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  budget network-recovery --expected "$SNAPSHOT" --command "$BUDGET_COMMAND" \
  add 1 --proposals 1
```

Read the updated head before issuing the next mutation. The coordinator records
one genesis discovery with an empty branch path and `next-choice` stop; a modeled
terminal verdict may complete it sooner. This admission survives restart and
does not repeat. A proposal-only grant does not fund discovery. Campaign-wide
grant enforcement for later planner issuance remains under verification; this
first-attempt check does not certify that broader limit.

Run each command with `--help` before scripting it. Pause policies are semantic:
`drain` waits for admitted work, `retry` preserves canceled work as retryable,
and `checkpoint` requires the executor's guarded exact-checkpoint path.

## Inspect authenticated progress

All page cursors are bound to the exact immutable snapshot. A cursor from one
snapshot is invalid for another. Machine consumers should page until the
authenticated response reports EOF rather than inferring EOF from a short page.

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  report network-recovery --snapshot "$SNAPSHOT" \
  --limit 32 --pages 8 --format json

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  frontier network-recovery --snapshot "$SNAPSHOT" --limit 256 --format jsonl

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  findings network-recovery --snapshot "$SNAPSHOT" --limit 256 --format jsonl
```

`report` combines the exact observed outcome classes with admitted execution
bases, retained findings, planner-chain identity, and continuation totals. It
names explored, stopped, successful, failed, and unexplored attempts separately
and distinguishes unvisited, exhausted, and budget- or policy-closed (pruned)
continuations. Exhaustive nonstatistical campaigns are descriptive; adaptive
tree and beam campaigns are labeled guidance-biased. A statistical campaign
returns `no-estimate` until every policy-declared endpoint has an authenticated
observation. Once complete, its paged endpoint records carry exact target `P`,
proposal `Q`, estimator weight, and evidence identities. In this report,
`complete` describes endpoint pagination; the campaign lifecycle remains in
the separate `state` field.

Object bodies require their own authorization even when an ID appeared in a
graph page. Use `graph-object`, `choice-object`, or `frontier-object`; do not
read repository files directly.

## Explain a decision or finding

`explain-attempt` authenticates the attempt, its execution-basis admission,
branch selection and proposal, optional completion, and—when a planner issued
the proposal—the accepted planner step. JSON version 2 includes exact
fixed-point guidance terms and coordinator accounting:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  explain-attempt network-recovery \
  --snapshot "$SNAPSHOT" --attempt "$ATTEMPT" --format json
```

Use `explain` for a choice/frontier legality join and `explain-finding` for the
representative observation plus original reproduction. Each operation rejects
individually valid records whose cross-object basis does not agree.

To compare every PUCT candidate served across a bounded planner scan, start at
the newest accepted planner step reported by `explain-attempt`:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  rankings network-recovery \
  --snapshot "$SNAPSHOT" --step "$PLANNER_STEP" --pages 16 \
  --branch-point "$BRANCH_POINT" --top 20 --format json
```

Each page authenticates one step under the snapshot's coordination root and
recomputes scores from its complete retained request. The report is globally
best-first across the returned pages. If `next_step` is present, repeat from
that step to continue beyond the selected page bound. The command stops at a
different policy, engine, policy artifact, or planning view instead of merging
incomparable score bases. `--branch-point` and `--source` accept exact canonical
IDs and filter only after response authentication; `--top` truncates only after
global ordering. JSON and JSONL use
`crucible.cli.campaign-rankings.v2`, echo the filter basis, and report the
number of matching candidates before truncation.

Triage every finding retained by an exact snapshot through the same campaign
owner:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  triage network-recovery --snapshot "$SNAPSHOT" \
  --policy exact --minimize representative --report ./triage-report
```

The shorter spelling is equivalent:

```sh
crucible triage --campaign-socket "$CAMPAIGN_SOCKET" --principal operator \
  network-recovery --snapshot "$SNAPSHOT" \
  --policy exact --minimize representative --report ./triage-report
```

Both forms fetch and authenticate snapshot membership, every retained finding
occurrence, its reproduction objects, and its segmented native replay proof.
They do not accept a local findings ledger as an independent campaign
authority.

## Campaign command summary

The [`campaign` reference](reference-cli.md#campaign) lists every argument and
default. This summary groups the subcommands by task. Subcommands in the first
group run without `--socket` and `--principal`; the others use a connected
campaign socket unless noted.

- **Author and validate offline:** `fixture worked-network`,
  `validate-import`, `validate --policy`, `scenario compile`,
  `configuration compile`, `schedule compile`, `policy compile`, and
  `lineage compile`.
- **Create and attach:** `create`, `derive`, `attach`, and `list`.
- **Control the lifecycle:** `start`, `resume`, `pause`, `stop` (with optional
  `--seal`), `unseal`, `budget add`, `steer`, `pin`, and `unpin`.
- **Branch:** `branch`, `choice-value encode`, `capture-attempt`,
  `capture-status`, and `select-capture`.
- **Inspect:** `status`, `watch`, `snapshot`, `compare`, `report`, `graph`,
  `graph-object`, `choices`, `choice-object`, `frontier`, `frontier-object`,
  `request-attempts`, and `findings`.
- **Explain:** `explain`, `explain-finding`, `explain-attempt`, and `rankings`.
- **Work with findings:** `replay`, `triage`, `debug`, and `finding-bundle`
  (`export`, `verify`, `midpoint`, `fork-write`, `branch`).
- **Archive between stopped owners:** `archive transfer` and
  `archive inspect`.

### Branch from a discovered choice

`branch` submits one finite additive operator branch request. Name the
semantic branch point, the exact parent configuration artifact, and the
choice either by its exact opportunity and domain IDs or by one or more
`--selector` expressions. Then supply finite `--value` entries, a
`--generator`, or `--all`:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  branch network-recovery --expected "$SNAPSHOT" --command "$BRANCH_COMMAND" \
  --branch-point "$BRANCH_POINT" --parent "$CONFIGURATION_ARTIFACT" \
  --opportunity "$OPPORTUNITY" --domain "$DOMAIN" \
  --value true --attempts 1 --stop next-choice
```

A value is `true`, `false`, `i64:N`, `u64:N`, `discrete:ID`, or `group:HEX`.
`choice-value encode` produces the `group:HEX` form from complete
`--member NAME=VALUE` assignments against an authenticated group domain.
`--stop` defaults to `next-choice`; the other conditions are `terminal`,
`boundary:NAME`, `virtual-time-ps:N`, `events:N`, `execution-quanta:N`, and
`virtual-time-or-execution-quanta:TIME:QUANTA`. The active policy's attempt
deadlines also apply. `--all` exhausts the authenticated finite domain under
the active exhaustive policy and takes no `--command` or `--proposals`.

`choices` pages the discovered choice opportunities of a snapshot,
`choice-object --kind declaration|domain` inspects what one opportunity
names, and `request-attempts` reads the execution bases admitted for one
branch request.

### Capture and continue a completed attempt

`capture-attempt` replays a completed next-choice attempt to an exact
pending-choice checkpoint. `capture-status` inspects the authenticated outcome
and retained root of that capture request. Once the capture is Ready,
`select-capture` admits an exact-source continuation and requires the later
`--stop` condition reached after the pending choice is answered.

### Replay, export, and archive findings

`replay NAME --snapshot SNAPSHOT --finding FINDING` replays one authenticated
finding reproduction through its pure oracle; add `--minimized` to replay the
authenticated minimized reproduction when present.

`finding-bundle export` writes one finding and its complete executable archive
from a stopped owner into a new directory. `finding-bundle verify DIR` checks
the archived evidence offline, and `--exact` repeats the retained production
boundary in a fresh local QEMU lifecycle. `midpoint` opens an archived exact
checkpoint in a private read-only QEMU session, `fork-write` forks a second
private midpoint and proves one non-canonical register write, and `branch`
executes a declared alternate choice from the imported executable archive.

`archive transfer` moves one exact snapshot between stopped deployment owners
under a closed `--mode` (`metadata`, `findings`, `debug`, `executable`, or
`mirror`); `archive inspect` authenticates one named archive in a stopped
deployment.
