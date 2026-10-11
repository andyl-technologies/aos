# 5. Database and scheduling

## 5.1. Authoritative logical model

The following are logical entities, not prescribed SQL table names. Native
and Worker database adapters MUST implement the same uniqueness, transaction,
compare-and-swap, and authorization semantics. Provider requests MUST NOT run
inside a database transaction.

| Entity | Identity and required durable state |
| --- | --- |
| Inventory subject | Tenant/resource/version/platform key, authenticated publication reference, inventory digest, revision, visibility |
| Scan definition | Immutable digest, schema, canonical content, admitted publication/source authority |
| Inventory | Immutable digest, canonical graph, coverage, input object references |
| Provider observation | Immutable digest, source identity, evidence references, timestamps, coverage, adapter version |
| Advisory snapshot | Immutable digest, source revisions, manifest/shards, coverage and authorization partition |
| Candidate history | Provider/project/stream identity, candidate identity, first admitted observation, history revision |
| Assessment | Immutable digest, canonical content, scan input, engine identity, evidence retention references |
| Subject assessment head | Subject/profile/policy key, current inventory revision, desired generation, committed generation, assessment digest |
| Scan operation | Scan ID, request, actor/trigger, pinned scope, generations, state, progress, idempotency identity |
| Scan task | Scan/task IDs, generation, dependencies, operation, claim/lease, budget reservation, attempt, outcome |
| Schedule | Scoped resource selector, profiles, cadence, policy reference, revision, next due time, enabled state |
| Source budget | Provider/credential scope, quota window, reserved/consumed requests, next eligible time, circuit state |
| Alert | Stable issue identity, episode, latest evidence, disposition, acknowledgement, transition sequence |
| Subscription | Scoped selector, event filters, destination reference, secret revision, enabled state |
| Event/outbox | Tenant sequence, event ID, committed resource revision, payload reference, delivery state |
| Import receipt | Bundle digest, uploader, validation result, resulting assessment and authority classification |

Inventory and evidence objects MAY be stored outside SQL using existing
admitted object storage. SQL MUST retain their authenticated identities and
availability/retention references. A blob in an object cache is not a committed
assessment. RFC-0023's physical storage journals remain authoritative for
physical operations; this service MUST NOT replace them with scan task rows.

Candidate history is explicitly part of the evaluator's input. `firstObserved`
means first admission into the named history scope, not an executor's clock or
an upstream release timestamp. Public provider history MAY be shared when
policy permits; private history MUST remain authorization-partitioned. Local
evaluation can import that history for parity, or use its own separately
identified history. An old locally observed candidate cannot silently obtain
the Hub's stabilization age without the corresponding evidence.

## 5.2. Scan operation lifecycle

The scan operation states are:

```text
queued -> running -> succeeded
                  -> partial
                  -> failed
queued/running -> cancelling -> cancelled
queued/running -> superseded
```

`succeeded` means the requested execution completed with its declared coverage;
it does not mean that no vulnerabilities or updates exist. A requested profile
with missing required source coverage produces `partial` when useful results
can be evaluated, and `failed` when a trustworthy assessment cannot be built.
An intentional metadata exclusion, such as a manually maintained package,
is a policy result rather than a provider failure. Terminal states are immutable.

Each task has `pending`, `leased`, `waiting`, `succeeded`, `partial`, `failed`,
`cancelled`, or `superseded` state. `waiting` carries a typed reason and next
eligible timestamp, including quota exhaustion. A retry changes attempt/claim,
not the logical task identity or admitted request. Tasks dependent on failed
evidence MUST NOT pretend their dependencies succeeded.

Progress counts completed bounded tasks and evaluated subjects. It MUST NOT
claim a percentage based on unknown provider page counts. A cancelled scan
retains already admitted observations and any immutable assessments committed
before cancellation. Cancellation prevents subsequent head/alert commits for
that operation; it does not retract published evidence.

## 5.3. Claims, leases, and fencing

The coordinator claims a task transactionally using a database time source and
an unguessable claim token. Claiming also reserves its provider budget. Claims
bind the scan generation and exact request. Workers receive no permission to
extend a lease, alter generation, or allocate another reservation.

Expired work MAY still finish physically. A result is admitted only if its
claim, generation, request digest, and authorization remain valid. A stale
result MUST NOT advance a task, assessment head, alert, or delivery state.
Already verified immutable evidence MAY enter the appropriate cache through
a separate admission; that does not make the stale execution current.

Lease duration MUST exceed the admitted execution deadline plus configured
clock/network margin. The execution validity window remains bounded by
Chapter 4. A long source refresh therefore uses several bounded tasks with
new claims and continuations. Worker-only coordinator invocation limits use
the same resumable task model; in-memory continuation state is insufficient.

Unique constraints and compare-and-swap are REQUIRED for claims, idempotency,
head promotion, alert episodes, and outbox creation. A distributed application
lock MAY optimize contention, but MUST NOT be the only correctness mechanism.

## 5.4. Pinning and committing a result

At request admission the coordinator pins a finite, authorized subject set,
inventory revisions, scan definitions, policy, and evaluation intent. A large
selector becomes a durable paged inventory snapshot, not a changing query on
each page. New package versions enter a subsequent generation.

Provider work can discover newer evidence during execution. Before evaluation,
the coordinator freezes the complete `scan-input/v1`, including observation
digests, advisory snapshot, dispositions, candidate history, engine, and
evaluation time. It MUST NOT replace these inputs while the pure evaluator
runs. An evaluator checkpoint binds the same input digest.

Committing a current assessment performs one transaction that:

1. Checks the current authorization, inventory revision, desired generation,
   policy revision, and cancellation fence.
2. Records the immutable assessment and retention references, or verifies an
   existing identical assessment.
3. Advances the applicable subject/profile/policy head using compare-and-swap.
4. Derives alert transitions against the previous committed state and stores
   their new state and sequence.
5. Inserts durable events and notification outbox entries with unique IDs.
6. Updates operation progress and, if complete, its terminal state.

A crash exposes either the committed assessment with its events or neither.
No notification is sent before this transaction commits. An immutable result
that loses the head race remains inspectable as historical evidence; it MUST
NOT overwrite a newer desired generation.

Generation ordering describes desired resource state, not worker completion
order. When an inventory, required policy, disposition, or advisory input
changes, the coordinator advances the relevant desired generation. Manual
refreshes with equivalent scope MAY coalesce into that generation and report
the associated scan operation. A generation cannot indefinitely starve older
work by treating every clock tick as a new input; coalescing and maximum
reassessment delay are required.

## 5.5. Continuous triggers

The service supports these trigger classes:

| Trigger | Minimum effect |
| --- | --- |
| Admitted package/artifact inventory | Initial assessment of its exact revision |
| Updated scan definition or identity mapping | Re-evaluate affected inventory; invalidate incompatible observations |
| New provider candidate | Re-evaluate compatible streams using retained candidate history |
| Changed advisory record or withdrawal | Re-evaluate all retained matching component versions, including old releases |
| KEV/severity/disposition change | Re-evaluate applicable findings and release policy |
| Stabilization/freshness deadline | Re-evaluate policy or mark effective state stale; fetch when scheduled |
| Authorized manual request | Admit bounded requested scope and freshness mode |
| Scheduled refresh | Refresh due provider evidence and assess affected subjects |

Provider ingestion commits its cursor only after every required page and
retained record in that checkpoint is durable. Partial ingestion does not
replace a complete advisory snapshot. A provider's absence/deletion semantics
MUST be honored; a missing record in an incomplete fetch is not a withdrawal.

Indexed identity/range associations select affected subjects. These indexes
are disposable projections. A parser or mapping change MUST provide a bounded
reindex/reassessment path and MUST NOT rely solely on old indexes to find new
matches. Periodic complete reconciliation repairs missed triggers.

Continuous means changes cause durable bounded work, with observable latency.
It does not promise instantaneous knowledge of an advisory that its source
has not published or that the deployment has not fetched. The API exposes
source checkpoint times and evaluation times separately.

## 5.6. Scheduling and budgets

Schedules define resource selectors, profiles, desired cadence, freshness
policy, and concurrency/budget class. Package metadata defines scan semantics;
deployment administrators own quota, credentials, cadence, and operational
limits. Tenants MAY choose only within their granted quota and policy bounds.

The `aos.assessment-schedule-configuration/v1` field `continuous` is an optional
boolean, defaulting to `false` and omitted when false. An explicit `true`
reviews the existing bounded selection for admitted inventory/policy changes
and elapsed complete-profile freshness deadlines in addition to its cadence.
Absence MUST preserve prior serialized configuration bytes and cadence-only
behavior. All readers MUST support the
field before writers enable it; deployments MUST NOT downgrade readers while
such reviews exist.

A coordinator observes at most ten future reviews per registry pass and rotates
observations using a persisted monotonic attempt clock. A private retained
input watermark records the last admitted input, including input mutation
revision: policy A-to-B-to-A and inventory reactivation are changes, whereas
scan-generation allocation alone is not. Multiple changes while a slot is
already due MUST coalesce without replacing its admitted retry identity. A
reactive retry identity MUST use a domain distinct from cadence slots and bind
the captured input watermark, configuration revision and due time, including
multiple wakeups in one UTC second.

Elapsed freshness observation MUST select the exact reviewed package coordinates
and profiles under the current inventory and policy. It reads indexed deadline
metadata, never provider bodies or an unbounded evidence closure. A private
monotonic admission clock covers all deadlines elapsed at the last matching
admission. Renewing or removing a head MUST NOT lower that clock or self-trigger
a scan. A newer elapsed deadline contributes to the exact reactive retry identity.
Heads without complete source coverage have no indexed freshness deadline and
MUST NOT acquire fresh coverage from scheduling. The original reviewed acquisition
intent remains authoritative; deadline wakeups do not silently upgrade an offline
or cached review to network refresh. All readers MUST support the private expiry
clock before updated coordinators write it. Earlier continuous reviews without
that clock receive bounded catch-up; cadence-only reviews remain unchanged.

Only admission against the current input may acknowledge a watermark. The
watermark and due cursor MUST persist atomically under current resource and
review fences, without extending credential or review deadlines. Neither
observation nor a watermark grants execution authority. Every admission and
subsequent effect MUST still check the existing current principal, credential,
configuration, inventory, policy, cancellation and quota guards. This inventory
and policy observation does not itself establish advisory-feed, evidence-expiry
or disposition-trigger integration; those triggers require their own retained
input identities and deadline work.

The scheduler uses deterministic jitter derived from schedule identity and
time window. It persists the next due time and coalesces missed executions
after downtime. A backlog MUST NOT trigger unbounded catch-up fetches. Priority
order SHOULD favor known exposed vulnerabilities, newly published subjects,
release-gate requests, and evidence approaching expiry, with fairness that
prevents starvation of ordinary checks.

Provider budgets apply across all scans sharing the relevant provider and
credential scope. Per-worker rate limits alone are insufficient. Reservations
are made before issuance and consumed conservatively when an attempt may have
reached the provider. Retried requests do not reuse spent allowance. Unused
allowance MAY be released only when non-execution is established. Source
limits, tenant limits, and request-wide limits all apply; the tightest wins.

Each scan admission pins maximum subjects, graph nodes/edges, provider
requests, tasks, normalized bytes, evaluation work, and wall-clock lifetime.
These are independent of per-task limits. Exceeding a limit gives a typed
partial/failure result with a continuation or narrower-scope recommendation;
it MUST NOT silently omit excess subjects. Pagination is not an authorization
to create unbounded additional work.

Provider outages open a persisted circuit with a bounded retry/backoff policy.
Circuit status is operational state, not vulnerability applicability. Cached
evidence may remain useful but its age and missing refresh are explicit.

## 5.7. Freshness and reads

An assessment's evaluation time is immutable. Its effective freshness at a
later read is derived from its pinned evidence and the active policy, with
the read's `asOf` time reported separately. Expiry does not rewrite an
assessment digest. A policy change MAY immediately make an existing head
ineligible while replacement evaluation is queued.

Read methods MUST NOT fetch providers or launch scans implicitly. They return
the committed head, effective freshness, pending generation, and last refresh
outcome. A client explicitly requests a scan when fresh evidence is needed.
Alert freshness transitions are persisted by scheduled deadline work;
correctness of the read does not depend on that task having already run.

## 5.8. Recovery and deletion

Coordinator restart reclaims expired tasks, reconciles reserved budgets,
resumes due schedules, and retries outbox delivery. It does not invent
successful outcomes for lost worker responses. Disaster recovery MUST restore
database generations, event positions, and evidence retention together, or
mark affected assessments unavailable pending reconciliation.

Deleting a subject or revoking access prevents new scans and notifications
for that scope. Retained audit evidence follows the authorized retention
policy and is no longer exposed through the deleted resource's public route.
An inventory deletion is not a finding resolution. Pinned release/handoff
references prevent garbage collection while retained and authorized.
