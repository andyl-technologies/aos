# Execution contract: lifecycle, publication, and recovery

This chapter defines the runtime behavior behind the operation vocabulary in
[structured activation](06-structured-activation.md). It complements the
[data and composition contract](implementation-contract.md). It describes the
target implementation; existing activation keeps its current behavior until
the replacement is qualified.

## Initial operation families and trusted adapters

Version 1 supports the following semantic families for the first complete
activation path. Exact interface method declarations refine their inputs and
outputs; a string with one of these names is not executable authority.

| Family | Inputs and completion contract |
| --- | --- |
| Verify artifact | Authenticated exact artifact/closure; completes after integrity and required provenance checks |
| Prepare managed configuration | Desired files/templates, owner, destination resource; returns an immutable candidate and publication preconditions |
| Acquire/deliver credential | Authorized opaque credential/version reference and workload view; returns scoped delivery evidence without secret bytes in the plan |
| Validate candidate | Exact executable/arguments, candidate, identity, credential and filesystem views; returns validation evidence tied to those inputs |
| Publish configuration | Validated candidate and expected current revision; returns an authoritative publication receipt |
| Prepare manager configuration | Exact unit definitions and manager scope; returns staged/loaded unit revision with declared visibility |
| Start/reload/restart/stop | Exact managed instance and expected revision; returns operation acknowledgement with any necessary reconciliation evidence |
| Observe readiness | Declared probe and expected behavior/revision; returns readiness evidence or bounded failure |
| Release resource | Exact owned resource, expected assignment, and zero remaining required users; completes after release/fencing is observed |
| Record generation association | Exact published artifacts and observed consumers; durably records their actual relationship |

Traffic shift/drain, image staging/boot selection, Kubernetes apply/wait, and
provider-specific storage operations extend these families through explicit
versioned interfaces. Their specialized semantics are not approximated with a
generic command. An unsupported operation blocks that strategy until its
adapter and tests exist.

Initially, privileged leaves use trusted compiled runtime adapters, existing
broker/manager protocols, or explicitly cataloged constrained helper processes.
There is no package-supplied dynamic-library plugin loaded into a privileged
executor. A helper has an exact artifact, entry point, argument schema, allowed
resources/identity, result schema, and recovery contract; arbitrary shell text
does not satisfy that catalog.

Each invocation carries operation/attempt IDs, plan and binding identities,
typed inputs, expected resource revisions, and its bounded deadline. Results
are typed as completed, rejected-before-effect, or indeterminate, with
provider evidence and an error class where appropriate. Completion evidence
identifies the affected resource/revision. Helpers cannot return new privileged
operations for the executor to run without replanning and validation.

## Dependency and scheduling rules

| Edge | Scheduling meaning |
| --- | --- |
| Data | Producer succeeds and the typed output is available before the consumer starts |
| Required success | Predecessor succeeds before the consumer starts |
| Ordering only | Predecessor reaches a settled outcome; no success is implied |
| Readiness | The named observation establishes the required revision/condition before dependent exposure |
| Retention | Required artifact/resource stays retained; no startup order is implied |
| Communication | Permitted runtime relationship; no automatic execution edge |

Indeterminate operations are unsettled until reconciled or explicitly reported
as requiring intervention. An ordering-only edge cannot bypass a missing data,
authorization, validation, or required-success prerequisite. A failure handler
may run after a settled failure only when declared and authorized in the plan.

The planner inserts serialization for overlapping mutable resource accesses.
Conflicting independent desired owners fail preflight; serialization cannot
resolve a semantic ownership conflict. Runtime ownership uses the existing
provider/broker locks or leases. Acquire multi-resource reservations in stable
resource-ID order, or use an atomic broker reservation, and release an incomplete
acquisition before retrying. Do not hold a partial reservation while waiting
indefinitely for another controller.

Among ready nonconflicting nodes, use stable operation-ID order for dispatch
selection and a configured bounded concurrency limit. Actual independent
completion order may vary outside Crucible. Correctness must not depend on it;
completion order is recorded, not forced into the plan's semantic identity.

No runtime operation may change the admitted graph, its authority, or required
guarantees. Bounded retry/observation loops are declared method semantics.
Recovery that needs a different operation graph creates a new linked plan.

## Lifecycle selection

The controller selects one case from the complete current/desired/observed
state. Drift is explicit input; absence of trustworthy observations is unknown,
not automatically proof that a resource is absent.

| Change | Required transition |
| --- | --- |
| Instance absent, desired enabled | Prepare required resources, validate, publish, start, and observe |
| Configuration changes on an active instance | Prepare/validate/publish; reload only if the provider declares it sufficient, otherwise restart |
| Executable, identity, confinement, or incompatible binding changes | Revalidate and use the declared restart/replacement path; a configuration-only reload is insufficient |
| Credential reference/version changes | Redeliver and use the provider's declared reload/restart behavior; secret bytes never enter the diff |
| Desired unchanged, observed healthy and matching | Record no-op outcome without unnecessary reload or publication |
| Desired unchanged, observed stopped/stale/divergent | Reconcile under current authority; first classify actual state, then plan required operations |
| Consumer contribution removed | Recompute the aggregate and update its remaining provider-owned state |
| Instance disabled/removed | Withdraw dependent exposure, drain if supported, stop, detach consumers, release eligible resources; retain persistent data by default |
| Provider/binding replacement | Explicit compatible handoff or create/transition/retire; reject an unsupported transfer |
| Retained generation selected | Newly validate and plan toward that target; do not replay an old successful grant |

If a provider advertises reload, its contract states which changed fields it
covers and how readiness is established for the result. Unknown changed fields
do not default to no-op. A provider without a safe restart/replacement path
rejects the transition rather than silently weakening semantics.

Initial nginx startup and subsequent reload are separate cases. First startup
must not validate against old live files or attempt to reload a nonexistent
process. Removing the final application contribution does not itself remove
an operator-enabled nginx instance.

## Durable transaction state

The transaction progresses through these states, with the full prior history
retained:

```text
planned -> admitted -> preparing -> publishing -> converging -> succeeded
              |           |            |             |
              +-----------+------------+-------------+-> recovering
                                                       -> settled failure
                                                       -> intervention required
```

`planned` has validated immutable input/plan references and retention roots.
`admitted` records checked runtime assignments and ownership. `preparing`
performs candidate work without claiming live publication. `publishing` crosses
declared visibility boundaries. `converging` applies lifecycle effects and
observes consumers. `succeeded` means the command's declared target condition
has been established, not merely that the graph was traversed.

Per-operation state records pending, admitted intent, running, completed,
rejected-before-effect, indeterminate, and any compensation/reconciliation.
A crash after admitted intent can leave the operation indeterminate even if
no running event was persisted. Attempt numbers increase within a stable
operation identity; provider idempotency keys identify the logical operation
across retries rather than making each retry a new side effect.

Durable records use versioned bounded frames with sequence, previous-record
digest, and body digest. Persist plan/required roots before intent, intent
before the effect, and completion evidence before scheduling its required
success dependents. Synchronize files and containing directories at the
storage provider's documented durable boundaries. A torn final frame may be
discarded only after verifying the complete preceding prefix; retain that
prefix's unresolved intent for reconciliation. Corruption in the committed
prefix fails recovery and preserves the evidence.

The journal records what the controller knows. It does not make an external
effect atomic with its local record. A recovery record links to the same
transaction or a successor recovery plan; it does not rewrite failed history.

## Publication and generation visibility

Every publication method declares its atomicity scope, linearization point,
durability condition, expected old revision, and observation/recovery method.
For filesystem publication, staging and atomic rename must obey the selected
filesystem's constraints; cross-filesystem moves are not assumed atomic.
Managed roots and destinations are acquired through their provider, not
unchecked path strings supplied by consumers.

For the first activation implementation, retain the existing configuration
commit boundary. Candidate preparation cannot update a live profile or service
selection. At commit, compare the expected current revision under ownership,
publish through the existing backend, and retain its outcome/receipt. When a
crash interrupts receipt recording, inspect the backend's actual selected
revision and recovery evidence before deciding whether publication occurred.

Package-profile, configuration, and image pointers are separate state axes.
Do not claim one filesystem rename atomically switches them all. Record each
axis's old/new revision and actual publication outcome, and complete interrupted
pointer/record maintenance under the same recovery controller. Concurrent
mutating workflows are fenced during an unresolved local publication.
Readers report the recorded transition/uncertainty when the axes have not
converged instead of presenting a fictitious single generation.

Failure before any live publication leaves the old live target selected and
cleans eligible candidate resources. Failure after publication retains that
commit, returns a failed/degraded activation result, and records which consumers
still run old or unknown revisions. It does not silently change the committed
target back. Explicit compensation or rollback is a separately validated
transition with its own outcome.

An explicitly supported degraded boot may commit a validated subset. The
controller records the original intent, omitted consumers, recomputed aggregate,
and committed subset. Missing required enforcement excludes its consumer or
fails the transition; it never becomes an optional missing dependency.

## Errors, retries, cancellation, and time

Use structured error classes: invalid contract, incompatible interface,
unauthorized, ambiguous binding, unsatisfied obligation, resource conflict,
stale precondition, unavailable provider, deadline exceeded, indeterminate
effect, and corrupt recovery state. Diagnostics identify phase, operation,
relevant resources, and whether a live effect may have occurred. Human wording
and numeric CLI exit assignments remain frontend details.

Default automatic retry is disabled. A method may explicitly permit bounded
retry with a maximum attempt count, backoff, and total deadline. Retry is safe
only when rejection-before-effect is established or the provider supplies
idempotency/reconciliation for the logical operation. Authorization/schema
errors are not transient retries. An indeterminate result first invokes the
declared observation/reconciliation path; inability to determine the result
becomes intervention required, not blind repeated execution.

Cancellation stops admission of new ordinary operations, requests cancellation
of in-flight methods according to their contracts, and records their actual
settlement. It does not assert that effects disappeared. Required cleanup or
compensation can continue only within its existing authorization and bounded
recovery plan. Ownership is retained until a resource is known safe to release
or responsibility is transferred to an explicit recovery controller.

Every operation declares a finite timeout and a bounded total recovery budget.
Use monotonic time for one live attempt. Reboot recovery retains the deadline
policy and elapsed/budget evidence; it must not reset retries indefinitely on
each restart. Cross-boot leases use their issuing provider's freshness/expiry
contract. Unverifiable expiry blocks further dependent effects. Crucible tests
use the generic modeled clock/choice integration, with AOS interpretation
remaining guest-side.

## Recovery, upgrades, and external resources

On startup, enumerate unresolved durable transactions before new work in their
resource scopes. Validate their formats/artifacts, reacquire controller
ownership, authenticate current policy/provider assignments, inspect ambiguous
effects, and resume or produce a linked recovery plan. A current policy may
authorize stopping an old consumer without authorizing its restart; do not
restore revoked workload authority merely to finish an old plan.

An executor upgrade retains the code/artifacts needed for outstanding recovery
until the new executor can interpret the journal and every used method version.
Otherwise finish/drain the old work before replacing it, or explicitly retain
the supported old recovery service under constrained authority. Unknown journal
or handler versions prohibit automatic resume. Do not discard an unresolved
transaction to make the upgrade appear successful.

External managers and Kubernetes controllers keep their own reconciliation
authority. AOS records submitted revisions and observes their promised outcomes;
it does not concurrently reconcile their private child objects. Multi-host
rollout has per-environment commits and an explicit aggregate result. Its
strategy defines what to do when only some environments commit. No global
rollback or exactly-once remote effect is inferred.

## Retention and completion

Root exact plans, modules, handlers, payloads, candidates, and other required
artifacts before they become inputs to admitted work. Maintain roots for
unresolved transactions, observed active consumers, retained generations, and
declared rollback windows. Add replacement roots before releasing predecessors
under the existing GC/ownership coordination.

Release ephemeral resources only after required consumers and recoverable
attempts detach. Persistent state deletion requires its own grant, selected
retention policy, and operation. Keep protected execution records containing
private references separate from public documentation/inspection projections.
Compaction retains verifiable terminal summaries and all still-required
recovery evidence; an unresolved intent is never compacted away.

An activation command succeeds only when its declared target is reached.
Explicit preparation can succeed with recorded deployment obligations because
its target is preparation, while activation cannot report success with those
obligations unresolved. Queries may successfully describe failed state without
converting that state into a successful activation. Persist actual outcomes
before reporting command completion.
