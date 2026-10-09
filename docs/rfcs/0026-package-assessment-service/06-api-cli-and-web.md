# 6. API and user interfaces

## 6.1. One application surface

Hub exposes assessment operations through its generated Connect API and the
shared application service. Native and Worker handlers are transport/runtime
adapters. The Hub CLI and web console call those services; neither implements
provider matching or a parallel assessment store.

Service names below are proposed additions to the versioned Hub API namespace.
Exact generated-language names follow existing repository conventions. Domain
objects carried as canonical JSON MUST pass the same strict parser and digest
validation as local objects. Protobuf numeric coercion or ignored unknown
fields MUST NOT bypass the domain contract.

| Service/method | Request and result |
| --- | --- |
| `AssessmentService.GetStatus` | Resource/profile/policy selector; current head, effective freshness, pending generation, source health |
| `AssessmentService.ListAssessments` | Authorized subject and filters; immutable assessment references and cursor |
| `AssessmentService.GetAssessment` | Assessment digest and resource scope; canonical assessment plus authorized evidence references |
| `AssessmentService.ListFindings` | Scope, applicability, severity and freshness filters; finding instances and coverage |
| `AssessmentService.GetAdvisory` | Provider-native/CVE ID, optional snapshot, authorized resource scope; cached record revisions, aliases, severity, fixes and finding associations |
| `ScanService.RequestScan` | Versioned scan request, resource selector, idempotency key; durable operation |
| `ScanService.GetScan` | Scan ID; frozen request, state, task progress, typed diagnostics and results |
| `ScanService.ListScans` | Scope/state/trigger/time filters; paged operations |
| `ScanService.CancelScan` | Scan ID and expected revision; cancellation acknowledgement |
| `ScanService.RetryScan` | Terminal scan ID, permitted retry scope, idempotency key; new linked operation |
| `ScheduleService.ListSchedules` | Scope and cursor; configured schedules and source budget status |
| `ScheduleService.PutSchedule` | Scoped schedule and expected revision; admitted revision |
| `ScheduleService.DeleteSchedule` | ID and expected revision; tombstone |
| `AlertService.ListAlerts` | Scope, issue/state filters; alerts with evidence and acknowledgement |
| `AlertService.AcknowledgeAlert` | Alert/episode and expected revision; actor-bound acknowledgement |
| `SubscriptionService.PutSubscription` | Authorized selector, event filters, destination/secret references, expected revision |
| `SubscriptionService.ListSubscriptions` / `DeleteSubscription` | Authorized scoped configuration management |
| `EvidenceService.ExportAssessment` | Assessment digest and export profile; scoped short-lived bundle export reference |
| `EvidenceService.ImportAssessment` | Admitted bundle reference, intended scope and idempotency key; validation operation/receipt |
| `AssessmentEventService.Watch` | Authorized scope and replay cursor; committed events and heartbeats |

Dispositions are managed through a reviewed evidence/authorization workflow,
not by editing a finding's displayed status. Chapter 8 defines that workflow.
The initial surface MUST expose a way to submit, review, and revoke dispositions
under existing release/review authorization; its concrete service placement
must be resolved before the release-policy stage ships.

Advisory lookup is a read of admitted evidence, including CVE aliases. It
reports the selected source revision and cannot silently query a provider on
cache miss. An explicit authorized scan/refresh obtains additional evidence.
Private finding associations are permission-filtered independently from a
public advisory's body.

## 6.2. Resource binding and authorization

Selectors use existing organization/project/registry/package/version/platform
resource identities. A registry selector expands inventory through normalized
database relationships. The scanner MUST NOT parse Git paths to decide who
can read or scan a package. Mutable channel names resolve to immutable
membership at admission, and results report that binding.

The minimum permissions are:

| Permission | Authority |
| --- | --- |
| Assessment read | Read the selected package inventory and its permitted derived results |
| Scan request/cancel | Consume scanning quota in the selected scope; cancel only permitted operations |
| Schedule manage | Change cadence and selection within administrator limits |
| Alert acknowledge | Record acknowledgement for the permitted issue/episode |
| Subscription manage | Configure delivery only for events and resources the actor may access |
| Evidence export/import | Read/export admissible evidence, or submit evidence for scoped validation |
| Disposition review | Approve explicit component/advisory/time/release scope under release/security policy |

An identifier or digest is never sufficient read authority. Shared public
observations may be deduplicated physically while private package membership,
credentials, histories, and finding relationships remain scoped. A request
spanning unauthorized resources MUST fail before work admission or return a
documented filtered scope that the requester explicitly selected. It MUST NOT
silently imply all requested resources were scanned.

Streaming events and export downloads recheck current access. Subscription
delivery rechecks resource visibility and destination authorization; revocation
stops future delivery even for queued events. Signed published evidence follows
its publication visibility contract, not a private inventory route.

## 6.3. Request identity, concurrency, and errors

Mutating calls require an idempotency key scoped to actor/tenant, method, and
resource. Reusing a key with a different canonical request is a conflict.
Retained receipts return the original operation; expiry of the idempotency
window is advertised and MUST NOT invalidate an already issued operation ID.

Configuration and acknowledgement mutations require an expected revision.
Stale revisions produce a conflict with the current authorized revision.
Provider failures live in operation diagnostics; they do not become an
unstructured transport failure after successful scan admission.

Scan admission is an observational operation: it pins a closed inventory and
policy selector and records an idempotent request. It MUST NOT update packages,
infrastructure configuration, schedules, credentials, or delivery destinations.
The retained-control method classifier therefore distinguishes this exact
admission method from reviewed configuration plan/apply pairs. Source effects
occur only through separately fenced provider work. Cancellation and retry use
the operation lifecycle classification; retry preserves the original immutable
selection and ceilings and consumes a new allowance. Schedule, subscription,
policy, and disposition configuration remain subject to their applicable
reviewed mutation contracts.

Typed application errors include `invalid-argument`, `unauthenticated`,
`permission-denied`, `not-found`, `conflict`, `resource-exhausted`,
`unsupported-profile`, `unavailable`, and `evidence-unavailable`. Adapters map
these to existing Connect codes. Diagnostics carry retryability and bounded
context without credentials or raw provider payloads. A missing capability
is distinguishable from no updates or no known vulnerabilities.

Read responses include server `asOf`, resource revision, assessment/input
digests, policy and engine identities, effective freshness, and source coverage.
Counts always identify their scope and completeness. An aggregate zero from
only assessed packages MUST NOT hide unassessed inventory.

## 6.4. Pagination and watch

List methods use opaque, signed or server-held cursors bound to the authorized
scope, filters, sort order, snapshot revision, and expiration. Cursor contents
are not client authority. Default page size is 50 and the initial maximum is
200 items; item byte limits apply separately. Pagination follows a stable
snapshot. A cursor whose retained snapshot expired produces a typed restart
response, not an apparently complete truncated list.

Watch events carry tenant-scoped monotonic sequence strings, event IDs,
resource revisions, event type, time, and bounded evidence references. Tenant
sequences need not be gap-free for a filtered reader. Ordering is guaranteed
within the committed tenant event stream, not across tenants or independent
Hub installations. Consumers deduplicate by event ID.

Reconnect accepts the last committed cursor. Replay older than retention
returns `cursor-expired` with an authorized snapshot/restart path. Heartbeats
contain connection time/health and are not durable events. Slow consumers
receive a resume cursor and disconnect at the configured buffer limit. The
server MUST NOT hold a SQL transaction open for the life of a watch stream.

## 6.5. Local and hosted CLI grammar

The existing `aos maintain` grammar and v1 report/update-run semantics remain
supported. New scan functionality uses the same option vocabulary and shared
presentation code. The Hub client adds the corresponding remote group:

```text
aos maintain scan <packages...> [--profile updates|vulnerabilities|all]
    [--freshness cached|refresh-stale|refresh|offline] [--json]
aos maintain status [<packages...>] [--json]
aos maintain scans list [--json]
aos maintain scans inspect <scan-id> [--json]
aos maintain scans cancel <scan-id>
aos maintain evidence export <assessment-digest> --output <path>
aos maintain evidence import <path> [--json]

aos hub maintain scan <resource> [--profile updates|vulnerabilities|all]
    [--freshness cached|refresh-stale|refresh|offline] [--wait] [--json]
aos hub maintain status <resource> [--json]
aos hub maintain scans list <resource> [--json]
aos hub maintain scans inspect <scan-id> [--json]
aos hub maintain scans cancel <scan-id>
aos hub maintain scans retry <scan-id> [--wait] [--json]
aos hub maintain evidence export <assessment-digest> --output <path>
aos hub maintain evidence import <path> --resource <resource> [--wait] [--json]
aos hub maintain schedules list <resource>
aos hub maintain alerts list <resource>
aos hub maintain alerts acknowledge <alert-id> --episode <episode>
aos hub maintain subscriptions list <resource>
```

This is the target grammar, not a claim that those subcommands exist today.
`--profile all` expands to the explicit sorted supported profile set and records
that set in the request; it never means unknown future profiles. Repeated
`--profile` options select a subset, including `license-signals` when supported.
Concrete schedule/subscription create/update flags MUST be generated from
their typed configuration contracts rather than an unvalidated free-form
command string. Existing scan flags are retained with documented aliases where
they select the same semantics. Existing `status` update-run selectors and
`inspect` are not reinterpreted as scan operation IDs; `scans` distinguishes
the new operation lifecycle.

Local `scan` evaluates the current machine's inventory and normally waits to
completion. Hosted `scan` returns admission unless `--wait` is requested.
Both print an execution envelope with the shared assessment. Local operation
IDs identify a local journal, not an unrelated Hub operation. Unresolvable
IDs produce a typed not-found error with the selected execution context.

`offline` prohibits provider network access in both modes and evaluates only
admitted retained evidence. In hosted mode, the CLI still uses the Hub API;
offline describes the scan's source acquisition. `cached` permits no new
source request for the operation but can consume evidence refreshed elsewhere.
Explicit scan inputs freeze that evidence before evaluation. Neither mode
claims freshness merely because its cache was recently opened.

`--json` writes one versioned machine-readable response to stdout. Progress
and diagnostics intended for humans go to stderr; a watch mode uses explicitly
versioned JSON Lines event envelopes. CLI human reports share section order,
status vocabulary, severity formatting, coverage notices, and action intents.
Context-specific operation IDs and commands may differ.

Exit codes distinguish successful command execution from assessment policy.
Ordinary report commands return zero when a valid report was obtained,
including a report with findings. A shared `--fail-on` policy flag provides
automation failure for specified update/vulnerability/coverage conditions.
Its normalized policy and outcome are included in JSON. A transport or local
execution error remains separate. Existing exit-code behavior MUST remain
available through compatibility mode during migration.

## 6.6. Action intents and handoffs

Reports contain typed action intents such as `inspect-assessment`,
`request-refresh`, `export-evidence`, and `plan-package-update`, each bound to
exact subject/input identities. The renderer selects a local or hosted CLI
prefix and validates supported arguments. It MUST NOT execute arbitrary
command strings from provider data or package metadata.

An update intent carries a candidate/component vector and evidence references.
It invokes RFC-0018 planning only after the local checkout binding is validated.
A Hub assessment is useful planning input, not permission to mutate source.
The current hard-coded local `NextAction` validation requires an explicit
versioned converter; replacing text prefixes without changing the semantic
contract is insufficient.

## 6.7. Web console

Package pages show immutable version/platform identity, current update
decision, vulnerability findings, source coverage, last successful observation,
evaluation time, effective freshness, and pending scan state. A release's
publication assessment and its current live assessment are distinct links.

The initial console includes scoped inventory summaries, package detail,
scan history/progress, finding/advisory evidence, alert inbox/acknowledgement,
schedule controls, subscription controls, and evidence export. Permission
checks are server-side as well as reflected in available controls.

Unknown/unmapped/partial/stale states require textual labels alongside visual
signals. A green zero cannot represent an unscanned package. Aggregate views
show assessed and unassessed counts and allow filtering by coverage. Severity
and exploited status are separate fields. Withdrawn advisories retain their
history and explanation.

The console subscribes to committed events and refreshes affected scoped
views. It recovers expired event cursors by taking a new snapshot. Read views
never start scans by mounting or refreshing a browser component. Provider URLs
and descriptions are escaped, links use permitted schemes, and large/raw
payloads are not rendered as executable HTML.
