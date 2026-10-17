# 7. Alerts and notifications

## 7.1. Three separate objects

A scan operation records execution. An assessment records a deterministic
evaluation of frozen inputs. An alert records the ongoing attention state of
an issue over several assessments. These objects have different identities
and MUST NOT be collapsed into one mutable scan-result row.

An alert key binds tenant, immutable subject/component identity, issue family,
and normalized issue identity. Families initially are `vulnerability`,
`package-update`, `coverage`, and `source-health`. A vulnerability key uses
the advisory lineage described in Chapter 2. An update key identifies a
maintained stream/component group; its candidate can change without creating
an unrelated alert every time. A coverage/source-health key identifies the
affected scope and source/profile.

An alert episode starts when the issue becomes actionable under its pinned
alert policy after a previous definitive resolution. Episode numbers and
transition sequences are decimal strings. Repeated equivalent evaluations
within an episode update permitted evidence references without generating a
new opening event. Alias merges/splits preserve explicit lineage; they MUST
NOT silently discard acknowledgements or count the same issue twice.

## 7.2. State and transitions

Attention states are `open`, `resolved`, and `retired`. Uncertainty and
disposition are separate dimensions. An open issue can be currently
unconfirmed because evidence is stale or incomplete; it is not thereby
resolved. Acknowledgement is actor/time/episode metadata, not applicability.

| New committed evidence | Transition |
| --- | --- |
| Newly actionable known vulnerability or eligible update | Open first/new episode |
| Same issue and materially equivalent evidence | Preserve episode; no opening notification |
| Changed severity, exploitation signal, candidate, or applicability | Record changed evidence and policy-selected change event |
| Fresh, complete relevant evidence establishes no longer affected or updated subject | Resolve with assessment and reason |
| Authoritative withdrawal with no remaining applicable positive claim | Resolve applicable alert with withdrawal evidence; retain history |
| Partial fetch, missing artifact, stale source, identity removal | Retain prior issue; expose uncertainty/coverage issue |
| Approved scoped disposition | Update disposition and effective policy outcome; retain the observed finding |
| Disposition expires or is revoked while issue remains | Remove its effect; emit changed/reopened attention event as policy requires |
| Subject deleted or intentionally removed from monitored scope | Retire with reason; do not claim remediation |

A resolution requires the relevant matching source set, identity, and coverage
to justify absence. Complete coverage for an unrelated source cannot resolve
a prior finding. A new inventory component must have explicit replacement
lineage or a new subject identity; matching a package name alone does not
prove the old artifact was fixed. An update is resolved by an admitted version
or policy outcome, not by someone clicking its alert.

Initial alert policy opens confirmed affected vulnerabilities, actionable
supported-stream updates, and loss of required coverage. It surfaces potential
matches separately, with configurable attention thresholds. Criticality,
reachability/exposure when supported by evidence, KEV status, and freshness
may affect prioritization. Unsupported reachability MUST remain unknown.

## 7.3. Acknowledgement and disposition

Acknowledgement records that an authorized person saw an episode. It does
not change the canonical assessment, mark a CVE fixed, approve release, or
suppress every future episode. Acknowledgements include actor, time, optional
bounded reason, expected revision, and exact episode. A policy MAY notify
again when a material severity/exploitation change invalidates an earlier
attention decision; that rule is explicit and auditable.

Suppression is notification policy scoped to issue, recipient, and duration.
A security disposition is reviewed evidence scoped to component/advisory and
release policy. These are distinct. Suppression MUST NOT change release-gate
results or hide a finding from authorized reports. Dispositions follow Chapter
8 and remain visible with their author, justification, and validity.

## 7.4. Durable events

The initial versioned event vocabulary is:

```text
scan.requested
scan.started
scan.progress
scan.completed
scan.cancelled
assessment.committed
alert.opened
alert.changed
alert.resolved
alert.retired
alert.acknowledged
coverage.changed
schedule.changed
subscription.changed
delivery.failed
```

`scan.completed` carries terminal outcome `succeeded`, `partial`, `failed`,
or `superseded`. Progress events are coalesced and bounded; per-record provider
activity is telemetry, not an unbounded durable stream. Event IDs are unique
within a deployment. The envelope binds schema, tenant sequence, event ID,
type, committed resource revision, subject scope, `occurredAt`, and typed
payload/reference digests. Consumers MUST tolerate documented additive event
types at the transport envelope level while rejecting unknown closed domain
objects they are asked to evaluate.

Assessment/alert events and notification intents commit in the transaction
specified in Chapter 5. A separate outbox dispatcher performs delivery.
Delivery status cannot roll back an assessment. Unique constraints bind an
outbox intent to event/subscription revision/delivery class. Duplicate scan
results or transaction retries cannot create duplicate logical notifications.

## 7.5. Subscriptions and hooks

Subscriptions select authorized resources, event families, thresholds,
delivery frequency, and a registered destination. Immediate and digest
delivery are supported contracts; deployment profiles MAY expose only the
delivery adapters they implement. The initial interoperable adapter is the
existing authenticated Hub webhook mechanism. The web alert inbox requires
no external destination. Email/chat adapters are optional capabilities with
the same outbox and visibility semantics.

A scan hook is an authenticated event subscription with scoped event payloads.
It grants no additional scan, source-write, promotion, or credential authority.
Consumers request subsequent actions using their own authorized API identity.
Events are facts about committed state, not commands to execute uploaded code.
Callbacks MUST NOT synchronously block assessment commits.

Destination registration applies administrative allowlists and SSRF controls,
verifies permitted ownership, and stores secret references rather than raw
secrets in subscription JSON. Subscription changes create a new revision.
Queued work binds that revision and is cancelled or reauthorized according
to the explicit update policy. Destinations cannot be changed by provider data.

## 7.6. Delivery protocol

Webhook delivery uses the existing Hub signing/retry infrastructure where its
contract satisfies this RFC. The signed bytes bind an event/delivery ID,
timestamp, signature version, and exact bounded body. Secrets are versioned;
rotation includes a bounded verification overlap. Headers identify algorithm
and key version without exposing secret material. A receiver deduplicates by
event ID and, for digests, delivery ID plus member event IDs.

Transport delivery is at least once. An HTTP success means the configured
destination accepted the request, not that its downstream business action
completed. Crashes between acceptance and receipt storage can cause a retry.
The service MUST NOT promise exactly-once effects at third-party endpoints.

Delivery uses exponential backoff with jitter, source/destination budgets,
attempt and age limits, and a dead-letter state. Retryable network/5xx/429
outcomes differ from permanent destination/configuration errors. `Retry-After`
is bounded by the delivery policy. Redirects cannot move credentials or
signed private bodies to an unapproved origin. A nonretryable failure is
visible to the subscription owner without recursively notifying the same
failed destination indefinitely.

Hybrid Native allocates outbox claims and commits receipts. Workers perform
bounded delivery to admitted destinations. Provider-work credentials are not
notification credentials; delivery uses a distinct operation/authentication
domain. Worker-only and Native-only use the same dispatcher and receipt
logic through their respective runtime ports. Stale delivery claims cannot
mark an unrelated event delivered.

Digest delivery pins a finite ordered member set and content digest. Retrying
the same digest cannot pick up newer events and change its signed body.
Member events may be compacted only after their receipt/retention policy is
satisfied. Unsubscribe/revocation stops pending private delivery; it does
not recall an already accepted external message.

## 7.7. Noise and information disclosure

Notifications include resource identity, issue/episode, decision, coverage,
assessment digest, and authorized detail links. Private source URLs, credentials,
local checkout paths, and unrestricted raw advisory bodies are absent. A
public advisory is not evidence that a private package's existence is public.

Repeated failures are grouped by source/scope and policy window. A source
outage can create one source-health alert with affected counts rather than
one notification per package. Fanout remains bounded and fair. Rate limiting
MUST preserve durable alert state and report delayed delivery; it cannot
silently discard a critical alert as a successful notification.
