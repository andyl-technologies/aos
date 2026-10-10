# Install package assessment

Package assessment uses the same engine, provider parsers and canonical result
contracts as local `aos maintain` execution. Hub controllers assess authenticated
published package metadata from the Hub database. Package declarations select
supported source profiles and explicit security identities. Operator configuration
selects credentials, quota domains, evidence storage and physical placement.

This implementation is a draft. Assessment IAM grants are awaiting policy review;
installing a controller does not grant authenticated callers assessment permissions.
Packages without explicit authenticated scan declarations remain unassessed.
Missing source mappings and incomplete source responses remain coverage gaps.

Status responses also expose scoped `sourceStatus` entries from the current
installed route catalog. CLI and web views show whether another source reservation
is eligible, delayed by a quota window, spacing, cooldown or outage circuit, or
lacks live route authority. These reads do not consume quota, reset windows,
contact providers or read secret material. They omit account identifiers,
credential references and shared quota consumption. An installation that does
not supply source status leaves that projection unreported.

Availability describes reservation eligibility at the response's explicit time.
Atomic reservation checks still decide each physical call. Package evidence
coverage and findings retain their own freshness and completeness rules.

## Publication availability

`aos hub maintain publication --registry REGISTRY` reads the newest authenticated
publication without acquiring source evidence or activating an inventory. It
reports missing publications, incomplete or invalid projections, catalogs
without declarations, and declared inventories awaiting activation. The registry
console displays the same states alongside package checks.

Outputs without scan metadata retain their exact published package name, version,
platform and artifact coordinate. They remain unassessed; package names do not
become inferred security identities. A catalog must describe every primary output
in its complete artifact snapshot, with no duplicate or omitted coordinates.

`--limit 1..100` bounds complete output records. Continue with the returned
`--after-output`, `--publication-digest` and `--resource-scope`. A changed
publication or incarnation rejects continuation so pages cannot mix releases.
Availability of scan declarations does not assert that checks have run or that
any package is unaffected. Current assessment status waits for an active inventory.

## Cached CVE and advisory lookup

`aos hub maintain advisory CVE-2026-12345 --registry REGISTRY` reads admitted
normalized advisory revisions. `cve` is an alias for `advisory`; exact source
identifiers such as OSV IDs also work. Reads retain source severity, equivalent
aliases, version ranges, upstream fix claims and withdrawal history. Related
or upstream IDs do not create equivalence. A cache miss never contacts a
provider and does not establish that a package is unaffected.

Add `--assessment-digest DIGEST` to select that successfully admitted assessment's
immutable advisory snapshot. This selection also returns links to its original
raw findings, with the assessment's input, policy and evaluation time. Use
`--subject-ref SUBJECT` to select one subject within that assessment. The lookup
does not assert that a historical result remains current or fresh. The registry
console offers the same explicit cached lookup and historical selection.

`--limit 1..10` bounds revisions; use the returned `--after-record` and
`--resource-scope` with the same advisory/assessment selection to continue.
Responses are limited to 256 KiB and one hundred finding links per revision;
reduce the revision limit or select a subject if a response exceeds those bounds.
The shared runtime projection reads the exact frozen closure in every Hub mode,
including revisions that have no live provider index.

For local inspection, export a bundle with `aos maintain scan --profile
vulnerabilities --evidence-output FILE` and use `aos maintain advisory
CVE-2026-12345 --evidence-input FILE` (`cve` also works). Local and hosted
lookup use the same historical projection, canonical page and human renderer.
Local output identifies a bundle reproduction and a bundle-specific scope;
reproducing supplied evidence establishes semantic agreement, not independent
source authority. It does not import that evidence into Hub or change package
status. The local command rejects tampered bundles and performs no source HTTP.

Export an exact retained local result or reproduce a supplied bundle:

```sh
aos maintain evidence export ASSESSMENT_DIGEST --output bundle.json
aos maintain evidence import bundle.json --json
```

Export creates a new private file and verifies the committed receipt, frozen
input, closure and result. New scans retain references for historical exports;
older journals can export their retained global and profile heads. Unavailable
or inconsistent custody fails explicitly. Exports use the reference profile, so
raw provider bytes remain external references.

Import validates the complete bundle and reproduces its assessment without
contacting providers. Its `aos.assessment-bundle-reproduction/v1` receipt binds
the bundle manifest, inventory, input, result, engine and local state namespace.
The receipt reports `reproduced` and `not-established` authority: it does not
establish provider or publisher trust, authorize a release, or advance local
assessment heads. Equivalent reimports return the original receipt. The private
import index retains at most 64 distinct manifests and rejects further admission
explicitly; malformed, oversized, nonregular or altered evidence is rejected.
The existing `aos maintain evidence RUN_ID` still creates an upgrade-run dossier.

A fresh, actionable source assessment can export a typed update recommendation
alongside its evidence bundle:

```sh
aos maintain scan --profile updates --freshness cached \
  --evidence-output bundle.json \
  --update-intent-subject SUBJECT --update-intent-output intent.json
aos maintain plan UNIT --assessment-intent intent.json \
  --assessment-evidence bundle.json
```

Use the exact source subject from assessment status and its declared update unit.
Both exports create new private files. The `aos.assessment-update-intent/v1`
document contains the complete component vector, including unchanged components,
exact source/definition/input/result/policy/history commitments and the oldest
source's exclusive freshness deadline. Provisional, stabilizing, unknown,
manual or frozen selections cannot produce an actionable recommendation.

The local planner reproduces the evidence and verifies the intent, then checks
its current clean checkout, source content, controller and package policy. Each
changed candidate must independently occur in locally retained discovery and
remain eligible under local policy. Imported evidence does not replace local
discovery. Planning retains its exact selected discovery object while leaving
the discovery head and repository source untouched. Changed source, expired
evidence, a partial vector or a different candidate requires renewed planning
inputs. The intent carries no commands, paths, download URLs or write authority.

Local shared-profile scans retain the same frozen request and scan receipt
contracts used by the Hub. Inspect and manage them in the repository's protected
state namespace:

`--profile all` expands to the explicit sorted set `license-signals`, `updates`,
and `vulnerabilities`. Repeated profiles are deduplicated. Unsupported source
questions and unavailable license evidence remain visible coverage gaps.

Local scans accept `--freshness cached|refresh-stale|refresh|offline`. Cached and
offline scans contact no providers and read no source credentials. Refresh-stale
uses the shared policy and acquisition planner to refresh only missing, incomplete
or expired exact questions. Refresh revalidates selected questions within existing
budgets. The existing `--offline` flag selects offline intent; local scans otherwise
keep their refresh default. The chosen intent is retained in the scan request.

Hub scans support the same explicit options:

```text
aos hub maintain scan --registry REGISTRY --profile all \
    --package publisher/package --freshness refresh-stale --idempotency-key KEY
```

The client resolves exact coordinates against the admitted inventory before
requesting work. All versions, platforms and outputs of a selected coordinate
are pinned. Omitting `--package` selects the complete admitted inventory. Unknown
or unassessable coordinates, changed inventory/policy/resource revisions and
incomplete pagination fail before scan admission. Interactive enumeration is
limited to 4,096 subjects and 64 pages; larger selections use the existing exact
`--request FILE` submission contract. That file and interactive selectors are
mutually exclusive. Hub selectors default to refresh-stale and require an explicit
idempotency key. Returned receipts must match the exact submitted selection.

```text
aos maintain scans list --limit 20
aos maintain scans inspect SCAN_ID
aos maintain scans cancel SCAN_ID --expected-revision REVISION
aos maintain scans wait SCAN_ID --timeout 300
aos maintain scans recover --limit 100
aos maintain status --profiles all --limit 100
```

## Report policy for automation

Shared local scans and waited Hub scans accept the same explicit report policy:

```text
aos maintain scan --profile all --fail-on vulnerabilities,updates,coverage
aos hub maintain scan --registry REGISTRY --profile all \
    --package publisher/package --idempotency-key KEY --wait \
    --fail-on vulnerabilities,updates,coverage
```

The command prints one valid report and returns `20` when any selected condition
matches. Otherwise it returns `0`. Execution, authentication, custody and input
errors keep their existing error codes. Report-policy failure does not turn a
committed successful or partial scan into failed work, cancel it, or retry it.
Without `--fail-on`, existing command exit behavior remains unchanged.

`updates` matches an actionable maintained-stream update. Stabilizing, manual or
frozen candidates alone do not match. `vulnerabilities` matches any raw applicable,
potentially applicable or unresolved vulnerability claim, independently of
reviewed dispositions. `coverage` matches incomplete or unknown requested
coverage. Update and vulnerability conditions require their corresponding
evaluated profiles; local scan policy requires explicit `--profile`, and Hub
scan policy requires `--wait`. Conditions are sorted and deduplicated in output.

JSON adds `reportPolicy`, with the exact assessment digest, normalized policy,
matched conditions and failure decision. Human output ends with the policy
decision. The shared result and policy contracts reproduce the same decision
from the same immutable assessment in every execution mode.

Inspect an exact historical result with the same policy:

```text
aos maintain report --assessment-digest DIGEST --fail-on updates,coverage
aos hub maintain get --registry REGISTRY DIGEST --fail-on updates,coverage
```

Historical policy evaluates the frozen result at its original evaluation time.
It does not assert current freshness, update package status, acquire sources or
grant release authority. Use current status or request a new scan for current
freshness. Repeating a local idempotent scan with report policy reads its retained
result and preserves the original receipt, provider budget and assessment heads.
An operation without a committed report fails explicitly instead of reporting
that selected conditions passed. Legacy cached-discovery `maintain report`
filters continue to work without `--assessment-digest`.

Hub scan listings use retained pages:

```text
aos hub maintain scans list --registry REGISTRY --limit 20
aos hub maintain scans list --registry REGISTRY --limit 20 --after-scan NEXT_SCAN
```

Copy `nextScan` from the preceding response and keep the same page limit. Hub
pages retain the original scan states and observation time for fifteen minutes,
including when scans finish, new scans arrive or the service restarts. A changed
resource, invalid page handle or expired snapshot requires starting a new list.
Each continuation still requires current read access. The Hub retains at most
sixteen active captures per resource, each containing at most ten thousand scan
summaries; an exhausted bound fails explicitly. These limits do not truncate a
list silently. Listing acquires no provider evidence.

The console holds paginated scan summaries at their displayed observation time
until you refresh or change the page. Inspecting a scan continues to read its
current receipt. Submitting, cancelling or retrying a scan starts a new listing.

Use `scan --profile … --idempotency-key KEY` to name one exact request. Repeating
that key returns its retained receipt; changing its pinned selection, inventory,
policy or freshness intent conflicts. JSON scan output includes the committed
receipt under `execution.scan`, while `data` remains the canonical assessment.
List, inspect and wait do not acquire sources or recover operations. Cancellation
requires the current revision and prevents another physical reservation or
assessment-head commit. Already admitted work keeps its quota and evidence.

Receipt versions and assessment closures are immutable files selected by one
atomic journal index. A new inventory revision or desired generation cannot
resurrect an older result. Recovery checks released per-operation process leases
before finalizing interrupted work; active queued and running processes remain
eligible to finish. A new scan also performs bounded recovery. The namespace
retains at most 4,096 operations and returns an explicit capacity error on further
admission. A wait timeout or interrupt leaves the operation available to inspect.

Journal v2 maintains independent desired generations and committed heads for
each subject/profile. Disjoint update and vulnerability scans remain eligible
in either completion order. An overlapping newer request supersedes older work;
inventory or policy replacement invalidates every prior current slot. A failed,
cancelled refresh retains its prior evidence; incomplete profile evidence never
becomes fresh merely because its operation finished.

`aos maintain status --profiles all` reads the same inner status document and
uses the same human renderer as `aos hub maintain status`. It includes admitted
subjects even when a profile is unassessed, retains prior committed evidence
while newer work is pending, and computes freshness independently. Reads make
no provider calls and do not recover operations. Continuations require the exact
`--inventory-digest` and `--policy-digest` returned with `--after-subject`.
Immutable inventory, policy, input, closure and result custody is verified;
missing or inconsistent evidence fails the read instead of appearing clean.

Cached local scans merge evidence from the independently committed profile heads
for the same inventory and policy. An update scan finishing after a vulnerability
scan does not discard the latter's source snapshot. The shared merger keeps
original coverage and expiry, selects the latest admitted source validation, and
retains the earliest candidate observation. Cache reads make no provider calls,
do not publish journal changes, and verify every referenced immutable closure
within a 64 MiB read allowance. Historical inventory evidence contributes only
first-observation history when its inventory or policy differs. Current input
dispositions remain authoritative; historical cache statements do not replace
them.

The first new admission upgrades a v1 journal atomically. It preserves the head
v1 actually published and the latest desired requests, and seals active legacy
operations as superseded (or cancelled when already cancelling), preserving
v1's global supersession rule. It does not resurrect disjoint historical work
or treat every old terminal result as a previously committed profile head.
Shared status requires a new admission to pin inventory/policy custody when
reading a legacy journal. Existing immutable receipts remain inspectable.

Conditional refreshes use the exact admitted operation, partition, adapter and
retained response validators. A `304 Not Modified` preserves original response
bytes and retrieval time while admitting a new validation record. Frozen update
inputs retain all page records; the earliest page validation and exclusive source
expiry constrain freshness. Candidate first-observation history is unchanged.
An incomplete chain cannot renew a complete/current conclusion. Legacy bindings
without page records continue to use their original retrieval time.

Native and local execution retain raw evidence privately. Worker execution reads
its own partition-scoped R2 evidence; Hybrid sends compact observation references
and validators to the Worker. Missing or changed bytes fail validation, and a
settled invocation replay makes no further provider call. Conditional requests
consume the same physical request allowance as other source requests. POST OSV
batch queries and multi-record retrievals do not use conditional response caches.
Local conditional metadata requires an exact settled source receipt, retains
at most 4,096 operation entries per partition, and cannot roll back when an old
receipt is replayed. A full index returns a capacity error.

`aos hub maintain alerts --registry REGISTRY` reads complete alert episodes,
including resolved and retired history. Continue with the returned opaque
`--after-issue` token, the same `--limit`, and `--resource-scope`. All pages retain
their original observation time and revisions across acknowledgement, subsequent
scans and database restart. Refresh from the first page to see later changes.
Each resource admits sixteen active alert captures, bounded to 128 complete
records and eight MiB per capture. Captures expire after fifteen minutes;
oversized listings return an explicit capacity error. Every continuation checks
current read access. A historical page confers no acknowledgement authority.

The console preserves paginated alert revisions while continuing to replay new
events. Refreshing alerts or acknowledging an episode starts a new listing.
The displayed observation time identifies the captured alert state.

## Native controller

Supply an owner-private JSON file with `aos-hub serve
--assessment-config-file /etc/aos-hub/assessment.json`. The deployment ID must
match the active Hub installation. Registry partitions are exact, non-reusable
registry scope keys obtained from the Hub; display names cannot substitute for them.

```json
{
  "schema": "aos.assessment-installation/v1",
  "executor": {
    "kind": "native",
    "evidenceRoot": "/var/lib/aos-hub/assessment-evidence"
  },
  "routes": {
    "schema": "aos.assessment-source-routes/v1",
    "deploymentId": "hub-installation-1",
    "coordinatorId": "assessment-coordinator",
    "executorId": "assessment-native",
    "routes": [{
      "partition": "REPLACE_WITH_EXACT_REGISTRY_SCOPE_KEY",
      "provider": "github-tags",
      "budgetKey": "github-public",
      "expiresAt": "2027-01-01T00:00:00Z",
      "limits": {
        "responseBytes": 8388608,
        "sourceBytes": 67108864,
        "resultBytes": 262144,
        "normalizedEntries": 128,
        "requests": 1,
        "concurrency": 1,
        "connectSeconds": 10,
        "requestSeconds": 45
      }
    }]
  },
  "budgets": [{
    "key": "github-public",
    "windowSeconds": 3600,
    "allowance": 100,
    "minIntervalSeconds": 0
  }],
  "credentials": {
    "schema": "aos.assessment-source-credentials/v1",
    "grants": []
  },
  "policy": {
    "schema": "aos.assessment-policy/v1",
    "upstreamMaxAgeSeconds": 86400,
    "advisoryMaxAgeSeconds": 86400,
    "requiredAdvisorySources": [],
    "requireDependencyCoverage": true
  },
  "secretVersions": {},
  "pollSeconds": 5,
  "coordinatorConcurrency": 2,
  "sourceTtlSeconds": 3600
}
```

Scan admission and execution verify the newest authenticated release catalog,
its complete artifact snapshot and the exact declared inventory. A newly
published release without a complete catalog, or a catalog without scan
declarations, cannot authorize work against the previous inventory. Current
status refuses that superseded publication context. Exact retained assessments
remain available for historical inspection. Reintroducing an identical artifact
inventory preserves its first admission and increments the active inventory
revision; old scan leases cannot become current again.

Routes and quota domains must be sorted and unique. Every routed quota domain
must have exactly one installed budget. Share a provider/account budget across
its routes so fan-out cannot multiply its allowance. Restarting a controller
preserves consumption; uncertain physical outcomes are never refunded.

Settled transport uncertainty, HTTP 429 and upstream 5xx responses persist
backoff in that same shared budget. Backoff starts at twenty seconds with
bounded jitter, grows exponentially and stops at one hour; five recorded
outages open the persisted circuit. Bad questions (including HTTP 400/404) and
ordinary pagination or enumeration limits do not open that circuit. Exact
receipt replay adds no failure, restarting preserves cooldowns, and an
in-flight success cannot shorten a concurrent cooldown. Settlement holds
current job and IAM guards through the budget and attempt transaction.
Provider health remains operational state, separate from vulnerability
applicability and evidence freshness.

Native and Worker executors share source throttling normalization. HTTP
`Retry-After` accepts seconds or an HTTP-date. GitHub HTTP 403 responses count
as throttling only with an explicit retry hint or an exhausted primary quota;
ordinary permission denials do not open a source circuit. An exhausted GitHub
quota preserves the later of the retry hint and `x-ratelimit-reset`. HTTP 429
without a usable hint waits at least sixty seconds. Source-directed delays
are capped at one day and never shorten existing cooldowns. A retryable
response stops further source calls in that physical batch. Its exact
observation and cooldown commit together; replay cannot extend the deadline. Local shared-profile
scans use the same outage classification, exponential delays and retry-header
parser. Their protected host-wide budget atomically retains each consumed
reservation and exact settlement receipt. GitHub release and tag scans share
one allowance; shared and legacy Repology calls share the existing quota and
respect assessment cooldowns. Day rollover resets allowance without erasing
cooldowns. Expired unfinished attempts become uncertain once, and replay
cannot execute a second call, refund quota or erase a concurrent cooldown.

Authenticated source routes refer to immutable credential grants. Grants constrain
provider, partition, source scope, secret binding and expiry. Native
`secretVersions` maps each selected binding to an immutable installed secret
version. Neither package metadata nor a scan request can provide credential bytes.
The grant must cover the complete issued physical invocation deadline.

## Worker and Hybrid placement

The deployment commands accept `--assessment-profile-file` containing the closed
`aos.assessment-edge-profile/v1` contract. The physical profile includes:

```json
{
  "schema": "aos.assessment-edge-profile/v1",
  "deploymentId": "hub-installation-1",
  "coordinatorId": "assessment-coordinator",
  "executorId": "assessment-worker",
  "evidenceBucket": "hub-assessment-evidence",
  "sourceTtlSeconds": 3600,
  "credentials": {
    "schema": "aos.assessment-source-credentials/v1",
    "grants": []
  }
}
```

The evidence bucket must differ from the deployment's registry surface bucket.
The generated profile installs `ASSESSMENT_EVIDENCE` and the per-reservation
`ASSESSMENT_PROVIDER_TASKS` Durable Object. Raw provider bodies remain in R2.
SQL stores compact normalized evidence, authority, quota and operation state.

Supply the dedicated work key through `--assessment-work-key-file`. Its material
must be at least 32 bytes and separate from other control keys. Initial installation
requires this key; updates preserve it when omitted. Hybrid's Native controller
must use the matching key, deployment ID and service identities. Select its
`executor` as `kind: "worker"`, with the exact paired HTTPS `origin` and absolute
private `workKeyFile`; leave Native `secretVersions` empty. Hybrid never substitutes
direct Native HTTP when the paired Worker is unavailable.

For authenticated sources, `--assessment-source-secrets-file` reads an
owner-private JSON map from selected `ASSESSMENT_` binding names to absolute
owner-private secret files. Secrets travel to Worker secret delivery on stdin
and are excluded from generated configuration. Omitted existing bindings are
preserved. Credentials outside the reviewed profile are refused.

Worker-only deployments additionally include a `worker` member in the edge
profile. Its `aos.assessment-worker-installation/v1` contract contains `routes`,
`budgets`, `credentials` and `policy` with the same shapes as the Native example.
Pairing and credential declarations must exactly match the physical profile.
This installs the shared logical controller and a separate one-minute assessment
tick. The existing fifteen-minute general maintenance tick remains independent.
Hybrid edge profiles reject this member because Native owns coordination and SQL.

## Reviewed recurring scans

Schedule listings retain the original public review revisions, due times and
observation time for fifteen minutes. Continue with `nextSchedule` as
`--after-schedule`, the same `--limit 1..10`, and the returned `--resource-scope`.
Pages preserve those original values across replacement, due-time advancement
and database restart. Refresh from the first page for current reviews; exact
`--schedule-id` detail reads current state.

Each resource admits sixteen active captures, with at most sixty-four complete
public reviews and eight MiB per capture. Oversized review sets fail explicitly;
they do not return partial apparently complete listings. Private authenticated
review provenance is excluded. Every continuation requires current read access,
and retained expired or disabled reviews confer no execution or write authority.
The web view displays the captured observation time, holds paginated reviews
until refresh, and starts a new listing when refreshed. Single-page listings
continue to poll for current state.

The remote CLI exposes `aos hub maintain schedules` and
`aos hub maintain schedule --request FILE --idempotency-key KEY`. The latter
retains an immutable plan and prints its exact effects, expiry and confirmation
hash. After reviewing it, use `aos hub maintain apply-schedule --plan-id ID
--confirmation-hash HASH --idempotency-key KEY`. The web console provides the
same separate plan and confirmation steps; a pending review freezes its form.
A schedule pins an exact registry scope, explicit nonempty package selectors,
profiles, freshness, limits, cadence and review expiry. Creation and replacement
use optimistic revisions. Disabling or replacing a review fences already queued
work. Each physical effect rechecks the execution principal, current scan
permission, credential state, registry incarnation and review revision.
Session-backed schedules additionally recheck the original schedule-management
permission.

The original authenticated credential expiry caps the schedule review. Scheduling
does not silently turn a short-lived credential into permanent execution authority.

To review recurring execution independently of that session, put the exact
existing service-account credential UUID in `serviceCredentialId` at the top
level of the schedule write document. This is the credential identity exposed by
token management, not its secret. The account must belong to the registry's
organization and already possess current scan and read access. Applying the
exact plan checks both the reviewer and service account; it creates no token,
changes no role grant, and mints no bearer token. The requested review deadline
must be within thirty days and is capped by the credential's expiry.

The public `serviceAuthority` receipt contains commitments to the service
principal, credential generation and reviewer, plus the finite expiry. Imported
receipts confer no authority. After review, the service account executes the
exact selection independently of the reviewing session. Disabling or replacing
the schedule revokes that revision, including already admitted work; revoking
the service credential or its granting membership fences later effects.
Credential rotation does not silently adopt the replacement generation.
Replacing a service-backed review requires explicitly selecting the existing
or replacement credential again. The web form exposes the same review choice.

Missed slots coalesce into one scan; deterministic jitter spreads subsequent slots.
Manual and recurring requests share the durable scan journal and result contracts.
Acknowledgements remain attention state and cannot suppress vulnerability evidence.

## Reviewed notification subscriptions

`aos hub maintain notification-destination` reads the exact registered webhook
commitment for a registry and review expiry. The webhook must be active and owned
by that registry's organization. `aos hub maintain subscription --request FILE
--idempotency-key KEY` plans an exact creation, replacement or disable. Review
its effects before `aos hub maintain apply-subscription --plan-id ID
--confirmation-hash HASH --idempotency-key KEY`; applying consumes that exact
actor-bound, expiring plan. The configuration, journal event and immutable apply
receipt commit in one transaction. Retries preserve the original authority and
do not duplicate the event. `aos hub maintain subscriptions` reads
its public projection. The web console exposes these same controls. Generic
webhook wildcards do not subscribe to assessment events.

Subscription listings retain their original public review revisions and
observation time for fifteen minutes, including across review replacement and
service restart. Continue with the returned `nextSubscription` as
`--after-subscription`, the same `--limit`, and `--resource-scope` from the page.
Each page requires current read access. Invalid handles, changed selectors or
expired custody require restarting the list. Each resource retains at most
sixteen active subscription captures, with at most sixty-four public reviews and
8 MiB per capture. Reads do not renew review authority or dispatch callbacks;
an old enabled review in a retained page does not authorize current delivery.
The console holds paginated subscription reviews until refresh; applying a
review starts a new listing. Single-page listings continue to poll.

A subscription chooses explicit event kinds, issue families, all attention or
confirmed attention, and immediate delivery or a UTC digest window of 60 through
86,400 seconds. It binds the exact destination revision and digest. The effective
review expiry for a session-backed subscription is capped by the original
authenticated credential expiry. Replaying
an identical write preserves that original authority; replacing or disabling a
review revokes its pending and leased deliveries. A disabled or rotated destination
does not prevent an unchanged subscription from being disabled.

For recurring delivery, explicitly select an existing service-account credential
UUID in the subscription write's `serviceCredentialId`. The applying reviewer
requires current subscription-management and read permission; the selected
service account requires current assessment read permission in the registry's
organization. The review expires within thirty days and no later than the service
credential's expiry. Delivery can continue after the reviewing session expires or
is revoked. Each attempt and receipt settlement checks the exact service
credential generation, membership, organization, destination and enabled review
revision. Revoking that credential or replacing/disabling the review fences
outstanding work without refunding consumed delivery quota. The public
`serviceAuthority` receipt contains commitments, never credential secrets or
authentication authority. Replacing the review requires selecting the service
credential again; neither CLI nor console silently adopts rotated credentials.

The complete subscription configuration also supports `packageCoordinates`,
`severity`, and `suppressions`. An absent or empty coordinate list includes the
resource; a nonempty list selects exact publisher-scoped coordinates, including
all versions and outputs of each selected package. At most 256 sorted, unique
coordinates are accepted. Selection uses facts retained with the committed
alert revision, never a later inventory or assessment head. Operational events
without package context do not match a package filter.

`severity` selects vulnerability attention only. Its `minimum` is `none`, `low`,
`medium`, `high`, or `critical`, and its required `includeUnknown` boolean makes
unknown-score handling explicit. Any supported source's supplied CVSS v3/v4
base score meeting the threshold selects the event; conflicting source scores
are retained. Bands follow the [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale)
and [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document#Qualitative-Severity-Rating-Scale).
Missing scores, vector-only entries, unsupported schemes and malformed decimal
scores remain unknown. This filter does not compute vectors or assert risk.
Historical alerts without selection context match only an explicitly included
unknown severity, and cannot match a package selector.

`suppressions` contains at most 128 sorted entries, each with an exact `issueKey`
and exclusive UTC `until` deadline within the configuration's review expiry.
Each issue may appear once. A silence applies to this subscription's recipient
and to events committed before its deadline. It does not change findings,
acknowledgements, alert episodes, or release decisions. Expiration selects future
events; it does not replay previously silenced events. These selectors and
silences bind the same reviewed configuration digest as the destination and
delivery frequency. The web console supports editing them, and the CLI accepts
them in the complete subscription request document.

Native controller configuration accepts an optional `notifications` member:

```json
{
  "installation": {
    "schema": "aos.assessment-notification-installation/v1",
    "deploymentId": "hub-installation-1",
    "coordinatorId": "notification-coordinator",
    "executorId": "notification-native",
    "destinations": [{
      "destination": "REPLACE_WITH_EXACT_REVIEWED_DESTINATION_DOCUMENT",
      "budgetKey": "notification:registered-account"
    }],
    "budgets": [{
      "key": "notification:registered-account",
      "windowSeconds": 3600,
      "allowance": 100,
      "minIntervalSeconds": 1
    }]
  }
}
```

Replace the destination placeholder with the complete destination document returned
by the review command, including the exact review expiry and credential fingerprint.
Sort grants by resource scope and destination reference, and budgets by key. Each
required quota must be declared exactly once. The configured immutable signing-key
version must also be available through the Native secret-version resolver.
Installation grants no subscription permission. Current read and subscription
management authority are rechecked before every effect and receipt admission.

Bodies contain compact committed event facts. They exclude raw advisory text,
source URLs, provider credentials and acknowledgement notes. A digest freezes at
most 50 events; retries preserve those exact bytes and event identities. Every new
attempt consumes one shared notification quota unit, including uncertain attempts.
Callbacks use HTTPS with pinned public DNS, refuse redirects, and do not retain
response bodies. Destination acceptance means a 2xx HTTP response, rather than
confirmation of any downstream action.

Each admitted failed attempt records one `delivery.failed` event for the
physical batch, even when the digest contains several events. The failure
records the original receipt, attempt, subscription revision and retry or
dead-letter state. Readers can inspect it through Hub events and the console;
it contains no callback destination, body or credentials. Failure events
never create callback intents, so an unavailable destination cannot cause a
notification loop. Receipt replay creates no additional failure event.

Failed source attempts also retain `source.failed` events in the same
transaction as their physical settlement. These identify the scan, public
provider, exact operation and plan commitments, and original attempt. An
admitted response includes its receipt commitment; validated throttling or
retry responses include their status and source retry boundary. Execution
uncertainty has no response receipt. The event exposes no private request,
account, credential or raw error text, and replay creates no additional event.
Physical failure events do not create callback intents; grouped source-health
attention is a separate notification decision.

Receivers verify `X-AOS-Signature-Version`, `X-AOS-Signing-Key-Version`,
`X-AOS-Timestamp`, `X-AOS-Delivery-ID` and `X-AOS-Signature` against the exact
canonical body. The shared `CallbackSignature::verify` implementation enforces the
HMAC domain, immutable key version and timestamp window. Receivers also deduplicate
stable delivery and original event identities. Retryable transport outcomes use
bounded backoff; attempts stop after 20 tries or seven days, or when review
revocation prevents another effect.

The edge assessment profile accepts a separate `notifications` installation:

```json
{
  "schema": "aos.assessment-worker-notification-installation/v1",
  "installation": "REPLACE_WITH_SHARED_NOTIFICATION_INSTALLATION",
  "egressGatewayUrl": "https://egress.example/v1/fetch",
  "secretBindings": [{
    "versionReference": "worker://assessment/notification/v1",
    "binding": "ASSESSMENT_NOTIFICATION_CALLBACK_V1"
  }]
}
```

Replace the installation placeholder with the same reviewed grants, budgets and
notification pairing used by the coordinator. Sort key versions, and declare
exactly the versions referenced by those grants. Source and callback bindings and
quota domains are separate. Notification coordinator/executor identities have their
own bindings and can differ from provider identities.

Both Worker and Hybrid deploy commands accept
`--assessment-notification-work-key-file` and
`--assessment-notification-secrets-file`. The latter is an owner-private JSON map
from the selected callback bindings and `HUB_EGRESS_GATEWAY_KEY` to absolute private
files. The work key must match Native's `notifications.workKeyFile` in Hybrid and
must differ from provider, ingress, storage and callback keys. A deployment checks
callback key fingerprints and independently challenges the gateway's notification
contract before delivering secrets or publishing the Worker. Updates require the
gateway key file for that check; other omitted deployed secrets are preserved.

Worker callbacks require the connect-time public-address gateway, which must support
`aos-hardened-egress-assessment-notification-v1`. There is no direct Fetch or Native
callback fallback. Hybrid uses the already configured exact Native origin for fresh
SQL confirmation; Worker-only uses the Hub database object and the same shared SQL
checks. A dispatch grant lasts at most five seconds and requires authority through
the complete physical timeout. Per-attempt durable objects pin work before any
effect. Completed replay returns the exact receipt; interrupted replay cannot
dispatch again. Uncertain retries wait until the original dispatch deadline.

`aos hub maintain deliveries --registry REGISTRY` reads a finite delivery-status
page; `--subscription-id NAME` applies a public subscription filter.
`aos hub maintain delivery --registry REGISTRY --delivery-id ID` reads one retained
event intent. JSON output preserves decimal event/revision counters, state,
attempt count, eligibility, lease expiry, closed failure categories and compact
receipt/body commitments. Continue a list with the returned `--resource-scope`
and opaque `nextDelivery` token as `--after-delivery`, retaining the same
subscription filter and page limit. Pages preserve their original state,
attempt counters, batch linkage and observation time across later attempts,
review replacement and database restart. A resource admits sixteen active
captures, each bounded to 128 complete delivery projections and eight MiB,
with a fifteen-minute custody deadline. Excessive rows, bytes or retained
captures fail explicitly; expired custody requires restarting the list. Initial
projection also bounds immutable batch-body reads to sixteen MiB.

The web notification panel holds paginated delivery status until refresh and
displays its observation time. Inspecting one delivery resumes current status
polling. Every server read requires current access; retained historical status
confers no execution authority.

Status reads neither reconcile nor retry delivery. Digest members share one
physical delivery identity after their first claim. A leased record can have an
uncertain physical outcome, even after its lease expires; a delivered record
means the destination accepted the callback. Projections omit claim tokens,
callback URLs, credentials, callback bodies and private review claims.

Assessment permission policy remains pending, so this draft does not yet provide
authorized end-user delivery through these controls. The callback Worker fleet
suite exercises physical execution and durable replay with paired protocol fixtures;
it does not establish public service IAM admission.
