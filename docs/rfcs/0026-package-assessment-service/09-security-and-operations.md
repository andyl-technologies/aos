# 9. Security and operational considerations

## 9.1. Threat model

Untrusted inputs include package-authored scan declarations, provider responses,
advisory descriptions/ranges, imported bundles, registry objects, browser
requests, delivery destinations, and stale or compromised executor results.
An authenticated tenant can still submit hostile metadata. A legitimate
provider can change content, be unavailable, or publish incorrect advisories.

Trusted boundaries are authenticated package publication, installed provider
profiles, credential custody, coordinator/database authority, explicitly
admitted executor identities, reviewed dispositions, and release approvers.
Their authority is scoped. No one signature or component name bridges all
these boundaries.

The service detects known advisory matches and upstream changes. It does not
prove that arbitrary source code is free of vulnerabilities. Reports MUST
use the coverage-qualified wording in Chapter 2 and MUST NOT advertise
complete security assurance based on an empty provider response.

## 9.2. SSRF and credential protection

Recurring execution MAY use a separately reviewed existing service-account
credential. The reviewer MUST explicitly select the credential generation in
the exact configuration plan. The coordinator MUST verify the reviewer's current
management, scan and read authority and the service account's current scan and
read authority when applying that plan. The service account MUST belong to the
registry's organization. This review MUST NOT mint an access token, modify role
grants, extend the reviewer's authenticated claims, or infer delegation from an
imported public receipt. Reviews MUST expire within thirty days and no later than
the selected credential's own expiry.

The configuration revision is the delegation's replacement and revocation
handle. Every due admission and subsequent effect MUST recheck the existing
credential generation, stable service principal incarnation, current granting
membership, organization and registry incarnation, finite review deadline and
enabled configuration revision. Rotation MUST NOT silently adopt another
credential generation. Session-backed configurations retain their original
credential expiry and current management-permission checks. A service-backed
review survives expiry or revocation of the reviewing session; administrators
revoke the review through configuration replacement/disable or service authority
revocation. Public receipts expose commitments and the finite deadline without
raw credential identities or private claims; they confer no execution authority.

Provider profiles map typed identities to installed HTTPS origins and request
templates. Metadata cannot specify arbitrary request URLs, DNS resolvers,
headers, credentials, or executable adapters. Enterprise/private providers
require an administrator-reviewed profile and explicit network partition.

Egress validates scheme, port, normalized hostname, origin allowlist, and
resolved destination addresses at connection time, including redirects and
DNS rebinding. Loopback, link-local, metadata-service, multicast, and private
address ranges are denied in public profiles. IPv4/IPv6 and mapped-address
forms receive equivalent checks. Private profiles explicitly enumerate their
permitted destinations; they are not a global bypass.

Provider credentials bind profile, tenant/authorization partition, operation,
and permitted project scope. They are resolved after plan validation, kept
out of canonical public inputs, redacted from errors, and never forwarded on
cross-origin redirects. Authentication cache partitions include effective
credential scope/revision without exposing credential bytes. Secret rotation
or revocation invalidates incompatible in-flight work and private cache reuse.

Webhook delivery applies independent destination controls and credentials.
Allowlisting a provider origin does not allow posting private event bodies
to it. Pre-signed evidence handles cannot be recycled as arbitrary provider
targets. Credential references and service plans are not user-visible exports.

## 9.3. Parsing and resource exhaustion

All adapters enforce source-byte limits while streaming, before parsing.
Decompression limits apply to expanded bytes. Structured formats bound depth,
string sizes, members, page items, range events, graph nodes/edges, and derived
records. Over-limit input produces typed incomplete coverage or rejection,
never silent truncation reported as complete.

Version/range matching uses supported bounded algorithms. Untrusted regexes,
embedded scripts, dynamic plugins, and arbitrary evaluation expressions are
excluded from v1. Malformed advisory configurations remain retained evidence
with an unsupported/malformed diagnostic; they cannot become an empty range.
Canonical integer/string validation occurs before digest comparison.

Request-wide quotas protect against many individually valid tasks. Database
fanout, advisory-index scans, evidence exports, import expansion, event buffers,
and notification recipients have separate bounds. Resumable computation does
not erase already consumed allowance. Reports identify which limit prevented
complete coverage and provide a safe narrower continuation where possible.

## 9.4. Authenticity, integrity, and compromised executors

TLS, exact-byte digests, authenticated collectors, immutable source revisions,
and publisher signatures supply distinct kinds of evidence. Where upstream
advisories are unsigned, a collector signature attests what it observed; it
does not cryptographically prove that upstream authored truthful content.
Reports and import receipts preserve that provenance limitation.

Native admits only results bound to current claims, permitted adapter versions,
input/source scope, and verified evidence references. It recomputes normalized
digests and validates completion proofs. A digest without retained content
and authenticated origin is insufficient authority. An optional sampling or
dual-observation policy can detect a misbehaving trusted collector; a protocol
signature alone cannot make a compromised authorized executor truthful.

Quarantining an executor/provider prevents new authority admission and queues
affected reassessment under policy. Historical assessments retain their
original provenance; trust eligibility changes are visible separately. The
service must be able to identify assessments depending on a revoked collector,
credential, parser profile, or disposition authority.

Hybrid storage and provider capabilities remain separate. Inspection of an
authenticated object uses RFC-0023's scoped storage contract. Neither generic
provider work nor an assessment import obtains delete, publication, or bucket
ownership authority. Code follows the repository's existing process/license
boundaries; no external scanner is linked across an incompatible boundary.

## 9.5. Privacy

Component names and provider queries can disclose private dependency choices.
Deployments document which providers receive identities and whether private
advisory mirrors/offline snapshots are required. An OSV query for a private
inventory requires the applicable egress/data-sharing policy; public advisory
availability is not implicit permission to disclose private package membership.

Shared caches are restricted to genuinely public queries/results. Private
credentials, queries, inventories, candidate histories, alerts, and bundles
are partitioned and encrypted under existing platform policy. Logs contain
stable opaque operation/source IDs rather than secrets, raw requests, local
paths, or private source URLs. Metrics avoid high-cardinality private package
labels. Exporters describe and minimize retained personal/local metadata.

Subscriptions cannot widen a viewer's scope. Imported evidence cannot expose
another tenant's existence through a digest lookup. Errors use existing
not-found/permission-denied visibility conventions. Public package pages
cannot link to private provider evidence without a separate authorized route.

## 9.6. Availability and degraded operation

| Failure | Required behavior |
| --- | --- |
| Provider unavailable or quota exhausted | Retain evidence/findings, show source health/freshness, schedule bounded retry |
| Hybrid Native/database unavailable | Workers finish admitted bounded work only; no autonomous logical scans or alert commits |
| Hybrid Workers unavailable | Queue admitted work; no implicit bulk fetch fallback through Native |
| Worker-only invocation deadline | Persist checkpoint/claim and resume without changing frozen inputs |
| Evidence object unavailable | Report unavailable evidence and block dependent verification/gates |
| Notification destination unavailable | Preserve committed alerts; retry/dead-letter delivery independently |
| Clock disagreement | Reject unsafe plan windows; report operational degradation rather than alter assessment times |
| Parser/engine upgrade incompatible | Retain old evidence, expose unsupported result, run explicit migration/reassessment |

Native-only MAY fetch source bytes in its own runtime when its administrator
selects that mode and its limits. This does not authorize Hybrid fallback.
Mode transitions fence old generations/claims and preserve logical state.
Existing RFC-0023 ingress/storage outage behavior remains authoritative for
those routes; scan unavailability MUST NOT accidentally turn scanning into
a prerequisite for every unrelated Hub read.

Provider-work authentication allows configured bounded clock skew, but the
executor still enforces maximum validity duration. Evaluation consumes the
explicit coordinator time, never the worker wall clock. Clock corrections
cannot extend expired dispositions or create negative candidate age; invalid
history/time ordering yields a diagnostic and policy-safe result.

## 9.7. Storage, retention, and recovery

Retention distinguishes raw responses, normalized observations, advisory
snapshots, canonical assessments, import receipts, operation journals,
events, and delivery receipts. Administrators publish default/maximum periods
and the resulting offline-reproduction/replay guarantees. Assessment metadata
MUST NOT claim full reproducibility after required members were intentionally
removed; unavailable evidence is explicit.

Published release decisions, active dispositions, pinned handoffs, and ongoing
review references hold retention pins according to publication/legal policy.
Garbage collection traverses admitted references and physical storage journals,
not only current assessment heads. It cannot remove an object during an
authorized export/import/verification lease. Public mirrors and private
evidence may have different retention/custody classes.

Backup/restore qualification includes SQL plus evidence manifests, signing
key references, current generation fences, budget windows, and outbox receipts.
Reconciliation after a partial restore marks uncertain state instead of
replaying every notification as new. Restoring old database state MUST NOT
allow previously expired work plans to regain authority.

## 9.8. Observability and performance objectives

Telemetry measures admission-to-assessment latency, source checkpoint age,
required-coverage percentage, queued/leased/expired tasks, provider request
and byte budgets, reassessment fanout, evaluation duration, outbox lag,
delivery retry/dead-letter counts, and export/import bytes. Trace correlation
uses scan/task/event IDs and safe digests. Content/credential logs are absent.

Deployment SLOs specify measured percentiles, scope, quota assumptions, and
excluded upstream outages. The specification does not impose an unsupported
global real-time latency promise. The initial qualification target is bounded
work and demonstrated horizontal I/O scaling with Native SQL/evaluation
capacity measured independently.

Hybrid measurement records provider-to-Worker bytes, Worker-to-Native normalized
bytes, RPC count, storage traffic, and coordinator/evaluator CPU. A benchmark
that only measures total runtime cannot establish the required placement.
Increasing Worker count should increase admitted I/O throughput only within
global provider limits. Native graph/policy evaluation scales through its
local data/CPU capacity without distributing semantic authority to workers.
