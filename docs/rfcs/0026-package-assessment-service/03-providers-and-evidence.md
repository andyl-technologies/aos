# 3. Providers and advisory evidence

## 3.1. Adapter contract and initial profiles

An adapter is reviewed AOS code identified by a versioned capability. It
accepts typed project/query configuration and bounded transport responses,
then returns normalized evidence with coverage. It MUST share parsing and
decision-relevant behavior across local and hosted execution.

The initial set preserves GitHub releases, GitHub tags, Go releases, and
Repology from RFC-0018 and adds OSV queries, NVD mapped-product/advisory
ingestion, and CISA KEV enrichment. Additional adapters are admitted by a
versioned profile with fixtures and limits, not package-authored code.

| Provider | Authority in evaluation |
| --- | --- |
| Declared upstream release/tag/feed | Candidate enumeration, subject to package policy |
| OSV | Structured affected-component evidence for supported identities |
| NVD | CVE metadata and mapped product/configuration evidence |
| Reviewed upstream security records | Applicability/fix evidence under a supported format |
| Repology | Non-authoritative cross-repository version, vulnerability, and license signals |
| CISA KEV | Exploitation-priority enrichment of an already identified CVE |

No provider's successful HTTP response establishes comprehensive global
coverage. The configured source set and identity scope define the checked
question. Disagreement is retained with source attribution. The evaluator
MUST NOT average conflicting claims or let one source's absence negate
another source's positive finding.

## 3.2. Upstream release discovery

Adapters enumerate through a completeness boundary sufficient for the
declared stream. They preserve raw IDs, versions, publication time, prerelease
and withdrawal/yank status, source references, and durable first-observed time.
The package's primary adapter selects candidates; advisor signals do not.

GitHub releases/tags MUST use bounded pagination and exact configured tag
projection. `/releases/latest` MUST NOT be used as a greatest-version or
supported-stream decision. An unordered feed needs a profile-specific
completion proof. A cap reached before the proof yields partial coverage.

VCS ordering needs admitted ancestry evidence under the declared lineage.
A commit timestamp alone MUST NOT establish ancestry. Provider publication
times are validated for plausible bounds and source identity. Clock rollback
or a missing required time basis makes stabilization unknown.

## 3.3. OSV profile

The OSV adapter accepts exact ecosystem/package, supported PURL, or upstream
Git identity according to the provider contract [OSV-API]. It MUST NOT send
both a versioned PURL and a duplicate version parameter. A Git tag query and
an immutable commit query remain distinct evidence classes.

Batch responses are mapped to their corresponding input positions. Returned
IDs/modification identities are followed by bounded record retrieval. Per-query
continuations MUST be completed independently; one completed query cannot
hide another query's remaining pages. A successful empty result establishes
only no reported matches for that query, not provider support for every
possible upstream product.

Normalized records retain schema version, native ID, modification/withdrawal
state, affected identities/ranges, source-attributed severity and references.
The admitted OSV normalization profile is initially based on schema 1.9.1.
Future fields MAY be ignored only when the adapter profile establishes they
cannot change applicability; unknown decision-relevant range types yield
unsupported coverage. Aliases, upstream, and related edges stay distinct.

Provider API matching may include normalization or fuzzy behavior. Returned
records MUST be checked against the admitted component identity and matching
profile before promoting an API candidate to a finding. Git matching from an
API is source-attributed evidence; local range evaluation cannot invent an
unavailable commit graph.

## 3.4. NVD and native products

The NVD adapter uses explicit CPE/product mappings, advisory IDs, and bounded
incremental ingestion [NVD-API]. Package-name keyword search MAY assist a
mapping review but MUST NOT automatically establish applicability.

The matching profile MUST interpret the complete relevant configuration,
including version bounds, vulnerable/non-vulnerable terms, and logical
operators. Unsupported environmental constraints produce potentially-affected
or unknown applicability with the original constraint preserved. Flattening a
configuration into a union of product strings is prohibited.

Distribution-specific package revisions and patches MUST NOT be applied to
AOS merely because upstream names match. CPE wildcard or product ambiguity
remains visible. A CNA/upstream correction, rejected record, or changed NVD
configuration creates a new record revision and triggers reassessment.

Ingestion tracks provider-supported modification windows with an overlap and
record deduplication. A polling checkpoint advances only after all admitted
pages are validated and the new snapshot is committed. Missing a provider
window or source withdrawal prevents claiming a complete incremental refresh;
the coordinator schedules a bounded repair/full reconciliation.

## 3.5. Repology profile

Repology uses an explicit project mapping where available. Optional same-name
fallback is labeled heuristic. Its sanitized and original versions, repository
identity, statuses, and exact-current vulnerability boolean are preserved.
There is no invented CVE ID for a boolean signal.

The request budget MUST enforce at most one request per second for the shared
provider domain and a conservative daily maximum of 1,000 requests, subject
to stricter deployment policy. Bulk requests require the identifying user
agent described by [REPOLOGY]. Parallel executors do not multiply the budget.
Budget exhaustion yields a visible advisory-source unknown state.

Only records participating in an explicitly bounded question are required in
the semantic projection, but original response bytes remain referenced.
Repology cannot override supported streams, choose compatible update vectors,
construct trusted source URLs, or authorize source bytes.

## 3.6. Enrichment and severity

KEV enrichment matches exact CVE identifiers and records the catalog revision,
addition date, and source reference. Absence from KEV is not evidence that a
vulnerability is unexploited. Local policies MAY prioritize known exploitation
independently of severity.

CVSS vectors and scores MUST retain their version and source. Decimal scores
are strings in AOS canonical records, not floating-point JSON. Severity
aggregation uses a versioned policy; missing or unparseable severity remains
unknown and is not coerced to low severity. Risk policy MUST expose which
source and rule produced its chosen priority.

## 3.7. Transport, freshness, and cache

Requests enforce TLS validation, approved provider origins, safe redirects,
timeouts, decompressed response limits, and typed retries. Request identity
includes adapter, project/query, provider API revision, and authorization
partition. Public requests MAY share cached responses across subjects.
Private responses MUST remain isolated to their authorized tenant/credential
scope even if the project string matches a public request.

Conditional revalidation MUST account for the exact cached response it
validates. A `304` with missing/corrupt cached bytes is not a successful
observation. Cached bytes are reparsed under the admitted adapter version.
Changes to parser behavior invalidate derived projections, not raw identities.

Each source policy declares maximum observation age and required completeness.
Age is evaluated against explicit time; a future validation time is an error.
An advisory snapshot records per-source freshness, not only a top-level date.
Offline evaluation applies the same rules and never extends cache lifetime.

First-observed identities persist independently from disposable HTTP caches.
A changed raw tag pointing at different immutable content is quarantined where
the adapter promises immutable identities. Imported first-observed history
requires accepted provenance; otherwise stabilization restarts conservatively
without rewriting the imported record.

## 3.8. Immutable advisory snapshots

`aos.advisory-snapshot/v1` is a canonical manifest containing source revisions,
record digests, ingestion coverage, adapter versions, and source evidence.
Records are stored by content identity; the SQL index is a rebuildable lookup
projection of admitted records, not their sole evidence representation.

Provider archives can remain in object storage. A complete snapshot MAY be
represented by ordered, digest-bound manifest shards. It MUST identify every
shard and its coverage; a partial download cannot become the current complete
snapshot. Matching references the pinned record set, never a mutable table
whose contents change during evaluation.

Withdrawal, alias correction, deletion, and new applicability each trigger
affected-component reassessment. Deletion is authoritative only under a
complete provider deletion/withdrawal contract; a disappeared fetch or a `404`
alone cannot resolve an existing finding. Historical snapshots remain
replayable under retention policy.
