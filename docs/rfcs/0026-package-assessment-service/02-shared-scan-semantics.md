# 2. Shared scan semantics

## 2.1. Scan request and frozen evaluation input

`aos.scan-request/v1` identifies the requested immutable inventory or a
selector to resolve before admission, profiles, freshness mode, and policy.
Selectors MUST be closed resource selectors, not arbitrary URLs or expressions.
Profiles are `updates`, `vulnerabilities`, and `license-signals`; a request MAY
select several. The existing Repology vulnerability signal remains available
but MUST NOT substitute for the `vulnerabilities` profile's coverage.

Freshness mode is `cached`, `refresh-stale`, `refresh`, or `offline`. `refresh`
bypasses application freshness reuse but MAY use conditional HTTP validation.
It does not bypass budgets. `offline` forbids provider network acquisition and
reports insufficient evidence explicitly; local journal and Hub API effects
remain available. Missing advisory data does not block a separately complete
version assessment, and missing version data does not erase known CVE findings.

The shared evaluator consumes `aos.scan-input/v1`:

| Field | Contract |
| --- | --- |
| `schema` | Exact schema identifier |
| `inventoryDigest` | Identity of the complete normalized inventory |
| `subjectRefs` | Sorted exact selected subjects within that immutable inventory |
| `profiles` | Sorted requested profiles |
| `observationDigests` | Sorted immutable provider observation references |
| `advisorySnapshotDigest` | Optional only when vulnerabilities are not requested |
| `dispositionSetDigest` | Identity of the complete supplied reviewed statement set |
| `policyDigest` | Immutable evaluation-policy identity |
| `historyDigest` | Candidate first-observed and relevant identity history |
| `engineDigest` | Shared semantic engine/profile identity |
| `evaluatedAt` | Explicit whole-second UTC evaluation time |

Every referenced object MUST be available and validated before evaluation.
The subject selector participates in the input digest. Selection MUST NOT
rewrite the retained inventory identity, and evaluation MUST NOT emit results
for unselected subjects. Required runtime dependencies and aggregate members
remain in the selected subject's evaluated closure.
Required missing references produce a typed input error, not an invented empty
set. An advisory snapshot MAY explicitly declare an unavailable source; that
is valid incomplete evidence and produces unknown coverage.

Refresh failure retains admissible prior source records in the frozen input,
with their original validation times and explicit missing-refresh coverage.
It does not replace them with a successful empty source. The evaluator derives
carried findings only from those pinned records; it MUST NOT secretly read a
previous database head. If prior records are no longer available or applicable,
the new assessment reports unknown coverage while the alert reducer separately
preserves unresolved prior issues. No carried record acquires a fresh timestamp
merely because the failed operation was recent.

`engineDigest` identifies portable semantic code/profile and conformance data,
not the different Native/Wasm executable bytes. Execution provenance separately
records actual build identities. Transport credentials, scan IDs, SQL IDs,
durations, absolute paths, and worker locations MUST NOT enter semantic inputs.

## 2.2. Shared stages

The implementation MUST share the following stages across all execution modes:

1. Validate and normalize inventory/scan definitions.
2. Plan bounded provider and inspection work from requests and cache state.
3. Parse responses into immutable observations and completeness evidence.
4. Resolve advisory identities and component applicability.
5. Apply stream, stabilization, lifecycle, and disposition policy.
6. Construct canonical assessment and structured diagnostics.
7. Reduce assessments into presentation-neutral report records.

Effects are supplied through ports. Decisions MUST NOT be duplicated in CLI
handlers, Worker handlers, SQL expressions, or web rendering. SQL indexes MAY
accelerate lookup, but evaluator inputs MUST identify the exact records returned.
Database query planning cannot become an undocumented matching algorithm.

## 2.3. Observation contract

Existing `aos.upstream-observation/v1` records remain valid under their original
contract. The new `aos.provider-observation/v1` additionally supports advisory
and object-derived evidence without pretending to be a local discovery snapshot.

| Field | Contract |
| --- | --- |
| `provider`, `project` | Exact supported adapter and query identity |
| `adapterVersion` | Parser and request-contract revision |
| `requestIdentityDigest` | Sanitized typed request, credential scope excluded from public form |
| `retrievedAt`, `validatedAt`, `expiresAt` | Distinct retrieval, revalidation, and policy-expiry times |
| `responseDigest` | Exact bounded response bytes; not a normalized-payload hash |
| `payloadDigest` | Canonical normalized candidates/advisories/inspection fields |
| `validators` | Optional sanitized ETag/Last-Modified evidence |
| `coverage` | Provider-specific completion proof or explicit incomplete reason |
| `sourceRefs` | Evidence object references with size and origin |

The raw response and canonical projection MUST have separate identities.
Revalidation of unchanged bytes creates a new observation linked to the same
response digest. First-observed time is durable history, not retrieval time.
Cache eviction MUST NOT reset stabilization history.

Coverage has state `complete`, `through-boundary`, `partial`, or `unknown`.
`through-boundary` is sufficient only for a question whose configured adapter
can prove that boundary includes every relevant candidate. It records the
boundary identity and proof class. `partial` identifies a limit, continuation,
or missing scope. `unknown` identifies a failure or unsupported interpretation.

## 2.4. Version decisions

Each component version result preserves current raw identity, latest known
upstream candidate, eligible candidate, rejected candidates with reasons,
observation references, and coverage. `latestKnown` MUST be labeled provisional
when enumeration is incomplete. It MUST NOT establish `current`.

The decision is one of:

| Decision | Meaning |
| --- | --- |
| `update-available` | Complete required evidence establishes an eligible newer component vector |
| `current` | Complete required evidence establishes no eligible newer release |
| `stabilizing` | A newer candidate exists but has not satisfied minimum age |
| `manual` | Package policy requires an explicit selection |
| `frozen` | Package policy intentionally prevents automatic selection |
| `unknown` | Required identity, ordering, coverage, or freshness is insufficient |
| `quarantined` | Conflicting immutable identities or suspicious evidence require review |

The unit result applies existing compatible-vector and cohort semantics.
Independent component maxima MUST NOT be assembled into an incompatible unit.
Prerelease, yanked, stream-major/minor, time-basis, and source-identity rules
apply before selection. An unsupported scheme remains unknown.

"Current" means current under the declared policy. It does not assert that no
newer release exists outside the supported stream. A result SHOULD display
out-of-stream newer releases separately when their evidence is complete.

## 2.5. Vulnerability findings

`aos.vulnerability-finding/v1` binds a component instance and advisory record
revision. It contains:

| Field | Meaning |
| --- | --- |
| `findingKey` | Domain-separated identity of component instance, advisory equivalence identity, and profile |
| `componentInstanceDigest` | Exact assessed build/source component |
| `advisoryIds` | Sorted equivalent IDs, preserving provider-native IDs |
| `advisoryRecordDigests` | Exact source record revisions |
| `match` | Identity, affected-range/commit evidence, comparator profile, and confidence |
| `applicability` | `affected`, `potentially-affected`, or `unknown` |
| `severity` | Source-attributed severity/vector/score entries; missing severity is unknown |
| `fixes` | Source-attributed fixed identities/ranges, possibly empty |
| `exploitSignals` | Optional source-attributed exploitation evidence |
| `dispositionRefs` | Applicable reviewed statements without deleting the raw match |

A version-range match establishes the provider's affected-version claim. It
does not establish live exploitability in an AOS configuration. Heuristic
product matches MUST be `potentially-affected`, never confirmed merely because
version strings intersect. Unsupported range/configuration expressions MUST
produce `unknown` for their relevant scope.

Admitted comparator profiles MUST define their exact version grammar and
ordering; generic lexical comparison is prohibited. OSV `introduced`/`fixed`
ranges are lower-inclusive/upper-exclusive, `last_affected` is upper-inclusive,
and `limit` excludes its bound without claiming a fix. The special introduced
value `0` is interpreted under the OSV profile, not as an ordinary package
version. Explicit affected versions and multiple affected ranges are combined
under the source contract. Unsupported ecosystem/range combinations remain
unknown rather than being coerced into SemVer.

NVD configuration evaluation uses three-valued logic for supported facts:
false dominates an AND, true dominates an OR, and otherwise unknown propagates;
negation preserves unknown. Version bounds and environment terms are evaluated
under their admitted profiles. A vulnerability claim requires both the relevant
vulnerable product association and the applicable configuration; a true
non-vulnerable environment term alone is not an affected finding.

Duplicate advisory aliases MAY share one finding, but `related` and downstream
`upstream` relationships MUST NOT be merged as equivalent aliases. Alias
corrections are snapshot-specific. If equivalence changes finding keys, retain
an explicit merge/split lineage and notification continuity rather than
rewriting historical records or erasing acknowledged state.

Fixes are advisory evidence, not approved AOS updates. The evaluator MUST
check whether a fixed release is within the supported stream and actually
addresses the applicable range. It MUST distinguish `fixed-upstream`,
`eligible-update`, and `published-fix-available`. No fix information means
unknown/unavailable fix evidence, not a claim that a fix cannot exist.

## 2.6. Assessment and coverage

`aos.package-assessment/v1` contains `schema`, `inputDigest`, ordered
`subjectResults`, ordered `diagnostics`, and `coverage`. Its identity is its
domain-separated canonical digest. The full input retains the evaluation
time; the assessment references it rather than inventing a second clock.

Each subject result contains version decisions, findings, and independently
classified coverage for requested profiles. Vulnerability status is
`known-findings` or `no-known-findings`; coverage and freshness are separate
axes. `no-known-findings` with incomplete coverage MUST be rendered as
"no known findings in the checked scope; coverage incomplete", never "clean".

Only requested profiles are evaluated. Committing an updates-only assessment
cannot clear a vulnerability head or its alerts. Aggregate reads retain the
separate profile assessment/input references and effective freshness instead
of fabricating one canonical assessment assembled from different input times.

Coverage records totals for declared, evaluated, unmapped, unsupported, stale,
and failed component/source scopes. A component MAY be mapped to several
sources; aggregate completeness requires every source required by policy.
Optional-source loss is still visible. Counts MUST be derived from enumerated
scope identities and MUST NOT count the same component as several successes.

Diagnostics have stable `code`, `severity`, `subjectRef`, `summary`, optional
bounded `detail`, and optional `remediation`. Raw errors, credential-bearing
URLs, and provider text MUST NOT be persisted as diagnostic detail without
sanitization. Relevant codes include `identity-unmapped`, `coverage-truncated`,
`provider-rate-limited`, `provider-unavailable`, `version-unsupported`,
`snapshot-stale`, `metadata-invalid`, and `input-superseded`.

## 2.7. Execution envelopes and report parity

`aos.scan-result/v1` wraps an assessment reference with operation identity,
execution status, origin, timestamps, and provenance. Those values are not
part of the assessment digest. Human and machine presentation MUST retain
the same assessment semantics even when execution envelopes differ.

The shared report model MUST include unit/component, current and candidate
versions, finding IDs, severity, fix state, coverage, freshness, and next-action
intents. Action intents are typed semantic operations bound to input digests.
Local and remote renderers translate them into their command prefixes. Shell
command strings MUST NOT become protocol authority.

Local discovery snapshot v1 and command-result v1 MUST NOT be silently
reinterpreted. Explicit converters preserve original identities and label
which fields were derived. A converted Repology boolean cannot manufacture
an advisory ID or complete CVE coverage.
