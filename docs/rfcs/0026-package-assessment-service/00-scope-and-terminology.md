# 0. Scope and terminology

## 0.1. Requirement language and precedence

Uppercase MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY,
and OPTIONAL express the requirement levels of BCP 14 ([RFC2119] and
[RFC8174]). Lowercase words have their ordinary meaning. References in square
brackets resolve in [Chapter 11](11-decisions-and-references.md).

Requirements apply to a conforming implementation of this specification.
Examples, deployment targets, and alternatives are informative unless a
requirement explicitly incorporates them. An implementation MAY use different
internal tables or crate names while preserving the contracts and invariants.
Unknown or contradictory inputs MUST produce the specified diagnostic or
failure; readers MUST NOT resolve ambiguity by accepting weaker semantics.

Earlier RFCs remain authoritative for their own boundaries. This RFC extends
scan and assessment semantics only. A conflict involving IAM, publication,
release qualification, or Hybrid storage authority MUST be resolved before
the affected operation is implemented or enabled.

## 0.2. Scope

The service provides upstream-version discovery, vulnerability assessment,
CVE/advisory lookup, continuous status, alerting, notifications, reproducible
evidence, and release-policy evaluation for declared package components.
Subjects include package artifacts, retained package versions, release
closures, system images, and OCI images with admitted component inventories.
Source-tree scans are supported by the local inventory adapter.

Scanning means matching declared or verified components to known advisory
evidence. It does not establish exploitability by executing an exploit, prove
the absence of undisclosed vulnerabilities, perform arbitrary source-code
analysis, or establish which packages are deployed on a fleet. Such claims
MUST NOT appear as successful outcomes of this protocol.

The service MUST operate over normalized Hub database inventory. Registry
Git objects MAY supply that inventory through existing authenticated ingestion.
The scanner MUST NOT require a registry checkout, branch layout, file path, or
Git implementation to identify a scan subject. Local planning MAY additionally
require source-repository provenance under RFC-0018.

## 0.3. Terminology

| Term | Definition |
| --- | --- |
| Scan definition | Immutable package-authored declaration of components, identities, adapters, and version policy |
| Inventory revision | Immutable normalized set of subjects and components with a canonical digest |
| Subject | A particular package version/artifact or aggregate whose exposure is evaluated |
| Component | An upstream software identity contained in, linked by, or used to build a subject |
| Update unit | RFC-0018's compatible component vector selected and updated together |
| Provider observation | Immutable normalized result of a bounded upstream or advisory request |
| Advisory snapshot | Immutable manifest of the advisory records and source evidence supplied to evaluation |
| Assessment | Deterministic version decisions, vulnerability matches, coverage, and diagnostics for frozen inputs |
| Scan operation | Durable execution lifecycle producing one or more assessment revisions |
| Finding | A component-specific advisory match, with evidence and applicability confidence |
| Disposition | Reviewed, scoped conclusion about a finding or a risk exception |
| Alert | Durable attention state derived from assessments and alert policy |
| Subscription | Authorized selection of events and notification destinations |
| Executor | Runtime adapter performing admitted provider or object work |
| Coordinator | Owner of logical scheduling, task issuance, evaluation, and commits |
| Coverage | Evidence of what identities, versions, pages, and dependencies were actually checked |
| Freshness | Age/validity of evidence at a specified evaluation time |
| Handoff bundle | Portable inputs, observations, and assessments with verifiable content identities |

"Latest published" denotes the selected AOS-published version under its
catalog/channel policy. "Latest upstream" denotes the greatest known release
under an explicit comparison scope. "Eligible update" additionally satisfies
the package's stream, prerelease, stabilization, and lifecycle policy. These
values MUST NOT be collapsed into one `latestVersion` field.

## 0.4. Invariants

**I1, one evaluator:** Equal inventory, observations, advisory snapshot,
dispositions, policy, first-observed history, engine identity, and evaluation
time MUST produce byte-identical canonical assessments. Deployment mode,
transport, database row IDs, and filesystem paths MUST NOT affect evaluation.

**I2, explicit uncertainty:** No-match, current, complete, and resolved are
positive conclusions requiring their stated evidence. Absence of evidence
MUST NOT establish those conclusions. Known findings MAY coexist with unknown
coverage. There is no aggregate "safe" state.

**I3, immutable evidence:** Published metadata, observations, assessment
payloads, and policy decisions are immutable. Refresh creates new revisions.
Current pointers and freshness projections MAY change without rewriting them.

**I4, bounded effects:** Network, parsing, allocation, pagination, fanout,
database batches, result pages, and delivery attempts have explicit limits.
Hitting a limit before completeness is established MUST preserve uncertainty.

**I5, Hybrid authority:** Native/PostgreSQL owns logical scan and alert state.
Hybrid Workers MUST NOT attach a writable Hub database, admit public control
mutations locally, or independently decide package/promotion status.

**I6, origin and authority:** A content digest proves identity, not who issued
a claim or whether it is true. Authentication, publisher trust, provider
identity, and disposition authority MUST be checked separately.

**I7, identity before name:** An AOS package name or generic PURL alone does
not establish a supported advisory identity. Heuristic candidates MUST remain
distinct from reviewed identity mappings and exact matches.

**I8, no incidental write authorization:** A scan, notification, imported
assessment, or eligible candidate MUST NOT authorize source modification,
publication, merging, or release promotion by itself.

## 0.5. Common encoding and identity

AOS-owned immutable records MUST use the integer-only canonical JSON dialect
implemented by `aos-contract`. Duplicate members, non-ASCII member names,
floating-point numbers, trailing bytes, and out-of-range integers are rejected.
Digest construction MUST use its domain-separated `Sha256Digest::of_canonical`
with the complete schema identifier; raw response digests use `of_bytes`.
Implementations MUST NOT substitute a different JSON canonicalizer.

JSON examples are pretty-printed for readability; signed/exported bytes are
canonical. Wire members use camelCase unless a preserved older schema says
otherwise. Optional absent values are omitted, not `null`. Each schema is
closed: unknown members, enum values, duplicate set entries, invalid ordering,
and incompatible schema versions MUST be rejected. Third-party documents are
parsed under a separate bounded adapter profile, then normalized.

Counters serialized as JSON integers MUST fit the exact I-JSON integer range.
Persistent SQL sequence numbers use nonnegative decimal strings without
leading zeroes, avoiding browser precision loss. SHA-256 identities are
`sha256:` plus 64 lowercase hexadecimal digits. Database and execution IDs
are opaque strings, at most 128 UTF-8 bytes, without control characters.

New contracts use UTC RFC3339 timestamps at whole-second precision, ending in
`Z`. Leap-second values and non-UTC offsets are rejected by this profile.
Existing Unix-time contracts are translated without rounding. Evaluation
time is explicit; adapters MUST NOT call an ambient clock during evaluation.

Set-valued arrays are deduplicated and sorted by their schema-defined identity
using UTF-8 byte order. Ordered provider pages preserve their provider order
and carry explicit boundaries. Component IDs are stable within the declared
update unit; raw upstream versions and commits retain their original spelling.
Provider-specific normalization MUST preserve the original value alongside
its comparison representation.

## 0.6. Conformance classes

A **core evaluator** implements the portable contracts and deterministic
decisions. A **local runner** additionally implements admitted effects and
RFC-0018 presentation. A **Hub service** additionally implements inventory,
durable scans, API, alerts, and policy. A **Hybrid executor** implements the
closed task protocol and its authenticated capabilities.

The mandatory core adapter/profile set is the same across deployment modes.
An optional adapter MAY be absent, but the service MUST advertise that absence
and return `unsupported`, never a different successful algorithm. A deployment
MUST NOT advertise a configured required profile unless its paired executor
can execute it within the negotiated contract.

## 0.7. Existing implementation boundary

`aos-maintain` already owns pure maintenance contracts and version selection.
`aos/src/commands/maintain/discovery.rs` owns provider effects. Its current
observation cache is coupled to a local repository envelope, and its
presentation validates suggested commands as `aos maintain` invocations.
These are extraction/migration constraints, not portable protocol requirements.

The registry manifest rejects unknown fields. Adding scan metadata therefore
requires the reader-first, explicit-format rollout in Chapter 10. The release
SBOM currently carries Nix identities and versions; comprehensive component
matching requires the enrichment specified in Chapter 1.
