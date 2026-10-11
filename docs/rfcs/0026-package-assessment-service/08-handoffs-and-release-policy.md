# 8. Handoffs and release policy

## 8.1. Portable evidence bundle

`aos.assessment-bundle/v1` transports sufficient frozen inputs for an authorized
consumer to reproduce an assessment. Its manifest binds:

| Field | Contents |
| --- | --- |
| `schema` | Exact bundle identifier |
| `inventoryDigest` | Portable inventory and scan-definition references |
| `scanInputDigest` | Complete frozen evaluation contract |
| `assessmentDigest` | Canonical claimed result |
| `engineDigest` | Required semantic engine profile |
| `objects` | Sorted content-addressed members with schema/type, digest and exact byte length |
| `externalReferences` | Explicit authorized retrievable members omitted from this export |
| `provenance` | Publisher/collector statements and source evidence references |
| `executionEnvelope` | Optional separately hashed local/Hub operation metadata |

The manifest's digest excludes its own digest and signatures. Signatures are
detached and domain-separated from registry publication and work plans. A
signature attests the named signer's claim, not automatically upstream
authorship or release authorization. Digests use Chapter 0 canonical rules;
binary member digests cover exact bytes. A transport container is not the
content identity of the bundle.

A self-contained export includes scan definitions, inventory, provider
observations and their normalized content, advisory snapshot manifests and
required records, policy, dispositions, candidate history, scan input,
assessment, and engine-profile reference. Where an adapter's reproducibility
contract requires retained raw source bytes, those are members or declared
external references. Credentials and authorization tokens are never members.

Members form a finite acyclic reference closure apart from explicitly allowed
domain graph cycles inside an inventory. The importer verifies declared member
sizes before allocation, rejects duplicate/conflicting members, unsafe paths,
unlisted executable content, unsupported schemas, and digest mismatches.
Compression expansion, object count, graph depth, and total bytes are bounded
by an advertised import profile. Importing is not permission to unpack arbitrary
files into a checkout or follow arbitrary network URLs.

Exports have `self-contained` or `reference` profile and state whether offline
reproduction is possible. A reference export's missing members are explicit.
Private retrieval URLs are scoped, short-lived handles resolved through an
authenticated API, not reusable provider secrets. In Hybrid, large exports
stream through admitted Worker/object delivery, not through Native as an
implicit bulk proxy. Export authorization is rechecked at download time.

## 8.2. Import and trust classification

An import validates container limits, canonical schemas/digests, reference
closure, engine support, source/publication bindings, tenant visibility,
signature authorization, observation coverage, and disposition scope. It
recomputes the assessment using the shared engine when all required inputs
are available. An unsupported engine or missing member cannot be reported as
a verified equivalent result.

The import receipt classifies evidence as `reproduced`, `trusted-attested`,
`unverified`, or `rejected`, with exact reasons. `reproduced` establishes
deterministic agreement with supplied inputs, not that the provider or
publisher told the truth. `trusted-attested` requires an installed authority
policy for the specific signer, input scope, and semantic engine; it is not
an automatic shortcut for any signed upload.

Imports do not advance the live assessment head, open alerts, or satisfy
release gates solely because their digest matches. Admission into authoritative
Hub evidence requires current resource/source authority, freshness policy,
complete required inputs, and the Chapter 5 generation transaction. An
authorized local import can be useful offline evidence even when it lacks
Hub authority. The UI/CLI displays this distinction.

An import operation is idempotent by bundle digest and intended authorized
scope. Re-importing the same bundle with different authority credentials can
create a new validation receipt, not rewrite the old receipt. An exporter
pins one committed input closure; it MUST NOT mix a head that changed during
export with objects from its replacement assessment.

## 8.3. Local checkout binding

Portable inventory does not contain absolute checkout paths. The local
execution envelope binds RFC-0018's repository root/common directory, clean
base commit/tree, dirty-tree state when scanning allows it, controller build,
and selected package paths. Sensitive local paths are omitted from portable
export unless explicitly requested by an authorized local user.

A local scan MAY inspect a dirty tree and label it accordingly. Creating or
applying a package-update plan still obeys RFC-0018's clean-base and exact
source-binding requirements. The handoff verifies that the current package
definition, component vector, and source tree match the scan inputs. A stale
or differently patched package requires rescan/replanning; an advisory match
against a generic upstream version is insufficient mutation authority.

Hub-derived action intents identify exact candidate evidence. Local planning
revalidates the repository/controller envelope and resolves candidate sources
under the existing fetch/update policy. Results can be exported back through
the same bundle/receipt contracts. This supports human and programmatic
handoffs without treating command output as a trusted executable script.

## 8.4. Reviewed security dispositions

A disposition is immutable signed/reviewed evidence with:

- Exact component instance or explicitly bounded component/version/artifact
  scope, advisory IDs/lineage, and relevant input/evidence digests.
- Statement status, technical justification, supporting patch/build/runtime
  evidence, issuer and reviewer identities, review authority, and time bounds.
- Applicable tenant/release/channel policy scope and revocation/supersession
  references.

OpenVEX supplies interoperable `affected`, `not_affected`, `fixed`, and
`under_investigation` statements where its product identity/justification can
be bound to the AOS component. `not_affected` requires supported reasoning;
`fixed` requires evidence of a fix in the exact artifact, including a reviewed
backport where applicable. `under_investigation` is not a clean result.
Accepting release risk is a separate authorization decision, not an invented
OpenVEX applicability status.

An upstream version range alone MUST NOT undo a valid, specifically reviewed
backport statement; neither does a package author's unsigned assertion
automatically override a credible affected match. Conflicting evidence is
retained and surfaced for policy/review. The deterministic evaluator applies
the pinned disposition set and its precedence rules, including expiration at
`evaluatedAt`. It never contacts a reviewer or chooses by mutable UI order.

Disposition submission and review use separate permissions. Policy specifies
required reviewer count/role, allowed scope and maximum validity. A statement
that grants a broader scope than the reviewer's authority is rejected.
Revocation triggers reassessment and release eligibility checks; signed old
assessments remain immutable history.

## 8.5. Release eligibility

Promotion MUST pin the exact release plan, artifact/SBOM inventory, scan
definition, assessment/input digests, advisory snapshot, disposition set,
engine profile, and release-policy digest. It MUST verify subject bindings,
evidence authority, freshness at the decision time, and required coverage.
The currently displayed package head is not a substitute for that evidence.

The initial release-policy contract requires:

| Condition | Required outcome |
| --- | --- |
| Missing/stale/unsupported mandatory scan evidence | Block promotion or an explicitly authorized policy exception |
| Confirmed critical/high vulnerability or required KEV match | Block unless an exact reviewed remediation/non-applicability or bounded risk exception is authorized |
| Potential match or unsupported applicability needed by policy | Block pending review or exact authorized exception; do not infer safe |
| Lower severity findings | Record and apply explicit channel policy |
| Required update stream behind a security fix | Apply declared security-update policy; latest release alone is not proof of fix |
| Alert acknowledged or notification suppressed | No change to eligibility |

Severity and KEV thresholds are versioned policy values, not hard-coded
provider assumptions. An exception binds the issue, exact artifact/release,
approver authority, justification, expiration, and policy revision. It cannot
waive contributor authorization, signing, provenance, or existing publication
requirements. Policy denial is distinct from a failed scan operation.

The current release assembly's advisory-disposition v1 plan/SBOM binding and
production rejection of unresolved findings MUST remain intact during rollout.
Its reviewed-source/unresolved fields alone do not prove that a scan occurred.
A versioned successor binds actual assessment authority and required coverage.
Readers support it before writers emit it; a gate MUST NOT silently accept a
v1 record as a v2 verified assessment.

Promotion performs an authorization/freshness recheck under the existing
release transaction/custody model. If required inputs changed before commit,
it fails with a precise stale-decision conflict or explicitly repins and
reevaluates before approval. It MUST NOT swap a different assessment into an
already approved decision invisibly. Publication retains the decision evidence.

## 8.6. Live findings and historical publication

New advisories can affect a release that was eligible when published. Hub
reassesses its retained immutable inventory, opens live alerts, and exposes
current eligibility/status independently from its original signed publication
evidence. It MUST NOT rewrite signed manifests to pretend the earlier
assessment included an advisory not then known.

Any channel removal, rollback, remediation, or revocation is a separate
authorized publication operation. The scanner may issue an action intent;
finding a CVE does not grant permission to move channels or alter artifacts.
Published and live assessments are both available with their times, authority,
policy, and input identities so consumers can reason about the difference.
