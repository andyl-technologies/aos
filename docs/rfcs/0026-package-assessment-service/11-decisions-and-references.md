# 11. Decisions and references

## 11.1. Design decisions

| Decision | Rationale and rejected alternative |
| --- | --- |
| Extend package-authored maintenance metadata | Existing component vectors/providers/streams are the source of update policy; a separate Hub-only map would drift |
| Normalize inventory into Hub's database | Scanning follows authenticated package identity regardless of Git, OCI, or other registry backend; polling repository paths would couple correctness to storage |
| Separate immutable publication from live assessments | New advisories change knowledge about old artifacts without changing signed historical metadata |
| Extract shared evaluator and adapters | Identical frozen inputs must give identical results; separate local/hosted implementations would diverge in policy and output |
| Use structured OSV and reviewed NVD mappings | Repology's boolean lacks advisory identity/range evidence; generic package-name matching would make unsupported applicability appear certain |
| Keep third-party scanner backends optional | Grype/OSV-Scanner can supply comparative integration evidence, but shelling out to a Native binary cannot define Worker parity or AOS policy |
| Distinguish coverage from finding count | Empty results after failure, stale evidence, and unmapped identities must not become a clean report |
| Keep all three Hub modes | Placement affects transport/storage, not package scan semantics; Hybrid is not an excuse to disable Worker-only scanning |
| Native coordinator, bounded Hybrid executors | SQL joins/policy use Native CPU/local data; provider/object I/O benefits from Worker bandwidth and horizontal fanout |
| New provider-work domain | Existing storage work intentionally excludes generic network access; extending it into an HTTP execution channel would erase its capability boundary |
| Durable alert episodes and transactional outbox | Repeated scans should not repeatedly open the same issue; notification retries must not lose or duplicate logical state transitions |
| Import evidence with separate trust validation | Reproducible matching digests do not establish publisher/provider authority or permission to promote |
| Pin release assessment and policy | A live UI head can race with approval; signed publication retains the actual evidence used at decision time |

## 11.2. Worked continuity example

This example uses fictional versions/advisory `x_AOS-example-1`. Times and
digest labels describe a fixture scenario, not an actual vulnerability report.
The example's release policy permits series 1 and requires three days of
admitted candidate age.

| Time (UTC) | Durable observation/state | Result |
| --- | --- | --- |
| October 1, 00:00 | Package 1.4.0 inventory I1 admitted with component C1 | Initial assessment queued |
| October 1, 00:01 | Complete upstream observation O1 enumerates 1.4.1; history H1 first observes it now | Candidate is stabilizing, not yet eligible |
| October 1, 00:02 | Complete required advisory snapshot S1 has no matching records | No known findings under S1; coverage/freshness recorded |
| October 4, 00:01 | Age deadline fires with I1/O1/H1, no new upstream candidate required | 1.4.1 becomes an eligible update; one update-alert episode opens |
| October 4, 01:00 | Snapshot S2 adds a confirmed affected range for C1, fixed upstream in 1.4.2 | New vulnerability-alert episode opens for retained 1.4.0 |
| October 4, 01:05 | Provider refresh times out | Partial assessment retains the finding and exposes missing fresh coverage |
| October 4, 01:10 | User acknowledges the vulnerability alert | Episode acknowledgement changes; assessment and release denial do not |
| October 4, 02:00 | Local imports exact frozen I1/O1/S2/policy/history/time and evaluates | Canonical assessment equals the Hub's; local execution envelope differs |
| October 5, 00:00 | Artifact I2 has a reviewed exact backport disposition D2 | Finding remains source-attributed; disposition/policy evaluates exact I2 |
| October 5, 00:05 | I2 promotion pins its assessment, D2 and release policy and passes authorized review | Publication retains that decision; I1 remains affected |
| October 6, 00:00 | New record revision revokes the basis of D2 or D2 is revoked by its authority | I2 is reassessed; live status may become blocked without rewriting its publication |

If S2 is only a partial source ingest, it cannot replace S1 as a complete
snapshot. Known positive records can still contribute findings with partial
coverage. If a scan for I1 completes after I2's newer desired generation for
the same mutable selector, it remains history rather than replacing I2's
current head. Different immutable version subjects retain independent heads.

The upstream fixed version 1.4.2 is not automatically an eligible candidate
under stabilization policy, and neither upstream fixation nor a reviewed
backport means that Hub has published a corresponding artifact. Reports
distinguish these three facts.

## 11.3. Frozen input example

The following is syntactically valid `scan-input/v1` JSON. Repeated hexadecimal
values are illustrative references, not published objects or computed digests.
The objects named by these references must exist and validate before evaluation.
Pretty printing is not the canonical signing representation.

```json
{
  "schema": "aos.scan-input/v1",
  "inventoryDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "profiles": ["updates", "vulnerabilities"],
  "observationDigests": [
    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  ],
  "advisorySnapshotDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "dispositionSetDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
  "policyDigest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "historyDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
  "engineDigest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "evaluatedAt": "2026-10-04T02:00:00Z"
}
```

Changing evaluation time, history, dispositions, provider record revision,
policy, or semantic engine changes input identity even if the finding count
stays the same. An execution ID or local checkout path does not enter this
portable object. A no-dispositions/no-history input uses canonical empty-set
objects of the corresponding schemas, not missing digest fields.

## 11.4. Internal registrations and versioning

This project RFC requests no IANA registrations. AOS maintains the schema,
provider/comparator profile, diagnostic, event, permission, and action-intent
identifiers introduced here in its own versioned contracts. Implementation
MUST add machine-readable schemas/fixtures and a registry documenting each
identifier's owner, semantics, version, supported targets, and limits.

An incompatible field, comparator rule, coverage proof, or action semantic
requires a new schema/profile version. Adding a provider is a capability
addition; it cannot silently broaden the source set of an already pinned
policy. A build change with no semantic change retains the semantic profile
and records a separate executor build identity. Changing the parser or
evaluator in a way that can affect canonical outputs changes engine identity.

Closed AOS domain records are distinct from forward-compatible transport
envelopes and third-party source parsers. The implementation MUST document
which layer may ignore an extension. A new decision-relevant provider field
cannot be discarded solely to preserve a prior assessment digest.

## 11.5. Review questions before implementation freeze

The following choices require review but do not relax the invariants:

1. Exact API package/version and disposition-service placement in the existing
   generated Hub/release API. The domain operations and permissions are fixed
   here; names must follow repository conventions.
2. Initial supported ecosystem comparator set and the pinned NVD/CPE profile.
   Unlisted/unsupported schemes remain unknown until qualified. Fixtures must
   establish semantics before an adapter advertises coverage.
3. Production freshness/cadence, aggregate scan/import limits, retention,
   destination quotas, and deployment SLO values. Administrators must set
   explicit bounded values; operational defaults are not package-authored.
4. Disposition reviewer roles/counts, backport evidence requirements, and
   channel-specific severity/KEV exception policy. Existing release authorization
   and unresolved-finding rejection remain effective until successors ship.
5. Whether optional Grype/OSV-Scanner integration is useful for comparative
   qualification. It cannot replace the shared evaluator or become an implicit
   Worker capability. Licensing/build packaging requires normal review.

PR #374 is the intended Hub integration base. Domain extraction may proceed
independently, but the provider-work route, Hybrid refusal, scoped storage
evidence, and byte-placement qualification must be reviewed against its final
merged topology. The RFC records its reviewed base SHA so drift is visible.

## 11.6. Normative references

External standards are referenced for their defined formats and semantics,
not as authority for AOS deployment defaults. Research was checked on
2026-10-08. Implementations pin source/profile revisions where behavior matters;
these links are not a promise that upstream APIs remain unchanged.

- **[RFC2119]** Bradner, S., [Key words for use in RFCs to Indicate Requirement
  Levels](https://www.rfc-editor.org/rfc/rfc2119), BCP 14, March 1997.
- **[RFC8174]** Leiba, B., [Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words](https://www.rfc-editor.org/rfc/rfc8174), BCP 14, May 2017.
- **[RFC3339]** Klyne, G. and Newman, C., [Date and Time on the Internet:
  Timestamps](https://www.rfc-editor.org/rfc/rfc3339), July 2002. Chapter 0
  defines AOS's stricter timestamp profile.
- **[RFC9110]** Fielding, R., Nottingham, M. and Reschke, J., [HTTP
  Semantics](https://www.rfc-editor.org/rfc/rfc9110), June 2022; conditional
  requests, validators, status and retry semantics.
- **[OSV-SCHEMA]** OpenSSF, [Open Source Vulnerability
  format](https://ossf.github.io/osv-schema/), version 1.9.1, September 24, 2026.
- **[OSV-API]** OSV, [API](https://google.github.io/osv.dev/api/), including
  [query](https://google.github.io/osv.dev/post-v1-query/),
  [querybatch](https://google.github.io/osv.dev/post-v1-querybatch/), and
  [record retrieval](https://google.github.io/osv.dev/get-v1-vulns/).
- **[NVD-API]** NIST, [Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
  and [CPE APIs](https://nvd.nist.gov/developers/products), API 2.0.
- **[CPE]** NIST, [Common Platform Enumeration](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe);
  name/matching and applicability profiles require explicit versioning.
- **[PURL]** Package URL project, [Package URL specification](https://github.com/package-url/purl-spec);
  implementation pins the supported type definitions and normalization rules.
- **[OPENVEX]** OpenVEX project, [OpenVEX specification](https://github.com/openvex/spec);
  Chapter 8 adds AOS artifact-binding, review and authorization requirements.
- **[KEV]** CISA, [Known Exploited Vulnerabilities
  Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  including its [JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **[AOS-0012]** [RFC-0012: Hub surface topology](../0012-hub-surface-topology/README.md).
- **[AOS-0017]** [RFC-0017: Canonical Hub publishing](../0017-canonical-hub-publishing/README.md).
- **[AOS-0018]** [RFC-0018: Maintainer package upgrades](../0018-maintainer-package-upgrades/README.md).
- **[AOS-0023]** [RFC-0023: Hub hybrid topology](../0023-hub-hybrid-topology/README.md),
  particularly its [storage protocol](../0023-hub-hybrid-topology/02-storage-work-protocol.md)
  and [state portability](../0023-hub-hybrid-topology/05-state-deployment-and-portability.md).

## 11.7. Informative research and code references

- **[REPOLOGY]** Repology's [API documentation source](https://github.com/repology/repology-rs/blob/master/repology-webapp/templates/api.html)
  documents its request/bulk-client guidance. RFC-0018 also records a
  [pinned source revision](https://github.com/repology/repology-rs/blob/4f10afe4209e8d8e28d9622090a6ddded4a901fc/repology-webapp/templates/api.html).
  Chapter 3 sets a conservative explicit AOS budget independently of future
  provider changes.
- GitHub, [REST releases API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release).
  Its latest endpoint is not an AOS supported-stream version selector.
- OSV, [FAQ and data dumps](https://google.github.io/osv.dev/faq/), for bounded
  snapshot ingestion and offline evidence design.
- Anchore, [Grype supported scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/),
  and [Syft supported ecosystems](https://oss.anchore.com/docs/capabilities/all-packages/).
  These inform optional integration research, not required AOS match semantics.
- [Hybrid PR #374](https://github.com/andyl-technologies/aos/pull/374), reviewed
  at `5a2c173ce59fce593bb2ca21d28f27fa477688ff`. This RFC's PR is stacked there
  to expose only the assessment design delta.

Current implementation references below are relative to this RFC's reviewed
tree. They are evidence of extraction opportunities, not claims that the
new service is implemented.

| Code | Observed responsibility |
| --- | --- |
| [Maintain library](../../../crates/aos-maintain/src/lib.rs) | Pure maintenance contracts/workflows |
| [Discovery contracts](../../../crates/aos-maintain/src/discovery.rs) | Component observations, version selection, discovery snapshot |
| [Inventory contracts](../../../crates/aos-maintain/src/inventory.rs) | Existing classifications, ownership, lifecycle and vector validation |
| [Local provider adapter](../../../crates/aos/src/commands/maintain/discovery.rs) | HTTP, bounds, state/cache/time effects |
| [Local envelope](../../../crates/aos-maintain/src/envelope.rs) | Checkout and controller binding |
| [Presentation contracts](../../../crates/aos-maintain/src/presentation.rs) | Report and currently local command actions |
| [Canonical JSON](../../../crates/aos-contract/src/canonical.rs) and [digests](../../../crates/aos-contract/src/digest.rs) | Existing canonical/digest dialect |
| [Upstream builder](../../../pkgs/build-support/_upstream.nix) and [zlib declaration](../../../pkgs/compression/zlib.nix) | Evaluated maintenance metadata and existing package authoring pattern |
| [Derivation metadata](../../../lib/derivations.nix) | Attaches maintenance declarations to `passthru.aos` |
| [Registry manifest](../../../crates/aos-registry-surface/src/manifest.rs) | Closed authenticated package metadata surface |
| [Release SBOM](../../../crates/aos-release/src/sbom.rs) | Current SPDX source/output inventory |
| [Release assembly](../../../crates/aos/src/commands/release/assemble/mod.rs) and [tier policy](../../../crates/aos-release/src/registry.rs) | Plan/SBOM advisory-disposition binding and unresolved production rejection |
| [Hub core](../../../crates/aos-hub-core/src/lib.rs) and [jobs](../../../crates/aos-hub-core/src/jobs.rs) | Shared application and logical background work |
| [Worker jobs](../../../crates/aos-hub-worker/src/worker_jobs.rs) | Worker-only execution and Hybrid refusal |
| [Storage-work contract](../../../crates/aos-hub-core/src/storage_work.rs) and [Native admission](../../../crates/aos-hub/src/storage_work.rs) | Scoped existing Hybrid physical work |
| [Console](../../../crates/aos-hub-console/src/lib.rs) | Shared Hub browser interface integration point |
