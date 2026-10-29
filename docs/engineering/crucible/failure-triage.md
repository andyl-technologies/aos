# Failure triage

Exploration finds the same defect many times, from different seeds, schedules,
and topologies. Triage groups those findings by a deterministic root-cause
signature, shrinks one representative per group while preserving that
signature, and writes one report per group.

Triage is an offline, content-addressed projection over records Crucible
already keeps: self-contained reproduction artifacts, the recorded event log,
and assertion violation records. It adds no execution path, no run state, and
no second record of what happened. Clustering and signature computation read
stored evidence only; the only execution triage performs is minimization's
candidate replay, which is a re-reduction of a recorded schedule. Re-running
triage on the same findings and policy produces byte-identical results.

```text
  findings ledger --> FailureSignature per finding (read from recorded evidence)
                          |
                          v  SignaturePolicy projects KEY fields
                      FailureSignatureKey --> cluster id = H(key material)
                          |
                          v  FailureClusteringResult (clusters by id, members by artifact)
              signature-preserving minimization of each representative
                          |
                          v
              FailureClusterReport per cluster --> json | jsonl | table | markdown
                          |
                          v
              FailureTriageResult stored in the DagStore (+ optional self-check, diff)
```

The model lives in `crates/crucible/crucible-engine/src/model/failure/`:

| File | Owns |
|------|------|
| `model.rs` | `FindingDiscoveryPath`, `FindingReproductionArtifact` |
| `model/signature.rs` | `FailureSignature`, `FailureRecordedEventLog`, normalization, timeout and violation records |
| `model/signature_policy.rs` | `FailureKind`, `SignaturePolicy`, `FailureSignatureKey`, `FailureTriageResultIdentity` |
| `model/clustering.rs` | `FailureClusteringResult`, signature-preserving minimization |
| `model/reporting.rs` | `FailureClusterReport`, `FailureClusterReportSet`, `FailureClusterReportFormat` |
| `model/triage.rs` | `FailureFindingsLedger`, `FailureTriageSignatureSelfCheck`, `FailureTriageResult`, `FailureTriageResultDiff` |
| `material.rs`, `material/reporting.rs` | Canonical material, causal cone, validation helpers |
| `replay_evidence.rs` | Portable replay evidence for independently observed signature replays |

The CLI driver is `crates/crucible/crucible-cli/src/cli/triage_debug/`.
Reproduction artifacts and the base minimizer are described in
[exploration.md](exploration.md).

## Inputs

A finding is a `FindingReproductionArtifact`: a self-contained
`(ScenarioDefForm, Schedule)` artifact, its discovery path, the discovering
oracle's finding fingerprint, the configuration id, and replay evidence.

Signature construction never reads raw caller claims. It first builds a
`FailureRecordedEventLog`, which binds event-log entries to the same artifact:

- `from_recorded_artifact(finding, event_log_artifact, entries)` recomputes the
  causal projection of `entries` and rejects any mismatch with the recorded
  `ReproductionEventLogArtifact` (artifact id, causal-subsequence hash, byte
  length, event count, and the coverage fingerprint recomputed with
  `coverage_fingerprint_from_event_log`).
- `from_causal_entries_coverage_and_frames(finding, causal_entries, coverage,
  frames)` is the adapter for remote streams that retain exact causal events
  while coverage travels through the shared coverage-feedback projection.

Both compute an `evidence_binding`:

```text
BLAKE3( "crucible.failure-recorded-evidence.v1\0"
        || causal_projection.content_hash
        || coverage_fingerprint
        || u64le(frame_count) || for each frame: u64le(len) || frame )
```

The binding is part of every signature's report material, so offline
recomputation detects tampering with, or drift in, the retained frames.

## The failure signature

`FailureSignature` is computed from the recorded run alone: the immutable
scenario, the recorded schedule, and the causal subsequence of the event log.
It deliberately omits the discovery path, the discovering campaign, the
finding fingerprint, wall-clock data, and raw observational entries.

| Field | Meaning |
|-------|---------|
| `failure_kind` | `FailureKind::PropertyViolation`, `Divergence`, or `Timeout` |
| `property` | `FailurePropertyKey { id, quantifier }` for a property violation, else `None` |
| `first_failing_point` | `FailureFirstFailingPoint { event_kind, faulting_node }`, node symmetry-canonicalized |
| `coverage_class` | `FailureCoverageClass { algorithm, bucket }` derived from the coverage fingerprint |
| `evidence_binding` | Binding over causal projection, coverage, and frames (report material only) |
| `causal_slice_hash` | Hash of the canonical causal cone |
| `causal_cone` | Full canonical cone material (`FailureCausalCone`), used by `exact` |
| `at_icount_report_only` | Absolute retired icount of the first failing point; report-only |

Each kind has a constructor, and each `*_with_normalization` variant takes a
`FailureSignatureNormalization`:

| Kind | Constructor | Source of the first failing point |
|------|-------------|-----------------------------------|
| Property violation | `from_recorded_property_violation` | `FailurePropertyViolationRecord` wrapping a `HostAssertionViolation` |
| Divergence | `from_recorded_divergence` | `EventLogCausalDivergencePoint` from replay-oracle bisection |
| Timeout | `from_recorded_timeout` | `FailureTimeoutRecord` at the execution-budget boundary |

The signature is read, not re-derived: every field comes from the deterministic
record, and constructors validate that record instead of trusting it.

- **Property violation.** The quantifier is any `AssertionQuantifierKind`,
  including the guest marker flavors. `validated_property_violation` reruns the
  `OfflineAssertionChecker` over the retained raw entries and requires a
  matching violation. If the log retains the runtime's `assertion_state_changed`
  transition to `Violated`, it must be unique, engine-sourced, at a boundary
  stamp, and agree with the rechecked verdict. A guest-marker violation must
  have exactly one matching `GuestMarker` witness preceding the transition. The
  witness coordinate and the host violation are appended to the cone material.
- **Divergence.** The bisection point must be present in the checked causal
  projection with the same raw index, stamp, source, and kind. The faulting
  node is the event's node source, or the stamp's node for scenario, engine, and
  command sources.
- **Timeout.** `FailureTimeoutRecord::new` fixes the event kind to
  `execution_budget_exhausted`. The boundary must exist in the causal
  projection with the same virtual time, node, optional icount, and a
  `budget_kind` attribute of `execution-quanta` or `virtual-time`
  (`FailureTimeoutBudgetKind::{ExecutionQuanta, VirtualTime}`). A timeout is a
  concrete execution that exhausted its configured budget; frontier exhaustion
  without a terminal execution is campaign status, not a finding.

Any failed check returns `EngineError::ReplayTargetMismatch` or
`EngineError::UnifiedOperationEvidenceMismatch`; a signature is never
fabricated for evidence that does not validate.

### Normalizations

Three normalizations keep the signature stable under minimization and keep one
defect from splitting into many clusters:

1. **Absolute icount is report-only.** Minimization removes decisions and shifts
   every later icount, so `at_icount_report_only` is excluded from
   `FailureSignature::content_hash` and from every key except `exact`. It still
   appears in report material.
2. **`faulting_node` is symmetry-canonical.** `FailureSymmetryCanonicalizer`
   rewrites a node that belongs to an interchangeable class in
   `SymmetryReductionClasses` to `symmetry-class:<len>:<class-name>`; other nodes
   keep their scenario identity. "Replica A crashes" and "replica B crashes" then
   share one key. This is the triage-side use of the same classes that drive
   symmetry reduction in search.
3. **The slice hash covers the causal cone, not the whole schedule.**
   `failure_causal_cone_entries` takes the causal entries up to and including the
   anchor (the first failing causal entry) that share a dependency key with the
   anchor. Dependency keys (`failure_causal_dependency_keys`) are the canonical
   node of the source or stamp, scenario event names, and string, node, and event
   attribute values. Trailing entries and earlier entries with no shared key
   are outside the cone, so removing them does not move the hash.

Cone material lists, per entry, the cone index, canonical stamp node, canonical
source, level, class, kind, and attributes. `VirtualTime` and `Icount`
attributes are omitted, so absolute positions do not leak into the hash. The
cone hash is `causal_slice_hash`, computed under
`crucible.failure-signature.causal-slice.v1`.

### Canonical material

`FailureSignature::content_hash` hashes this material under
`crucible.failure-signature.v1`:

```text
failure_kind=property-violation|divergence|timeout
property=some|none
<assertion id material>                       (property only)
property_quantifier=<label>                   (property only)
first_failing_event_kind_len=<n>
first_failing_event_kind=<kind>
faulting_node=...|none
coverage_class_algorithm=crucible.failure-signature.coverage-class.top16.v1
coverage_class_bucket=<u16>
causal_slice_hash=<hex>|none
```

`report_material()` appends `evidence_binding=<hex>`,
`at_icount_report_only=<n>|none`, and the cone between
`causal_cone_material_BEGIN` and `causal_cone_material_END`. Report material is
what the findings ledger stores and what the self-check compares byte for byte.

The coverage class algorithm `crucible.failure-signature.coverage-class.top16.v1`
takes the first two bytes of the deterministic coverage fingerprint as a
big-endian `u16` bucket. Runs that reach the failure through the same code
region share a bucket; a different algorithm string is a different class.

## Signature policy

`SignaturePolicy` is the closed, versioned selector of which signature fields
are key fields (clustered on) and which are detail (reported only).
`SignaturePolicyLevel` has exactly the levels coarse/default/fine/exact, with
`Default` as the default.

| Level | Key fields |
|-------|-----------|
| `Coarse` | `failure_kind`, `property.id` |
| `Default` | coarse + `property.quantifier`, first failing event kind, canonical `faulting_node`, coverage class |
| `Fine` | default + `causal_slice_hash` (`keys_causal_slice_hash`) |
| `Exact` | fine + absolute icount (`at_icount_key`) + full cone (`exact_causal_cone_material_BEGIN` ... `END`) (`keys_absolute_icount`) |

`SignaturePolicy::signature_key(signature)` produces a `FailureSignatureKey`
whose canonical material starts with the policy material and wraps the selected
fields in `key_fields_BEGIN` / `key_fields_END`:

```text
signature_policy_schema_version=1
signature_policy_level=coarse|default|fine|exact
coverage_class_algorithm=crucible.failure-signature.coverage-class.top16.v1
minimize_merge_allowed=true|false
key_fields_BEGIN
...
key_fields_END
```

Projection fails with `UnifiedOperationEvidenceMismatch` when the signature's
coverage class was built by a different algorithm, or when `exact` is requested
for a signature without cone material. `SIGNATURE_POLICY_SCHEMA_VERSION` is `1`;
changing which fields a level keys is a versioned schema change.
`allows_minimize_merge()` is `false` only for `exact`, which is forensic; the
flag is recorded in policy material so a forensic result can never share an
identity with a mergeable one.

The policy is part of the triage result identity. `FailureTriageResultIdentity`
is `(findings_ledger, policy)`, hashed under
`crucible.failure-triage.result-identity.v1`, so re-clustering the same ledger
under the same policy is idempotent and a policy change is a distinct result.
An operator who suspects over- or under-clustering re-triages under a finer or
coarser policy and compares the two results.

## Clustering

`FailureClusteringResult::from_findings(policy, findings)` is a deterministic
equivalence-class partition of `FailureClusterFinding { reproduction_artifact,
signature }` inputs. Two findings share a cluster exactly when their
`FailureSignatureKey`s are equal, and the cluster id is the key's content hash
under `crucible.failure-signature.key.v1`.

- Clusters are built in a `BTreeMap` keyed by cluster id and members in a
  `BTreeMap` keyed by reproduction-artifact hash, so output is content-address
  ordered: clusters by id, members by artifact hash. No host map order, thread
  scheduling, or clock is involved.
- The same artifact supplied twice with a different key or different report
  material is rejected ("conflicting failure signatures"), as are two distinct
  keys that collide to one cluster id.
- `FailureCluster::representative_member()` is the first member, the
  content-address-least artifact, so representative choice is reproducible.

The canonical clustering material (`crucible.failure-triage.clustering-result.v1`)
records the policy, counts, and for each cluster its id, key material, and
member artifact and signature hashes.

## Signature-preserving minimization

`FailureClusteringResult::minimize_representatives(config, load, signature)`
extends `FindingReproductionArtifact::minimize` instead of adding a new
shrinker. Everything in the base pass is reused: seeded content-address
candidate order, compiled bounds, and replay validation of every candidate
before the oracle sees it. Only the accept predicate changes. The oracle passed
to the base pass recomputes the candidate's signature, projects it under the
active policy, and accepts only candidates whose active-policy
`FailureSignatureKey` equals the original representative's key:

```text
for each cluster (in cluster-id order):
  require cluster.id == H(cluster.signature_key)
  rep    := cluster.representative_member()           # content-address least
  target := signature_key(rep.signature, policy)      # must equal cluster key
  run    := load(rep).minimize(config,
              |cand| key(signature(cand), policy) == target ? Some(fingerprint) : None)
  require key(signature(run.minimized), policy) == target
          else "minimal representative signature changed"
```

The central invariant is `signature(minimal, policy) == signature(original,
policy)`; a result that violates it is an error, never an accepted output.
Because icount is report-only, `faulting_node` is canonical, and the slice hash
is cone-scoped, ordinary out-of-cone shrinks keep the key, and the minimal
representative stays in its own cluster.

Each `FailureSignaturePreservingMinimizationRun` records the cluster id,
representative artifact, target and minimized keys, the underlying
`MinimizationRun`, and a `FailureMinimizationDisposition`:

| Disposition | Label | When |
|-------------|-------|------|
| `Minimized` | `minimized` | The shrink pass ran |
| `NotRequested` | `not-requested` | `--minimize none`, any failure kind |
| `NotApplicableTimeout` | `not-applicable-timeout` | Minimization requested for a timeout |

A timeout has no assertion or divergence predicate the offline minimizer can
safely replay, so a requested timeout minimization keeps the original
representative, attempts zero candidates, and still checks the signature.
The result (`crucible.failure-triage.signature-preserving-minimization.v1`)
records runs in cluster-id order. The default minimizes one representative per
cluster, so cost is proportional to clusters, not findings.

## Per-cluster reports

`FailureClusterReport::from_cluster(policy, cluster, run, failure, event_log,
normalization, excerpt_len)` builds one report per cluster. Before reading any
field it checks that the cluster id matches its key, the run belongs to the
cluster and used its representative, the run preserved the signature, and the
event log belongs to the minimized artifact. It then recomputes the minimized
representative's full signature from checked evidence rather than trusting
caller-supplied signature detail, and requires its key to equal the cluster key.

| Field | Content |
|-------|---------|
| `cluster_id`, `policy`, `signature` | Cluster identity and the minimized representative's full signature |
| `member_hashes`, `member_count` | Member reproduction artifacts in content-address order |
| `representative_artifact`, `minimal_representative` | Original and minimized representative artifacts |
| `minimal_reproduction` | `FailureClusterReportReproduction { artifact, seed, scenario, schedule }` |
| `failure` | `FailureClusterReportFailure::{Property, Divergence, Timeout}` detail |
| `event_log_excerpt` | Last `excerpt_len` causal entries ending at the first failing point |
| `causal_chain` | The causal cone as ordered `FailureClusterReportCausalStep`s |
| `replay_command` | `crucible replay blake3:<minimal artifact hex>` |

Divergence detail (`FailureClusterReportDivergence`) carries the bisected first
difference: raw index, node, stamp node, tick, icount, source, kind, and
expected- and reproduced-side state summaries. Each causal step carries the raw
index, renumbered causal sequence, canonical node, tick, icount, kind, canonical
source, and the entry's content hash. The CLI uses an excerpt length of 8.

All renderings are pure functions of one canonical report material
(`crucible.failure-triage.cluster-report.v1`), so regenerating a report is
byte-identical on any host and the format changes presentation, never content.
The deterministic `json`, `jsonl`, `table`, and `markdown` renderings are:

| `FailureClusterReportFormat` | Report set rendering | CLI file |
|------------------------------|----------------------|----------|
| `Json` | One object with schema, policy, report-set hash, and reports | `triage-report.json` |
| `JsonLines` | One report object per line | `triage-report.jsonl` |
| `Table` | Tab-separated `field`/`value` rows per report | `triage-report.txt` |
| `Markdown` | One `# Crucible Triage Cluster` section per report | `triage-report.md` |

Each JSON report object holds `schema`, `cluster_id`, `policy`, `report_hash`,
`signature_hash`, `member_count`, `member_hashes`, `minimal_representative`,
`replay_command`, and the full `canonical_material`. `FailureClusterReportSet`
orders reports by cluster id and rejects mixed policies or duplicate clusters.

## Findings ledger

### Model

`FailureFindingsLedger` is the model input. `from_signed_findings` deduplicates
by reproduction-artifact hash and rejects one artifact with conflicting
discovery-signature report material, so a finding seen by two campaigns is one
entry and a finding's identity is its artifact hash. `from_artifacts` builds an
artifact-only ledger, which cannot be clustered until engine-owned evidence
supplies signatures. The ledger's stored bytes are its canonical material under
`crucible.failure-triage.findings-ledger.v1`, and its content hash is the BLAKE3
hash of those bytes.

### On-disk format

The CLI exchanges findings as a canonical text ledger, schema
`crucible.failure-triage.findings-ledger.v4`, with two kinds. Live QEMU `search`
and `fuzz` write a reproduction ledger with `--findings-out <path>`, or by
default to `<artifact-dir>/findings/<digest>.crucible-findings` when at least
one finding was retained. Entries are written in artifact-hash order:

```text
crucible.failure-triage.findings-ledger.v4
ledger_kind=reproduction
finding_count=1
finding.0.artifact=<hex>
finding.0.discovery_path=<path label>
finding.0.finding_fingerprint=<hex>
finding.0.coverage_fingerprint=<hex>
finding.0.discovery_signature=<hex>
finding.0.discovery_signature_material_hex=<hex of report material>
finding.0.evidence=property|timeout
  property: assertion_hex, message_hex, quantifier, at_virtual_time,
            at_icount, node_hex, detail_hex
  timeout:  budget_kind, configured_limit, observed_quanta,
            at_virtual_time, at_icount, node_hex
finding.0.event_frame_count=<n>
finding.0.event_frame.<i>=<hex frame>
```

Each entry binds a stored reproduction artifact to its exact discovery-time
event frames, coverage fingerprint, typed property-violation or timeout record,
and discovery-signature bytes. The parser (`parse_reproduction_finding_evidence`)
reloads and replays the artifact from the store, rebuilds the typed record,
recomputes the signature from the frames, and rejects the entry unless the
recomputed signature hash and report material equal the recorded
`discovery_signature` and `discovery_signature_material_hex`. The reproduction
writer rejects divergence evidence, so divergence signatures exist in the
engine model but are not carried by CLI ledgers.

A campaign ledger (`ledger_kind=campaign`) embeds, per finding, the canonical
campaign membership request and authenticated response and every occurrence
page, all hex-encoded. It is bounded to 1 GiB and is built by the CLI from the
campaign service.

## Self-check, result, and comparison

`FailureTriageSignatureSelfCheck::from_signature_pairs` compares each
finding's discovery-time and recomputed signatures. A record stores both
signature hashes and both report-material hashes (domain
`crucible.failure-triage.signature-self-check.v1`); `matched` requires identical
report material, so recomputed signatures equal discovery-time signatures
byte-for-byte or the finding is a mismatch. A mismatch means a signature
depended on something it must not, and it fails loudly: `assert_clean` errors,
`FailureTriageResult::from_parts` refuses to assemble the result, and the CLI
exits `1`. `FailureTriageSignatureSelfCheck::skipped()` records that no check
was requested.

`FailureTriageResult::from_parts(ledger, clustering, minimization, report_set,
self_check)` validates that every part describes the same `(findings ledger,
policy)` triage: matching policies; unique cluster ids, runs, and reports; a
self-check that is either skipped or covers exactly the clustered findings,
with discovery hashes matching the cluster members and no unmatched record;
and runs and reports bound to the same representatives, members, keys, and
minimal artifacts. Its
canonical material (`crucible.failure-triage.result.v1`) names the identity,
the hashes of each part, cluster and member counts, and per-report cluster id,
report hash, and minimal representative.

`FailureTriageResult::store(store)` writes `domain\nmaterial\n` bytes as a
content-addressed triage result in the DagStore. The stored key is the BLAKE3
hash of those bytes, and `FailureTriageStoredArtifact::cache_hit` reports
whether the object already existed, so triaging the same ledger twice under the
same policy deduplicates to one stored result.

`FailureTriageResult::compare_to(baseline)` returns a
`FailureTriageResultDiff`: a content diff over per-cluster report hashes, listing
added, removed, changed (with both report hashes), and unchanged clusters, not a
re-clustering. Its material is hashed under
`crucible.failure-triage.result-diff.v1`.

## CLI surface

Triage runs over the authenticated findings retained by a campaign snapshot:

```text
crucible [--format jsonl|json|table|markdown] [--artifact-dir <path>] \
  triage --campaign-socket <path> --principal <principal> \
  <NAME> --snapshot <SNAPSHOT> \
  [--policy coarse|default|fine|exact] \
  [--minimize none|representative|all] \
  [--report <dir>] [--recompute-signatures]
```

`crucible campaign --socket <path> --principal <principal> triage <NAME>
--snapshot <SNAPSHOT> ...` is the same operation under the campaign command;
the top-level form is rewritten into it by `dispatch`.

| Flag | Default | Effect |
|------|---------|--------|
| `--policy` | `default` | `TriagePolicyArg` mapped to `SignaturePolicy` |
| `--minimize` | `representative` | `none` records `not-requested`; `representative` minimizes each cluster's content-address-least member; `all` minimizes every member |
| `--report <dir>` | `--artifact-dir` | Directory for `triage-report.<ext>` |
| `--recompute-signatures` | off | Builds the self-check; any drift fails the run |
| global `--format` | `table` on a terminal, else `jsonl` | Report rendering |

`run_campaign_triage_invocation` is a thin driver. It pages the snapshot's
findings (at most `MAX_CAMPAIGN_TRIAGE_FINDINGS` = `65_536`), captures each
finding's authenticated evidence from the campaign service, encodes a campaign
ledger, and stores the ledger and result in `<artifact-dir>/campaign-triage-store`.
It then runs cluster, minimize representative, report, store, and prints one
summary line (`crucible: triage findings=campaign ...`) with the ledger and
result keys and their cache-hit flags. For campaign evidence, minimization does
not re-run candidates: it checks that the campaign's retained original and
selected replays, from both the minimization and verification passes, project
to the member's key under the active policy, and fails otherwise.

Exit codes follow the shared CLI mapping in [cli.md](cli.md):

| Exit | Cause |
|------|-------|
| `0` | Triage completed |
| `1` | `CliError::Triage`: clustering, minimization signature preservation, report construction, or self-check failure |
| `4` | `CliError::Backend` |
| `5` | Malformed or unresolvable ledger, artifact, store, or I/O failure |
| `64` | Usage error, including parse-time errors |

The engine also exposes `FailureTriageResult::compare_to` for result
comparison, but the CLI surface currently has no compare flag. Operator usage is
in [the user exploration guide](../../users/crucible/exploration.md).

## Content-hash domains

| Domain | Object |
|--------|--------|
| `crucible.failure-signature.v1` | Signature tuple |
| `crucible.failure-signature.key.v1` | Signature key, cluster id, policy |
| `crucible.failure-signature.causal-slice.v1` | Causal cone |
| `crucible.failure-signature.coverage-class.top16.v1` | Coverage bucketing algorithm label |
| `crucible.failure-triage.findings-ledger.v1` | Model findings ledger |
| `crucible.failure-triage.result-identity.v1` | `(ledger, policy)` identity |
| `crucible.failure-triage.signature-self-check.v1` | Self-check report-material hashes |
| `crucible.failure-triage.clustering-result.v1` | Clustering result |
| `crucible.failure-triage.signature-preserving-minimization.v1` | Minimization result |
| `crucible.failure-triage.cluster-report.v1` | One report |
| `crucible.failure-triage.cluster-report-set.v1` | Report set |
| `crucible.failure-triage.result.v1` | Triage result |
| `crucible.failure-triage.result-diff.v1` | Result diff |
