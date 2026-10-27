//! Content-addressed campaign findings ledger and its folding loader.
//!
//! A campaign findings ledger is a small manifest naming one evidence record
//! per finding in canonical finding-ID order. Records, occurrence chunks,
//! report projections, and every canonical request and response live beside
//! it in the same evidence store, so the manifest's content address commits to
//! all of them:
//!
//! ```text
//! crucible.failure-triage.findings-ledger.v5
//! ledger_kind=campaign
//! finding_count=1
//! finding.0=crucible.campaign.finding@... <record hash>
//! ```
//!
//! Loading authenticates one finding at a time and one occurrence at a time.
//! Only the clustering input stays resident: one signed `(artifact, signature)`
//! pair per distinct reproduction artifact, plus where in the ledger each
//! artifact's evidence lives. [`CampaignTriageEvidence`] re-reads a selected
//! member's report and replays on demand.

use super::record::CampaignFindingEvidenceRecord;
use super::service::{
    CampaignFindingAuthenticationContext, OccurrenceCursorCheck,
    authenticate_campaign_finding_head, authenticate_campaign_occurrence,
    authenticate_campaign_occurrences, validate_campaign_triage_finding,
};
use super::store::{parse_evidence_hash, put_evidence_blob, read_evidence_blob};
use super::*;
use crate::cli_triage_debug::ledger_format::{
    parse_reproduction_finding_evidence, parse_required_hash_field,
};

/// Manifest bound: about 150 bytes per finding for every triaged finding.
const MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

/// Report projection bound: its event frames are hexadecimal copies of a
/// replay payload, which is itself bounded.
const MAX_FINDING_REPORT_BYTES: usize =
    2 * crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES + 1024 * 1024;

/// Encodes the canonical ledger manifest for captured finding records.
///
/// Entries are sorted into canonical finding-ID order. A finding captured
/// twice with the same record is written once.
///
/// # Errors
///
/// Returns an error when one finding has two different records or the
/// manifest exceeds its bound.
pub(crate) fn campaign_findings_ledger_bytes(
    findings: &[(crucible_campaign::FindingId, crucible_engine::ContentHash)],
) -> Result<Vec<u8>, CliError> {
    let mut canonical = BTreeMap::new();
    for (finding, record) in findings {
        if let Some(existing) = canonical.insert(*finding, *record)
            && existing != *record
        {
            return Err(artifact_error(
                "cannot write conflicting evidence for one campaign snapshot finding",
            ));
        }
    }

    let mut text = format!(
        "{FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA}\nledger_kind=campaign\nfinding_count={}\n",
        canonical.len()
    );
    for (index, (finding, record)) in canonical.into_iter().enumerate() {
        text.push_str(&format!(
            "finding.{index}={} {}\n",
            finding.to_text(),
            record.to_hex()
        ));
    }
    if text.len() > MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES {
        return Err(artifact_error(format!(
            "campaign findings ledger exceeds {MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES} bytes"
        )));
    }
    Ok(text.into_bytes())
}

/// Stores the ledger manifest and reports whether it was already present.
///
/// # Errors
///
/// Returns an error when the manifest cannot be encoded or stored.
pub(crate) fn write_campaign_findings_ledger(
    store: &crucible_engine::LocalDagStore,
    findings: &[(crucible_campaign::FindingId, crucible_engine::ContentHash)],
) -> Result<crucible_engine::FailureTriageStoredArtifact, CliError> {
    let bytes = campaign_findings_ledger_bytes(findings)?;
    let key = crucible_engine::ContentHash::from_bytes(&bytes);
    let cache_hit = store.exists(&key).map_err(CliError::Store)?;
    if put_evidence_blob(store, &bytes)? != key {
        return Err(artifact_error(
            "stored findings ledger key did not match content hash",
        ));
    }
    Ok(crucible_engine::FailureTriageStoredArtifact {
        key,
        cache_hit,
        size_bytes: bytes.len(),
    })
}

/// Loads and authenticates the ledger stored under `manifest` in `evidence`.
///
/// Derived reproduction artifacts are written to `artifacts`, which may be
/// the evidence store itself.
///
/// # Errors
///
/// Returns an error when the manifest or any blob it reaches is missing,
/// noncanonical, or unauthenticated, or two findings bind one reproduction
/// artifact to different native signatures.
pub(crate) fn load_campaign_findings_ledger(
    evidence: &crucible_engine::LocalDagStore,
    artifacts: &crucible_engine::LocalDagStore,
    manifest: crucible_engine::ContentHash,
) -> Result<LoadedTriageFindings, CliError> {
    let bytes = read_evidence_blob(
        evidence,
        manifest,
        MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES,
        "campaign findings ledger",
    )?;
    load_campaign_findings_ledger_bytes(evidence, artifacts, &bytes)
}

/// Loads and authenticates a ledger manifest supplied as bytes.
///
/// # Errors
///
/// Returns the same errors as [`load_campaign_findings_ledger`].
pub(crate) fn load_campaign_findings_ledger_bytes(
    evidence: &crucible_engine::LocalDagStore,
    artifacts: &crucible_engine::LocalDagStore,
    bytes: &[u8],
) -> Result<LoadedTriageFindings, CliError> {
    if bytes.len() > MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES {
        return Err(artifact_error(format!(
            "campaign findings ledger exceeds {MAX_CAMPAIGN_FINDINGS_MANIFEST_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| artifact_error("campaign findings ledger is not UTF-8"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| artifact_error("campaign findings ledger does not end with a line feed"))?;
    let mut lines = body.split('\n');
    if lines.next() != Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA)
        || lines.next() != Some("ledger_kind=campaign")
    {
        return Err(artifact_error(
            "unsupported campaign findings ledger schema",
        ));
    }
    let finding_count = lines
        .next()
        .and_then(|line| line.strip_prefix("finding_count="))
        .and_then(|value| {
            value
                .parse::<usize>()
                .ok()
                .filter(|count| count.to_string() == value)
        })
        .ok_or_else(|| artifact_error("malformed campaign findings count"))?;

    let mut fold = CampaignTriageFold::default();
    let mut records = Vec::new();
    let mut previous = None;
    for index in 0..finding_count {
        let (finding, record) = lines
            .next()
            .and_then(|line| line.strip_prefix(&format!("finding.{index}=")))
            .and_then(|value| value.split_once(' '))
            .ok_or_else(|| {
                artifact_error("campaign findings ledger count or indices are not canonical")
            })?;
        let finding = crucible_campaign::FindingId::parse(finding)
            .map_err(|error| artifact_error(format!("finding {index} ID is invalid: {error}")))?;
        if previous.is_some_and(|previous| previous >= finding) {
            return Err(artifact_error(
                "campaign findings are not in canonical finding-ID order",
            ));
        }
        previous = Some(finding);
        let record = parse_evidence_hash("finding record", record)?;
        fold_campaign_finding(evidence, artifacts, index, finding, record, &mut fold)?;
        records.push(record);
    }
    if lines.next().is_some() {
        return Err(artifact_error(
            "campaign findings ledger count or indices are not canonical",
        ));
    }

    let ledger = crucible_engine::FailureFindingsLedger::from_signed_findings(fold.signed)
        .map_err(|_| artifact_error("campaign findings contain conflicting signatures"))?;
    Ok(LoadedTriageFindings {
        ledger,
        evidence: CampaignTriageEvidence {
            evidence_store: evidence.clone(),
            artifact_store: artifacts.clone(),
            records,
            members: fold
                .members
                .into_iter()
                .map(|(artifact, (_, location))| (artifact, location))
                .collect(),
        },
    })
}

/// Authenticates one finding and adds its clustering members to `fold`.
fn fold_campaign_finding(
    evidence: &crucible_engine::LocalDagStore,
    artifacts: &crucible_engine::LocalDagStore,
    index: usize,
    finding: crucible_campaign::FindingId,
    record_key: crucible_engine::ContentHash,
    fold: &mut CampaignTriageFold,
) -> Result<(), CliError> {
    let record = CampaignFindingEvidenceRecord::read(evidence, record_key)?;
    if record.finding != finding {
        return Err(artifact_error(format!(
            "finding {index} evidence record names another finding"
        )));
    }
    let item = authenticate_campaign_finding(evidence, artifacts, index, &record)?;
    let report_artifact = item.report.finding.artifact.id();

    // Each occurrence contributes its minimization-original replay. The
    // finding's own report joins only when no occurrence covers it, so a
    // representative without replay evidence is never projected onto another
    // occurrence's signature.
    let mut covered = false;
    let context = CampaignFindingAuthenticationContext {
        index,
        record: &record,
        finding: &item.finding,
        template: &item.report,
        evidence,
    };
    authenticate_campaign_occurrences(context, &mut |occurrence, role, native| {
        if role != crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal {
            return Ok(());
        }
        let artifact = native.finding().artifact.id();
        let stored = artifacts
            .put(&native.finding().artifact.to_compact_binary())
            .map_err(CliError::Store)?;
        if stored != artifact {
            return Err(artifact_error(format!(
                "finding {index} occurrence reproduction payload has the wrong identity"
            )));
        }
        covered |= artifact == report_artifact;
        fold.insert(
            artifact,
            native.signature().clone(),
            CampaignTriageMemberLocation {
                finding: index,
                occurrence: Some(occurrence),
            },
        )
    })?;
    if !covered {
        fold.insert(
            report_artifact,
            item.report.discovery_signature.clone(),
            CampaignTriageMemberLocation {
                finding: index,
                occurrence: None,
            },
        )?;
    }
    Ok(())
}

/// Authenticates one record's finding-level exchanges and report projection.
fn authenticate_campaign_finding(
    evidence: &crucible_engine::LocalDagStore,
    artifacts: &crucible_engine::LocalDagStore,
    index: usize,
    record: &CampaignFindingEvidenceRecord,
) -> Result<CampaignTriageFindingEvidence, CliError> {
    let head = authenticate_campaign_finding_head(index, evidence, record)?;
    let report = load_campaign_finding_report(
        evidence,
        artifacts,
        index,
        record,
        &head.reproduction_artifact,
    )?;
    let item = CampaignTriageFindingEvidence {
        campaign: record.campaign.clone(),
        snapshot: record.snapshot,
        finding: head.finding,
        observation: head.observation,
        reproduction: head.reproduction,
        minimized_reproduction: head.minimized_reproduction,
        minimized_artifact: head.minimized_artifact,
        report,
        occurrence_count: record.occurrence_count,
    };
    validate_campaign_triage_finding(index, record.finding, &item)?;
    Ok(item)
}

/// Reads one report projection and binds it to the authenticated
/// reproduction's Crucible artifact.
fn load_campaign_finding_report(
    evidence: &crucible_engine::LocalDagStore,
    artifacts: &crucible_engine::LocalDagStore,
    index: usize,
    record: &CampaignFindingEvidenceRecord,
    reproduction: &crucible_engine::ReproductionArtifact,
) -> Result<TriageFindingEvidence, CliError> {
    let bytes = read_evidence_blob(
        evidence,
        record.report,
        MAX_FINDING_REPORT_BYTES,
        "finding report projection",
    )?;
    let fields = parse_finding_report_fields(&bytes)?;
    let expected_model_artifact = parse_required_hash_field(&fields, "artifact")?;
    let stored_model_artifact = artifacts
        .put(&reproduction.to_compact_binary())
        .map_err(CliError::Store)?;
    if stored_model_artifact != expected_model_artifact {
        return Err(artifact_error(format!(
            "finding {index} campaign reproduction payload differs from its report artifact"
        )));
    }
    parse_reproduction_finding_evidence(artifacts, index, &fields)
}

/// Parses a single-finding reproduction ledger into its report fields.
fn parse_finding_report_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| artifact_error("finding report projection is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA)
        || lines.next() != Some("ledger_kind=reproduction")
        || lines.next() != Some("finding_count=1")
    {
        return Err(artifact_error(
            "unsupported finding report projection schema",
        ));
    }
    let mut fields = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (field, value) = line
            .strip_prefix("finding.0.")
            .and_then(|field_value| field_value.split_once('='))
            .ok_or_else(|| artifact_error("malformed finding report projection field"))?;
        if fields.insert(field.to_owned(), value.to_owned()).is_some() {
            return Err(artifact_error("duplicate finding report projection field"));
        }
    }
    Ok(fields)
}

/// Where one clustered reproduction artifact's evidence lives in the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CampaignTriageMemberLocation {
    finding: usize,
    /// `None` names the finding's own report projection.
    occurrence: Option<u64>,
}

/// Clustering input accumulated while a ledger loads.
#[derive(Default)]
struct CampaignTriageFold {
    signed: Vec<crucible_engine::FailureClusterFinding>,
    members: BTreeMap<crucible_engine::ContentHash, (usize, CampaignTriageMemberLocation)>,
}

impl CampaignTriageFold {
    /// Adds one member; the first location of an artifact wins.
    fn insert(
        &mut self,
        artifact: crucible_engine::ContentHash,
        signature: crucible_engine::FailureSignature,
        location: CampaignTriageMemberLocation,
    ) -> Result<(), CliError> {
        match self.members.entry(artifact) {
            Entry::Vacant(entry) => {
                entry.insert((self.signed.len(), location));
                self.signed
                    .push(crucible_engine::FailureClusterFinding::new(artifact, signature));
            }
            Entry::Occupied(entry)
                if self.signed.get(entry.get().0).is_some_and(|existing| {
                    existing.signature.report_material() == signature.report_material()
                }) => {}
            Entry::Occupied(_) => {
                return Err(artifact_error(
                    "campaign findings repeat a reproduction artifact with conflicting authenticated native signatures",
                ));
            }
        }
        Ok(())
    }
}

/// Authenticated ledger evidence that loads members on demand.
///
/// Holds two store handles, one record key per finding, and one location per
/// clustered artifact. Every accessor re-reads content-addressed blobs, so
/// the bytes it decodes are exactly the ones authenticated at load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CampaignTriageEvidence {
    evidence_store: crucible_engine::LocalDagStore,
    artifact_store: crucible_engine::LocalDagStore,
    records: Vec<crucible_engine::ContentHash>,
    members: BTreeMap<crucible_engine::ContentHash, CampaignTriageMemberLocation>,
}

/// One clustered member's finding records, report, and native replays.
pub(crate) struct CampaignTriageMember {
    pub(crate) finding: CampaignTriageFindingEvidence,
    /// Native replays of the member's occurrence; `None` when the member is
    /// the finding's own report projection.
    pub(super) replays: Option<CampaignOccurrenceNativeTriageReplays>,
}

impl CampaignTriageMember {
    /// Reports whether the member was loaded with its occurrence's replays.
    #[cfg(test)]
    pub(crate) fn retains_occurrence_replays(&self) -> bool {
        self.replays.is_some()
    }

    /// Returns the member's report evidence as clustered at load.
    ///
    /// # Errors
    ///
    /// Returns an error when a retained replay's log can no longer be read.
    pub(crate) fn report(&self) -> Result<TriageFindingEvidence, CliError> {
        self.replays.as_ref().map_or_else(
            || Ok(self.finding.report.clone()),
            |replays| triage_finding_evidence_from_replay(&replays.minimization_original),
        )
    }
}

impl CampaignTriageEvidence {
    /// Returns the number of findings in the ledger.
    pub(crate) fn finding_count(&self) -> usize {
        self.records.len()
    }

    /// Returns clustered reproduction artifacts in ascending order.
    pub(crate) fn member_artifacts(&self) -> impl Iterator<Item = crucible_engine::ContentHash> + '_ {
        self.members.keys().copied()
    }

    /// Re-reads and re-authenticates one finding's finding-level records.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` is outside the ledger or its evidence can
    /// no longer be read.
    pub(crate) fn finding(&self, index: usize) -> Result<CampaignTriageFindingEvidence, CliError> {
        let key = self
            .records
            .get(index)
            .copied()
            .ok_or_else(|| artifact_error("campaign finding index is outside its ledger"))?;
        let record = CampaignFindingEvidenceRecord::read(&self.evidence_store, key)?;
        authenticate_campaign_finding(&self.evidence_store, &self.artifact_store, index, &record)
    }

    /// Loads one clustered member, or `None` when `artifact` is not clustered.
    ///
    /// # Errors
    ///
    /// Returns an error when the member's evidence can no longer be read or
    /// decoded.
    pub(crate) fn member(
        &self,
        artifact: crucible_engine::ContentHash,
    ) -> Result<Option<CampaignTriageMember>, CliError> {
        let Some(location) = self.members.get(&artifact).copied() else {
            return Ok(None);
        };
        let key =
            self.records.get(location.finding).copied().ok_or_else(|| {
                artifact_error("campaign member names a finding outside its ledger")
            })?;
        let record = CampaignFindingEvidenceRecord::read(&self.evidence_store, key)?;
        let finding = authenticate_campaign_finding(
            &self.evidence_store,
            &self.artifact_store,
            location.finding,
            &record,
        )?;
        let replays = match location.occurrence {
            None => None,
            Some(occurrence) => {
                let exchanges = record.read_occurrence(&self.evidence_store, occurrence)?;
                let mut collected = CampaignOccurrenceReplayCollector::default();
                authenticate_campaign_occurrence(
                    CampaignFindingAuthenticationContext {
                        index: location.finding,
                        record: &record,
                        finding: &finding.finding,
                        template: &finding.report,
                        evidence: &self.evidence_store,
                    },
                    occurrence,
                    &exchanges,
                    OccurrenceCursorCheck::Loaded,
                    &mut |_, role, native| collected.insert(role, native),
                )?;
                Some(collected.finish()?)
            }
        };
        Ok(Some(CampaignTriageMember { finding, replays }))
    }

    /// Loads one clustered member's report evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when `artifact` is not clustered or its evidence can
    /// no longer be read.
    pub(crate) fn member_report(
        &self,
        artifact: crucible_engine::ContentHash,
    ) -> Result<TriageFindingEvidence, CliError> {
        self.member(artifact)?
            .map(|member| member.report())
            .ok_or_else(|| artifact_error("missing member evidence in findings ledger"))?
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn manifest_orders_findings_and_rejects_conflicting_records() {
        let finding = |label: &[u8]| {
            crucible_campaign::FindingId::parse(&format!(
                "crucible.campaign.finding@{}",
                crucible_store::content_store::ContentId::for_bytes(
                    crucible_campaign::CampaignRecordKind::Finding.object_kind(),
                    crucible_campaign::CampaignRecordKind::Finding.schema_version(),
                    label,
                )
            ))
            .expect("finding ID")
        };
        let (first, second) = {
            let left = finding(b"left");
            let right = finding(b"right");
            if left < right {
                (left, right)
            } else {
                (right, left)
            }
        };
        let record = crucible_engine::ContentHash::from_bytes(b"record");
        let other = crucible_engine::ContentHash::from_bytes(b"other record");

        let bytes =
            campaign_findings_ledger_bytes(&[(second, other), (first, record), (first, record)])
                .expect("manifest encodes");
        let text = String::from_utf8(bytes).expect("manifest is UTF-8");
        assert_eq!(
            text,
            format!(
                "{FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA}\nledger_kind=campaign\nfinding_count=2\nfinding.0={} {}\nfinding.1={} {}\n",
                first.to_text(),
                record.to_hex(),
                second.to_text(),
                other.to_hex()
            )
        );
        assert!(campaign_findings_ledger_bytes(&[(first, record), (first, other)]).is_err());
    }

    #[test]
    fn manifest_loader_rejects_old_and_noncanonical_headers_before_reading_records() {
        let directory = tempfile::tempdir().expect("temporary store");
        let store = crucible_engine::LocalDagStore::new(directory.path());
        for rejected in [
            "crucible.failure-triage.findings-ledger.v4\nledger_kind=campaign\nfinding_count=0\n",
            "crucible.failure-triage.findings-ledger.v5\nledger_kind=reproduction\nfinding_count=0\n",
            "crucible.failure-triage.findings-ledger.v5\nledger_kind=campaign\nfinding_count=00\n",
            "crucible.failure-triage.findings-ledger.v5\nledger_kind=campaign\nfinding_count=0",
            "crucible.failure-triage.findings-ledger.v5\nledger_kind=campaign\nfinding_count=0\nfinding.0=x y\n",
        ] {
            assert!(
                load_campaign_findings_ledger_bytes(&store, &store, rejected.as_bytes()).is_err(),
                "{rejected:?} must be rejected"
            );
        }
        let empty = load_campaign_findings_ledger_bytes(
            &store,
            &store,
            b"crucible.failure-triage.findings-ledger.v5\nledger_kind=campaign\nfinding_count=0\n",
        )
        .expect("an empty ledger loads");
        assert_eq!(empty.evidence.finding_count(), 0);
    }
}
