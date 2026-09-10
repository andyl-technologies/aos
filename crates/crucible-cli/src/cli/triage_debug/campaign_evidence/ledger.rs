//! Versioned text encoding for authenticated campaign Finding evidence.
//!
//! V4 embeds each canonical request and authenticated response as lowercase
//! hexadecimal while keeping finding and occurrence counts explicit:
//!
//! ```text
//! crucible.failure-triage.findings-ledger.v4
//! finding_count=1
//! finding.0.campaign=nightly-search
//! finding.0.campaign_snapshot=crucible-campaign-snapshot:...
//! finding.0.campaign_membership_request_hex=...
//! finding.0.campaign_membership_response_hex=...
//! finding.0.campaign_occurrence_page_count=1
//! finding.0.campaign_occurrence.0.request_hex=...
//! finding.0.campaign_occurrence.0.response_hex=...
//! ```

use super::guarded_export::campaign_triage_evidence_from_guarded_exports;
use super::service::{authenticate_campaign_triage_finding, validate_campaign_triage_finding};
use super::*;

const MAX_FAILURE_FINDINGS_LEDGER_V4_BYTES: usize = 1024 * 1024 * 1024;

struct BoundedV4Ledger {
    bytes: Vec<u8>,
    encoded_bytes: usize,
    exceeded_limit: bool,
    maximum_bytes: usize,
}

impl BoundedV4Ledger {
    fn with_maximum_bytes(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            encoded_bytes: 0,
            exceeded_limit: false,
            maximum_bytes,
        }
    }

    fn push(&mut self, line: String) {
        if self.exceeded_limit {
            return;
        }
        let Some(next_len) = self
            .encoded_bytes
            .checked_add(line.len())
            .and_then(|length| length.checked_add(1))
        else {
            self.exceeded_limit = true;
            return;
        };
        if next_len > self.maximum_bytes {
            self.exceeded_limit = true;
            return;
        }

        self.bytes.extend_from_slice(line.as_bytes());
        self.bytes.push(b'\n');
        self.encoded_bytes = next_len;
    }

    fn finish(self) -> Result<Vec<u8>, CliError> {
        if self.exceeded_limit {
            let maximum_bytes = self.maximum_bytes;
            return Err(artifact_error(format!(
                "V4 campaign findings ledger exceeds {maximum_bytes} bytes"
            )));
        }
        Ok(self.bytes)
    }
}

fn parse_campaign_hex_bytes(index: usize, field: &str, value: &str) -> Result<Vec<u8>, CliError> {
    let maximum_hex_bytes = crucible_campaign::MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES
        .checked_mul(2)
        .ok_or_else(|| artifact_error("campaign service hex size bound overflow"))?;
    if value.len() > maximum_hex_bytes {
        return Err(artifact_error(format!(
            "finding {index} `{field}` exceeds the campaign message bound"
        )));
    }
    super::parse_hex_bytes(index, field, value)
}

pub(crate) fn parse_failure_findings_ledger_v4_bytes(
    store: &crucible::LocalDagStore,
    bytes: &[u8],
    text: &str,
) -> Result<LoadedTriageFindings, CliError> {
    if bytes.len() > MAX_FAILURE_FINDINGS_LEDGER_V4_BYTES {
        return Err(artifact_error(format!(
            "V4 campaign findings ledger exceeds {MAX_FAILURE_FINDINGS_LEDGER_V4_BYTES} bytes"
        )));
    }

    let mut by_index = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut finding_count = None;
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("finding_count=") {
            if finding_count
                .replace(
                    value
                        .parse::<usize>()
                        .map_err(|_| artifact_error("malformed v4 findings count"))?,
                )
                .is_some()
            {
                return Err(artifact_error("duplicate v4 findings count"));
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("finding.") else {
            return Err(artifact_error("malformed v4 campaign findings ledger line"));
        };
        let Some((index, field_value)) = rest.split_once('.') else {
            return Err(artifact_error(
                "malformed v4 campaign findings ledger field",
            ));
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| artifact_error("malformed v4 campaign findings ledger index"))?;
        let Some((field, value)) = field_value.split_once('=') else {
            return Err(artifact_error(
                "malformed v4 campaign findings ledger value",
            ));
        };
        if by_index
            .entry(index)
            .or_default()
            .insert(field.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(artifact_error(
                "duplicate v4 campaign findings ledger field",
            ));
        }
    }
    let finding_count = finding_count
        .ok_or_else(|| artifact_error("v4 campaign findings ledger is missing finding count"))?;
    if by_index.len() != finding_count || by_index.keys().copied().ne(0..finding_count) {
        return Err(artifact_error(
            "v4 campaign findings ledger count or indices are not canonical",
        ));
    }

    let mut signed_findings = Vec::new();
    let mut report_evidence = BTreeMap::new();
    let mut campaign_evidence = Vec::new();
    let mut previous_finding_id = None;
    for (index, fields) in by_index {
        let item = parse_triage_v4_finding_evidence(store, index, &fields)?;
        let finding_id = item
            .finding
            .id()
            .map_err(|error| artifact_error(format!("finding {index} ID is invalid: {error}")))?;
        if previous_finding_id.is_some_and(|previous| previous >= finding_id) {
            return Err(artifact_error(
                "v4 campaign findings are not in canonical finding-ID order",
            ));
        }
        previous_finding_id = Some(finding_id);
        let mut occurrence_reports = Vec::new();
        for occurrence in campaign_occurrences(&item) {
            let Some(replays) =
                campaign_occurrence_native_triage_replays(occurrence, &item.report)?
            else {
                continue;
            };
            let report = triage_finding_evidence_from_replay(&replays.minimization_original);
            let stored = store
                .put(&report.finding.artifact.to_compact_binary())
                .map_err(CliError::Store)?;
            if stored != report.finding.artifact.id() {
                return Err(artifact_error(format!(
                    "finding {index} occurrence reproduction payload has the wrong identity"
                )));
            }
            occurrence_reports.push(report);
        }
        if occurrence_reports
            .iter()
            .all(|report| report.finding.artifact.id() != item.report.finding.artifact.id())
        {
            // Schema-v1 candidate bundles do not contain native replay evidence.
            // Preserve only the independently recorded representative instead
            // of projecting its signature onto unrelated occurrences.
            occurrence_reports.push(item.report.clone());
        }
        for report in occurrence_reports {
            let artifact = report.finding.artifact.id();
            match report_evidence.entry(artifact) {
                Entry::Vacant(entry) => {
                    signed_findings.push(crucible::FailureClusterFinding::new(
                        artifact,
                        report.discovery_signature.clone(),
                    ));
                    entry.insert(report);
                }
                Entry::Occupied(entry)
                    if entry.get().discovery_signature.report_material()
                        == report.discovery_signature.report_material() => {}
                Entry::Occupied(_) => {
                    return Err(artifact_error(
                        "v4 campaign findings repeat a reproduction artifact with conflicting authenticated native signatures",
                    ));
                }
            }
        }
        campaign_evidence.push(item);
    }
    let ledger = crucible::FailureFindingsLedger::from_signed_findings(signed_findings)
        .map_err(|_| artifact_error("v4 campaign findings contain conflicting signatures"))?;
    Ok(LoadedTriageFindings {
        ledger,
        evidence: report_evidence,
        campaign_evidence,
        artifact_bytes: bytes.to_vec(),
    })
}

fn parse_triage_v4_finding_evidence(
    store: &crucible::LocalDagStore,
    index: usize,
    fields: &BTreeMap<String, String>,
) -> Result<CampaignTriageFindingEvidence, CliError> {
    let campaign = crucible_campaign::CampaignName::new(required_field(fields, "campaign")?)
        .map_err(|error| artifact_error(format!("finding {index} campaign is invalid: {error}")))?;
    let snapshot =
        crucible_campaign::CampaignSnapshotId::parse(required_field(fields, "campaign_snapshot")?)
            .map_err(|error| {
                artifact_error(format!("finding {index} snapshot is invalid: {error}"))
            })?;
    let membership = CampaignFindingsMembershipProof {
        request: crucible_campaign::QueryCampaignFindingsRequest::from_canonical_bytes(
            &parse_campaign_hex_bytes(
                index,
                "campaign_membership_request_hex",
                required_field(fields, "campaign_membership_request_hex")?,
            )?,
        )
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} membership request is invalid: {error}"
            ))
        })?,
        response: crucible_campaign::QueryCampaignFindingsResponse::from_canonical_bytes(
            &parse_campaign_hex_bytes(
                index,
                "campaign_membership_response_hex",
                required_field(fields, "campaign_membership_response_hex")?,
            )?,
        )
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} membership response is invalid: {error}"
            ))
        })?,
    };
    let observation_proof = parse_campaign_finding_object_proof(
        index,
        fields,
        "campaign_observation_request_hex",
        "campaign_observation_response_hex",
    )?;
    let reproduction_proof = parse_campaign_finding_object_proof(
        index,
        fields,
        "campaign_reproduction_request_hex",
        "campaign_reproduction_response_hex",
    )?;
    let minimized_reproduction_proof =
        match required_field(fields, "campaign_minimized_request_hex")? {
            "none" => {
                if required_field(fields, "campaign_minimized_response_hex")? != "none" {
                    return Err(artifact_error(format!(
                        "finding {index} minimized campaign proof is incomplete"
                    )));
                }
                None
            }
            request => {
                if required_field(fields, "campaign_minimized_response_hex")? == "none" {
                    return Err(artifact_error(format!(
                        "finding {index} minimized campaign proof is incomplete"
                    )));
                }
                Some(parse_campaign_finding_object_proof_bytes(
                    index,
                    request,
                    required_field(fields, "campaign_minimized_response_hex")?,
                )?)
            }
        };
    let occurrence_page_count = required_field(fields, "campaign_occurrence_page_count")?
        .parse::<usize>()
        .map_err(|_| artifact_error(format!("finding {index} occurrence page count is invalid")))?;
    if occurrence_page_count > crucible_campaign::MAX_FINDING_OCCURRENCES as usize {
        return Err(artifact_error(format!(
            "finding {index} occurrence page count exceeds the campaign bound"
        )));
    }
    let mut occurrence_proofs = Vec::with_capacity(occurrence_page_count);
    for page in 0..occurrence_page_count {
        let request_field = format!("campaign_occurrence.{page}.request_hex");
        let response_field = format!("campaign_occurrence.{page}.response_hex");
        let request_value = fields.get(&request_field).ok_or_else(|| {
            artifact_error(format!("finding {index} is missing `{request_field}`"))
        })?;
        let response_value = fields.get(&response_field).ok_or_else(|| {
            artifact_error(format!("finding {index} is missing `{response_field}`"))
        })?;
        let request =
            crucible_campaign::QueryCampaignFindingOccurrencesRequest::from_canonical_bytes(
                &parse_campaign_hex_bytes(index, &request_field, request_value)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence page {page} request is invalid: {error}"
                ))
            })?;
        let response =
            crucible_campaign::QueryCampaignFindingOccurrencesResponse::from_canonical_bytes(
                &parse_campaign_hex_bytes(index, &response_field, response_value)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence page {page} response is invalid: {error}"
                ))
            })?;
        let page_proof = CampaignFindingOccurrencesProof { request, response };
        let observation =
            parse_campaign_finding_occurrence_object_proof(index, page, fields, "observation")?;
        let reproduction =
            parse_campaign_finding_occurrence_object_proof(index, page, fields, "reproduction")?;
        let minimized_reproduction =
            parse_campaign_finding_occurrence_object_proof(index, page, fields, "minimized")?;
        let triage_evidence = parse_campaign_finding_occurrence_triage_proof(
            index,
            page,
            fields,
            page_proof
                .response
                .entries()
                .first()
                .and_then(|entry| entry.bundle().triage_evidence())
                .is_some(),
        )?;
        occurrence_proofs.push(CampaignFindingOccurrenceProof {
            page: page_proof,
            observation,
            reproduction,
            minimized_reproduction,
            triage_evidence,
        });
    }
    let finding = crucible_campaign::Finding::from_canonical_bytes(&parse_campaign_hex_bytes(
        index,
        "campaign_finding_hex",
        required_field(fields, "campaign_finding_hex")?,
    )?)
    .map_err(|error| artifact_error(format!("finding {index} body is invalid: {error}")))?;
    let observation = crucible_campaign::Observation::from_canonical_bytes(
        &parse_campaign_hex_bytes(
            index,
            "campaign_observation_hex",
            required_field(fields, "campaign_observation_hex")?,
        )?,
    )
    .map_err(|error| artifact_error(format!("finding {index} observation is invalid: {error}")))?;
    let reproduction =
        crucible_campaign::ReproductionArtifact::from_canonical_bytes(&parse_campaign_hex_bytes(
            index,
            "campaign_reproduction_hex",
            required_field(fields, "campaign_reproduction_hex")?,
        )?)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign reproduction is invalid: {error}"
            ))
        })?;
    let minimized_reproduction = match required_field(fields, "campaign_minimized_hex")? {
        "none" => None,
        value => Some(
            crucible_campaign::ReproductionArtifact::from_canonical_bytes(
                &parse_campaign_hex_bytes(index, "campaign_minimized_hex", value)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} minimized campaign reproduction is invalid: {error}"
                ))
            })?,
        ),
    };
    let expected_finding_id =
        crucible_campaign::FindingId::parse(required_field(fields, "campaign_finding_id")?)
            .map_err(|error| artifact_error(format!("finding {index} ID is invalid: {error}")))?;

    let mut report_fields = fields.clone();
    for field in [
        "campaign",
        "campaign_snapshot",
        "campaign_finding_id",
        "campaign_membership_request_hex",
        "campaign_membership_response_hex",
        "campaign_observation_request_hex",
        "campaign_observation_response_hex",
        "campaign_reproduction_request_hex",
        "campaign_reproduction_response_hex",
        "campaign_minimized_request_hex",
        "campaign_minimized_response_hex",
        "campaign_occurrence_page_count",
        "campaign_finding_hex",
        "campaign_observation_hex",
        "campaign_reproduction_hex",
        "campaign_minimized_hex",
    ] {
        report_fields.remove(field);
    }
    for page in 0..occurrence_page_count {
        report_fields.remove(&format!("campaign_occurrence.{page}.request_hex"));
        report_fields.remove(&format!("campaign_occurrence.{page}.response_hex"));
        for object in ["observation", "reproduction", "minimized"] {
            report_fields.remove(&format!("campaign_occurrence.{page}.{object}_request_hex"));
            report_fields.remove(&format!("campaign_occurrence.{page}.{object}_response_hex"));
        }
        for object in [
            "minimization_original_triage",
            "minimization_selected_triage",
            "verification_original_triage",
            "verification_selected_triage",
        ] {
            let count_field = format!("campaign_occurrence.{page}.{object}_segment_count");
            if let Some(count) = report_fields.remove(&count_field)
                && count != "none"
            {
                let count = count.parse::<usize>().map_err(|_| {
                    artifact_error(format!(
                        "finding {index} occurrence {page} {object} segment count is invalid"
                    ))
                })?;
                for segment in 0..count {
                    report_fields.remove(&format!(
                        "campaign_occurrence.{page}.{object}.segment.{segment}.request_hex"
                    ));
                    report_fields.remove(&format!(
                        "campaign_occurrence.{page}.{object}.segment.{segment}.response_hex"
                    ));
                }
            }
        }
    }
    let expected_model_artifact = parse_required_hash_field(&report_fields, "artifact")?;
    let stored_model_artifact = store.put(reproduction.payload()).map_err(CliError::Store)?;
    if stored_model_artifact != expected_model_artifact {
        return Err(artifact_error(format!(
            "finding {index} campaign reproduction payload differs from its report artifact"
        )));
    }
    let report = parse_triage_v3_finding_evidence(store, index, &report_fields)?;
    let item = CampaignTriageFindingEvidence {
        campaign,
        snapshot,
        membership,
        observation_proof,
        reproduction_proof,
        minimized_reproduction_proof,
        occurrence_proofs,
        finding,
        observation,
        reproduction,
        minimized_reproduction,
        report,
    };
    authenticate_campaign_triage_finding(index, expected_finding_id, &item)?;
    validate_campaign_triage_finding(index, expected_finding_id, &item)?;
    Ok(item)
}

fn parse_campaign_finding_object_proof(
    index: usize,
    fields: &BTreeMap<String, String>,
    request_field: &'static str,
    response_field: &'static str,
) -> Result<CampaignFindingObjectProof, CliError> {
    parse_campaign_finding_object_proof_bytes(
        index,
        required_field(fields, request_field)?,
        required_field(fields, response_field)?,
    )
}

fn parse_campaign_finding_object_proof_bytes(
    index: usize,
    request: &str,
    response: &str,
) -> Result<CampaignFindingObjectProof, CliError> {
    let request = crucible_campaign::GetCampaignFindingObjectRequest::from_canonical_bytes(
        &parse_campaign_hex_bytes(index, "campaign object request", request)?,
    )
    .map_err(|error| {
        artifact_error(format!(
            "finding {index} campaign object request is invalid: {error}"
        ))
    })?;
    let response = crucible_campaign::GetCampaignFindingObjectResponse::from_canonical_bytes(
        &parse_campaign_hex_bytes(index, "campaign object response", response)?,
    )
    .map_err(|error| {
        artifact_error(format!(
            "finding {index} campaign object response is invalid: {error}"
        ))
    })?;
    Ok(CampaignFindingObjectProof { request, response })
}

fn parse_campaign_finding_occurrence_object_proof(
    index: usize,
    occurrence: usize,
    fields: &BTreeMap<String, String>,
    object: &str,
) -> Result<CampaignFindingOccurrenceObjectProof, CliError> {
    let request_field = format!("campaign_occurrence.{occurrence}.{object}_request_hex");
    let response_field = format!("campaign_occurrence.{occurrence}.{object}_response_hex");
    let request = fields
        .get(&request_field)
        .ok_or_else(|| artifact_error(format!("finding {index} is missing `{request_field}`")))?;
    let response = fields
        .get(&response_field)
        .ok_or_else(|| artifact_error(format!("finding {index} is missing `{response_field}`")))?;
    let request =
        crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::from_canonical_bytes(
            &parse_campaign_hex_bytes(index, &request_field, request)?,
        )
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} occurrence {occurrence} {object} request is invalid: {error}"
            ))
        })?;
    let response =
        crucible_campaign::GetCampaignFindingOccurrenceObjectResponse::from_canonical_bytes(
            &parse_campaign_hex_bytes(index, &response_field, response)?,
        )
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} occurrence {occurrence} {object} response is invalid: {error}"
            ))
        })?;
    Ok(CampaignFindingOccurrenceObjectProof { request, response })
}

fn parse_campaign_finding_occurrence_triage_proof(
    index: usize,
    occurrence: usize,
    fields: &BTreeMap<String, String>,
    expected: bool,
) -> Result<Option<CampaignFindingOccurrenceTriageProof>, CliError> {
    let parsed = [
        "minimization_original_triage",
        "minimization_selected_triage",
        "verification_original_triage",
        "verification_selected_triage",
    ]
    .map(|object| {
        let count_field = format!("campaign_occurrence.{occurrence}.{object}_segment_count");
        let count = fields.get(&count_field).ok_or_else(|| {
            artifact_error(format!("finding {index} is missing `{count_field}`"))
        })?;
        if count == "none" {
            return Ok(None);
        }
        let count = count.parse::<usize>().map_err(|_| {
            artifact_error(format!(
                "finding {index} occurrence {occurrence} {object} segment count is invalid"
            ))
        })?;
        if count == 0 || count > 8 {
            return Err(artifact_error(format!(
                "finding {index} occurrence {occurrence} {object} segment count exceeds its bound"
            )));
        }
        let mut segments = Vec::with_capacity(count);
        for segment in 0..count {
            let request_field = format!(
                "campaign_occurrence.{occurrence}.{object}.segment.{segment}.request_hex"
            );
            let response_field = format!(
                "campaign_occurrence.{occurrence}.{object}.segment.{segment}.response_hex"
            );
            let request = fields.get(&request_field).ok_or_else(|| {
                artifact_error(format!("finding {index} is missing `{request_field}`"))
            })?;
            let response = fields.get(&response_field).ok_or_else(|| {
                artifact_error(format!("finding {index} is missing `{response_field}`"))
            })?;
            let request = crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::from_canonical_bytes(
                &parse_campaign_hex_bytes(index, &request_field, request)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence {occurrence} {object} segment {segment} request is invalid: {error}"
                ))
            })?;
            let response = crucible_campaign::GetCampaignFindingTriageReplaySegmentResponse::from_canonical_bytes(
                &parse_campaign_hex_bytes(index, &response_field, response)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence {occurrence} {object} segment {segment} response is invalid: {error}"
                ))
            })?;
            segments.push(CampaignFindingTriageReplaySegmentProof { request, response });
        }
        Ok(Some(CampaignFindingTriageReplayProof { segments }))
    });
    let [
        minimization_original,
        minimization_selected,
        verification_original,
        verification_selected,
    ] = parsed;
    let complete = match (
        minimization_original?,
        minimization_selected?,
        verification_original?,
        verification_selected?,
    ) {
        (
            Some(minimization_original),
            Some(minimization_selected),
            Some(verification_original),
            Some(verification_selected),
        ) => Some(CampaignFindingOccurrenceTriageProof {
            minimization_original,
            minimization_selected,
            verification_original,
            verification_selected,
        }),
        (None, None, None, None) => None,
        _ => {
            return Err(artifact_error(format!(
                "finding {index} occurrence {occurrence} has an incomplete triage replay set"
            )));
        }
    };
    if complete.is_some() != expected {
        return Err(artifact_error(format!(
            "finding {index} occurrence {occurrence} triage replay set disagrees with its bundle schema"
        )));
    }
    Ok(complete)
}

pub(super) fn failure_findings_ledger_v4_bytes(
    evidence: &[CampaignTriageFindingEvidence],
) -> Result<Vec<u8>, CliError> {
    failure_findings_ledger_v4_bytes_with_limit(evidence, MAX_FAILURE_FINDINGS_LEDGER_V4_BYTES)
}

fn failure_findings_ledger_v4_bytes_with_limit(
    evidence: &[CampaignTriageFindingEvidence],
    maximum_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    let mut canonical_evidence = BTreeMap::new();
    for item in evidence {
        let finding_id = item
            .finding
            .id()
            .map_err(|error| artifact_error(format!("campaign finding ID is invalid: {error}")))?;
        authenticate_campaign_triage_finding(0, finding_id, item)?;
        validate_campaign_triage_finding(0, finding_id, item)?;
        let scope = (
            item.campaign.as_str().to_owned(),
            item.snapshot.to_text(),
            finding_id.to_text(),
        );
        if let Some((_, existing)) = canonical_evidence.insert(scope, (finding_id, item))
            && existing != item
        {
            return Err(artifact_error(
                "cannot write conflicting evidence for one campaign snapshot finding",
            ));
        }
    }

    let mut lines = BoundedV4Ledger::with_maximum_bytes(maximum_bytes);
    lines.push(String::from(FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V4));
    lines.push(format!("finding_count={}", canonical_evidence.len()));
    for (index, (_, (finding_id, item))) in canonical_evidence.into_iter().enumerate() {
        let prefix = format!("finding.{index}");
        lines.push(format!("{prefix}.campaign={}", item.campaign.as_str()));
        lines.push(format!(
            "{prefix}.campaign_snapshot={}",
            item.snapshot.to_text()
        ));
        lines.push(format!(
            "{prefix}.campaign_finding_id={}",
            finding_id.to_text()
        ));
        lines.push(format!(
            "{prefix}.campaign_membership_request_hex={}",
            ledger_hex(&item.membership.request.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_membership_response_hex={}",
            ledger_hex(&item.membership.response.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_observation_request_hex={}",
            ledger_hex(&item.observation_proof.request.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_observation_response_hex={}",
            ledger_hex(&item.observation_proof.response.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_reproduction_request_hex={}",
            ledger_hex(&item.reproduction_proof.request.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_reproduction_response_hex={}",
            ledger_hex(&item.reproduction_proof.response.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_minimized_request_hex={}",
            item.minimized_reproduction_proof.as_ref().map_or_else(
                || String::from("none"),
                |proof| ledger_hex(&proof.request.canonical_bytes())
            )
        ));
        lines.push(format!(
            "{prefix}.campaign_minimized_response_hex={}",
            item.minimized_reproduction_proof.as_ref().map_or_else(
                || String::from("none"),
                |proof| ledger_hex(&proof.response.canonical_bytes())
            )
        ));
        lines.push(format!(
            "{prefix}.campaign_occurrence_page_count={}",
            item.occurrence_proofs.len()
        ));
        for (page, proof) in item.occurrence_proofs.iter().enumerate() {
            lines.push(format!(
                "{prefix}.campaign_occurrence.{page}.request_hex={}",
                ledger_hex(&proof.page.request.canonical_bytes())
            ));
            lines.push(format!(
                "{prefix}.campaign_occurrence.{page}.response_hex={}",
                ledger_hex(&proof.page.response.canonical_bytes())
            ));
            for (object, object_proof) in [
                ("observation", &proof.observation),
                ("reproduction", &proof.reproduction),
                ("minimized", &proof.minimized_reproduction),
            ] {
                lines.push(format!(
                    "{prefix}.campaign_occurrence.{page}.{object}_request_hex={}",
                    ledger_hex(&object_proof.request.canonical_bytes())
                ));
                lines.push(format!(
                    "{prefix}.campaign_occurrence.{page}.{object}_response_hex={}",
                    ledger_hex(&object_proof.response.canonical_bytes())
                ));
            }
            let triage_objects = [
                (
                    "minimization_original_triage",
                    proof
                        .triage_evidence
                        .as_ref()
                        .map(|triage| &triage.minimization_original),
                ),
                (
                    "minimization_selected_triage",
                    proof
                        .triage_evidence
                        .as_ref()
                        .map(|triage| &triage.minimization_selected),
                ),
                (
                    "verification_original_triage",
                    proof
                        .triage_evidence
                        .as_ref()
                        .map(|triage| &triage.verification_original),
                ),
                (
                    "verification_selected_triage",
                    proof
                        .triage_evidence
                        .as_ref()
                        .map(|triage| &triage.verification_selected),
                ),
            ];
            for (object, object_proof) in triage_objects {
                let count = object_proof
                    .map(|proof| proof.segments.len().to_string())
                    .unwrap_or_else(|| String::from("none"));
                lines.push(format!(
                    "{prefix}.campaign_occurrence.{page}.{object}_segment_count={count}"
                ));
                if let Some(proof) = object_proof {
                    for (segment, proof) in proof.segments.iter().enumerate() {
                        lines.push(format!(
                            "{prefix}.campaign_occurrence.{page}.{object}.segment.{segment}.request_hex={}",
                            ledger_hex(&proof.request.canonical_bytes())
                        ));
                        lines.push(format!(
                            "{prefix}.campaign_occurrence.{page}.{object}.segment.{segment}.response_hex={}",
                            ledger_hex(&proof.response.canonical_bytes())
                        ));
                    }
                }
            }
        }
        lines.push(format!(
            "{prefix}.campaign_finding_hex={}",
            ledger_hex(&item.finding.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_observation_hex={}",
            ledger_hex(&item.observation.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_reproduction_hex={}",
            ledger_hex(&item.reproduction.canonical_bytes())
        ));
        lines.push(format!(
            "{prefix}.campaign_minimized_hex={}",
            item.minimized_reproduction.as_ref().map_or_else(
                || String::from("none"),
                |reproduction| ledger_hex(&reproduction.canonical_bytes())
            )
        ));

        let projected = failure_findings_ledger_v3_bytes(std::slice::from_ref(&item.report))?;
        let projected = std::str::from_utf8(&projected)
            .map_err(|_| artifact_error("internal v3 findings projection is not UTF-8"))?;
        for line in projected.lines().skip(2) {
            let Some(suffix) = line.strip_prefix("finding.0") else {
                if line.is_empty() {
                    continue;
                }
                return Err(artifact_error(
                    "internal v3 findings projection is malformed",
                ));
            };
            lines.push(format!("{prefix}{suffix}"));
        }
    }
    lines.finish()
}

#[cfg(test)]
pub(crate) fn failure_findings_ledger_v4_bytes_with_test_limit(
    evidence: &[CampaignTriageFindingEvidence],
    maximum_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    failure_findings_ledger_v4_bytes_with_limit(evidence, maximum_bytes)
}

pub(crate) fn write_failure_findings_ledger_v4(
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    evidence: &[CampaignTriageFindingEvidence],
) -> Result<(PathBuf, crucible::ContentHash, Vec<u8>), CliError> {
    let bytes = failure_findings_ledger_v4_bytes(evidence)?;
    let digest = crucible::ContentHash::from_bytes(&bytes);
    let path = findings_out.map(Path::to_path_buf).unwrap_or_else(|| {
        artifact_dir
            .join("findings")
            .join(format!("{}.crucible-findings", digest.to_hex()))
    });
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &bytes)?;
    Ok((path, digest, bytes))
}

/// Writes guarded owners' complete final finding exports as a V4 triage ledger.
///
/// V4 retains every proof attached to a finding and names each finding's own
/// campaign and snapshot. Its schema has no top-level field for authenticated
/// empty query pages, so empty exports contribute no entry only after their
/// in-memory pages are validated.
///
/// # Errors
///
/// Returns an error if an export or report association is invalid, the encoded
/// ledger exceeds its aggregate bound, or the destination cannot be written.
pub(crate) fn write_guarded_campaign_finding_exports_v4(
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    exports: &[crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingExport],
    reports: &[TriageFindingEvidence],
) -> Result<(PathBuf, crucible::ContentHash, Vec<u8>), CliError> {
    let evidence = campaign_triage_evidence_from_guarded_exports(exports, reports)?;
    write_failure_findings_ledger_v4(artifact_dir, findings_out, &evidence)
}

#[cfg(test)]
mod bounded_ledger_tests {
    use super::*;

    #[test]
    fn bounded_v4_ledger_stops_before_aggregate_overflow() {
        assert_eq!(MAX_FAILURE_FINDINGS_LEDGER_V4_BYTES, 1024 * 1024 * 1024);

        let mut ledger = BoundedV4Ledger::with_maximum_bytes(8);
        ledger.push(String::from("abc"));
        ledger.push(String::from("def"));
        assert_eq!(ledger.bytes, b"abc\ndef\n");

        ledger.push(String::from("x"));
        assert_eq!(ledger.bytes, b"abc\ndef\n");
        assert!(ledger.finish().is_err());
    }
}
