//! Authenticated campaign Finding import, export, and triage projection.
//!
//! Campaign findings evidence is content-addressed: capture writes every
//! checked service exchange into an evidence store, a per-finding record and
//! occurrence chunks index those exchanges, and a small ledger manifest names
//! the records. Loading authenticates the ledger as a fold and keeps only the
//! clustering input; minimization and reports fetch a selected member's
//! replays by its ledger location.

use super::*;

#[path = "campaign_evidence/ledger.rs"]
mod ledger;
#[path = "campaign_evidence/record.rs"]
mod record;
#[path = "campaign_evidence/reproduction.rs"]
mod reproduction;
#[path = "campaign_evidence/service.rs"]
mod service;
#[path = "campaign_evidence/store.rs"]
mod store;
#[path = "campaign_evidence/triage_segments.rs"]
mod triage_segments;

pub(crate) use ledger::{
    CampaignTriageEvidence, campaign_findings_ledger_bytes, load_campaign_findings_ledger,
    load_campaign_findings_ledger_bytes, write_campaign_findings_ledger,
};
pub(crate) use reproduction::fetch_campaign_reproduction;
#[cfg(test)]
pub(crate) use service::capture_campaign_triage_finding;
pub(crate) use service::{
    CampaignFindingCaptureScope, capture_campaign_triage_finding_from_service,
    find_campaign_finding_membership,
};
pub(crate) use store::sync_evidence_store;

pub(super) fn build_campaign_triage_minimization(
    plan: &TriageInvocationPlan,
    clustering: &crucible_engine::FailureClusteringResult,
    findings: &LoadedTriageFindings,
) -> Result<crucible_engine::FailureSignaturePreservingMinimizationResult, CliError> {
    let mut runs = Vec::new();
    for cluster in &clustering.clusters {
        let selected_members = selected_triage_members(plan.minimize, cluster.members.as_slice())?;
        for member in selected_members {
            let evidence = findings
                .evidence
                .member(member.reproduction_artifact)?
                .ok_or_else(|| {
                    artifact_error("campaign finding is missing for a selected triage member")
                })?;
            let replays = evidence.replays.as_ref().ok_or_else(|| {
                artifact_error(
                    "campaign finding has no retained candidate occurrence for a selected triage member",
                )
            })?;
            let target_signature_key = member
                .signature
                .signature_key(plan.policy)
                .map_err(|_| campaign_signature_policy_error("triage member"))?;
            let observed_signatures: [(&str, &crucible_engine::FailureSignature); 4] = [
                (
                    "minimization original",
                    replays.minimization_original.signature(),
                ),
                (
                    "minimization selected",
                    replays.minimization_selected.signature(),
                ),
                (
                    "verification original",
                    replays.verification_original.signature(),
                ),
                (
                    "verification selected",
                    replays.verification_selected.signature(),
                ),
            ];
            for (name, signature) in observed_signatures {
                let observed_key = signature
                    .signature_key(plan.policy)
                    .map_err(|_| campaign_signature_policy_error(name))?;
                if observed_key != target_signature_key {
                    return Err(CliError::Triage(format!(
                        "campaign {name} replay changed the selected triage signature for {}",
                        member.reproduction_artifact.to_hex()
                    )));
                }
            }
            if replays.minimization_original.finding().artifact.id() != member.reproduction_artifact
            {
                return Err(CliError::Triage(format!(
                    "campaign original replay names another selected triage member for {}",
                    member.reproduction_artifact.to_hex()
                )));
            }
            let timeout = member.signature.failure_kind == crucible_engine::FailureKind::Timeout;
            let original = replays.minimization_original.finding().clone();
            let minimized = if timeout {
                original.clone()
            } else {
                replays.minimization_selected.finding().clone()
            };
            runs.push(crucible_model::FailureSignaturePreservingMinimizationRun {
                cluster_id: cluster.id,
                representative_artifact: member.reproduction_artifact,
                target_signature_key: target_signature_key.clone(),
                minimized_signature_key: target_signature_key,
                disposition: if timeout {
                    crucible_model::FailureMinimizationDisposition::NotApplicableTimeout
                } else {
                    crucible_model::FailureMinimizationDisposition::Minimized
                },
                minimization: crucible_model::MinimizationRun {
                    seed: minimized.artifact.seed(),
                    interesting_window: None,
                    target_fingerprint: evidence.finding.report.finding.finding_fingerprint,
                    original,
                    minimized,
                    // Campaign evidence retains the exact two-pass replay
                    // observations. The core attempt model does not encode
                    // those full signatures, so the authenticated records are
                    // checked above and the result carries their selected run.
                    attempts: Vec::new(),
                },
            });
        }
    }
    Ok(
        crucible_engine::FailureSignaturePreservingMinimizationResult {
            policy: plan.policy,
            runs,
        },
    )
}

fn campaign_signature_policy_error(source: &str) -> CliError {
    CliError::Triage(format!(
        "campaign {source} signature does not project under the active policy"
    ))
}

/// Four decoded native replays of one occurrence, in role order.
struct CampaignOccurrenceNativeTriageReplays {
    minimization_original: crucible_engine::FailureTriageReplayEvidence,
    minimization_selected: crucible_engine::FailureTriageReplayEvidence,
    verification_original: crucible_engine::FailureTriageReplayEvidence,
    verification_selected: crucible_engine::FailureTriageReplayEvidence,
}

/// Gathers the native replays an occurrence authentication yields per role.
#[derive(Default)]
struct CampaignOccurrenceReplayCollector {
    roles: [Option<crucible_engine::FailureTriageReplayEvidence>; 4],
}

impl CampaignOccurrenceReplayCollector {
    fn insert(
        &mut self,
        role: crucible_campaign::CampaignFindingTriageReplayRole,
        replay: crucible_engine::FailureTriageReplayEvidence,
    ) -> Result<(), CliError> {
        let slot = match role {
            crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal => 0,
            crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected => 1,
            crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal => 2,
            crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected => 3,
        };
        if self.roles[slot].replace(replay).is_some() {
            return Err(artifact_error(
                "campaign occurrence repeats a triage replay role",
            ));
        }
        Ok(())
    }

    fn finish(self) -> Result<CampaignOccurrenceNativeTriageReplays, CliError> {
        match self.roles {
            [
                Some(minimization_original),
                Some(minimization_selected),
                Some(verification_original),
                Some(verification_selected),
            ] => Ok(CampaignOccurrenceNativeTriageReplays {
                minimization_original,
                minimization_selected,
                verification_original,
                verification_selected,
            }),
            _ => Err(artifact_error(
                "campaign candidate predates native triage replay evidence",
            )),
        }
    }
}

/// Returns the evidence identity a bundle names for one replay role.
fn triage_role_evidence(
    evidence: &crucible_campaign::FindingTriageEvidenceSet,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
) -> crucible_campaign::FindingTriageReplayEvidenceId {
    match role {
        crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal => {
            evidence.minimization_original()
        }
        crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected => {
            evidence.minimization_selected()
        }
        crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal => {
            evidence.verification_original()
        }
        crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected => {
            evidence.verification_selected()
        }
    }
}

/// Replays a reproduction's decoded Crucible artifact into a finding framed
/// by `template`, checking it against the campaign record's identities.
fn campaign_model_finding_reproduction(
    template: &crucible_engine::FindingReproductionArtifact,
    reproduction: &crucible_campaign::ReproductionArtifact,
    artifact: crucible_engine::ReproductionArtifact,
) -> Result<crucible_engine::FindingReproductionArtifact, CliError> {
    let replay = artifact.replay().map_err(|error| {
        artifact_error(format!(
            "campaign minimized reproduction does not replay: {error}"
        ))
    })?;
    let configuration = crucible_engine::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    };
    let finding = crucible_engine::FindingReproductionArtifact {
        discovery_path: template.discovery_path,
        finding_fingerprint: template.finding_fingerprint,
        configuration: configuration.id(),
        artifact,
        replay,
    };
    let campaign_configuration =
        crucible_campaign::CampaignHash::from_bytes(finding.configuration.bytes);
    let campaign_scenario =
        crucible_campaign::CampaignHash::from_bytes(finding.artifact.scenario_def().id().bytes);
    if reproduction.scenario().as_hash() != campaign_scenario
        || reproduction.configuration().as_hash() != campaign_configuration
        || reproduction.finding_fingerprint()
            != crucible_campaign::CampaignHash::from_bytes(finding.finding_fingerprint.bytes)
    {
        return Err(artifact_error(
            "campaign minimized reproduction semantic identity is inconsistent",
        ));
    }
    Ok(finding)
}

/// Decodes one authenticated replay record into its native evidence.
///
/// The record's role and evidence identity are already bound by
/// authentication, and `log_segments` holds the authenticated segments the
/// record names; this checks its reproduction and signature bindings.
pub(crate) fn decode_campaign_triage_replay_record(
    record: &crucible_campaign::FindingTriageReplayEvidence,
    reproduction: &crucible_campaign::ReproductionArtifact,
    finding: crucible_engine::FindingReproductionArtifact,
    log_segments: crucible_engine::FailureTriageReplaySegments,
) -> Result<crucible_engine::FailureTriageReplayEvidence, CliError> {
    let reproduction_id = reproduction.id().map_err(|error| {
        artifact_error(format!(
            "campaign occurrence triage reproduction ID is invalid: {error}"
        ))
    })?;
    if record.reproduction() != reproduction_id
        || record.payload_schema() != crucible_engine::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    {
        return Err(artifact_error(
            "campaign occurrence triage payload has an incompatible semantic binding",
        ));
    }
    let replay = crucible_engine::FailureTriageReplayEvidence::from_compact_binary(
        finding,
        record.payload(),
        log_segments,
    )
    .map_err(|error| {
        artifact_error(format!(
            "campaign occurrence triage payload is invalid: {error}"
        ))
    })?;

    // The record's trace leaves must name exactly the payload's segments, in
    // order, so a record cannot pin unrelated objects or omit a log segment.
    let referenced = replay.referenced_segments();
    let names_payload_segments = record.log_segments().len() == referenced.len()
        && record
            .log_segments()
            .iter()
            .zip(&referenced)
            .all(|(named, segment)| {
                named.content() == segment.id && named.bytes() == segment.encoded_bytes
            });
    if !names_payload_segments {
        return Err(artifact_error(
            "campaign occurrence triage record names other log segments than its payload",
        ));
    }

    validate_campaign_native_signature_binding(record, reproduction, &replay)?;
    Ok(replay)
}

pub(crate) fn reassemble_campaign_triage_replay_proof(
    proof: &CampaignFindingTriageReplayProof,
) -> Result<crucible_campaign::FindingTriageReplayEvidence, CliError> {
    let first = proof
        .segments
        .first()
        .ok_or_else(|| artifact_error("campaign occurrence triage proof has no segment"))?;
    let description = first.response.description();
    let mut envelopes = Vec::with_capacity(description.objects().len());
    let mut segment_position = 0;
    for object in description.objects() {
        let object_bytes = usize::try_from(object.stored_envelope_bytes())
            .map_err(|_| artifact_error("campaign triage storage envelope length is invalid"))?;
        let mut envelope = Vec::with_capacity(object_bytes);
        let segment_count = object
            .stored_envelope_bytes()
            .checked_add(crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
            .ok_or_else(|| artifact_error("campaign triage segment count overflows"))?
            / crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES;
        for segment_index in 0..u32::try_from(segment_count)
            .map_err(|_| artifact_error("campaign triage segment count is invalid"))?
        {
            let segment = proof.segments.get(segment_position).ok_or_else(|| {
                artifact_error("campaign occurrence triage proof ends before its description")
            })?;
            segment
                .response
                .validate_for(&segment.request)
                .map_err(|error| {
                    artifact_error(format!(
                        "campaign occurrence triage segment response is invalid: {error}"
                    ))
                })?;
            if segment.request.principal() != first.request.principal()
                || segment.request.campaign() != first.request.campaign()
                || segment.request.snapshot() != first.request.snapshot()
                || segment.request.finding() != first.request.finding()
                || segment.request.bundle() != first.request.bundle()
                || segment.request.role() != first.request.role()
                || segment.request.evidence() != first.request.evidence()
                || segment.request.object_ordinal() != object.ordinal()
                || segment.request.object() != object.content()
                || segment.request.segment_index() != segment_index
                || segment.response.description() != description
            {
                return Err(artifact_error(
                    "campaign occurrence triage proof is reordered or substituted",
                ));
            }
            envelope.extend_from_slice(segment.response.range_bytes());
            segment_position += 1;
        }
        if envelope.len() != object_bytes {
            return Err(artifact_error(
                "campaign occurrence triage envelope is incomplete",
            ));
        }
        envelopes.push(envelope);
    }
    if segment_position != proof.segments.len() {
        return Err(artifact_error(
            "campaign occurrence triage proof has unexpected segments",
        ));
    }
    crucible_campaign::FindingTriageReplayEvidence::from_storage_envelopes(description, &envelopes)
        .map_err(|error| {
            artifact_error(format!("campaign triage storage proof is invalid: {error}"))
        })
}

fn validate_campaign_native_signature_binding(
    record: &crucible_campaign::FindingTriageReplayEvidence,
    reproduction: &crucible_campaign::ReproductionArtifact,
    replay: &crucible_engine::FailureTriageReplayEvidence,
) -> Result<(), CliError> {
    let observed = record.observed_signature();
    let native = replay.signature();
    let kind_matches = matches!(
        (observed.kind(), native.failure_kind),
        (
            crucible_campaign::FindingKind::PropertyViolation,
            crucible_engine::FailureKind::PropertyViolation
        ) | (
            crucible_campaign::FindingKind::Divergence,
            crucible_engine::FailureKind::Divergence
        ) | (
            crucible_campaign::FindingKind::Timeout,
            crucible_engine::FailureKind::Timeout
        )
    );
    let native_property = native
        .property
        .as_ref()
        .map(|property| property.id.name.as_str());
    let target_matches = matches!(
        observed.target(),
        Some(crucible_campaign::FindingTarget::Configuration(target))
            if target == reproduction.configuration_artifact()
    );
    let finding = replay.finding();
    let fingerprint =
        crucible_campaign::CampaignHash::from_bytes(finding.finding_fingerprint.bytes);
    let scenario =
        crucible_campaign::CampaignHash::from_bytes(finding.artifact.scenario_def().id().bytes);
    let configuration = crucible_campaign::CampaignHash::from_bytes(finding.configuration.bytes);

    if !kind_matches
        || observed.property() != native_property
        || observed.fingerprint() != fingerprint
        || reproduction.finding_fingerprint() != fingerprint
        || reproduction.scenario().as_hash() != scenario
        || reproduction.configuration().as_hash() != configuration
        || !target_matches
    {
        return Err(artifact_error(
            "campaign occurrence triage payload disagrees with its observed campaign signature",
        ));
    }
    Ok(())
}

/// Projects native replay evidence into the CLI's report evidence.
///
/// The CLI report and minimization paths still work over a resident log, so
/// the replay's segmented log is read back here; campaign replays carry no
/// CLI recording frames.
fn triage_finding_evidence_from_replay(
    replay: &crucible_engine::FailureTriageReplayEvidence,
) -> Result<TriageFindingEvidence, CliError> {
    let mut causal_entries = Vec::new();
    replay
        .recorded_event_log()
        .try_for_each_entry(|entry| {
            causal_entries.push(entry.clone());
            Ok(())
        })
        .map_err(|error| {
            artifact_error(format!("campaign triage replay log is unreadable: {error}"))
        })?;
    Ok(TriageFindingEvidence {
        finding: replay.finding().clone(),
        causal_entries,
        recorded_event_log: replay.recorded_event_log().clone(),
        failure: replay.failure().clone(),
        discovery_signature: replay.signature().clone(),
        recorded_event_frames: Vec::new(),
    })
}

pub(super) fn campaign_triage_report_evidence_for_run(
    run: &crucible_engine::FailureSignaturePreservingMinimizationRun,
    evidence: &CampaignTriageEvidence,
) -> Result<TriageFindingEvidence, CliError> {
    let replays = evidence
        .member(run.representative_artifact)?
        .and_then(|member| member.replays)
        .ok_or_else(|| {
            artifact_error("campaign minimized triage result has no authenticated replay evidence")
        })?;
    let selected = triage_finding_evidence_from_replay(&replays.minimization_selected)?;
    if selected.finding.artifact.id() != run.minimized_artifact() {
        return Err(artifact_error(
            "campaign selected replay disagrees with its minimized triage result",
        ));
    }
    Ok(selected)
}
