//! Authenticated campaign Finding import, export, and triage projection.

use super::*;

#[path = "campaign_evidence/ledger.rs"]
mod ledger;
#[path = "campaign_evidence/service.rs"]
mod service;

pub(super) use ledger::parse_failure_findings_ledger_v4_bytes;
// crucible-lint: allow rust-allow -- the producer consumes these staged boundaries in the composed integration stack.
#[allow(unused_imports)]
pub(crate) use ledger::write_failure_findings_ledger_v4;
// crucible-lint: allow rust-allow -- the producer consumes these staged boundaries in the composed integration stack.
#[allow(unused_imports)]
pub(crate) use service::capture_campaign_triage_finding;

pub(super) fn build_campaign_triage_minimization(
    plan: &TriageInvocationPlan,
    clustering: &crucible::FailureClusteringResult,
    findings: &LoadedTriageFindings,
) -> Result<crucible::FailureSignaturePreservingMinimizationResult, CliError> {
    let mut campaign_by_artifact = BTreeMap::new();
    for item in &findings.campaign_evidence {
        campaign_by_artifact
            .entry(item.report.finding.artifact.id())
            .or_insert(item);
        for occurrence in campaign_occurrences(item) {
            if occurrence.triage_evidence.is_some() {
                campaign_by_artifact
                    .entry(crucible::ContentHash::from_bytes(
                        campaign_occurrence_reproduction(occurrence)?.payload(),
                    ))
                    .or_insert(item);
            }
        }
    }
    let mut runs = Vec::new();
    for cluster in &clustering.clusters {
        let _representative = cluster
            .representative_member()
            .ok_or_else(|| CliError::Triage("triage cluster has no representative".to_string()))?;
        let selected_members = match plan.minimize {
            TriageMinimizeArg::Representative => &cluster.members[..1],
            TriageMinimizeArg::All => cluster.members.as_slice(),
            TriageMinimizeArg::None => unreachable!("campaign minimization mode is selected"),
        };
        for member in selected_members {
            let item = campaign_by_artifact
                .get(&member.reproduction_artifact)
                .copied()
                .ok_or_else(|| {
                    artifact_error("campaign finding is missing for a selected triage member")
                })?;
            let occurrence = campaign_occurrence_for_artifact(item, member.reproduction_artifact)?
                .ok_or_else(|| {
                    artifact_error(
                        "campaign finding has no retained candidate occurrence for a selected triage member",
                    )
                })?;
            let replays = campaign_occurrence_native_triage_replays(occurrence, &item.report)?
                .ok_or_else(|| {
                    artifact_error(
                        "campaign finding candidate predates native triage replay evidence",
                    )
                })?;
            let target_signature_key = member
                .signature
                .signature_key(plan.policy)
                .map_err(|_| campaign_signature_policy_error("triage member"))?;
            let observed_signatures: [(&str, &crucible::FailureSignature); 4] = [
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
            let timeout = member.signature.failure_kind == crucible::FailureKind::Timeout;
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
                    target_fingerprint: item.report.finding.finding_fingerprint,
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
    Ok(crucible::FailureSignaturePreservingMinimizationResult {
        policy: plan.policy,
        runs,
    })
}

fn campaign_signature_policy_error(source: &str) -> CliError {
    CliError::Triage(format!(
        "campaign {source} signature does not project under the active policy"
    ))
}

struct CampaignOccurrenceNativeTriageReplays {
    minimization_original: crucible::FailureTriageReplayEvidence,
    minimization_selected: crucible::FailureTriageReplayEvidence,
    verification_original: crucible::FailureTriageReplayEvidence,
    verification_selected: crucible::FailureTriageReplayEvidence,
}

fn campaign_occurrences(
    item: &CampaignTriageFindingEvidence,
) -> impl Iterator<Item = &CampaignFindingOccurrenceProof> {
    item.occurrence_proofs.iter()
}

fn campaign_occurrence_for_artifact(
    item: &CampaignTriageFindingEvidence,
    artifact: crucible::ContentHash,
) -> Result<Option<&CampaignFindingOccurrenceProof>, CliError> {
    let mut legacy_match = None;
    for occurrence in campaign_occurrences(item) {
        let reproduction = campaign_occurrence_reproduction(occurrence)?;
        if crucible::ContentHash::from_bytes(reproduction.payload()) == artifact {
            if occurrence.triage_evidence.is_some() {
                return Ok(Some(occurrence));
            }
            legacy_match = Some(occurrence);
        }
    }
    Ok(legacy_match)
}

fn campaign_occurrence_bundle(
    occurrence: &CampaignFindingOccurrenceProof,
) -> Result<&crucible_campaign::FindingCandidateBundle, CliError> {
    occurrence
        .page
        .response
        .entries()
        .first()
        .map(crucible_campaign::CampaignFindingOccurrence::bundle)
        .ok_or_else(|| artifact_error("campaign occurrence page has no candidate bundle"))
}

fn campaign_occurrence_reproduction(
    occurrence: &CampaignFindingOccurrenceProof,
) -> Result<&crucible_campaign::ReproductionArtifact, CliError> {
    match occurrence.reproduction.response.object() {
        crucible_campaign::CampaignFindingOccurrenceObject::Reproduction(reproduction) => {
            Ok(reproduction)
        }
        _ => Err(artifact_error(
            "campaign occurrence reproduction proof has another object kind",
        )),
    }
}

fn campaign_occurrence_minimized_reproduction(
    occurrence: &CampaignFindingOccurrenceProof,
) -> Result<&crucible_campaign::ReproductionArtifact, CliError> {
    match occurrence.minimized_reproduction.response.object() {
        crucible_campaign::CampaignFindingOccurrenceObject::MinimizedReproduction(reproduction) => {
            Ok(reproduction)
        }
        _ => Err(artifact_error(
            "campaign occurrence minimized proof has another object kind",
        )),
    }
}

fn campaign_model_finding_reproduction(
    template: &crucible::FindingReproductionArtifact,
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> Result<crucible::FindingReproductionArtifact, CliError> {
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .map_err(|error| {
            artifact_error(format!(
                "campaign minimized reproduction payload is invalid: {error}"
            ))
        })?;
    let replay = artifact.replay().map_err(|error| {
        artifact_error(format!(
            "campaign minimized reproduction does not replay: {error}"
        ))
    })?;
    let configuration = crucible::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    };
    let finding = crucible::FindingReproductionArtifact {
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

fn campaign_occurrence_native_triage_replays(
    occurrence: &CampaignFindingOccurrenceProof,
    template: &TriageFindingEvidence,
) -> Result<Option<CampaignOccurrenceNativeTriageReplays>, CliError> {
    let Some(triage) = &occurrence.triage_evidence else {
        return Ok(None);
    };
    let original_reproduction = campaign_occurrence_reproduction(occurrence)?;
    let selected_reproduction = campaign_occurrence_minimized_reproduction(occurrence)?;
    let original_finding =
        campaign_model_finding_reproduction(&template.finding, original_reproduction)?;
    let selected_finding =
        campaign_model_finding_reproduction(&template.finding, selected_reproduction)?;

    Ok(Some(CampaignOccurrenceNativeTriageReplays {
        minimization_original: decode_campaign_occurrence_triage_replay(
            &triage.minimization_original,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence,
            original_reproduction,
            original_finding.clone(),
        )?,
        minimization_selected: decode_campaign_occurrence_triage_replay(
            &triage.minimization_selected,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence,
            selected_reproduction,
            selected_finding.clone(),
        )?,
        verification_original: decode_campaign_occurrence_triage_replay(
            &triage.verification_original,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence,
            original_reproduction,
            original_finding,
        )?,
        verification_selected: decode_campaign_occurrence_triage_replay(
            &triage.verification_selected,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence,
            selected_reproduction,
            selected_finding,
        )?,
    }))
}

fn decode_campaign_occurrence_triage_replay(
    proof: &CampaignFindingOccurrenceObjectProof,
    expected_kind: crucible_campaign::CampaignFindingOccurrenceObjectKind,
    reproduction: &crucible_campaign::ReproductionArtifact,
    finding: crucible::FindingReproductionArtifact,
) -> Result<crucible::FailureTriageReplayEvidence, CliError> {
    let record = match (expected_kind, proof.response.object()) {
        (
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence,
            crucible_campaign::CampaignFindingOccurrenceObject::MinimizationOriginalTriageEvidence(record),
        )
        | (
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence,
            crucible_campaign::CampaignFindingOccurrenceObject::MinimizationSelectedTriageEvidence(record),
        )
        | (
            crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence,
            crucible_campaign::CampaignFindingOccurrenceObject::VerificationOriginalTriageEvidence(record),
        )
        | (
            crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence,
            crucible_campaign::CampaignFindingOccurrenceObject::VerificationSelectedTriageEvidence(record),
        ) => record,
        _ => {
            return Err(artifact_error(
                "campaign occurrence triage proof has another object kind",
            ));
        }
    };
    let reproduction_id = reproduction.id().map_err(|error| {
        artifact_error(format!(
            "campaign occurrence triage reproduction ID is invalid: {error}"
        ))
    })?;
    if proof.request.kind() != expected_kind
        || record.reproduction() != reproduction_id
        || record.payload_schema() != crucible::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    {
        return Err(artifact_error(
            "campaign occurrence triage payload has an incompatible semantic binding",
        ));
    }
    let replay =
        crucible::FailureTriageReplayEvidence::from_compact_binary(finding, record.payload())
            .map_err(|error| {
                artifact_error(format!(
                    "campaign occurrence triage payload is invalid: {error}"
                ))
            })?;
    validate_campaign_native_signature_binding(record, reproduction, &replay)?;
    Ok(replay)
}

fn validate_campaign_native_signature_binding(
    record: &crucible_campaign::FindingTriageReplayEvidence,
    reproduction: &crucible_campaign::ReproductionArtifact,
    replay: &crucible::FailureTriageReplayEvidence,
) -> Result<(), CliError> {
    let observed = record.observed_signature();
    let native = replay.signature();
    let kind_matches = matches!(
        (observed.kind(), native.failure_kind),
        (
            crucible_campaign::FindingKind::PropertyViolation,
            crucible::FailureKind::PropertyViolation
        ) | (
            crucible_campaign::FindingKind::Divergence,
            crucible::FailureKind::Divergence
        ) | (
            crucible_campaign::FindingKind::Timeout,
            crucible::FailureKind::Timeout
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

fn triage_finding_evidence_from_replay(
    replay: &crucible::FailureTriageReplayEvidence,
) -> TriageFindingEvidence {
    TriageFindingEvidence {
        finding: replay.finding().clone(),
        causal_entries: replay.causal_entries().to_vec(),
        recorded_event_log: replay.recorded_event_log().clone(),
        failure: replay.failure().clone(),
        discovery_signature: replay.signature().clone(),
        recorded_event_frames: replay.recorded_event_frames().to_vec(),
    }
}

pub(super) fn campaign_triage_report_evidence_for_run(
    run: &crucible::FailureSignaturePreservingMinimizationRun,
    evidence: &[CampaignTriageFindingEvidence],
) -> Result<TriageFindingEvidence, CliError> {
    for item in evidence {
        let Some(occurrence) = campaign_occurrence_for_artifact(item, run.representative_artifact)?
        else {
            continue;
        };
        let replays = campaign_occurrence_native_triage_replays(occurrence, &item.report)?
            .ok_or_else(|| {
                artifact_error("campaign candidate predates native triage report evidence")
            })?;
        let selected = triage_finding_evidence_from_replay(&replays.minimization_selected);
        if selected.finding.artifact.id() != run.minimized_artifact() {
            return Err(artifact_error(
                "campaign selected replay disagrees with its minimized triage result",
            ));
        }
        return Ok(selected);
    }
    Err(artifact_error(
        "campaign minimized triage result has no authenticated replay evidence",
    ))
}
