//! Projection of immutable guarded-owner finding exports into V4 evidence.

use super::service::{
    ImportedCampaignFindingService, authenticate_campaign_triage_finding,
    validate_campaign_triage_finding,
};
use super::*;

/// Projects one immutable guarded-owner export into the existing V4 ledger model.
///
/// The guarded owner deliberately queries findings and occurrences one at a
/// time. This boundary reauthenticates that complete in-memory page chain before
/// selecting the per-finding exchanges that V4 can retain. An empty V4 ledger
/// does not preserve the owner's authenticated empty page.
///
/// # Errors
///
/// Returns an error if any query or object proof fails authentication, a page
/// chain is incomplete, or a finding has no unique report projection.
pub(crate) fn campaign_triage_evidence_from_guarded_export(
    export: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingExport,
    reports: &[TriageFindingEvidence],
) -> Result<Vec<CampaignTriageFindingEvidence>, CliError> {
    let query_pages = validate_guarded_finding_query_chain(export)?;

    let mut evidence = Vec::with_capacity(export.findings().len());
    for (index, (finding_proof, membership)) in
        export.findings().iter().zip(query_pages).enumerate()
    {
        let finding_id = finding_proof.finding();
        let finding = membership
            .response
            .entries()
            .first()
            .cloned()
            .ok_or_else(|| {
                artifact_error(format!(
                    "guarded campaign finding export page {index} has no finding"
                ))
            })?;
        let representative = guarded_representative_object_proofs(index, finding_proof, &finding)?;
        let report =
            guarded_finding_report(index, &finding, &representative.reproduction, reports)?;
        let occurrence_proofs = guarded_occurrence_proofs(
            index,
            export,
            finding_id,
            &finding,
            &membership,
            finding_proof.occurrences(),
        )?;
        let item = CampaignTriageFindingEvidence {
            campaign: export.campaign().clone(),
            snapshot: export.snapshot(),
            membership,
            observation_proof: representative.observation,
            reproduction_proof: representative.reproduction_proof,
            minimized_reproduction_proof: representative.minimized_proof,
            occurrence_proofs,
            finding,
            observation: representative.observation_body,
            reproduction: representative.reproduction,
            minimized_reproduction: representative.minimized,
            report,
        };
        authenticate_campaign_triage_finding(index, finding_id, &item)?;
        validate_campaign_triage_finding(index, finding_id, &item)?;
        evidence.push(item);
    }
    Ok(evidence)
}

/// Projects several independently authenticated final snapshots into V4 entries.
///
/// Each export retains and validates its own complete query chain. The V4
/// format carries the campaign and snapshot on every resulting finding, so it
/// can combine fuzz iterations without implying one shared snapshot.
///
/// # Errors
///
/// Returns an error if no export is supplied, any export is invalid, or a
/// report does not correspond to an exported finding.
pub(crate) fn campaign_triage_evidence_from_guarded_exports(
    exports: &[crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingExport],
    reports: &[TriageFindingEvidence],
) -> Result<Vec<CampaignTriageFindingEvidence>, CliError> {
    if exports.is_empty() {
        return Err(artifact_error(
            "guarded campaign finding serialization requires at least one export",
        ));
    }

    let finding_capacity = exports.iter().try_fold(0_usize, |count, export| {
        count.checked_add(export.findings().len()).ok_or_else(|| {
            artifact_error("guarded campaign finding export count exceeds platform limits")
        })
    })?;
    let mut evidence = Vec::with_capacity(finding_capacity);
    for export in exports {
        evidence.extend(campaign_triage_evidence_from_guarded_export(
            export, reports,
        )?);
    }

    for report in reports {
        if !evidence.iter().any(|item| item.report == *report) {
            return Err(artifact_error(
                "guarded campaign finding reports contain an unexported projection",
            ));
        }
    }
    Ok(evidence)
}

fn validate_guarded_finding_query_chain(
    export: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingExport,
) -> Result<Vec<CampaignFindingsMembershipProof>, CliError> {
    let pages = export
        .query_pages()
        .iter()
        .map(|page| CampaignFindingsMembershipProof {
            request: page.request().clone(),
            response: page.response().clone(),
        })
        .collect::<Vec<_>>();
    let findings = export
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.finding(),
                CampaignFindingsMembershipProof {
                    request: finding.request().clone(),
                    response: finding.response().clone(),
                },
            )
        })
        .collect::<Vec<_>>();
    validate_guarded_finding_query_chain_parts(
        export.campaign(),
        export.snapshot(),
        &pages,
        &findings,
    )
}

/// Authenticates and normalizes one complete limit-one finding query chain.
///
/// # Errors
///
/// Returns [`CliError`] when the chain is empty or incomplete, a request
/// changes its authority or cursor, or a response proof does not authenticate
/// the expected finding at the requested snapshot.
pub(crate) fn validate_guarded_finding_query_chain_parts(
    campaign: &crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    pages: &[CampaignFindingsMembershipProof],
    findings: &[(
        crucible_campaign::FindingId,
        CampaignFindingsMembershipProof,
    )],
) -> Result<Vec<CampaignFindingsMembershipProof>, CliError> {
    if pages.is_empty() {
        return Err(artifact_error(
            "guarded campaign finding export has no authenticated query page",
        ));
    }
    let expected_pages = findings.len().max(1);
    if pages.len() != expected_pages {
        return Err(artifact_error(
            "guarded campaign finding export query chain is incomplete",
        ));
    }

    let principal = pages[0].request.principal();
    let mut after = None;
    let mut normalized = Vec::with_capacity(pages.len());
    for (index, page) in pages.iter().enumerate() {
        let request = &page.request;
        if request.principal() != principal
            || request.campaign() != campaign
            || request.snapshot() != snapshot
            || request.after() != after
            || request.limit() != 1
        {
            return Err(artifact_error(format!(
                "guarded campaign finding export page {index} breaks the canonical query chain"
            )));
        }

        let response = authenticate_campaign_findings_page(index, page)?;
        let expected_finding = findings.get(index);
        match (response.entries(), expected_finding) {
            ([], None) => {}
            ([finding], Some((expected_id, expected_proof)))
                if finding.id() == Ok(*expected_id) && expected_proof == page => {}
            _ => {
                return Err(artifact_error(format!(
                    "guarded campaign finding export page {index} does not match its finding proof"
                )));
            }
        }

        after = response.next_after();
        if after.is_none() && index + 1 != pages.len() {
            return Err(artifact_error(format!(
                "guarded campaign finding export page {index} claims an early end of index"
            )));
        }
        normalized.push(page.clone());
    }
    if after.is_some() {
        return Err(artifact_error(
            "guarded campaign finding export query chain is incomplete",
        ));
    }
    Ok(normalized)
}

fn authenticate_campaign_findings_page(
    index: usize,
    proof: &CampaignFindingsMembershipProof,
) -> Result<crucible_campaign::QueryCampaignFindingsResponse, CliError> {
    let client = crucible_campaign::CampaignClient::new(ImportedCampaignFindingService::new(
        proof.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    client
        .query_campaign_findings(&proof.request)
        .map_err(|error| {
            artifact_error(format!(
                "guarded campaign finding export page {index} was rejected: {error}"
            ))
        })
}

struct GuardedRepresentativeObjectProofs {
    observation: CampaignFindingObjectProof,
    reproduction_proof: CampaignFindingObjectProof,
    minimized_proof: Option<CampaignFindingObjectProof>,
    observation_body: crucible_campaign::Observation,
    reproduction: crucible_campaign::ReproductionArtifact,
    minimized: Option<crucible_campaign::ReproductionArtifact>,
}

fn guarded_representative_object_proofs(
    index: usize,
    proof: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingProof,
    finding: &crucible_campaign::Finding,
) -> Result<GuardedRepresentativeObjectProofs, CliError> {
    let mut observation = None;
    let mut reproduction = None;
    let mut minimized = None;
    for object in proof.objects() {
        let normalized = CampaignFindingObjectProof {
            request: object.request().clone(),
            response: object.response().clone(),
        };
        let slot = match object.request().kind() {
            crucible_campaign::CampaignFindingObjectKind::Observation => &mut observation,
            crucible_campaign::CampaignFindingObjectKind::Reproduction => &mut reproduction,
            crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction => &mut minimized,
            crucible_campaign::CampaignFindingObjectKind::LatestOccurrence => {
                return Err(artifact_error(format!(
                    "guarded campaign finding export {index} retains an unexpected latest-occurrence proof"
                )));
            }
        };
        if slot.replace(normalized).is_some() {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} repeats a representative object proof"
            )));
        }
    }
    let observation = observation.ok_or_else(|| {
        artifact_error(format!(
            "guarded campaign finding export {index} has no observation proof"
        ))
    })?;
    let reproduction_proof = reproduction.ok_or_else(|| {
        artifact_error(format!(
            "guarded campaign finding export {index} has no reproduction proof"
        ))
    })?;
    if minimized.is_some() != finding.minimized().is_some() {
        return Err(artifact_error(format!(
            "guarded campaign finding export {index} has incomplete minimized proof material"
        )));
    }

    let observation_body = match observation.response.object() {
        crucible_campaign::CampaignFindingObject::Observation(value) => value.clone(),
        _ => {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} observation proof has another object kind"
            )));
        }
    };
    let reproduction_body = match reproduction_proof.response.object() {
        crucible_campaign::CampaignFindingObject::Reproduction(value) => value.clone(),
        _ => {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} reproduction proof has another object kind"
            )));
        }
    };
    let minimized_body = minimized
        .as_ref()
        .map(|proof| match proof.response.object() {
            crucible_campaign::CampaignFindingObject::MinimizedReproduction(value) => {
                Ok(value.clone())
            }
            _ => Err(artifact_error(format!(
                "guarded campaign finding export {index} minimized proof has another object kind"
            ))),
        })
        .transpose()?;

    Ok(GuardedRepresentativeObjectProofs {
        observation,
        reproduction_proof,
        minimized_proof: minimized,
        observation_body,
        reproduction: reproduction_body,
        minimized: minimized_body,
    })
}

/// Selects the unique local triage report bound to one guarded finding.
///
/// # Errors
///
/// Returns [`CliError`] when no report matches the finding's reproduction,
/// signature, and configuration, or when more than one report matches.
pub(crate) fn guarded_finding_report(
    index: usize,
    finding: &crucible_campaign::Finding,
    reproduction: &crucible_campaign::ReproductionArtifact,
    reports: &[TriageFindingEvidence],
) -> Result<TriageFindingEvidence, CliError> {
    let mut matching = reports.iter().filter(|report| {
        report.finding.artifact.to_compact_binary() == reproduction.payload()
            && guarded_report_matches_finding(report, finding, reproduction)
    });
    let report = matching.next().ok_or_else(|| {
        artifact_error(format!(
            "guarded campaign finding export {index} has no matching report projection"
        ))
    })?;
    if matching.next().is_some() {
        return Err(artifact_error(format!(
            "guarded campaign finding export {index} has ambiguous report projections"
        )));
    }
    Ok(report.clone())
}

fn guarded_report_matches_finding(
    report: &TriageFindingEvidence,
    finding: &crucible_campaign::Finding,
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> bool {
    let fingerprint =
        crucible_campaign::CampaignHash::from_bytes(report.finding.finding_fingerprint.bytes);
    let configuration =
        crucible_campaign::CampaignHash::from_bytes(report.finding.configuration.bytes);
    let property = report
        .discovery_signature
        .property
        .as_ref()
        .map(|property| property.id.name.as_str());
    let kind_matches = matches!(
        (
            finding.signature().kind(),
            report.discovery_signature.failure_kind
        ),
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

    kind_matches
        && finding.signature().fingerprint() == fingerprint
        && finding.signature().property() == property
        && reproduction.finding_fingerprint() == fingerprint
        && reproduction.configuration().as_hash() == configuration
}

fn guarded_occurrence_proofs(
    index: usize,
    export: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingExport,
    finding_id: crucible_campaign::FindingId,
    finding: &crucible_campaign::Finding,
    membership: &CampaignFindingsMembershipProof,
    pages: &[crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingOccurrenceProof],
) -> Result<Vec<CampaignFindingOccurrenceProof>, CliError> {
    let expected = usize::try_from(finding.candidate_occurrence_count())
        .map_err(|_| artifact_error("guarded campaign finding occurrence count is invalid"))?;
    let expected_pages = expected.max(1);
    if pages.len() != expected_pages {
        return Err(artifact_error(format!(
            "guarded campaign finding export {index} occurrence query chain is incomplete"
        )));
    }

    let principal = membership.request.principal();
    let mut after = None;
    let mut normalized = Vec::with_capacity(expected);
    for (page_index, page) in pages.iter().enumerate() {
        let request = page.request();
        if request.principal() != principal
            || request.campaign() != export.campaign()
            || request.snapshot() != export.snapshot()
            || request.finding() != finding_id
            || request.after() != after
            || request.limit() != 1
        {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} breaks the canonical query chain"
            )));
        }
        let page_proof = CampaignFindingOccurrencesProof {
            request: request.clone(),
            response: page.response().clone(),
        };
        if expected == 0 {
            authenticate_empty_guarded_occurrence_page(index, membership, &page_proof)?;
            if !page.response().entries().is_empty()
                || page.response().next_after().is_some()
                || !page.objects().is_empty()
            {
                return Err(artifact_error(format!(
                    "guarded campaign finding export {index} has a nonempty zero-occurrence page"
                )));
            }
            continue;
        }
        let bundle = page
            .response()
            .entries()
            .first()
            .map(crucible_campaign::CampaignFindingOccurrence::bundle)
            .ok_or_else(|| {
                artifact_error(format!(
                    "guarded campaign finding export {index} occurrence page {page_index} has no bundle"
                ))
            })?;
        if page.response().entries().len() != 1 {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} is not limit-one"
            )));
        }
        let objects = guarded_occurrence_object_proofs(index, page_index, page, bundle)?;
        normalized.push(CampaignFindingOccurrenceProof {
            page: page_proof,
            observation: objects.observation,
            reproduction: objects.reproduction,
            minimized_reproduction: objects.minimized,
            triage_evidence: objects.triage,
        });
        after = page.response().next_after();
        if after.is_none() && page_index + 1 != pages.len() {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} claims an early end of index"
            )));
        }
    }
    if after.is_some() || normalized.len() != expected {
        return Err(artifact_error(format!(
            "guarded campaign finding export {index} occurrence query chain is incomplete"
        )));
    }
    Ok(normalized)
}

fn authenticate_empty_guarded_occurrence_page(
    index: usize,
    membership: &CampaignFindingsMembershipProof,
    page: &CampaignFindingOccurrencesProof,
) -> Result<(), CliError> {
    let client = crucible_campaign::CampaignClient::new(ImportedCampaignFindingService::new(
        membership.clone(),
        Vec::new(),
        vec![page.clone()],
        Vec::new(),
    ));
    client
        .query_campaign_finding_occurrences(&page.request)
        .map(|_| ())
        .map_err(|error| {
            artifact_error(format!(
                "guarded campaign finding export {index} empty occurrence page was rejected: {error}"
            ))
        })
}

struct GuardedOccurrenceObjectProofs {
    observation: CampaignFindingOccurrenceObjectProof,
    reproduction: CampaignFindingOccurrenceObjectProof,
    minimized: CampaignFindingOccurrenceObjectProof,
    triage: Option<CampaignFindingOccurrenceTriageProof>,
}

fn guarded_occurrence_object_proofs(
    index: usize,
    page_index: usize,
    page: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingOccurrenceProof,
    bundle: &crucible_campaign::FindingCandidateBundle,
) -> Result<GuardedOccurrenceObjectProofs, CliError> {
    let mut observation = None;
    let mut reproduction = None;
    let mut minimized = None;
    for object in page.objects() {
        let normalized = CampaignFindingOccurrenceObjectProof {
            request: object.request().clone(),
            response: object.response().clone(),
        };
        let slot = match object.request().kind() {
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation => &mut observation,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction => &mut reproduction,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction => {
                &mut minimized
            }
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence
            | crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence
            | crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence
            | crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence => {
                return Err(artifact_error(format!(
                    "guarded campaign finding export {index} occurrence page {page_index} contains an unsegmented triage proof"
                )));
            }
        };
        if slot.replace(normalized).is_some() {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} repeats an object proof"
            )));
        }
    }

    let required = |proof: Option<CampaignFindingOccurrenceObjectProof>, name: &str| {
        proof.ok_or_else(|| {
            artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} has no {name} proof"
            ))
        })
    };
    let observation = required(observation, "observation")?;
    let reproduction = required(reproduction, "reproduction")?;
    let minimized = required(minimized, "minimized reproduction")?;
    let triage = match (bundle.triage_evidence(), page.triage_replays()) {
        (None, None) => None,
        (Some(evidence), Some(replays)) => Some(CampaignFindingOccurrenceTriageProof {
            minimization_original: guarded_triage_replay_proof(
                index,
                page_index,
                crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal,
                evidence.minimization_original(),
                replays.minimization_original(),
            )?,
            minimization_selected: guarded_triage_replay_proof(
                index,
                page_index,
                crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected,
                evidence.minimization_selected(),
                replays.minimization_selected(),
            )?,
            verification_original: guarded_triage_replay_proof(
                index,
                page_index,
                crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal,
                evidence.verification_original(),
                replays.verification_original(),
            )?,
            verification_selected: guarded_triage_replay_proof(
                index,
                page_index,
                crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected,
                evidence.verification_selected(),
                replays.verification_selected(),
            )?,
        }),
        _ => {
            return Err(artifact_error(format!(
                "guarded campaign finding export {index} occurrence page {page_index} has incomplete triage replay proofs"
            )));
        }
    };
    Ok(GuardedOccurrenceObjectProofs {
        observation,
        reproduction,
        minimized,
        triage,
    })
}

fn guarded_triage_replay_proof(
    finding_index: usize,
    page_index: usize,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
    proof: &crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignFindingTriageReplayProof,
) -> Result<CampaignFindingTriageReplayProof, CliError> {
    if proof.segments().is_empty() {
        return Err(artifact_error(format!(
            "guarded campaign finding export {finding_index} occurrence page {page_index} has an empty triage replay transfer"
        )));
    }
    let segments = proof
        .segments()
        .iter()
        .map(|segment| {
            if segment.request().role() != role || segment.request().evidence() != evidence {
                return Err(artifact_error(format!(
                    "guarded campaign finding export {finding_index} occurrence page {page_index} has a substituted triage replay segment"
                )));
            }
            Ok(CampaignFindingTriageReplaySegmentProof {
                request: segment.request().clone(),
                response: segment.response().clone(),
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(CampaignFindingTriageReplayProof { segments })
}
