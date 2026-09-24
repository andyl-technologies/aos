//! Campaign service capture and offline proof authentication.

use super::*;

#[derive(Clone)]
pub(crate) struct CampaignFindingOccurrenceScope {
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    bundle: crucible_campaign::FindingCandidateBundleId,
}

impl CampaignFindingOccurrenceScope {
    pub(crate) fn new(
        principal: crucible_campaign::CampaignPrincipal,
        campaign: crucible_campaign::CampaignName,
        snapshot: crucible_campaign::CampaignSnapshotId,
        finding: crucible_campaign::FindingId,
        bundle: crucible_campaign::FindingCandidateBundleId,
    ) -> Self {
        Self {
            principal,
            campaign,
            snapshot,
            finding,
            bundle,
        }
    }
}

#[derive(Clone, Copy)]
struct CampaignTriageReplayAuthenticationContext<'a> {
    finding_index: usize,
    page_index: usize,
    item: &'a CampaignTriageFindingEvidence,
    finding: crucible_campaign::FindingId,
    bundle: crucible_campaign::FindingCandidateBundleId,
}

#[cfg(test)]
pub(crate) fn capture_campaign_triage_finding<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding_id: crucible_campaign::FindingId,
    report: TriageFindingEvidence,
) -> Result<CampaignTriageFindingEvidence, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_triage_finding_with_report(
        client,
        principal,
        campaign,
        snapshot,
        finding_id,
        Some(report),
    )
}

pub(crate) fn capture_campaign_triage_finding_from_service<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding_id: crucible_campaign::FindingId,
) -> Result<CampaignTriageFindingEvidence, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_triage_finding_with_report(
        client, principal, campaign, snapshot, finding_id, None,
    )
}

fn capture_campaign_triage_finding_with_report<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding_id: crucible_campaign::FindingId,
    report: Option<TriageFindingEvidence>,
) -> Result<CampaignTriageFindingEvidence, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut after = None;
    let (membership, finding) = loop {
        let request = crucible_campaign::QueryCampaignFindingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            crucible_campaign::MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
        )
        .map_err(|error| artifact_error(format!("build campaign finding query: {error}")))?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(|error| artifact_error(format!("query campaign finding evidence: {error}")))?;
        let finding = response
            .entries()
            .iter()
            .find(|finding| finding.id() == Ok(finding_id))
            .cloned();
        if let Some(finding) = finding {
            break (
                CampaignFindingsMembershipProof { request, response },
                finding,
            );
        }
        after = response.next_after();
        if after.is_none() {
            return Err(artifact_error(
                "campaign snapshot does not retain the requested finding",
            ));
        }
    };

    let observation_proof = capture_campaign_finding_object(
        client,
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding_id,
        crucible_campaign::CampaignFindingObjectKind::Observation,
    )?;
    let reproduction_proof = capture_campaign_finding_object(
        client,
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding_id,
        crucible_campaign::CampaignFindingObjectKind::Reproduction,
    )?;
    let minimized_reproduction_proof = finding
        .minimized()
        .map(|_| {
            capture_campaign_finding_object(
                client,
                principal.clone(),
                campaign.clone(),
                snapshot,
                finding_id,
                crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction,
            )
        })
        .transpose()?;
    let observation = match observation_proof.response.object() {
        crucible_campaign::CampaignFindingObject::Observation(value) => value.clone(),
        _ => return Err(artifact_error("campaign returned another observation kind")),
    };
    let reproduction = match reproduction_proof.response.object() {
        crucible_campaign::CampaignFindingObject::Reproduction(value) => value.clone(),
        _ => {
            return Err(artifact_error(
                "campaign returned another reproduction kind",
            ));
        }
    };
    let minimized_reproduction = minimized_reproduction_proof
        .as_ref()
        .map(|proof| match proof.response.object() {
            crucible_campaign::CampaignFindingObject::MinimizedReproduction(value) => {
                Ok(value.clone())
            }
            _ => Err(artifact_error(
                "campaign returned another minimized reproduction kind",
            )),
        })
        .transpose()?;

    let mut occurrence_proofs = Vec::new();
    let mut occurrence_after = None;
    while occurrence_proofs.len()
        < usize::try_from(finding.candidate_occurrence_count())
            .map_err(|_| artifact_error("campaign finding occurrence count is invalid"))?
    {
        let request = crucible_campaign::QueryCampaignFindingOccurrencesRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            occurrence_after,
            1,
        )
        .map_err(|error| artifact_error(format!("build campaign occurrence query: {error}")))?;
        let response = client
            .query_campaign_finding_occurrences(&request)
            .map_err(|error| artifact_error(format!("query campaign occurrence: {error}")))?;
        let bundle = response
            .entries()
            .first()
            .ok_or_else(|| artifact_error("campaign occurrence query ended before its count"))?
            .bundle();
        let bundle_id = bundle.id().map_err(|error| {
            artifact_error(format!("campaign occurrence bundle ID is invalid: {error}"))
        })?;
        let occurrence_scope = CampaignFindingOccurrenceScope::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            bundle_id,
        );
        let observation = capture_campaign_finding_occurrence_object(
            client,
            &occurrence_scope,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation,
        )?;
        let reproduction = capture_campaign_finding_occurrence_object(
            client,
            &occurrence_scope,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction,
        )?;
        let minimized_reproduction = capture_campaign_finding_occurrence_object(
            client,
            &occurrence_scope,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
        )?;
        let triage_evidence = bundle
            .triage_evidence()
            .as_ref()
            .map(|evidence| {
                capture_campaign_finding_triage_replay_set(client, &occurrence_scope, evidence)
            })
            .transpose()?;
        occurrence_after = response.next_after();
        occurrence_proofs.push(CampaignFindingOccurrenceProof {
            page: CampaignFindingOccurrencesProof { request, response },
            observation,
            reproduction,
            minimized_reproduction,
            triage_evidence,
        });
    }

    let report = match report {
        Some(report) => report,
        None => campaign_triage_report_from_occurrences(&occurrence_proofs)?,
    };
    let evidence = CampaignTriageFindingEvidence {
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
    authenticate_campaign_triage_finding(0, finding_id, &evidence)?;
    validate_campaign_triage_finding(0, finding_id, &evidence)?;
    Ok(evidence)
}

fn campaign_triage_report_from_occurrences(
    occurrences: &[CampaignFindingOccurrenceProof],
) -> Result<TriageFindingEvidence, CliError> {
    for occurrence in occurrences {
        let Some(triage) = occurrence.triage_evidence.as_ref() else {
            continue;
        };
        let bundle = campaign_occurrence_bundle(occurrence)?;
        let expected = bundle
            .triage_evidence()
            .ok_or_else(|| artifact_error("campaign occurrence has no triage evidence set"))?
            .minimization_original();
        let reproduction = campaign_occurrence_reproduction(occurrence)?;
        let record = reassemble_campaign_triage_replay_proof(&triage.minimization_original)?;
        if triage.minimization_original.segments.iter().any(|segment| {
            segment.request.role()
                != crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal
                || segment.request.evidence() != expected
        }) || record.id().ok() != Some(expected)
            || record.reproduction()
                != reproduction.id().map_err(|error| {
                    artifact_error(format!("campaign reproduction ID is invalid: {error}"))
                })?
            || record.payload_schema() != crucible::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
        {
            return Err(artifact_error(
                "campaign occurrence triage payload has an incompatible semantic binding",
            ));
        }
        let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
            .map_err(|error| {
                artifact_error(format!("campaign reproduction is invalid: {error}"))
            })?;
        let replay = crucible::FailureTriageReplayEvidence::from_compact_binary_for_reproduction(
            crucible::ContentHash {
                bytes: reproduction.finding_fingerprint().as_bytes(),
            },
            artifact,
            record.payload(),
        )
        .map_err(|error| {
            artifact_error(format!(
                "campaign occurrence triage payload is invalid: {error}"
            ))
        })?;
        validate_campaign_native_signature_binding(&record, reproduction, &replay)?;

        return Ok(triage_finding_evidence_from_replay(&replay));
    }

    Err(artifact_error(
        "campaign finding has no retained native triage replay evidence",
    ))
}

fn capture_campaign_finding_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    kind: crucible_campaign::CampaignFindingObjectKind,
) -> Result<CampaignFindingObjectProof, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
        principal, campaign, snapshot, finding, kind,
    )
    .map_err(|error| artifact_error(format!("build campaign finding object query: {error}")))?;
    let response = client
        .get_campaign_finding_object(&request)
        .map_err(|error| artifact_error(format!("query campaign finding object: {error}")))?;
    Ok(CampaignFindingObjectProof { request, response })
}

fn capture_campaign_finding_occurrence_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope,
    kind: crucible_campaign::CampaignFindingOccurrenceObjectKind,
) -> Result<CampaignFindingOccurrenceObjectProof, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::new(
        scope.principal.clone(),
        scope.campaign.clone(),
        scope.snapshot,
        scope.finding,
        scope.bundle,
        kind,
    )
    .map_err(|error| artifact_error(format!("build campaign occurrence object query: {error}")))?;
    let response = client
        .get_campaign_finding_occurrence_object(&request)
        .map_err(|error| artifact_error(format!("query campaign occurrence object: {error}")))?;
    Ok(CampaignFindingOccurrenceObjectProof { request, response })
}

pub(crate) fn capture_campaign_finding_triage_replay<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
) -> Result<CampaignFindingTriageReplayProof, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let selection = crucible_campaign::CampaignFindingTriageReplaySelection::new(
        scope.principal.clone(),
        scope.campaign.clone(),
        scope.snapshot,
        scope.finding,
        scope.bundle,
        role,
        evidence,
    );
    let first_request = crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::new(
        selection.clone(),
        crucible_campaign::CampaignFindingTriageReplaySegment::new(0, evidence.content_id(), 0),
    )
    .map_err(|error| artifact_error(format!("build campaign triage segment query: {error}")))?;
    let first_response = client
        .get_campaign_finding_triage_replay_segment(&first_request)
        .map_err(|error| artifact_error(format!("query campaign triage segment: {error}")))?;
    let description = first_response.description().clone();
    let mut segments = vec![CampaignFindingTriageReplaySegmentProof {
        request: first_request,
        response: first_response,
    }];

    let root = description
        .objects()
        .first()
        .ok_or_else(|| artifact_error("campaign triage storage description has no root"))?;
    let root_segment_count = object_segment_count(root.stored_envelope_bytes())?;
    for segment_index in 1..root_segment_count {
        let request = crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::new(
            selection.clone(),
            crucible_campaign::CampaignFindingTriageReplaySegment::new(
                root.ordinal(),
                root.content(),
                segment_index,
            ),
        )
        .map_err(|error| artifact_error(format!("build campaign triage segment query: {error}")))?;
        let response = client
            .get_campaign_finding_triage_replay_segment(&request)
            .map_err(|error| artifact_error(format!("query campaign triage segment: {error}")))?;
        segments.push(CampaignFindingTriageReplaySegmentProof { request, response });
    }
    let root_bytes = campaign_triage_object_bytes(&description, root, &segments)?;
    description
        .authenticate_root_envelope(&root_bytes)
        .map_err(|error| {
            artifact_error(format!(
                "campaign triage root storage proof is invalid: {error}"
            ))
        })?;

    for object in &description.objects()[1..] {
        let segment_count = object.stored_envelope_bytes();
        let segment_count = object_segment_count(segment_count)?;
        for segment_index in 0..segment_count {
            let request = crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::new(
                selection.clone(),
                crucible_campaign::CampaignFindingTriageReplaySegment::new(
                    object.ordinal(),
                    object.content(),
                    segment_index,
                ),
            )
            .map_err(|error| {
                artifact_error(format!("build campaign triage segment query: {error}"))
            })?;
            let response = client
                .get_campaign_finding_triage_replay_segment(&request)
                .map_err(|error| {
                    artifact_error(format!("query campaign triage segment: {error}"))
                })?;
            segments.push(CampaignFindingTriageReplaySegmentProof { request, response });
        }
    }
    let proof = CampaignFindingTriageReplayProof { segments };
    reassemble_campaign_triage_replay_proof(&proof)?;
    Ok(proof)
}

fn capture_campaign_finding_triage_replay_set<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope,
    evidence: &crucible_campaign::FindingTriageEvidenceSet,
) -> Result<CampaignFindingOccurrenceTriageProof, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    Ok(CampaignFindingOccurrenceTriageProof {
        minimization_original: capture_campaign_finding_triage_replay(
            client,
            scope,
            crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal,
            evidence.minimization_original(),
        )?,
        minimization_selected: capture_campaign_finding_triage_replay(
            client,
            scope,
            crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected,
            evidence.minimization_selected(),
        )?,
        verification_original: capture_campaign_finding_triage_replay(
            client,
            scope,
            crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal,
            evidence.verification_original(),
        )?,
        verification_selected: capture_campaign_finding_triage_replay(
            client,
            scope,
            crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected,
            evidence.verification_selected(),
        )?,
    })
}

fn object_segment_count(stored_envelope_bytes: u64) -> Result<u32, CliError> {
    let count = stored_envelope_bytes
        .checked_add(crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
        .ok_or_else(|| artifact_error("campaign triage segment count overflows"))?
        / crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES;
    u32::try_from(count).map_err(|_| artifact_error("campaign triage segment count is invalid"))
}

fn campaign_triage_object_bytes(
    description: &crucible_campaign::FindingTriageReplayStorageDescription,
    object: &crucible_campaign::FindingTriageReplayStorageObject,
    segments: &[CampaignFindingTriageReplaySegmentProof],
) -> Result<Vec<u8>, CliError> {
    let object_bytes = usize::try_from(object.stored_envelope_bytes())
        .map_err(|_| artifact_error("campaign triage storage envelope length is invalid"))?;
    let mut envelope = Vec::with_capacity(object_bytes);
    for segment in segments
        .iter()
        .filter(|segment| segment.request.object_ordinal() == object.ordinal())
    {
        let expected_index = u32::try_from(
            u64::try_from(envelope.len())
                .map_err(|_| artifact_error("campaign triage storage envelope is oversized"))?
                / crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
        )
        .map_err(|_| artifact_error("campaign triage segment count is invalid"))?;
        if segment.request.object() != object.content()
            || segment.request.segment_index() != expected_index
            || segment.response.description() != description
        {
            return Err(artifact_error(
                "campaign triage storage segments are reordered or substituted",
            ));
        }
        segment
            .response
            .validate_for(&segment.request)
            .map_err(|error| {
                artifact_error(format!(
                    "campaign triage segment response is invalid: {error}"
                ))
            })?;
        envelope.extend_from_slice(segment.response.range_bytes());
    }
    if envelope.len() != object_bytes {
        return Err(artifact_error(
            "campaign triage storage envelope transfer is incomplete",
        ));
    }
    Ok(envelope)
}

#[derive(Clone)]
/// Serves imported guarded proofs through the campaign finding query traits.
pub(super) struct ImportedCampaignFindingService {
    membership: CampaignFindingsMembershipProof,
    objects: Vec<CampaignFindingObjectProof>,
    occurrences: Vec<CampaignFindingOccurrencesProof>,
    occurrence_objects: Vec<CampaignFindingOccurrenceObjectProof>,
    triage_segments: Vec<CampaignFindingTriageReplaySegmentProof>,
}

impl crucible_campaign::CampaignFindingOccurrenceService for ImportedCampaignFindingService {
    fn query_campaign_finding_occurrences(
        &self,
        request: &crucible_campaign::QueryCampaignFindingOccurrencesRequest,
    ) -> Result<crucible_campaign::QueryCampaignFindingOccurrencesResponse, Self::Error> {
        self.occurrences
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        self.occurrence_objects
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
        self.triage_segments
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }
}

macro_rules! reject_imported_campaign_service_operations {
    ($($method:ident($request:ty) -> $response:ty;)*) => {
        $(
            fn $method(&self, _request: &$request) -> Result<$response, Self::Error> {
                Err(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
            }
        )*
    };
}

impl crucible_campaign::CampaignService for ImportedCampaignFindingService {
    type Error = crucible_campaign::CampaignServiceFailure;

    reject_imported_campaign_service_operations! {
        list_campaigns(crucible_campaign::ListCampaignsRequest) -> crucible_campaign::ListCampaignsResponse;
        create_campaign(crucible_campaign::CreateCampaignRequest) -> crucible_campaign::CreateCampaignResponse;
        derive_campaign(crucible_campaign::DeriveCampaignRequest) -> crucible_campaign::DeriveCampaignResponse;
        get_campaign(crucible_campaign::GetCampaignRequest) -> crucible_campaign::GetCampaignResponse;
        get_campaign_status(crucible_campaign::GetCampaignStatusRequest) -> crucible_campaign::GetCampaignStatusResponse;
        query_campaign_report(crucible_campaign::QueryCampaignReportRequest) -> crucible_campaign::QueryCampaignReportResponse;
        get_campaign_snapshot(crucible_campaign::GetCampaignSnapshotRequest) -> crucible_campaign::GetCampaignSnapshotResponse;
        watch_campaign(crucible_campaign::WatchCampaignRequest) -> crucible_campaign::WatchCampaignResponse;
        query_campaign_graph(crucible_campaign::QueryCampaignGraphRequest) -> crucible_campaign::QueryCampaignGraphResponse;
        get_campaign_graph_object(crucible_campaign::GetCampaignGraphObjectRequest) -> crucible_campaign::GetCampaignGraphObjectResponse;
        query_campaign_choices(crucible_campaign::QueryCampaignChoicesRequest) -> crucible_campaign::QueryCampaignChoicesResponse;
        query_campaign_frontier(crucible_campaign::QueryCampaignFrontierRequest) -> crucible_campaign::QueryCampaignFrontierResponse;
        explain_campaign_attempt(crucible_campaign::ExplainCampaignAttemptRequest) -> crucible_campaign::ExplainCampaignAttemptResponse;
        get_campaign_trace_chunk(crucible_campaign::GetCampaignTraceChunkRequest) -> crucible_campaign::GetCampaignTraceChunkResponse;
        query_campaign_request_attempts(crucible_campaign::QueryCampaignRequestAttemptsRequest) -> crucible_campaign::QueryCampaignRequestAttemptsResponse;
        get_campaign_planner_rankings(crucible_campaign::GetCampaignPlannerRankingsRequest) -> crucible_campaign::GetCampaignPlannerRankingsResponse;
        get_campaign_frontier_object(crucible_campaign::GetCampaignFrontierObjectRequest) -> crucible_campaign::GetCampaignFrontierObjectResponse;
        get_campaign_choice_object(crucible_campaign::GetCampaignChoiceObjectRequest) -> crucible_campaign::GetCampaignChoiceObjectResponse;
        apply_campaign_command(crucible_campaign::ApplyCampaignCommandRequest) -> crucible_campaign::ApplyCampaignCommandResponse;
        pin_campaign(crucible_campaign::PinCampaignRequest) -> crucible_campaign::PinCampaignResponse;
        submit_discovery_request(crucible_campaign::SubmitCampaignDiscoveryRequest) -> crucible_campaign::SubmitCampaignDiscoveryResponse;
        submit_branch_request(crucible_campaign::SubmitCampaignBranchRequest) -> crucible_campaign::SubmitCampaignBranchResponse;
    }

    fn query_campaign_findings(
        &self,
        request: &crucible_campaign::QueryCampaignFindingsRequest,
    ) -> Result<crucible_campaign::QueryCampaignFindingsResponse, Self::Error> {
        if request != &self.membership.request {
            return Err(crucible_campaign::CampaignServiceFailure::ProtocolViolation);
        }
        Ok(self.membership.response.clone())
    }

    fn get_campaign_finding_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingObjectResponse, Self::Error> {
        self.objects
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }
}

#[path = "service/authentication.rs"]
mod authentication;

pub(crate) use authentication::{
    authenticate_campaign_triage_finding, validate_campaign_triage_finding,
};
