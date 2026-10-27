//! Campaign service capture and the store-backed offline proof service.
//!
//! Capture writes every checked request and response into the evidence store
//! as soon as it arrives and keeps only content addresses. A triage replay's
//! segments stay resident only while that one replay is reassembled and
//! checked. The result is one stored [`CampaignFindingEvidenceRecord`].
//!
//! Offline authentication replays the same client checks against
//! [`StoredCampaignFindingService`], which answers a request only when its
//! canonical bytes hash to a request named in the current evidence scope.

use super::record::{
    CampaignFindingEvidenceRecord, CampaignOccurrenceChunkWriter, CampaignOccurrenceExchanges,
    CampaignTriageRoleExchanges, TRIAGE_REPLAY_ROLES,
};
use super::reproduction::{
    capture_finding_reproduction_segments, capture_occurrence_reproduction_segments,
};
use super::store::{
    CampaignExchangeRef, MAX_CAMPAIGN_EXCHANGE_BLOB_BYTES, put_evidence_blob, read_evidence_blob,
};
use super::triage_segments::capture_occurrence_triage_log_segments;
use super::*;

/// Principal, campaign snapshot, and finding that one capture reads.
#[derive(Clone)]
pub(crate) struct CampaignFindingCaptureScope {
    pub(crate) principal: crucible_campaign::CampaignPrincipal,
    pub(crate) campaign: crucible_campaign::CampaignName,
    pub(crate) snapshot: crucible_campaign::CampaignSnapshotId,
    pub(crate) finding: crucible_campaign::FindingId,
}

/// Capture scope narrowed to one retained candidate bundle.
pub(super) struct CampaignFindingOccurrenceScope<'a> {
    pub(super) finding: &'a CampaignFindingCaptureScope,
    pub(super) bundle: crucible_campaign::FindingCandidateBundleId,
}

/// Finds the findings page that admits `scope.finding`.
///
/// Triage already holds each page while it walks the snapshot and passes it
/// to [`capture_campaign_triage_finding_from_service`] directly; this scan is
/// for single-finding callers such as bundle export.
///
/// # Errors
///
/// Returns an error when a query fails or the snapshot does not retain the
/// finding.
pub(crate) fn find_campaign_finding_membership<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
) -> Result<CampaignFindingsMembershipProof, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut after = None;
    loop {
        let request = crucible_campaign::QueryCampaignFindingsRequest::new(
            scope.principal.clone(),
            scope.campaign.clone(),
            scope.snapshot,
            after,
            crucible_campaign::MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
        )
        .map_err(|error| artifact_error(format!("build campaign finding query: {error}")))?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(|error| artifact_error(format!("query campaign finding evidence: {error}")))?;
        if response
            .entries()
            .iter()
            .any(|finding| finding.id() == Ok(scope.finding))
        {
            return Ok(CampaignFindingsMembershipProof { request, response });
        }
        after = response.next_after();
        if after.is_none() {
            return Err(artifact_error(
                "campaign snapshot does not retain the requested finding",
            ));
        }
    }
}

/// Captures one finding with an explicit report projection into `store`.
///
/// # Errors
///
/// Returns an error when a service read fails or the evidence cannot be stored.
#[cfg(test)]
pub(crate) fn capture_campaign_triage_finding<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    membership: &CampaignFindingsMembershipProof,
    report: TriageFindingEvidence,
    store: &crucible_engine::LocalDagStore,
) -> Result<crucible_engine::ContentHash, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_triage_finding_with_report(client, scope, membership, Some(report), store)
}

/// Captures one finding into `store` and returns its evidence record key.
///
/// `membership` is the checked findings page that admits the finding. The
/// report projection is derived from the first occurrence that retains native
/// triage replays. Capture does not authenticate; loading the ledger does.
///
/// # Errors
///
/// Returns an error when a service read fails, no occurrence retains native
/// triage replays, or the evidence cannot be stored.
pub(crate) fn capture_campaign_triage_finding_from_service<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    membership: &CampaignFindingsMembershipProof,
    store: &crucible_engine::LocalDagStore,
) -> Result<crucible_engine::ContentHash, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_triage_finding_with_report(client, scope, membership, None, store)
}

fn capture_campaign_triage_finding_with_report<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    membership: &CampaignFindingsMembershipProof,
    mut report: Option<TriageFindingEvidence>,
    store: &crucible_engine::LocalDagStore,
) -> Result<crucible_engine::ContentHash, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let finding = membership
        .response
        .entries()
        .iter()
        .find(|finding| finding.id() == Ok(scope.finding))
        .ok_or_else(|| artifact_error("campaign snapshot does not retain the requested finding"))?;
    let membership_exchange = CampaignExchangeRef::put(
        store,
        &membership.request.canonical_bytes(),
        &membership.response.canonical_bytes(),
    )?;
    let observation = capture_campaign_finding_object(
        client,
        scope,
        crucible_campaign::CampaignFindingObjectKind::Observation,
        store,
    )?;
    let (reproduction, reproduction_response) = capture_campaign_finding_object_with_response(
        client,
        scope,
        crucible_campaign::CampaignFindingObjectKind::Reproduction,
        store,
    )?;
    let reproduction_segments = capture_finding_reproduction_segments(
        client,
        scope,
        false,
        finding_reproduction(&reproduction_response, false)?,
        store,
    )?;
    let minimized = finding
        .minimized()
        .map(|_| {
            let (exchange, response) = capture_campaign_finding_object_with_response(
                client,
                scope,
                crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction,
                store,
            )?;
            let segments = capture_finding_reproduction_segments(
                client,
                scope,
                true,
                finding_reproduction(&response, true)?,
                store,
            )?;
            Ok::<_, CliError>((exchange, segments))
        })
        .transpose()?;

    let expected_occurrences = u64::from(finding.candidate_occurrence_count());
    let mut chunks = CampaignOccurrenceChunkWriter::new(store);
    let mut occurrence_after = None;
    for _ in 0..expected_occurrences {
        let (occurrence, next_after) = capture_campaign_finding_occurrence(
            client,
            scope,
            occurrence_after,
            &mut report,
            store,
        )?;
        chunks.push(occurrence)?;
        occurrence_after = next_after;
    }
    let (occurrence_count, chunks) = chunks.finish()?;

    let report = report.ok_or_else(|| {
        artifact_error("campaign finding has no retained native triage replay evidence")
    })?;
    let report = put_evidence_blob(
        store,
        &crate::cli_triage_debug::ledger_format::reproduction_findings_ledger_bytes(
            std::slice::from_ref(&report),
        )?,
    )?;
    CampaignFindingEvidenceRecord {
        campaign: scope.campaign.clone(),
        snapshot: scope.snapshot,
        finding: scope.finding,
        membership: membership_exchange,
        observation,
        reproduction,
        reproduction_segments,
        minimized: minimized.map(|(exchange, _)| exchange),
        minimized_segments: minimized.map(|(_, segments)| segments),
        report,
        occurrence_count,
        chunks,
    }
    .put(store)
}

/// Returns the reproduction a finding-object response carries.
fn finding_reproduction(
    response: &crucible_campaign::GetCampaignFindingObjectResponse,
    minimized: bool,
) -> Result<&crucible_campaign::ReproductionArtifact, CliError> {
    match (minimized, response.object()) {
        (false, crucible_campaign::CampaignFindingObject::Reproduction(reproduction))
        | (true, crucible_campaign::CampaignFindingObject::MinimizedReproduction(reproduction)) => {
            Ok(reproduction)
        }
        _ => Err(artifact_error(
            "campaign finding reproduction response has another object kind",
        )),
    }
}

/// Captures one occurrence page, its objects, and its replays.
///
/// When `report` is still unset and the occurrence retains native triage
/// replays, the report projection is derived from its minimization-original
/// replay while that replay is resident.
fn capture_campaign_finding_occurrence<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    after: Option<crucible_campaign::CampaignHash>,
    report: &mut Option<TriageFindingEvidence>,
    store: &crucible_engine::LocalDagStore,
) -> Result<
    (
        CampaignOccurrenceExchanges,
        Option<crucible_campaign::CampaignHash>,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::QueryCampaignFindingOccurrencesRequest::new(
        scope.principal.clone(),
        scope.campaign.clone(),
        scope.snapshot,
        scope.finding,
        after,
        crucible_campaign::MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS,
    )
    .map_err(|error| artifact_error(format!("build campaign occurrence query: {error}")))?;
    let response = client
        .query_campaign_finding_occurrences(&request)
        .map_err(|error| artifact_error(format!("query campaign occurrence: {error}")))?;
    let page = CampaignExchangeRef::put(
        store,
        &request.canonical_bytes(),
        &response.canonical_bytes(),
    )?;
    let bundle = response
        .entries()
        .first()
        .ok_or_else(|| artifact_error("campaign occurrence query ended before its count"))?
        .bundle();
    let occurrence_scope = CampaignFindingOccurrenceScope {
        finding: scope,
        bundle: bundle.id().map_err(|error| {
            artifact_error(format!("campaign occurrence bundle ID is invalid: {error}"))
        })?,
    };

    let observation = capture_campaign_finding_occurrence_object(
        client,
        &occurrence_scope,
        crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation,
        store,
    )?;
    let (reproduction, reproduction_response) =
        capture_campaign_finding_occurrence_object_with_response(
            client,
            &occurrence_scope,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction,
            store,
        )?;
    let (minimized, minimized_response) = capture_campaign_finding_occurrence_object_with_response(
        client,
        &occurrence_scope,
        crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
        store,
    )?;

    // The report projection decodes the original reproduction's artifact, so
    // its segments are authenticated as they are captured.
    let wants_report = report.is_none() && bundle.triage_evidence().is_some();
    let (reproduction_segments, reproduction_artifact) = capture_occurrence_reproduction_segments(
        client,
        &occurrence_scope,
        false,
        occurrence_reproduction(&reproduction_response)?,
        wants_report,
        store,
    )?;
    let (minimized_segments, _) = capture_occurrence_reproduction_segments(
        client,
        &occurrence_scope,
        true,
        occurrence_minimized_reproduction(&minimized_response)?,
        false,
        store,
    )?;

    let triage = match bundle.triage_evidence() {
        None => None,
        Some(evidence) => {
            let mut roles: [CampaignTriageRoleExchanges; 4] = Default::default();
            for ((role, _), exchanges) in TRIAGE_REPLAY_ROLES.iter().zip(&mut roles) {
                let (captured, proof, record) = capture_campaign_finding_triage_replay(
                    client,
                    &occurrence_scope,
                    *role,
                    triage_role_evidence(&evidence, *role),
                    store,
                )?;
                // One replay's log segments are resident only while its
                // report projection, if any, is decoded.
                let (log_segments, segments) = capture_occurrence_triage_log_segments(
                    client,
                    &occurrence_scope,
                    *role,
                    &record,
                    store,
                )?;
                if report.is_none()
                    && *role
                        == crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal
                {
                    let artifact = reproduction_artifact.clone().ok_or_else(|| {
                        artifact_error("campaign occurrence reproduction was not decoded")
                    })?;
                    *report = Some(campaign_triage_report_from_replay(
                        evidence.minimization_original(),
                        occurrence_reproduction(&reproduction_response)?,
                        artifact,
                        &proof,
                        &record,
                        segments,
                    )?);
                }
                *exchanges = CampaignTriageRoleExchanges {
                    segments: captured,
                    log_segments,
                };
            }
            Some(roles)
        }
    };

    Ok((
        CampaignOccurrenceExchanges {
            page,
            observation,
            reproduction,
            reproduction_segments,
            minimized,
            minimized_segments,
            triage,
        },
        response.next_after(),
    ))
}

fn occurrence_reproduction(
    response: &crucible_campaign::GetCampaignFindingOccurrenceObjectResponse,
) -> Result<&crucible_campaign::ReproductionArtifact, CliError> {
    match response.object() {
        crucible_campaign::CampaignFindingOccurrenceObject::Reproduction(reproduction) => {
            Ok(reproduction)
        }
        _ => Err(artifact_error(
            "campaign occurrence reproduction proof has another object kind",
        )),
    }
}

fn occurrence_minimized_reproduction(
    response: &crucible_campaign::GetCampaignFindingOccurrenceObjectResponse,
) -> Result<&crucible_campaign::ReproductionArtifact, CliError> {
    match response.object() {
        crucible_campaign::CampaignFindingOccurrenceObject::MinimizedReproduction(reproduction) => {
            Ok(reproduction)
        }
        _ => Err(artifact_error(
            "campaign occurrence minimized proof has another object kind",
        )),
    }
}

/// Decodes the report projection from one minimization-original replay.
fn campaign_triage_report_from_replay(
    expected: crucible_campaign::FindingTriageReplayEvidenceId,
    reproduction: &crucible_campaign::ReproductionArtifact,
    artifact: crucible_engine::ReproductionArtifact,
    proof: &CampaignFindingTriageReplayProof,
    record: &crucible_campaign::FindingTriageReplayEvidence,
    log_segments: crucible_engine::FailureTriageReplaySegments,
) -> Result<TriageFindingEvidence, CliError> {
    if proof.segments.iter().any(|segment| {
        segment.request.role()
            != crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal
            || segment.request.evidence() != expected
    }) || record.id().ok() != Some(expected)
        || record.reproduction()
            != reproduction.id().map_err(|error| {
                artifact_error(format!("campaign reproduction ID is invalid: {error}"))
            })?
        || record.payload_schema() != crucible_engine::FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    {
        return Err(artifact_error(
            "campaign occurrence triage payload has an incompatible semantic binding",
        ));
    }
    let replay =
        crucible_engine::FailureTriageReplayEvidence::from_compact_binary_for_reproduction(
            crucible_engine::ContentHash {
                bytes: reproduction.finding_fingerprint().as_bytes(),
            },
            artifact,
            record.payload(),
            log_segments,
        )
        .map_err(|error| {
            artifact_error(format!(
                "campaign occurrence triage payload is invalid: {error}"
            ))
        })?;
    validate_campaign_native_signature_binding(record, reproduction, &replay)?;
    triage_finding_evidence_from_replay(&replay)
}

fn capture_campaign_finding_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    kind: crucible_campaign::CampaignFindingObjectKind,
    store: &crucible_engine::LocalDagStore,
) -> Result<CampaignExchangeRef, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_finding_object_with_response(client, scope, kind, store)
        .map(|(exchange, _)| exchange)
}

fn capture_campaign_finding_object_with_response<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    kind: crucible_campaign::CampaignFindingObjectKind,
    store: &crucible_engine::LocalDagStore,
) -> Result<
    (
        CampaignExchangeRef,
        crucible_campaign::GetCampaignFindingObjectResponse,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
        scope.principal.clone(),
        scope.campaign.clone(),
        scope.snapshot,
        scope.finding,
        kind,
    )
    .map_err(|error| artifact_error(format!("build campaign finding object query: {error}")))?;
    let response = client
        .get_campaign_finding_object(&request)
        .map_err(|error| artifact_error(format!("query campaign finding object: {error}")))?;
    let exchange = CampaignExchangeRef::put(
        store,
        &request.canonical_bytes(),
        &response.canonical_bytes(),
    )?;
    Ok((exchange, response))
}

fn capture_campaign_finding_occurrence_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope<'_>,
    kind: crucible_campaign::CampaignFindingOccurrenceObjectKind,
    store: &crucible_engine::LocalDagStore,
) -> Result<CampaignExchangeRef, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    capture_campaign_finding_occurrence_object_with_response(client, scope, kind, store)
        .map(|(exchange, _)| exchange)
}

fn capture_campaign_finding_occurrence_object_with_response<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope<'_>,
    kind: crucible_campaign::CampaignFindingOccurrenceObjectKind,
    store: &crucible_engine::LocalDagStore,
) -> Result<
    (
        CampaignExchangeRef,
        crucible_campaign::GetCampaignFindingOccurrenceObjectResponse,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::new(
        scope.finding.principal.clone(),
        scope.finding.campaign.clone(),
        scope.finding.snapshot,
        scope.finding.finding,
        scope.bundle,
        kind,
    )
    .map_err(|error| artifact_error(format!("build campaign occurrence object query: {error}")))?;
    let response = client
        .get_campaign_finding_occurrence_object(&request)
        .map_err(|error| artifact_error(format!("query campaign occurrence object: {error}")))?;
    let exchange = CampaignExchangeRef::put(
        store,
        &request.canonical_bytes(),
        &response.canonical_bytes(),
    )?;
    Ok((exchange, response))
}

/// Captures one replay role, storing each segment exchange as it arrives.
///
/// The returned proof holds only this replay's segments; callers drop it once
/// any report projection has been derived.
fn capture_campaign_finding_triage_replay<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope<'_>,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
    store: &crucible_engine::LocalDagStore,
) -> Result<
    (
        Vec<CampaignExchangeRef>,
        CampaignFindingTriageReplayProof,
        crucible_campaign::FindingTriageReplayEvidence,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let selection = crucible_campaign::CampaignFindingTriageReplaySelection::new(
        scope.finding.principal.clone(),
        scope.finding.campaign.clone(),
        scope.finding.snapshot,
        scope.finding.finding,
        scope.bundle,
        role,
        evidence,
    );
    let mut exchanges = Vec::new();
    let mut segments = Vec::new();
    let fetch = |exchanges: &mut Vec<CampaignExchangeRef>,
                 segments: &mut Vec<CampaignFindingTriageReplaySegmentProof>,
                 segment: crucible_campaign::CampaignFindingTriageReplaySegment| {
        let request = crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::new(
            selection.clone(),
            segment,
        )
        .map_err(|error| artifact_error(format!("build campaign triage segment query: {error}")))?;
        let response = client
            .get_campaign_finding_triage_replay_segment(&request)
            .map_err(|error| artifact_error(format!("query campaign triage segment: {error}")))?;
        exchanges.push(CampaignExchangeRef::put(
            store,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?);
        let description = response.description().clone();
        segments.push(CampaignFindingTriageReplaySegmentProof { request, response });
        Ok::<_, CliError>(description)
    };

    // The root envelope must be fetched and authenticated before its
    // description may be trusted to name the child objects.
    let description = fetch(
        &mut exchanges,
        &mut segments,
        crucible_campaign::CampaignFindingTriageReplaySegment::new(0, evidence.content_id(), 0),
    )?;
    let root = description
        .objects()
        .first()
        .ok_or_else(|| artifact_error("campaign triage storage description has no root"))?;
    for segment_index in 1..object_segment_count(root.stored_envelope_bytes())? {
        fetch(
            &mut exchanges,
            &mut segments,
            crucible_campaign::CampaignFindingTriageReplaySegment::new(
                root.ordinal(),
                root.content(),
                segment_index,
            ),
        )?;
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
        for segment_index in 0..object_segment_count(object.stored_envelope_bytes())? {
            fetch(
                &mut exchanges,
                &mut segments,
                crucible_campaign::CampaignFindingTriageReplaySegment::new(
                    object.ordinal(),
                    object.content(),
                    segment_index,
                ),
            )?;
        }
    }
    let proof = CampaignFindingTriageReplayProof { segments };
    let record = reassemble_campaign_triage_replay_proof(&proof)?;
    Ok((exchanges, proof, record))
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

/// Serves stored canonical responses through the campaign finding query traits.
///
/// Each table maps the content address of a request's canonical bytes to its
/// response blob, so a request is answered only when it is byte-for-byte one
/// that the current evidence scope names. Any other request, a missing or
/// corrupt blob, or an undecodable response is a protocol violation, exactly
/// as an absent in-memory proof was.
pub(super) struct StoredCampaignFindingService {
    store: crucible_engine::LocalDagStore,
    findings: BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
    objects: BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
    occurrences: BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
    occurrence_objects: BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
    triage_segments: BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
}

impl StoredCampaignFindingService {
    /// Serves one finding's membership and finding-object exchanges.
    pub(super) fn for_finding(
        store: &crucible_engine::LocalDagStore,
        record: &CampaignFindingEvidenceRecord,
    ) -> Self {
        let mut service = Self::empty(store);
        insert_exchange(&mut service.findings, record.membership);
        for exchange in [record.observation, record.reproduction]
            .into_iter()
            .chain(record.minimized)
        {
            insert_exchange(&mut service.objects, exchange);
        }
        service
    }

    /// Serves one occurrence's page, object, and segment exchanges.
    pub(super) fn for_occurrence(
        store: &crucible_engine::LocalDagStore,
        occurrence: &CampaignOccurrenceExchanges,
    ) -> Self {
        let mut service = Self::empty(store);
        insert_exchange(&mut service.occurrences, occurrence.page);
        for exchange in [
            occurrence.observation,
            occurrence.reproduction,
            occurrence.minimized,
        ] {
            insert_exchange(&mut service.occurrence_objects, exchange);
        }
        for exchange in occurrence
            .triage
            .iter()
            .flatten()
            .flat_map(|role| &role.segments)
        {
            insert_exchange(&mut service.triage_segments, *exchange);
        }
        service
    }

    /// Serves the finding-object exchanges of one reproduction's segments.
    pub(super) fn for_finding_objects(
        store: &crucible_engine::LocalDagStore,
        exchanges: &[CampaignExchangeRef],
    ) -> Self {
        let mut service = Self::empty(store);
        for exchange in exchanges {
            insert_exchange(&mut service.objects, *exchange);
        }
        service
    }

    /// Serves the occurrence-object exchanges of one reproduction's segments.
    pub(super) fn for_occurrence_objects(
        store: &crucible_engine::LocalDagStore,
        exchanges: &[CampaignExchangeRef],
    ) -> Self {
        let mut service = Self::empty(store);
        for exchange in exchanges {
            insert_exchange(&mut service.occurrence_objects, *exchange);
        }
        service
    }

    fn empty(store: &crucible_engine::LocalDagStore) -> Self {
        Self {
            store: store.clone(),
            findings: BTreeMap::new(),
            objects: BTreeMap::new(),
            occurrences: BTreeMap::new(),
            occurrence_objects: BTreeMap::new(),
            triage_segments: BTreeMap::new(),
        }
    }

    fn respond<T>(
        &self,
        table: &BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
        request: &[u8],
        decode: impl FnOnce(&[u8]) -> Result<T, crucible_campaign::CampaignCodecError>,
    ) -> Result<T, crucible_campaign::CampaignServiceFailure> {
        let response = table
            .get(&crucible_engine::ContentHash::from_bytes(request))
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)?;
        let bytes = read_evidence_blob(
            &self.store,
            *response,
            MAX_CAMPAIGN_EXCHANGE_BLOB_BYTES,
            "campaign response",
        )
        .map_err(|_| crucible_campaign::CampaignServiceFailure::ProtocolViolation)?;
        decode(&bytes).map_err(|_| crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }
}

fn insert_exchange(
    table: &mut BTreeMap<crucible_engine::ContentHash, crucible_engine::ContentHash>,
    exchange: CampaignExchangeRef,
) {
    table.insert(exchange.request, exchange.response);
}

impl crucible_campaign::CampaignFindingOccurrenceService for StoredCampaignFindingService {
    fn query_campaign_finding_occurrences(
        &self,
        request: &crucible_campaign::QueryCampaignFindingOccurrencesRequest,
    ) -> Result<crucible_campaign::QueryCampaignFindingOccurrencesResponse, Self::Error> {
        self.respond(
            &self.occurrences,
            &request.canonical_bytes(),
            crucible_campaign::QueryCampaignFindingOccurrencesResponse::from_canonical_bytes,
        )
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        self.respond(
            &self.occurrence_objects,
            &request.canonical_bytes(),
            crucible_campaign::GetCampaignFindingOccurrenceObjectResponse::from_canonical_bytes,
        )
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
        self.respond(
            &self.triage_segments,
            &request.canonical_bytes(),
            crucible_campaign::GetCampaignFindingTriageReplaySegmentResponse::from_canonical_bytes,
        )
    }
}

macro_rules! reject_stored_campaign_service_operations {
    ($($method:ident($request:ty) -> $response:ty;)*) => {
        $(
            fn $method(&self, _request: &$request) -> Result<$response, Self::Error> {
                Err(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
            }
        )*
    };
}

impl crucible_campaign::CampaignService for StoredCampaignFindingService {
    type Error = crucible_campaign::CampaignServiceFailure;

    reject_stored_campaign_service_operations! {
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
        campaign_savepoint(crucible_campaign::CampaignSavepointRequest) -> crucible_campaign::CampaignSavepointResponse;
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
        self.respond(
            &self.findings,
            &request.canonical_bytes(),
            crucible_campaign::QueryCampaignFindingsResponse::from_canonical_bytes,
        )
    }

    fn get_campaign_finding_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingObjectResponse, Self::Error> {
        self.respond(
            &self.objects,
            &request.canonical_bytes(),
            crucible_campaign::GetCampaignFindingObjectResponse::from_canonical_bytes,
        )
    }
}

#[path = "service/authentication.rs"]
mod authentication;

pub(crate) use authentication::{
    CampaignFindingAuthenticationContext, OccurrenceCursorCheck,
    authenticate_campaign_finding_head, authenticate_campaign_occurrence,
    authenticate_campaign_occurrences, validate_campaign_triage_finding,
};
