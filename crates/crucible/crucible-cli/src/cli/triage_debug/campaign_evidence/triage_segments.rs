//! Attempt-log segments named by campaign triage replay records.
//!
//! A triage replay record's payload references the replayed attempt logs by
//! segment, and the record names each segment as a trace leaf. Capture
//! fetches each segment through the occurrence-object service and stores the
//! exchange; one segment-list blob per replay role names those exchanges in
//! record order:
//!
//! ```text
//! crucible.failure-triage.triage-log-segments.v1
//! segment_count=2
//! segment.0=<request hash> <response hash>
//! segment.1=<request hash> <response hash>
//! ```
//!
//! Authentication replays each exchange against the stored service, checks
//! that the request names this finding, bundle, role, and position, and that
//! the served bytes derive the segment the authenticated record names. The
//! native replay evidence is then decoded from those segments, which
//! authenticates every log entry against the payload's manifests. Only one
//! replay's segments are resident at a time.

use std::sync::Arc;

use super::record::CampaignFindingEvidenceRecord;
use super::reproduction::SegmentListFormat;
use super::service::{CampaignFindingOccurrenceScope, StoredCampaignFindingService};
use super::store::CampaignExchangeRef;
use super::*;

/// The segment list of one triage replay record's log segments.
const TRIAGE_LOG_SEGMENT_LIST: SegmentListFormat = SegmentListFormat {
    schema: "crucible.failure-triage.triage-log-segments.v1",
    max_segments: crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_LOG_SEGMENTS,
    label: "triage log segment list",
};

/// Captures every log segment `record` names and returns the key of its
/// segment list with the authenticated segments.
///
/// # Errors
///
/// Returns an error when a service read fails, evidence cannot be stored, or
/// a served segment does not derive the segment the record names.
pub(super) fn capture_occurrence_triage_log_segments<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope<'_>,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    record: &crucible_campaign::FindingTriageReplayEvidence,
    store: &crucible_engine::LocalDagStore,
) -> Result<
    (
        crucible_engine::ContentHash,
        crucible_engine::FailureTriageReplaySegments,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let segments = crucible_engine::SharedSegmentStore::new();
    let mut exchanges = Vec::with_capacity(record.log_segments().len());
    for index in 0..segment_positions(record)? {
        let request = crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::new(
            scope.finding.principal.clone(),
            scope.finding.campaign.clone(),
            scope.finding.snapshot,
            scope.finding.finding,
            scope.bundle,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::TriageReplayLogSegment {
                role,
                index,
            },
        )
        .map_err(|error| artifact_error(format!("build triage log segment query: {error}")))?;
        let response = client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(|error| artifact_error(format!("query triage log segment: {error}")))?;
        exchanges.push(CampaignExchangeRef::put(
            store,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?);
        let crucible_campaign::CampaignFindingOccurrenceObject::TriageReplayLogSegment {
            bytes,
            ..
        } = response.object()
        else {
            return Err(artifact_error(
                "campaign triage log segment response has another object kind",
            ));
        };
        store_authenticated_segment(&segments, record, index, bytes)?;
    }

    let list = TRIAGE_LOG_SEGMENT_LIST.put(store, &exchanges)?;
    Ok((list, Arc::new(segments)))
}

/// Authenticates one role's captured log segments against `replay`.
///
/// `replay` must already be authenticated through the same snapshot and
/// bundle.
///
/// # Errors
///
/// Returns an error when the list is malformed or does not cover the record,
/// a request names another dependency, a proof is rejected, or served bytes
/// do not derive the segment the record names.
pub(super) fn authenticate_occurrence_triage_log_segments(
    evidence: &crucible_engine::LocalDagStore,
    record: &CampaignFindingEvidenceRecord,
    bundle: crucible_campaign::FindingCandidateBundleId,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    replay: &crucible_campaign::FindingTriageReplayEvidence,
    list: crucible_engine::ContentHash,
) -> Result<crucible_engine::FailureTriageReplaySegments, CliError> {
    let exchanges = TRIAGE_LOG_SEGMENT_LIST.read(evidence, list)?;
    if exchanges.len() != replay.log_segments().len() {
        return Err(artifact_error(
            "campaign triage log segment list does not cover its record",
        ));
    }
    let client = crucible_campaign::CampaignClient::new(
        StoredCampaignFindingService::for_occurrence_objects(evidence, &exchanges),
    );

    let segments = crucible_engine::SharedSegmentStore::new();
    for (index, exchange) in (0_u32..).zip(&exchanges) {
        let request =
            crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::from_canonical_bytes(
                &exchange.read_request(evidence)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "campaign triage log segment request is invalid: {error}"
                ))
            })?;
        let kind = crucible_campaign::CampaignFindingOccurrenceObjectKind::TriageReplayLogSegment {
            role,
            index,
        };
        if request.campaign() != &record.campaign
            || request.snapshot() != record.snapshot
            || request.finding() != record.finding
            || request.bundle() != bundle
            || request.kind() != kind
        {
            return Err(artifact_error(
                "campaign triage log segment request names another dependency",
            ));
        }
        let response = client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(|error| {
                artifact_error(format!(
                    "campaign triage log segment proof was rejected: {error}"
                ))
            })?;
        let crucible_campaign::CampaignFindingOccurrenceObject::TriageReplayLogSegment {
            bytes,
            ..
        } = response.object()
        else {
            return Err(artifact_error(
                "campaign triage log segment proof has another object kind",
            ));
        };
        store_authenticated_segment(&segments, replay, index, bytes)?;
    }
    Ok(Arc::new(segments))
}

/// Number of log segments `record` names, as request positions.
fn segment_positions(
    record: &crucible_campaign::FindingTriageReplayEvidence,
) -> Result<u32, CliError> {
    u32::try_from(record.log_segments().len())
        .map_err(|_| artifact_error("campaign triage record names too many log segments"))
}

/// Admits served bytes only when they derive the segment at `index`.
fn store_authenticated_segment(
    segments: &crucible_engine::SharedSegmentStore,
    record: &crucible_campaign::FindingTriageReplayEvidence,
    index: u32,
    bytes: &[u8],
) -> Result<(), CliError> {
    let segment = usize::try_from(index)
        .ok()
        .and_then(|index| record.log_segments().get(index))
        .ok_or_else(|| artifact_error("campaign triage log segment is outside its record"))?;
    if bytes.len() as u64 != segment.bytes() || !segment.content().authenticates(bytes) {
        return Err(artifact_error(
            "campaign triage log segment does not derive its record reference",
        ));
    }
    crucible_engine::SegmentSink::put_segment(segments, segment.content(), bytes)
        .map_err(|error| artifact_error(format!("retain campaign triage log segment: {error}")))
}
