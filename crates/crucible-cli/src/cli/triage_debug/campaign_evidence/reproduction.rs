//! Run-length payload segments of campaign reproductions.
//!
//! A campaign reproduction record keeps its Crucible scenario and schedule
//! manifest inline and names every schedule segment as a trace leaf. Capture
//! fetches each segment through the finding-object service and stores the
//! exchange; one segment-list blob per reproduction names those exchanges in
//! payload order:
//!
//! ```text
//! crucible.failure-triage.reproduction-segments.v1
//! segment_count=2
//! segment.0=<request hash> <response hash>
//! segment.1=<request hash> <response hash>
//! ```
//!
//! The list is strict: it must be exactly the bytes the encoder writes.
//! Authentication replays each exchange against the stored service, checks
//! that the request names this finding, reproduction, and position, and that
//! the served bytes derive the segment the authenticated record names. The
//! Crucible artifact is then decoded from those segments, which authenticates
//! the reassembled schedule against the record's manifest.

use super::record::CampaignFindingEvidenceRecord;
use super::service::{CampaignFindingOccurrenceScope, StoredCampaignFindingService};
use super::store::{CampaignExchangeRef, put_evidence_blob, read_evidence_blob};
use super::*;

/// Schema line of one reproduction's segment list.
const REPRODUCTION_SEGMENTS_SCHEMA: &str = "crucible.failure-triage.reproduction-segments.v1";

/// Segment-list bound: the schema and count lines plus one line of at most
/// 160 bytes for each of the at most
/// [`crucible_campaign::MAX_REPRODUCTION_PAYLOAD_SEGMENTS`] segments.
const MAX_REPRODUCTION_SEGMENTS_BYTES: usize =
    1024 + crucible_campaign::MAX_REPRODUCTION_PAYLOAD_SEGMENTS * 160;

/// Encodes one canonical segment list.
fn encode_segment_list(exchanges: &[CampaignExchangeRef]) -> Vec<u8> {
    let mut text = format!(
        "{REPRODUCTION_SEGMENTS_SCHEMA}\nsegment_count={}\n",
        exchanges.len()
    );
    for (index, exchange) in exchanges.iter().enumerate() {
        text.push_str(&format!("segment.{index}={}\n", exchange.encode()));
    }
    text.into_bytes()
}

/// Stores one reproduction's segment exchanges as a list and returns its key.
fn put_segment_list(
    store: &crucible::LocalDagStore,
    exchanges: &[CampaignExchangeRef],
) -> Result<crucible::ContentHash, CliError> {
    put_evidence_blob(store, &encode_segment_list(exchanges))
}

/// Reads one strict segment list.
fn read_segment_list(
    store: &crucible::LocalDagStore,
    key: crucible::ContentHash,
) -> Result<Vec<CampaignExchangeRef>, CliError> {
    let bytes = read_evidence_blob(
        store,
        key,
        MAX_REPRODUCTION_SEGMENTS_BYTES,
        "reproduction segment list",
    )?;
    let malformed = || artifact_error("campaign reproduction segment list is malformed");

    let text = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
    let mut lines = text.lines();
    if lines.next() != Some(REPRODUCTION_SEGMENTS_SCHEMA) {
        return Err(artifact_error(
            "unsupported campaign reproduction segment list schema",
        ));
    }
    let count = lines
        .next()
        .and_then(|line| line.strip_prefix("segment_count="))
        .and_then(|count| count.parse::<usize>().ok())
        .filter(|count| *count <= crucible_campaign::MAX_REPRODUCTION_PAYLOAD_SEGMENTS)
        .ok_or_else(malformed)?;
    let mut exchanges = Vec::with_capacity(count);
    for index in 0..count {
        let field = format!("segment.{index}");
        let value = lines
            .next()
            .and_then(|line| line.strip_prefix(field.as_str()))
            .and_then(|rest| rest.strip_prefix('='))
            .ok_or_else(malformed)?;
        exchanges.push(CampaignExchangeRef::parse(&field, value)?);
    }

    // Re-encoding rejects every spelling but the canonical one, including
    // trailing lines and non-shortest numbers.
    if encode_segment_list(&exchanges) != bytes {
        return Err(malformed());
    }
    Ok(exchanges)
}

/// Captures every payload segment of a finding-level reproduction and
/// returns the key of its segment list.
///
/// # Errors
///
/// Returns an error when a service read fails or evidence cannot be stored.
pub(super) fn capture_finding_reproduction_segments<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
    store: &crucible::LocalDagStore,
) -> Result<crucible::ContentHash, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut exchanges = Vec::with_capacity(reproduction.payload_segments().len());
    for index in 0..segment_positions(reproduction)? {
        let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
            scope.principal.clone(),
            scope.campaign.clone(),
            scope.snapshot,
            scope.finding,
            crucible_campaign::CampaignFindingObjectKind::ReproductionPayloadSegment {
                minimized,
                index,
            },
        )
        .map_err(|error| artifact_error(format!("build reproduction segment query: {error}")))?;
        let response = client
            .get_campaign_finding_object(&request)
            .map_err(|error| artifact_error(format!("query reproduction segment: {error}")))?;
        exchanges.push(CampaignExchangeRef::put(
            store,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?);
    }
    put_segment_list(store, &exchanges)
}

/// Captures every payload segment of an occurrence's reproduction and
/// returns the key of its segment list.
///
/// With `decode`, the served segments are also authenticated against the
/// record as they arrive and the Crucible artifact is decoded from them.
///
/// # Errors
///
/// Returns an error when a service read fails, evidence cannot be stored, or
/// a requested decode fails.
pub(super) fn capture_occurrence_reproduction_segments<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingOccurrenceScope<'_>,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
    decode: bool,
    store: &crucible::LocalDagStore,
) -> Result<
    (
        crucible::ContentHash,
        Option<crucible::ReproductionArtifact>,
    ),
    CliError,
>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let segments = crucible::SharedSegmentStore::new();
    let mut exchanges = Vec::with_capacity(reproduction.payload_segments().len());
    for index in 0..segment_positions(reproduction)? {
        let request = crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::new(
            scope.finding.principal.clone(),
            scope.finding.campaign.clone(),
            scope.finding.snapshot,
            scope.finding.finding,
            scope.bundle,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::ReproductionPayloadSegment {
                minimized,
                index,
            },
        )
        .map_err(|error| {
            artifact_error(format!(
                "build occurrence reproduction segment query: {error}"
            ))
        })?;
        let response = client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(|error| {
                artifact_error(format!("query occurrence reproduction segment: {error}"))
            })?;
        exchanges.push(CampaignExchangeRef::put(
            store,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?);
        if decode {
            let crucible_campaign::CampaignFindingOccurrenceObject::ReproductionPayloadSegment {
                bytes,
                ..
            } = response.object()
            else {
                return Err(artifact_error(
                    "campaign occurrence reproduction segment response has another object kind",
                ));
            };
            store_authenticated_segment(&segments, reproduction, index, bytes)?;
        }
    }

    let list = put_segment_list(store, &exchanges)?;
    let artifact = decode
        .then(|| decode_campaign_reproduction(reproduction, &segments))
        .transpose()?;
    Ok((list, artifact))
}

/// Fetches a finding-level reproduction's segments from a live service and
/// decodes its Crucible artifact.
///
/// `reproduction` must already be authenticated through the same snapshot.
///
/// # Errors
///
/// Returns an error when a service read fails, a served segment does not
/// derive the segment the record names, or the artifact does not decode.
pub(crate) fn fetch_campaign_reproduction<S>(
    client: &crucible_campaign::CampaignClient<S>,
    scope: &CampaignFindingCaptureScope,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> Result<crucible::ReproductionArtifact, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let segments = crucible::SharedSegmentStore::new();
    for index in 0..segment_positions(reproduction)? {
        let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
            scope.principal.clone(),
            scope.campaign.clone(),
            scope.snapshot,
            scope.finding,
            crucible_campaign::CampaignFindingObjectKind::ReproductionPayloadSegment {
                minimized,
                index,
            },
        )
        .map_err(|error| artifact_error(format!("build reproduction segment query: {error}")))?;
        let response = client
            .get_campaign_finding_object(&request)
            .map_err(|error| artifact_error(format!("query reproduction segment: {error}")))?;
        let crucible_campaign::CampaignFindingObject::ReproductionPayloadSegment { bytes, .. } =
            response.object()
        else {
            return Err(artifact_error(
                "campaign reproduction segment response has another object kind",
            ));
        };
        store_authenticated_segment(&segments, reproduction, index, bytes)?;
    }
    decode_campaign_reproduction(reproduction, &segments)
}

/// Authenticates a finding-level reproduction's captured segments and decodes
/// its Crucible artifact.
///
/// # Errors
///
/// Returns an error when the list does not hold one exchange per segment, a
/// request names another dependency, a response fails its checked binding,
/// a served segment does not derive the record's segment, or the artifact
/// does not decode.
pub(super) fn authenticate_finding_reproduction(
    evidence: &crucible::LocalDagStore,
    record: &CampaignFindingEvidenceRecord,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
    list: crucible::ContentHash,
) -> Result<crucible::ReproductionArtifact, CliError> {
    let exchanges = read_segment_list(evidence, list)?;
    if exchanges.len() != reproduction.payload_segments().len() {
        return Err(artifact_error(
            "campaign reproduction segment list does not cover its payload",
        ));
    }
    let client = crucible_campaign::CampaignClient::new(
        StoredCampaignFindingService::for_finding_objects(evidence, &exchanges),
    );

    let segments = crucible::SharedSegmentStore::new();
    for (index, exchange) in (0_u32..).zip(&exchanges) {
        let request = crucible_campaign::GetCampaignFindingObjectRequest::from_canonical_bytes(
            &exchange.read_request(evidence)?,
        )
        .map_err(|error| {
            artifact_error(format!(
                "campaign reproduction segment request is invalid: {error}"
            ))
        })?;
        let kind = crucible_campaign::CampaignFindingObjectKind::ReproductionPayloadSegment {
            minimized,
            index,
        };
        if request.campaign() != &record.campaign
            || request.snapshot() != record.snapshot
            || request.finding() != record.finding
            || request.kind() != kind
        {
            return Err(artifact_error(
                "campaign reproduction segment request names another dependency",
            ));
        }
        let response = client
            .get_campaign_finding_object(&request)
            .map_err(|error| {
                artifact_error(format!(
                    "campaign reproduction segment proof was rejected: {error}"
                ))
            })?;
        let crucible_campaign::CampaignFindingObject::ReproductionPayloadSegment { bytes, .. } =
            response.object()
        else {
            return Err(artifact_error(
                "campaign reproduction segment proof has another object kind",
            ));
        };
        store_authenticated_segment(&segments, reproduction, index, bytes)?;
    }
    decode_campaign_reproduction(reproduction, &segments)
}

/// Authenticates an occurrence reproduction's captured segments and decodes
/// its Crucible artifact.
///
/// # Errors
///
/// Returns the errors of [`authenticate_finding_reproduction`], with the
/// request additionally bound to `bundle`.
pub(super) fn authenticate_occurrence_reproduction(
    evidence: &crucible::LocalDagStore,
    record: &CampaignFindingEvidenceRecord,
    bundle: crucible_campaign::FindingCandidateBundleId,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
    list: crucible::ContentHash,
) -> Result<crucible::ReproductionArtifact, CliError> {
    let exchanges = read_segment_list(evidence, list)?;
    if exchanges.len() != reproduction.payload_segments().len() {
        return Err(artifact_error(
            "campaign occurrence reproduction segment list does not cover its payload",
        ));
    }
    let client = crucible_campaign::CampaignClient::new(
        StoredCampaignFindingService::for_occurrence_objects(evidence, &exchanges),
    );

    let segments = crucible::SharedSegmentStore::new();
    for (index, exchange) in (0_u32..).zip(&exchanges) {
        let request =
            crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::from_canonical_bytes(
                &exchange.read_request(evidence)?,
            )
            .map_err(|error| {
                artifact_error(format!(
                    "campaign occurrence reproduction segment request is invalid: {error}"
                ))
            })?;
        let kind =
            crucible_campaign::CampaignFindingOccurrenceObjectKind::ReproductionPayloadSegment {
                minimized,
                index,
            };
        if request.campaign() != &record.campaign
            || request.snapshot() != record.snapshot
            || request.finding() != record.finding
            || request.bundle() != bundle
            || request.kind() != kind
        {
            return Err(artifact_error(
                "campaign occurrence reproduction segment request names another dependency",
            ));
        }
        let response = client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(|error| {
                artifact_error(format!(
                    "campaign occurrence reproduction segment proof was rejected: {error}"
                ))
            })?;
        let crucible_campaign::CampaignFindingOccurrenceObject::ReproductionPayloadSegment {
            bytes,
            ..
        } = response.object()
        else {
            return Err(artifact_error(
                "campaign occurrence reproduction segment proof has another object kind",
            ));
        };
        store_authenticated_segment(&segments, reproduction, index, bytes)?;
    }
    decode_campaign_reproduction(reproduction, &segments)
}

/// Decodes a campaign reproduction's Crucible artifact from `segments`.
///
/// # Errors
///
/// Returns an error for an unsupported payload schema, a missing or
/// unauthentic segment, or bytes that do not decode.
pub(super) fn decode_campaign_reproduction(
    reproduction: &crucible_campaign::ReproductionArtifact,
    segments: &dyn crucible::SegmentSource,
) -> Result<crucible::ReproductionArtifact, CliError> {
    crucible_daemon::decode_crucible_reproduction(reproduction, segments, "campaign reproduction")
        .map_err(|error| artifact_error(format!("campaign reproduction is invalid: {error}")))
}

/// Number of payload segments `reproduction` names, as request positions.
fn segment_positions(
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> Result<u32, CliError> {
    u32::try_from(reproduction.payload_segments().len())
        .map_err(|_| artifact_error("campaign reproduction names too many payload segments"))
}

/// Admits served bytes only when they derive the segment at `index`.
fn store_authenticated_segment(
    segments: &crucible::SharedSegmentStore,
    reproduction: &crucible_campaign::ReproductionArtifact,
    index: u32,
    bytes: &[u8],
) -> Result<(), CliError> {
    let segment = usize::try_from(index)
        .ok()
        .and_then(|index| reproduction.payload_segments().get(index))
        .ok_or_else(|| artifact_error("campaign reproduction segment is outside its payload"))?;
    if bytes.len() as u64 != segment.bytes() || !segment.content().authenticates(bytes) {
        return Err(artifact_error(
            "campaign reproduction segment does not derive its record reference",
        ));
    }
    crucible::SegmentSink::put_segment(segments, segment.content(), bytes)
        .map_err(|error| artifact_error(format!("retain campaign reproduction segment: {error}")))
}
