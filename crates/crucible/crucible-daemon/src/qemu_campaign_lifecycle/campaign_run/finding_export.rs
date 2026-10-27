//! Immutable final-snapshot finding proofs retained by a guarded campaign run.
//!
//! The guarded owner uses its checked [`CampaignClient`] while the ephemeral
//! repository is still live. Every request-bound Merkle response is appended
//! to a private on-disk transcript as it arrives, so the export outlives
//! repository teardown without holding a campaign-length transcript in
//! memory. The run's admitted disk limit is the transcript's quota and a
//! fixed deadline bounds its wall time.
//!
//! Frames appear in capture order. Each finding query page is followed, when
//! it names a finding, by that finding's object frames and then by its
//! occurrence pages; each occurrence page is followed by its bundle's object
//! frames and, for a rich bundle, by the segments of its four triage replays
//! in minimization-original, minimization-selected, verification-original,
//! verification-selected order:
//!
//! ```text
//! FindingQuery
//!   FindingObject (observation, reproduction[, minimized reproduction])
//!   OccurrenceQuery
//!     OccurrenceObject (observation, reproduction, minimized reproduction)
//!     TriageReplaySegment ... (four replays, root-first storage order)
//!   OccurrenceQuery ...
//! FindingQuery ...
//! ```
//!
//! [`GuardedCampaignFindingExport::frames`] re-validates every response
//! against its request while streaming the transcript back.

mod proofs;
#[cfg(test)]
mod tests;
mod transcript;

use std::path::PathBuf;
use std::time::Duration;

use crucible_campaign::{
    CampaignClient, CampaignClientError, CampaignCodecError, CampaignFindingObjectKind,
    CampaignFindingOccurrenceObjectKind, CampaignFindingOccurrenceService,
    CampaignFindingTriageReplayRole, CampaignName, CampaignPrincipal, CampaignService,
    CampaignServiceFailureSource, CampaignSnapshotId, FindingId, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFindingOccurrenceObjectRequest,
    GetCampaignFindingOccurrenceObjectResponse, GetCampaignFindingTriageReplaySegmentRequest,
    GetCampaignFindingTriageReplaySegmentResponse, MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
    QueryCampaignFindingOccurrencesRequest, QueryCampaignFindingOccurrencesResponse,
    QueryCampaignFindingsRequest, QueryCampaignFindingsResponse,
};

use crate::{ExecutionCancellation, supervision::ProcessDeadline};

use super::GuardedDefaultCampaignRunError;
pub use proofs::{
    GuardedCampaignFindingExport, GuardedCampaignFindingExportFrame,
    GuardedCampaignFindingExportFrames, GuardedCampaignFindingExportReadError,
    GuardedCampaignFindingObjectProof, GuardedCampaignFindingOccurrenceObjectProof,
    GuardedCampaignFindingOccurrenceQueryProof, GuardedCampaignFindingQueryProof,
    GuardedCampaignFindingTriageReplaySegmentProof,
};
use transcript::{FrameKind, TranscriptWriteError, TranscriptWriter};

const FINDING_EXPORT_DEADLINE: Duration = Duration::from_secs(300);

/// Directory, below the run-state root, that holds finding-export transcripts.
pub(super) const FINDING_EXPORT_DIRECTORY: &str = "campaign-finding-exports";

/// Owner-supplied storage for one finding-export transcript.
pub(super) struct FindingExportStorage {
    /// Directory created on demand to hold the transcript file.
    pub(super) directory: PathBuf,
    /// Disk quota for the complete transcript, in bytes.
    pub(super) maximum_bytes: u64,
}

/// Deadline and transcript writer shared by every capture step.
struct FindingExportRecorder {
    deadline: ProcessDeadline,
    transcript: TranscriptWriter,
}

struct FindingExportContext<'a, C> {
    client: &'a C,
    principal: &'a CampaignPrincipal,
    campaign: &'a CampaignName,
    snapshot: CampaignSnapshotId,
    cancellation: &'a ExecutionCancellation,
}

pub(super) trait FindingExportClient {
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError>;

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError>;

    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, CampaignClientError>;

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, CampaignClientError>;

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, CampaignClientError>;
}

impl<S> FindingExportClient for CampaignClient<S>
where
    S: CampaignService + CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, CampaignClientError> {
        CampaignClient::query_campaign_findings(self, request)
    }

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, CampaignClientError> {
        CampaignClient::get_campaign_finding_object(self, request)
    }

    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, CampaignClientError> {
        CampaignClient::query_campaign_finding_occurrences(self, request)
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, CampaignClientError> {
        CampaignClient::get_campaign_finding_occurrence_object(self, request)
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, CampaignClientError> {
        CampaignClient::get_campaign_finding_triage_replay_segment(self, request)
    }
}

impl FindingExportRecorder {
    fn create<E>(
        storage: &FindingExportStorage,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> Result<Self, GuardedDefaultCampaignRunError<E>>
    where
        E: std::error::Error + 'static,
    {
        let deadline = ProcessDeadline::after(FINDING_EXPORT_DEADLINE)
            .ok_or(super::GuardedDefaultCampaignInvariantError::FindingExportDeadline)?;
        let transcript = TranscriptWriter::create(
            &storage.directory,
            campaign,
            snapshot,
            storage.maximum_bytes,
        )
        .map_err(map_transcript_write_error)?;
        Ok(Self {
            deadline,
            transcript,
        })
    }

    fn check(&self) -> Result<(), super::GuardedDefaultCampaignInvariantError> {
        if self.deadline.expired() {
            return Err(super::GuardedDefaultCampaignInvariantError::FindingExportDeadline);
        }
        Ok(())
    }

    /// Appends one checked exchange to the transcript under the deadline.
    fn record<E>(
        &mut self,
        kind: FrameKind,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), GuardedDefaultCampaignRunError<E>>
    where
        E: std::error::Error + 'static,
    {
        self.check()?;
        self.transcript
            .append(kind, request, response)
            .map_err(map_transcript_write_error)
    }
}

fn map_transcript_write_error<E>(error: TranscriptWriteError) -> GuardedDefaultCampaignRunError<E>
where
    E: std::error::Error + 'static,
{
    match error {
        TranscriptWriteError::Quota => {
            super::GuardedDefaultCampaignInvariantError::FindingExportLimit.into()
        }
        TranscriptWriteError::Io(source) => GuardedDefaultCampaignRunError::FindingExport(source),
    }
}

pub(super) fn capture_final_finding_export<C, E>(
    client: &C,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    cancellation: &ExecutionCancellation,
    storage: &FindingExportStorage,
) -> Result<GuardedCampaignFindingExport, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    // A canceled run must not create even an empty transcript.
    check_cancellation(cancellation)?;
    let mut recorder = FindingExportRecorder::create(storage, campaign, snapshot)?;
    let context = FindingExportContext {
        client,
        principal,
        campaign,
        snapshot,
        cancellation,
    };

    let mut findings = 0_u64;
    let mut after = None;
    loop {
        recorder.check()?;
        let request = QueryCampaignFindingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            1,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(cancellation)?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        recorder.record(
            FrameKind::FindingQuery,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?;

        if let Some(finding) = response.entries().first() {
            let finding_id = finding
                .id()
                .map_err(GuardedDefaultCampaignRunError::Codec)?;
            capture_finding_objects(
                &context,
                finding_id,
                finding.minimized().is_some(),
                &mut recorder,
            )?;
            capture_finding_occurrences(&context, finding_id, &mut recorder)?;
            findings = findings
                .checked_add(1)
                .ok_or(super::GuardedDefaultCampaignInvariantError::FindingExportLimit)?;
        }

        let Some(cursor) = response.next_after() else {
            break;
        };
        after = Some(cursor);
    }

    check_cancellation(cancellation)?;
    let transcript = recorder
        .transcript
        .seal()
        .map_err(map_transcript_write_error)?;
    Ok(GuardedCampaignFindingExport::new(
        campaign.clone(),
        snapshot,
        findings,
        transcript,
    ))
}

fn capture_finding_objects<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    has_minimized: bool,
    recorder: &mut FindingExportRecorder,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut kinds = vec![
        CampaignFindingObjectKind::Observation,
        CampaignFindingObjectKind::Reproduction,
    ];
    if has_minimized {
        kinds.push(CampaignFindingObjectKind::MinimizedReproduction);
    }

    for kind in kinds {
        recorder.check()?;
        let request = GetCampaignFindingObjectRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            kind,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .get_campaign_finding_object(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        recorder.record(
            FrameKind::FindingObject,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?;
    }
    Ok(())
}

fn capture_finding_occurrences<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    recorder: &mut FindingExportRecorder,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let mut after = None;
    loop {
        recorder.check()?;
        let request = QueryCampaignFindingOccurrencesRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            after,
            1,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .query_campaign_finding_occurrences(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        recorder.record(
            FrameKind::OccurrenceQuery,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?;

        if let Some(occurrence) = response.entries().first() {
            capture_occurrence_objects(context, finding, occurrence.bundle(), recorder)?;
            capture_occurrence_triage_replays(context, finding, occurrence.bundle(), recorder)?;
        }

        let Some(cursor) = response.next_after() else {
            break;
        };
        after = Some(cursor);
    }
    Ok(())
}

fn capture_occurrence_objects<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    bundle: &crucible_campaign::FindingCandidateBundle,
    recorder: &mut FindingExportRecorder,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let kinds = [
        CampaignFindingOccurrenceObjectKind::Observation,
        CampaignFindingOccurrenceObjectKind::Reproduction,
        CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
    ];
    let bundle = bundle.id().map_err(GuardedDefaultCampaignRunError::Codec)?;

    for kind in kinds {
        recorder.check()?;
        let request = GetCampaignFindingOccurrenceObjectRequest::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            finding,
            bundle,
            kind,
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        check_cancellation(context.cancellation)?;
        let response = context
            .client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(GuardedDefaultCampaignRunError::Service)?;
        recorder.record(
            FrameKind::OccurrenceObject,
            &request.canonical_bytes(),
            &response.canonical_bytes(),
        )?;
    }
    Ok(())
}

fn capture_occurrence_triage_replays<C, E>(
    context: &FindingExportContext<'_, C>,
    finding: FindingId,
    bundle: &crucible_campaign::FindingCandidateBundle,
    recorder: &mut FindingExportRecorder,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let Some(evidence) = bundle.triage_evidence() else {
        return Ok(());
    };
    let bundle = bundle.id().map_err(GuardedDefaultCampaignRunError::Codec)?;

    for (role, replay) in [
        (
            CampaignFindingTriageReplayRole::MinimizationOriginal,
            evidence.minimization_original(),
        ),
        (
            CampaignFindingTriageReplayRole::MinimizationSelected,
            evidence.minimization_selected(),
        ),
        (
            CampaignFindingTriageReplayRole::VerificationOriginal,
            evidence.verification_original(),
        ),
        (
            CampaignFindingTriageReplayRole::VerificationSelected,
            evidence.verification_selected(),
        ),
    ] {
        let identity = TriageReplayIdentity {
            finding,
            bundle,
            role,
            evidence: replay,
        };
        capture_triage_replay_segments(context, &identity, recorder)?;
    }
    Ok(())
}

/// Captures and authenticates every stored segment of one triage replay.
///
/// One replay's segments stay in memory until the replay authenticates,
/// because the evidence decoder needs every envelope at once. That buffer is
/// bounded by the triage-replay evidence format, not by campaign length; the
/// segments are already in the transcript as they arrive.
fn capture_triage_replay_segments<C, E>(
    context: &FindingExportContext<'_, C>,
    identity: &TriageReplayIdentity,
    recorder: &mut FindingExportRecorder,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let first_request = GetCampaignFindingTriageReplaySegmentRequest::new(
        identity.selection(context),
        crucible_campaign::CampaignFindingTriageReplaySegment::new(
            0,
            identity.evidence.content_id(),
            0,
        ),
    )
    .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let first = capture_triage_replay_segment(context, first_request, recorder)?;
    let description = first.response().description().clone();
    let mut segments = vec![first];

    let root = description
        .objects()
        .first()
        .ok_or(GuardedDefaultCampaignRunError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage description has no root",
            },
        ))?;
    capture_remaining_triage_object_segments(context, identity, root, 1, recorder, &mut segments)?;
    let root_bytes = captured_object_bytes(&description, root, &segments)
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    description
        .authenticate_root_envelope(&root_bytes)
        .map_err(GuardedDefaultCampaignRunError::Codec)?;

    // Child identities become trustworthy only after the complete root
    // envelope authenticates the returned storage description.
    for object in &description.objects()[1..] {
        capture_remaining_triage_object_segments(
            context,
            identity,
            object,
            0,
            recorder,
            &mut segments,
        )?;
    }

    authenticate_captured_triage_replay(identity.evidence, &description, &segments)
        .map_err(GuardedDefaultCampaignRunError::Codec)
}

#[derive(Clone, Copy)]
struct TriageReplayIdentity {
    finding: FindingId,
    bundle: crucible_campaign::FindingCandidateBundleId,
    role: CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
}

impl TriageReplayIdentity {
    fn selection<C>(
        &self,
        context: &FindingExportContext<'_, C>,
    ) -> crucible_campaign::CampaignFindingTriageReplaySelection {
        crucible_campaign::CampaignFindingTriageReplaySelection::new(
            context.principal.clone(),
            context.campaign.clone(),
            context.snapshot,
            self.finding,
            self.bundle,
            self.role,
            self.evidence,
        )
    }
}

fn capture_remaining_triage_object_segments<C, E>(
    context: &FindingExportContext<'_, C>,
    identity: &TriageReplayIdentity,
    object: &crucible_campaign::FindingTriageReplayStorageObject,
    first_segment_index: u32,
    recorder: &mut FindingExportRecorder,
    segments: &mut Vec<GuardedCampaignFindingTriageReplaySegmentProof>,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    let segment_count = object
        .stored_envelope_bytes()
        .checked_add(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
        .ok_or(GuardedDefaultCampaignRunError::Codec(
            CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-storage-segment-count",
            },
        ))?
        / MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES;
    let segment_count = u32::try_from(segment_count).map_err(|_| {
        GuardedDefaultCampaignRunError::Codec(CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-segment-count",
        })
    })?;
    for segment_index in first_segment_index..segment_count {
        let request = GetCampaignFindingTriageReplaySegmentRequest::new(
            identity.selection(context),
            crucible_campaign::CampaignFindingTriageReplaySegment::new(
                object.ordinal(),
                object.content(),
                segment_index,
            ),
        )
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
        segments.push(capture_triage_replay_segment(context, request, recorder)?);
    }
    Ok(())
}

fn captured_object_bytes(
    description: &crucible_campaign::FindingTriageReplayStorageDescription,
    object: &crucible_campaign::FindingTriageReplayStorageObject,
    segments: &[GuardedCampaignFindingTriageReplaySegmentProof],
) -> Result<Vec<u8>, CampaignCodecError> {
    let object_bytes = usize::try_from(object.stored_envelope_bytes()).map_err(|_| {
        CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-envelope-bytes",
        }
    })?;
    let mut envelope = Vec::with_capacity(object_bytes);
    for segment in segments
        .iter()
        .filter(|segment| segment.request().object_ordinal() == object.ordinal())
    {
        let expected_index = u32::try_from(
            u64::try_from(envelope.len()).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-storage-envelope-bytes",
            })? / MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
        )
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "finding-triage-replay-storage-segment-count",
        })?;
        if segment.request().segment_index() != expected_index
            || segment.request().object() != object.content()
            || segment.response().description() != description
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay storage segments are reordered or substituted",
            });
        }
        segment.response().validate_for(segment.request())?;
        envelope.extend_from_slice(segment.response().range_bytes());
    }
    if envelope.len() != object_bytes {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay storage envelope transfer is incomplete",
        });
    }
    Ok(envelope)
}

fn capture_triage_replay_segment<C, E>(
    context: &FindingExportContext<'_, C>,
    request: GetCampaignFindingTriageReplaySegmentRequest,
    recorder: &mut FindingExportRecorder,
) -> Result<GuardedCampaignFindingTriageReplaySegmentProof, GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    recorder.check()?;
    check_cancellation(context.cancellation)?;
    let response = context
        .client
        .get_campaign_finding_triage_replay_segment(&request)
        .map_err(GuardedDefaultCampaignRunError::Service)?;
    recorder.record(
        FrameKind::TriageReplaySegment,
        &request.canonical_bytes(),
        &response.canonical_bytes(),
    )?;
    Ok(GuardedCampaignFindingTriageReplaySegmentProof::new(
        request, response,
    ))
}

fn authenticate_captured_triage_replay(
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
    description: &crucible_campaign::FindingTriageReplayStorageDescription,
    segments: &[GuardedCampaignFindingTriageReplaySegmentProof],
) -> Result<(), CampaignCodecError> {
    let mut envelopes = Vec::with_capacity(description.objects().len());
    let mut expected_segment_count = 0_usize;
    for object in description.objects() {
        expected_segment_count = expected_segment_count
            .checked_add(
                usize::try_from(
                    object
                        .stored_envelope_bytes()
                        .checked_add(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
                        .ok_or(CampaignCodecError::LimitExceeded {
                            limit: "finding-triage-replay-storage-segment-count",
                        })?
                        / MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
                )
                .map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "finding-triage-replay-storage-segment-count",
                })?,
            )
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-storage-segment-count",
            })?;
        envelopes.push(captured_object_bytes(description, object, segments)?);
    }
    if segments.len() != expected_segment_count {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay storage transfer has unexpected segments",
        });
    }
    let replay = crucible_campaign::FindingTriageReplayEvidence::from_storage_envelopes(
        description,
        &envelopes,
    )?;
    if replay.id()? != evidence {
        return Err(CampaignCodecError::InvalidValue {
            reason: "finding triage replay storage transfer has another evidence identity",
        });
    }
    Ok(())
}

fn check_cancellation<E>(
    cancellation: &ExecutionCancellation,
) -> Result<(), GuardedDefaultCampaignRunError<E>>
where
    E: std::error::Error + 'static,
{
    if cancellation.is_canceled() {
        return Err(super::GuardedDefaultCampaignInvariantError::FindingExportCanceled.into());
    }
    Ok(())
}
