//! Retained proof types, the transcript handle, and its validating reader.
//!
//! Capture writes exchanges straight to the transcript; these types are what
//! a caller reads back. Every response is decoded and validated against its
//! request again on read, so a transcript altered after capture cannot yield
//! an exchange the campaign client would have rejected.

use std::io;
use std::path::Path;

use crucible_campaign::{
    CampaignCodecError, CampaignName, CampaignSnapshotId, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFindingOccurrenceObjectRequest,
    GetCampaignFindingOccurrenceObjectResponse, GetCampaignFindingTriageReplaySegmentRequest,
    GetCampaignFindingTriageReplaySegmentResponse, QueryCampaignFindingOccurrencesRequest,
    QueryCampaignFindingOccurrencesResponse, QueryCampaignFindingsRequest,
    QueryCampaignFindingsResponse,
};
use thiserror::Error;

use super::transcript::{
    FrameKind, RawFrame, SealedTranscript, TranscriptReadError, TranscriptReader,
};

/// One checked request and response for a final-snapshot finding query page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingQueryProof {
    request: QueryCampaignFindingsRequest,
    response: QueryCampaignFindingsResponse,
}

impl GuardedCampaignFindingQueryProof {
    /// Returns the exact snapshot-bound page request.
    #[must_use]
    pub const fn request(&self) -> &QueryCampaignFindingsRequest {
        &self.request
    }

    /// Returns the client-validated page and Merkle proof.
    #[must_use]
    pub const fn response(&self) -> &QueryCampaignFindingsResponse {
        &self.response
    }
}

/// One checked request and response for a representative finding dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingObjectProof {
    request: GetCampaignFindingObjectRequest,
    response: GetCampaignFindingObjectResponse,
}

impl GuardedCampaignFindingObjectProof {
    /// Returns the exact snapshot-bound request.
    #[must_use]
    pub const fn request(&self) -> &GetCampaignFindingObjectRequest {
        &self.request
    }

    /// Returns the client-validated response and Merkle proof.
    #[must_use]
    pub const fn response(&self) -> &GetCampaignFindingObjectResponse {
        &self.response
    }
}

/// One checked limit-one page of a finding's candidate occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOccurrenceQueryProof {
    request: QueryCampaignFindingOccurrencesRequest,
    response: QueryCampaignFindingOccurrencesResponse,
}

impl GuardedCampaignFindingOccurrenceQueryProof {
    /// Returns the exact request for this occurrence page.
    #[must_use]
    pub const fn request(&self) -> &QueryCampaignFindingOccurrencesRequest {
        &self.request
    }

    /// Returns the client-validated occurrence page.
    #[must_use]
    pub const fn response(&self) -> &QueryCampaignFindingOccurrencesResponse {
        &self.response
    }
}

/// One checked request and response for a candidate-bundle dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOccurrenceObjectProof {
    request: GetCampaignFindingOccurrenceObjectRequest,
    response: GetCampaignFindingOccurrenceObjectResponse,
}

impl GuardedCampaignFindingOccurrenceObjectProof {
    /// Returns the exact finding- and bundle-bound request.
    #[must_use]
    pub const fn request(&self) -> &GetCampaignFindingOccurrenceObjectRequest {
        &self.request
    }

    /// Returns the client-validated response and both Merkle proofs.
    #[must_use]
    pub const fn response(&self) -> &GetCampaignFindingOccurrenceObjectResponse {
        &self.response
    }
}

/// One checked request and response for a stored replay-envelope segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingTriageReplaySegmentProof {
    request: GetCampaignFindingTriageReplaySegmentRequest,
    response: GetCampaignFindingTriageReplaySegmentResponse,
}

impl GuardedCampaignFindingTriageReplaySegmentProof {
    pub(super) const fn new(
        request: GetCampaignFindingTriageReplaySegmentRequest,
        response: GetCampaignFindingTriageReplaySegmentResponse,
    ) -> Self {
        Self { request, response }
    }

    /// Returns the exact occurrence-, role-, object-, and segment-bound request.
    #[must_use]
    pub const fn request(&self) -> &GetCampaignFindingTriageReplaySegmentRequest {
        &self.request
    }

    /// Returns the client-validated response and authenticated storage basis.
    #[must_use]
    pub const fn response(&self) -> &GetCampaignFindingTriageReplaySegmentResponse {
        &self.response
    }
}

/// One re-validated exchange read back from a finding-export transcript.
///
/// The module documentation gives the order in which frames nest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardedCampaignFindingExportFrame {
    /// A finding query page; a nonempty page names the finding that follows.
    FindingQuery(Box<GuardedCampaignFindingQueryProof>),
    /// A representative dependency of the preceding finding.
    FindingObject(Box<GuardedCampaignFindingObjectProof>),
    /// An occurrence page of the current finding.
    OccurrenceQuery(Box<GuardedCampaignFindingOccurrenceQueryProof>),
    /// A dependency of the preceding occurrence page's bundle.
    OccurrenceObject(Box<GuardedCampaignFindingOccurrenceObjectProof>),
    /// A stored triage-replay segment of the preceding occurrence page's bundle.
    TriageReplaySegment(Box<GuardedCampaignFindingTriageReplaySegmentProof>),
}

/// Handle to the on-disk proof transcript for every finding at one final snapshot.
///
/// Clones share the transcript file, which is removed when the last handle
/// drops. Two handles are equal when they describe the same campaign,
/// snapshot, and sealed transcript contents, wherever the files live.
#[derive(Clone, Debug)]
pub struct GuardedCampaignFindingExport {
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    findings: u64,
    transcript: SealedTranscript,
}

impl PartialEq for GuardedCampaignFindingExport {
    fn eq(&self, other: &Self) -> bool {
        self.campaign == other.campaign
            && self.snapshot == other.snapshot
            && self.findings == other.findings
            && self.transcript.frames == other.transcript.frames
            && self.transcript.bytes == other.transcript.bytes
            && self.transcript.digest == other.transcript.digest
    }
}

impl Eq for GuardedCampaignFindingExport {}

impl GuardedCampaignFindingExport {
    pub(super) const fn new(
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        findings: u64,
        transcript: SealedTranscript,
    ) -> Self {
        Self {
            campaign,
            snapshot,
            findings,
            transcript,
        }
    }

    /// Returns the campaign named by every retained request.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the immutable final snapshot authenticated by every response.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the number of incorporated final findings in the transcript.
    #[must_use]
    pub const fn findings(&self) -> u64 {
        self.findings
    }

    /// Returns the number of exchange frames in the transcript.
    #[must_use]
    pub const fn frame_count(&self) -> u64 {
        self.transcript.frames
    }

    /// Returns the complete transcript length in bytes.
    #[must_use]
    pub const fn transcript_bytes(&self) -> u64 {
        self.transcript.bytes
    }

    /// Returns the BLAKE3 digest recorded in the transcript trailer.
    #[must_use]
    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript.digest
    }

    /// Returns the path of the private transcript file.
    #[must_use]
    pub fn transcript_path(&self) -> &Path {
        self.transcript.file.path()
    }

    /// Streams every exchange back in capture order.
    ///
    /// Each frame's response is validated against its request, and both must
    /// name this export's campaign and snapshot. The iterator yields an error
    /// and then stops if the file is truncated, altered, or carries a trailer
    /// that differs from the one recorded when it was sealed. The transcript
    /// has been read completely only once the iterator returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingExportReadError`] when the transcript
    /// cannot be opened or its header names another campaign or snapshot.
    pub fn frames(
        &self,
    ) -> Result<GuardedCampaignFindingExportFrames, GuardedCampaignFindingExportReadError> {
        let reader = TranscriptReader::open(&self.transcript, &self.campaign, self.snapshot)?;
        Ok(GuardedCampaignFindingExportFrames {
            reader,
            campaign: self.campaign.clone(),
            snapshot: self.snapshot,
            failed: false,
        })
    }
}

/// Streaming, validating reader over one finding-export transcript.
///
/// The reader keeps the transcript file alive while it is open.
pub struct GuardedCampaignFindingExportFrames {
    reader: TranscriptReader,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    failed: bool,
}

impl std::fmt::Debug for GuardedCampaignFindingExportFrames {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardedCampaignFindingExportFrames")
            .field("transcript", &self.reader.file().path())
            .field("campaign", &self.campaign)
            .field("snapshot", &self.snapshot)
            .field("failed", &self.failed)
            .finish()
    }
}

impl Iterator for GuardedCampaignFindingExportFrames {
    type Item = Result<GuardedCampaignFindingExportFrame, GuardedCampaignFindingExportReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let frame = match self.reader.next_frame() {
            Ok(Some(frame)) => decode_frame(frame, &self.campaign, self.snapshot),
            Ok(None) => return None,
            Err(error) => Err(error.into()),
        };
        self.failed = frame.is_err();
        Some(frame)
    }
}

/// Failure to read a finding-export transcript back.
#[derive(Debug, Error)]
pub enum GuardedCampaignFindingExportReadError {
    /// The transcript file could not be opened or read.
    #[error("finding export transcript could not be read: {0}")]
    Io(#[source] io::Error),
    /// A retained exchange failed to decode or to validate against its request.
    #[error("finding export transcript exchange is invalid: {0}")]
    Exchange(#[source] CampaignCodecError),
    /// The transcript structure differs from the sealed export.
    #[error("finding export transcript is malformed: {reason}")]
    Malformed {
        /// Stable description of the structural violation.
        reason: &'static str,
    },
}

impl From<TranscriptReadError> for GuardedCampaignFindingExportReadError {
    fn from(error: TranscriptReadError) -> Self {
        match error {
            TranscriptReadError::Io(source) => Self::Io(source),
            TranscriptReadError::Malformed(reason) => Self::Malformed { reason },
        }
    }
}

/// Request and response decoding shared by every retained exchange kind.
trait RetainedExchange: Sized {
    type Response;

    fn decode_request(bytes: &[u8]) -> Result<Self, CampaignCodecError>;

    fn decode_response(bytes: &[u8]) -> Result<Self::Response, CampaignCodecError>;

    fn validate(response: &Self::Response, request: &Self) -> Result<(), CampaignCodecError>;

    fn campaign(&self) -> &CampaignName;

    fn snapshot(&self) -> CampaignSnapshotId;
}

macro_rules! retained_exchange {
    ($request:ty => $response:ty) => {
        impl RetainedExchange for $request {
            type Response = $response;

            fn decode_request(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
                <$request>::from_canonical_bytes(bytes)
            }

            fn decode_response(bytes: &[u8]) -> Result<Self::Response, CampaignCodecError> {
                <$response>::from_canonical_bytes(bytes)
            }

            fn validate(
                response: &Self::Response,
                request: &Self,
            ) -> Result<(), CampaignCodecError> {
                response.validate_for(request)
            }

            fn campaign(&self) -> &CampaignName {
                <$request>::campaign(self)
            }

            fn snapshot(&self) -> CampaignSnapshotId {
                <$request>::snapshot(self)
            }
        }
    };
}

retained_exchange!(QueryCampaignFindingsRequest => QueryCampaignFindingsResponse);
retained_exchange!(GetCampaignFindingObjectRequest => GetCampaignFindingObjectResponse);
retained_exchange!(
    QueryCampaignFindingOccurrencesRequest => QueryCampaignFindingOccurrencesResponse
);
retained_exchange!(
    GetCampaignFindingOccurrenceObjectRequest => GetCampaignFindingOccurrenceObjectResponse
);
retained_exchange!(
    GetCampaignFindingTriageReplaySegmentRequest => GetCampaignFindingTriageReplaySegmentResponse
);

fn decode_exchange<R>(
    frame: &RawFrame,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
) -> Result<(R, R::Response), GuardedCampaignFindingExportReadError>
where
    R: RetainedExchange,
{
    let request = R::decode_request(&frame.request)
        .map_err(GuardedCampaignFindingExportReadError::Exchange)?;
    if request.campaign() != campaign || request.snapshot() != snapshot {
        return Err(GuardedCampaignFindingExportReadError::Malformed {
            reason: "finding export exchange names another campaign or snapshot",
        });
    }
    let response = R::decode_response(&frame.response)
        .map_err(GuardedCampaignFindingExportReadError::Exchange)?;
    R::validate(&response, &request).map_err(GuardedCampaignFindingExportReadError::Exchange)?;
    Ok((request, response))
}

fn decode_frame(
    frame: RawFrame,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
) -> Result<GuardedCampaignFindingExportFrame, GuardedCampaignFindingExportReadError> {
    Ok(match frame.kind {
        FrameKind::FindingQuery => {
            let (request, response) = decode_exchange(&frame, campaign, snapshot)?;
            GuardedCampaignFindingExportFrame::FindingQuery(Box::new(
                GuardedCampaignFindingQueryProof { request, response },
            ))
        }
        FrameKind::FindingObject => {
            let (request, response) = decode_exchange(&frame, campaign, snapshot)?;
            GuardedCampaignFindingExportFrame::FindingObject(Box::new(
                GuardedCampaignFindingObjectProof { request, response },
            ))
        }
        FrameKind::OccurrenceQuery => {
            let (request, response) = decode_exchange(&frame, campaign, snapshot)?;
            GuardedCampaignFindingExportFrame::OccurrenceQuery(Box::new(
                GuardedCampaignFindingOccurrenceQueryProof { request, response },
            ))
        }
        FrameKind::OccurrenceObject => {
            let (request, response) = decode_exchange(&frame, campaign, snapshot)?;
            GuardedCampaignFindingExportFrame::OccurrenceObject(Box::new(
                GuardedCampaignFindingOccurrenceObjectProof { request, response },
            ))
        }
        FrameKind::TriageReplaySegment => {
            let (request, response) = decode_exchange(&frame, campaign, snapshot)?;
            GuardedCampaignFindingExportFrame::TriageReplaySegment(Box::new(
                GuardedCampaignFindingTriageReplaySegmentProof { request, response },
            ))
        }
    })
}
