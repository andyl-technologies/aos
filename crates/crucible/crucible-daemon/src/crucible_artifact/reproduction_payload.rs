//! Crucible reproduction payloads with segment-referenced schedules.
//!
//! A campaign reproduction record keeps the Crucible stored form inline: the
//! scenario form and the schedule manifest. Every schedule segment is a trace
//! leaf the record names in manifest order, so the record's size is fixed by
//! the scenario and the manifest bound rather than by the reproduced run.
//!
//! ```text
//! CrucibleReproductionPayloadV5:
//!   inline    "crucible.reproduction-artifact-manifest.v1\0"
//!               blob scenario-def-form v9, blob schedule-manifest
//!   segments  (ContentId(trace, 1) schedule segment, u64 bytes)*
//!                                         // exactly the manifest's segments
//! ```
//!
//! Writers visit the segments one at a time from the in-memory schedule and
//! publish each before the record that names it. Readers decode through a
//! [`crucible_engine::SegmentSource`] that authenticates each segment as it is read.

use std::io;

use crucible_engine::{Schedule, ScheduleManifest};
use crucible_campaign::{
    CampaignExecutorStore, CampaignRepository, CampaignRepositoryError, ReproductionArtifact,
    ReproductionArtifactId, ReproductionPayload, ReproductionPayloadSegment,
};
use crucible_store::content_store::ContentId;

use super::{
    CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5, CrucibleArtifactError, CrucibleCampaignArtifactStore,
    PreparedCrucibleFindingCandidate,
};

/// Builds the campaign payload for a verified Crucible reproduction.
///
/// No segment is written; the schedule's
/// [`crucible_engine::Schedule::try_for_each_segment`] visits the same segments for
/// publication.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when the schedule cannot be segmented
/// within one manifest's bounds or the payload exceeds its campaign bound.
pub fn crucible_reproduction_payload(
    artifact: &crucible_engine::ReproductionArtifact,
) -> Result<ReproductionPayload, CrucibleArtifactError> {
    let (stored, manifest) =
        artifact
            .to_stored_form()
            .map_err(|source| CrucibleArtifactError::InvalidPayload {
                artifact: "finding reproduction",
                source: Box::new(source),
            })?;

    ReproductionPayload::new(
        CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5,
        stored,
        payload_segments(&manifest)?,
    )
    .map_err(Into::into)
}

/// Visits each schedule segment of `schedule` as a payload segment, in order.
///
/// # Errors
///
/// Returns the first error `visit` returns, or an invalid-payload error when
/// the schedule cannot be segmented.
pub(crate) fn try_for_each_payload_segment<E>(
    schedule: &crucible_engine::Schedule,
    mut visit: impl FnMut(ReproductionPayloadSegment, &[u8]) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<CrucibleArtifactError>,
{
    // The schedule visitor speaks EngineError; the caller's error is kept
    // aside and the walk is stopped with a placeholder that is never shown.
    let mut visit_error = None;
    let walked = schedule.try_for_each_segment(|segment, bytes| {
        let result = ReproductionPayloadSegment::new(segment.id, segment.encoded_bytes)
            .map_err(|error| E::from(CrucibleArtifactError::Campaign(error)))
            .and_then(|segment| visit(segment, bytes));
        result.map_err(|error| {
            visit_error = Some(error);
            crucible_engine::EngineError::ScenarioSerialization {
                reason: String::from("reproduction payload segment visit stopped"),
            }
        })
    });

    if let Some(error) = visit_error {
        return Err(error);
    }
    walked.map(drop).map_err(|source| {
        E::from(CrucibleArtifactError::InvalidPayload {
            artifact: "finding reproduction",
            source: Box::new(source),
        })
    })
}

/// Decodes a campaign reproduction's Crucible artifact, reading its schedule
/// segments from `source`.
///
/// The record must name exactly the segments its inline manifest names, so a
/// record cannot retain leaves its payload does not use. Each segment is
/// authenticated as it is read, and the reassembled schedule must derive the
/// manifest's schedule identity.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError::UnsupportedPayloadSchema`] for another
/// payload schema, [`CrucibleArtifactError::SemanticIdentityMismatch`] when
/// the record's segments differ from its manifest's, and
/// [`CrucibleArtifactError::InvalidPayload`] for malformed bytes or a missing
/// or unauthentic segment.
pub fn decode_crucible_reproduction(
    record: &ReproductionArtifact,
    source: &dyn crucible_engine::SegmentSource,
    artifact_name: &'static str,
) -> Result<crucible_engine::ReproductionArtifact, CrucibleArtifactError> {
    if record.payload_schema() != CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5 {
        return Err(CrucibleArtifactError::UnsupportedPayloadSchema {
            artifact: artifact_name,
            actual: record.payload_schema(),
            expected: CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5,
        });
    }
    let invalid = |source| CrucibleArtifactError::InvalidPayload {
        artifact: artifact_name,
        source: Box::new(source),
    };

    let manifest = crucible_engine::ReproductionArtifact::stored_form_schedule_manifest(record.payload())
        .map_err(invalid)?;
    if payload_segments(&manifest)? != record.payload_segments() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: artifact_name,
        });
    }
    crucible_engine::ReproductionArtifact::from_stored_form(record.payload(), source).map_err(invalid)
}

impl CrucibleCampaignArtifactStore {
    /// Publishes `schedule`'s payload segments, then the record naming them.
    pub(super) fn publish_reproduction_record(
        &self,
        artifact: &ReproductionArtifact,
        schedule: &Schedule,
    ) -> Result<ReproductionArtifactId, CrucibleArtifactError> {
        let expected = artifact.id()?;
        try_for_each_payload_segment(schedule, |segment, bytes| {
            self.repository
                .publish_reproduction_payload_segment(segment, bytes)
                .map(drop)
                .map_err(CrucibleArtifactError::RepositoryPublication)
        })?;
        let stored = match artifact.minimization() {
            Some(minimization) => self.repository.publish_minimized_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.reproduction_payload().clone(),
                minimization.clone(),
            ),
            None => self.repository.publish_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.reproduction_payload().clone(),
            ),
        }
        .map_err(CrucibleArtifactError::RepositoryPublication)?;
        if stored != expected {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "stored finding reproduction",
            });
        }
        Ok(stored)
    }
}

/// Publishes a reproduction schedule's payload segments through the executor.
pub(super) fn publish_executor_payload_segments(
    store: &CampaignExecutorStore,
    schedule: &Schedule,
) -> Result<(), CampaignRepositoryError> {
    try_for_each_payload_segment(schedule, |segment, bytes| {
        store
            .publish_executor_reproduction_payload_segment(segment, bytes)
            .map(drop)
            .map_err(PayloadSegmentPublicationError::Repository)
    })
    .map_err(|error| match error {
        PayloadSegmentPublicationError::Repository(error) => error,
        PayloadSegmentPublicationError::Unsegmentable => CampaignRepositoryError::Integrity {
            reason: "prepared-finding-reproduction-segments",
        },
    })
}

/// Failure while publishing payload segments through a repository capability
/// whose error type has no Crucible payload variant.
enum PayloadSegmentPublicationError {
    Repository(CampaignRepositoryError),
    /// The prepared schedule could not be segmented. Preparation already
    /// segmented the same schedule, so this reports an integrity failure.
    Unsegmentable,
}

impl From<CrucibleArtifactError> for PayloadSegmentPublicationError {
    fn from(_: CrucibleArtifactError) -> Self {
        Self::Unsegmentable
    }
}

impl PreparedCrucibleFindingCandidate {
    /// Returns a segment source over both reproductions' schedule segments.
    ///
    /// Until a journal stages them, the segments exist only as the resident
    /// schedules, so a prepared result decodes its finding through this
    /// source.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleArtifactError::InvalidPayload`] when a schedule
    /// cannot be segmented within one manifest's bounds.
    pub(crate) fn resident_reproduction_segments(
        &self,
    ) -> Result<crucible_engine::ResidentScheduleSegments, CrucibleArtifactError> {
        crucible_engine::ResidentScheduleSegments::new([
            self.original_artifact.schedule(),
            self.minimized_artifact.schedule(),
        ])
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: "finding reproduction",
            source: Box::new(source),
        })
    }
}

/// Payload segments of a schedule manifest, in manifest order.
fn payload_segments(
    manifest: &ScheduleManifest,
) -> Result<Vec<ReproductionPayloadSegment>, CrucibleArtifactError> {
    manifest
        .segments()
        .iter()
        .map(|segment| ReproductionPayloadSegment::new(segment.id, segment.encoded_bytes))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

/// Segment source over the payload segments one stored reproduction names.
///
/// Every read is scoped to the reproduction and authenticated by the
/// repository against the segment identity and declared length.
#[derive(Clone, Copy)]
pub struct RepositoryReproductionSegments<'a> {
    pub(crate) repository: &'a CampaignRepository,
    pub(crate) reproduction: ReproductionArtifactId,
}

impl<'a> RepositoryReproductionSegments<'a> {
    /// Reads the payload segments `reproduction` names from `repository`.
    #[must_use]
    pub const fn new(
        repository: &'a CampaignRepository,
        reproduction: ReproductionArtifactId,
    ) -> Self {
        Self {
            repository,
            reproduction,
        }
    }
}

impl crucible_engine::SegmentSource for RepositoryReproductionSegments<'_> {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.repository
            .read_reproduction_payload_segment(self.reproduction, id)
            .map_err(|error: CampaignRepositoryError| io::Error::other(error.to_string()))
    }
}
