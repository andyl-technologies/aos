//! Segment sources over published campaign evidence.
//!
//! A published replay leaf's segments are trace leaves owned by the same
//! measurement set. These adapters read them back through the repository's
//! ownership-checked accessors, so a reader can only fetch segments the
//! measurement set it is verifying actually owns.

use std::io;

use crucible_campaign::{
    CampaignExecutorStore, CampaignRepository, MeasurementSetId, ObjectiveEvaluationInput,
};
use crucible_store::content_store::ContentId;

use crate::attempt_event_log::{AttemptLogSegmentSource, MAX_ATTEMPT_LOG_SEGMENT_BYTES};

/// Reads segments owned by one published measurement set.
pub struct MeasurementSetSegmentSource<'store> {
    store: &'store CampaignExecutorStore,
    measurements: MeasurementSetId,
}

impl<'store> MeasurementSetSegmentSource<'store> {
    /// Reads through `store`, limited to the evidence `measurements` owns.
    #[must_use]
    pub const fn new(store: &'store CampaignExecutorStore, measurements: MeasurementSetId) -> Self {
        Self {
            store,
            measurements,
        }
    }
}

impl AttemptLogSegmentSource for MeasurementSetSegmentSource<'_> {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.store
            .read_measurement_evidence_leaf(
                self.measurements,
                id,
                MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64,
            )
            .map_err(io::Error::other)
    }
}

/// Reads segments owned by one objective-evaluation input.
pub struct ObjectiveInputSegmentSource<'input> {
    repository: &'input CampaignRepository,
    input: &'input ObjectiveEvaluationInput,
}

impl<'input> ObjectiveInputSegmentSource<'input> {
    /// Reads through `repository`, limited to the evidence `input` owns.
    #[must_use]
    pub const fn new(
        repository: &'input CampaignRepository,
        input: &'input ObjectiveEvaluationInput,
    ) -> Self {
        Self { repository, input }
    }
}

impl AttemptLogSegmentSource for ObjectiveInputSegmentSource<'_> {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.repository
            .read_objective_evidence_leaf(self.input, id, MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64)
            .map_err(io::Error::other)
    }
}

/// Reads any published segment by identity, without an ownership check.
///
/// Used where the caller already authenticates the referencing leaf against
/// its owner, such as the exact-retention check of a finding boundary.
pub struct ExecutorTraceSegmentSource<'store> {
    store: &'store CampaignExecutorStore,
}

impl<'store> ExecutorTraceSegmentSource<'store> {
    /// Reads through `store`.
    #[must_use]
    pub const fn new(store: &'store CampaignExecutorStore) -> Self {
        Self { store }
    }
}

impl AttemptLogSegmentSource for ExecutorTraceSegmentSource<'_> {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.store
            .load_executor_trace_leaf(id, MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64)
            .map_err(io::Error::other)
    }
}
