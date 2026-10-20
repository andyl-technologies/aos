//! Queries the actual Capture once slot and SDK frontier with fixed scratch.
//!
//! These borrowed views retain the genuine emitter, immutable codec, live
//! registration, selected features and completed first-Observe correspondence.
//! Full schema authentication and Source/Window Capture admission stay separate.

use super::*;

impl CnpController {
    /// Reports actual once-slot presence under the original current SDK owners.
    ///
    /// Every partial, refused or completed Capture remains present. Absence is
    /// read directly; failure of a completed-owner lender never proves absence.
    /// The same emitter/codec/registration, selected-owner and first-Observe
    /// checks lend DATA only, without authenticating schemas or issuing rights.
    ///
    /// # Errors
    /// Refuses foreign or stale original parents, revoked selection/registration,
    /// a fenced Controller or incomplete/changed first-Observe journal custody.
    pub fn original_restored_settled_capture_is_retained_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<bool, ProviderError> {
        self.authenticate_completed_capture17_cached_selection_data(emitter)?;
        Ok(self.original_restored_settled_capture.is_some())
    }

    /// Borrows the actual pre-upload SDK frontier using fixed owner checks.
    ///
    /// The Source's opaque synchronous cut independently joins this coordinate
    /// to its same live Controller and once owner. It creates no Capture slot,
    /// deadline, sequence or completion, and authenticates no supplied schema.
    /// The ordinary full-schema frontier getter remains separately available.
    ///
    /// # Errors
    /// Refuses foreign or stale original parents, revoked selection/registration,
    /// a fenced Controller, changed first Observe or unfinished complete restore.
    pub fn original_restored_settled_capture_history_next_sequence_precredit_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<U64, ProviderError> {
        self.authenticate_completed_capture17_cached_selection_data(emitter)?;
        self.ensure_no_pending_original_complete_restore()?;
        self.session.fresh_restore_query_sequence()
    }

    /// Names the fixed original-owner query controls before any borrowed walk.
    ///
    /// The existing precredit counter covers the actual shared guard and first
    /// Observe checks. These additional headers name the independent once-slot
    /// observation and boolean result. No dynamic contract work is inferred.
    pub fn original_restored_settled_capture_once_query_counter_scratch_data() -> usize {
        Self::original_completed_restored_settled_capture_precredit_counter_scratch_data()
            + size_of::<Option<&AssignedRestoredSettledCapture>>()
            + size_of::<Result<bool, ProviderError>>()
    }
}
