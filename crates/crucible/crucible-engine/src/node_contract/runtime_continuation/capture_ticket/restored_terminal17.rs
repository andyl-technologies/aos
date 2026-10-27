//! Authenticates actual completed current17 outputs before pure terminal work.
//!
//! This guard only borrows the Runtime-retained attempt. It cannot fabricate a
//! completed result, replace an uncertain owner, publish an archive or renew an ID.

use super::*;
use crate::node_contract::{PreparedRestoredHost17Capture, RestoredCollectingCaptureScope17};

impl OriginalLineageWorldCapture {
    /// Authenticates genuine settled output custody beneath the same current17 scope.
    ///
    /// # Errors
    /// Refuses a foreign/inactive/persisted attempt, incomplete or uncertain
    /// owners, another archive/Runtime/Scope, a legacy Host family, another
    /// prepared Rc, or a Host producer that has not actually left its capsule.
    pub(crate) fn authenticate_restored_terminal_data(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        scope: &RestoredCollectingCaptureScope17<'_>,
        archive: &crate::node_state::NativeArchiveRecord,
        prepared: &Rc<PreparedRestoredHost17Capture>,
    ) -> Result<(), RuntimeError> {
        scope.authenticate_runtime_data(runtime)?;
        self.authenticate_pending_archive_write_origin(runtime, archive)?;
        let actual = match &self.attempt.host {
            host_preparation::family::PreparedHostCaptureFamily::Settled17(actual) => actual,
            host_preparation::family::PreparedHostCaptureFamily::Initial15(_) => {
                return Err(RuntimeError::UnsupportedFacet);
            }
        };
        if !Rc::ptr_eq(actual, prepared)
            || &self.attempt.capture_id != scope.capture_id_data()
            || !self.attempt.activation.same_authority(scope.world_data())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        actual.authenticate_host_data(scope.host_data())?;
        actual.authenticate_runtime_data(
            runtime,
            scope.world_data(),
            &self.attempt.runtime_object,
        )?;
        actual.authenticate_spent_data()?;
        scope.authenticate_runtime_data(runtime)
    }

    /// Names the real local and pending-write guard controls before their walk.
    pub(crate) fn restored_terminal_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&crate::node_contract::NodeRuntime>()
            + size_of::<&RestoredCollectingCaptureScope17<'_>>()
            + size_of::<&crate::node_state::NativeArchiveRecord>()
            + size_of::<&Rc<PreparedRestoredHost17Capture>>()
            + size_of::<&Rc<OriginalLineageCaptureAttempt>>()
            + size_of::<Option<&Rc<OriginalLineageCaptureAttempt>>>()
            + size_of::<Result<OriginalLineageWorldCaptureRead<'_>, RuntimeError>>()
            + size_of::<OriginalLineageWorldCaptureRead<'_>>()
            + size_of::<Ref<'_, Vec<Option<super::super::InstalledOriginalLineageCapture>>>>()
            + size_of::<Ref<'_, Vec<Option<(ContentRef, ContentRef)>>>>()
            + size_of::<
                Result<
                    Ref<'_, Option<crate::node_contract::HostSchedulingRestoredContinuation17>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<[usize; 5]>()
            + size_of::<std::slice::Iter<'_, OriginalCaptureOwnerReservation>>()
            + size_of::<std::slice::Iter<'_, crate::node_state::NativeOwnerState>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
