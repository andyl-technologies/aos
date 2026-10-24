//! Joins saved Source floor comparison to the genuine current Authority owner.
//!
//! The lower model is DATA. Only this native method repeats the actual owner,
//! independent credential and complete-history gates before the comparison.

use aos_sandbox_ledger_replay::replay::root_saved_floor::RootSavedSourceFloorDataV1;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentReplyFieldsV1;

use super::super::{RootAuthorityErrorV1, RootAuthorityOriginalV1};

impl RootAuthorityOriginalV1 {
    /// Compares the saved floor while retaining the same actual native owner.
    ///
    /// # Errors
    /// Refuses changed fixed custody, pins, any complete history member, a
    /// foreign supplied tuple or a changed canonical Source Tree/lineage cut.
    pub fn compare_saved_source_floor_v1(
        &self,
        pins: &[u8; 488],
        source: &SourceDeleteCurrentReplyFieldsV1,
    ) -> Result<RootSavedSourceFloorDataV1, RootAuthorityErrorV1> {
        self.recheck()?;
        if self.pins.record_bytes()? != pins {
            return Err(RootAuthorityErrorV1::Stale);
        }
        aos_sandbox_ledger_replay::replay::root_saved_floor::compare_saved_source_floor_v1(
            self.journal.read_view().historical_view(),
            source,
        )
        .map_err(RootAuthorityErrorV1::from)
    }
}
