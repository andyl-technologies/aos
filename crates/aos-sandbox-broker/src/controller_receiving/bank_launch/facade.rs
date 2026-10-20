//! Implements sealed mechanical dispatch for the genuine Controller coordinator.
//!
//! The closed fixed opening creates the only implementor. Domain's existing
//! semantic coordinator remains responsible for its effect gates and exact
//! ordering. No role loan implements these traits or gains native mutation.

use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use crate::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use crate::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
    CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1, sealed,
};

use super::{ControllerBankLaunchErrorV1, ControllerCoordinatorWriterV1, ControllerPreparedAppendV1};

impl<P> sealed::ReadOwner for ControllerCoordinatorWriterV1<P> {}

impl<P> CanonicalCoordinatorReadV1<P> for ControllerCoordinatorWriterV1<P> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        let physical = self.physical_data();
        CanonicalWriterReadViewV1::from_parts(
            physical.native.native(), &physical.index, Some(&physical.location),
        )
    }
}

impl sealed::AppendData for ControllerPreparedAppendV1 {}

impl CanonicalCoordinatorAppendDataV1 for ControllerPreparedAppendV1 {
    fn transaction(&self) -> Option<&JournalTransaction> {
        self.transaction()
    }

    fn encoded_frames(&self) -> Option<&[Vec<u8>]> {
        self.encoded_frames().ok()
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        self.projected_materialized_bytes().ok()
    }

    fn last_applied_record(&self) -> Option<&JournalRecord> {
        self.last_applied_record()
    }

    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        self.published_coordinates()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl<P> sealed::AppendOwner for ControllerCoordinatorWriterV1<P> {}

impl<P> CanonicalCoordinatorAppendV1<P> for ControllerCoordinatorWriterV1<P> {
    type Error = ControllerBankLaunchErrorV1;
    type Prepared<'transaction> = ControllerPreparedAppendV1;

    fn poison(&mut self) {
        self.fixed.fence();
    }

    fn prepare_append_once<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<Self::Prepared<'transaction>, Self::Error> {
        self.prepare_controller_append_once(transaction)
    }

    fn append_coordinates_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(u64, u64), Self::Error> {
        self.controller_append_coordinates_once(stage)
    }

    fn expected_append_length_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error> {
        self.expected_controller_append_length_once(stage)
    }

    fn append_prepared_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error> {
        self.append_controller_prepared_once(stage)
    }

    fn apply_next_record_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<bool, Self::Error> {
        self.apply_next_controller_record_once(stage)
    }

    fn publish_append_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, Self::Error> {
        self.publish_controller_append_once(stage)
    }

    fn finish_append_after_posts_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(), Self::Error> {
        self.finish_controller_append_after_posts_once(stage)
    }
}

impl<P> sealed::NativeOwner for ControllerCoordinatorWriterV1<P> {}

impl<P> crate::canonical_journal::coordinator::CanonicalCoordinatorNativeV1<P> for ControllerCoordinatorWriterV1<P> {
    fn native_operations(&self)
        -> crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1<'_, P>
    {
        let physical = self.physical_data();
        crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1::from_parts(
            physical.native.native(), Some(&physical.location), None,
        )
    }
}
