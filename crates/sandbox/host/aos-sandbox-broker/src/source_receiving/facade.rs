//! Implements sealed native dispatch for the genuine fixed Source coordinator.

use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use crate::canonical_journal::coordinator::{
    CanonicalCoordinatorReadV1, CanonicalCoordinatorAppendV1,
    CanonicalCoordinatorAppendDataV1, CanonicalWriterReadViewV1, sealed,
};
use super::{SourceCoordinatorWriterV1, SourcePreparedAppendV1, SourceNativeErrorV1};

impl<P> sealed::ReadOwner for SourceCoordinatorWriterV1<P> {}

impl<P> CanonicalCoordinatorReadV1<P> for SourceCoordinatorWriterV1<P> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        CanonicalWriterReadViewV1::from_parts(
            self.physical.native.native(), &self.physical.index, Some(&self.physical.location),
        )
    }
}

impl sealed::AppendData for SourcePreparedAppendV1 {}

impl CanonicalCoordinatorAppendDataV1 for SourcePreparedAppendV1 {
    fn transaction(&self) -> Option<&JournalTransaction> {
        self.storage.body().map(|body| body.stages.transaction())
    }

    fn encoded_frames(&self) -> Option<&[Vec<u8>]> {
        self.storage.body().and_then(|body| body.stages.encoded_frames())
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        self.storage.body().and_then(|body| body.stages.projected_materialized_bytes())
    }

    fn last_applied_record(&self) -> Option<&JournalRecord> {
        self.storage.body().and_then(|body| body.stages.last_applied_record())
    }

    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        self.storage.body().and_then(|body| body.stages.published_coordinates())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

impl<P> sealed::AppendOwner for SourceCoordinatorWriterV1<P> {}

impl<P> CanonicalCoordinatorAppendV1<P> for SourceCoordinatorWriterV1<P> {
    type Error = SourceNativeErrorV1;
    type Prepared<'transaction> = SourcePreparedAppendV1;

    fn poison(&mut self) {
        self.fenced = true;
        self.physical.native.native_mut().poison();
    }

    fn prepare_append_once<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<Self::Prepared<'transaction>, Self::Error> {
        self.prepare_source_append_once(transaction)
    }

    fn append_coordinates_once(&self, stage: &mut Self::Prepared<'_>) -> Result<(u64, u64), Self::Error> {
        self.require_stage(stage)?.stages.coordinates_once().map_err(|_| SourceNativeErrorV1::Closed)
    }

    fn expected_append_length_once(&self, stage: &mut Self::Prepared<'_>) -> Result<u64, Self::Error> {
        self.require_stage(stage)?.stages.expected_length_once(self.physical.native.native())
            .map_err(|_| SourceNativeErrorV1::Closed)
    }

    fn append_prepared_once(&mut self, stage: &mut Self::Prepared<'_>) -> Result<u64, Self::Error> {
        self.require_stage(stage)?.stages.append_once(self.physical.native.native_mut())
            .map_err(|_| SourceNativeErrorV1::Closed)
    }

    fn apply_next_record_once(&mut self, stage: &mut Self::Prepared<'_>) -> Result<bool, Self::Error> {
        self.apply_next_source_record_once(stage)
    }

    fn publish_append_once(&mut self, stage: &mut Self::Prepared<'_>)
        -> Result<CanonicalAppendPublishedDataV1, Self::Error>
    {
        self.publish_source_append_once(stage)
    }

    fn finish_append_after_posts_once(&mut self, stage: &mut Self::Prepared<'_>) -> Result<(), Self::Error> {
        self.dispose_source_append_once(stage)
    }
}

impl<P> sealed::NativeOwner for SourceCoordinatorWriterV1<P> {}

impl<P> crate::canonical_journal::coordinator::CanonicalCoordinatorNativeV1<P> for SourceCoordinatorWriterV1<P> {
    fn native_operations(&self)
        -> crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1<'_, P>
    {
        crate::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1::from_parts(
            self.physical.native.native(), Some(&self.physical.location), None,
        )
    }
}
