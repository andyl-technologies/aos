//! Lends existing ordinary native fields to the same named mechanical stages.
//!
//! These adapters borrow caller-supplied DATA. They construct no protected role
//! or selected C/R original and never export the supplied native/location/file.
//! The trusted ordinary coordinator keeps its original immediate error disposal.

use std::borrow::Borrow;
use std::collections::BTreeMap;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::owner::NativeJournal;
use aos_sandbox_journal::protected_storage::ProtectedJournalLocation;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalTransaction};

use super::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
    CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1, sealed,
};
use crate::canonical_journal::append_stages::{
    CanonicalAppendClosedV1, CanonicalAppendPublishedDataV1, CanonicalAppendStagesV1,
};

type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Borrows actual ordinary native fields without adopting or authenticating them.
pub struct OrdinaryCoordinatorReadV1<'owner, P> {
    view: CanonicalWriterReadViewV1<'owner, P>,
}

impl<'owner, P> OrdinaryCoordinatorReadV1<'owner, P> {
    /// Lends supplied ordinary DATA without native IO, cloning or authority.
    #[must_use]
    pub const fn from_supplied_data_v1(
        native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
        index: &'owner Index,
        location: Option<&'owner ProtectedJournalLocation<P>>,
    ) -> Self {
        Self { view: CanonicalWriterReadViewV1::from_parts(native, index, location) }
    }

    /// Moves the same borrowed DATA view out of this temporary ordinary adapter.
    ///
    /// The references keep their supplied owner lifetime; consuming this adapter
    /// performs no native work, validation, allocation or role admission.
    #[must_use]
    pub const fn into_read_view_v1(self) -> CanonicalWriterReadViewV1<'owner, P> {
        self.view
    }

    /// Moves this ordinary DATA adapter into its same-lifetime native port.
    #[must_use]
    pub fn into_native_operations_v1(self) -> super::CanonicalWriterNativeOperationsV1<'owner, P> {
        self.view.ordinary_native_operations()
    }

}

impl<P> sealed::ReadOwner for OrdinaryCoordinatorReadV1<'_, P> {}

impl<P> CanonicalCoordinatorReadV1<P> for OrdinaryCoordinatorReadV1<'_, P> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        self.view
    }
}

/// Borrows actual ordinary mutable native/index fields without a raw projection.
///
/// This adapter is not a selected role port. Only the trusted coordinator's
/// existing ordinary variant supplies these fields, after its real semantic
/// gates. No transaction clone or new native owner is introduced.
pub struct OrdinaryCoordinatorAppendV1<'owner, P> {
    native: &'owner mut NativeJournal<RecordNamespace, JournalLimits>,
    index: &'owner mut Index,
    location: Option<&'owner ProtectedJournalLocation<P>>,
}

impl<'owner, P> OrdinaryCoordinatorAppendV1<'owner, P> {
    /// Lends supplied ordinary DATA at the caller's actual native frontier.
    #[must_use]
    pub fn from_supplied_data_v1(
        native: &'owner mut NativeJournal<RecordNamespace, JournalLimits>,
        index: &'owner mut Index,
        location: Option<&'owner ProtectedJournalLocation<P>>,
    ) -> Self {
        Self { native, index, location }
    }
}

impl<P> sealed::ReadOwner for OrdinaryCoordinatorAppendV1<'_, P> {}
impl<P> sealed::AppendOwner for OrdinaryCoordinatorAppendV1<'_, P> {}

impl<P> CanonicalCoordinatorReadV1<P> for OrdinaryCoordinatorAppendV1<'_, P> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        CanonicalWriterReadViewV1::from_parts(self.native, self.index, self.location)
    }
}

impl<T: Borrow<JournalTransaction>> sealed::AppendData for CanonicalAppendStagesV1<T> {}

impl<T: Borrow<JournalTransaction>> CanonicalCoordinatorAppendDataV1 for CanonicalAppendStagesV1<T> {
    fn transaction(&self) -> Option<&JournalTransaction> {
        Some(CanonicalAppendStagesV1::transaction(self))
    }

    fn encoded_frames(&self) -> Option<&[Vec<u8>]> {
        CanonicalAppendStagesV1::encoded_frames(self)
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        CanonicalAppendStagesV1::projected_materialized_bytes(self)
    }

    fn last_applied_record(&self)
        -> Option<&aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>
    {
        CanonicalAppendStagesV1::last_applied_record(self)
    }

    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        CanonicalAppendStagesV1::published_coordinates(self)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        CanonicalAppendStagesV1::failure(self)
    }
}

impl<P> CanonicalCoordinatorAppendV1<P> for OrdinaryCoordinatorAppendV1<'_, P> {
    type Error = CanonicalAppendClosedV1;
    type Prepared<'transaction> = CanonicalAppendStagesV1<&'transaction JournalTransaction>;

    fn poison(&mut self) {
        self.native.poison();
    }

    fn prepare_append_once<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<Self::Prepared<'transaction>, Self::Error> {
        let mut stage = CanonicalAppendStagesV1::new(transaction);
        if stage.project_once(self.native).is_ok() {
            let _encoded = stage.encode_once(self.native);
        }
        Ok(stage)
    }

    fn append_coordinates_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(u64, u64), Self::Error> {
        stage.coordinates_once()
    }

    fn expected_append_length_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error> {
        stage.expected_length_once(self.native)
    }

    fn append_prepared_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error> {
        stage.append_once(self.native)
    }

    fn apply_next_record_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<bool, Self::Error> {
        stage.apply_next_record_once(self.native, self.index)
    }

    fn publish_append_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, Self::Error> {
        stage.publish_once(self.native)
    }

    fn finish_append_after_posts_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(), Self::Error> {
        if stage.is_published() && stage.failure().is_none() {
            Ok(())
        } else {
            Err(CanonicalAppendClosedV1)
        }
    }
}

impl<P> sealed::NativeOwner for OrdinaryCoordinatorReadV1<'_, P> {}
impl<P> sealed::NativeOwner for OrdinaryCoordinatorAppendV1<'_, P> {}

impl<P> super::CanonicalCoordinatorNativeV1<P> for OrdinaryCoordinatorReadV1<'_, P> {
    fn native_operations(&self) -> super::CanonicalWriterNativeOperationsV1<'_, P> {
        self.view.ordinary_native_operations()
    }
}

impl<P> super::CanonicalCoordinatorNativeV1<P> for OrdinaryCoordinatorAppendV1<'_, P> {
    fn native_operations(&self) -> super::CanonicalWriterNativeOperationsV1<'_, P> {
        super::CanonicalWriterNativeOperationsV1::from_parts(self.native, self.location, None)
    }
}
