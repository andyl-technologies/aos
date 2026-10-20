//! Shares the existing fixed captured Journal stages across Network catalogs.
//!
//! The private recipe set selects only image-fixed Network paths. It lends no
//! writer until the same staged opener has retained its complete replay and
//! native posts. Each typed catalog owns its subsequent model and append work.

use crate::journal::{
    Journal, JournalError, JournalLimits,
    NetworkLifecycleCapturedJournalOpenV4, NetworkNamespaceCapturedJournalOpenV4,
    NetworkPreparationCapturedJournalOpenV4, ProtectedJournalPreopenReplayExtentV1, RecoveryReport,
};
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, FixedServiceReceivingCaptureV1 as Common,
};
use aos_sandbox_core::{AccountingError, ResourceVector};

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkJournalStartupErrorV4 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Geometry(#[from] AccountingError),
    #[error("the same image-enrolled Network startup remains closed")]
    Closed,
}

pub(crate) type Result<T> = std::result::Result<T, NetworkJournalStartupErrorV4>;

pub(crate) trait NetworkJournalRecipeV4 {
    fn new_v4() -> Self;
    fn fixed_v4() -> std::result::Result<ResourceVector, JournalError>;
    fn prepare_v4(&mut self, limits: JournalLimits);
    fn extent_v4(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1>;
    fn replay_v4(&mut self);
    fn take_v4(&mut self) -> Option<(Journal, RecoveryReport)>;
    fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)>;
    fn inventory_demand_v2(&self) -> std::result::Result<ResourceVector, JournalError>;
    fn inventory_before_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), JournalError>;
    fn inventory_after_owed_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), JournalError>;

}

// These are typed adapters to the sole captured writer, not alternate native
// open/replay implementations or a caller-selected path/account factory.
macro_rules! recipe {
    ($native:ty) => {
        impl NetworkJournalRecipeV4 for $native {
            fn new_v4() -> Self { Self::new() }
            fn fixed_v4() -> std::result::Result<ResourceVector, JournalError> { Self::fixed_preparation_demand() }
            fn prepare_v4(&mut self, limits: JournalLimits) {
                self.prepare_once(limits);
            }
            fn extent_v4(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
                self.captured_extent()
            }
            fn replay_v4(&mut self) { self.replay_once(); }
            fn take_v4(&mut self) -> Option<(Journal, RecoveryReport)> { self.take_opened() }
            fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
            fn inventory_demand_v2(&self) -> std::result::Result<ResourceVector, JournalError> {
                self.inventory_currentness_receiving_demand_v2()
            }

            fn inventory_before_v2(&self, journal: &Journal,
                original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
            ) -> std::result::Result<(), JournalError> {
                self.observe_inventory_currentness_before_v2(journal, original)
            }

            fn inventory_after_owed_v2(&self, journal: &Journal,
                original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
            ) -> std::result::Result<(), JournalError> {
                self.observe_inventory_currentness_after_owed_v2(journal, original)
            }

        }
    };
}

recipe!(NetworkLifecycleCapturedJournalOpenV4);
recipe!(NetworkPreparationCapturedJournalOpenV4);
recipe!(NetworkNamespaceCapturedJournalOpenV4);

pub(crate) struct NetworkJournalOriginalV4<N: NetworkJournalRecipeV4> {
    native: N,
    journal: Option<Journal>,
    report: Option<RecoveryReport>,
    result: Option<Result<()>>,
    funding: [Option<std::result::Result<(), Closed>>; 2],
    original_selected: bool,
    entered: bool,
}

impl<N: NetworkJournalRecipeV4> NetworkJournalOriginalV4<N> {
    pub(crate) fn new() -> Self {
        Self { native: N::new_v4(), journal: None, report: None, result: None,
            funding: std::array::from_fn(|_| None), original_selected: false, entered: false }
    }

    pub(crate) fn open_once_v4(&mut self, common: &mut Common<Closed>, limits: JournalLimits,
        model_demand: fn(&ProtectedJournalPreopenReplayExtentV1) -> Result<ResourceVector>) -> Result<()> {
        if self.entered { return Err(NetworkJournalStartupErrorV4::Closed); }
        self.entered = true;
        self.result = Some(self.open_inner(common, limits, model_demand));
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(NetworkJournalStartupErrorV4::Closed) }
    }

    fn open_inner(&mut self, common: &mut Common<Closed>, limits: JournalLimits,
        model_demand: fn(&ProtectedJournalPreopenReplayExtentV1) -> Result<ResourceVector>) -> Result<()> {
        if common.require_network_startup_current_v4().is_err() {
            self.original_selected = true;
            return Err(NetworkJournalStartupErrorV4::Closed);
        }
        self.admit_v4(common, N::fixed_v4()?, 0)?;
        self.native.prepare_v4(limits);
        let extent = self.native.extent_v4().ok_or(NetworkJournalStartupErrorV4::Closed)?;
        let demand = extent.dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(model_demand(extent)?)?;
        self.admit_v4(common, demand, 1)?;
        self.native.replay_v4();
        let (journal, report) = self.native.take_v4().ok_or(NetworkJournalStartupErrorV4::Closed)?;
        self.journal = Some(journal);
        self.report = Some(report);
        Ok(())
    }

    fn admit_v4(&mut self, common: &mut Common<Closed>, demand: ResourceVector, slot: usize) -> Result<()> {
        self.funding[slot] = Some(common.require_additional_startup_representation_v4(demand));
        if !matches!(self.funding[slot], Some(Ok(()))) {
            self.original_selected = true;
            return Err(NetworkJournalStartupErrorV4::Closed);
        }
        Ok(())
    }

    pub(crate) fn inventory_currentness_demand_v2(&self)
        -> std::result::Result<ResourceVector, JournalError>
    {
        self.native.inventory_demand_v2()
    }

    pub(crate) fn inventory_currentness_before_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), JournalError> {
        self.native.inventory_before_v2(journal, original)
    }

    pub(crate) fn inventory_currentness_after_owed_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), JournalError> {
        self.native.inventory_after_owed_v2(journal, original)
    }

    pub(crate) fn journal_v4(&self) -> Option<&Journal> { self.journal.as_ref() }

    pub(crate) fn journal_mut_v4(&mut self) -> Option<&mut Journal> { self.journal.as_mut() }

    pub(crate) fn take_journal_v4(&mut self) -> Option<Journal> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.journal.take()
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool { self.original_selected }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure_v4()
            .or_else(|| self.journal.as_ref().and_then(Journal::retained_native_append_failure_v1))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Bounds actual reached named rows before any typed catalog model grows.
pub(crate) fn reached_rows_v4(extent: &ProtectedJournalPreopenReplayExtentV1) -> Result<usize> {
    extent.source_transactions.checked_mul(extent.limits.maximum_records_per_transaction)
        .and_then(|rows| rows.checked_add(extent.source_checkpoint_rows))
        .map(|rows| rows.min(extent.limits.maximum_materialized_records))
        .ok_or(NetworkJournalStartupErrorV4::Closed)
}

/// Prices the fixed scalar/byte-array initialization-head decoder's transient peak.
///
/// The existing canonical JSON reader retains a typed envelope and reencodes it
/// once for byte equality. These heads have no variable fields: successful
/// canonical output cannot exceed their input. The three buffer planes match
/// canonical_map's existing geometric encoder supplier; the protected MAC opener
/// borrows its payload, so the sealed input is a conservative encoded extent.
pub(crate) fn inventory_head_decode_memory_v2<T>(encoded: &[u8]) -> Option<usize> {
    encoded.len().max(128).checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<T>().checked_mul(2)?))
}
