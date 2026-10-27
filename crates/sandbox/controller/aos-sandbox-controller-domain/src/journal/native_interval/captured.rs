//! Keeps Domain Delete-window gates around the sole shared captured append owner.
//!
//! Installation is private to the fixed captured opener. Its actual Host20 or
//! Controller B/operation owner pays native posts and owned append growth.

use super::*;
pub(in crate::journal) use aos_sandbox_broker::canonical_journal::captured::CapturedWriterGuardRecipeV1 as CapturedGuardRecipeV1;
use aos_sandbox_broker::canonical_journal::captured::{
    CapturedAppendDataOwnerV1, CapturedAppendPostsV1,
};
use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use aos_sandbox_broker::canonical_journal::coordinator::retained_data::RetainedAppendDataCustodyV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

mod delete_window;
pub(in crate::journal) use delete_window::DeleteSessionAppendWindowV1;

pub(in crate::journal) struct CapturedAppendOwnerV1 {
    common: CapturedAppendDataOwnerV1<JournalError>,
    delete_window: Option<std::sync::Arc<DeleteSessionAppendWindowV1>>,
}

pub(in crate::journal) struct CapturedAppendPostV1 {
    common: CapturedAppendPostsV1<JournalError>,
    delete_window: Option<std::sync::Arc<DeleteSessionAppendWindowV1>>,
    delete_window_selected: bool,
    delete_window_completion_selected: bool,
}

impl CapturedAppendOwnerV1 {
    pub(in crate::journal) fn new(directory: &'static str, name: &'static str, uid: u32) -> Self {
        Self {
            common: CapturedAppendDataOwnerV1::new(directory, name, uid),
            delete_window: None,
        }
    }

    pub(in crate::journal) fn construction_demand_v1() -> Option<ResourceVector> {
        let upper = u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?;
        CapturedAppendDataOwnerV1::<JournalError>::construction_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, upper))
            .ok()
    }

    pub(in crate::journal) fn append_demand_v1(
        &self,
        encoded: u64,
    ) -> Result<ResourceVector, JournalError> {
        self.common
            .append_demand_v1(encoded, Self::upper_interval_bytes_v1()?)
    }

    pub(in crate::journal) fn append_demand_for_fixed_v1(
        directory: &'static str,
        name: &'static str,
        encoded: u64,
    ) -> Result<ResourceVector, JournalError> {
        CapturedAppendDataOwnerV1::<JournalError>::append_demand_for_fixed_v1(
            directory,
            name,
            encoded,
            Self::upper_interval_bytes_v1()?,
        )
    }

    fn upper_interval_bytes_v1() -> Result<usize, JournalError> {
        JournalNativeIntervalOriginalV1::captured_receiving_construction_bytes_v1().ok_or(
            JournalError::LimitExceeded("captured append representation"),
        )
    }

    pub(in crate::journal) fn data_custody_v1(&self) -> &RetainedAppendDataCustodyV1 {
        self.common.data_custody_v1()
    }

    pub(in crate::journal) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.common
            .native_failure_v1()
            .or_else(|| {
                self.delete_window
                    .as_ref()
                    .and_then(|window| window.failure())
            })
            .or_else(|| self.common.data_custody_v1().failure())
    }

    pub(in crate::journal) fn is_closed(&self) -> bool {
        self.common.is_closed()
            || self
                .delete_window
                .as_ref()
                .is_some_and(|window| window.failure().is_some())
    }

    // Only the genuine C17 inventory constructor installs this SAME bounded
    // window. Native ownership and the ordinary fixed opener stay unchanged.
    pub(in crate::journal) fn install_delete_window_v1(
        &mut self,
        window: std::sync::Arc<DeleteSessionAppendWindowV1>,
    ) -> Result<(), JournalError> {
        if self.delete_window.is_some()
            || self.is_closed()
            || !self.common.data_custody_v1().is_idle_v1()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.delete_window = Some(window);
        Ok(())
    }

    pub(in crate::journal) fn require_delete_append_window_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let Some(window) = &self.delete_window else {
            return Ok(());
        };
        let encoded =
            aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(
                transaction,
            )?;
        window.admit_encoded_once(encoded)
    }

    pub(in crate::journal) fn require_delete_identity_v1(
        &self,
        directory: &'static str,
        name: &'static str,
        uid: u32,
    ) -> Result<(), JournalError> {
        if !self.common.matches_identity_v1(directory, name, uid)
            || self.is_closed()
            || !self.common.data_custody_v1().is_idle_v1()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(in crate::journal) fn require_delete_window_retirement_v1(
        &self,
        expected: &std::sync::Arc<DeleteSessionAppendWindowV1>,
    ) -> Result<(), JournalError> {
        if self.is_closed()
            || !self.common.data_custody_v1().is_idle_v1()
            || !self
                .delete_window
                .as_ref()
                .is_some_and(|actual| std::sync::Arc::ptr_eq(actual, expected))
            || !expected.is_exhausted_inactive_v1()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    // Only the exclusive, already-checked D positive-disposal token calls
    // this after successful upper disposal. It performs no IO or admission.
    pub(in crate::journal) fn complete_delete_window_retirement_v1(&mut self) {
        drop(self.delete_window.take());
    }

    pub(in crate::journal) fn observe_guard_v1(
        &self,
        view: CanonicalWriterReadViewV1<'_, super::super::native_backing::Selection>,
        recipe: CapturedGuardRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.common.observe_guard_v1(view, recipe)
    }

    pub(in crate::journal) fn arm(&self) -> CapturedAppendPostV1 {
        CapturedAppendPostV1 {
            common: self.common.arm(),
            delete_window: self.delete_window.as_ref().map(std::sync::Arc::clone),
            delete_window_selected: false,
            delete_window_completion_selected: false,
        }
    }
}

impl CapturedAppendPostV1 {
    pub(super) fn before_once(
        &mut self,
        view: CanonicalWriterReadViewV1<'_, super::super::native_backing::Selection>,
    ) -> Result<(), JournalError> {
        self.common.before_once(view)
    }

    pub(super) fn after_once(
        &mut self,
        view: CanonicalWriterReadViewV1<'_, super::super::native_backing::Selection>,
    ) -> Result<(), JournalError> {
        self.common.after_once(view)
    }

    pub(super) fn mark_primary_return_v1(&mut self) {
        self.common.mark_primary_return_v1();
        self.delete_window_selected = self
            .delete_window
            .as_ref()
            .is_some_and(|window| window.failure().is_some());
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.common.before_failure().or_else(|| {
            if self.delete_window_selected {
                self.delete_window
                    .as_ref()
                    .and_then(|window| window.failure())
            } else {
                None
            }
        })
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure()
            .or_else(|| self.common.failure())
            .or_else(|| {
                if self.delete_window_completion_selected {
                    self.delete_window
                        .as_ref()
                        .and_then(|window| window.failure())
                } else {
                    None
                }
            })
    }

    pub(super) fn dispose(&mut self) -> Result<(), JournalError> {
        self.common.require_complete_v1()?;
        if let Some(window) = &self.delete_window {
            // The same native/publication join still precedes the C17 window.
            self.delete_window_completion_selected = true;
            window.complete_positive_append_v1()?;
        }
        self.common.dispose()
    }
}
