//! Joins the same J original to reached readonly Native semantic frontiers.
//!
//! The actual Cache loan constructs this private context while retaining its
//! initialized originals. The shared captured reader alone supplies validated
//! COMMIT positions and its captured file end. There is no second parser,
//! generic callback, public payer constructor or detached authority witness.

use super::*;
use crate::journal::{JournalTransaction, create_storage_history::HistoryPairNativeSuffixV1};
use crate::controller_resource_reservation::CreateStorageOriginalLoanV1;
use aos_sandbox_model::ResourceVector;

type State = std::collections::BTreeMap<(crate::RecordNamespace, Vec<u8>), Vec<u8>>;

/// Binds one paid readonly continuation to the actual existing Cache original.
pub(crate) struct CacheHeldReadonlyContextV1<'borrow, 'original, 'data> {
    pub(super) original: CacheHeldReadonlyPayerV1<'borrow, 'original>,
    pub(super) identity: CacheHeldIdentityDataV1,
    pub(super) complete_base: ResourceVector,
    pub(super) captured_end: u64,
    pub(super) suffix: Option<HistoryPairNativeSuffixV1<'data, 'borrow>>,
    pub(super) released_suffix: Option<crate::journal::create_storage_history::ControllerHistoryNativeSuffixV1<'data, 'borrow, 2>>,
    pub(super) geometry: &'borrow mut Option<Result<ResourceVector, JournalError>>,
    pub(super) admission: &'borrow mut Option<Result<(), ResourceReservationErrorV1>>,
}

// The two variants are concrete genuine loans. Neither accepts an amount,
// callback or caller-implemented payer; both retain their actual original J.
pub(super) enum CacheHeldReadonlyPayerV1<'borrow, 'original> {
    Initial(&'borrow mut CreateStorageOriginalLoanV1<'original>),
    Current(&'borrow mut crate::controller_resource_reservation::CacheCurrentAuditReceivingLoanV1<'original>),
    Release(&'borrow mut crate::controller_resource_reservation::CacheReleaseReceivingLoanV1<'original>),
    Delete(&'borrow mut super::delete_inventory::native_admission::CacheDeleteReadAdmissionV1<'original>),
}

impl CacheHeldReadonlyPayerV1<'_, '_> {
    fn prepaid_semantic_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        match self {
            Self::Initial(_) => Ok(ResourceVector::ZERO),
            Self::Delete(original) => original.semantic_peak_v1(),
            Self::Current(original) => original.cache_current_semantic_peak_v1()
                .map_err(|_| JournalError::ProtectedBoundary),
            Self::Release(original) => original.cache_current_semantic_peak_v1()
                .map_err(|_| JournalError::ProtectedBoundary),
        }
    }

    fn require_cache_named_preparation(&mut self, identity: CacheHeldIdentityDataV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        match self {
            Self::Initial(original) => original.require_cache_named_preparation(identity),
            Self::Current(original) => original.require_cache_named_preparation(identity),
            Self::Release(original) => original.require_cache_named_preparation(identity),
            Self::Delete(original) => original.require_identity_v1(identity),
        }
    }

    fn admit_cache_semantic_shape(&mut self, shape: &CacheHeldNativeSemanticShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        match self {
            Self::Initial(original) => original.admit_cache_semantic_shape(shape),
            Self::Current(original) => original.admit_cache_semantic_shape(shape),
            Self::Release(original) => original.admit_cache_semantic_shape(shape),
            Self::Delete(original) => original.require_semantic_shape_v1(shape),
        }
    }
}

/// Carries the complete actual semantic peak to the same original J accounting.
pub(crate) struct CacheHeldNativeSemanticShapeV1 {
    pub(super) identity: CacheHeldIdentityDataV1,
    pub(super) complete: ResourceVector,
}

impl CacheHeldNativeSemanticShapeV1 {
    /// Returns Eq-only comparison DATA, never the initialized owners or a grant.
    pub(crate) fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }

    /// Returns the COMPLETE fixed, native/model and reached semantic demand.
    ///
    /// # Errors
    /// The actual constructor already retained any checked arithmetic refusal;
    /// no caller can construct a different raw demand through this API.
    pub(crate) fn dominant_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        Ok(self.complete)
    }
}

impl CacheHeldReadonlyContextV1<'_, '_, '_> {
    /// Rejoins the same already-paid fixed/captured J stage before named IO.
    ///
    /// # Errors
    /// Retains original identity, accounting phase or earlier sticky refusal.
    pub(crate) fn require_fixed_named_preparation(&mut self) -> Result<(), JournalError> {
        if self.failed() { return Err(JournalError::ProtectedBoundary); }
        *self.admission = Some(self.original.require_cache_named_preparation(self.identity));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Compares the actual reader's captured end before any replay growth.
    ///
    /// # Errors
    /// Refuses a changed file length or earlier retained geometry/payment debt.
    pub(crate) fn require_captured_file_end(&mut self, actual_end: u64) -> Result<(), JournalError> {
        if actual_end != self.captured_end || self.failed() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Admits reached current/proposed carriers before the existing reducers.
    ///
    /// # Errors
    /// Retains actual checked geometry and same-J payment refusal before typed
    /// allocation, including historical/foreign declared-vector EOF frontiers.
    pub(crate) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        if self.failed() { return Err(JournalError::ProtectedBoundary); }
        // This is the shared passive per-row/family carrier calculation, not a
        // Source payer. Actual Native/Cache receiving remains on this same J.
        *self.geometry = Some((|| {
            let dynamic = crate::journal::source_readonly_semantic_demand_v1(state, transaction)?;
            let prepaid = self.original.prepaid_semantic_demand_v1()?;
            // The current purpose already includes its five-prefix semantic
            // bound. Only a reached excess grows the complete reservation.
            // Initial Held has zero prepayment and preserves its old formula.
            let additional = dynamic.componentwise_max(prepaid).checked_sub(prepaid)
                .map_err(|_| JournalError::LimitExceeded("Cache Held semantic geometry"))?;
            self.complete_base.checked_add(additional)
                .map_err(|_| JournalError::LimitExceeded("Cache Held semantic geometry"))
        })());
        let complete = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        let shape = CacheHeldNativeSemanticShapeV1 { identity: self.identity, complete };
        *self.admission = Some(self.original.admit_cache_semantic_shape(&shape));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Observes one transaction from the sole validated Native COMMIT parser.
    ///
    /// # Errors
    /// Retains a prefix-crossing, substituted/extra transaction or wrong native
    /// coordinates in the actual borrowed suffix owner; no retry heals it.
    pub(crate) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        if let Some(suffix) = self.suffix.as_mut() {
            suffix.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        if let Some(suffix) = self.released_suffix.as_mut() {
            suffix.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        Ok(())
    }

    /// Completes suffix DATA against the same parser and captured physical end.
    ///
    /// # Errors
    /// Retains absent/extra suffix, partial tail or differing durable positions.
    pub(crate) fn finish_native(
        &mut self,
        durable_next: u64,
        durable_end: u64,
        captured_end: u64,
    ) -> Result<(), JournalError> {
        self.require_captured_file_end(captured_end)?;
        if let Some(suffix) = self.suffix.as_mut() {
            suffix.finish(durable_next, durable_end, captured_end)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        if let Some(suffix) = self.released_suffix.as_mut() {
            suffix.finish(durable_next, durable_end, captured_end)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        Ok(())
    }

    fn failed(&self) -> bool {
        matches!(self.geometry, Some(Err(_))) || matches!(self.admission, Some(Err(_)))
            || self.suffix.as_ref().is_some_and(|suffix| suffix.failure().is_some())
            || self.released_suffix.as_ref().is_some_and(|suffix| suffix.failure_v1().is_some())
    }
}
