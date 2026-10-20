//! Holds the actual fixed Source writer and its permanent selected append sink.

use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::canonical_journal::CanonicalWriterCustodyDataV1;
use crate::canonical_journal::coordinator::selected_append::SelectedAppendCustodyV1;
use crate::controller_receiving::ControllerSourceOriginalRefV1;

use super::SourceNativeErrorV1;
use super::append::{SourceAppendBodyV1, SourcePreparedAppendV1, SourceAppendFailureOriginalV1};

/// Retains fixed Source custody at the trusted semantic coordinator boundary.
///
/// Only the genuine fixed opening creates this owner. It has no public tuple,
/// raw native, File, FD, mutable map or account projection. Its mechanical
/// stages do not establish any Source semantic or cross-owner permission.
pub struct SourceCoordinatorWriterV1<P> {
    pub(super) physical: CanonicalWriterCustodyDataV1<P>,
    pub(super) original: ControllerSourceOriginalRefV1,
    pub(super) base: ResourceVector,
    pub(super) semantic_peak: ResourceVector,
    pub(super) semantic_dynamic: Option<Result<ResourceVector, SourceNativeErrorV1>>,
    pub(super) durable_end: u64,
    pub(super) custody: Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>,
    pub(super) debit_failure: Option<SourceNativeErrorV1>,
    pub(super) replacement_custody: Arc<SelectedAppendCustodyV1<super::replacement::SourceReplacementBodyV1<P>>>,
    pub(super) replacement_semantic_bytes: Option<usize>,
    pub(super) native_post_active: bool,
    pub(super) delete_scope_active: bool,
    pub(super) provisioning_scope_active: bool,
    pub(super) provisioning_transaction: Option<[u8; 32]>,
    pub(super) provisioning_publication: Option<([u8; 32], crate::canonical_journal::append_stages::CanonicalAppendPublishedDataV1)>,
    pub(super) append_prepaid: bool,
    pub(super) append_upper_interval_bytes: Option<usize>,
    pub(super) fenced: bool,
}

impl<P> SourceCoordinatorWriterV1<P> {
    pub(super) fn from_fixed_opening(
        physical: CanonicalWriterCustodyDataV1<P>,
        original: ControllerSourceOriginalRefV1,
        base: ResourceVector,
        semantic_peak: ResourceVector,
        durable_end: u64,
        custody: Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>,
    ) -> Self {
        Self {
            physical, original, base, semantic_peak, semantic_dynamic: None, durable_end,
            custody,
            debit_failure: None,
            replacement_custody: Arc::new(SelectedAppendCustodyV1::new()),
            replacement_semantic_bytes: None,
            native_post_active: false,
            delete_scope_active: false,
            provisioning_scope_active: false,
            provisioning_transaction: None,
            provisioning_publication: None,
            append_prepaid: false,
            append_upper_interval_bytes: None,
            fenced: false,
        }
    }

    pub(super) fn construction_demand() -> Result<ResourceVector, SourceNativeErrorV1> {
        let bytes = CanonicalWriterCustodyDataV1::<P>::receiving_construction_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SelectedAppendCustodyV1<SourceAppendBodyV1>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SelectedAppendCustodyV1<super::replacement::SourceReplacementBodyV1<P>>>()))
            .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
            .ok_or(SourceNativeErrorV1::Closed)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| SourceNativeErrorV1::Closed)?))
    }

    /// Returns the same retained native writer's next sequence as comparison DATA.
    pub const fn next_sequence(&self) -> u64 {
        self.physical.native.native().next_sequence()
    }

    /// Returns the same retained native writer's durable end as comparison DATA.
    pub const fn durable_end_data_v1(&self) -> u64 {
        self.durable_end
    }

    /// Returns the same fixed native writer's configured limits as comparison DATA.
    pub const fn limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        self.physical.native.native().limits()
    }

    /// Reports native uncertainty while allowing an already healthy active stage.
    pub fn has_native_uncertainty_v1(&self) -> bool {
        self.fenced || self.physical.native.native().is_poisoned() || self.custody.is_closed()
            || self.replacement_custody.is_closed() || self.physical.replacement_custody.is_closed()
    }

    /// Reports closure or an in-progress append before any fresh owner entry.
    pub fn is_closed_or_poisoned_v1(&self) -> bool {
        self.delete_scope_active || self.provisioning_scope_active || self.native_post_active || self.append_prepaid
            || self.has_native_uncertainty_v1()
            || !self.custody.is_idle() || !self.replacement_custody.is_idle()
            || !self.physical.replacement_custody.is_idle()
    }

    /// Borrows the actual permanently retained append or debit cause.
    pub fn retained_append_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.debit_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.semantic_dynamic.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.custody.parked_body().and_then(SourceAppendBodyV1::failure))
    }

    /// Restricts the same Source original for its actual reached semantic models.
    ///
    /// This representation-only DATA port selects no work and returns no
    /// capacity, native custody, currentness or semantic readiness.
    ///
    /// # Errors
    /// Retains the first actual debit refusal and fences fresh native reuse.
    #[doc(hidden)]
    pub fn prepay_semantic_demand_once(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), SourceNativeErrorV1> {
        self.require_idle()?;
        self.prepay_semantic_demand_inner_v1(demand)
    }

    pub(super) fn prepay_semantic_demand_inner_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.native_post_active || self.append_prepaid {
            return Err(SourceNativeErrorV1::Closed);
        }
        let mut peak = ResourceVector::ZERO;
        for dimension in aos_sandbox_core::ResourceDimension::ALL {
            peak = peak.with(dimension, self.semantic_peak.get(dimension).max(demand.get(dimension)));
        }
        self.semantic_dynamic = Some((|| {
            let extent = crate::canonical_journal::CanonicalReplayExtentDataV1::new(
                self.limits(), self.durable_end,
            )?;
            let index = crate::canonical_journal::coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
                .map_err(|cause| match cause {
                    crate::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1::Native(cause) => SourceNativeErrorV1::Native(cause),
                    crate::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1::Closed => SourceNativeErrorV1::Closed,
                })?;
            let complete = self.base.checked_add(extent.dominant_native_receiving_demand_v1()?)?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(index)?.checked_add(peak)?;
            self.original.debit_complete_representation_v1(complete)?;
            Ok(peak)
        })());
        if matches!(self.semantic_dynamic, Some(Ok(_))) {
            self.semantic_peak = peak;
            Ok(())
        } else {
            self.fenced = true;
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Parks a passive geometry refusal without granting further native entry.
    ///
    /// # Errors
    /// Always returns a stopping marker after retaining the first actual cause.
    #[doc(hidden)]
    pub fn refuse_semantic_geometry_once(
        &mut self,
        cause: crate::canonical_journal::CanonicalJournalMechanicalErrorV1,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.semantic_dynamic.as_ref().is_none_or(|value| value.is_ok()) {
            self.semantic_dynamic = Some(Err(SourceNativeErrorV1::SemanticGeometry(cause)));
        }
        self.fenced = true;
        Err(SourceNativeErrorV1::Closed)
    }

    pub(super) fn require_idle(&self) -> Result<(), SourceNativeErrorV1> {
        // An already-armed post deliberately surrounds one actual append.
        // Its active bit cannot be a fresh-entry guard within that same body.
        if self.delete_scope_active || self.provisioning_scope_active || self.has_native_uncertainty_v1() || !self.custody.is_idle()
            || !self.replacement_custody.is_idle() || !self.physical.replacement_custody.is_idle()
        { Err(SourceNativeErrorV1::Closed) } else { Ok(()) }
    }

    pub(super) fn require_append_representation(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), SourceNativeErrorV1> {
        // This is a monotone restriction of the same genuine Source original.
        // No amount returns role admission or a native completion witness.
        use crate::canonical_journal::CanonicalReplayExtentDataV1;
        use crate::canonical_journal::coordinator::indexed_replay::{
            CanonicalReplayIndexOriginalsV1, CanonicalIndexedReplayErrorV1,
        };
        let invalid = || SourceNativeErrorV1::Closed;
        let appended = aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)
            .map_err(crate::canonical_journal::NativeJournalDataErrorV1::from)?;
        let end = self.durable_end.checked_add(appended).ok_or_else(invalid)?;
        let extent = CanonicalReplayExtentDataV1::new(self.physical.limits(), end)?;
        let stage_bytes = crate::canonical_journal::coordinator::selected_append::selected_append_stage_bytes_v1(
            transaction, appended,
            std::mem::size_of::<SourcePreparedAppendV1>(),
            std::mem::size_of::<SourceAppendFailureOriginalV1>(),
            std::mem::size_of::<SourceAppendBodyV1>(), 0,
        ).ok_or_else(invalid)?;
        let stage = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(stage_bytes).map_err(|_| invalid())?);
        let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
            .map_err(|cause| match cause {
                CanonicalIndexedReplayErrorV1::Native(cause) => SourceNativeErrorV1::Native(cause),
                CanonicalIndexedReplayErrorV1::Closed => SourceNativeErrorV1::Closed,
            })?;
        let upper = self.append_upper_interval_bytes.ok_or(SourceNativeErrorV1::Closed)?;
        let upper = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(upper).map_err(|_| invalid())?);
        let complete = self.base.checked_add(extent.dominant_native_receiving_demand_v1()?)?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(index)?.checked_add(stage)?.checked_add(upper)?.checked_add(self.semantic_peak)?
            .checked_add(super::SourceNativePostOriginalV1::receiving_demand_v1()?)?;
        self.original.debit_complete_representation_v1(complete)?;
        Ok(())
    }
}

impl<P> Drop for SourceCoordinatorWriterV1<P> {
    fn drop(&mut self) {
        if self.has_native_uncertainty_v1() || self.custody.is_active()
            || self.delete_scope_active || self.provisioning_scope_active || self.native_post_active || self.append_prepaid
            || !self.replacement_custody.is_idle()
        {
            // Do not dispose an uncertain selected native prefix or stage.
            std::process::abort();
        }
    }
}
