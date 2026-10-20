//! Retains reached label invoices on the actual State readback owner.
//!
//! This is a private adapter over the genuine same-F State loan. The lower
//! traversal supplies opaque reached shape DATA before growth; this owner
//! pays only the new highwater delta and retains arithmetic/payment refusal.
//! It cannot create a Native operation, choose a different purpose or waive a
//! single confinement predicate.

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelReadReachedDataV2;

pub(crate) struct GuestRootLabelReceivingV2<'stage, 'cut, 'original> {
    state: &'stage aos_sandbox::Journal,
    payer: LabelPayerV2<'stage, 'cut, 'original>,
}

enum LabelPayerV2<'stage, 'cut, 'original> {
    State(&'stage mut crate::state::encoding::StateEncodingLoanV1<'cut, 'original>),
    RootExport(&'stage mut aos_sandbox::StorageRootLaunchExportReceivingLoanV2<'cut, 'original>),
}

impl<'stage, 'cut, 'original> GuestRootLabelReceivingV2<'stage, 'cut, 'original> {
    pub(crate) fn state_v2(
        state: &'stage aos_sandbox::Journal,
        loan: &'stage mut crate::state::encoding::StateEncodingLoanV1<'cut, 'original>,
    ) -> Self {
        Self { state, payer: LabelPayerV2::State(loan) }
    }

    pub(crate) fn root_export_v2(
        state: &'stage aos_sandbox::Journal,
        loan: &'stage mut aos_sandbox::StorageRootLaunchExportReceivingLoanV2<'cut, 'original>,
    ) -> Self {
        Self { state, payer: LabelPayerV2::RootExport(loan) }
    }

    fn reserve_v2(&mut self, delta: ResourceVector) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        match &mut self.payer {
            LabelPayerV2::State(loan) => loan.reserve_inventory_readback_v1(self.state, delta),
            LabelPayerV2::RootExport(loan) => loan.reserve_guest_root_readback_delta_v2(self.state, delta),
        }
    }
}

#[derive(Default)]
pub(super) struct GuestRootLabelInvoiceOriginalV2 {
    reached: ResourceVector,
    demand: Option<Result<ResourceVector, AccountingError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
}

impl GuestRootLabelInvoiceOriginalV2 {
    pub(super) fn admit_v2(
        &mut self,
        shape: GuestRootLabelReadReachedDataV2,
        receiving: &mut GuestRootLabelReceivingV2<'_, '_, '_>,
    ) -> bool {
        if matches!(self.demand, Some(Err(_))) || matches!(self.payment, Some(Err(_))) {
            return false;
        }
        self.demand = Some((|| {
            let overflow = |dimension| AccountingError::ArithmeticOverflow { dimension };
            let shape = shape.receiving_footprint_v2().ok_or_else(|| overflow(D::MemoryBytes))?;
            let required = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(shape.memory_bytes).map_err(|_| overflow(D::MemoryBytes))?)
                .with(D::OpenFiles, u64::try_from(shape.open_files).map_err(|_| overflow(D::OpenFiles))?)
                .with(D::MetadataEntries, u64::try_from(shape.metadata_entries).map_err(|_| overflow(D::MetadataEntries))?);
            // The lower producer's peak depth and named count are monotone.
            // A backwards shape refuses instead of forgiving prior debt.
            required.checked_sub(self.reached)?;
            Ok(required)
        })());
        let Some(Ok(required)) = self.demand.as_ref().copied() else { return false; };
        let delta = match required.checked_sub(self.reached) {
            Ok(delta) => delta,
            Err(cause) => { self.demand = Some(Err(cause)); return false; }
        };
        if delta == ResourceVector::ZERO {
            return true;
        }
        self.payment = Some(receiving.reserve_v2(delta));
        if !matches!(self.payment, Some(Ok(()))) {
            return false;
        }
        self.reached = required;
        true
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}
