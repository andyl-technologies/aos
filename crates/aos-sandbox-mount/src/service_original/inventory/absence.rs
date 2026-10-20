//! Arms the selected Mount16 complete empty native observation before IO.

use super::*;
use aos_sandbox_broker::receiving::FixedServiceInventoryFdStoreEmptyOriginalV2;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::fixed_service_inventory_absence::FixedServiceInventoryAbsenceDataV2;
use crate::destination_slot::MountInventoryRootAbsenceOriginalV2;
use aos_sandbox_mount_native::MountInventoryJournalCurrentnessOriginalV2;

// Field7's one-byte tag and the one-byte length of this fixed96-byte payload.
const ABSENCE_WIRE_BYTES: u64 = FixedServiceInventoryAbsenceDataV2::BYTES_V2 as u64 + 2;

#[derive(Clone, Copy)]
enum First { Shape, Funding, JournalBefore, FdBefore, ClockBefore, RootBefore, RootAfter, JournalAfter, FdAfter, ClockAfter, Comparison, Encoding }

#[derive(Default)]
pub(super) struct MountNativeAbsenceOriginalV2 {
    entered: bool,
    shape: Option<Result<ResourceVector>>,
    journal_shape: Option<std::result::Result<ResourceVector, JournalError>>,
    funding: Option<std::result::Result<(), Closed>>,
    journal: MountInventoryJournalCurrentnessOriginalV2,
    journal_before: Option<std::result::Result<(), JournalError>>,
    journal_after: Option<std::result::Result<(), JournalError>>,
    fd_store: FixedServiceInventoryFdStoreEmptyOriginalV2,
    fd_before: Option<std::result::Result<(), Closed>>,
    clock_before: Option<std::result::Result<RawPairedClockSample, Closed>>,
    root_before: MountInventoryRootAbsenceOriginalV2,
    root_before_result: Option<Result<()>>,
    root_after: MountInventoryRootAbsenceOriginalV2,
    root_after_result: Option<Result<()>>,
    fd_after: Option<std::result::Result<(), Closed>>,
    clock_after: Option<std::result::Result<RawPairedClockSample, Closed>>,
    comparison: Option<Result<()>>,
    encoding: Option<std::result::Result<FixedServiceInventoryAbsenceDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
    first: Option<First>,
}

impl MountNativeAbsenceOriginalV2 {
    pub(super) fn before_once_v2(&mut self, loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        store: &DestinationSlotStoreV1, state: &Journal, opening: &MountStateCapturedJournalOpenV4) -> Result<()> {
        if self.entered { return Err(closed("Mount absence cannot reenter")); }
        self.entered = true;
        self.journal_shape = Some(opening.inventory_currentness_receiving_demand_v2());
        // Inline native buffers are already counted by the enclosing inventory
        // header. Both read descriptors/names and all four encoder planes are
        // additional to that header and the existing ordinary census invoice.
        self.shape = Some((|| {
            use aos_sandbox_core::ResourceDimension as D;
            let directory = MountInventoryRootAbsenceOriginalV2::receiving_demand_v2()?;
            let names = directory.get(D::MetadataEntries).checked_mul(2)
                .ok_or_else(|| closed("Mount absence namespace geometry overflow"))?;
            let files = directory.get(D::OpenFiles).checked_mul(2)
                .ok_or_else(|| closed("Mount absence descriptor geometry overflow"))?;
            let root = ResourceVector::ZERO.with(D::MemoryBytes, 4 * ABSENCE_WIRE_BYTES)
                .with(D::OutputBytes, ABSENCE_WIRE_BYTES).with(D::MetadataEntries, names).with(D::OpenFiles, files);
            let journal = self.journal_shape.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(|| closed("Mount native journal geometry refused"))?;
            root.checked_add(journal).map_err(|_| closed("Mount absence complete geometry overflow"))
        })());
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(First::Shape); return Err(closed("Mount absence geometry refused"));
        };
        self.funding = Some(loan.require_additional_representation_v4(*shape));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding); return Err(closed("Mount absence receiving refused"));
        }
        self.journal_before = Some(opening.observe_inventory_currentness_before_v2(state, &mut self.journal));
        if !matches!(self.journal_before, Some(Ok(()))) {
            self.first = Some(First::JournalBefore); return Err(closed("Mount state native before refused"));
        }
        self.fd_before = Some(loan.observe_inventory_fd_store_empty_before_v2(&mut self.fd_store));
        if !matches!(self.fd_before, Some(Ok(()))) {
            self.first = Some(First::FdBefore); return Err(closed("Mount descriptor-store before refused"));
        }
        self.clock_before = Some(loan.observe_inventory_population_clock_before_v2(&mut self.fd_store));
        if !matches!(self.clock_before, Some(Ok(_))) {
            self.first = Some(First::ClockBefore); return Err(closed("Mount population clock before refused"));
        }
        self.root_before_result = Some(self.root_before.observe_once_v2(store));
        if !matches!(self.root_before_result, Some(Ok(()))) {
            self.first = Some(First::RootBefore); return Err(closed("Mount whole-root before refused"));
        }
        Ok(())
    }

    pub(super) fn finish_after_once_v2(&mut self, loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        store: &DestinationSlotStoreV1, state: &Journal, opening: &MountStateCapturedJournalOpenV4,
        request: [u8; 16]) -> Result<()> {
        if !matches!(self.funding, Some(Ok(()))) { return Err(closed("Mount absence was not prepaid")); }
        // Every independent after is attempted despite an earlier body/native
        // refusal. No new healthy-currentness check or debit gates these posts.
        self.root_after_result = Some(self.root_after.observe_once_v2(store));
        if !matches!(self.root_after_result, Some(Ok(()))) { self.first.get_or_insert(First::RootAfter); }
        self.journal_after = Some(opening.observe_inventory_currentness_after_owed_v2(state, &mut self.journal));
        if !matches!(self.journal_after, Some(Ok(()))) { self.first.get_or_insert(First::JournalAfter); }
        self.fd_after = Some(loan.observe_inventory_fd_store_empty_after_owed_v2(&mut self.fd_store));
        if !matches!(self.fd_after, Some(Ok(()))) { self.first.get_or_insert(First::FdAfter); }
        self.clock_after = Some(loan.observe_inventory_population_clock_after_owed_v2(&mut self.fd_store));
        if !matches!(self.clock_after, Some(Ok(_))) { self.first.get_or_insert(First::ClockAfter); }
        self.comparison = Some((|| {
            state.ensure_healthy()?;
            self.journal.require_complete_v2()?;
            if state.all_records().next().is_some() || !store.inventory_custody_empty_v2()
                || self.root_before.root_identity_v2().is_none()
                || self.root_before.root_identity_v2() != self.root_after.root_identity_v2() {
                return Err(closed("Mount retains durable/native resource or changed root"));
            }
            let (before, after) = self.fd_store.population_interval_data_v2()
                .ok_or_else(|| closed("Mount population interval did not complete"))?;
            if before.host_boot_id() != store.retained_kernel_boot_id_v4()
                || after.host_boot_id() != store.retained_kernel_boot_id_v4() {
                return Err(closed("Mount population changed original boot"));
            }
            Ok(())
        })());
        if !matches!(self.comparison, Some(Ok(()))) { self.first.get_or_insert(First::Comparison); }
        if self.first.is_some() { return Err(closed("Mount absence conjunction retained refusal")); }
        let (before, after) = self.fd_store.population_interval_data_v2()
            .ok_or_else(|| closed("Mount population interval absent"))?;
        let invocation = self.fd_store.recipient_invocation_data_v2()
            .ok_or_else(|| closed("Mount actual recipient absent"))?;
        let root = self.root_before.root_identity_v2().ok_or_else(|| closed("Mount actual root absent"))?;
        self.encoding = Some(FixedServiceInventoryAbsenceDataV2::from_mount_native_data_v2(
            request, store.retained_kernel_boot_id_v4(), invocation,
            before.boottime_nanoseconds(), after.boottime_nanoseconds(), root));
        if !matches!(self.encoding, Some(Ok(_))) {
            self.first.get_or_insert(First::Encoding); return Err(closed("Mount absence companion refused"));
        }
        Ok(())
    }

    pub(super) fn encoded_v2(&self) -> Option<[u8; 96]> {
        if self.first.is_some() { return None; }
        Some(self.encoding.as_ref()?.as_ref().ok()?.encode_v2())
    }

    pub(super) fn original_failure_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
            || matches!(self.first, Some(First::FdBefore | First::FdAfter))
                && self.fd_store.original_failure_selected_v2()
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Shape => self.journal_shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.shape.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::JournalBefore | First::JournalAfter => self.journal.failure_v2(),
            First::FdBefore | First::FdAfter | First::ClockBefore | First::ClockAfter => self.fd_store.failure_v2(),
            First::RootBefore => self.root_before.failure_v2(),
            First::RootAfter => self.root_after.failure_v2(),
            First::Comparison => self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Encoding => self.encoding.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}
