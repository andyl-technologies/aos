//! Retains the real spent native17 reserve and its complete raw-first union.

use super::{
    current_actions::HistoricalRestoredAction17,
    current_contracts::{CurrentDto17, CurrentField17},
    current_fixed::*,
    current_purpose::CurrentPurpose17,
    current_shared::{CurrentShared17, read_shared_vector17, shared_row17},
};
use crate::{
    ProviderError,
    protocol_snapshot::{
        owned11::typed::{Fields, HistoricalType, Ledger, invalid},
        restored_suffix_history::HistoricalRestoredSuffixLedger,
    },
    reference_packet::service::{ack_emitter::NativeAckBoot, native_startup::*},
    retained_metadata::aliases::MetadataSharedKind,
};
use std::{
    cell::RefCell,
    mem::{align_of, size_of},
    rc::Rc,
};

/// Preserves scalar sealed construction facts without creating a reservation.
#[derive(Clone, Copy)]
pub(crate) struct CurrentSealedReserve17 {
    pub(crate) carrier: PacketRestoredSettledNativeCarrierData,
    pub(crate) retained: usize,
    pub(crate) transient: usize,
    pub(crate) scratch: usize,
    pub(crate) frame_bytes: usize,
    pub(crate) metadata_rows: [usize; 2],
    pub(crate) requested: usize,
    pub(crate) existing_rows: PacketRestoredSettledNativeExistingRowsData,
}

pub(crate) struct CurrentReserve17 {
    pub(crate) creator: u32,
    pub(crate) boot_group: usize,
    pub(crate) carrier: PacketRestoredSettledNativeCarrierData,
    pub(crate) existing_rows: PacketRestoredSettledNativeExistingRowsData,
    pub(crate) purpose: CurrentPurpose17,
    pub(crate) final_native_birth: PacketNativeStartupAllocationRow,
    pub(crate) final_restore_prepare: Option<PacketNativeStartupAllocationRow>,
    pub(crate) sealed: Option<CurrentSealedReserve17>,
    pub(crate) ledger: HistoricalRestoredSuffixLedger,
    pub(crate) attempts: Vec<CurrentShared17<HistoricalRestoredAction17>>,
    pub(crate) current: Option<usize>,
    pub(crate) failed: bool,
}
impl CurrentReserve17 {
    /// Borrows the exact in-progress enclosing Boot group, never a decoded ID.
    pub(crate) fn read_with_native_parent_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        expected_boot_group: usize,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-restored-settled-capture-reserve/17",
        )?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        role17(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        role17(fields.named("boot_role")?, "native-boot")?;
        let layout = NativeAckBoot::current_boot_shared_layout17_data();
        shared_row17(ledger, layout)?;
        let boot_group =
            ledger.shared_native_boot_parent_reference(expected_boot_group, layout.0)?;
        let carrier =
            <CurrentDto17<PacketRestoredSettledNativeCarrierData> as CurrentField17>::read(
                fields.named("carrier")?,
                ledger,
                true,
            )?
            .ok_or_else(invalid)?;
        carrier.validate_data()?;
        let existing_rows =
            <CurrentDto17<PacketRestoredSettledNativeExistingRowsData> as CurrentField17>::read(
                fields.named("existing_rows")?,
                ledger,
                true,
            )?
            .ok_or_else(invalid)?;
        existing_rows.validate_data()?;
        let purpose = ledger.read::<CurrentPurpose17>(fields.named("purpose")?, build)?;
        let final_native_birth = ledger
            .read::<PacketNativeStartupAllocationRow>(fields.named("final_native_birth")?, build)?;
        let final_restore_prepare = ledger.read::<Option<PacketNativeStartupAllocationRow>>(
            fields.named("final_restore_prepare")?,
            build,
        )?;
        let raw = fields.named("sealed")?;
        let sealed = ledger.read::<Option<CurrentSealedReserve17>>(raw, build)?;
        let budget = read_ledger17(fields.named("ledger")?, ledger, true)?.ok_or_else(invalid)?;
        budget.validate_data()?;
        let attempts = read_shared_vector17::<HistoricalRestoredAction17>(
            fields.named("attempts")?,
            ledger,
            build,
            MetadataSharedKind::NativeRestoredSettledActionAttempt,
            (
                size_of::<RefCell<NativeRestoredSettledActionAttempt>>(),
                align_of::<RefCell<NativeRestoredSettledActionAttempt>>(),
            ),
            (
                size_of::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>(),
                align_of::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>(),
            ),
            None,
        )?;
        let current = ledger.read::<Option<usize>>(fields.named("current")?, build)?;
        let failed = ledger.read::<bool>(fields.named("failed")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            boot_group,
            carrier,
            existing_rows,
            purpose: purpose.ok_or_else(invalid)?,
            final_native_birth: final_native_birth.ok_or_else(invalid)?,
            final_restore_prepare: final_restore_prepare.ok_or_else(invalid)?,
            sealed: sealed.ok_or_else(invalid)?,
            ledger: budget,
            attempts: attempts.ok_or_else(invalid)?,
            current: current.ok_or_else(invalid)?,
            failed: failed.ok_or_else(invalid)?,
        }))
    }

    /// Checks structural spend history without deciding current Capture eligibility.
    pub(crate) fn authenticate_data(&self) -> Result<(), ProviderError> {
        self.carrier.validate_data()?;
        self.existing_rows.validate_data()?;
        self.ledger.validate_data()?;
        if self.creator == 0
            || self.attempts.len()
                > usize::try_from(self.carrier.maximum_originals.get()).map_err(|_| invalid())?
            || self
                .current
                .is_some_and(|index| index >= self.attempts.len())
            || self.ledger.originals_data()
                < u64::try_from(self.attempts.len()).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            if attempt.payload.ordinal
                != u64::try_from(index)
                    .map_err(|_| invalid())?
                    .checked_add(1)
                    .ok_or_else(invalid)?
            {
                return Err(invalid());
            }
        }
        if let Some(sealed) = &self.sealed
            && (sealed.carrier != self.carrier
                || sealed.existing_rows != self.existing_rows
                || sealed
                    .retained
                    .checked_add(sealed.transient)
                    .and_then(|n| n.checked_add(sealed.scratch))
                    != Some(sealed.requested)
                || sealed.frame_bytes == 0
                || sealed.metadata_rows.contains(&0))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl HistoricalType for CurrentSealedReserve17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let carrier =
            <CurrentDto17<PacketRestoredSettledNativeCarrierData> as CurrentField17>::read(
                fields.named("carrier")?,
                ledger,
                build,
            )?;
        let retained = ledger.read::<usize>(fields.named("retained")?, build)?;
        let transient = ledger.read::<usize>(fields.named("transient")?, build)?;
        let scratch = ledger.read::<usize>(fields.named("scratch")?, build)?;
        let frame_bytes = ledger.read::<usize>(fields.named("frame_bytes")?, build)?;
        let metadata_rows = fixed_usizes17::<2>(fields.named("metadata_rows")?, ledger, build)?;
        let requested = ledger.read::<usize>(fields.named("requested")?, build)?;
        let existing_rows =
            <CurrentDto17<PacketRestoredSettledNativeExistingRowsData> as CurrentField17>::read(
                fields.named("existing_rows")?,
                ledger,
                build,
            )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            carrier: carrier.ok_or_else(invalid)?,
            retained: retained.ok_or_else(invalid)?,
            transient: transient.ok_or_else(invalid)?,
            scratch: scratch.ok_or_else(invalid)?,
            frame_bytes: frame_bytes.ok_or_else(invalid)?,
            metadata_rows: metadata_rows.ok_or_else(invalid)?,
            requested: requested.ok_or_else(invalid)?,
            existing_rows: existing_rows.ok_or_else(invalid)?,
        }))
    }
}
