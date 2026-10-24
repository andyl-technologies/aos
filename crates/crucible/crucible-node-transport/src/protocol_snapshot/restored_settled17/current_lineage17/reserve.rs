//! Borrows the actual current action while checking every retained reserve owner.

use super::super::{
    current_actions::{CurrentInputAttempt17, HistoricalRestoredAction17},
    current_capture17_borrowed::{BorrowedCurrentCapture17, read_current_capture17_borrowed_data},
    current_fixed::read_ledger17,
    current_purpose::CurrentPurpose17,
    current_reserve::CurrentSealedReserve17,
};
use super::*;
use crate::{
    protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger,
    reference_packet::service::native_startup::*, retained_metadata::records::MetadataRecordKind,
};
use std::rc::Rc;

/// Records the genuine selected union occurrence and its immutable full fields.
pub(crate) struct BorrowedCurrentAction17<'body, 'rows> {
    pub(crate) group: usize,
    pub(crate) index: usize,
    pub(crate) ordinal: u64,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) definition: &'body [u8],
    pub(crate) selected: &'body [u8],
    pub(crate) capture: Option<BorrowedCurrentCapture17<'body, 'rows>>,
    pub(crate) upload: Option<
        super::super::current_capture17_upload_ingress::BorrowedCurrentCaptureUploadIngress17<
            'body,
            'rows,
        >,
    >,
    pub(crate) decoded: bool,
    pub(crate) failed: bool,
}

/// Retains all logical spend facts and the full current immutable action loan.
pub(crate) struct BorrowedReserveLineage17<'body, 'rows> {
    pub(crate) creator: u32,
    pub(crate) carrier: PacketRestoredSettledNativeCarrierData,
    pub(crate) existing_rows: PacketRestoredSettledNativeExistingRowsData,
    pub(crate) ledger: HistoricalRestoredSuffixLedger,
    pub(crate) attempts: &'body [u8],
    pub(crate) attempt_count: usize,
    pub(crate) current: Option<BorrowedCurrentAction17<'body, 'rows>>,
    pub(crate) failed: bool,
}

fn current<'body, 'rows>(
    input: &'body [u8],
    index: usize,
    group: usize,
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentAction17<'body, 'rows>, ProviderError> {
    let mut f = Fields::object(input)?;
    let ordinal = scalar::<u64>(f.named("ordinal")?, ledger)?;
    let original = loan(f.named("original")?, ledger)?;
    let selected = f.named("selected")?;
    let decoded = scalar::<bool>(f.named("decoded")?, ledger)?;
    let failed = scalar::<bool>(f.named("failed")?, ledger)?;
    f.finish()?;
    let mut capture = None;
    let mut upload = None;
    if selected != b"null" {
        let mut selected_fields = Fields::object(selected)?;
        let family = plain_string(selected_fields.named("family")?)?;
        let data = selected_fields.named("data")?;
        selected_fields.finish()?;
        match family {
            "capture" => capture = Some(read_current_capture17_borrowed_data(data, ledger)?),
            "capture_upload17" => upload = Some(super::super::current_capture17_upload_ingress::read_current_capture17_upload_ingress_data(data, ledger)?),
            "input_reactive" => discard::<CurrentInputAttempt17>(data, ledger)?,
            _ => return Err(invalid()),
        }
    }
    if ordinal
        != u64::try_from(index)
            .map_err(|_| invalid())?
            .checked_add(1)
            .ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    Ok(BorrowedCurrentAction17 {
        group,
        index,
        ordinal,
        original,
        definition: input,
        selected,
        capture,
        upload,
        decoded,
        failed,
    })
}

pub(super) fn read<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
    expected_boot_group: usize,
) -> Result<BorrowedReserveLineage17<'body, 'rows>, ProviderError> {
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-restored-settled-capture-reserve/17",
    )?;
    let creator = scalar::<u32>(f.named("creator")?, ledger)?;
    role(
        f.named("thread_role")?,
        "same-original-native-thread-history-only",
    )?;
    role(f.named("boot_role")?, "native-boot")?;
    let layout = NativeAckBoot::current_boot_shared_layout17_data();
    shared_row17(ledger, layout)?;
    let _ = ledger.shared_native_boot_parent_reference(expected_boot_group, layout.0)?;
    let carrier = scalar::<CurrentDto17<PacketRestoredSettledNativeCarrierData>>(
        f.named("carrier")?,
        ledger,
    )?
    .0;
    carrier.validate_data()?;
    let existing_rows = scalar::<CurrentDto17<PacketRestoredSettledNativeExistingRowsData>>(
        f.named("existing_rows")?,
        ledger,
    )?
    .0;
    existing_rows.validate_data()?;
    discard::<CurrentPurpose17>(f.named("purpose")?, ledger)?;
    discard::<PacketNativeStartupAllocationRow>(f.named("final_native_birth")?, ledger)?;
    discard::<Option<PacketNativeStartupAllocationRow>>(f.named("final_restore_prepare")?, ledger)?;
    discard::<Option<CurrentSealedReserve17>>(f.named("sealed")?, ledger)?;
    let budget = read_ledger17(f.named("ledger")?, ledger, true)?.ok_or_else(invalid)?;
    let attempts = f.named("attempts")?;
    let current_raw = f.named("current")?;
    let failed_raw = f.named("failed")?;
    f.finish()?;
    // Scalar slots have no source backing; read them before the vector only to
    // select the exact occurrence. Every heap-bearing field keeps source order.
    let selected_index = scalar::<Option<usize>>(current_raw, ledger)?;
    let failed = scalar::<bool>(failed_raw, ledger)?;
    let capacity = ledger.row_aligned(
        MetadataRecordKind::Vector,
        size_of::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>(),
        align_of::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>(),
    )?;
    if capacity
        .checked_mul(size_of::<Rc<RefCell<NativeRestoredSettledActionAttempt>>>())
        .is_none_or(|bytes| bytes > ledger.limits.maximum_owned_backing_bytes)
    {
        return Err(invalid());
    }
    let mut current_value = None;
    let mut attempt_count = 0usize;
    let mut attempts_fields = Fields::array(attempts)?;
    while let Some(raw) = attempts_fields.next_value()? {
        let index = attempt_count;
        attempt_count = attempt_count.checked_add(1).ok_or_else(invalid)?;
        if attempt_count > capacity
            || u64::try_from(attempt_count).map_err(|_| invalid())?
                > carrier.maximum_originals.get()
        {
            return Err(invalid());
        }
        let start = ledger.rows.encoded_position();
        let layout = (
            size_of::<RefCell<NativeRestoredSettledActionAttempt>>(),
            align_of::<RefCell<NativeRestoredSettledActionAttempt>>(),
        );
        shared_row17(ledger, layout)?;
        let group = ledger.shared_begin(MetadataSharedKind::NativeRestoredSettledActionAttempt)?;
        if Some(index) == selected_index {
            current_value = Some(current(raw, index, group, ledger)?);
        } else {
            discard::<HistoricalRestoredAction17>(raw, ledger)?;
            let mut wrapper = Fields::object(raw)?;
            if unsigned(wrapper.named("ordinal")?)?
                != u64::try_from(attempt_count).map_err(|_| invalid())?
            {
                return Err(invalid());
            }
        }
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, layout.0, raw, rows)?;
    }
    attempts_fields.finish()?;
    if creator == 0
        || selected_index.is_some() != current_value.is_some()
        || budget.originals_data() < u64::try_from(attempt_count).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(BorrowedReserveLineage17 {
        creator,
        carrier,
        existing_rows,
        ledger: budget,
        attempts,
        attempt_count,
        current: current_value,
        failed,
    })
}
