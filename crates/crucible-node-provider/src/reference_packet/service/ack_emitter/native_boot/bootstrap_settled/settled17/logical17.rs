//! Checks complete bootstrap lineage without reconstructing its parser heap.

use super::*;
use crate::connection::native17_borrowed_bytes::{
    Bytes17, ExactBytes17, Frames17, boolean, canonical_to_writer, field, quantity,
};
use std::io::Write;

/// Borrows signed bootstrap evidence and keeps every actual issued/failure fact.
pub(crate) struct BorrowedBootstrap17LineageData<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) invocation: PacketNativeInvocationPurposeData,
    pub(crate) suffix: PacketRestoredSuffixReservationData,
    pub(crate) existing_rows: PacketRestoredSettledNativeExistingRowsData,
    pub(crate) capture: PacketRestoredSettledNativeCarrierData,
    pub(crate) prefix: [u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
    pub(crate) launch_digest: [u8; 32],
    pub(crate) launch_bytes: usize,
    pub(crate) issued: bool,
    pub(crate) failed: bool,
    pub(crate) launch_transferred: bool,
}

/// Compares fixed purpose, all raw launch wrappers, DOM views and private frames.
///
/// # Errors
/// Refuses unfinished bootstrap, changed fixed/prefix fields, any raw/DOM or
/// literal mismatch, or invalid recorded channel completion. This cannot attest
/// current EOF; the genuine Source guard separately checks that live socket.
pub(crate) fn borrow_current_bootstrap17_lineage_data(
    input: &[u8],
) -> Result<BorrowedBootstrap17LineageData<'_>, ProviderError> {
    let issued = boolean(field(input, "issued")?)?;
    let failed = boolean(field(input, "failed")?)?;
    let launch_transferred = boolean(field(input, "launch_transferred")?)?;
    let reader = field(input, "reader")?;
    if !issued
        || failed
        || !launch_transferred
        || boolean(field(reader, "failed")?)?
        || quantity(field(reader, "last_original_slot")?)? != 1
    {
        return Err(invalid());
    }
    let (launch8, _) = Bytes17::bank(field(input, "launch8")?, true)?;
    let (launch7, _) = Bytes17::bank(field(input, "launch7")?, true)?;
    let (launch6, _) = Bytes17::bank(field(input, "launch6")?, true)?;
    let launch_value = field(input, "launch_value")?;
    let boot_value = field(input, "boot_value")?;
    if launch_value == b"null" || boot_value == b"null" {
        return Err(invalid());
    }
    launch8.canonical(launch_value)?;
    let private_frames = Frames17::read(field(input, "private_frames")?)?;
    if private_frames.count()? != 2 || private_frames.incoming != 2 || private_frames.outgoing != 0
    {
        return Err(invalid());
    }
    private_frames.require_complete()?;
    let first = private_frames.frame(0)?;
    let second = private_frames.frame(1)?;
    if !first.incoming || !second.incoming {
        return Err(invalid());
    }
    first
        .bytes
        .range(4, first.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
        .equal(launch8)?;
    second
        .bytes
        .range(4, second.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
        .canonical(boot_value)?;

    let mut fixed = Fields::array(field(input, "typed_fixed")?)?;
    let invocation = PacketNativeInvocationPurposeData::read_settled17_data(next(&mut fixed)?)?;
    let suffix: PacketRestoredSuffixReservationData = scalar_data(next(&mut fixed)?)?;
    let existing_rows: PacketRestoredSettledNativeExistingRowsData =
        scalar_data(next(&mut fixed)?)?;
    let capture: PacketRestoredSettledNativeCarrierData = scalar_data(next(&mut fixed)?)?;
    fixed.finish()?;
    let raw_prefix = Bytes17::compact(field(input, "prefix")?)?;
    let mut prefix = [0; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES];
    if raw_prefix.len() != prefix.len() {
        return Err(invalid());
    }
    raw_prefix.copy(0, &mut prefix)?;
    let decoded_prefix = decode_original_native_settled_preamble_data(&prefix)?;
    let launch_digest = launch8.hash()?;
    if decoded_prefix.capture != capture
        || decoded_prefix.suffix.suffix_reservation != suffix
        || decoded_prefix.suffix.invocation.launch_bytes as usize != launch8.len()
        || decoded_prefix.suffix.invocation.launch_digest != launch_digest
        || scalar_data::<PacketRestoredSettledNativeCarrierData>(field(
            launch_value,
            "capture_reservation",
        )?)? != capture
        || scalar_data::<PacketRestoredSettledNativeExistingRowsData>(field(
            launch_value,
            "existing_rows",
        )?)? != existing_rows
        || field(launch_value, "schema_version")? != b"8"
    {
        return Err(invalid());
    }
    let nested = field(launch_value, "suffix")?;
    launch7.canonical(nested)?;
    if field(nested, "schema_version")? != b"7"
        || scalar_data::<PacketRestoredSuffixReservationData>(field(nested, "suffix_reservation")?)?
            != suffix
    {
        return Err(invalid());
    }
    let mut purpose_sink = ExactBytes17::new(Bytes17::Slice(field(nested, "invocation")?))?;
    write_original_native_invocation_purpose_data(&invocation, &mut purpose_sink)?;
    purpose_sink.finish()?;
    // The authoritative launch writer preserves canonical launch5 verbatim.
    // Stream that same wrapper while canonicalizing its borrowed DOM view;
    // no full raw launch bank is reconstructed solely for this comparison.
    let mut launch_sink = ExactBytes17::new(launch6)?;
    launch_sink.write_all(b"{\"invocation\":")?;
    write_original_native_invocation_purpose_data(&invocation, &mut launch_sink)?;
    launch_sink.write_all(b",\"launch\":")?;
    canonical_to_writer(field(nested, "launch")?, &mut launch_sink)?;
    launch_sink.write_all(b",\"schema_version\":6}")?;
    launch_sink.finish()?;
    Ok(BorrowedBootstrap17LineageData {
        encoded: input,
        invocation,
        suffix,
        existing_rows,
        capture,
        prefix,
        launch_digest,
        launch_bytes: launch8.len(),
        issued,
        failed,
        launch_transferred,
    })
}
