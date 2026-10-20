//! Preserves complete emitted bootstrap17 history without a stream or birth cut.

use super::*;
use crate::connection::settled17::HistoricalReversedByteBank17;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::protocol_snapshot::owned11::reader::HistoricalFrameReaderFacts;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string};
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use crate::transport::{DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames};
use serde_json::Value;
use std::mem::align_of;

impl SettledBootstrapHistory17<'_> {
    /// Appends the real boxed owner, both private-bank edges and every raw/DOM bank.
    ///
    /// # Errors
    /// Refuses changed bootstrap origin/cut, unavailable actual state or banks.
    pub(in crate::reference_packet::service) fn observe_settled17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        authenticate_settled_bootstrap_history(self.owner, self.actual_boot)?;
        let SettledBootstrap {
            reader: _,
            literals,
            launch_value,
            launch8,
            launch7,
            launch6,
            decoded: _,
            launch,
            boot_value,
            boot,
            startup: _,
        } = self.owner;
        if launch.is_some() {
            return Err(invalid());
        }
        observer.boxed_value(self.owner)?;
        let literals = literals.as_ref().ok_or_else(invalid)?;
        observer.shared_original(MetadataSharedKind::PrivateBootstrapBank, literals.as_ref())?;
        self.literals.observe_owned11_metadata(observer)?;
        // Reader and capsule own the very same actual Rc. The second full view
        // consumes its real metadata rows while retaining the first definition.
        observer.shared_original(MetadataSharedKind::PrivateBootstrapBank, literals.as_ref())?;
        self.literals.observe_owned11_metadata(observer)?;
        observer.observe(launch_value)?;
        observer.vector::<u8>(launch8.capacity())?;
        observer.vector::<u8>(launch7.capacity())?;
        observer.vector::<u8>(launch6.capacity())?;
        observer.observe(boot_value)?;
        observer.shared_original(
            MetadataSharedKind::NativeBoot,
            boot.as_ref().ok_or_else(invalid)?.as_ref(),
        )
    }
}

/// Identifies the checked private-channel bank and actual enclosing Boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentBootstrap17GroupIds {
    pub(crate) private_frames: usize,
    pub(crate) boot: usize,
}

/// Retains every one of the fifteen emitted fields as nonrenewing history.
pub(crate) struct HistoricalCurrentBootstrap17 {
    pub(crate) reader: HistoricalFrameReaderFacts,
    pub(crate) private_frames: DecodedCompactOriginalFrames,
    pub(crate) launch_value: Option<Value>,
    pub(crate) launch8: Vec<u8>,
    pub(crate) launch7: Vec<u8>,
    pub(crate) launch6: Vec<u8>,
    pub(crate) invocation: PacketNativeInvocationPurposeData,
    pub(crate) suffix: PacketRestoredSuffixReservationData,
    pub(crate) existing_rows: PacketRestoredSettledNativeExistingRowsData,
    pub(crate) capture: PacketRestoredSettledNativeCarrierData,
    pub(crate) launch_transferred: bool,
    pub(crate) boot_value: Option<Value>,
    pub(crate) prefix: [u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
    pub(crate) issued: bool,
    pub(crate) failed: bool,
    pub(crate) groups: CurrentBootstrap17GroupIds,
}

impl HistoricalCurrentBootstrap17 {
    /// Checks retained DOM/raw/fixed/private-frame agreement after construction.
    ///
    /// # Errors
    /// Refuses changed successful-source history; no private key becomes a grant.
    pub(crate) fn authenticate_correspondence_data(&self) -> Result<(), ProviderError> {
        use crate::transport::original_frames::FrameDirection;
        if self.reader.failed
            || self.reader.last_original_slot != Some(1)
            || !self.launch_transferred
            || !self.issued
            || self.failed
            || self.private_frames.frames().count() != 2
        {
            return Err(invalid());
        }
        let prefix = decode_original_native_settled_preamble_data(&self.prefix)?;
        if prefix.capture != self.capture
            || prefix.suffix.suffix_reservation != self.suffix
            || prefix.suffix.invocation.launch_bytes as usize != self.launch8.len()
            || blake3::hash(&self.launch8).as_bytes() != &prefix.suffix.invocation.launch_digest
        {
            return Err(invalid());
        }
        for (index, frame) in self.private_frames.frames().enumerate() {
            if frame.direction != FrameDirection::Incoming
                || !frame.complete
                || frame.transferred != frame.bytes.len()
                || frame.bytes.len() < 4
            {
                return Err(invalid());
            }
            let body = &frame.bytes[4..];
            if index == 0 {
                if body != self.launch8 {
                    return Err(invalid());
                }
                crate::protocol_snapshot::owned11::correspondence::json_value(
                    self.launch_value.as_ref().ok_or_else(invalid)?,
                    body,
                )?;
            } else {
                crate::protocol_snapshot::owned11::correspondence::json_value(
                    self.boot_value.as_ref().ok_or_else(invalid)?,
                    body,
                )?;
            }
        }
        // The nested raw7 is retained independently; it must be the exact
        // borrowed suffix of the original wrapper8, not a reconstructed launch.
        let mut wrapper = Fields::object(&self.launch8)?;
        if scalar_data::<PacketRestoredSettledNativeCarrierData>(
            wrapper.named("capture_reservation")?,
        )? != self.capture
            || scalar_data::<PacketRestoredSettledNativeExistingRowsData>(
                wrapper.named("existing_rows")?,
            )? != self.existing_rows
        {
            return Err(invalid());
        }
        if wrapper.named("schema_version")? != b"8" || wrapper.named("suffix")? != self.launch7 {
            return Err(invalid());
        }
        wrapper.finish()?;
        let mut nested = Fields::object(&self.launch7)?;
        let purpose_raw = nested.named("invocation")?;
        let mut purpose_sink = ExactOutput {
            expected: purpose_raw,
            position: 0,
        };
        write_original_native_invocation_purpose_data(&self.invocation, &mut purpose_sink)?;
        purpose_sink.finish()?;
        let launch5 = nested.named("launch")?;
        if nested.named("schema_version")? != b"7"
            || scalar_data::<PacketRestoredSuffixReservationData>(
                nested.named("suffix_reservation")?,
            )? != self.suffix
        {
            return Err(invalid());
        }
        nested.finish()?;
        let mut launch_sink = ExactOutput {
            expected: &self.launch6,
            position: 0,
        };
        write_original_native_invocation_launch_data(&self.invocation, launch5, &mut launch_sink)?;
        launch_sink.finish()
    }
}

/// Reads complete native emitted-order bootstrap fields on the caller's ledger.
///
/// # Errors
/// Refuses missing/unknown fields, incomplete compact leaves, exact-capacity or
/// shared-group disagreement, invalid fixed DATA or unavailable retained banks.
pub(crate) fn read_current_native17_bootstrap_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentBootstrap17>,
        CurrentBootstrap17GroupIds,
    ),
    ProviderError,
> {
    if ledger.row_aligned(MetadataRecordKind::Boxed, 1, align_of::<SettledBootstrap>())?
        != size_of::<SettledBootstrap>()
    {
        return Err(invalid());
    }
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        "source-private.native-current-bootstrap/17",
    )?;
    let reader = ledger.read::<HistoricalFrameReaderFacts>(fields.named("reader")?, build)?;
    let private = fields.named("private_frames")?;
    let (private_frames, private_group) = read_private_frames(private, ledger, build)?;
    let suspension = ledger.suspend_native17_targets_data()?;
    let repeated = read_private_frames(private, ledger, false);
    ledger.resume_native17_targets_data(suspension)?;
    let (_, reader_group) = repeated?;
    if private_group != reader_group {
        return Err(invalid());
    }
    let launch_value = ledger.read::<Option<Value>>(fields.named("launch_value")?, build)?;
    let launch8 = ledger.read::<HistoricalReversedByteBank17>(fields.named("launch8")?, build)?;
    let launch7 = ledger.read::<HistoricalReversedByteBank17>(fields.named("launch7")?, build)?;
    let launch6 = ledger.read::<HistoricalReversedByteBank17>(fields.named("launch6")?, build)?;
    let mut fixed = Fields::array(fields.named("typed_fixed")?)?;
    let invocation = PacketNativeInvocationPurposeData::read_settled17_data(next(&mut fixed)?)?;
    // These three deny-unknown-fields DATA types contain only scalar quantities,
    // fixed digests and nested fixed rows. They allocate no strings or DOM.
    let suffix: PacketRestoredSuffixReservationData = scalar_data(next(&mut fixed)?)?;
    let existing_rows: PacketRestoredSettledNativeExistingRowsData =
        scalar_data(next(&mut fixed)?)?;
    let capture: PacketRestoredSettledNativeCarrierData = scalar_data(next(&mut fixed)?)?;
    fixed.finish()?;
    suffix.requested_bytes_data()?;
    existing_rows.validate_data()?;
    capture.validate_data()?;
    let launch_transferred = ledger
        .read::<bool>(fields.named("launch_transferred")?, true)?
        .ok_or_else(invalid)?;
    let boot_value = ledger.read::<Option<Value>>(fields.named("boot_value")?, build)?;
    exact(fields.named("boot_role")?, "native-boot")?;
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<RefCell<super::super::boot::NativeAckBoot>>(),
    )? != size_of::<RefCell<super::super::boot::NativeAckBoot>>()
    {
        return Err(invalid());
    }
    let boot = ledger.shared_reference(
        MetadataSharedKind::NativeBoot,
        size_of::<RefCell<super::super::boot::NativeAckBoot>>(),
    )?;
    let prefix = ValidatedCompactBytes::validate(
        fields.named("prefix")?,
        ledger.limits.maximum_input_bytes,
        ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES,
    )?;
    if prefix.decoded_length() != ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES {
        return Err(invalid());
    }
    let mut prefix_bytes = [0; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES];
    prefix.copy_range(0, &mut prefix_bytes)?;
    decode_original_native_settled_preamble_data(&prefix_bytes)?;
    let issued = ledger
        .read::<bool>(fields.named("issued")?, true)?
        .ok_or_else(invalid)?;
    let failed = ledger
        .read::<bool>(fields.named("failed")?, true)?
        .ok_or_else(invalid)?;
    exact(
        fields.named("original_cut_role")?,
        "genuine-original-birth-cut-transferred-history-only",
    )?;
    fields.finish()?;
    let groups = CurrentBootstrap17GroupIds {
        private_frames: private_group,
        boot,
    };
    if !build {
        return Ok((None, groups));
    }
    Ok((
        Some(HistoricalCurrentBootstrap17 {
            reader: reader.ok_or_else(invalid)?,
            private_frames: private_frames.ok_or_else(invalid)?,
            launch_value: launch_value.ok_or_else(invalid)?,
            launch8: launch8.ok_or_else(invalid)?.0,
            launch7: launch7.ok_or_else(invalid)?.0,
            launch6: launch6.ok_or_else(invalid)?.0,
            invocation,
            suffix,
            existing_rows,
            capture,
            launch_transferred,
            boot_value: boot_value.ok_or_else(invalid)?,
            prefix: prefix_bytes,
            issued,
            failed,
            groups,
        }),
        groups,
    ))
}

fn read_private_frames(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<DecodedCompactOriginalFrames>, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = size_of::<RefCell<OriginalFrameReservation>>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<RefCell<OriginalFrameReservation>>(),
    )? != layout
    {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::PrivateBootstrapBank)?;
    let plan = ValidatedCompactOriginalFrames::validate(
        input,
        ledger.limits.maximum_input_bytes,
        ledger.maximum_literal_bytes,
    )?;
    let mut fields = Fields::array(input)?;
    for _ in 0..4 {
        next(&mut fields)?;
    }
    let bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let slots = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    if ledger.row_aligned(MetadataRecordKind::Vector, 1, align_of::<u8>())? != bytes
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            crate::transport::original_frames::original_frame_slot_layout(),
            crate::transport::original_frames::original_frame_slot_alignment_data(),
        )? != slots
    {
        return Err(invalid());
    }
    ledger.literal_bytes = ledger
        .literal_bytes
        .checked_add(plan.allocated_bytes())
        .ok_or_else(invalid)?;
    if ledger.literal_bytes > ledger.maximum_literal_bytes {
        return Err(invalid());
    }
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    plan.native17_target_data(ledger)?;
    Ok((
        if build {
            Some(plan.reconstruct()?)
        } else {
            None
        },
        group,
    ))
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn scalar_data<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, ProviderError> {
    serde_json::from_slice(input)
        .map_err(crucible_node_format::ContractError::from)
        .map_err(Into::into)
}

// Fixed DATA is compared with its retained canonical bytes without encoding a
// second body bank or allocating a generic JSON proof object.
struct ExactOutput<'a> {
    expected: &'a [u8],
    position: usize,
}

impl ExactOutput<'_> {
    fn finish(&self) -> Result<(), ProviderError> {
        if self.position != self.expected.len() {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Write for ExactOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("bootstrap17 comparison extent"))?;
        if self.expected.get(self.position..end) != Some(bytes) {
            return Err(std::io::Error::other(
                "bootstrap17 fixed/raw history differs",
            ));
        }
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[path = "settled17/logical17.rs"]
mod logical17;
pub(crate) use logical17::{
    BorrowedBootstrap17LineageData, borrow_current_bootstrap17_lineage_data,
};
