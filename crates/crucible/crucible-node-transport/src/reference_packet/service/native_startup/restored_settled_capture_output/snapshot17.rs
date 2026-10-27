//! Streams the closed native17 outer Snapshot into its actual once output slot.
//!
//! Actual completed Control and Before banks supply every embedded byte,
//! full reference and capacity. Counting, stable digest and writing use one
//! defining shape. This is inert output construction: the caller must admit
//! all prospective storage and hold its real Source/native action separately.

use super::*;
use crate::bodies::CaptureArguments;
use crate::envelope::{Envelope, MessageKind, Method};
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::reference_packet::service::{
    native_startup::PacketNativeStartupAllocationRow,
    restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE,
};
use crucible_node_format::{HashRef, Id, Phase, Position, U64};
use serde_json::{Map, Value};
use std::{io, mem::size_of};

const SCHEMA: &[u8] = b"source-owned.packet-native-continuation/17";
const BEFORE_TAG: &[u8] = b"source-private.native-before-protocol/17";
// Only these closed DTO leaves use U64's original formatter. Actual Envelope
// body/extensions already own encoded Value strings; Before uses stack chunks.
const CLOSED_LEAF_FORMATTER_BYTES: usize = 20;
const REFERENCE_BACKING_BYTES: usize =
    "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();

/// Keeps complete output correspondence and prospective storage as inert DATA.
pub(crate) struct NativeCapture17SnapshotStorageData {
    encoded: usize,
    digest: [u8; 32],
    row: PacketNativeStartupAllocationRow,
}

impl NativeCapture17SnapshotStorageData {
    /// Returns independently admitted requested output/formatter/scratch axes.
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }

    /// Returns the exact requested byte bank, without charging existing excess.
    pub(crate) fn encoded_bytes_data(&self) -> usize {
        self.encoded
    }
}

struct SnapshotShape17<'a> {
    capture: &'a CaptureArguments,
    original: &'a Envelope,
    control_reference: &'a ContentRef,
    control: &'a [u8],
    before_reference: &'a ContentRef,
    before: &'a [u8],
    before_capacity: usize,
}

// These leaf fields follow the strict native17 reference grammar. The public
// HashRef DTO's declaration order differs; serializing it directly would emit
// a snapshot whose own defining reader refuses the embedded references.
#[derive(serde::Serialize)]
struct SnapshotReference17<'a> {
    hash: SnapshotHash17<'a>,
    length: &'a U64,
    media_type: &'a str,
}

#[derive(serde::Serialize)]
struct SnapshotHash17<'a> {
    algorithm: &'a str,
    digest: &'a str,
    domain: &'a str,
}

impl<'a> SnapshotReference17<'a> {
    fn new(reference: &'a ContentRef) -> Self {
        Self {
            hash: SnapshotHash17 {
                algorithm: &reference.hash.algorithm,
                digest: &reference.hash.digest,
                domain: &reference.hash.domain,
            },
            length: &reference.length,
            media_type: &reference.media_type,
        }
    }
}

impl NativeRestoredSettledCaptureOutputs {
    /// Quotes the closed outer from these actual completed Control/Before banks.
    ///
    /// The caller prepays the fixed counter and closed-leaf formatter phase
    /// before this count. This DATA does not reserve or debit a bank. Existing
    /// output capacity above the exact requested bank remains independently
    /// retained/funded; the quote never converts that excess into action credit.
    ///
    /// # Errors
    /// Refuses missing/failed source banks, changed full references, unrelated
    /// Capture arguments/original, overflow, an output ceiling or short row.
    pub(crate) fn quote_snapshot17_data(
        &self,
        capture: &CaptureArguments,
        original: &Envelope,
        maximum_requested: usize,
    ) -> Result<NativeCapture17SnapshotStorageData, ProviderError> {
        self.ensure_usable()?;
        let control = &self.banks[NativeRestoredSettledCaptureOutput::Control.index()];
        let before = &self.banks[NativeRestoredSettledCaptureOutput::Before.index()];
        let shape = shape_data(capture, original, control, before)?;
        quote_shape_data(
            &shape,
            self.limits[NativeRestoredSettledCaptureOutput::Snapshot.index()],
            maximum_requested,
        )
    }

    /// Writes that same closed outer into the retained Snapshot slot once.
    ///
    /// The bank must already be independently reserved and admitted; this method
    /// never grows it. It marks the actual owner/slot before any fallible field
    /// check or requote and retains partial bytes through every refusal.
    ///
    /// # Errors
    /// Refuses another quote/shape, prior output, absent source banks, a short
    /// preallocated bank, a changed count/digest or encoding/fullref failure.
    pub(crate) fn write_snapshot17_data(
        &mut self,
        capture: &CaptureArguments,
        original: &Envelope,
        storage: &NativeCapture17SnapshotStorageData,
    ) -> Result<(), ProviderError> {
        self.ensure_usable()?;
        self.failed = true;
        let [snapshot, control, before, _, _] = &mut self.banks;
        if std::mem::replace(&mut snapshot.attempted, true)
            || !snapshot.bytes.is_empty()
            || snapshot.reference.is_some()
        {
            return Err(refused());
        }
        let shape = shape_data(capture, original, control, before)?;
        let actual = quote_shape_data(&shape, self.limits[0], usize::MAX)?;
        if actual.encoded != storage.encoded
            || actual.digest != storage.digest
            || actual.row != storage.row
            || snapshot.bytes.capacity() < storage.encoded
        {
            return Err(refused());
        }
        let mut writer = Bounded {
            output: &mut snapshot.bytes,
            maximum: storage.encoded,
        };
        write_shape_data(&mut writer, &shape)?;
        if snapshot.bytes.len() != storage.encoded
            || blake3::hash(&snapshot.bytes).as_bytes() != &storage.digest
        {
            return Err(refused());
        }
        snapshot.reference = Some(canonical::content_ref(&snapshot.bytes, "application/json")?);
        self.failed = false;
        Ok(())
    }
}

fn shape_data<'a>(
    capture: &'a CaptureArguments,
    original: &'a Envelope,
    control: &'a Output,
    before: &'a Output,
) -> Result<SnapshotShape17<'a>, ProviderError> {
    if !control.attempted
        || !before.attempted
        || before.bytes.len() > before.bytes.capacity()
        || control.bytes.first() != Some(&b'{')
        || control.bytes.last() != Some(&b'}')
        || original.message != MessageKind::Request
        || original.method != Method::Begin
        || original.request_id.0.is_none()
        || original.operation_id.0.is_none()
        || original.capture_owner_id.0.is_none()
        || original.execution_owner_id.0.is_some()
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_SETTLED_CAPTURE_FEATURE)
        || original.body.get("kind").and_then(Value::as_str) != Some("capture")
    {
        return Err(refused());
    }
    authenticate_arguments_data(capture, original.body.get("arguments").ok_or_else(refused)?)?;
    let control_reference = control.reference.as_ref().ok_or_else(refused)?;
    let before_reference = before.reference.as_ref().ok_or_else(refused)?;
    authenticate_reference_data(control_reference, &control.bytes)?;
    authenticate_reference_data(before_reference, &before.bytes)?;
    Ok(SnapshotShape17 {
        capture,
        original,
        control_reference,
        control: &control.bytes,
        before_reference,
        before: &before.bytes,
        before_capacity: before.bytes.capacity(),
    })
}

fn authenticate_reference_data(reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
    let ContentRef {
        hash,
        length,
        media_type,
    } = reference;
    let HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    if algorithm != "blake3-256"
        || media_type != "application/json"
        || domain != "cnp.blob.v1"
        || usize::try_from(length.get()).ok() != Some(bytes.len())
    {
        return Err(refused());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&reference.length.get().to_be_bytes());
    hash.update(bytes);
    if hash.finalize().to_hex().as_str() != digest.as_str() {
        return Err(refused());
    }
    Ok(())
}

fn authenticate_arguments_data(
    capture: &CaptureArguments,
    value: &Value,
) -> Result<(), ProviderError> {
    let CaptureArguments {
        capture_id,
        participant_ids,
        cut_id,
        cut,
        event_ordinal,
        ordering_profile,
        preservation_contract,
    } = capture;
    let fields = value.as_object().ok_or_else(refused)?;
    let participants = fields
        .get("participant_ids")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if fields.len() != 7
        || fields.get("capture_id").and_then(Value::as_str) != Some(capture_id.as_str())
        || participants.len() != participant_ids.len()
        || participants
            .iter()
            .zip(participant_ids)
            .any(|(value, expected)| value.as_str() != Some(expected.as_str()))
        || fields.get("cut_id").and_then(Value::as_str) != Some(cut_id.as_str())
        || fields.get("ordering_profile").and_then(Value::as_str) != Some(ordering_profile.as_str())
        || fields.get("preservation_contract").and_then(Value::as_str)
            != Some(preservation_contract.as_str())
        || !u64_matches_data(fields.get("event_ordinal"), *event_ordinal)
    {
        return Err(refused());
    }
    let Position {
        time_ps,
        microstep,
        phase,
    } = cut;
    let cut = fields
        .get("cut")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let phase = match phase {
        Phase::BoundaryControl => 0,
        Phase::Publication => 1,
        Phase::Delivery => 2,
        Phase::Reaction => 3,
    };
    if cut.len() != 3
        || !u64_matches_data(cut.get("time_ps"), *time_ps)
        || !u64_matches_data(cut.get("microstep"), *microstep)
        || cut.get("phase").and_then(Value::as_u64) != Some(phase)
    {
        return Err(refused());
    }
    Ok(())
}

fn u64_matches_data(value: Option<&Value>, expected: U64) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().ok() == Some(expected.get())
    })
}

fn quote_shape_data(
    shape: &SnapshotShape17<'_>,
    output_limit: usize,
    maximum_requested: usize,
) -> Result<NativeCapture17SnapshotStorageData, ProviderError> {
    // Count without an output ceiling; ordinary short-output rejection happens
    // afterward as a static ProviderError, without a serde IO-error allocation.
    let mut count = Count {
        used: 0,
        maximum: usize::MAX,
        hash: blake3::Hasher::new(),
    };
    write_shape_data(&mut count, shape)?;
    if count.used == 0 || count.used > output_limit {
        return Err(exhausted());
    }
    let quantity = |bytes| u64::try_from(bytes).map(U64::new).map_err(|_| exhausted());
    let retained = count
        .used
        .checked_add(REFERENCE_BACKING_BYTES)
        .ok_or_else(exhausted)?;
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(CLOSED_LEAF_FORMATTER_BYTES)?,
        declared_counter_scratch_bytes: quantity(native_capture17_snapshot_counter_scratch_data())?,
    };
    if usize::try_from(row.requested_peak_data()?).map_err(|_| exhausted())? > maximum_requested {
        return Err(exhausted());
    }
    Ok(NativeCapture17SnapshotStorageData {
        encoded: count.used,
        digest: *count.hash.finalize().as_bytes(),
        row,
    })
}

fn write_shape_data(
    writer: &mut impl Write,
    shape: &SnapshotShape17<'_>,
) -> Result<(), ProviderError> {
    write_raw_data(writer, b"{\"capture\":")?;
    serde_json::to_writer(&mut *writer, shape.capture).map_err(|_| exhausted())?;
    write_raw_data(writer, b",\"capture_request\":")?;
    serde_json::to_writer(&mut *writer, shape.original).map_err(|_| exhausted())?;
    write_raw_data(writer, b",\"control\":")?;
    write_raw_data(writer, shape.control)?;
    write_raw_data(writer, b",\"control_reference\":")?;
    serde_json::to_writer(
        &mut *writer,
        &SnapshotReference17::new(shape.control_reference),
    )
    .map_err(|_| exhausted())?;
    write_raw_data(writer, b",\"protocol\":[\"")?;
    write_raw_data(writer, BEFORE_TAG)?;
    write_raw_data(writer, b"\",")?;
    serde_json::to_writer(
        &mut *writer,
        &SnapshotReference17::new(shape.before_reference),
    )
    .map_err(|_| exhausted())?;
    write_raw_data(writer, b",")?;
    serde_json::to_writer(&mut *writer, &shape.before_capacity).map_err(|_| exhausted())?;
    write_raw_data(writer, b",")?;
    serde_json::to_writer(&mut *writer, &BorrowedCompactBytes::new(shape.before))
        .map_err(|_| exhausted())?;
    write_raw_data(writer, b"],\"schema\":\"")?;
    write_raw_data(writer, SCHEMA)?;
    write_raw_data(writer, b"\"}")
}

fn write_raw_data(writer: &mut impl Write, bytes: &[u8]) -> Result<(), ProviderError> {
    writer.write_all(bytes).map_err(|_| exhausted())
}

/// Names fixed input/hash/framing/compact writer headers before count or write.
pub(crate) const fn native_capture17_snapshot_counter_scratch_data() -> usize {
    size_of::<SnapshotShape17<'static>>()
        + size_of::<SnapshotReference17<'static>>()
        + size_of::<&SnapshotReference17<'static>>()
        + size_of::<&SnapshotHash17<'static>>()
        + size_of::<NativeCapture17SnapshotStorageData>()
        + size_of::<Result<NativeCapture17SnapshotStorageData, ProviderError>>()
        + size_of::<Count>()
        + size_of::<Bounded<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<ContentRef>()
        + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), io::Error>>()
        + size_of::<&CaptureArguments>()
        + size_of::<&Envelope>()
        + size_of::<&[u8]>() * 4
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 20]>()
        + size_of::<[u8; 8]>()
        + size_of::<[u8; 4]>()
        + size_of::<Option<U64>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<String>() * 4
        + size_of::<serde_json::Serializer<&'static mut Count>>()
        + size_of::<serde_json::Serializer<&'static mut Bounded<'static>>>()
        + size_of::<&Map<String, Value>>() * 2
        + size_of::<std::iter::Zip<std::slice::Iter<'static, Value>, std::slice::Iter<'static, Id>>>(
        )
        + BorrowedCompactBytes::requested_serialization_scratch_bytes()
}

#[cfg(test)]
#[path = "snapshot17_tests.rs"]
mod tests;
