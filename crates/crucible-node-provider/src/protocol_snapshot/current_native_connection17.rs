//! Reads current native codec and Blob ledger DATA without native reconstruction.
//!
//! The native whole-owner reader separately authenticates Boot/Commit/Endpoint
//! and immutable import context. These logical fields create neither a policy,
//! ledger, stream, token nor an opportunity to replay historical operation IDs.

use super::current_controller17::*;
use crate::ProviderError;
use crucible_node_contract::{ContentRef, Id, U64};
use serde_json::Value;
use std::mem::size_of;

pub(super) fn validate_native_codec_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &["schema", "kind", "data"])?;
    text(
        field(value, "schema")?,
        "source-private.native5-codec-restored-settled/17",
    )?;
    text(field(value, "kind")?, "native")?;
    let policy = object(
        field(value, "data")?,
        &[
            "schema",
            "selection",
            "coordinator",
            "definition",
            "connected",
            "capture_profile",
            "confirmation_selection",
            "confirmation_definition",
            "ack_emitter_selection",
            "ack_emitter_definition",
            "native_codec_metadata_extent",
            "protocol_metadata_limits",
            "complete_restore_selection",
            "complete_restore_definitions",
            "complete_restore_transfer_definitions",
            "restore_input_emitter_selection",
            "restore_input_emitter_definition",
            "capture_allocation_selection",
            "capture_allocation_definitions",
            "fresh_restore_allocation_selection",
            "fresh_restore_allocation_definitions",
        ],
    )?;
    text(
        field(policy, "schema")?,
        "source-private.native5-policy-restored-settled/17",
    )?;
    super::current_transport17::validate_declared_selection_data(field(policy, "selection")?)?;
    let coordinator = tuple(field(policy, "coordinator")?, 3)?;
    let reference: ContentRef = read(&coordinator[0])?;
    compact(&coordinator[2], Some(number(&coordinator[1])?))?;
    verify_compact_reference_data(&reference, &coordinator[2])?;
    typed::<ContentRef>(field(policy, "definition")?)?;
    typed::<crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation>(field(
        policy,
        "connected",
    )?)?;
    typed::<crate::reference_packet::service::PacketNative5CaptureProfile>(field(
        policy,
        "capture_profile",
    )?)?;
    optional(
        field(policy, "confirmation_selection")?,
        typed::<crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection>,
    )?;
    optional(
        field(policy, "ack_emitter_selection")?,
        typed::<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
    )?;
    optional(
        field(policy, "native_codec_metadata_extent")?,
        typed::<crate::client::CanonicalAckCodecMetadataExtent>,
    )?;
    optional(
        field(policy, "protocol_metadata_limits")?,
        typed::<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
    )?;
    optional(field(policy,"complete_restore_selection")?,typed::<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>)?;
    optional(field(policy,"restore_input_emitter_selection")?,typed::<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>)?;
    optional(field(policy,"capture_allocation_selection")?,typed::<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>)?;
    optional(field(policy,"fresh_restore_allocation_selection")?,typed::<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>)?;
    for name in [
        "confirmation_definition",
        "ack_emitter_definition",
        "restore_input_emitter_definition",
    ] {
        optional(field(policy, name)?, typed::<ContentRef>)?;
    }
    optional(
        field(policy, "complete_restore_definitions")?,
        typed::<[ContentRef; 3]>,
    )?;
    optional(
        field(policy, "complete_restore_transfer_definitions")?,
        typed::<[ContentRef; 7]>,
    )?;
    optional(
        field(policy, "capture_allocation_definitions")?,
        typed::<[ContentRef; 2]>,
    )?;
    optional(
        field(policy, "fresh_restore_allocation_definitions")?,
        typed::<[ContentRef; 5]>,
    )
}

type RecordKey = (u8, Id, Id, Id);

pub(super) fn validate_blob_ledger_data(value: &Value) -> Result<(), ProviderError> {
    // This stable leaf tuple is a complete BlobProtocolOwner ledger, not an old
    // whole native/Controller codec fallback. All live pins and tombstones stay.
    let value = tuple(value, 5)?;
    text(&value[0], "source-private.native-blob-ledger/11")?;
    number(&value[1])?;
    let next_pin: U64 = read(&value[2])?;
    let pins_created = number(&value[3])?;
    let records = value[4].as_array().ok_or_else(invalid)?;
    let mut previous: Option<RecordKey> = None;
    let mut pins = 0u64;
    let mut charged_bytes = 0u64;
    for record in records {
        let record = tuple(record, 11)?;
        let key = tuple(&record[0], 4)?;
        let origin = match key[0].as_str() {
            Some("controller") => 0,
            Some("provider") => 1,
            _ => return Err(invalid()),
        };
        let key = (
            origin,
            read::<Id>(&key[1])?,
            read::<Id>(&key[2])?,
            read::<Id>(&key[3])?,
        );
        if previous.as_ref().is_some_and(|old| old >= &key) {
            return Err(invalid());
        }
        previous = Some(key);
        let reference: ContentRef = read(&record[1])?;
        let length = number(&record[2])?;
        let bytes = tuple(&record[3], 2)?;
        compact(&bytes[1], Some(number(&bytes[0])?))?;
        let raw = tuple(&bytes[1], 3)?;
        let actual = number(&raw[1])?;
        if actual > length || reference.length.get() != length {
            return Err(invalid());
        }
        let chunks = record[4].as_array().ok_or_else(invalid)?;
        let mut previous_offset = None;
        let mut chunk_end = 0u64;
        for chunk in chunks {
            let chunk = tuple(chunk, 2)?;
            let offset = number(&chunk[0])?;
            let length = number(&chunk[1])?;
            if previous_offset.is_some_and(|old| old >= offset)
                || offset.checked_add(length).is_none_or(|end| end > actual)
            {
                return Err(invalid());
            }
            if offset != chunk_end {
                return Err(invalid());
            }
            chunk_end = offset.checked_add(length).ok_or_else(invalid)?;
            previous_offset = Some(offset);
        }
        for flag in [&record[5], &record[6], &record[7], &record[10]] {
            boolean(flag)?;
        }
        retirement_data(&record[8])?;
        let charged = record[10].as_bool().ok_or_else(invalid)?;
        let verified = record[5].as_bool().ok_or_else(invalid)?;
        if chunk_end != actual {
            return Err(invalid());
        }
        if charged {
            charged_bytes = charged_bytes.checked_add(length).ok_or_else(invalid)?;
            if verified {
                verify_compact_reference_data(&reference, &bytes[1])?;
            }
        } else if actual != 0
            || !chunks.is_empty()
            || tuple(&record[8], 3)?[0].as_str() == Some("none")
        {
            return Err(invalid());
        }
        let mut previous_pin = None;
        for pin in record[9].as_array().ok_or_else(invalid)? {
            let pin = tuple(pin, 5)?;
            let id: U64 = read(&pin[0])?;
            if previous_pin.is_some_and(|old| old >= id.get()) || id.get() >= next_pin.get() {
                return Err(invalid());
            }
            previous_pin = Some(id.get());
            if !charged && pin[3].as_str() != Some("settled") {
                return Err(invalid());
            }
            pins = pins.checked_add(1).ok_or_else(invalid)?;
            typed::<Id>(&pin[1])?;
            typed::<ContentRef>(&pin[2])?;
            phase(&pin[3], &["held", "quarantined", "settled"])?;
            optional(&pin[4], typed::<ContentRef>)?;
        }
    }
    if pins > pins_created || charged_bytes != number(&value[1])? {
        return Err(invalid());
    }
    Ok(())
}

fn retirement_data(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 3)?;
    match value[0].as_str() {
        Some("none" | "abandon-inert") if value[1].is_null() && value[2].is_null() => Ok(()),
        Some("operation") => {
            typed::<Id>(&value[1])?;
            typed::<ContentRef>(&value[2])
        }
        Some("durable-store") if value[1].is_null() => typed::<ContentRef>(&value[2]),
        _ => Err(invalid()),
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<RecordKey>() * 2
        + size_of::<Option<RecordKey>>()
        + size_of::<Option<&RecordKey>>()
        + size_of::<Option<u64>>() * 2
        + size_of::<(&Value, &Value, &Value, &Value)>()
        + size_of::<[&Value; 4]>()
        + size_of::<std::array::IntoIter<&Value, 4>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<[&str; 21]>()
        + size_of::<[&str; 3]>()
        + size_of::<std::array::IntoIter<&str, 3>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<bool>()
        + size_of::<u8>()
        + size_of::<u64>()
        + size_of::<usize>()
}
