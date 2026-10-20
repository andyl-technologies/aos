//! Quotes only the actual closed native-five launch decoding layouts.
//!
//! Recognition inspects the immutable encoded launch before any DOM or typed
//! owner is constructed. It authenticates no Source or launch right. Unknown
//! editions, fields or program variants keep the generic issuer quote, and the
//! original duplicate-refusing parser, typed decoder and validators still run.

use super::*;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
};

// The selection's nested DTO/Vec roster is the same compiled portable roster
// used by the complete coordinator. The other independently allocated launch
// elements are producer events, reactive connections and decoded Bytes octets.
// Nested fixed records/enums live inline in the launch or these Vec elements.
fn element_slot() -> usize {
    coordinator_decode::typed_slot()
        .max(size_of::<crate::reference_packet::PacketEvent>())
        .max(size_of::<
            crate::reference_packet::connected::PacketInputConnection,
        >())
        .max(size_of::<u8>())
}

const FIELDS: &[&str] = &[
    "schema_version",
    "selection",
    "program",
    "controller_pid",
    "controller_uid",
    "controller_executable",
    "admission_token",
    "initial_coordinator",
    "limits",
    "storage",
    "effects",
    "capture_profile",
    "confirmation_selection",
    "ack_emitter_selection",
    "native_codec_metadata_extent",
    "protocol_metadata_limits",
    "complete_restore_selection",
    "restore_input_emitter_selection",
    "capture_allocation_selection",
    "fresh_restore_allocation_selection",
];

fn definition(bytes: &[u8], names: &[&str]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut seen = 0u8;
    while let Some((key, _)) = fields.pair()? {
        let index = names
            .iter()
            .position(|name| plain_string(key).is_ok_and(|key| key == *name))
            .ok_or_else(refused)?;
        let bit = 1u8.checked_shl(index as u32).ok_or_else(refused)?;
        if seen & bit != 0 {
            return Err(refused());
        }
        seen |= bit;
    }
    fields.finish()?;
    if seen != (1 << names.len()) - 1 {
        return Err(refused());
    }
    Ok(())
}

fn program(bytes: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut kind = None;
    let mut body = None;
    while let Some((key, value)) = fields.pair()? {
        match plain_string(key)? {
            "kind" if kind.is_none() => kind = Some(plain_string(value)?),
            "program" if body.is_none() => body = Some(value),
            _ => return Err(refused()),
        }
    }
    fields.finish()?;
    let body = body.ok_or_else(refused)?;
    match kind {
        Some("producer") => definition(body, &["schema", "events"]),
        Some("reactive") => definition(body, &["schema", "connections", "output"]),
        _ => Err(refused()),
    }
}

pub(super) fn recognized(bytes: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut seen = 0u32;
    while let Some((key, value)) = fields.pair()? {
        let name = plain_string(key)?;
        let index = FIELDS
            .iter()
            .position(|field| *field == name)
            .ok_or_else(refused)?;
        let bit = 1u32.checked_shl(index as u32).ok_or_else(refused)?;
        if seen & bit != 0 {
            return Err(refused());
        }
        seen |= bit;
        match name {
            "schema_version" if value != b"5" => return Err(refused()),
            "program" => program(value)?,
            _ => {}
        }
    }
    fields.finish()?;
    // The first eleven fields are required by the actual native-five DTO;
    // the remaining fields have the original serde defaults. This recognizes
    // the decoder's class, not the values or authority of an untrusted launch.
    if seen & ((1 << 11) - 1) != (1 << 11) - 1 {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn quote(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    if recognized(bytes).is_err() {
        return super::super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
            bytes, size_of::<PacketNative5SourceLaunch>(), maximum,
        );
    }
    // Keep the complete conservative DecodedStorage total, including its
    // separate Value/typed backing and work rows. This intentionally covers
    // more than the minimal live decode: all opaque Value/string/map banks,
    // array minimum/spare capacity, borrowed/owned rebuilding, canonical output
    // and collect/sort banks remain; only the unrelated Control per-token tax
    // disappears. This result never includes or replaces launch.validate work.
    decoded::quote(
        bytes,
        size_of::<PacketNative5SourceLaunch>(),
        element_slot(),
        maximum,
    )?
    .total(maximum)
}

pub(super) fn counter_scratch_data() -> usize {
    // Recognition returns before the decoded occurrence walk. Conservatively
    // retain every nested recognition cursor/key/result and compiled roster
    // alongside the parent's separately named decoded scanner and sort banks.
    3 * size_of::<Fields<'static>>()
        + size_of::<[usize; 29]>()
        + size_of::<[usize; 7]>()
        + size_of::<u32>()
        + size_of::<u8>()
        + 3 * size_of::<Option<&'static [u8]>>()
        + size_of::<Option<&'static str>>()
        + 3 * size_of::<Option<(&'static [u8], &'static [u8])>>()
        + size_of::<&'static [&'static str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        // Full return views are separate from the payloads above. Recognition
        // nests the outer/program/definition field cursors; position and its
        // checked conversion, plain-string and checked-bit results also live
        // in that call chain. They are not borrowed from unrelated row slack.
        + 3 * size_of::<Result<Fields<'static>, ProviderError>>()
        + 3 * size_of::<Result<Option<(&'static [u8], &'static [u8])>, ProviderError>>()
        + 3 * size_of::<Result<&'static str, ProviderError>>()
        + 3 * size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<Option<usize>>()
        + 2 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<u8>>()
        + size_of::<Result<u8, ProviderError>>()
        + size_of::<Option<u32>>()
        + size_of::<Result<u32, ProviderError>>()
        + 3 * size_of::<bool>()
}

#[cfg(test)]
mod tests;
