//! Shares the original closed native-five launch classification and typed roster.
//!
//! Recognition only selects a decode-storage class. It does not validate a
//! launch, construct a typed owner, authenticate Source, or grant authority.
//! The genuine generic issuer fallback remains in the upper transport caller.

use crate::borrowed_literal::{OrderedFields as Fields, plain_string};
use crate::errors::ProviderError;
use crate::profile::reference_packet::control::PacketControlSelection;
use crucible_node_format::*;
use std::mem::size_of;

/// Returns the largest actual launch element layout from the shared DTO roster.
pub fn element_slot() -> usize {
    typed_slot()
        .max(size_of::<crate::profile::reference_packet::PacketEvent>())
        .max(size_of::<
            crate::profile::reference_packet::connected::PacketInputConnection,
        >())
        .max(size_of::<u8>())
}

/// Returns the largest of the original 29 actual portable coordinator layouts.
pub fn typed_slot() -> usize {
    [
        size_of::<PacketControlSelection>(),
        size_of::<ProviderManifest>(),
        size_of::<NodeManifest>(),
        size_of::<ImplementationIdentity>(),
        size_of::<ArtifactIdentity>(),
        size_of::<RealizationManifest>(),
        size_of::<NodeDescriptor>(),
        size_of::<PortDescriptor>(),
        size_of::<LaneDescriptor>(),
        size_of::<NodeBinding>(),
        size_of::<BindingCompatibility>(),
        size_of::<LiveAuthority>(),
        size_of::<OwnerRef>(),
        size_of::<OwnerBinding>(),
        size_of::<NodeBindingRef>(),
        size_of::<OperatingContract>(),
        size_of::<FacetSelection>(),
        size_of::<crate::profile::bodies::RealizeRequest>(),
        size_of::<ResourceLimits>(),
        size_of::<SchemaRef>(),
        size_of::<ContentRef>(),
        size_of::<HashRef>(),
        size_of::<Id>(),
        size_of::<String>(),
        size_of::<serde_json::Value>(),
        size_of::<WorldBinding>(),
        size_of::<ConnectionDescriptor>(),
        size_of::<Endpoint>(),
        size_of::<GuaranteeProfile>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
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

/// Recognizes the original closed launch fields and producer/reactive class.
///
/// # Errors
/// Refuses malformed cursors, duplicate or unknown fields, unsupported program
/// classes, missing required fields, and a non-five schema discriminator.
pub fn recognized(bytes: &[u8]) -> Result<(), ProviderError> {
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

/// Returns the unchanged fixed cursor, result, bit and roster counter window.
pub fn counter_scratch_data() -> usize {
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

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}
