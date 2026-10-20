//! Counts the real launch field sequence without reconstructing private text.
//!
//! Real fields use the original checked counter and the same JSON serializer.
//! Opaque token/path shapes only advance an exact quoted-string extent at their
//! original position. No placeholder bytes or synthetic serde error are created.

use super::*;
use crate::connection::{SerializedCreditCounter, serialized_credit};
use serde::Serialize;
use std::io::{self, Write};

pub(super) enum Credit<'a> {
    Original(&'a PacketNative5SourceLaunch),
    Projected {
        token_length: usize,
        path: PacketNative5PathSerializationData,
    },
}

impl Credit<'_> {
    pub(super) fn check_data(
        &self,
        fields: &PacketNative5LaunchValidationFields<'_>,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        match self {
            Self::Original(launch) => serialized_credit(*launch, maximum),
            Self::Projected { token_length, path } => {
                projected_credit_data(fields, *token_length, *path, maximum)
            }
        }
    }

    pub(super) fn token_length_data(&self) -> usize {
        match self {
            Self::Original(launch) => launch.admission_token.as_slice().len(),
            Self::Projected { token_length, .. } => *token_length,
        }
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("prepared whole frame bytes")
}

struct Record {
    counter: SerializedCreditCounter,
    first: bool,
}

impl Record {
    fn begin(maximum: usize) -> Result<Self, ProviderError> {
        let mut counter = SerializedCreditCounter::projection_data(maximum);
        counter.write_all(b"{").map_err(|_| exhausted())?;
        Ok(Self {
            counter,
            first: true,
        })
    }

    fn prefix(&mut self, key: &'static str) -> Result<(), ProviderError> {
        if !self.first {
            self.counter.write_all(b",").map_err(|_| exhausted())?;
        }
        self.first = false;
        serde_json::to_writer(&mut self.counter, key).map_err(|_| exhausted())?;
        self.counter.write_all(b":").map_err(|_| exhausted())
    }

    fn field(&mut self, key: &'static str, value: &impl Serialize) -> Result<(), ProviderError> {
        self.prefix(key)?;
        serde_json::to_writer(&mut self.counter, value).map_err(|_| exhausted())
    }

    fn token(&mut self, length: usize) -> Result<(), ProviderError> {
        self.prefix("admission_token")?;
        // URL_SAFE_NO_PAD emits only unescaped JSON ASCII. The original Bytes
        // serializer adds exactly the opening/closing string quotes.
        let bytes = base64::encoded_len(length, false)
            .and_then(|encoded| encoded.checked_add(2))
            .ok_or_else(exhausted)?;
        self.counter.advance_projection_data(bytes)
    }

    fn path(&mut self, path: PacketNative5PathSerializationData) -> Result<(), ProviderError> {
        self.prefix("effects")?;
        match path {
            PacketNative5PathSerializationData::QuotedUtf8 { bytes } if bytes >= 2 => {
                self.counter.advance_projection_data(bytes)
            }
            // The original whole serializer collapses Path/custom/IO failures
            // to this same ProviderError. We retain no fabricated serde cause.
            PacketNative5PathSerializationData::QuotedUtf8 { .. }
            | PacketNative5PathSerializationData::InvalidUtf8
            | PacketNative5PathSerializationData::Unrepresentable => Err(exhausted()),
        }
    }

    fn finish(mut self) -> Result<usize, ProviderError> {
        self.counter.write_all(b"}").map_err(|_| exhausted())?;
        Ok(self.counter.used_data())
    }
}

pub(super) fn projected_credit_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
    token_length: usize,
    path: PacketNative5PathSerializationData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut record = Record::begin(maximum)?;
    // This is the actual derived Launch field order and original skip rules.
    // All values remain borrowed from real nonsecret operands, never JSON DOMs.
    record.field("schema_version", &fields.schema_version)?;
    record.field("selection", fields.selection)?;
    record.field("program", fields.program)?;
    record.field("controller_pid", &fields.controller_pid)?;
    record.field("controller_uid", &fields.controller_uid)?;
    record.field("controller_executable", fields.controller_executable)?;
    record.token(token_length)?;
    record.field("initial_coordinator", fields.initial_coordinator)?;
    record.field("limits", fields.limits)?;
    record.field("storage", fields.storage)?;
    if !fields.capture_profile.is_original_arrays() {
        record.field("capture_profile", fields.capture_profile)?;
    }
    if fields.confirmation_selection.is_some() {
        record.field("confirmation_selection", &fields.confirmation_selection)?;
    }
    if fields.ack_emitter_selection.is_some() {
        record.field("ack_emitter_selection", &fields.ack_emitter_selection)?;
    }
    if fields.native_codec_metadata_extent.is_some() {
        record.field(
            "native_codec_metadata_extent",
            &fields.native_codec_metadata_extent,
        )?;
    }
    if fields.protocol_metadata_limits.is_some() {
        record.field("protocol_metadata_limits", &fields.protocol_metadata_limits)?;
    }
    if fields.complete_restore_selection.is_some() {
        record.field(
            "complete_restore_selection",
            &fields.complete_restore_selection,
        )?;
    }
    if fields.restore_input_emitter_selection.is_some() {
        record.field(
            "restore_input_emitter_selection",
            &fields.restore_input_emitter_selection,
        )?;
    }
    if fields.capture_allocation_selection.is_some() {
        record.field(
            "capture_allocation_selection",
            &fields.capture_allocation_selection,
        )?;
    }
    if fields.fresh_restore_allocation_selection.is_some() {
        record.field(
            "fresh_restore_allocation_selection",
            &fields.fresh_restore_allocation_selection,
        )?;
    }
    record.path(path)?;
    record.finish()
}

// This sink records only the actual string formatter's logical byte count.
// Returning every chunk's length avoids allocating an IO/serde error merely to
// discover a shape. Checked overflow becomes deferred Unrepresentable DATA.
#[derive(Default)]
struct StringExtent {
    used: usize,
    overflow: bool,
}

impl Write for StringExtent {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.used.checked_add(bytes.len()) {
            Some(next) => self.used = next,
            None => self.overflow = true,
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn path_serialization_data(
    path: &std::path::Path,
) -> PacketNative5PathSerializationData {
    let Some(text) = path.to_str() else {
        return PacketNative5PathSerializationData::InvalidUtf8;
    };
    let mut extent = StringExtent::default();
    if serde_json::to_writer(&mut extent, text).is_err() || extent.overflow {
        PacketNative5PathSerializationData::Unrepresentable
    } else {
        PacketNative5PathSerializationData::QuotedUtf8 { bytes: extent.used }
    }
}
