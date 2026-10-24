//! Visits the real projected launch field sequence without reconstructing secrets.

use super::reference_packet::service::{
    PacketNative5LaunchValidationFields, PacketNative5PathSerializationData,
};
use crate::errors::ProviderError;
use serde::Serialize;

pub(crate) trait ProjectedRecord {
    fn field(&mut self, key: &'static str, value: &impl Serialize) -> Result<(), ProviderError>;
    fn token(&mut self, length: usize) -> Result<(), ProviderError>;
    fn path(&mut self, path: PacketNative5PathSerializationData) -> Result<(), ProviderError>;
}

pub(crate) fn visit_fields(
    fields: &PacketNative5LaunchValidationFields<'_>,
    token_length: usize,
    path: PacketNative5PathSerializationData,
    record: &mut impl ProjectedRecord,
) -> Result<(), ProviderError> {
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
    Ok(())
}
