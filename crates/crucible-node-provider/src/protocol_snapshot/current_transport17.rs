//! Validates the closed transport and SDK component shapes within Controller17.
//!
//! These checks preserve independent raw and typed failure partials. They never
//! normalize a partial into a successful reply or construct a live transport.

use super::current_controller17::invalid;
use super::current_controller17::*;
use crate::{ProviderError, bodies::*, envelope::Envelope};
use crucible_node_contract::{ContentRef, HashRef, Id, U64};
use serde_json::Value;
use std::mem::size_of;

pub(super) fn validate_frame_bank_data(value: &Value) -> Result<(), ProviderError> {
    let bytes = encoded(value)?;
    crate::transport::original_frames::ValidatedCompactOriginalFrames::validate(
        &bytes,
        bytes.len(),
        usize::MAX,
    )?;
    Ok(())
}

pub(super) fn validate_content_data(value: &Value) -> Result<(), ProviderError> {
    use crate::client::{
        compact_cursor::CompactContentLimits,
        compact_metadata8::{CompactMetadata8Limits, ValidatedCompactMetadata8},
    };
    let bytes = encoded(value)?;
    let plan = ValidatedCompactMetadata8::validate(
        &bytes,
        CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: bytes.len(),
                max_rows: CompactContentLimits::maximum_supported_combined_rows_data(),
                max_groups: CompactContentLimits::maximum_supported_combined_rows_data(),
                max_first_group_capacity_bytes: usize::MAX,
            },
            maximum_metadata_capacity_bytes: usize::MAX,
        },
    )?;
    let content = plan.data();
    for row in content.transfers().chain(content.objects()) {
        let row = row?;
        // Failed/incomplete transfer bytes are preserved as inert partials.
        // Every completed transfer and object must retain its actual hash.
        if row.complete == Some(false) {
            continue;
        }
        let reference: ContentRef = serde_json::from_slice(row.reference.encoded())
            .map_err(crucible_node_contract::ContractError::from)?;
        let payload = if let Some(payload) = row.payload {
            payload
        } else {
            let original = match row.edge.kind {
                crate::client::compact_cursor::ContentGroupKind::Transfer => {
                    content.transfers().nth(row.edge.index)
                }
                crate::client::compact_cursor::ContentGroupKind::Object => {
                    content.objects().nth(row.edge.index)
                }
            }
            .ok_or_else(invalid)??;
            original.payload.ok_or_else(invalid)?
        };
        verify_compact_payload_data(&reference, &payload)?;
    }
    Ok(())
}

pub(super) fn validate_blob_data(_value: &Value) -> Result<(), ProviderError> {
    // Host Controllers do not own the native receiver ledger. The native
    // Connection structural plan instead lends its exact span to that reader.
    Err(invalid())
}

pub(super) fn validate_correlations_data(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 12)?;
    text(&value[0], "source-private.correlations/6")?;
    typed::<Id>(&value[1])?;
    typed::<Id>(&value[2])?;
    typed::<U64>(&value[3])?;
    typed::<U64>(&value[4])?;
    let maximum = number(&value[5])?;
    for map in [&value[6], &value[7], &value[8]] {
        let map = map.as_object().ok_or_else(invalid)?;
        if map.len() as u64 > maximum {
            return Err(invalid());
        }
        for (key, envelope) in map {
            Id::new(key.clone())?;
            let envelope: Envelope = read(envelope)?;
            if envelope.request_id.0.as_ref().map(Id::as_str) != Some(key.as_str()) {
                return Err(invalid());
            }
        }
    }
    typed::<std::collections::BTreeSet<String>>(&value[9])?;
    boolean(&value[10])?;
    boolean(&value[11])
}

pub(super) fn validate_declared_selection_data(value: &Value) -> Result<(), ProviderError> {
    let selection: crate::reference_packet::control::PacketControlSelection = read(value)?;
    if selection.realization.bindings.is_empty() {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        crate::reference_packet::service::complete_restore::settled_recapture::authenticate_restored_settled_capture_immutable_declaration_data(
            &selection.provider.implementation.formats,
            &binding.compatibility.implementation.formats,
            &selection.provider.extensions_supported,
        )?;
    }
    Ok(())
}

pub(super) fn validate_controller_codec_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &["schema", "kind", "data"])?;
    text(
        field(value, "schema")?,
        "source-private.native5-codec-restored-settled/17",
    )?;
    text(field(value, "kind")?, "controller")?;
    let policy = object(
        field(value, "data")?,
        &[
            "schema",
            "metadata_extent",
            "selection",
            "coordinator",
            "definition",
            "connected",
            "wire",
            "capture_profile",
            "confirmation_selection",
            "confirmation_definition",
            "ack_emitter_selection",
            "ack_emitter_definition",
            "complete_restore_selection",
            "complete_restore_definitions",
            "complete_restore_transfer_definitions",
            "restore_input_emitter_selection",
            "restore_input_emitter_definition",
            "fresh_restore_allocation_selection",
            "fresh_restore_allocation_definitions",
        ],
    )?;
    text(
        field(policy, "schema")?,
        "source-private.controller-native5-policy-restored-settled/17",
    )?;
    optional(field(policy, "metadata_extent")?, |v| {
        text(v, "CanonicalAck512KiB")
    })?;
    super::current_transport17::validate_declared_selection_data(field(policy, "selection")?)?;
    let content = object(
        field(policy, "coordinator")?,
        &["reference", "capacity", "bytes"],
    )?;
    let reference: ContentRef = read(field(content, "reference")?)?;
    compact(
        field(content, "bytes")?,
        Some(number(field(content, "capacity")?)?),
    )?;
    verify_compact_reference_data(&reference, field(content, "bytes")?)?;
    typed::<ContentRef>(field(policy, "definition")?)?;
    typed::<crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation>(field(
        policy,
        "connected",
    )?)?;
    let wire = tuple(field(policy, "wire")?, 5)?;
    typed::<Id>(&wire[0])?;
    typed::<Id>(&wire[1])?;
    typed::<U64>(&wire[2])?;
    typed::<Id>(&wire[3])?;
    typed::<HashRef>(&wire[4])?;
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
    optional(field(policy,"complete_restore_selection")?,typed::<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>)?;
    optional(field(policy,"restore_input_emitter_selection")?,typed::<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>)?;
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
        field(policy, "fresh_restore_allocation_definitions")?,
        typed::<[ContentRef; 5]>,
    )
}

pub(super) fn validate_activation_command_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &["kind", "data"])?;
    text(field(value, "kind")?, "command")?;
    let command = object(field(value, "data")?, &["kind", "data"])?;
    match field(command, "kind")?.as_str() {
        Some("arm") => typed::<ActivateRequest>(field(command, "data")?),
        Some("world_activate") => typed::<WorldActivateRequest>(field(command, "data")?),
        _ => Err(invalid()),
    }
}

pub(super) fn validate_activation_request_data(value: &Value) -> Result<(), ProviderError> {
    typed::<crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationRequest>(value)
}

pub(super) fn validate_observation_request_data(value: &Value) -> Result<(), ProviderError> {
    typed::<crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest>(value)
}

pub(super) fn validate_supervisor_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(value, &["schema", "phase", "incidents", "pending"])?;
    text(
        field(value, "schema")?,
        "source-private.retained-supervisor-restored-settled/17",
    )?;
    let phase = tuple(field(value, "phase")?, 5)?;
    text(
        &phase[0],
        "source-private.supervisor-phase-restored-settled/17",
    )?;
    number(&phase[1])?;
    text(&phase[2], "nonportable-original-thread")?;
    boolean(&phase[3])?;
    boolean(&phase[4])?;
    for incident in field(value, "incidents")?.as_array().ok_or_else(invalid)? {
        incident_data(incident)?;
    }
    optional(field(value, "pending")?, incident_data)
}

fn incident_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "session",
            "incarnation",
            "connection",
            "failure",
            "transport_fenced",
            "outgoing",
            "incoming",
        ],
    )?;
    for name in ["session", "incarnation", "connection"] {
        typed::<Id>(field(value, name)?)?;
    }
    phase(
        field(value, "failure")?,
        &["read", "write", "protocol", "authority", "closed"],
    )?;
    boolean(field(value, "transport_fenced")?)?;
    typed::<Vec<Envelope>>(field(value, "outgoing")?)?;
    typed::<Vec<Envelope>>(field(value, "incoming")?)
}

pub(super) fn validate_upload_data(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 8)?;
    text(&value[0], "source-private.sdk-activation-upload-current/17")?;
    typed::<crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationUploadRequest>(&value[1])?;
    optional(&value[2], typed::<Id>)?;
    optional(&value[3], |v| {
        let value = tuple(v, 3)?;
        typed::<ContentRef>(&value[0])?;
        compact(&value[1], Some(number(&value[2])?))
    })?;
    let frames = value[4].as_array().ok_or_else(invalid)?;
    if frames.len() as u64 > number(&value[5])? {
        return Err(invalid());
    }
    for frame in frames {
        let frame = object(
            frame,
            &[
                "request_id",
                "method",
                "offset",
                "length",
                "original",
                "received",
                "attempted",
                "complete",
            ],
        )?;
        typed::<Id>(field(frame, "request_id")?)?;
        typed::<crate::envelope::Method>(field(frame, "method")?)?;
        number(field(frame, "offset")?)?;
        number(field(frame, "length")?)?;
        optional(field(frame, "original")?, typed::<Envelope>)?;
        boolean(field(frame, "attempted")?)?;
        boolean(field(frame, "complete")?)?;
        optional(field(frame, "received")?, |v| {
            let value = tuple(v, 2)?;
            typed::<Envelope>(&value[0])?;
            received_body_data(&value[1])
        })?;
    }
    phase(
        &value[6],
        &[
            "preparing",
            "unsigned",
            "sealing",
            "sealed",
            "publishing",
            "complete",
        ],
    )?;
    text(&value[7], "historical-nonrenewable-operational-cut")
}

fn received_body_data(value: &Value) -> Result<(), ProviderError> {
    let value = tuple(value, 2)?;
    match value[0].as_str() {
        Some("response") => response(&value[1]),
        Some("notification") => typed::<NotificationBody>(&value[1]),
        Some("request") => {
            let value = tuple(&value[1], 2)?;
            match value[0].as_str() {
                Some("blob_begin") => typed::<BlobBeginRequest>(&value[1]),
                Some("blob_chunk") => typed::<BlobChunkRequest>(&value[1]),
                Some("blob_finish") => typed::<BlobFinishRequest>(&value[1]),
                Some("retire") => typed::<RetireRequest>(&value[1]),
                _ => Err(invalid()),
            }
        }
        _ => Err(invalid()),
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::client::compact_cursor::{BorrowedContentRow, CompactContentRows, ContentGroupKind};
    let content_views = size_of::<BorrowedContentRow<'static>>()
        + size_of::<Result<BorrowedContentRow<'static>, ProviderError>>()
        + size_of::<Option<Result<BorrowedContentRow<'static>, ProviderError>>>()
        + size_of::<ContentGroupKind>()
        + size_of::<std::iter::Chain<CompactContentRows<'static>, CompactContentRows<'static>>>()
        + size_of::<Option<super::compact_bytes::ValidatedCompactBytes<'static>>>();
    content_views
        + size_of::<&crate::reference_packet::control::PacketControlSelection>()
        + selection_binding_view_bytes(|selection|selection.realization.bindings.iter())
        + crate::reference_packet::service::complete_restore::settled_recapture::restored_settled_capture_selection_counter_scratch_data()

        +  size_of::<Result<Vec<u8>,serde_json::Error>>()
        +  size_of::<Result<(),ProviderError>>()
        +  size_of::<Result<Envelope,ProviderError>>()
        +  size_of::<Result<crate::reference_packet::control::PacketControlSelection,ProviderError>>()
        +  size_of::<Result<crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation,ProviderError>>()
        +  size_of::<Result<crate::reference_packet::service::PacketNative5CaptureProfile,ProviderError>>()
        +  size_of::<Result<crate::client::compact_metadata8::ValidatedCompactMetadata8<'static>,ProviderError>>()
        +  size_of::<crate::client::compact_metadata8::CompactMetadata8Limits>()
        +  size_of::<crate::client::compact_cursor::CompactContentLimits>()
        +  size_of::<Result<crate::transport::original_frames::ValidatedCompactOriginalFrames<'static>,ProviderError>>()
        +  size_of::<std::slice::Iter<'static,Value>>()
        +  size_of::<serde_json::map::Iter<'static>>()
        +  size_of::<[&str;19]>()
        +  size_of::<[&str;3]>()
        +  size_of::<std::array::IntoIter<&str,3>>()
        +  size_of::<&Value>()
        +  size_of::<&serde_json::Map<String,Value>>()
}

fn encoded(value: &Value) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(ProviderError::from)
}

fn selection_binding_view_bytes<T>(
    _: impl FnOnce(&'static crate::reference_packet::control::PacketControlSelection) -> T,
) -> usize {
    size_of::<T>()
}
