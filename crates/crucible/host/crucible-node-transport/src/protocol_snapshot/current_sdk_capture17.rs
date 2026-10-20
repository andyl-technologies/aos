//! Validates every current SDK Capture17 partial without a live SDK constructor.
//!
//! A retained decoded response and its original raw terminal are separate fields.
//! Failed partials remain representable; a complete phase requires the owners its
//! defining SDK actually retained. Signed outer provenance remains independent.

use super::current_controller17::invalid;
use super::current_controller17::*;
use crate::reference_packet::service::{
    restored_settled_capture::*, restored_settled_confirmation::*,
};
use crate::{ProviderError, bodies::*, envelope::Envelope};
use crucible_node_format::{ContentRef, Id, U64};
use serde_json::Value;
use std::mem::size_of;

pub(super) fn validate_capture_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "schema",
            "request_id",
            "operation_id",
            "body",
            "request",
            "prefix_frontier",
            "auxiliary_uploads",
            "maximum_auxiliary_originals",
            "arguments",
            "unsigned_request",
            "original",
            "context",
            "artifact",
            "canonical",
            "cut_present",
            "terminal",
            "decoded",
            "roots",
            "capture_frontier",
            "confirmation",
            "stage",
        ],
    )?;
    text(
        field(value, "schema")?,
        "source-private.restored-settled-capture-sdk/17",
    )?;
    typed::<Id>(field(value, "request_id")?)?;
    typed::<Id>(field(value, "operation_id")?)?;
    typed::<BeginRequest>(field(value, "body")?)?;
    typed::<PacketRestoredSettledCaptureRequest>(field(value, "request")?)?;
    optional(field(value, "prefix_frontier")?, typed::<U64>)?;
    let maximum = tuple(field(value, "maximum_auxiliary_originals")?, 2)?;
    let uploads = tuple(field(value, "auxiliary_uploads")?, 2)?;
    for (index, upload) in uploads.iter().enumerate() {
        let maximum = number(&maximum[index])?;
        if field(value, "stage")?.as_str() != Some("reserving") && (maximum == 0 || maximum > 256) {
            return Err(invalid());
        }
        optional(upload, |value| upload_data(value, maximum))?;
    }
    optional(field(value, "arguments")?, typed::<CaptureArguments>)?;
    optional(field(value, "unsigned_request")?, typed::<Value>)?;
    optional(field(value, "original")?, typed::<Envelope>)?;
    optional(
        field(value, "context")?,
        typed::<PacketRestoredSettledCaptureContext>,
    )?;
    optional(
        field(value, "artifact")?,
        typed::<PacketRestoredSettledCaptureArtifact>,
    )?;
    typed::<Vec<u8>>(field(value, "canonical")?)?;
    boolean(field(value, "cut_present")?)?;
    optional(field(value, "terminal")?, typed::<Envelope>)?;
    optional(field(value, "decoded")?, response)?;
    typed::<Vec<ContentRef>>(field(value, "roots")?)?;
    optional(field(value, "capture_frontier")?, typed::<U64>)?;
    optional(field(value, "confirmation")?, confirmation_data)?;
    phase(
        field(value, "stage")?,
        &[
            "reserving",
            "reserved",
            "assigning",
            "unsigned",
            "sealing",
            "sealed",
            "publishing",
            "captured",
            "confirming",
            "complete",
        ],
    )?;
    if field(value, "stage")?.as_str() == Some("complete") {
        for name in [
            "original",
            "terminal",
            "decoded",
            "capture_frontier",
            "confirmation",
        ] {
            if field(value, name)?.is_null() {
                return Err(invalid());
            }
        }
        let confirmation = field(value, "confirmation")?
            .as_object()
            .ok_or_else(invalid)?;
        text(field(confirmation, "stage")?, "complete")?;
    }
    Ok(())
}

fn upload_data(value: &Value, maximum: u64) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "request",
            "context",
            "artifact",
            "pending",
            "completed",
            "next_offset",
            "maximum_chunk",
            "finished",
            "maximum_originals",
        ],
    )?;
    typed::<PacketRestoredSettledCaptureUploadRequest>(field(value, "request")?)?;
    optional(
        field(value, "context")?,
        typed::<PacketRestoredSettledCaptureUploadContext>,
    )?;
    optional(
        field(value, "artifact")?,
        typed::<PacketRestoredSettledCaptureUploadArtifact>,
    )?;
    let completed = field(value, "completed")?.as_array().ok_or_else(invalid)?;
    let pending = field(value, "pending")?;
    if number(field(value, "maximum_originals")?)? != maximum
        || completed.len() as u64 + u64::from(!pending.is_null()) > maximum
    {
        return Err(invalid());
    }
    for original in completed {
        original_data(original)?;
        let original = original.as_object().ok_or_else(invalid)?;
        text(field(original, "stage")?, "complete")?;
    }
    optional(pending, original_data)?;
    typed::<U64>(field(value, "next_offset")?)?;
    optional(field(value, "maximum_chunk")?, typed::<U64>)?;
    boolean(field(value, "finished")?)?;
    Ok(())
}

fn original_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "request_id",
            "body",
            "continuation",
            "extension",
            "original",
            "cut_present",
            "terminal",
            "decoded",
            "frontier",
            "stage",
        ],
    )?;
    typed::<Id>(field(value, "request_id")?)?;
    let body = object(field(value, "body")?, &["kind", "data"])?;
    match field(body, "kind")?.as_str() {
        Some("begin") => typed::<BlobBeginRequest>(field(body, "data")?)?,
        Some("chunk") => typed::<BlobChunkRequest>(field(body, "data")?)?,
        Some("finish") => typed::<BlobFinishRequest>(field(body, "data")?)?,
        _ => return Err(invalid()),
    }
    optional(
        field(value, "continuation")?,
        typed::<PacketRestoredSettledCaptureUploadContinuation>,
    )?;
    optional(field(value, "extension")?, typed::<Value>)?;
    optional(field(value, "original")?, typed::<Envelope>)?;
    boolean(field(value, "cut_present")?)?;
    optional(field(value, "terminal")?, typed::<Envelope>)?;
    optional(field(value, "decoded")?, response)?;
    optional(field(value, "frontier")?, typed::<U64>)?;
    phase(
        field(value, "stage")?,
        &[
            "preparing",
            "unsigned",
            "sealing",
            "assigned",
            "publishing",
            "complete",
        ],
    )?;
    if field(value, "stage")?.as_str() == Some("complete") {
        for name in ["original", "terminal", "decoded", "frontier"] {
            if field(value, name)?.is_null() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn confirmation_data(value: &Value) -> Result<(), ProviderError> {
    let value = object(
        value,
        &[
            "request_id",
            "request",
            "extension",
            "original",
            "cut_present",
            "terminal",
            "decoded",
            "receipt",
            "roots",
            "frontier",
            "stage",
        ],
    )?;
    typed::<Id>(field(value, "request_id")?)?;
    typed::<PacketRestoredSettledAfterConfirmationRequest>(field(value, "request")?)?;
    optional(field(value, "extension")?, typed::<Value>)?;
    optional(field(value, "original")?, typed::<Envelope>)?;
    boolean(field(value, "cut_present")?)?;
    optional(field(value, "terminal")?, typed::<Envelope>)?;
    optional(field(value, "decoded")?, response)?;
    optional(
        field(value, "receipt")?,
        typed::<PacketRestoredSettledAfterConfirmationReceipt>,
    )?;
    typed::<Vec<ContentRef>>(field(value, "roots")?)?;
    optional(field(value, "frontier")?, typed::<U64>)?;
    phase(
        field(value, "stage")?,
        &["preparing", "assigned", "publishing", "complete"],
    )?;
    if field(value, "stage")?.as_str() == Some("complete") {
        for name in ["original", "terminal", "decoded", "receipt", "frontier"] {
            if field(value, name)?.is_null() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Result<(), ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureRequest, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureContext, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureArtifact, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadRequest, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadContext, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadArtifact, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadContinuation, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledAfterConfirmationRequest, ProviderError>>()
        + size_of::<Result<PacketRestoredSettledAfterConfirmationReceipt, ProviderError>>()
        + size_of::<Result<BeginRequest, ProviderError>>()
        + size_of::<Result<CaptureArguments, ProviderError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<Vec<ContentRef>, ProviderError>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<[&str; 21]>()
        + size_of::<[&str; 10]>()
        + size_of::<std::array::IntoIter<&str, 5>>()
        + size_of::<std::array::IntoIter<&str, 4>>()
        + size_of::<std::array::IntoIter<&str, 3>>()
        + size_of::<(&Value, &Value)>()
        + size_of::<usize>()
        + size_of::<u64>()
        + size_of::<bool>()
}
