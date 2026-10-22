//! Projects closed Bootstrap18 envelopes before assigning an original request.
//!
//! These allocation-free component facts cover the sealed request and terminal
//! bootstrap-only response. Raw parser owners, typed decoders, SDK custody,
//! private Source guards and whole-holder admission remain separate obligations.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape, OriginalSerializationStorageProjection as Projection,
};
use crucible_node_format::values::MAX_ID_BYTES;
use std::mem::size_of;

/// Reports independent closed request and completed-response serialization demand.
///
/// The shapes use the three present bounded IDs, four required null native IDs,
/// sequence two and the exact proof/receipt extension positions. They grant no
/// authority to assign, publish, receive or acknowledge an original.
pub struct PacketNativeImport18BootstrapEnvelopeProjectionData {
    request: Shape,
    response: Shape,
}

impl PacketNativeImport18BootstrapEnvelopeProjectionData {
    /// Returns sealed-request and completed-response encoded bounds, in that order.
    ///
    /// These bound closed serialized outputs, not arbitrary incoming JSON spelling.
    pub fn maximum_encoded_bytes_data(&self) -> [usize; 2] {
        [
            self.request.maximum_encoded_bytes,
            self.response.maximum_encoded_bytes,
        ]
    }

    /// Returns independent DOM/JCS, parser and output demand for each envelope.
    ///
    /// Each row is `[DOM-and-JCS, parser, output]`, in request/response order.
    /// Actual surviving DOMs and literal banks are charged separately by their
    /// enclosing owner; sequential work cannot substitute for retained backing.
    pub fn serialization_requested_bytes_data(&self) -> [[usize; 3]; 2] {
        [&self.request, &self.response].map(|shape| {
            [
                shape.dom_and_canonical_scratch_bytes,
                shape.projected_parser_requested_bytes,
                shape.canonical_output_requested_bytes,
            ]
        })
    }

    /// Returns separately owned Value backing for the request and response.
    pub fn retained_value_backing_bytes_data(&self) -> [usize; 2] {
        [
            self.request.retained_value_backing_bytes,
            self.response.retained_value_backing_bytes,
        ]
    }
}

/// Projects every closed request/response field without constructing either DTO.
///
/// Identifier widths come from the ID type's unescaped ASCII grammar. Digests come
/// from validated 32-byte unpadded base64, and row widths from decimal `u64`.
/// `maximum` restricts derived component demand and never supplies an allowance.
///
/// # Errors
/// Refuses checked storage overflow or a component exceeding the restriction.
pub fn native_import18_bootstrap_envelope_projection_data(
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapEnvelopeProjectionData, ProviderError> {
    let mut request = Projection::new(maximum)?;
    envelope(&mut request, "request")?;
    object(
        &mut request,
        &["schema", "recipe_identity", "initial_funding"],
    )?;
    request.add_string(NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA)?;
    digest(&mut request)?;
    funding(&mut request)?;
    object(&mut request, &[NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF])?;
    object(
        &mut request,
        &["schema", "algorithm", "context_digest", "mac"],
    )?;
    request.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)?;
    request.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    digest(&mut request)?;
    digest(&mut request)?;
    let request = request.finish(maximum)?;

    let mut response = Projection::new(maximum)?;
    envelope(&mut response, "response")?;
    object(
        &mut response,
        &["status", "operation_state", "result", "extensions"],
    )?;
    response.add_string("completed")?;
    response.add_string("completed")?;
    object(
        &mut response,
        &["schema", "state", "recipe_identity", "initial_funding"],
    )?;
    response.add_string(NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA)?;
    response.add_string("bootstrap_only")?;
    digest(&mut response)?;
    funding(&mut response)?;
    // The common completed body retains an independently owned empty map.
    object(&mut response, &[])?;
    object(&mut response, &[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT])?;
    object(
        &mut response,
        &[
            "schema",
            "algorithm",
            "state",
            "context_digest",
            "assigned_response",
            "mac",
        ],
    )?;
    response.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)?;
    response.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    response.add_string("bootstrap_only")?;
    for _ in 0..3 {
        digest(&mut response)?;
    }
    let response = response.finish(maximum)?;

    Ok(PacketNativeImport18BootstrapEnvelopeProjectionData { request, response })
}

fn envelope(out: &mut Projection, message: &str) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    out.add_string("CNP/1")?;
    out.add_string(message)?;
    for _ in 0..3 {
        out.add_unescaped_ascii_extent(MAX_ID_BYTES)?;
    }
    for _ in 0..4 {
        out.add_value(&())?;
    }
    out.add_string("2")?;
    out.add_string("native_import18_bootstrap")
}

fn funding(out: &mut Projection) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    for _ in 0..3 {
        out.add_unescaped_ascii_extent(20)?;
    }
    Ok(())
}

fn object(out: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for field in fields {
        out.add_field(field)?;
    }
    Ok(())
}

fn digest(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(43)
}

/// Names the projection's fixed controls separately from enclosing owner work.
pub fn native_import18_bootstrap_envelope_projection_counter_scratch_data() -> usize {
    size_of::<Projection>()
        + size_of::<Shape>() * 2
        + size_of::<PacketNativeImport18BootstrapEnvelopeProjectionData>()
        + size_of::<Result<PacketNativeImport18BootstrapEnvelopeProjectionData, ProviderError>>()
        + size_of::<&mut Projection>()
        + size_of::<&str>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&&str>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Result<(), ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

// Exhaustive rosters fail compilation when defining envelope/DTO fields grow.
const _: fn(&Envelope) = |value| {
    let Envelope {
        protocol: _,
        message: _,
        session_id: _,
        incarnation_id: _,
        node_id: _,
        execution_owner_id: _,
        capture_owner_id: _,
        request_id: _,
        operation_id: _,
        sequence: _,
        method: _,
        body: _,
        extensions: _,
    } = value;
};

const _: fn(&PacketNativeImport18BootstrapRequest) = |value| {
    let PacketNativeImport18BootstrapRequest {
        schema: _,
        recipe_identity: _,
        initial_funding: _,
    } = value;
};

const _: fn(&PacketNativeImport18BootstrapResult) = |value| {
    let PacketNativeImport18BootstrapResult {
        schema: _,
        state: _,
        recipe_identity: _,
        initial_funding: _,
    } = value;
};

#[cfg(test)]
#[path = "envelope_projection/tests.rs"]
mod tests;
