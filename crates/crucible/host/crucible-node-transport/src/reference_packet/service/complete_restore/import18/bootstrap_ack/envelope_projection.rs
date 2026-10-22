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
    trees: [[usize; 2]; 2],
    native_request_trees: [usize; 2],
}

impl PacketNativeImport18BootstrapEnvelopeProjectionData {
    /// Prices native request backing under an enclosing typed tree census.
    ///
    /// The serialized Envelope's outer object is absent from its typed owner.
    /// Its remaining maps use the enclosing census's largest entry layout;
    /// projected text and other backing remain independently retained.
    ///
    /// # Errors
    /// Refuses unsupported tree alignment or checked layout overflow.
    pub(crate) fn request_native_backing_storage_data(
        &self,
        entry_bytes: usize,
        entry_alignment: usize,
    ) -> Result<usize, ProviderError> {
        use crate::retained_metadata::requested_storage::tree_storage_data;
        use serde_json::Value;
        use std::mem::align_of;

        let value_entry = size_of::<String>() + size_of::<Value>();
        let value_alignment = align_of::<String>().max(align_of::<Value>());
        let [containers, entries] = self.trees[0];
        let serialized_trees =
            tree_storage_data(containers, entries, value_entry, value_alignment)?;
        let [containers, entries] = self.native_request_trees;
        let native_trees = tree_storage_data(
            containers,
            entries,
            value_entry.max(entry_bytes),
            value_alignment.max(entry_alignment),
        )?;
        self.request
            .retained_value_backing_bytes
            .checked_sub(serialized_trees)
            .and_then(|bytes| bytes.checked_add(native_trees))
            .ok_or_else(invalid)
    }

    /// Returns compiled object-container/member populations for both envelopes.
    pub(crate) const fn tree_populations_data(&self) -> [[usize; 2]; 2] {
        self.trees
    }

    /// Prices unformatted serializer errors and bounded canonical reason text.
    pub(crate) fn serialization_failure_requested_bytes_data() -> usize {
        crate::reference_packet::continuation_models::serde_partials::diagnostic_error_impl_allocation_upper_bytes_data()
            + canonical::CANONICAL_JSON_INVALID_REASON_BYTES_DATA
    }

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
    let mut request_trees = [0; 2];
    let mut request = Projection::new(maximum)?;
    envelope(&mut request, &mut request_trees, "request")?;
    let request_header_trees = request_trees;
    object(
        &mut request,
        &mut request_trees,
        &["schema", "recipe_identity", "initial_funding"],
    )?;
    request.add_string(NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA)?;
    digest(&mut request)?;
    funding(&mut request, &mut request_trees)?;
    object(
        &mut request,
        &mut request_trees,
        &[NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF],
    )?;
    object(
        &mut request,
        &mut request_trees,
        &["schema", "algorithm", "context_digest", "mac"],
    )?;
    request.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)?;
    request.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    digest(&mut request)?;
    digest(&mut request)?;
    let request = request.finish(maximum)?;

    let mut response_trees = [0; 2];
    let mut response = Projection::new(maximum)?;
    envelope(&mut response, &mut response_trees, "response")?;
    object(
        &mut response,
        &mut response_trees,
        &["status", "operation_state", "result", "extensions"],
    )?;
    response.add_string("completed")?;
    response.add_string("completed")?;
    object(
        &mut response,
        &mut response_trees,
        &["schema", "state", "recipe_identity", "initial_funding"],
    )?;
    response.add_string(NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA)?;
    response.add_string("bootstrap_only")?;
    digest(&mut response)?;
    funding(&mut response, &mut response_trees)?;
    // The common completed body retains an independently owned empty map.
    object(&mut response, &mut response_trees, &[])?;
    object(
        &mut response,
        &mut response_trees,
        &[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT],
    )?;
    object(
        &mut response,
        &mut response_trees,
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

    Ok(PacketNativeImport18BootstrapEnvelopeProjectionData {
        request,
        response,
        trees: [request_trees, response_trees],
        native_request_trees: [
            request_trees[0]
                .checked_sub(request_header_trees[0])
                .ok_or_else(invalid)?,
            request_trees[1]
                .checked_sub(request_header_trees[1])
                .ok_or_else(invalid)?,
        ],
    })
}

fn envelope(
    out: &mut Projection,
    trees: &mut [usize; 2],
    message: &str,
) -> Result<(), ProviderError> {
    object(
        out,
        trees,
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

fn funding(out: &mut Projection, trees: &mut [usize; 2]) -> Result<(), ProviderError> {
    object(
        out,
        trees,
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

fn object(
    out: &mut Projection,
    trees: &mut [usize; 2],
    fields: &[&str],
) -> Result<(), ProviderError> {
    trees[0] = trees[0].checked_add(1).ok_or_else(invalid)?;
    trees[1] = trees[1].checked_add(fields.len()).ok_or_else(invalid)?;
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
        + size_of::<[[usize; 2]; 2]>()
        + size_of::<[usize; 6]>()
        + size_of::<&PacketNativeImport18BootstrapEnvelopeProjectionData>()
        + size_of::<&mut [usize; 2]>()
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
