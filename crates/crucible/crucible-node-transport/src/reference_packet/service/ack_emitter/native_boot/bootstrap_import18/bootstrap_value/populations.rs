//! Derives the closed request's pre-parser populations from its complete fields.
//!
//! Escape spelling can multiply an ASCII byte's wire width by six. The raw
//! lexical census counts that spelling conservatively; whitespace consumes the
//! separately retained frame bank without enlarging a JSON population.

use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_population_data,
};
use crucible_node_format::values::MAX_ID_BYTES;

const ENVELOPE_FIELDS: [&str; 13] = [
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
];
const REQUEST_FIELDS: [&str; 3] = ["schema", "recipe_identity", "initial_funding"];
const FUNDING_FIELDS: [&str; 3] = [
    "retained_requested_bytes",
    "maximum_simultaneous_transient_bytes",
    "declared_counter_scratch_bytes",
];
const PROOF_FIELDS: [&str; 4] = ["schema", "algorithm", "context_digest", "mac"];

/// Bounds populations of all closed headers, body, initial row and sole proof.
///
/// This is a parser resource bound, not validation of the parsed request.
///
/// # Errors
/// Refuses checked population arithmetic or unsupported pinned tree layouts.
pub(in super::super) fn extent_data() -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    let mut members = 1usize; // The sole proof18 extension entry.
    let mut strings = NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.len();
    for fields in [
        ENVELOPE_FIELDS.as_slice(),
        REQUEST_FIELDS.as_slice(),
        FUNDING_FIELDS.as_slice(),
        PROOF_FIELDS.as_slice(),
    ] {
        members = members.checked_add(fields.len()).ok_or_else(exhausted)?;
        for field in fields {
            strings = strings.checked_add(field.len()).ok_or_else(exhausted)?;
        }
    }
    for text in [
        "CNP/1",
        "request",
        "native_import18_bootstrap",
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        PACKET_COMPLETE_RESTORE_ALGORITHM,
    ] {
        strings = strings.checked_add(text.len()).ok_or_else(exhausted)?;
    }
    // Seven present nullable IDs, three fixed-width unpadded base64 values,
    // and four U64 values, whose serializer uses quoted decimal strings.
    strings = strings
        .checked_add(MAX_ID_BYTES.checked_mul(7).ok_or_else(exhausted)?)
        .and_then(|sum| sum.checked_add(43 * 3))
        .and_then(|sum| sum.checked_add(20 * 4))
        .ok_or_else(exhausted)?;
    let nodes = members
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(exhausted)?;
    original_json_value_storage_population_data(
        nodes,
        members,
        strings.checked_mul(6).ok_or_else(exhausted)?,
    )
}

/// Names actual fixed population, roster-walk and checked-layout controls.
pub(super) fn counter_scratch_data() -> usize {
    original_json_value_storage_extent_counter_scratch_data()
        + size_of::<[&[&str]; 4]>()
        + size_of::<std::array::IntoIter<&[&str], 4>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<[&str; 6]>()
        + size_of::<std::array::IntoIter<&str, 6>>()
        + size_of::<&str>()
        + size_of::<&&str>()
        + size_of::<usize>() * 4
        + size_of::<Option<usize>>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
}

// Exhaustive defining patterns keep the closed population roster reviewable
// when an actual schema changes. No positive request or authority is created.
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
const _: fn(&PacketNativeStartupAllocationRow) = |value| {
    let PacketNativeStartupAllocationRow {
        retained_requested_bytes: _,
        maximum_simultaneous_transient_bytes: _,
        declared_counter_scratch_bytes: _,
    } = value;
};
const _: fn(&PacketNativeImport18BootstrapAckProof) = |value| {
    let PacketNativeImport18BootstrapAckProof {
        schema: _,
        algorithm: _,
        context_digest: _,
        mac: _,
    } = value;
};
