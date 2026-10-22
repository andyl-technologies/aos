//! Prices the complete closed reply, its serializer partials and actual census.
//!
//! These facts supply no opaque Initial, Recipe or publication rights. The
//! original request assignment is quoted independently of the response DOMs.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_population_data,
};
use crucible_node_format::values::MAX_ID_BYTES;
use serde_json::Value;
use std::mem::{align_of, size_of};

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
const BODY_FIELDS: [&str; 4] = ["status", "operation_state", "result", "extensions"];
const RESULT_FIELDS: [&str; 4] = ["schema", "state", "recipe_identity", "initial_funding"];
const FUNDING_FIELDS: [&str; 3] = [
    "retained_requested_bytes",
    "maximum_simultaneous_transient_bytes",
    "declared_counter_scratch_bytes",
];
const RECEIPT_FIELDS: [&str; 6] = [
    "schema",
    "algorithm",
    "state",
    "context_digest",
    "assigned_response",
    "mac",
];

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}

fn envelope_backing_text_data() -> Result<usize, ProviderError> {
    let mut text = sum(&[
        "CNP/1".len(),
        7 * MAX_ID_BYTES,
        "completed".len() * 2,
        NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.len(),
        "bootstrap_only".len(),
        43,
        3 * 20,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        "bootstrap_only".len(),
        3 * 43,
    ])?;
    for fields in [
        BODY_FIELDS.as_slice(),
        RESULT_FIELDS.as_slice(),
        FUNDING_FIELDS.as_slice(),
        &[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT],
        RECEIPT_FIELDS.as_slice(),
    ] {
        for field in fields {
            text = add(text, field.len())?;
        }
    }
    Ok(text)
}

/// Bounds every actual serializer Value tree, including all top-level fields.
pub(super) fn extent_data() -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    let mut text = envelope_backing_text_data()?;
    for field in ENVELOPE_FIELDS {
        text = add(text, field.len())?;
    }
    text = sum(&[
        text,
        "response".len(),
        "native_import18_bootstrap".len(),
        20,
    ])?;
    original_json_value_storage_population_data(63, 31, text)
}

/// Quotes typed Result/Envelope/Receipt outputs and their constructor partials.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let extent = extent_data()?;
    let literal = super::literal::backing_construction_data(extent)?;
    let incoming = super::super::bootstrap_proof::construction_data(launch, maximum)?;
    let projection = native_import18_bootstrap_ack_projection_data(maximum)?;
    let context = projection.serialization_requested_bytes_data()[0];
    let trees = tree_storage_data(
        6,
        18,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let envelope = add(trees, envelope_backing_text_data()?)?;
    let result = add(NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.len(), 32)?;
    let receipt = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        3 * 32,
    ])?;
    let retained = sum(&[size_of::<Attempt>(), envelope, result, receipt, literal[0]])?;
    // Assignment holds the reply DOM while bounded canonicalization builds its
    // second DOM and JCS bank. The incoming request's independent typed decode
    // and both DTO serialization/constructor partials remain separate windows.
    let transient = sum(&[
        literal[1],
        envelope,
        result,
        receipt,
        incoming[1],
        extent
            .value_dom_requested_bytes
            .checked_mul(3)
            .ok_or_else(exhausted)?,
        extent.canonical_work_requested_bytes,
        extent.canonical_output_requested_bytes,
        context[0],
        context[2],
        projection.bytes_formatter_temporary_data(),
        size_of::<ReplyResult>(),
        size_of::<Option<ReplyResult>>(),
        size_of::<Result<ReplyResult, ProviderError>>(),
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Result<Envelope, ProviderError>>(),
        size_of::<Receipt>(),
        size_of::<Option<Receipt>>(),
        size_of::<Result<Receipt, ProviderError>>(),
        size_of::<Value>(),
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<Attempt>(),
        size_of::<Option<Attempt>>(),
        size_of::<Result<Attempt, ProviderError>>(),
    ])?;
    let scratch = sum(&[
        literal[2],
        incoming[2],
        extent.declared_counter_scratch_bytes,
        native_import18_bootstrap_ack_counter_scratch_data(),
        crate::session::CorrelationGuard::original_bootstrap_response_sequence_counter_scratch_data(
        ),
    ])?;
    let row = [retained, transient, scratch];
    if sum(&row)? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

/// Counts every surviving output using actual capacities and ordinary tree rules.
///
/// # Errors
/// Refuses metadata limits, unsupported layouts or checked capacity overflow.
pub(super) fn retained_data(attempt: &Attempt) -> Result<usize, ProviderError> {
    let mut observer = crate::retained_metadata::MetadataObserver::new();
    if let Some(result) = &attempt.result {
        let ReplyResult {
            schema,
            state: _,
            recipe_identity,
            initial_funding: _,
        } = result;
        observer.observe(schema)?;
        observer.observe(recipe_identity)?;
    }
    if let Some(envelope) = &attempt.envelope {
        super::super::bootstrap_codec::observe_envelope_data(envelope, &mut observer)?;
    }
    if let Some(receipt) = &attempt.receipt {
        let Receipt {
            schema,
            algorithm,
            state: _,
            context_digest,
            assigned_response,
            mac,
        } = receipt;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(context_digest)?;
        observer.observe(assigned_response)?;
        observer.observe(mac)?;
    }
    add(
        size_of::<Attempt>(),
        add(
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?,
            attempt.literal.retained_backing_data()?,
        )?,
    )
}

/// Names actual projection, serialization, census and borrowed-key controls.
pub(super) fn counter_scratch_data() -> usize {
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapAckProjectionData;
    native_import18_bootstrap_ack_counter_scratch_data()
        + size_of::<PacketNativeImport18BootstrapAckProjectionData>()
        + size_of::<Result<PacketNativeImport18BootstrapAckProjectionData, ProviderError>>()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<crate::retained_metadata::MetadataObserver>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<[usize; 3]>() * 5
        + size_of::<[usize; 25]>()
        + size_of::<[usize; 11]>()
        + size_of::<[usize; 5]>() * 3
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[usize]>()
        + size_of::<[&str; 13]>()
        + size_of::<std::array::IntoIter<&'static str, 13>>()
        + size_of::<[&[&str]; 5]>()
        + size_of::<std::array::IntoIter<&'static [&'static str], 5>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        // Six owning maps are walked in the completed response.
        + 6 * (size_of::<&Value>() + size_of::<&String>()
            + size_of::<(&String, &Value)>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>())
        + size_of::<&crate::envelope::Nullable<crucible_node_format::Id>>() * 7
        + size_of::<&Bytes>() * 4 + size_of::<&String>() * 5
        + size_of::<&Attempt>()
        + size_of::<&ReplyResult>()
        + size_of::<&Envelope>()
        + size_of::<&Receipt>()
        + size_of::<&crate::session::CorrelationGuard>()
        + size_of::<&mut crate::retained_metadata::MetadataObserver>()
        + size_of::<&[u8]>()
        + size_of::<&[u8; 32]>()
        + size_of::<Result<&[u8; 32], std::array::TryFromSliceError>>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<Result<[u8; 32], ProviderError>>() * 2
        + size_of::<serde_json::Map<String, Value>>()
        + size_of::<std::collections::BTreeMap<String, Value>>()
        + size_of::<Option<Value>>()
        + size_of::<Option<&str>>()
        + size_of::<usize>() * 12
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<(), ProviderError>>() * 8
}
