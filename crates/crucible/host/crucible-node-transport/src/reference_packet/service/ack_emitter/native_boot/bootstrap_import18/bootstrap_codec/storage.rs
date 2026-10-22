//! Prices closed borrowed-Value bootstrap decoding and its actual partials.
//!
//! Preflight admits only the complete Envelope13/body3/funding3/proof4 grammar.
//! The four surviving Value maps belong to body, funding, extensions and proof.
//! Typed request and proof decoding retain separate schema and byte allocations.

use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_format::values::MAX_ID_BYTES;
use serde_json::Value;
use std::mem::{align_of, size_of};

decoder_struct!(PacketNativeImport18BootstrapRequest {
    schema,
    recipe_identity,
    initial_funding
});
decoder_struct!(PacketNativeImport18BootstrapAckProof {
    schema,
    algorithm,
    context_digest,
    mac
});

const MAP_KEYS: [&str; 11] = [
    "schema",
    "recipe_identity",
    "initial_funding",
    "retained_requested_bytes",
    "maximum_simultaneous_transient_bytes",
    "declared_counter_scratch_bytes",
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
    "schema",
    "algorithm",
    "context_digest",
    "mac",
];
// Pinned base64 0.22.1 allocates ceil(encoded_length/4)*3, then truncates the
// resulting Vec without shrinking its capacity. The input is exactly 43 bytes.
const DIGEST_DECODE_CAPACITY: usize = ((43usize / 4) + 1) * 3;

/// Quotes all retained decoded backing, actual serde partials and diagnostics.
///
/// This DATA quote requires the unchanged allocation-free closed preflight
/// before constructing a decoder. It supplies no resource permission.
///
/// # Errors
/// Refuses unsupported tree layouts, checked overflow or a short restriction.
pub(super) fn construction_data(maximum: usize) -> Result<[usize; 3], ProviderError> {
    let envelope_text = envelope_text_data()?;
    let trees = tree_storage_data(
        4,
        MAP_KEYS.len(),
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let envelope = add(envelope_text, trees)?;
    let request = add(
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.len(),
        DIGEST_DECODE_CAPACITY,
    )?;
    let proof = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        DIGEST_DECODE_CAPACITY,
        DIGEST_DECODE_CAPACITY,
    ])?;
    let retained = sum(&[size_of::<Attempt>(), envelope, request, proof])?;

    let names = sum(&[
        Envelope::DIAGNOSTIC_NAMES_BYTES,
        PacketNativeImport18BootstrapRequest::DIAGNOSTIC_NAMES_BYTES,
        PacketNativeImport18BootstrapAckProof::DIAGNOSTIC_NAMES_BYTES,
    ])?;
    let diagnostic_text = sum(&[
        mul(6, envelope_text)?,
        names,
        serde_partials::diagnostic_format_text_bytes_data(),
        size_of::<[u8; 20]>(),
    ])?;
    let diagnostic = add(mul(8, diagnostic_text)?, 8)?;
    let transient_fields: [usize; 25] = [
        envelope,
        request,
        proof,
        diagnostic,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        Envelope::partial_counter_data(),
        PacketNativeImport18BootstrapRequest::partial_counter_data(),
        PacketNativeImport18BootstrapAckProof::partial_counter_data(),
        // An encoded Bytes String remains live while its output Vec is decoded.
        43,
        DIGEST_DECODE_CAPACITY,
        // Quoted numeric and Nullable-ID decoding can clone these leaves.
        mul(4, 20)?,
        MAX_ID_BYTES,
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Result<Envelope, serde_json::Error>>(),
        size_of::<PacketNativeImport18BootstrapRequest>(),
        size_of::<Option<PacketNativeImport18BootstrapRequest>>(),
        size_of::<Result<PacketNativeImport18BootstrapRequest, serde_json::Error>>(),
        size_of::<PacketNativeImport18BootstrapAckProof>(),
        size_of::<Option<PacketNativeImport18BootstrapAckProof>>(),
        size_of::<Result<PacketNativeImport18BootstrapAckProof, serde_json::Error>>(),
        size_of::<Attempt>(),
        size_of::<Result<Attempt, ProviderError>>(),
        size_of::<super::attempt::Failure>() * 2,
        size_of::<Option<super::attempt::Failure>>(),
    ];
    let transient = sum(&transient_fields)?;
    let row = [retained, transient, counter_scratch_data()];
    if sum(&row)? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

fn envelope_text_data() -> Result<usize, ProviderError> {
    let mut text = sum(&[
        "CNP/1".len(),
        mul(7, MAX_ID_BYTES)?,
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.len(),
        43,
        mul(3, 20)?,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        43,
        43,
    ])?;
    for key in MAP_KEYS {
        text = add(text, key.len())?;
    }
    Ok(text)
}

/// Names concrete derive visitors, census and fixed checked-quote controls.
pub(super) fn counter_scratch_data() -> usize {
    Envelope::partial_counter_data()
        + PacketNativeImport18BootstrapRequest::partial_counter_data()
        + PacketNativeImport18BootstrapAckProof::partial_counter_data()
        // The closed maps have at most four simultaneous census walk frames.
        + 4 * (size_of::<&Value>() + size_of::<&String>()
            + size_of::<(&String, &Value)>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>())
        + size_of::<&crate::envelope::Nullable<crucible_node_format::Id>>() * 7
        + size_of::<&crucible_node_format::Bytes>() * 3
        + size_of::<&String>() * 5
        + size_of::<&Envelope>()
        + size_of::<&PacketNativeImport18BootstrapRequest>()
        + size_of::<&PacketNativeImport18BootstrapAckProof>()
        + size_of::<[usize; 6]>() // Requested-backing sum fields.
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 9]>()
        + size_of::<[usize; 25]>()
        + size_of::<[usize; 11]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[usize]>()
        + size_of::<[&str; 11]>()
        + size_of::<std::array::IntoIter<&str, 11>>()
        + size_of::<&str>()
        + size_of::<usize>() * 8
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 3], ProviderError>>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
