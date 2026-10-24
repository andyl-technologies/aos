//! Writes the existing initial response envelope through borrowed canonical fields.
//!
//! The outer ASCII field roster follows UTF-16 order. Body and extension maps use
//! the authoritative JCS object writer at their actual enclosing depth. No Value
//! wrapper, cloned DOM, alternate number formatter or request re-encoding occurs.

use crate::ProviderError;
use crate::envelope::{Envelope, Nullable};
use crucible_node_format::{ContractError, Id, U64, canonical};
use serde::{Serialize, Serializer};
use std::io::{self, Write};
use std::mem::size_of;

/// Writes an already authenticated envelope without constructing another DOM.
///
/// The caller admits canonical ordering/formatter work and its bounded sink
/// before invoking this helper. It must retain any partially initialized output.
///
/// # Errors
/// Refuses the authoritative JCS depth, numeric or array limits, or sink errors.
pub(crate) fn write_response_data(
    response: &Envelope,
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    let Envelope {
        protocol,
        message,
        session_id,
        incarnation_id,
        node_id,
        execution_owner_id,
        capture_owner_id,
        request_id,
        operation_id,
        sequence,
        method,
        body,
        extensions,
    } = response;

    output.write_all(b"{\"body\":")?;
    canonical::canonical_json_object_to_writer_at_depth(body, output, 1)?;
    output.write_all(b",\"capture_owner_id\":")?;
    scalar(capture_owner_id, output)?;
    output.write_all(b",\"execution_owner_id\":")?;
    scalar(execution_owner_id, output)?;
    output.write_all(b",\"extensions\":")?;
    canonical::canonical_json_btree_object_to_writer_at_depth(extensions, output, 1)?;
    output.write_all(b",\"incarnation_id\":")?;
    scalar(incarnation_id, output)?;
    output.write_all(b",\"message\":")?;
    scalar(message, output)?;
    output.write_all(b",\"method\":")?;
    scalar(method, output)?;
    output.write_all(b",\"node_id\":")?;
    scalar(node_id, output)?;
    output.write_all(b",\"operation_id\":")?;
    scalar(operation_id, output)?;
    output.write_all(b",\"protocol\":")?;
    scalar(protocol, output)?;
    output.write_all(b",\"request_id\":")?;
    scalar(request_id, output)?;
    output.write_all(b",\"sequence\":")?;
    scalar(sequence, output)?;
    output.write_all(b",\"session_id\":")?;
    scalar(session_id, output)?;
    output.write_all(b"}")?;
    Ok(())
}

// Every caller above is a typed string, unit variant, nullable Id or U64. Numeric
// Value leaves stay exclusively in the authoritative canonical map writer.
fn scalar(value: &impl Serialize, output: &mut impl Write) -> Result<(), ProviderError> {
    serde_json::to_writer(output, value).map_err(ContractError::from)?;
    Ok(())
}

/// Names canonical work and the closed, sequential scalar-header serializer.
///
/// Dynamic map ordering/formatting and output backing are separate constructor
/// terms. W names the actual caller's sink, without constructing one here.
pub(crate) fn counter_scratch_data<W: Write + 'static>() -> usize {
    type Json<W> = serde_json::Serializer<&'static mut W>;
    type Borrowed<W> = &'static mut Json<W>;
    let scalar_layer = size_of::<Json<W>>() * 2
        + size_of::<&mut Json<W>>() * 3
        + size_of::<<Borrowed<W> as Serializer>::SerializeSeq>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeTuple>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeTupleStruct>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeTupleVariant>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeMap>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeStruct>()
        + size_of::<<Borrowed<W> as Serializer>::SerializeStructVariant>()
        + size_of::<serde_json::ser::CharEscape>()
        + size_of::<serde_json::ser::CompactFormatter>()
        + size_of::<&mut serde_json::ser::CompactFormatter>() * 3
        + size_of::<&mut W>() * 4
        + size_of::<&str>() * 5
        + size_of::<&[u8]>() * 8
        + size_of::<Option<(&u8, &[u8])>>()
        + size_of::<(&[u8], &[u8])>()
        + size_of::<[u8; 6]>()
        + size_of::<[u8; 2]>()
        + size_of::<[u8; 4]>()
        + size_of::<u8>() * 4
        + size_of::<usize>() * 5
        + size_of::<Option<usize>>() * 3
        + size_of::<bool>() * 3
        + size_of::<Result<(), serde_json::Error>>() * 4
        + size_of::<Result<(), io::Error>>() * 4
        + size_of::<Result<usize, io::Error>>() * 2;
    // Nullable -> Option<Id> -> Id -> String is the longest closed header path.
    // The U64 branch independently carries its allocation-free decimal buffer.
    canonical::canonical_json_counter_scratch_bytes_data()
        + 4 * scalar_layer
        + size_of::<[u8; 20]>()
        + size_of::<Result<&'static str, std::str::Utf8Error>>()
        + size_of::<&Envelope>()
        + size_of::<&String>()
        + size_of::<&Nullable<Id>>() * 8
        + size_of::<&crate::envelope::MessageKind>()
        + size_of::<&crate::envelope::Method>()
        + size_of::<&U64>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<&crucible_node_format::Extensions>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<Result<(), ContractError>>() * 2
        + size_of::<serde_json::Error>()
        + size_of::<io::Error>()
}

#[cfg(test)]
#[path = "canonical_response_tests.rs"]
mod tests;
