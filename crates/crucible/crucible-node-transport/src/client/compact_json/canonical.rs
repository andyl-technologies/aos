//! Writes complete canonical envelopes into one exactly bounded output bank.
//!
//! Root fields borrow the concrete Envelope; nested objects use the defining
//! JCS writers. Measurement and output never construct a whole-envelope Value.
//! The original envelope, typed validation and correlation copies remain
//! independently owned, as does the strict parse performed by the connection.

use super::CompactJson;
use crate::{ProviderError, envelope::Envelope};
use crucible_node_format::{ContractError, canonical};
use serde::Serialize;
use std::io::{self, Write};

impl CompactJson {
    /// Names the actual direct-envelope output and field serializer controls.
    pub(in crate::client) fn canonical_encoding_counter_scratch_data() -> usize {
        use std::mem::size_of;

        Self::envelope_preflight_counter_scratch_data()
            + canonical::canonical_json_counter_scratch_bytes_data()
            + size_of::<Output>()
            + size_of::<serde_json::Serializer<&mut Output>>()
            + size_of::<&Envelope>()
            + size_of::<&mut Output>()
            + size_of::<&[u8]>()
            + size_of::<&str>()
            + 13 * size_of::<&serde_json::Value>()
            + size_of::<Vec<u8>>()
            + size_of::<Result<Vec<u8>, ProviderError>>()
            + size_of::<Result<Output, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), serde_json::Error>>()
            + size_of::<Result<(), io::Error>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Option<usize>>()
            + 3 * size_of::<usize>()
    }
}

/// Encodes inert envelope DATA without granting send or allocation authority.
///
/// # Errors
/// Refuses unsupported geometry, checked overflow, unavailable exact capacity,
/// canonical encoding failures or output beyond the independent byte ceiling.
pub(crate) fn encode_envelope(
    envelope: &Envelope,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProviderError> {
    let expected = envelope_encoded_bytes(envelope, maximum_bytes)?;
    let mut output = Output::new(expected)?;
    let result = write_envelope(envelope, &mut output);
    if output.refused {
        return Err(credit());
    }
    result?;
    if output.bytes.len() != expected {
        return Err(ProviderError::Frame("compact canonical envelope extent"));
    }
    Ok(output.bytes)
}

/// Measures the defining wire encoding before typed codec work or allocation.
///
/// # Errors
/// Refuses unsupported geometry, overflow or an encoding beyond the ceiling.
pub(crate) fn envelope_encoded_bytes(
    envelope: &Envelope,
    maximum_bytes: usize,
) -> Result<usize, ProviderError> {
    let maximum_bank = maximum_bytes.checked_mul(9).ok_or_else(credit)?;
    let (_, expected) = CompactJson::envelope_extents(envelope, maximum_bank, maximum_bytes)?;
    Ok(expected)
}

fn write_envelope(envelope: &Envelope, output: &mut Output) -> Result<(), ProviderError> {
    // A new Envelope field must be reviewed in both measurement and JCS order.
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
    } = envelope;

    output.write_all(b"{\"body\":")?;
    canonical::canonical_json_object_to_writer_at_depth(body, output, 1)?;
    field(output, b",\"capture_owner_id\":", capture_owner_id)?;
    field(output, b",\"execution_owner_id\":", execution_owner_id)?;
    output.write_all(b",\"extensions\":")?;
    canonical::canonical_json_btree_object_to_writer_at_depth(extensions, output, 1)?;
    field(output, b",\"incarnation_id\":", incarnation_id)?;
    field(output, b",\"message\":", message)?;
    field(output, b",\"method\":", method)?;
    field(output, b",\"node_id\":", node_id)?;
    field(output, b",\"operation_id\":", operation_id)?;
    field(output, b",\"protocol\":", protocol)?;
    field(output, b",\"request_id\":", request_id)?;
    field(output, b",\"sequence\":", sequence)?;
    field(output, b",\"session_id\":", session_id)?;
    output.write_all(b"}")?;
    Ok(())
}

pub(in crate::client) fn field(
    output: &mut Output,
    prefix: &[u8],
    value: &impl Serialize,
) -> Result<(), ProviderError> {
    output.write_all(prefix)?;
    serde_json::to_writer(output, value).map_err(ContractError::from)?;
    Ok(())
}

pub(in crate::client) struct Output {
    pub(in crate::client) bytes: Vec<u8>,
    pub(in crate::client) refused: bool,
}

impl Output {
    pub(in crate::client) fn new(requested: usize) -> Result<Self, ProviderError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(requested).map_err(|_| credit())?;
        if bytes.capacity() != requested {
            return Err(credit());
        }
        Ok(Self {
            bytes,
            refused: false,
        })
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.bytes.capacity() - self.bytes.len() {
            self.refused = true;
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("compact original journal credit")
}

#[cfg(test)]
mod tests;
