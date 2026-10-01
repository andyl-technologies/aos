//! Implements exact canonical D-79 evidence schemas without native authority.
//!
//! ```text
//! physical-registration = [1, id, root, domain, dev, ino, lock_dev,
//!                          lock_ino, control]
//!                       / [2, id, domain, remote_binding, control]
//! ```

use super::validation::Validate;
use super::*;
use crate::cbor::{Decoder, write_array, write_bytes, write_map, write_text, write_uint};
use alloc::string::ToString;

mod guard;
mod lineage;
mod original;

trait Record: Sized {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError>;
    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError>;
}

macro_rules! codec {
    ($($record:ty),+ $(,)?) => {$(
        impl $record {
            /// Encodes the untrusted value with its exact canonical record shape.
            ///
            /// # Errors
            /// Rejects invalid fields, unregistered revisions, and contradictions
            /// decidable from represented evidence. No private capability is created.
            pub fn encode(&self) -> Result<Vec<u8>, EvidenceError> {
                self.validate()?;
                let mut output = Vec::new();
                self.write(&mut output)?;
                Ok(output)
            }

            /// Decodes canonical bytes as untrusted typed evidence.
            ///
            /// # Errors
            /// Rejects noncanonical or oversized input, unknown fields or revisions,
            /// invalid shapes, represented contradictions, and trailing bytes.
            pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
                let mut decoder = Decoder::new(bytes);
                let record = read::<Self>(&mut decoder)?;
                decoder.finish()?;
                Ok(record)
            }
        }
    )+};
}

codec!(
    LocalOriginalRegistration,
    PhysicalRegistration,
    OriginalBootstrap,
    OriginalAssociation,
    OriginalImport,
    OriginalImportBinding,
    OriginalImportTrust,
    IssuerRow,
    DisclosureRow,
    SeededChunkProfile,
    TrustedGuardConfig,
    ConfiguredRegistryInputs,
    GuardSnapshot,
    RequiredControlPin,
    ConsumedRootPolicy,
    ConsumedViewPolicy,
    LineageUsedInputs,
    CheckedLineage
);

fn read<T: Record + Validate>(decoder: &mut Decoder<'_>) -> Result<T, EvidenceError> {
    let record = T::read(decoder)?;
    record.validate()?;
    Ok(record)
}

fn array(decoder: &mut Decoder<'_>, expected: usize) -> Result<(), EvidenceError> {
    if decoder.array(expected)? != expected {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn version(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), EvidenceError> {
    if decoder.uint()? != expected {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), EvidenceError> {
    version(decoder, expected)
}

fn map(decoder: &mut Decoder<'_>, count: usize) -> Result<(), EvidenceError> {
    if decoder.map(count)? != count {
        return Err(EvidenceError::Schema);
    }
    key(decoder, 0)?;
    version(decoder, 1)
}

fn header(output: &mut Vec<u8>, count: usize) {
    write_map(output, count);
    write_uint(output, 0);
    write_uint(output, 1);
}

fn digest(decoder: &mut Decoder<'_>) -> Result<RawDigest, EvidenceError> {
    decoder
        .bytes(32)?
        .try_into()
        .map_err(|_| EvidenceError::Schema)
}

fn text(decoder: &mut Decoder<'_>) -> Result<String, EvidenceError> {
    Ok(decoder.text(decoder.remaining().len())?.to_string())
}

fn bytes(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, EvidenceError> {
    Ok(decoder.bytes(decoder.remaining().len())?.to_vec())
}

fn optional<T>(
    decoder: &mut Decoder<'_>,
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T, EvidenceError>,
) -> Result<Option<T>, EvidenceError> {
    if decoder.peek_major()? == 7 {
        if decoder.simple()? != 0xf6 {
            return Err(EvidenceError::Schema);
        }
        Ok(None)
    } else {
        Ok(Some(read(decoder)?))
    }
}

fn write_optional<T: ?Sized>(
    output: &mut Vec<u8>,
    value: Option<&T>,
    write: impl FnOnce(&T, &mut Vec<u8>),
) {
    if let Some(value) = value {
        write(value, output);
    } else {
        output.push(0xf6);
    }
}

fn read_rows<T: Record + Validate>(decoder: &mut Decoder<'_>) -> Result<Vec<T>, EvidenceError> {
    let count = decoder.array(decoder.remaining().len())?;
    // Collection headers are input-bounded before allocation. Gradual growth
    // also avoids reserving a large typed collection from a short forged body.
    let mut rows = Vec::new();
    for _ in 0..count {
        rows.push(read(decoder)?);
    }
    Ok(rows)
}

fn write_rows<T: Record>(output: &mut Vec<u8>, rows: &[T]) -> Result<(), EvidenceError> {
    write_array(output, rows.len());
    for row in rows {
        row.write(output)?;
    }

    Ok(())
}

fn binding(decoder: &mut Decoder<'_>) -> Result<BackendBinding, EvidenceError> {
    Ok(BackendBinding::decode(
        decoder.raw_value(decoder.remaining().len())?,
    )?)
}

fn write_binding(binding: &BackendBinding, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
    output.extend_from_slice(&binding.encode()?);
    Ok(())
}

#[cfg(test)]
mod tests;
