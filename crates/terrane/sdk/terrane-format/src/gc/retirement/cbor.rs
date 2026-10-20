//! Implements disjoint D-82 deterministic records without granting authority.
//!
//! ```text
//! sweep = {0: 2, 1: nonce, ..., 7: witness, ..., 13: 1}
//! copy = {0: 2, 1: nonce, ..., 14: 1, 15: genesis, 16: preparation}
//! ```

mod authorization;
mod fence;
mod progress;

use super::*;
use crate::cbor::{Decoder, write_array, write_bytes, write_map, write_text, write_uint};
use alloc::string::ToString;

pub(super) trait Record: Sized {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError>;
    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError>;
}

macro_rules! codec {
    ($($record:ty),+ $(,)?) => {$(
        impl $record {
            /// Encodes the exact untrusted canonical D-82 representation.
            ///
            /// # Errors
            /// Rejects malformed fields, limits, arithmetic overflow and represented contradictions.
            pub fn encode(&self) -> Result<Vec<u8>, RetirementError> {
                let mut output = Vec::new();
                self.write(&mut output)?;
                Self::decode(&output)?;
                Ok(output)
            }

            /// Decodes a canonical record without granting physical or elapsed permission.
            ///
            /// # Errors
            /// Rejects noncanonical, unknown, oversized, contradictory or trailing input.
            pub fn decode(bytes: &[u8]) -> Result<Self, RetirementError> {
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(crate::cbor::Error::Limit.into());
                }
                let mut decoder = Decoder::new(bytes);
                let record = Self::read(&mut decoder)?;
                decoder.finish()?;
                Ok(record)
            }
        }
    )+};
}

codec!(
    PermanentDeleteAuthorization,
    RemoteSweepDeleteAuthorization,
    CopiedRetirementAuthorization,
    CopiedRetirementPlan,
    CopiedRetirementPreparation,
    PermanentDeleteOperation,
    PermanentDeletePass,
    PermanentBurnOwner,
    PermanentOwnerSelection,
    CopiedPlacementFence,
    CurrentCollectionFence
);

fn array(decoder: &mut Decoder<'_>, expected: usize) -> Result<(), RetirementError> {
    if decoder.array(expected)? != expected {
        return Err(RetirementError::Schema);
    }
    Ok(())
}

fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), RetirementError> {
    if decoder.uint()? != expected {
        return Err(RetirementError::Schema);
    }
    Ok(())
}

fn version(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), RetirementError> {
    key(decoder, 0)?;
    if decoder.uint()? != expected {
        return Err(RetirementError::Schema);
    }
    Ok(())
}

fn header(output: &mut Vec<u8>, count: usize) {
    write_map(output, count);
    field(output, 0, 2);
}

fn field(output: &mut Vec<u8>, key: u64, value: u64) {
    write_uint(output, key);
    write_uint(output, value);
}

fn digest<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], RetirementError> {
    decoder
        .bytes(N)?
        .try_into()
        .map_err(|_| RetirementError::Schema)
}

fn text(decoder: &mut Decoder<'_>) -> Result<String, RetirementError> {
    Ok(decoder.text(4096)?.to_string())
}

fn blob(decoder: &mut Decoder<'_>, limit: usize) -> Result<Vec<u8>, RetirementError> {
    Ok(decoder.bytes(limit)?.to_vec())
}

fn embedded<T>(
    decoder: &mut Decoder<'_>,
    read: impl FnOnce(&[u8]) -> Result<T, RetirementError>,
) -> Result<T, RetirementError> {
    let start = decoder.position();
    decoder.skip_value(MAX_RECORD_BYTES)?;
    read(decoder.slice(start, decoder.position())?)
}

fn backend(decoder: &mut Decoder<'_>) -> Result<BackendBinding, RetirementError> {
    embedded(decoder, |bytes| Ok(BackendBinding::decode(bytes)?))
}

fn lease(decoder: &mut Decoder<'_>) -> Result<GcLease, RetirementError> {
    embedded(decoder, |bytes| Ok(GcLease::decode(bytes)?))
}

fn null(decoder: &mut Decoder<'_>) -> Result<(), RetirementError> {
    if decoder.simple()? != 0xf6 {
        return Err(RetirementError::Schema);
    }
    Ok(())
}

fn optional<T>(
    decoder: &mut Decoder<'_>,
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T, RetirementError>,
) -> Result<Option<T>, RetirementError> {
    if decoder.peek_major()? == 7 {
        null(decoder)?;
        Ok(None)
    } else {
        Ok(Some(read(decoder)?))
    }
}

fn write_optional<T>(
    output: &mut Vec<u8>,
    value: Option<&T>,
    write: impl FnOnce(&T, &mut Vec<u8>) -> Result<(), RetirementError>,
) -> Result<(), RetirementError> {
    match value {
        Some(value) => write(value, output),
        None => {
            output.push(0xf6);
            Ok(())
        }
    }
}

fn pointer(decoder: &mut Decoder<'_>) -> Result<RecordPointer, RetirementError> {
    array(decoder, 2)?;
    Ok(RecordPointer {
        key: text(decoder)?,
        digest: digest(decoder)?,
    })
}

fn write_pointer(value: &RecordPointer, output: &mut Vec<u8>) -> Result<(), RetirementError> {
    write_array(output, 2);
    write_text(output, &value.key);
    write_bytes(output, &value.digest);
    Ok(())
}

fn slot(decoder: &mut Decoder<'_>) -> Result<OwnershipSlot, RetirementError> {
    array(decoder, 2)?;
    Ok(OwnershipSlot {
        revision: decoder.uint()?,
        digest: digest(decoder)?,
    })
}

fn write_slot(value: &OwnershipSlot, output: &mut Vec<u8>) -> Result<(), RetirementError> {
    write_array(output, 2);
    write_uint(output, value.revision);
    write_bytes(output, &value.digest);
    Ok(())
}

fn exclusion(decoder: &mut Decoder<'_>) -> Result<Exclusion, RetirementError> {
    array(decoder, 3)?;
    Ok(Exclusion {
        pack: digest(decoder)?,
        cycle: decoder.uint()?,
        epoch: decoder.uint()?,
    })
}

fn write_exclusion(value: &Exclusion, output: &mut Vec<u8>) {
    write_array(output, 3);
    write_bytes(output, &value.pack);
    write_uint(output, value.cycle);
    write_uint(output, value.epoch);
}

fn artifact(decoder: &mut Decoder<'_>) -> Result<RemoteArtifact, RetirementError> {
    array(decoder, 3)?;
    Ok(RemoteArtifact {
        key: text(decoder)?,
        digest: digest(decoder)?,
        size: decoder.uint()?,
    })
}

fn write_artifact(value: &RemoteArtifact, output: &mut Vec<u8>) {
    write_array(output, 3);
    write_text(output, &value.key);
    write_bytes(output, &value.digest);
    write_uint(output, value.size);
}

fn barrier(decoder: &mut Decoder<'_>) -> Result<BarrierArtifact, RetirementError> {
    let count = decoder.array(4)?;
    let key = text(decoder)?;
    let identity = digest(decoder)?;
    match count {
        3 => Ok(BarrierArtifact::Remote(RemoteArtifact {
            key,
            digest: identity,
            size: decoder.uint()?,
        })),
        4 => {
            array(decoder, 2)?;
            if decoder.uint()? != 2 {
                return Err(RetirementError::Schema);
            }
            let tombstone = blob(decoder, 128)?;
            let file_identity = blob(decoder, 128)?;
            if file_identity.is_empty() {
                return Err(RetirementError::Schema);
            }
            Ok(BarrierArtifact::Local(LocalBarrierArtifact {
                key,
                nonce: identity,
                tombstone,
                file_identity,
            }))
        }
        _ => Err(RetirementError::Schema),
    }
}

fn write_barrier(value: &BarrierArtifact, output: &mut Vec<u8>) {
    match value {
        BarrierArtifact::Remote(value) => write_artifact(value, output),
        BarrierArtifact::Local(value) => {
            write_array(output, 4);
            write_text(output, &value.key);
            write_bytes(output, &value.nonce);
            write_array(output, 2);
            write_uint(output, 2);
            write_bytes(output, &value.tombstone);
            write_bytes(output, &value.file_identity);
        }
    }
}
