//! Allocation-aware CBOR helpers shared by fault-runtime artifacts.
//!
//! Canonical fault artifacts are admitted by encoded size before decoding.
//! [`scratch_bytes`] scans an encoded value once to find its longest text or
//! byte string, so the decoder's scratch buffer is sized to the input rather
//! than to a fixed guess. Collection sizes are bounded by the encoded input and
//! by the fallible owned-allocation budget, never by a whole-trace ceiling:
//! run-length traces are decoded one bounded segment at a time.

use super::*;

const MAX_DEPTH: usize = 128;

/// Returns the scratch length needed to decode one canonical CBOR value.
///
/// # Errors
///
/// Returns [`FaultRuntimeError::CheckpointEncoding`] for malformed CBOR, a
/// value nested beyond the supported depth, or trailing bytes.
pub(super) fn scratch_bytes(payload: &[u8]) -> Result<usize, FaultRuntimeError> {
    let mut cursor = CborCursor::new(payload);
    cursor.skip_value(0)?;
    if cursor.offset != payload.len() {
        return Err(FaultRuntimeError::CheckpointEncoding);
    }
    Ok(cursor.max_scalar_bytes)
}

pub(super) fn map_decode_error<T>(error: ciborium::de::Error<T>) -> FaultRuntimeError {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let mut fields = message.split('|');
    if fields.next() != Some("crucible-resource-limit") {
        return FaultRuntimeError::CheckpointEncoding;
    }
    let Some(field) = fields.next() else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let field = match field {
        "fat_checkpoint_bytes" => "fat_checkpoint_bytes",
        "thin_replay_events" => "thin_replay_events",
        "resolved_effect_records" => "resolved_effect_records",
        _ => return FaultRuntimeError::CheckpointEncoding,
    };
    let Some(current) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(requested) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(configured) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(hard) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    if fields.next().is_some() {
        return FaultRuntimeError::CheckpointEncoding;
    }
    resource(field, current, requested, configured, hard)
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> FaultRuntimeError {
    FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_scalar_bytes: usize,
}

impl<'a> CborCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            max_scalar_bytes: 0,
        }
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), FaultRuntimeError> {
        if depth >= MAX_DEPTH {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let argument = self.argument(initial & 0x1f)?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                self.observe_scalar(argument)?;
                self.take(argument).map(|_| ())
            }
            4 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            6 => self.skip_value(depth + 1),
            _ => Err(FaultRuntimeError::CheckpointEncoding),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, FaultRuntimeError> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.array()?))),
            27 => Ok(u64::from_be_bytes(self.array()?)),
            _ => Err(FaultRuntimeError::CheckpointEncoding),
        }
    }

    fn byte(&mut self) -> Result<u8, FaultRuntimeError> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        self.offset += 1;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FaultRuntimeError> {
        self.take(u64::try_from(N).unwrap_or(u64::MAX))?
            .try_into()
            .map_err(|_| FaultRuntimeError::CheckpointEncoding)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], FaultRuntimeError> {
        let length = usize::try_from(length).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn observe_scalar(&mut self, length: u64) -> Result<(), FaultRuntimeError> {
        let length = usize::try_from(length).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        self.max_scalar_bytes = self.max_scalar_bytes.max(length);
        Ok(())
    }
}
