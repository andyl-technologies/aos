//! Allocation-safe aggregate codec helpers for fault-runtime checkpoints.
//!
//! The runtime checkpoint keeps its established CBOR representation. Encoding
//! measures that representation before allocating and then writes into one
//! fallibly reserved buffer. Decoding admits the complete input against the
//! scenario-owned byte contract before CBOR can allocate nested state.

use std::io::{self, Write};

use serde::Serialize;

use super::{FaultResourceLimitError, FaultResourceLimits, FaultRuntimeError};

pub(in crate::model::fault_signal) fn encode<T: Serialize>(
    value: &T,
    resource_limits: FaultResourceLimits,
) -> Result<Vec<u8>, FaultRuntimeError> {
    encode_prefixed(value, &[], resource_limits)
}

pub(super) fn encode_prefixed<T: Serialize>(
    value: &T,
    prefix: &[u8],
    resource_limits: FaultResourceLimits,
) -> Result<Vec<u8>, FaultRuntimeError> {
    let maximum = resource_limits.fat_checkpoint_bytes;
    let hard = FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes;
    let mut counter = CountingWriter::new(maximum, hard);
    ciborium::ser::into_writer(value, &mut counter).map_err(|_| {
        counter
            .failure
            .unwrap_or(FaultRuntimeError::CheckpointEncoding)
    })?;

    let prefix_length = u64::try_from(prefix.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    let length = admit(prefix_length, counter.length, maximum, hard)?;
    let length_usize = usize::try_from(length)
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length_usize)
        .map_err(|_| resource_error(0, length, maximum, hard))?;
    bytes.extend_from_slice(prefix);
    let mut writer = ReservedWriter::new(&mut bytes, length, hard);
    ciborium::ser::into_writer(value, &mut writer).map_err(|_| {
        writer
            .failure
            .unwrap_or(FaultRuntimeError::CheckpointEncoding)
    })?;
    if bytes.len() != length_usize {
        return Err(FaultRuntimeError::CheckpointEncoding);
    }
    Ok(bytes)
}

pub(super) fn admit_input(
    bytes: &[u8],
    resource_limits: FaultResourceLimits,
) -> Result<(), FaultRuntimeError> {
    let requested = u64::try_from(bytes.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
    resource_limits
        .reserve("fat_checkpoint_bytes", 0, requested)
        .map_err(FaultRuntimeError::ResourceLimit)
}

fn admit(
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<u64, FaultRuntimeError> {
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource_error(current, requested, configured, hard))?;
    if total > configured || total > hard {
        return Err(resource_error(current, requested, configured, hard));
    }
    Ok(total)
}

fn resource_error(current: u64, requested: u64, configured: u64, hard: u64) -> FaultRuntimeError {
    FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
        field: "fat_checkpoint_bytes",
        current,
        requested,
        configured,
        hard,
    })
}

struct CountingWriter {
    configured: u64,
    hard: u64,
    length: u64,
    failure: Option<FaultRuntimeError>,
}

impl CountingWriter {
    const fn new(configured: u64, hard: u64) -> Self {
        Self {
            configured,
            hard,
            length: 0,
            failure: None,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        self.length =
            admit(self.length, requested, self.configured, self.hard).map_err(|error| {
                self.failure = Some(error);
                io::Error::other("fault-runtime checkpoint exceeds its bound")
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReservedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: u64,
    hard: u64,
    failure: Option<FaultRuntimeError>,
}

impl<'a> ReservedWriter<'a> {
    fn new(bytes: &'a mut Vec<u8>, maximum: u64, hard: u64) -> Self {
        Self {
            bytes,
            maximum,
            hard,
            failure: None,
        }
    }
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        admit(current, requested, self.maximum, self.hard).map_err(|error| {
            self.failure = Some(error);
            io::Error::other("fault-runtime checkpoint exceeded its reservation")
        })?;
        if buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len()) {
            self.failure = Some(resource_error(current, requested, self.maximum, self.hard));
            return Err(io::Error::other(
                "fault-runtime checkpoint allocation changed",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
