//! Shares the original checked serialized-byte sink without a connection owner.

use super::ProviderError;
use serde::Serialize;
use std::io::{self, Write};

/// Names the original private writer's unchanged credit-refusal diagnostic.
pub const SERIALIZED_CREDIT_FAILURE_MESSAGE: &str = "prepared frame exceeds complete byte credit";

/// Counts the original complete JSON formatter output against its byte ceiling.
///
/// # Errors
/// Refuses formatting failure, overflow or a complete encoding above maximum.
pub fn serialized_credit(value: &impl Serialize, maximum: usize) -> Result<usize, ProviderError> {
    let mut counter = SerializedCreditCounter { used: 0, maximum };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| ProviderError::ResourceExhausted("prepared whole frame bytes"))?;
    Ok(counter.used)
}

/// Counts original formatter chunks against one private byte-credit bound.
pub struct SerializedCreditCounter {
    used: usize,
    maximum: usize,
}

impl SerializedCreditCounter {
    /// Starts a private projected count without serializing placeholder bytes.
    pub fn projection_data(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    /// Returns actual counted JSON bytes after successful projection.
    pub fn used_data(&self) -> usize {
        self.used
    }

    /// Counts an exact opaque JSON extent at its original field position.
    ///
    /// This is not a Write operation or evidence that any bytes were emitted.
    /// The unchanged real writer below remains the formatter's checked sink.
    ///
    /// # Errors
    /// Returns the original whole-frame resource error on overflow or when the
    /// declared extent exceeds the remaining maximum.
    pub fn advance_projection_data(&mut self, bytes: usize) -> Result<(), ProviderError> {
        let next = self
            .used
            .checked_add(bytes)
            .filter(|next| *next <= self.maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "prepared whole frame bytes",
            ))?;
        self.used = next;
        Ok(())
    }
}

impl Write for SerializedCreditCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .used
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::other(SERIALIZED_CREDIT_FAILURE_MESSAGE))?;
        self.used = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Names actual counting writer/serializer headers before their borrowed walk.
pub fn original_serialized_credit_counter_scratch_data() -> usize {
    std::mem::size_of::<SerializedCreditCounter>()
        + std::mem::size_of::<serde_json::Serializer<&mut SerializedCreditCounter>>()
}
