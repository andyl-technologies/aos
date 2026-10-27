//! Logical native-console byte origins, independent of transport acceptance.
//!
//! The fixed V1 material contains no slot, PID, mapping, authorization token,
//! accepted clamp coordinate or transport-plan hash. Its original raw prefix
//! is preserved; cross-restore equality is a separate backend obligation.
//!
//! ```text
//! NCLOG001 | device[32] | stream:u32 | generation:u64 | node_seq:u64
//!          | stream_seq:u64 | emitted_ps:u64 | raw:u64 | vcpu:u32 | byte:u8
//!          | reserved_zero[7]
//! ```

use crate::ContentHash;

mod mapping;
pub use mapping::NativeConsoleMappingLease;

#[cfg(test)]
mod tests;

/// Exact size of the V1 logical byte-origin encoding.
pub const NATIVE_CONSOLE_ORIGIN_BYTES: usize = 96;

/// Complete logical origin of one native architectural UART byte.
///
/// Shape validation does not authenticate native custody or authorize an
/// operation. An execution adapter must prove those original owners before
/// publishing this value. Host admission and condition evaluation coordinates
/// are intentionally absent from the byte's canonical origin.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NativeConsoleByteOrigin {
    /// Stable admitted logical device identity, excluding physical resources.
    pub device: ContentHash,
    /// Stable nonzero logical stream identifier.
    pub stream: u32,
    /// Retained logical lifecycle generation.
    pub logical_generation: u64,
    /// Cumulative node byte sequence, beginning at one.
    pub node_sequence: u64,
    /// Cumulative stream byte sequence, beginning at one.
    pub stream_sequence: u64,
    /// Original native logical picoseconds at emission.
    pub emitted_ps: u64,
    /// Original raw executed prefix, without normalization or restamping.
    pub raw_prefix: u64,
    /// Actual admitted architectural vCPU index.
    pub vcpu: u32,
    /// Exact byte, including zero and non-UTF8 values.
    pub byte: u8,
}

/// A malformed logical origin or noncanonical V1 encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native-console logical origin is malformed")]
pub struct NativeConsoleOriginError;

impl NativeConsoleByteOrigin {
    /// Validates the fixed origin vocabulary without granting execution.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleOriginError`] for absent device/stream/sequence
    /// identity or a vCPU outside the V1 64-owner vocabulary.
    pub fn validate(&self) -> Result<(), NativeConsoleOriginError> {
        if self.device.bytes == [0; 32]
            || self.stream == 0
            || self.node_sequence == 0
            || self.stream_sequence == 0
            || self.vcpu >= 64
        {
            return Err(NativeConsoleOriginError);
        }
        Ok(())
    }

    /// Encodes every logical origin field with exact framing and zero padding.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleOriginError`] when the origin is malformed.
    pub fn to_canonical_bytes(
        &self,
    ) -> Result<[u8; NATIVE_CONSOLE_ORIGIN_BYTES], NativeConsoleOriginError> {
        self.validate()?;
        let mut bytes = [0; NATIVE_CONSOLE_ORIGIN_BYTES];
        bytes[..8].copy_from_slice(b"NCLOG001");
        bytes[8..40].copy_from_slice(&self.device.bytes);
        bytes[40..44].copy_from_slice(&self.stream.to_le_bytes());
        for (offset, value) in [
            (44, self.logical_generation),
            (52, self.node_sequence),
            (60, self.stream_sequence),
            (68, self.emitted_ps),
            (76, self.raw_prefix),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[84..88].copy_from_slice(&self.vcpu.to_le_bytes());
        bytes[88] = self.byte;
        Ok(bytes)
    }

    /// Decodes the exact closed V1 material without accepting alternate framing.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleOriginError`] for incorrect length, magic,
    /// padding or logical fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NativeConsoleOriginError> {
        let bytes: &[u8; NATIVE_CONSOLE_ORIGIN_BYTES] =
            bytes.try_into().map_err(|_| NativeConsoleOriginError)?;
        if &bytes[..8] != b"NCLOG001" || bytes[89..].iter().any(|byte| *byte != 0) {
            return Err(NativeConsoleOriginError);
        }
        let mut device = [0; 32];
        device.copy_from_slice(&bytes[8..40]);
        let u32_at = |offset| {
            let mut field = [0; 4];
            field.copy_from_slice(&bytes[offset..offset + 4]);
            u32::from_le_bytes(field)
        };
        let u64_at = |offset| {
            let mut field = [0; 8];
            field.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(field)
        };
        let value = Self {
            device: ContentHash { bytes: device },
            stream: u32_at(40),
            logical_generation: u64_at(44),
            node_sequence: u64_at(52),
            stream_sequence: u64_at(60),
            emitted_ps: u64_at(68),
            raw_prefix: u64_at(76),
            vcpu: u32_at(84),
            byte: bytes[88],
        };
        value.validate()?;
        Ok(value)
    }
}
