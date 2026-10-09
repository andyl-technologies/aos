//! Native-console process contract, without execution authority.
//!
//! These codecs require the coordinated ABI-31/control-4/setup-3 boundary.
//! They do not authenticate a phase transaction, resolve a native UART, or
//! authorize guest execution. Each process adapter must
//! bind each decoded value to its original owned process and phase fence.
//!
//! Integer fields are little-endian; fixed records contain only scalar values
//! and byte arrays. Reserved bytes are zero and unknown versions refuse.
//!
//! ```text
//! record: NCOR | version:u16 | length:u16 | owner | sequences | origin | byte
//! plan:   NCPLAN01 | version:u16 | header:u16 | length:u32 | bounded stream rows
//! ```

mod clamp;
mod operation_stop;
mod plan;
mod setup;
mod snapshots;
#[cfg(test)]
mod tests;

pub use clamp::*;
pub use operation_stop::*;
pub use plan::*;
pub use setup::*;
pub use snapshots::*;

use thiserror::Error;

/// Required shared-memory ABI for native-console admission.
pub const NATIVE_CONSOLE_REQUIRED_SHMEM_ABI: u32 = 31;
/// Required control-protocol version for native-console admission.
pub const NATIVE_CONSOLE_REQUIRED_CONTROL_VERSION: u32 = 4;
/// Required composite setup schema for native-console admission.
pub const NATIVE_CONSOLE_REQUIRED_SETUP_SCHEMA: u32 = 3;
/// Exact bytes in an immutable native-console record.
pub const NATIVE_CONSOLE_RECORD_BYTES: usize = 128;
/// Fixed records admitted in one native-console ring.
pub const NATIVE_CONSOLE_CAPACITY: u32 = 4_096;

/// A shape or ordering violation in the native-console contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NativeConsoleError {
    /// The body is not the exact canonical length.
    #[error("native-console length is invalid")]
    Length,
    /// A magic, version, or reserved field differs.
    #[error("native-console framing is invalid")]
    Framing,
    /// A required scalar or closed enum is invalid.
    #[error("native-console field is invalid")]
    Field,
    /// The plan has duplicate, unordered, or unsupported stream owners.
    #[error("native-console stream plan is invalid")]
    Plan,
    /// An expected authenticated tuple differs from the record or frontier.
    #[error("native-console owner or frontier differs")]
    Binding,
    /// A sequence, cursor, or allowance cannot advance exactly.
    #[error("native-console sequence or allowance is invalid")]
    Sequence,
}

/// Closed phase vocabulary; these values do not themselves grant execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NativeConsolePhase {
    /// An existing authenticated execution grant.
    Grant = 1,
    /// An existing authenticated cold-setup fence.
    ColdSetup = 2,
    /// An existing authenticated restore fence.
    Restore = 3,
    /// An existing authenticated idle-service fence.
    IdleService = 4,
}

impl TryFrom<u8> for NativeConsolePhase {
    type Error = NativeConsoleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Grant),
            2 => Ok(Self::ColdSetup),
            3 => Ok(Self::Restore),
            4 => Ok(Self::IdleService),
            _ => Err(NativeConsoleError::Field),
        }
    }
}

/// Physical tuple used only for transport authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleOwner {
    /// Physical VM slot in the owned region.
    pub slot: u32,
    /// Physical region incarnation, distinct from canonical node identity.
    pub region: [u8; 16],
    /// Nonzero physical process incarnation.
    pub process: u64,
    /// Nonzero authorization incarnation.
    pub authorization: u64,
}

impl NativeConsoleOwner {
    pub(super) fn validate(self) -> Result<(), NativeConsoleError> {
        if self.region == [0; 16] || self.process == 0 || self.authorization == 0 {
            return Err(NativeConsoleError::Field);
        }
        Ok(())
    }
}

/// Original logical byte origin, excluding physical transport identities.
///
/// Raw-prefix equality across restore remains a separate native restoration
/// obligation. This codec never normalizes or restamps an observed origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleOrigin {
    /// Closed, nonzero logical stream identifier.
    pub stream: u32,
    /// Stable logical lifecycle generation.
    pub logical_generation: u64,
    /// Cumulative node byte sequence, starting at one.
    pub node_sequence: u64,
    /// Cumulative per-stream byte sequence, starting at one.
    pub stream_sequence: u64,
    /// Original logical picoseconds, including the native SIM bias.
    pub logical_ps: u64,
    /// Original raw executed prefix in the existing native unit.
    pub raw_prefix: u64,
    /// Actual owning vCPU index.
    pub vcpu: u32,
    /// Exact emitted byte, including zero and non-UTF8 values.
    pub byte: u8,
}

/// One immutable native-console byte and its original authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleRecord {
    /// Physical authentication tuple; never canonical artifact material.
    pub owner: NativeConsoleOwner,
    /// Immutable original byte origin.
    pub origin: NativeConsoleOrigin,
    /// Original authorization's advance publication, not the later clamp.
    pub authorization_advance: u64,
    /// Closed phase label whose authority must be authenticated separately.
    pub phase: NativeConsolePhase,
}

impl NativeConsoleRecord {
    /// Encodes one exact record after validating its shape.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for absent owner or sequence fields,
    /// unsupported vCPU indices or an odd in-progress advance publication.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_RECORD_BYTES], NativeConsoleError> {
        self.owner.validate()?;
        if self.origin.stream == 0
            || self.origin.node_sequence == 0
            || self.origin.stream_sequence == 0
            || self.origin.vcpu >= 64
            || self.authorization_advance & 1 != 0
        {
            return Err(NativeConsoleError::Field);
        }
        let mut out = [0; NATIVE_CONSOLE_RECORD_BYTES];
        out[..4].copy_from_slice(b"NCOR");
        put16(&mut out, 4, 1);
        put16(&mut out, 6, NATIVE_CONSOLE_RECORD_BYTES as u16);
        put32(&mut out, 8, self.owner.slot);
        put32(&mut out, 12, self.origin.stream);
        out[16..32].copy_from_slice(&self.owner.region);
        for (offset, value) in [
            (32, self.owner.process),
            (40, self.owner.authorization),
            (48, self.origin.logical_generation),
            (56, self.origin.node_sequence),
            (64, self.origin.stream_sequence),
            (72, self.origin.logical_ps),
            (80, self.origin.raw_prefix),
            (88, self.authorization_advance),
        ] {
            put64(&mut out, offset, value);
        }
        put32(&mut out, 96, self.origin.vcpu);
        out[100] = self.phase as u8;
        out[101] = self.origin.byte;
        Ok(out)
    }

    /// Decodes one exact immutable record, rejecting unknown framing.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for invalid length, framing, fields or
    /// reserved bytes. Successful decoding proves shape, not origin custody.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_RECORD_BYTES)?;
        if &bytes[..4] != b"NCOR"
            || get16(bytes, 4) != 1
            || usize::from(get16(bytes, 6)) != NATIVE_CONSOLE_RECORD_BYTES
            || bytes[102..].iter().any(|value| *value != 0)
        {
            return Err(NativeConsoleError::Framing);
        }
        let mut region = [0; 16];
        region.copy_from_slice(&bytes[16..32]);
        let value = Self {
            owner: NativeConsoleOwner {
                slot: get32(bytes, 8),
                region,
                process: get64(bytes, 32),
                authorization: get64(bytes, 40),
            },
            origin: NativeConsoleOrigin {
                stream: get32(bytes, 12),
                logical_generation: get64(bytes, 48),
                node_sequence: get64(bytes, 56),
                stream_sequence: get64(bytes, 64),
                logical_ps: get64(bytes, 72),
                raw_prefix: get64(bytes, 80),
                vcpu: get32(bytes, 96),
                byte: bytes[101],
            },
            authorization_advance: get64(bytes, 88),
            phase: bytes[100].try_into()?,
        };
        value.encode()?;
        Ok(value)
    }
}

pub(super) fn exact(bytes: &[u8], length: usize) -> Result<(), NativeConsoleError> {
    if bytes.len() != length {
        return Err(NativeConsoleError::Length);
    }
    Ok(())
}

pub(super) fn put16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn get16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

pub(super) fn get32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

pub(super) fn get64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}
