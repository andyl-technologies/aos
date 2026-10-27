//! Framing for an accounted UART-operation stop, separate from byte emission.
//!
//! The native stopped completion publishes this record inside the original
//! node writer. Its shape proves neither native quiescence nor permission to
//! consume bytes; accepted control-frontier custody remains mandatory.

use super::*;

/// Exact bytes in the accounted console-operation stop table.
pub const NATIVE_CONSOLE_OPERATION_STOP_BYTES: usize = 128;

/// An original stopped completion and its immutable emitting authorization.
///
/// Accounted stopped coordinates can include the UART instruction that emitted
/// a byte. They remain separate from every record's original emission origin.
/// Physical fields authenticate transport and never enter canonical artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleOperationStop {
    /// Stable, nonzero even table publication.
    pub publication: u64,
    /// Sealed producer endpoint of the complete UART operation.
    pub ring_end: u64,
    /// Cumulative last byte sequence of that operation.
    pub node_sequence: u64,
    /// Original accounted stopped logical picoseconds.
    pub logical_ps: u64,
    /// Original accounted stopped raw retirement prefix.
    pub raw_prefix: u64,
    /// Physical owner retaining the immutable emitting authorization.
    pub owner: NativeConsoleOwner,
    /// Original emitting authorization's coherent advance publication.
    pub authorization_advance: u64,
    /// Captured canonical console generation, independent of physical restore.
    pub logical_generation: u64,
    /// Actual vCPU that owned the sealed UART operation.
    pub vcpu: u32,
    /// Exact even close generation from this same original node writer.
    pub closed_generation: u32,
    /// Original dual-role control request/ACK observed by the stopped owner.
    pub control_boundary_ack: u32,
    /// Original coherent advance observed by that stopped owner.
    pub stopped_advance: u64,
}

impl NativeConsoleOperationStop {
    /// Encodes the exact fixed-width accounted-stop record.
    ///
    /// # Errors
    ///
    /// Refuses absent physical owners or byte sequences, in-progress table,
    /// advance or node publications, and unsupported vCPU indices. A wrapped
    /// even node generation remains literal framing, not lifecycle authority.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_OPERATION_STOP_BYTES], NativeConsoleError> {
        self.owner.validate()?;
        if self.publication == 0
            || self.publication & 1 != 0
            || self.node_sequence == 0
            || self.authorization_advance & 1 != 0
            || self.stopped_advance & 1 != 0
            || self.closed_generation & 1 != 0
            || self.vcpu >= 64
        {
            return Err(NativeConsoleError::Field);
        }

        let mut bytes = [0; NATIVE_CONSOLE_OPERATION_STOP_BYTES];
        bytes[8..16].copy_from_slice(b"NCCOv1\0\0");
        for (offset, value) in [
            (0, self.publication),
            (16, self.ring_end),
            (24, self.node_sequence),
            (32, self.logical_ps),
            (40, self.raw_prefix),
            (48, self.owner.authorization),
            (56, self.authorization_advance),
            (64, self.logical_generation),
            (72, self.owner.process),
            (112, self.stopped_advance),
        ] {
            put64(&mut bytes, offset, value);
        }
        bytes[80..96].copy_from_slice(&self.owner.region);
        put32(&mut bytes, 96, self.owner.slot);
        put32(&mut bytes, 100, self.vcpu);
        put32(&mut bytes, 104, self.closed_generation);
        put32(&mut bytes, 108, self.control_boundary_ack);
        Ok(bytes)
    }

    /// Decodes exact framing without manufacturing native stopped ownership.
    ///
    /// # Errors
    ///
    /// Refuses different length, version magic, reserved bytes or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_OPERATION_STOP_BYTES)?;
        if &bytes[8..16] != b"NCCOv1\0\0" || bytes[120..].iter().any(|byte| *byte != 0) {
            return Err(NativeConsoleError::Framing);
        }
        let mut region = [0; 16];
        region.copy_from_slice(&bytes[80..96]);
        let stop = Self {
            publication: get64(bytes, 0),
            ring_end: get64(bytes, 16),
            node_sequence: get64(bytes, 24),
            logical_ps: get64(bytes, 32),
            raw_prefix: get64(bytes, 40),
            owner: NativeConsoleOwner {
                slot: get32(bytes, 96),
                region,
                process: get64(bytes, 72),
                authorization: get64(bytes, 48),
            },
            authorization_advance: get64(bytes, 56),
            logical_generation: get64(bytes, 64),
            vcpu: get32(bytes, 100),
            closed_generation: get32(bytes, 104),
            control_boundary_ack: get32(bytes, 108),
            stopped_advance: get64(bytes, 112),
        };
        stop.encode()?;
        Ok(stop)
    }
}
