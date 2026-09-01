//! Canonical x86 port-I/O transcript evidence.

use super::*;

/// Direction of one x86 port-I/O transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultInstructionPortIoDirectionV1 {
    /// Reads a value from an I/O port.
    Read = 0,
    /// Writes a value to an I/O port.
    Write = 1,
}

/// One transaction actually dispatched while executing a selected instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultInstructionPortIoEntryV1 {
    /// Direction of the transaction.
    pub direction: FaultInstructionPortIoDirectionV1,
    /// I/O port number.
    pub port: u32,
    /// Exact one-, two-, or four-byte value read or written.
    pub value: Vec<u8>,
    /// Whether QEMU's address-space dispatch completed without a transaction error.
    pub completed: bool,
}

/// Canonical transcript proving the device operation performed by one replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultInstructionPortIoEvidenceV1 {
    /// Transactions in dispatch order.
    pub entries: Vec<FaultInstructionPortIoEntryV1>,
}

impl FaultInstructionPortIoEvidenceV1 {
    /// Encodes and hashes the complete transaction transcript.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when the transcript is empty, too large, or
    /// contains an unsupported transaction width.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if self.entries.is_empty() || self.entries.len() > 8 {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut entries = Vec::with_capacity(
            self.entries.len() * FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES,
        );
        let mut byte_count = 0_u32;
        for entry in &self.entries {
            if !matches!(entry.value.len(), 1 | 2 | 4) {
                return Err(FaultAbiError::CapabilityInvariant);
            }
            byte_count = byte_count
                .checked_add(entry.value.len() as u32)
                .ok_or(FaultAbiError::CapabilityInvariant)?;
            let start = entries.len();
            entries.resize(start + FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES, 0);
            entries[start] = entry.direction as u8;
            entries[start + 1] = entry.value.len() as u8;
            entries[start + 2] = u8::from(entry.completed);
            put_u32(&mut entries, start + 4, entry.port);
            entries[start + 8..start + 8 + entry.value.len()].copy_from_slice(&entry.value);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"crucible.port-io.v1\0");
        hasher.update(&entries);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut bytes = vec![0_u8; FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_INSTRUCTION_PORT_IO_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, 1);
        put_u16(
            &mut bytes,
            10,
            FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES as u16,
        );
        put_u32(&mut bytes, 12, self.entries.len() as u32);
        put_u32(&mut bytes, 16, byte_count);
        bytes[24..56].copy_from_slice(&digest);
        bytes.extend_from_slice(&entries);
        Ok(bytes)
    }

    /// Decodes and verifies a complete transaction transcript.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, reserved bytes,
    /// unsupported values, inconsistent counts, or a digest mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES
            || bytes[..8] != FAULT_INSTRUCTION_PORT_IO_EVIDENCE_MAGIC_V1
            || u16_at(bytes, 8)? != 1
            || usize::from(u16_at(bytes, 10)?) != FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES
            || bytes[20..24].iter().any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let count =
            usize::try_from(u32_at(bytes, 12)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let entries_len = count
            .checked_mul(FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        if !(1..=8).contains(&count)
            || bytes.len() != FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES + entries_len
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let raw_entries = &bytes[FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES..];
        let mut hasher = Sha256::new();
        hasher.update(b"crucible.port-io.v1\0");
        hasher.update(raw_entries);
        if hasher.finalize().as_slice() != &bytes[24..56] {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut byte_count = 0_u32;
        let mut entries = Vec::with_capacity(count);
        for raw in raw_entries.chunks_exact(FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES) {
            let direction = match raw[0] {
                0 => FaultInstructionPortIoDirectionV1::Read,
                1 => FaultInstructionPortIoDirectionV1::Write,
                _ => return Err(FaultAbiError::CapabilityInvariant),
            };
            let size = usize::from(raw[1]);
            if !matches!(size, 1 | 2 | 4)
                || raw[2] > 1
                || raw[3] != 0
                || raw[8 + size..24].iter().any(|byte| *byte != 0)
            {
                return Err(FaultAbiError::CapabilityInvariant);
            }
            byte_count = byte_count
                .checked_add(size as u32)
                .ok_or(FaultAbiError::CapabilityInvariant)?;
            entries.push(FaultInstructionPortIoEntryV1 {
                direction,
                port: u32_at(raw, 4)?,
                value: raw[8..8 + size].to_vec(),
                completed: raw[2] == 1,
            });
        }
        if byte_count != u32_at(bytes, 16)? {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(Self { entries })
    }
}
