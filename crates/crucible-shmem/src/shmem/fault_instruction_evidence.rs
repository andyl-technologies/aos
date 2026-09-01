//! Canonical evidence for instruction mutations and delivered CPU exceptions.
//!
//! QEMU supplies a private raw record. The GPL bridge validates that record,
//! binds it to the submitted command and admitted register manifest, converts
//! retired-instruction coordinates to scheduler-logical coordinates, and then
//! publishes these pointer-free permissive protocol records.

use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use crate::{FaultAbiError, FaultCapabilityScope, FaultRegisterMutationEvidenceV1};

/// Magic prefix for version-1 canonical instruction evidence.
pub const FAULT_INSTRUCTION_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCIEV1";
/// Fixed bytes before exact instruction bytes and optional mutation detail.
pub const FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES: usize = 608;
/// Magic prefix for a canonical x86 port-I/O transcript.
pub const FAULT_INSTRUCTION_PORT_IO_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCIOP1";
/// Fixed bytes before canonical x86 port-I/O transcript entries.
pub const FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES: usize = 56;
/// Fixed size of one canonical x86 port-I/O transcript entry.
pub const FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES: usize = 24;
/// Magic prefix for version-1 canonical delivered-exception evidence.
pub const FAULT_EXCEPTION_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCEEV1";
/// Fixed size of a canonical delivered-exception record.
pub const FAULT_EXCEPTION_EVIDENCE_V1_BYTES: usize = 192;

/// Closed instruction mutation represented by evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FaultInstructionMutationKindV1 {
    /// Corrupts one decoded destination register after execution.
    ResultCorrupt = 1,
    /// Skips one safe sequential instruction.
    Skip = 2,
    /// Reexecutes one non-control-flow instruction a bounded number of times.
    Replay = 3,
}

/// Closed result of one selected instruction mutation opportunity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FaultInstructionEvidenceOutcomeV1 {
    /// The requested mutation completed.
    Applied = 1,
    /// The input-state precondition mismatched and the instruction ran unchanged.
    Suppressed = 2,
    /// Runtime revalidation failed and execution stopped fail-closed.
    Error = 4,
}

#[path = "fault_instruction_evidence/port_io.rs"]
mod port_io;

pub use port_io::{
    FaultInstructionPortIoDirectionV1, FaultInstructionPortIoEntryV1,
    FaultInstructionPortIoEvidenceV1,
};

impl FaultInstructionEvidenceOutcomeV1 {
    fn decode(value: u32) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Suppressed),
            4 => Ok(Self::Error),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

impl FaultInstructionMutationKindV1 {
    fn decode(value: u32) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::ResultCorrupt),
            2 => Ok(Self::Skip),
            3 => Ok(Self::Replay),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Complete independently verifiable record of one instruction mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultInstructionEvidenceV1 {
    /// Architecture that decoded and executed the instruction.
    pub architecture: FaultCapabilityScope,
    /// Mutation operation applied at this execution.
    pub mutation_kind: FaultInstructionMutationKindV1,
    /// Result of the selected mutation opportunity.
    pub outcome: FaultInstructionEvidenceOutcomeV1,
    /// Zero-based replay ordinal; zero is the original execution.
    pub replay_ordinal: u32,
    /// Requested replay count, excluding the original execution.
    pub replay_total: u32,
    /// Stable opcode class from the admitted decoder manifest.
    pub opcode_class: u32,
    /// Decoder flags describing control flow, indivisibility, memory, and I/O.
    pub flags: u32,
    /// Guest virtual address of the instruction.
    pub pc: u64,
    /// Guest physical address of the first instruction byte.
    pub physical_address: u64,
    /// Scheduler-logical retired-instruction coordinate.
    pub observed_icount: u64,
    /// Mutated vCPU index.
    pub vcpu_index: u32,
    /// Stable numeric register IDs bound by the admitted register manifest.
    pub destinations: Vec<u32>,
    /// SHA-256 digest of the exact instruction bytes.
    pub instruction_sha256: [u8; 32],
    /// SHA-256 digest of the complete input system state.
    pub before_state_sha256: [u8; 32],
    /// SHA-256 digest of the complete output system state.
    pub after_state_sha256: [u8; 32],
    /// SHA-256 digest of the immutable decoder manifest.
    pub manifest_sha256: [u8; 32],
    /// SHA-256 execution fingerprint of CPU state before execution.
    pub before_cpu_sha256: [u8; 32],
    /// SHA-256 execution fingerprint of CPU state after execution.
    pub after_cpu_sha256: [u8; 32],
    /// Optional required complete input-state digest from the selector.
    pub input_state_sha256: Option<[u8; 32]>,
    /// Actual complete input-state digest against which the selector was evaluated.
    pub matched_input_state_sha256: [u8; 32],
    /// Guest-physical bases of the one or two code pages containing the bytes.
    pub code_page_bases: Vec<u64>,
    /// SHA-256 digests of the corresponding complete code pages.
    pub code_page_sha256: Vec<[u8; 32]>,
    /// SHA-256 digest of writable guest RAM before execution.
    pub before_ram_sha256: [u8; 32],
    /// SHA-256 digest of writable guest RAM after execution.
    pub after_ram_sha256: [u8; 32],
    /// SHA-256 digest of QEMU's non-RAM migration VMState stream before execution.
    ///
    /// The stream may include registered CPU sections; use nested transaction
    /// evidence, rather than a digest delta, to prove device I/O.
    pub before_device_sha256: [u8; 32],
    /// SHA-256 digest of QEMU's non-RAM migration VMState stream after execution.
    pub after_device_sha256: [u8; 32],
    /// Number of guest RAM bytes included in the input digest.
    pub before_ram_bytes: u64,
    /// Number of guest RAM bytes included in the output digest.
    pub after_ram_bytes: u64,
    /// Number of migration VMState bytes included in the input digest.
    pub before_device_bytes: u64,
    /// Number of migration VMState bytes included in the output digest.
    pub after_device_bytes: u64,
    /// Exact instruction encoding observed at execution.
    pub instruction_bytes: Vec<u8>,
    /// Canonical nested register evidence for result corruption, otherwise empty.
    pub detail: Vec<u8>,
}

impl FaultInstructionEvidenceV1 {
    /// Encodes canonical instruction evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when any class, length, digest, replay ordinal,
    /// destination, page identity, or nested register record is inconsistent.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        self.validate()?;
        let mut bytes = vec![0_u8; FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_INSTRUCTION_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, self.architecture as u16);
        put_u32(&mut bytes, 12, self.mutation_kind as u32);
        put_u32(&mut bytes, 16, self.replay_ordinal);
        put_u32(&mut bytes, 20, self.replay_total);
        put_u32(&mut bytes, 24, self.opcode_class);
        put_u32(&mut bytes, 28, self.flags);
        put_u64(&mut bytes, 32, self.pc);
        put_u64(&mut bytes, 40, self.physical_address);
        put_u64(&mut bytes, 48, self.observed_icount);
        put_u32(&mut bytes, 56, self.instruction_bytes.len() as u32);
        put_u32(&mut bytes, 60, self.detail.len() as u32);
        bytes[64..96].copy_from_slice(&self.instruction_sha256);
        bytes[96..128].copy_from_slice(&self.before_state_sha256);
        bytes[128..160].copy_from_slice(&self.after_state_sha256);
        put_u32(&mut bytes, 160, self.vcpu_index);
        put_u32(&mut bytes, 164, self.destinations.len() as u32);
        for (index, destination) in self.destinations.iter().enumerate() {
            put_u32(&mut bytes, 168 + index * 4, *destination);
        }
        bytes[192..224].copy_from_slice(&self.manifest_sha256);
        for (index, digest) in self.code_page_sha256.iter().enumerate() {
            bytes[224 + index * 32..256 + index * 32].copy_from_slice(digest);
        }
        bytes[288..320].copy_from_slice(&self.before_ram_sha256);
        bytes[320..352].copy_from_slice(&self.after_ram_sha256);
        bytes[352..384].copy_from_slice(&self.before_device_sha256);
        bytes[384..416].copy_from_slice(&self.after_device_sha256);
        bytes[416..448].copy_from_slice(&self.before_cpu_sha256);
        bytes[448..480].copy_from_slice(&self.after_cpu_sha256);
        put_u64(&mut bytes, 480, self.before_ram_bytes);
        put_u64(&mut bytes, 488, self.after_ram_bytes);
        put_u64(&mut bytes, 496, self.before_device_bytes);
        put_u64(&mut bytes, 504, self.after_device_bytes);
        for (index, base) in self.code_page_bases.iter().enumerate() {
            put_u64(&mut bytes, 512 + index * 8, *base);
        }
        put_u32(&mut bytes, 528, self.code_page_bases.len() as u32);
        put_u32(
            &mut bytes,
            532,
            u32::from(self.input_state_sha256.is_some()),
        );
        if let Some(digest) = self.input_state_sha256 {
            bytes[536..568].copy_from_slice(&digest);
        }
        bytes[568..600].copy_from_slice(&self.matched_input_state_sha256);
        put_u32(&mut bytes, 600, self.outcome as u32);
        bytes.extend_from_slice(&self.instruction_bytes);
        bytes.extend_from_slice(&self.detail);
        Ok(bytes)
    }

    /// Decodes and validates canonical instruction evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, nonzero reserved bytes,
    /// unknown tags, inconsistent lengths or hashes, or invalid nested evidence.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES
            || bytes[..8] != FAULT_INSTRUCTION_EVIDENCE_MAGIC_V1
            || u16_at(bytes, 8)? != 1
            || bytes[604..608].iter().any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let instruction_len =
            usize::try_from(u32_at(bytes, 56)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let detail_len =
            usize::try_from(u32_at(bytes, 60)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let payload_len = FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES
            .checked_add(instruction_len)
            .and_then(|length| length.checked_add(detail_len))
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        if bytes.len() != payload_len {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let destination_count =
            usize::try_from(u32_at(bytes, 164)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let page_count =
            usize::try_from(u32_at(bytes, 528)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        if destination_count > 4 || !(1..=2).contains(&page_count) {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        if bytes[184..192].iter().any(|byte| *byte != 0) {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let instruction_start = FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES;
        let detail_start = instruction_start + instruction_len;
        let value = Self {
            architecture: FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?,
            mutation_kind: FaultInstructionMutationKindV1::decode(u32_at(bytes, 12)?)?,
            outcome: FaultInstructionEvidenceOutcomeV1::decode(u32_at(bytes, 600)?)?,
            replay_ordinal: u32_at(bytes, 16)?,
            replay_total: u32_at(bytes, 20)?,
            opcode_class: u32_at(bytes, 24)?,
            flags: u32_at(bytes, 28)?,
            pc: u64_at(bytes, 32)?,
            physical_address: u64_at(bytes, 40)?,
            observed_icount: u64_at(bytes, 48)?,
            vcpu_index: u32_at(bytes, 160)?,
            destinations: (0..destination_count)
                .map(|index| u32_at(bytes, 168 + index * 4))
                .collect::<Result<_, _>>()?,
            instruction_sha256: array32(bytes, 64)?,
            before_state_sha256: array32(bytes, 96)?,
            after_state_sha256: array32(bytes, 128)?,
            manifest_sha256: array32(bytes, 192)?,
            before_cpu_sha256: array32(bytes, 416)?,
            after_cpu_sha256: array32(bytes, 448)?,
            input_state_sha256: match u32_at(bytes, 532)? {
                0 => None,
                1 => Some(array32(bytes, 536)?),
                _ => return Err(FaultAbiError::CapabilityInvariant),
            },
            matched_input_state_sha256: array32(bytes, 568)?,
            code_page_bases: (0..page_count)
                .map(|index| u64_at(bytes, 512 + index * 8))
                .collect::<Result<_, _>>()?,
            code_page_sha256: (0..page_count)
                .map(|index| array32(bytes, 224 + index * 32))
                .collect::<Result<_, _>>()?,
            before_ram_sha256: array32(bytes, 288)?,
            after_ram_sha256: array32(bytes, 320)?,
            before_device_sha256: array32(bytes, 352)?,
            after_device_sha256: array32(bytes, 384)?,
            before_ram_bytes: u64_at(bytes, 480)?,
            after_ram_bytes: u64_at(bytes, 488)?,
            before_device_bytes: u64_at(bytes, 496)?,
            after_device_bytes: u64_at(bytes, 504)?,
            instruction_bytes: bytes[instruction_start..detail_start].to_vec(),
            detail: bytes[detail_start..].to_vec(),
        };
        if bytes[168 + destination_count * 4..184]
            .iter()
            .any(|byte| *byte != 0)
            || (page_count == 1
                && (bytes[256..288].iter().any(|byte| *byte != 0) || u64_at(bytes, 520)? != 0))
            || (value.input_state_sha256.is_none() && bytes[536..568].iter().any(|byte| *byte != 0))
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), FaultAbiError> {
        let architecture_valid = matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        );
        let replay_valid = match self.mutation_kind {
            FaultInstructionMutationKindV1::ResultCorrupt
            | FaultInstructionMutationKindV1::Skip => {
                self.replay_ordinal == 0 && self.replay_total == 0
            }
            FaultInstructionMutationKindV1::Replay => {
                (1..=256).contains(&self.replay_total) && self.replay_ordinal <= self.replay_total
            }
        };
        let detail_valid = match (self.outcome, self.mutation_kind) {
            (FaultInstructionEvidenceOutcomeV1::Suppressed, _) => {
                self.detail.is_empty() && self.before_state_sha256 == self.after_state_sha256
            }
            (
                FaultInstructionEvidenceOutcomeV1::Applied,
                FaultInstructionMutationKindV1::ResultCorrupt,
            ) => FaultRegisterMutationEvidenceV1::decode(&self.detail).is_ok(),
            (
                FaultInstructionEvidenceOutcomeV1::Applied,
                FaultInstructionMutationKindV1::Replay,
            ) if self.opcode_class == 0x0100_0008 => {
                FaultInstructionPortIoEvidenceV1::decode(&self.detail).is_ok()
            }
            (FaultInstructionEvidenceOutcomeV1::Applied, _) => self.detail.is_empty(),
            (FaultInstructionEvidenceOutcomeV1::Error, _) => self.detail.len() <= 32,
        };
        let input_match_valid = match (self.outcome, self.input_state_sha256) {
            (FaultInstructionEvidenceOutcomeV1::Applied, Some(expected)) => {
                expected == self.matched_input_state_sha256
            }
            (FaultInstructionEvidenceOutcomeV1::Suppressed, Some(expected)) => {
                expected != self.matched_input_state_sha256
            }
            (FaultInstructionEvidenceOutcomeV1::Suppressed, None) => false,
            _ => true,
        };
        let nonzero = |digest: &[u8; 32]| *digest != [0; 32];
        if !architecture_valid
            || !replay_valid
            || (self.opcode_class == 0 && self.outcome != FaultInstructionEvidenceOutcomeV1::Error)
            || self.flags & !0x3f != 0
            || !(1..=32).contains(&self.instruction_bytes.len())
            || self.destinations.len() > 4
            || self.destinations.contains(&0)
            || self.code_page_bases.len() != self.code_page_sha256.len()
            || !(1..=2).contains(&self.code_page_bases.len())
            || self.before_ram_bytes == 0
            || self.after_ram_bytes == 0
            || self.before_device_bytes == 0
            || self.after_device_bytes == 0
            || !detail_valid
            || !input_match_valid
            || Sha256::digest(&self.instruction_bytes).as_slice() != self.instruction_sha256
            || ![
                &self.before_state_sha256,
                &self.after_state_sha256,
                &self.manifest_sha256,
                &self.before_cpu_sha256,
                &self.after_cpu_sha256,
                &self.before_ram_sha256,
                &self.after_ram_sha256,
                &self.before_device_sha256,
                &self.after_device_sha256,
                &self.matched_input_state_sha256,
            ]
            .into_iter()
            .all(nonzero)
            || instruction_system_digest(
                self.before_cpu_sha256,
                self.before_ram_sha256,
                self.before_device_sha256,
                self.before_ram_bytes,
                self.before_device_bytes,
            ) != self.before_state_sha256
            || instruction_system_digest(
                self.after_cpu_sha256,
                self.after_ram_sha256,
                self.after_device_sha256,
                self.after_ram_bytes,
                self.after_device_bytes,
            ) != self.after_state_sha256
            || !self.code_page_sha256.iter().all(nonzero)
            || self
                .input_state_sha256
                .is_some_and(|digest| !nonzero(&digest))
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }
}

#[path = "fault_instruction_evidence/exception.rs"]
mod exception;

pub use exception::FaultExceptionEvidenceV1;

fn instruction_system_digest(
    cpu_sha256: [u8; 32],
    ram_sha256: [u8; 32],
    device_sha256: [u8; 32],
    ram_bytes: u64,
    device_bytes: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"crucible.instruction-state.v1\0");
    digest.update(cpu_sha256);
    digest.update(ram_sha256);
    digest.update(device_sha256);
    digest.update(ram_bytes.to_le_bytes());
    digest.update(device_bytes.to_le_bytes());
    digest.finalize().into()
}

#[path = "fault_instruction_evidence/c_header.rs"]
mod c_header;

pub(crate) use c_header::emit_fault_instruction_evidence_c_header;

fn bool_at(bytes: &[u8], offset: usize) -> Result<bool, FaultAbiError> {
    match bytes.get(offset) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(FaultAbiError::CapabilityInvariant),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultAbiError::CapabilityInvariant)
}

fn array32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FaultAbiError> {
    bytes
        .get(offset..offset + 32)
        .and_then(|value| value.try_into().ok())
        .ok_or(FaultAbiError::CapabilityInvariant)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "fault_instruction_evidence_test.rs"]
mod tests;
