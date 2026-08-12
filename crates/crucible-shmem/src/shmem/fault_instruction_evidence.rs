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

/// Complete record proving requested and actual architectural exception entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultExceptionEvidenceV1 {
    /// Architecture that delivered the exception.
    pub architecture: FaultCapabilityScope,
    /// Requested model phase.
    pub model_phase: u16,
    /// Target vCPU index.
    pub vcpu_index: u32,
    /// Requested architecture vector.
    pub vector: u32,
    /// Requested architecture syndrome or error code.
    pub syndrome: u64,
    /// Requested fault address, when present.
    pub fault_address: Option<u64>,
    /// Whether delivery was requested before rather than after the instruction.
    pub before_instruction: bool,
    /// Raw retired-instruction coordinate at command application, translated by the bridge.
    pub command_icount: u64,
    /// Scheduler-logical coordinate after architectural entry completed.
    pub delivered_icount: u64,
    /// Guest PC of the entered exception handler.
    pub entry_pc: u64,
    /// SHA-256 execution fingerprint before injection.
    pub before_sha256: [u8; 32],
    /// SHA-256 execution fingerprint after handler entry.
    pub after_sha256: [u8; 32],
}

impl FaultExceptionEvidenceV1 {
    /// Encodes canonical delivered-exception evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for an unsupported architecture, phase,
    /// missing entry state, zero digest, or inconsistent before/after request.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        self.validate()?;
        let mut bytes = vec![0_u8; FAULT_EXCEPTION_EVIDENCE_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_EXCEPTION_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, self.architecture as u16);
        put_u16(&mut bytes, 12, self.model_phase);
        put_u32(&mut bytes, 16, self.vcpu_index);
        put_u32(&mut bytes, 20, self.vector);
        put_u64(&mut bytes, 24, self.syndrome);
        put_u64(&mut bytes, 32, self.fault_address.unwrap_or(0));
        put_u64(&mut bytes, 40, self.command_icount);
        bytes[48] = u8::from(self.fault_address.is_some());
        bytes[49] = u8::from(self.before_instruction);
        bytes[51] = 1;
        put_u64(&mut bytes, 56, self.delivered_icount);
        put_u64(&mut bytes, 64, self.entry_pc);
        put_u32(&mut bytes, 72, self.vector);
        bytes[76] = u8::from(self.fault_address.is_some());
        put_u64(&mut bytes, 80, self.syndrome);
        put_u64(&mut bytes, 88, self.fault_address.unwrap_or(0));
        bytes[96..128].copy_from_slice(&self.before_sha256);
        bytes[128..160].copy_from_slice(&self.after_sha256);
        Ok(bytes)
    }

    /// Decodes and validates canonical delivered-exception evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, unknown tags, nonzero
    /// reserved bytes, or disagreement between requested and delivered state.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_EXCEPTION_EVIDENCE_V1_BYTES
            || bytes[..8] != FAULT_EXCEPTION_EVIDENCE_MAGIC_V1
            || u16_at(bytes, 8)? != 1
            || bytes[14..16].iter().any(|byte| *byte != 0)
            || bytes[50] != 0
            || bytes[51] != 1
            || bytes[52..56].iter().any(|byte| *byte != 0)
            || bytes[77..80].iter().any(|byte| *byte != 0)
            || bytes[160..192].iter().any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let has_address = bool_at(bytes, 48)?;
        if bool_at(bytes, 76)? != has_address
            || u32_at(bytes, 72)? != u32_at(bytes, 20)?
            || u64_at(bytes, 80)? != u64_at(bytes, 24)?
            || u64_at(bytes, 88)? != u64_at(bytes, 32)?
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let raw_address = u64_at(bytes, 32)?;
        if !has_address && raw_address != 0 {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let value = Self {
            architecture: FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?,
            model_phase: u16_at(bytes, 12)?,
            vcpu_index: u32_at(bytes, 16)?,
            vector: u32_at(bytes, 20)?,
            syndrome: u64_at(bytes, 24)?,
            fault_address: has_address.then_some(raw_address),
            before_instruction: bool_at(bytes, 49)?,
            command_icount: u64_at(bytes, 40)?,
            delivered_icount: u64_at(bytes, 56)?,
            entry_pc: u64_at(bytes, 64)?,
            before_sha256: array32(bytes, 96)?,
            after_sha256: array32(bytes, 128)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), FaultAbiError> {
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || !matches!(self.model_phase, 2 | 3)
            || self.before_instruction != (self.model_phase == 2)
            || self.vector == 0
            || self.entry_pc == 0
            || self.delivered_icount < self.command_icount
            || self.before_sha256 == [0; 32]
            || self.after_sha256 == [0; 32]
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }
}

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

pub(crate) fn emit_fault_instruction_evidence_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded canonical instruction-fault evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_MAGIC_V1 \"CRUCIEV1\"\n");
    define!("CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES",
        FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("MUTATION_KIND", 12),
        ("REPLAY_ORDINAL", 16),
        ("REPLAY_TOTAL", 20),
        ("OPCODE_CLASS", 24),
        ("FLAGS", 28),
        ("PC", 32),
        ("PHYSICAL_ADDRESS", 40),
        ("OBSERVED_ICOUNT", 48),
        ("INSTRUCTION_LENGTH", 56),
        ("DETAIL_LENGTH", 60),
        ("INSTRUCTION_SHA256", 64),
        ("BEFORE_STATE_SHA256", 96),
        ("AFTER_STATE_SHA256", 128),
        ("VCPU_INDEX", 160),
        ("DESTINATION_COUNT", 164),
        ("DESTINATIONS", 168),
        ("DECODE_RESERVED", 184),
        ("MANIFEST_SHA256", 192),
        ("CODE_PAGE_SHA256", 224),
        ("BEFORE_RAM_SHA256", 288),
        ("AFTER_RAM_SHA256", 320),
        ("BEFORE_DEVICE_SHA256", 352),
        ("AFTER_DEVICE_SHA256", 384),
        ("BEFORE_CPU_SHA256", 416),
        ("AFTER_CPU_SHA256", 448),
        ("BEFORE_RAM_BYTES", 480),
        ("AFTER_RAM_BYTES", 488),
        ("BEFORE_DEVICE_BYTES", 496),
        ("AFTER_DEVICE_BYTES", 504),
        ("CODE_PAGE_BASES", 512),
        ("CODE_PAGE_COUNT", 528),
        ("HAS_INPUT_STATE_SHA256", 532),
        ("INPUT_STATE_SHA256", 536),
        ("MATCHED_INPUT_STATE_SHA256", 568),
        ("OUTCOME", 600),
        ("RESERVED", 604),
        ("VALUES", 608),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_{name}_OFFSET {value}"
        );
    }
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_DECODE_RESERVED_BYTES",
        8
    );
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_RESULT_CORRUPT", 1);
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_SKIP", 2);
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_REPLAY", 3);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_APPLIED", 1);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_SUPPRESSED", 2);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_ERROR", 4);

    out.push_str("\n/* Canonical x86 port-I/O transcript nested in replay evidence. */\n");
    out.push_str("#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_MAGIC_V1 \"CRUCIOP1\"\n");
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_HEADER_V1_BYTES",
        FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_ENTRY_V1_BYTES",
        FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ENTRY_BYTES", 10),
        ("ENTRY_COUNT", 12),
        ("VALUE_BYTES", 16),
        ("RESERVED", 20),
        ("TRANSCRIPT_SHA256", 24),
        ("ENTRIES", 56),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_{name}_OFFSET {value}"
        );
    }
    for (name, value) in [
        ("DIRECTION", 0),
        ("VALUE_SIZE", 1),
        ("COMPLETED", 2),
        ("RESERVED0", 3),
        ("PORT", 4),
        ("VALUE", 8),
        ("RESERVED1", 12),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_ENTRY_{name}_OFFSET {value}"
        );
    }
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_DIRECTION_READ", 0);
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_DIRECTION_WRITE", 1);

    out.push_str("\n/* Byte-encoded canonical delivered-exception evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_MAGIC_V1 \"CRUCEEV1\"\n");
    define!("CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_V1_BYTES",
        FAULT_EXCEPTION_EVIDENCE_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("MODEL_PHASE", 12),
        ("RESERVED0", 14),
        ("VCPU_INDEX", 16),
        ("REQUESTED_VECTOR", 20),
        ("REQUESTED_SYNDROME", 24),
        ("REQUESTED_FAULT_ADDRESS", 32),
        ("COMMAND_ICOUNT", 40),
        ("HAS_FAULT_ADDRESS", 48),
        ("BEFORE_INSTRUCTION", 49),
        ("RESERVED1", 50),
        ("DELIVERED", 51),
        ("RESERVED2", 52),
        ("DELIVERED_ICOUNT", 56),
        ("ENTRY_PC", 64),
        ("DELIVERED_VECTOR", 72),
        ("DELIVERED_HAS_FAULT_ADDRESS", 76),
        ("RESERVED3", 77),
        ("DELIVERED_SYNDROME", 80),
        ("DELIVERED_FAULT_ADDRESS", 88),
        ("BEFORE_SHA256", 96),
        ("AFTER_SHA256", 128),
        ("RESERVED4", 160),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_{name}_OFFSET {value}"
        );
    }
}

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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn skip_evidence() -> FaultInstructionEvidenceV1 {
        let instruction_bytes = vec![0x90];
        let before_cpu_sha256 = [1; 32];
        let after_cpu_sha256 = [2; 32];
        let before_ram_sha256 = [5; 32];
        let after_ram_sha256 = [6; 32];
        let before_device_sha256 = [7; 32];
        let after_device_sha256 = [8; 32];
        FaultInstructionEvidenceV1 {
            architecture: FaultCapabilityScope::X86_64,
            mutation_kind: FaultInstructionMutationKindV1::Skip,
            outcome: FaultInstructionEvidenceOutcomeV1::Applied,
            replay_ordinal: 0,
            replay_total: 0,
            opcode_class: 0x0100_0001,
            flags: 0,
            pc: 0x1000,
            physical_address: 0x2000,
            observed_icount: 17,
            vcpu_index: 0,
            destinations: vec![1],
            instruction_sha256: Sha256::digest(&instruction_bytes).into(),
            before_state_sha256: instruction_system_digest(
                before_cpu_sha256,
                before_ram_sha256,
                before_device_sha256,
                4096,
                128,
            ),
            after_state_sha256: instruction_system_digest(
                after_cpu_sha256,
                after_ram_sha256,
                after_device_sha256,
                4096,
                128,
            ),
            manifest_sha256: [3; 32],
            before_cpu_sha256,
            after_cpu_sha256,
            input_state_sha256: None,
            matched_input_state_sha256: instruction_system_digest(
                before_cpu_sha256,
                before_ram_sha256,
                before_device_sha256,
                4096,
                128,
            ),
            code_page_bases: vec![0x2000],
            code_page_sha256: vec![[4; 32]],
            before_ram_sha256,
            after_ram_sha256,
            before_device_sha256,
            after_device_sha256,
            before_ram_bytes: 4096,
            after_ram_bytes: 4096,
            before_device_bytes: 128,
            after_device_bytes: 128,
            instruction_bytes,
            detail: Vec::new(),
        }
    }

    #[test]
    fn instruction_round_trip_rejects_reserved_bytes() {
        let evidence = skip_evidence();
        let bytes = evidence.encode().expect("valid instruction evidence");
        assert_eq!(
            FaultInstructionEvidenceV1::decode(&bytes).expect("canonical instruction evidence"),
            evidence
        );
        let mut malformed = bytes;
        malformed[607] = 1;
        assert!(FaultInstructionEvidenceV1::decode(&malformed).is_err());
    }

    #[test]
    fn suppressed_instruction_binds_mismatched_input_digest() {
        let mut evidence = skip_evidence();
        evidence.outcome = FaultInstructionEvidenceOutcomeV1::Suppressed;
        evidence.after_cpu_sha256 = evidence.before_cpu_sha256;
        evidence.after_ram_sha256 = evidence.before_ram_sha256;
        evidence.after_device_sha256 = evidence.before_device_sha256;
        evidence.after_ram_bytes = evidence.before_ram_bytes;
        evidence.after_device_bytes = evidence.before_device_bytes;
        evidence.after_state_sha256 = evidence.before_state_sha256;
        evidence.input_state_sha256 = Some([9; 32]);
        let bytes = evidence.encode().expect("valid suppressed evidence");
        assert_eq!(
            FaultInstructionEvidenceV1::decode(&bytes).expect("canonical suppressed evidence"),
            evidence
        );
    }

    #[test]
    fn device_replay_requires_an_authenticated_completed_port_io_transcript() {
        let transcript = FaultInstructionPortIoEvidenceV1 {
            entries: vec![FaultInstructionPortIoEntryV1 {
                direction: FaultInstructionPortIoDirectionV1::Write,
                port: 0xe9,
                value: vec![b'X'],
                completed: true,
            }],
        };
        let encoded = transcript.encode().expect("valid port-I/O transcript");
        assert_eq!(
            FaultInstructionPortIoEvidenceV1::decode(&encoded)
                .expect("authenticated port-I/O transcript"),
            transcript
        );

        let mut evidence = skip_evidence();
        evidence.mutation_kind = FaultInstructionMutationKindV1::Replay;
        evidence.replay_total = 1;
        evidence.opcode_class = 0x0100_0008;
        evidence.flags = 1 << 5;
        evidence.detail = encoded.clone();
        assert!(evidence.encode().is_ok());

        let mut missing = evidence.clone();
        missing.detail.clear();
        assert!(missing.encode().is_err());

        let mut corrupted = evidence;
        let last = corrupted.detail.len() - 1;
        corrupted.detail[last] ^= 1;
        assert!(corrupted.encode().is_err());
    }

    #[test]
    fn delivered_exception_round_trip_rejects_delivery_disagreement() {
        let evidence = FaultExceptionEvidenceV1 {
            architecture: FaultCapabilityScope::Aarch64,
            model_phase: 2,
            vcpu_index: 0,
            vector: 1,
            syndrome: 0x0200_0000,
            fault_address: None,
            before_instruction: true,
            command_icount: 11,
            delivered_icount: 11,
            entry_pc: 0x800,
            before_sha256: [1; 32],
            after_sha256: [2; 32],
        };
        let bytes = evidence.encode().expect("valid exception evidence");
        assert_eq!(
            FaultExceptionEvidenceV1::decode(&bytes).expect("canonical exception evidence"),
            evidence
        );
        let mut malformed = bytes;
        malformed[72] = 2;
        assert!(FaultExceptionEvidenceV1::decode(&malformed).is_err());
    }
}
