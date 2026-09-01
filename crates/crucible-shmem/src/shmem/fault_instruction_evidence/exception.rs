//! Canonical architectural exception-delivery evidence.

use super::*;

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
