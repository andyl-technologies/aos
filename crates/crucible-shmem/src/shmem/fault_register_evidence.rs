//! Canonical evidence for architecture register mutations performed by QEMU.
//!
//! The GPL-side implementation supplies complete before/after register bytes,
//! scheduler coordinates, performed side effects, and a post-mutation CPU
//! fingerprint. The permissive bridge binds those observations to the exact
//! target-manifest and realized-CPU identities admitted at launch.

use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

use crate::{
    FAULT_MODEL_PHASES_V1_MASK, FAULT_REGISTER_SIDE_EFFECTS_V1_MASK, FaultAbiError,
    FaultCapabilityScope, FaultRegisterCapabilityManifestV1, HARD_FAULT_REGISTER_WIDTH_BITS,
};

/// Magic prefix for version-1 register-mutation evidence.
pub const FAULT_REGISTER_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCREG1";
/// Fixed header bytes before complete before/after register values.
pub const FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES: usize = 256;

/// Computes the identity of complete canonical register-manifest bytes.
///
/// # Errors
///
/// Returns [`FaultAbiError`] when the manifest cannot be canonically encoded.
pub fn fault_register_manifest_digest_v1(
    manifest: &FaultRegisterCapabilityManifestV1,
) -> Result<[u8; 32], FaultAbiError> {
    Ok(*blake3::hash(&manifest.encode()?).as_bytes())
}

/// Computes the domain-separated identity of a realized CPU typename.
#[must_use]
pub fn fault_register_cpu_model_digest_v1(
    architecture: FaultCapabilityScope,
    cpu_model: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-realized-cpu-model.v1\0");
    hasher.update(&(architecture as u16).to_le_bytes());
    hasher.update(cpu_model.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Closed register mutation encoded in command and event evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FaultRegisterMutationKindV1 {
    /// Flips every selected bit.
    BitFlip = 1,
    /// Forces selected bits to their supplied stuck values.
    Stuck = 2,
    /// Replaces selected bits with their supplied values.
    Replace = 3,
}

impl FaultRegisterMutationKindV1 {
    fn decode(value: u32) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::BitFlip),
            2 => Ok(Self::Stuck),
            3 => Ok(Self::Replace),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Complete independently verifiable record of one register mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultRegisterMutationEvidenceV1 {
    /// Architecture that owns the register target.
    pub architecture: FaultCapabilityScope,
    /// Signal-model phase at which the mutation occurred.
    pub model_phase: u16,
    /// Mutated vCPU index.
    pub vcpu_index: u32,
    /// Process-private numeric ID from the admitted manifest.
    pub numeric_id: u32,
    /// Mutation transform applied to selected bits.
    pub mutation_kind: FaultRegisterMutationKindV1,
    /// Side effects declared by the admitted register row.
    pub declared_side_effects: u32,
    /// Side effects actually completed before acknowledgement.
    pub performed_side_effects: u32,
    /// First selected register bit.
    pub first_bit: u32,
    /// Positive selected bit count.
    pub bit_count: u32,
    /// Scheduler-logical retired-instruction coordinate.
    pub observed_icount: u64,
    /// vCPU selected by the deterministic round-robin scheduler.
    pub rr_current_vcpu: u64,
    /// Retired-instruction position inside the current RR quantum.
    pub rr_cursor_position: u64,
    /// Pinned RR quantum length.
    pub rr_switch_quantum: u64,
    /// BLAKE3 digest of the complete admitted register manifest bytes.
    pub manifest_digest: [u8; 32],
    /// BLAKE3 digest of the canonical realized CPU typename.
    pub cpu_model_digest: [u8; 32],
    /// SHA-256 digest of `before`.
    pub before_sha256: [u8; 32],
    /// SHA-256 digest of `after`.
    pub after_sha256: [u8; 32],
    /// SHA-256 CPU-state fingerprint captured after the mutation.
    pub execution_fingerprint_sha256: [u8; 32],
    /// Complete register value before mutation.
    pub before: Vec<u8>,
    /// Complete register value after mutation and side effects.
    pub after: Vec<u8>,
    /// Selected-bit mask, relative to `first_bit`.
    pub mask: Vec<u8>,
    /// Replacement bits for stuck/replace, or one zero byte for bit-flip.
    pub value: Vec<u8>,
}

impl FaultRegisterMutationEvidenceV1 {
    /// Encodes canonical register-mutation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for invalid identities, coordinates, masks,
    /// side-effect proof, value lengths, hashes, or reserved architecture tags.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        self.validate()?;
        let before_len =
            u32::try_from(self.before.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let after_len =
            u32::try_from(self.after.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let mask_len =
            u32::try_from(self.mask.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let value_len =
            u32::try_from(self.value.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let mut bytes = vec![0_u8; FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_REGISTER_EVIDENCE_MAGIC_V1);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(self.architecture as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&self.model_phase.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.vcpu_index.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.numeric_id.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.mutation_kind as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&self.declared_side_effects.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.performed_side_effects.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.first_bit.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.bit_count.to_le_bytes());
        bytes[44..48].copy_from_slice(&before_len.to_le_bytes());
        bytes[48..52].copy_from_slice(&after_len.to_le_bytes());
        bytes[52..56].copy_from_slice(&mask_len.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.observed_icount.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.rr_current_vcpu.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.rr_cursor_position.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.rr_switch_quantum.to_le_bytes());
        bytes[88..120].copy_from_slice(&self.manifest_digest);
        bytes[120..152].copy_from_slice(&self.cpu_model_digest);
        bytes[152..184].copy_from_slice(&self.before_sha256);
        bytes[184..216].copy_from_slice(&self.after_sha256);
        bytes[216..248].copy_from_slice(&self.execution_fingerprint_sha256);
        bytes[248..252].copy_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&self.before);
        bytes.extend_from_slice(&self.after);
        bytes.extend_from_slice(&self.mask);
        bytes.extend_from_slice(&self.value);
        Ok(bytes)
    }

    /// Decodes and validates canonical register-mutation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, unknown tags, nonzero
    /// reserved bytes, inconsistent lengths, digests, or scheduler coordinates.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES
            || bytes[..8] != FAULT_REGISTER_EVIDENCE_MAGIC_V1
            || u16_at(bytes, 8)? != 1
            || bytes[14..16] != [0, 0]
            || bytes[252..256].iter().any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let before_len =
            usize::try_from(u32_at(bytes, 44)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let after_len =
            usize::try_from(u32_at(bytes, 48)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let mask_len =
            usize::try_from(u32_at(bytes, 52)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let value_len =
            usize::try_from(u32_at(bytes, 248)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        if bytes.len()
            != FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES
                .checked_add(before_len)
                .and_then(|length| length.checked_add(after_len))
                .and_then(|length| length.checked_add(mask_len))
                .and_then(|length| length.checked_add(value_len))
                .ok_or(FaultAbiError::HeaderLength)?
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let before_start = FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES;
        let after_start = before_start + before_len;
        let mask_start = after_start + after_len;
        let value_start = mask_start + mask_len;
        let evidence = Self {
            architecture: FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?,
            model_phase: u16_at(bytes, 12)?,
            vcpu_index: u32_at(bytes, 16)?,
            numeric_id: u32_at(bytes, 20)?,
            mutation_kind: FaultRegisterMutationKindV1::decode(u32_at(bytes, 24)?)?,
            declared_side_effects: u32_at(bytes, 28)?,
            performed_side_effects: u32_at(bytes, 32)?,
            first_bit: u32_at(bytes, 36)?,
            bit_count: u32_at(bytes, 40)?,
            observed_icount: u64_at(bytes, 56)?,
            rr_current_vcpu: u64_at(bytes, 64)?,
            rr_cursor_position: u64_at(bytes, 72)?,
            rr_switch_quantum: u64_at(bytes, 80)?,
            manifest_digest: array32(bytes, 88)?,
            cpu_model_digest: array32(bytes, 120)?,
            before_sha256: array32(bytes, 152)?,
            after_sha256: array32(bytes, 184)?,
            execution_fingerprint_sha256: array32(bytes, 216)?,
            before: bytes[before_start..after_start].to_vec(),
            after: bytes[after_start..mask_start].to_vec(),
            mask: bytes[mask_start..value_start].to_vec(),
            value: bytes[value_start..].to_vec(),
        };
        evidence.validate()?;
        if evidence.encode()?.as_slice() != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), FaultAbiError> {
        let valid_architecture = matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        );
        let width_bits = u32::try_from(self.before.len())
            .ok()
            .and_then(|length| length.checked_mul(8));
        let mutation_bytes = usize::try_from(self.bit_count)
            .ok()
            .and_then(|bits| bits.checked_add(7))
            .map(|bits| bits / 8);
        if !valid_architecture
            || self.model_phase == 0
            || self.model_phase > 64
            || (UINT64_C_ONE << (self.model_phase - 1)) & FAULT_MODEL_PHASES_V1_MASK == 0
            || self.numeric_id == 0
            || self.declared_side_effects & !FAULT_REGISTER_SIDE_EFFECTS_V1_MASK != 0
            || self.performed_side_effects != self.declared_side_effects
            || self.bit_count == 0
            || self.before.is_empty()
            || self.before.len() != self.after.len()
            || mutation_bytes != Some(self.mask.len())
            || self.value.len()
                != if self.mutation_kind == FaultRegisterMutationKindV1::BitFlip {
                    1
                } else {
                    self.mask.len()
                }
            || (self.mutation_kind == FaultRegisterMutationKindV1::BitFlip && self.value != [0])
            || width_bits.is_none_or(|width| width > HARD_FAULT_REGISTER_WIDTH_BITS)
            || self
                .first_bit
                .checked_add(self.bit_count)
                .is_none_or(|end| width_bits.is_none_or(|width| end > width))
            || self.rr_current_vcpu != u64::from(self.vcpu_index)
            || self.rr_switch_quantum == 0
            || self.rr_cursor_position >= self.rr_switch_quantum
            || self.manifest_digest == [0; 32]
            || self.cpu_model_digest == [0; 32]
            || self.execution_fingerprint_sha256 == [0; 32]
            || self.before_sha256 != Sha256::digest(&self.before).as_slice()
            || self.after_sha256 != Sha256::digest(&self.after).as_slice()
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        for bit in self.bit_count
            ..u32::try_from(self.mask.len() * 8).map_err(|_| FaultAbiError::CapabilityInvariant)?
        {
            if bit_is_set(&self.mask, bit)
                || (self.mutation_kind != FaultRegisterMutationKindV1::BitFlip
                    && bit_is_set(&self.value, bit))
            {
                return Err(FaultAbiError::CapabilityInvariant);
            }
        }
        let mut transformed = self.before.clone();
        for bit in 0..self.bit_count {
            if !bit_is_set(&self.mask, bit) {
                continue;
            }
            let target = self.first_bit + bit;
            let byte =
                usize::try_from(target / 8).map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let bit_mask = 1_u8 << (target % 8);
            if self.mutation_kind == FaultRegisterMutationKindV1::BitFlip {
                transformed[byte] ^= bit_mask;
            } else if bit_is_set(&self.value, bit) {
                transformed[byte] |= bit_mask;
            } else {
                transformed[byte] &= !bit_mask;
            }
        }
        if transformed != self.after {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }
}

pub(crate) fn emit_fault_register_evidence_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded QEMU register-mutation evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_REGISTER_EVIDENCE_MAGIC_V1 \"CRUCREG1\"\n");
    define!("CRUCIBLE_FAULT_REGISTER_EVIDENCE_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES",
        FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES
    );
    for (name, value) in [
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_MAGIC_OFFSET", 0),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_VERSION_OFFSET", 8),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_ARCHITECTURE_OFFSET", 10),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_MODEL_PHASE_OFFSET", 12),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_RESERVED0_OFFSET", 14),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_VCPU_INDEX_OFFSET", 16),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_NUMERIC_ID_OFFSET", 20),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_MUTATION_KIND_OFFSET", 24),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_DECLARED_SIDE_EFFECTS_OFFSET",
            28,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_PERFORMED_SIDE_EFFECTS_OFFSET",
            32,
        ),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_FIRST_BIT_OFFSET", 36),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_BIT_COUNT_OFFSET", 40),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_BEFORE_LENGTH_OFFSET", 44),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_AFTER_LENGTH_OFFSET", 48),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_MASK_LENGTH_OFFSET", 52),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_OBSERVED_ICOUNT_OFFSET",
            56,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_RR_CURRENT_VCPU_OFFSET",
            64,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_RR_CURSOR_POSITION_OFFSET",
            72,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_RR_SWITCH_QUANTUM_OFFSET",
            80,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_MANIFEST_DIGEST_OFFSET",
            88,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_CPU_MODEL_DIGEST_OFFSET",
            120,
        ),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_BEFORE_SHA256_OFFSET", 152),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_AFTER_SHA256_OFFSET", 184),
        (
            "CRUCIBLE_FAULT_REGISTER_EVIDENCE_EXECUTION_FINGERPRINT_OFFSET",
            216,
        ),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_VALUE_LENGTH_OFFSET", 248),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_RESERVED2_OFFSET", 252),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_VALUES_OFFSET", 256),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_DIGEST_BYTES", 32),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_RESERVED0_BYTES", 2),
        ("CRUCIBLE_FAULT_REGISTER_EVIDENCE_RESERVED2_BYTES", 4),
        (
            "CRUCIBLE_FAULT_REGISTER_MUTATION_BIT_FLIP",
            FaultRegisterMutationKindV1::BitFlip as usize,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_MUTATION_STUCK",
            FaultRegisterMutationKindV1::Stuck as usize,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_MUTATION_REPLACE",
            FaultRegisterMutationKindV1::Replace as usize,
        ),
    ] {
        define!(name, value);
    }
}

const UINT64_C_ONE: u64 = 1;

fn bit_is_set(bytes: &[u8], bit: u32) -> bool {
    bytes[bit as usize / 8] & (1_u8 << (bit % 8)) != 0
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

fn array32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FaultAbiError> {
    bytes
        .get(offset..offset + 32)
        .and_then(|value| value.try_into().ok())
        .ok_or(FaultAbiError::HeaderLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_evidence_round_trips_and_authenticates_values() {
        let before = vec![0x11; 8];
        let mut after = before.clone();
        after[0] = 0x31;
        let evidence = FaultRegisterMutationEvidenceV1 {
            architecture: FaultCapabilityScope::X86_64,
            model_phase: 11,
            vcpu_index: 1,
            numeric_id: 7,
            mutation_kind: FaultRegisterMutationKindV1::BitFlip,
            declared_side_effects: 2,
            performed_side_effects: 2,
            first_bit: 5,
            bit_count: 1,
            observed_icount: 91,
            rr_current_vcpu: 1,
            rr_cursor_position: 11,
            rr_switch_quantum: 100,
            manifest_digest: [3; 32],
            cpu_model_digest: [4; 32],
            before_sha256: Sha256::digest(&before).into(),
            after_sha256: Sha256::digest(&after).into(),
            execution_fingerprint_sha256: [5; 32],
            before,
            after,
            mask: vec![1],
            value: vec![0],
        };
        let encoded = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode register evidence: {error}"));
        assert_eq!(
            FaultRegisterMutationEvidenceV1::decode(&encoded),
            Ok(evidence)
        );
        let mut corrupted = encoded;
        corrupted[FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES] ^= 1;
        assert!(FaultRegisterMutationEvidenceV1::decode(&corrupted).is_err());
    }
}
