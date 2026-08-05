//! Public byte codecs for QEMU memory-fault commands and evidence.
//!
//! The formats in this module cross the Apache/GPL process boundary as
//! independently decoded little-endian bytes. They contain addresses, numeric
//! identifiers, byte transforms, and digests only; no QEMU type or pointer is
//! part of the contract.

use core::fmt::Write as _;

use thiserror::Error;

use crate::HARD_FAULT_PAYLOAD_BYTES;

/// Eight-byte magic for a version-1 memory-mutation payload.
pub const MEMORY_MUTATION_PAYLOAD_MAGIC_V1: [u8; 8] = *b"CRUCMEM1";
/// Semantic version of the memory-mutation payload.
pub const MEMORY_MUTATION_PAYLOAD_VERSION_V1: u16 = 1;
/// Exact fixed header size before transform bytes.
pub const MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES: usize = 104;
/// Payload semantic-version field offset.
pub const MEMORY_MUTATION_VERSION_OFFSET: usize = 8;
/// Payload address-space field offset.
pub const MEMORY_MUTATION_ADDRESS_SPACE_OFFSET: usize = 10;
/// Payload transform-kind field offset.
pub const MEMORY_MUTATION_TRANSFORM_OFFSET: usize = 12;
/// Payload atomicity field offset.
pub const MEMORY_MUTATION_ATOMICITY_OFFSET: usize = 14;
/// Payload vCPU-index field offset.
pub const MEMORY_MUTATION_VCPU_INDEX_OFFSET: usize = 16;
/// Payload changed-byte length field offset.
pub const MEMORY_MUTATION_LENGTH_OFFSET: usize = 20;
/// Payload first guest-address field offset.
pub const MEMORY_MUTATION_ADDRESS_OFFSET: usize = 24;
/// Payload mask-length field offset.
pub const MEMORY_MUTATION_MASK_LENGTH_OFFSET: usize = 32;
/// Payload replacement-value length field offset.
pub const MEMORY_MUTATION_VALUES_LENGTH_OFFSET: usize = 36;
/// Payload expected translation SHA-256 field offset.
pub const MEMORY_MUTATION_TRANSLATION_SHA256_OFFSET: usize = 40;
/// Payload reserved-byte field offset.
pub const MEMORY_MUTATION_RESERVED_OFFSET: usize = 72;
/// Payload transform body offset.
pub const MEMORY_MUTATION_BODY_OFFSET: usize = MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES;
/// Default maximum bytes changed by one memory-mutation effect.
pub const DEFAULT_MEMORY_MUTATION_BYTES: u32 = 1_048_576;
/// Hard maximum bytes changed by one memory-mutation effect.
pub const HARD_MEMORY_MUTATION_BYTES: u32 = 16_777_216;
/// Reserved vCPU identifier for a GPA mutation with no translation context.
pub const MEMORY_MUTATION_NO_VCPU: u32 = u32::MAX;

const _: () = assert!(
    HARD_FAULT_PAYLOAD_BYTES as usize
        == MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES + 2 * HARD_MEMORY_MUTATION_BYTES as usize
);

/// Address space selected by one memory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MemoryMutationAddressSpace {
    /// Mutates a guest physical RAM range.
    GuestPhysical = 1,
    /// Resolves and mutates a guest virtual RAM range in one vCPU context.
    GuestVirtual = 2,
}

impl MemoryMutationAddressSpace {
    pub(crate) fn decode(value: u16) -> Result<Self, MemoryMutationPayloadError> {
        match value {
            1 => Ok(Self::GuestPhysical),
            2 => Ok(Self::GuestVirtual),
            _ => Err(MemoryMutationPayloadError::AddressSpace(value)),
        }
    }
}

/// Byte transform selected by one memory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MemoryMutationTransformKind {
    /// XORs each before byte with the corresponding mask byte.
    BitFlip = 1,
    /// Replaces selected bits using `(before & !mask) | (value & mask)`.
    Replace = 2,
}

impl MemoryMutationTransformKind {
    pub(crate) fn decode(value: u16) -> Result<Self, MemoryMutationPayloadError> {
        match value {
            1 => Ok(Self::BitFlip),
            2 => Ok(Self::Replace),
            _ => Err(MemoryMutationPayloadError::Transform(value)),
        }
    }
}

/// Atomicity contract for a memory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MemoryMutationAtomicity {
    /// Resolves and validates the complete range before changing any byte.
    AllOrNothing = 1,
}

impl MemoryMutationAtomicity {
    fn decode(value: u16) -> Result<Self, MemoryMutationPayloadError> {
        match value {
            1 => Ok(Self::AllOrNothing),
            _ => Err(MemoryMutationPayloadError::Atomicity(value)),
        }
    }
}

/// One exact-boundary RAM mutation command payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationPayloadV1 {
    /// Guest address space to resolve.
    pub address_space: MemoryMutationAddressSpace,
    /// Bit-level transform to apply.
    pub transform: MemoryMutationTransformKind,
    /// Required atomic mutation behavior.
    pub atomicity: MemoryMutationAtomicity,
    /// vCPU context for GVA translation, or [`MEMORY_MUTATION_NO_VCPU`] for GPA.
    pub vcpu_index: u32,
    /// First guest physical or virtual byte address.
    pub address: u64,
    /// One mask byte per addressed byte.
    pub mask: Vec<u8>,
    /// One replacement byte per addressed byte for `Replace`; empty for `BitFlip`.
    pub values: Vec<u8>,
    /// SHA-256 of canonical GVA translation records, or zero for GPA.
    pub expected_translation_sha256: [u8; 32],
}

impl MemoryMutationPayloadV1 {
    /// Encodes the canonical little-endian payload.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationPayloadError`] when the address-space context,
    /// lengths, transform body, reserved digest, or address range is invalid.
    pub fn encode(&self) -> Result<Vec<u8>, MemoryMutationPayloadError> {
        self.validate()?;
        let length =
            u32::try_from(self.mask.len()).map_err(|_source| MemoryMutationPayloadError::Length)?;
        let values_len = u32::try_from(self.values.len())
            .map_err(|_source| MemoryMutationPayloadError::Length)?;
        let capacity = MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES
            .checked_add(self.mask.len())
            .and_then(|value| value.checked_add(self.values.len()))
            .ok_or(MemoryMutationPayloadError::Length)?;
        if capacity > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(MemoryMutationPayloadError::Length);
        }
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&MEMORY_MUTATION_PAYLOAD_MAGIC_V1);
        bytes.extend_from_slice(&MEMORY_MUTATION_PAYLOAD_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&(self.address_space as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.transform as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.atomicity as u16).to_le_bytes());
        bytes.extend_from_slice(&self.vcpu_index.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&self.address.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&values_len.to_le_bytes());
        bytes.extend_from_slice(&self.expected_translation_sha256);
        bytes.extend_from_slice(&[0_u8; 32]);
        bytes.extend_from_slice(&self.mask);
        bytes.extend_from_slice(&self.values);
        Ok(bytes)
    }

    /// Decodes and validates one canonical payload.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationPayloadError`] for bad framing, unknown tags,
    /// nonzero reserved bytes, inconsistent lengths, or invalid context.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationPayloadError> {
        if bytes.len() < MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES
            || bytes[..8] != MEMORY_MUTATION_PAYLOAD_MAGIC_V1
        {
            return Err(MemoryMutationPayloadError::Framing);
        }
        let read_u16 = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let read_u32 = |offset| {
            u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        };
        if read_u16(8) != MEMORY_MUTATION_PAYLOAD_VERSION_V1 {
            return Err(MemoryMutationPayloadError::Version);
        }
        if bytes[72..104].iter().any(|byte| *byte != 0) {
            return Err(MemoryMutationPayloadError::Reserved);
        }
        let length =
            usize::try_from(read_u32(20)).map_err(|_source| MemoryMutationPayloadError::Length)?;
        let mask_len =
            usize::try_from(read_u32(32)).map_err(|_source| MemoryMutationPayloadError::Length)?;
        let values_len =
            usize::try_from(read_u32(36)).map_err(|_source| MemoryMutationPayloadError::Length)?;
        let expected_len = MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES
            .checked_add(mask_len)
            .and_then(|value| value.checked_add(values_len))
            .ok_or(MemoryMutationPayloadError::Length)?;
        if length != mask_len
            || expected_len > HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes.len() != expected_len
        {
            return Err(MemoryMutationPayloadError::Length);
        }
        let mut expected_translation_sha256 = [0_u8; 32];
        expected_translation_sha256.copy_from_slice(&bytes[40..72]);
        let value_start = MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES + mask_len;
        let payload = Self {
            address_space: MemoryMutationAddressSpace::decode(read_u16(10))?,
            transform: MemoryMutationTransformKind::decode(read_u16(12))?,
            atomicity: MemoryMutationAtomicity::decode(read_u16(14))?,
            vcpu_index: read_u32(16),
            address: u64::from_le_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30],
                bytes[31],
            ]),
            mask: bytes[MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES..value_start].to_vec(),
            values: bytes[value_start..].to_vec(),
            expected_translation_sha256,
        };
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), MemoryMutationPayloadError> {
        if self.mask.is_empty() || self.mask.len() > HARD_MEMORY_MUTATION_BYTES as usize {
            return Err(MemoryMutationPayloadError::Length);
        }
        let length =
            u64::try_from(self.mask.len()).map_err(|_source| MemoryMutationPayloadError::Length)?;
        self.address
            .checked_add(length - 1)
            .ok_or(MemoryMutationPayloadError::AddressOverflow)?;
        match self.transform {
            MemoryMutationTransformKind::BitFlip if !self.values.is_empty() => {
                return Err(MemoryMutationPayloadError::TransformBody);
            }
            MemoryMutationTransformKind::Replace if self.values.len() != self.mask.len() => {
                return Err(MemoryMutationPayloadError::TransformBody);
            }
            MemoryMutationTransformKind::BitFlip | MemoryMutationTransformKind::Replace => {}
        }
        match self.address_space {
            MemoryMutationAddressSpace::GuestPhysical
                if self.vcpu_index != MEMORY_MUTATION_NO_VCPU
                    || self.expected_translation_sha256 != [0; 32] =>
            {
                Err(MemoryMutationPayloadError::AddressContext)
            }
            MemoryMutationAddressSpace::GuestVirtual
                if self.vcpu_index == MEMORY_MUTATION_NO_VCPU
                    || self.expected_translation_sha256 == [0; 32] =>
            {
                Err(MemoryMutationPayloadError::AddressContext)
            }
            MemoryMutationAddressSpace::GuestPhysical
            | MemoryMutationAddressSpace::GuestVirtual => Ok(()),
        }
    }
}

/// Failure to encode or decode a memory-mutation payload.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryMutationPayloadError {
    /// Magic or total framing is invalid.
    #[error("memory mutation payload framing is invalid")]
    Framing,
    /// Payload semantic version is unsupported.
    #[error("memory mutation payload version is unsupported")]
    Version,
    /// Address-space tag is unknown.
    #[error("memory mutation address-space tag {0} is unknown")]
    AddressSpace(u16),
    /// Transform tag is unknown.
    #[error("memory mutation transform tag {0} is unknown")]
    Transform(u16),
    /// Atomicity tag is unknown.
    #[error("memory mutation atomicity tag {0} is unknown")]
    Atomicity(u16),
    /// Length is zero, inconsistent, or above the hard bound.
    #[error("memory mutation length is invalid")]
    Length,
    /// Address plus length overflows the guest address space.
    #[error("memory mutation address range overflows")]
    AddressOverflow,
    /// Address-space, vCPU, and translation digest fields disagree.
    #[error("memory mutation address context is invalid")]
    AddressContext,
    /// Transform mask and replacement bytes disagree with the transform kind.
    #[error("memory mutation transform body is invalid")]
    TransformBody,
    /// Reserved bytes are nonzero.
    #[error("memory mutation reserved bytes are nonzero")]
    Reserved,
}

pub(crate) fn emit_memory_fault_c_header(out: &mut String) {
    macro_rules! define {
        ($name:literal, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }
    out.push_str("\n/* Versioned QEMU memory-fault payload ABI. */\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_PAYLOAD_MAGIC_V1 \"CRUCMEM1\"\n");
    define!(
        "CRUCIBLE_MEMORY_MUTATION_PAYLOAD_VERSION_V1",
        MEMORY_MUTATION_PAYLOAD_VERSION_V1
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES",
        MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_DEFAULT_BYTES",
        DEFAULT_MEMORY_MUTATION_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_HARD_BYTES",
        HARD_MEMORY_MUTATION_BYTES
    );
    define!("CRUCIBLE_MEMORY_MUTATION_NO_VCPU", MEMORY_MUTATION_NO_VCPU);
    define!(
        "CRUCIBLE_MEMORY_MUTATION_VERSION_OFFSET",
        MEMORY_MUTATION_VERSION_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ADDRESS_SPACE_OFFSET",
        MEMORY_MUTATION_ADDRESS_SPACE_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_TRANSFORM_OFFSET",
        MEMORY_MUTATION_TRANSFORM_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ATOMICITY_OFFSET",
        MEMORY_MUTATION_ATOMICITY_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_VCPU_INDEX_OFFSET",
        MEMORY_MUTATION_VCPU_INDEX_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_LENGTH_OFFSET",
        MEMORY_MUTATION_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ADDRESS_OFFSET",
        MEMORY_MUTATION_ADDRESS_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_MASK_LENGTH_OFFSET",
        MEMORY_MUTATION_MASK_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_VALUES_LENGTH_OFFSET",
        MEMORY_MUTATION_VALUES_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_TRANSLATION_SHA256_OFFSET",
        MEMORY_MUTATION_TRANSLATION_SHA256_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_RESERVED_OFFSET",
        MEMORY_MUTATION_RESERVED_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BODY_OFFSET",
        MEMORY_MUTATION_BODY_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ADDRESS_GPA",
        MemoryMutationAddressSpace::GuestPhysical as u16
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ADDRESS_GVA",
        MemoryMutationAddressSpace::GuestVirtual as u16
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_TRANSFORM_BIT_FLIP",
        MemoryMutationTransformKind::BitFlip as u16
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_TRANSFORM_REPLACE",
        MemoryMutationTransformKind::Replace as u16
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_ATOMIC_ALL_OR_NOTHING",
        MemoryMutationAtomicity::AllOrNothing as u16
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_mutation_payload_round_trips_both_transforms() {
        for payload in [
            MemoryMutationPayloadV1 {
                address_space: MemoryMutationAddressSpace::GuestPhysical,
                transform: MemoryMutationTransformKind::BitFlip,
                atomicity: MemoryMutationAtomicity::AllOrNothing,
                vcpu_index: MEMORY_MUTATION_NO_VCPU,
                address: 0x1000,
                mask: vec![1, 2, 4],
                values: Vec::new(),
                expected_translation_sha256: [0; 32],
            },
            MemoryMutationPayloadV1 {
                address_space: MemoryMutationAddressSpace::GuestVirtual,
                transform: MemoryMutationTransformKind::Replace,
                atomicity: MemoryMutationAtomicity::AllOrNothing,
                vcpu_index: 3,
                address: 0x7fff_0000,
                mask: vec![0xff, 0x0f],
                values: vec![0xa5, 0x05],
                expected_translation_sha256: [9; 32],
            },
        ] {
            let bytes = payload
                .encode()
                .unwrap_or_else(|error| panic!("encode memory mutation: {error}"));
            assert_eq!(MemoryMutationPayloadV1::decode(&bytes), Ok(payload));
        }
    }

    #[test]
    fn memory_mutation_payload_rejects_partial_or_ambiguous_context() {
        let invalid = MemoryMutationPayloadV1 {
            address_space: MemoryMutationAddressSpace::GuestPhysical,
            transform: MemoryMutationTransformKind::Replace,
            atomicity: MemoryMutationAtomicity::AllOrNothing,
            vcpu_index: 0,
            address: u64::MAX,
            mask: vec![0xff, 0xff],
            values: vec![0, 0],
            expected_translation_sha256: [1; 32],
        };
        assert_eq!(
            invalid.encode(),
            Err(MemoryMutationPayloadError::AddressOverflow)
        );
    }

    #[test]
    fn memory_mutation_payload_bounds_match_the_transport_envelope() {
        let maximum = MemoryMutationPayloadV1 {
            address_space: MemoryMutationAddressSpace::GuestPhysical,
            transform: MemoryMutationTransformKind::Replace,
            atomicity: MemoryMutationAtomicity::AllOrNothing,
            vcpu_index: MEMORY_MUTATION_NO_VCPU,
            address: 0,
            mask: vec![0xff; HARD_MEMORY_MUTATION_BYTES as usize],
            values: vec![0xa5; HARD_MEMORY_MUTATION_BYTES as usize],
            expected_translation_sha256: [0; 32],
        };
        let encoded = maximum
            .encode()
            .unwrap_or_else(|error| panic!("encode maximum mutation: {error}"));
        assert_eq!(encoded.len(), HARD_FAULT_PAYLOAD_BYTES as usize);

        let mut above = maximum;
        above.mask.push(0xff);
        above.values.push(0xa5);
        assert_eq!(above.encode(), Err(MemoryMutationPayloadError::Length));
    }
}
