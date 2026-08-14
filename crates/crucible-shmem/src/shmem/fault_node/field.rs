//! Typed node-fault field tags, discriminants, and values.

use super::*;

/// Field tags shared by the host codec and GPL-side command handlers.
///
/// Tags 1 through 31 are command-specific parameters. Tags 100 through 109
/// carry the resolved target coordinates needed by QEMU. A command schema must
/// reject every tag not listed for its command and target kind.
pub mod node_fault_field {
    /// First command-specific parameter.
    pub const P1: u16 = 1;
    /// Second command-specific parameter.
    pub const P2: u16 = 2;
    /// Third command-specific parameter.
    pub const P3: u16 = 3;
    /// Fourth command-specific parameter.
    pub const P4: u16 = 4;
    /// Fifth command-specific parameter.
    pub const P5: u16 = 5;
    /// Sixth command-specific parameter.
    pub const P6: u16 = 6;
    /// Seventh command-specific parameter.
    pub const P7: u16 = 7;
    /// Eighth command-specific parameter.
    pub const P8: u16 = 8;
    /// Ninth command-specific parameter.
    pub const P9: u16 = 9;
    /// Tenth command-specific parameter.
    pub const P10: u16 = 10;
    /// Eleventh command-specific parameter.
    pub const P11: u16 = 11;
    /// First target-specific coordinate.
    pub const T1: u16 = 100;
    /// Second target-specific coordinate.
    pub const T2: u16 = 101;
    /// Third target-specific coordinate.
    pub const T3: u16 = 102;
    /// Fourth target-specific coordinate.
    pub const T4: u16 = 103;
    /// Fifth target-specific coordinate.
    pub const T5: u16 = 104;
}

/// Mutation of a persistent QEMU rule or one exact impulse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NodeFaultOperationV1 {
    /// Installs or atomically replaces one binding-owned rule generation.
    Upsert = 1,
    /// Removes one binding-owned rule generation.
    Remove = 2,
    /// Applies one exact opportunity or boundary impulse.
    Apply = 3,
}

impl NodeFaultOperationV1 {
    pub(super) fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
        match value {
            1 => Ok(Self::Upsert),
            2 => Ok(Self::Remove),
            3 => Ok(Self::Apply),
            _ => Err(NodeFaultPayloadError::Operation(value)),
        }
    }
}

/// Stable category of the fully resolved command target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NodeFaultTargetKindV1 {
    /// One emulated node.
    Node = 1,
    /// One vCPU in a node.
    Vcpu = 2,
    /// One architecture register bit range.
    Register = 3,
    /// One guest physical or virtual memory range.
    Memory = 4,
    /// One fully routed interrupt.
    Interrupt = 5,
    /// One guest-visible clock source.
    Clock = 6,
    /// One realized accelerator device.
    Accelerator = 7,
}

impl NodeFaultTargetKindV1 {
    pub(super) fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
        match value {
            1 => Ok(Self::Node),
            2 => Ok(Self::Vcpu),
            3 => Ok(Self::Register),
            4 => Ok(Self::Memory),
            5 => Ok(Self::Interrupt),
            6 => Ok(Self::Clock),
            7 => Ok(Self::Accelerator),
            _ => Err(NodeFaultPayloadError::TargetKind(value)),
        }
    }
}

/// Closed scalar or bounded-vector type carried by one named field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NodeFaultFieldTypeV1 {
    /// Unsigned 32-bit integer.
    U32 = 1,
    /// Unsigned 64-bit integer.
    U64 = 2,
    /// Signed 64-bit integer.
    I64 = 3,
    /// Canonical boolean encoded as one byte containing zero or one.
    Bool = 4,
    /// Exact ratio encoded as an `i64` numerator and `u64` denominator.
    Ratio = 5,
    /// SHA-256/BLAKE3-sized stable identity or content digest.
    Hash = 6,
    /// Bounded raw bytes whose meaning is fixed by the field tag.
    Bytes = 7,
    /// Nonempty canonical ordered set of 32-byte identities.
    HashSet = 8,
}

impl NodeFaultFieldTypeV1 {
    pub(super) fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
        match value {
            1 => Ok(Self::U32),
            2 => Ok(Self::U64),
            3 => Ok(Self::I64),
            4 => Ok(Self::Bool),
            5 => Ok(Self::Ratio),
            6 => Ok(Self::Hash),
            7 => Ok(Self::Bytes),
            8 => Ok(Self::HashSet),
            _ => Err(NodeFaultPayloadError::FieldType(value)),
        }
    }
}

/// One schema-named typed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeFaultFieldV1 {
    /// Field tag defined by the selected command-kind schema.
    pub tag: u16,
    /// Canonical value type required for this tag.
    pub field_type: NodeFaultFieldTypeV1,
    /// Canonically encoded value bytes.
    pub value: Vec<u8>,
}

impl NodeFaultFieldV1 {
    /// Builds an unsigned 32-bit field.
    #[must_use]
    pub fn u32(tag: u16, value: u32) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::U32,
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// Builds an unsigned 64-bit field.
    #[must_use]
    pub fn u64(tag: u16, value: u64) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::U64,
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// Builds a signed 64-bit field.
    #[must_use]
    pub fn i64(tag: u16, value: i64) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::I64,
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// Builds a canonical boolean field.
    #[must_use]
    pub fn boolean(tag: u16, value: bool) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::Bool,
            value: vec![u8::from(value)],
        }
    }

    /// Builds an exact-ratio field.
    #[must_use]
    pub fn ratio(tag: u16, numerator: i64, denominator: u64) -> Self {
        let mut value = Vec::with_capacity(16);
        value.extend_from_slice(&numerator.to_le_bytes());
        value.extend_from_slice(&denominator.to_le_bytes());
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::Ratio,
            value,
        }
    }

    /// Builds a 32-byte identity field.
    #[must_use]
    pub fn hash(tag: u16, value: [u8; 32]) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::Hash,
            value: value.to_vec(),
        }
    }

    /// Builds a schema-bounded byte field.
    #[must_use]
    pub fn bytes(tag: u16, value: Vec<u8>) -> Self {
        Self {
            tag,
            field_type: NodeFaultFieldTypeV1::Bytes,
            value,
        }
    }

    /// Builds a canonical identity-set field.
    pub fn hash_set(tag: u16, values: &[[u8; 32]]) -> Result<Self, NodeFaultPayloadError> {
        if values.is_empty()
            || values.len() > NODE_FAULT_MAX_HASH_SET_V1
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(NodeFaultPayloadError::FieldValue { tag });
        }
        let mut value = Vec::with_capacity(values.len() * 32);
        for hash in values {
            value.extend_from_slice(hash);
        }
        Ok(Self {
            tag,
            field_type: NodeFaultFieldTypeV1::HashSet,
            value,
        })
    }

    pub(super) fn validate(&self) -> Result<(), NodeFaultPayloadError> {
        if self.tag == 0 {
            return Err(NodeFaultPayloadError::FieldTag);
        }
        let valid = match self.field_type {
            NodeFaultFieldTypeV1::U32 => self.value.len() == 4,
            NodeFaultFieldTypeV1::U64 | NodeFaultFieldTypeV1::I64 => self.value.len() == 8,
            NodeFaultFieldTypeV1::Bool => {
                self.value.as_slice() == [0] || self.value.as_slice() == [1]
            }
            NodeFaultFieldTypeV1::Ratio => {
                self.value.len() == 16
                    && i64::from_le_bytes(self.value[..8].try_into().unwrap_or([0; 8])) > 0
                    && u64::from_le_bytes(self.value[8..16].try_into().unwrap_or([0; 8])) != 0
            }
            NodeFaultFieldTypeV1::Hash => self.value.len() == 32,
            NodeFaultFieldTypeV1::Bytes => !self.value.is_empty(),
            NodeFaultFieldTypeV1::HashSet => {
                !self.value.is_empty()
                    && self.value.len().is_multiple_of(32)
                    && self.value.len() / 32 <= NODE_FAULT_MAX_HASH_SET_V1
                    && !self
                        .value
                        .chunks_exact(32)
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
            }
        };
        if !valid {
            return Err(NodeFaultPayloadError::FieldValue { tag: self.tag });
        }
        Ok(())
    }
}
