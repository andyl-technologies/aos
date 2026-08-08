//! Closed typed-field codec for non-impulse QEMU node fault commands.
//!
//! The command kind in [`FaultCommandHeaderV1`](crate::FaultCommandHeaderV1)
//! selects a closed schema. This module carries that schema's operation,
//! target, and named fields as canonical little-endian bytes. Fields are
//! strictly ordered and uniquely tagged, so the GPL-side implementation can
//! reject unknown, duplicate, missing, or incorrectly typed values before it
//! changes QEMU state.

use core::fmt::Write as _;
use thiserror::Error;

use crate::{FaultCommandKind, HARD_FAULT_PAYLOAD_BYTES};

/// Eight-byte magic for a version-1 typed node-fault payload.
pub const NODE_FAULT_PAYLOAD_MAGIC_V1: [u8; 8] = *b"CRUCNOD1";
/// Semantic version of the typed node-fault payload.
pub const NODE_FAULT_PAYLOAD_VERSION_V1: u16 = 1;
/// Fixed bytes before the first typed field.
pub const NODE_FAULT_PAYLOAD_HEADER_V1_BYTES: usize = 128;
/// Fixed bytes in one typed-field header.
pub const NODE_FAULT_FIELD_HEADER_V1_BYTES: usize = 8;
/// Maximum number of typed fields in one command.
pub const NODE_FAULT_MAX_FIELDS_V1: usize = 128;
/// Maximum hashes in one canonical identity set.
pub const NODE_FAULT_MAX_HASH_SET_V1: usize = 4_096;
/// Eight-byte prefix for a closed policy encoded as canonical JSON.
pub const NODE_FAULT_POLICY_JSON_MAGIC_V1: [u8; 8] = *b"CRUCJSN1";
/// Eight-byte magic for typed node command evidence.
pub const NODE_FAULT_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCNEV1";
/// Fixed byte length of typed node command evidence.
pub const NODE_FAULT_EVIDENCE_V1_BYTES: usize = 228;

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
    fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
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
    fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
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
    fn decode(value: u16) -> Result<Self, NodeFaultPayloadError> {
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

    fn validate(&self) -> Result<(), NodeFaultPayloadError> {
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
                    && self.value.len() % 32 == 0
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

/// One closed-schema node rule or impulse payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeFaultPayloadV1 {
    /// Command kind whose schema validates `fields`.
    pub command_kind: FaultCommandKind,
    /// Rule-table operation or exact impulse.
    pub operation: NodeFaultOperationV1,
    /// Fully resolved target category.
    pub target_kind: NodeFaultTargetKindV1,
    /// Original model phase as its closed registry tag.
    pub model_phase: u16,
    /// Binding transition/rule generation.
    pub generation: u64,
    /// Canonical resolved action identity.
    pub action_hash: [u8; 32],
    /// Canonical resolved target identity.
    pub target_hash: [u8; 32],
    /// Schema identity advertised in the capability manifest.
    pub schema_hash: [u8; 32],
    /// Strictly increasing, uniquely tagged typed fields.
    pub fields: Vec<NodeFaultFieldV1>,
}

impl NodeFaultPayloadV1 {
    /// Encodes the canonical payload after structural and schema validation.
    ///
    /// # Errors
    ///
    /// Returns [`NodeFaultPayloadError`] for unsupported command kinds,
    /// malformed fields, noncanonical ordering, missing schema fields, or size
    /// overflow.
    pub fn encode(&self) -> Result<Vec<u8>, NodeFaultPayloadError> {
        self.validate()?;
        let body_bytes = self.fields.iter().try_fold(0_usize, |total, field| {
            total
                .checked_add(NODE_FAULT_FIELD_HEADER_V1_BYTES)
                .and_then(|value| value.checked_add(field.value.len()))
                .ok_or(NodeFaultPayloadError::Length)
        })?;
        let total = NODE_FAULT_PAYLOAD_HEADER_V1_BYTES
            .checked_add(body_bytes)
            .ok_or(NodeFaultPayloadError::Length)?;
        if total > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(NodeFaultPayloadError::Length);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&NODE_FAULT_PAYLOAD_MAGIC_V1);
        bytes.extend_from_slice(&NODE_FAULT_PAYLOAD_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&(self.command_kind as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.operation as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.target_kind as u16).to_le_bytes());
        bytes.extend_from_slice(&self.model_phase.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.action_hash);
        bytes.extend_from_slice(&self.target_hash);
        bytes.extend_from_slice(&self.schema_hash);
        bytes.extend_from_slice(&(self.fields.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        debug_assert_eq!(bytes.len(), NODE_FAULT_PAYLOAD_HEADER_V1_BYTES);
        for field in &self.fields {
            bytes.extend_from_slice(&field.tag.to_le_bytes());
            bytes.extend_from_slice(&(field.field_type as u16).to_le_bytes());
            bytes.extend_from_slice(&(field.value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&field.value);
        }
        Ok(bytes)
    }

    /// Decodes and validates one canonical payload.
    ///
    /// # Errors
    ///
    /// Returns [`NodeFaultPayloadError`] for every version, tag, reserved,
    /// length, canonical-order, field-type, or schema violation.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeFaultPayloadError> {
        if bytes.len() < NODE_FAULT_PAYLOAD_HEADER_V1_BYTES
            || bytes.len() > HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != NODE_FAULT_PAYLOAD_MAGIC_V1
        {
            return Err(NodeFaultPayloadError::Length);
        }
        let u16_at = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        if u16_at(8) != NODE_FAULT_PAYLOAD_VERSION_V1 || u16_at(18) != 0 || u16_at(126) != 0 {
            return Err(NodeFaultPayloadError::VersionOrReserved);
        }
        let command_kind = FaultCommandKind::from_u16(u16_at(10))
            .map_err(|_| NodeFaultPayloadError::CommandKind(u16_at(10)))?;
        let operation = NodeFaultOperationV1::decode(u16_at(12))?;
        let target_kind = NodeFaultTargetKindV1::decode(u16_at(14))?;
        let model_phase = u16_at(16);
        let generation = u64::from_le_bytes(
            bytes[20..28]
                .try_into()
                .map_err(|_| NodeFaultPayloadError::Length)?,
        );
        let action_hash = bytes[28..60]
            .try_into()
            .map_err(|_| NodeFaultPayloadError::Length)?;
        let target_hash = bytes[60..92]
            .try_into()
            .map_err(|_| NodeFaultPayloadError::Length)?;
        let schema_hash = bytes[92..124]
            .try_into()
            .map_err(|_| NodeFaultPayloadError::Length)?;
        let count = usize::from(u16_at(124));
        if count > NODE_FAULT_MAX_FIELDS_V1 {
            return Err(NodeFaultPayloadError::FieldCount);
        }
        let mut offset = NODE_FAULT_PAYLOAD_HEADER_V1_BYTES;
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let header_end = offset
                .checked_add(NODE_FAULT_FIELD_HEADER_V1_BYTES)
                .ok_or(NodeFaultPayloadError::Length)?;
            if header_end > bytes.len() {
                return Err(NodeFaultPayloadError::Length);
            }
            let tag = u16::from_le_bytes(
                bytes[offset..offset + 2]
                    .try_into()
                    .map_err(|_| NodeFaultPayloadError::Length)?,
            );
            let field_type = NodeFaultFieldTypeV1::decode(u16::from_le_bytes(
                bytes[offset + 2..offset + 4]
                    .try_into()
                    .map_err(|_| NodeFaultPayloadError::Length)?,
            ))?;
            let length = usize::try_from(u32::from_le_bytes(
                bytes[offset + 4..header_end]
                    .try_into()
                    .map_err(|_| NodeFaultPayloadError::Length)?,
            ))
            .map_err(|_| NodeFaultPayloadError::Length)?;
            offset = header_end;
            let end = offset
                .checked_add(length)
                .ok_or(NodeFaultPayloadError::Length)?;
            if end > bytes.len() {
                return Err(NodeFaultPayloadError::Length);
            }
            fields.push(NodeFaultFieldV1 {
                tag,
                field_type,
                value: bytes[offset..end].to_vec(),
            });
            offset = end;
        }
        if offset != bytes.len() {
            return Err(NodeFaultPayloadError::Length);
        }
        let value = Self {
            command_kind,
            operation,
            target_kind,
            model_phase,
            generation,
            action_hash,
            target_hash,
            schema_hash,
            fields,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), NodeFaultPayloadError> {
        if !matches!(
            self.command_kind,
            FaultCommandKind::NodeLifecycle
                | FaultCommandKind::NodeHang
                | FaultCommandKind::CpuService
                | FaultCommandKind::CpuVcpuState
                | FaultCommandKind::CpuRegisterTransform
                | FaultCommandKind::CpuInstructionTransform
                | FaultCommandKind::CpuException
                | FaultCommandKind::InterruptDisposition
                | FaultCommandKind::InterruptStorm
                | FaultCommandKind::MemoryAccessTransform
                | FaultCommandKind::MemoryEccEvent
                | FaultCommandKind::MemoryRegionState
                | FaultCommandKind::MemoryService
                | FaultCommandKind::ClockTransform
                | FaultCommandKind::ClockSourceState
                | FaultCommandKind::AcceleratorLifecycle
                | FaultCommandKind::AcceleratorResultTransform
                | FaultCommandKind::AcceleratorMemoryEvent
                | FaultCommandKind::AcceleratorService
        ) {
            return Err(NodeFaultPayloadError::CommandKind(self.command_kind as u16));
        }
        if self.model_phase == 0
            || self.generation == 0
            || self.action_hash == [0; 32]
            || self.target_hash == [0; 32]
            || self.schema_hash == [0; 32]
            || self.fields.len() > NODE_FAULT_MAX_FIELDS_V1
        {
            return Err(NodeFaultPayloadError::HeaderValue);
        }
        if !self.command_target_pair_is_valid() {
            return Err(NodeFaultPayloadError::TargetSchema {
                command_kind: self.command_kind as u16,
                target_kind: self.target_kind as u16,
            });
        }
        if self.operation == NodeFaultOperationV1::Remove {
            if !self.fields.is_empty() {
                return Err(NodeFaultPayloadError::RemoveFields);
            }
            return Ok(());
        }
        if self.fields.is_empty() {
            return Err(NodeFaultPayloadError::FieldCount);
        }
        let mut previous = 0;
        for field in &self.fields {
            field.validate()?;
            if field.tag <= previous {
                return Err(NodeFaultPayloadError::FieldOrder);
            }
            previous = field.tag;
        }
        self.validate_closed_schema()?;
        Ok(())
    }

    fn command_target_pair_is_valid(&self) -> bool {
        use FaultCommandKind as Command;
        use NodeFaultTargetKindV1 as Target;

        matches!(
            (self.command_kind, self.target_kind),
            (Command::NodeLifecycle, Target::Node)
                | (
                    Command::NodeHang,
                    Target::Node | Target::Vcpu | Target::Accelerator
                )
                | (Command::CpuService, Target::Node | Target::Vcpu)
                | (Command::CpuVcpuState, Target::Vcpu)
                | (Command::CpuRegisterTransform, Target::Register)
                | (
                    Command::CpuInstructionTransform | Command::CpuException,
                    Target::Vcpu
                )
                | (
                    Command::InterruptDisposition | Command::InterruptStorm,
                    Target::Interrupt
                )
                | (
                    Command::MemoryAccessTransform
                        | Command::MemoryEccEvent
                        | Command::MemoryRegionState
                        | Command::MemoryService,
                    Target::Memory
                )
                | (
                    Command::ClockTransform | Command::ClockSourceState,
                    Target::Clock
                )
                | (
                    Command::AcceleratorLifecycle
                        | Command::AcceleratorResultTransform
                        | Command::AcceleratorMemoryEvent
                        | Command::AcceleratorService,
                    Target::Accelerator
                )
        )
    }

    fn validate_closed_schema(&self) -> Result<(), NodeFaultPayloadError> {
        use NodeFaultFieldTypeV1 as Ty;
        use node_fault_field::*;

        let target = match self.target_kind {
            NodeFaultTargetKindV1::Node => &[][..],
            NodeFaultTargetKindV1::Vcpu => &[(T1, Ty::U32)][..],
            NodeFaultTargetKindV1::Register => &[
                (T1, Ty::U32),
                (T2, Ty::Hash),
                (T3, Ty::Hash),
                (T4, Ty::U32),
                (T5, Ty::U32),
            ][..],
            NodeFaultTargetKindV1::Memory => &[
                (T1, Ty::Hash),
                (T2, Ty::U64),
                (T3, Ty::Bool),
                (T4, Ty::U32),
                (T5, Ty::U64),
            ][..],
            NodeFaultTargetKindV1::Interrupt => {
                &[(T1, Ty::Hash), (T2, Ty::Hash), (T3, Ty::U32), (T4, Ty::U32)][..]
            }
            NodeFaultTargetKindV1::Clock => &[(T1, Ty::Hash)][..],
            NodeFaultTargetKindV1::Accelerator => &[(T1, Ty::Hash)][..],
        };
        let parameters = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::Bytes),
                (P4, Ty::U32),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::NodeHang => &[
                (P1, Ty::U32),
                (P2, Ty::Bytes),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
            ][..],
            FaultCommandKind::CpuService => &[
                (P1, Ty::Bytes),
                (P2, Ty::Ratio),
                (P3, Ty::U64),
                (P4, Ty::U32),
            ][..],
            FaultCommandKind::CpuVcpuState => &[(P1, Ty::U32), (P2, Ty::Bool), (P3, Ty::Hash)][..],
            FaultCommandKind::CpuRegisterTransform => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U32),
                (P4, Ty::U32),
                (P5, Ty::Bytes),
                (P6, Ty::Bool),
                (P7, Ty::Bytes),
                (P8, Ty::Bytes),
            ][..],
            FaultCommandKind::CpuInstructionTransform => &[
                (P1, Ty::Bytes),
                (P2, Ty::U32),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::CpuException => &[(P1, Ty::Bytes)][..],
            FaultCommandKind::InterruptDisposition => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::U64),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::InterruptStorm => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U64),
                (P4, Ty::U32),
                (P5, Ty::U32),
                (P6, Ty::Bytes),
            ][..],
            FaultCommandKind::MemoryAccessTransform => &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::Bytes),
                (P5, Ty::Bool),
                (P6, Ty::Bytes),
                (P7, Ty::Bytes),
                (P8, Ty::U32),
                (P9, Ty::Bool),
                (P10, Ty::Bool),
                (P11, Ty::Hash),
            ][..],
            FaultCommandKind::MemoryEccEvent => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U64),
                (P4, Ty::Hash),
                (P5, Ty::Hash),
                (P6, Ty::Hash),
                (P7, Ty::Bytes),
            ][..],
            FaultCommandKind::MemoryRegionState => {
                &[(P1, Ty::U64), (P2, Ty::U64), (P3, Ty::U32), (P4, Ty::Bytes)][..]
            }
            FaultCommandKind::MemoryService => &[
                (P1, Ty::U64),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ][..],
            FaultCommandKind::ClockTransform => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::I64),
                (P4, Ty::Ratio),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
                (P7, Ty::U32),
                (P8, Ty::U32),
            ][..],
            FaultCommandKind::ClockSourceState => {
                &[(P1, Ty::HashSet), (P2, Ty::Bytes), (P3, Ty::Bytes)][..]
            }
            FaultCommandKind::AcceleratorLifecycle => {
                &[(P1, Ty::Hash), (P2, Ty::U32), (P3, Ty::U32), (P4, Ty::U32)][..]
            }
            FaultCommandKind::AcceleratorResultTransform => &[(P1, Ty::Bytes), (P2, Ty::Bytes)][..],
            FaultCommandKind::AcceleratorMemoryEvent => &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::Bool),
                (P4, Ty::U32),
                (P5, Ty::Bool),
                (P6, Ty::U64),
                (P7, Ty::Bool),
                (P8, Ty::Bytes),
            ][..],
            FaultCommandKind::AcceleratorService => &[
                (P1, Ty::Ratio),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ][..],
            _ => return Err(NodeFaultPayloadError::CommandKind(self.command_kind as u16)),
        };
        if self.fields.len() != parameters.len() + target.len()
            || !parameters.iter().chain(target).all(|(tag, field_type)| {
                self.fields
                    .binary_search_by_key(tag, |field| field.tag)
                    .is_ok_and(|index| self.fields[index].field_type == *field_type)
            })
        {
            return Err(NodeFaultPayloadError::Schema {
                command_kind: self.command_kind as u16,
            });
        }
        self.validate_policy_fields()?;
        self.validate_discriminants()?;
        self.validate_cross_fields()?;
        Ok(())
    }

    fn validate_discriminants(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        let allowed: &[(u16, &[u32])] = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[
                (P1, &[1, 2, 3, 4, 5, 6]),
                (P4, &[1, 2, 3]),
                (P5, &[1, 2, 3]),
            ],
            FaultCommandKind::NodeHang => &[(P1, &[1, 2, 3])],
            FaultCommandKind::CpuService => &[(P4, &[1, 2])],
            FaultCommandKind::CpuVcpuState => &[(P1, &[1, 2, 3])],
            FaultCommandKind::CpuRegisterTransform => &[(P4, &[1, 2, 3])],
            FaultCommandKind::CpuInstructionTransform => &[(P2, &[1, 2, 3])],
            FaultCommandKind::InterruptDisposition => &[(P1, &[1, 2, 3, 4])],
            FaultCommandKind::MemoryAccessTransform => &[(P3, &[1, 2, 3, 4, 5])],
            FaultCommandKind::MemoryEccEvent => &[(P1, &[1, 2])],
            FaultCommandKind::MemoryRegionState => &[(P3, &[1, 2, 3])],
            FaultCommandKind::ClockTransform => &[
                (P2, &[1, 2, 3, 4, 5, 6]),
                (P7, &[1, 2, 3]),
                (P8, &[1, 2, 3]),
            ],
            FaultCommandKind::AcceleratorLifecycle => {
                &[(P2, &[1, 2, 3]), (P3, &[1, 2, 3]), (P4, &[1, 2, 3])]
            }
            _ => &[],
        };
        for (tag, values) in allowed {
            if !values.contains(&self.u32_field(*tag)?) {
                return Err(NodeFaultPayloadError::FieldValue { tag: *tag });
            }
        }
        if self.command_kind == FaultCommandKind::MemoryAccessTransform {
            let classes = self.u32_field(P8)?;
            if classes == 0 || classes & !0x1f != 0 {
                return Err(NodeFaultPayloadError::FieldValue { tag: P8 });
            }
        }
        Ok(())
    }

    fn validate_cross_fields(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        match self.command_kind {
            FaultCommandKind::CpuInstructionTransform => match self.u32_field(P2)? {
                1 if self.hash_is_zero(P3)? || self.u32_field(P5)? != 0 => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P3 })
                }
                2 if !self.hash_is_zero(P3)? || self.u32_field(P5)? != 0 => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P5 })
                }
                3 if !self.hash_is_zero(P3)? || !(1..=256).contains(&self.u32_field(P5)?) => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P5 })
                }
                _ => Ok(()),
            },
            FaultCommandKind::MemoryAccessTransform => {
                if self.u64_field(P2)? == 0 {
                    return Err(NodeFaultPayloadError::FieldValue { tag: P2 });
                }
                let kind = self.u32_field(P3)?;
                let has_value = self.bool_field(P5)?;
                let violate_atomicity = self.bool_field(P9)?;
                let has_dma_device = self.bool_field(P10)?;
                let dma_device_valid = if has_dma_device {
                    !self.hash_is_zero(P11)?
                        && self.u32_field(P8)? & !0x18 == 0
                        && !self.bool_field(T3)?
                } else {
                    self.hash_is_zero(P11)?
                };
                let mask = self.field_with_tag(P4)?.value.as_slice();
                let value = self.field_with_tag(P6)?.value.as_slice();
                let mask_has_one = mask.iter().any(|byte| *byte != 0);
                let value_has_one = value.iter().any(|byte| *byte != 0);
                let valid = match kind {
                    1 => {
                        has_value && !violate_atomicity && mask_has_one && mask.len() == value.len()
                    }
                    2 => !has_value && !violate_atomicity && mask_has_one && value == [0],
                    3 => !has_value && !violate_atomicity && mask == [0] && value == [0],
                    4 => {
                        has_value
                            && mask == [0]
                            && value_has_one
                            && value.iter().any(|byte| *byte != u8::MAX)
                    }
                    5 => has_value && !violate_atomicity && mask == [0],
                    _ => false,
                };
                if valid && dma_device_valid {
                    Ok(())
                } else {
                    Err(NodeFaultPayloadError::FieldValue { tag: P3 })
                }
            }
            FaultCommandKind::ClockTransform => {
                let kind = self.u32_field(P2)?;
                let process_is_sentinel = self.field_with_tag(P6)?.value == [0];
                if matches!(kind, 4 | 5 | 6) == process_is_sentinel {
                    Err(NodeFaultPayloadError::FieldValue { tag: P6 })
                } else {
                    Ok(())
                }
            }
            FaultCommandKind::AcceleratorMemoryEvent => {
                let has_ecc = self.bool_field(P3)?;
                let has_syndrome = self.bool_field(P5)?;
                let has_transform = self.bool_field(P7)?;
                let transform = self.field_with_tag(P8)?.value.as_slice();
                if (has_ecc && has_syndrome && !has_transform && transform == [0])
                    || (!has_ecc && !has_syndrome && has_transform && transform != [0])
                {
                    Ok(())
                } else {
                    Err(NodeFaultPayloadError::FieldValue { tag: P7 })
                }
            }
            _ => Ok(()),
        }
    }

    fn validate_policy_fields(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        let required: &[u16] = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[P3],
            FaultCommandKind::NodeHang => &[P2, P4],
            FaultCommandKind::CpuService => &[P1],
            FaultCommandKind::CpuRegisterTransform => &[P8],
            FaultCommandKind::CpuInstructionTransform => &[P1],
            FaultCommandKind::CpuException => &[P1],
            FaultCommandKind::InterruptStorm => &[P6],
            FaultCommandKind::MemoryAccessTransform => &[P7],
            FaultCommandKind::MemoryEccEvent => &[P7],
            FaultCommandKind::MemoryRegionState => &[P4],
            FaultCommandKind::MemoryService => &[P6],
            FaultCommandKind::ClockSourceState => &[P2, P3],
            FaultCommandKind::AcceleratorResultTransform => &[P1, P2],
            FaultCommandKind::AcceleratorService => &[P6],
            _ => &[],
        };
        for tag in required {
            self.validate_policy_json(*tag)?;
        }
        if self.command_kind == FaultCommandKind::CpuInstructionTransform {
            if self.u32_field(P2)? == 1 {
                self.validate_policy_json(P4)?;
            } else {
                self.validate_sentinel(P4)?;
            }
        }
        if self.command_kind == FaultCommandKind::MemoryAccessTransform {
            if self.u32_field(P3)? == 5 {
                self.validate_policy_json(P6)?;
            }
        }
        if self.command_kind == FaultCommandKind::ClockTransform {
            if matches!(self.u32_field(P2)?, 4 | 5 | 6) {
                self.validate_policy_json(P6)?;
            } else {
                self.validate_sentinel(P6)?;
            }
        }
        Ok(())
    }

    fn field_with_tag(&self, tag: u16) -> Result<&NodeFaultFieldV1, NodeFaultPayloadError> {
        self.fields
            .binary_search_by_key(&tag, |field| field.tag)
            .map(|index| &self.fields[index])
            .map_err(|_| NodeFaultPayloadError::Schema {
                command_kind: self.command_kind as u16,
            })
    }

    fn u32_field(&self, tag: u16) -> Result<u32, NodeFaultPayloadError> {
        let field = self.field_with_tag(tag)?;
        field
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| NodeFaultPayloadError::FieldValue { tag })
    }

    fn u64_field(&self, tag: u16) -> Result<u64, NodeFaultPayloadError> {
        let field = self.field_with_tag(tag)?;
        field
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| NodeFaultPayloadError::FieldValue { tag })
    }

    fn bool_field(&self, tag: u16) -> Result<bool, NodeFaultPayloadError> {
        match self.field_with_tag(tag)?.value.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(NodeFaultPayloadError::FieldValue { tag }),
        }
    }

    fn hash_is_zero(&self, tag: u16) -> Result<bool, NodeFaultPayloadError> {
        let value = self.field_with_tag(tag)?.value.as_slice();
        if value.len() == 32 {
            Ok(value.iter().all(|byte| *byte == 0))
        } else {
            Err(NodeFaultPayloadError::FieldValue { tag })
        }
    }

    fn validate_sentinel(&self, tag: u16) -> Result<(), NodeFaultPayloadError> {
        if self.field_with_tag(tag)?.value == [0] {
            Ok(())
        } else {
            Err(NodeFaultPayloadError::FieldValue { tag })
        }
    }

    fn validate_policy_json(&self, tag: u16) -> Result<(), NodeFaultPayloadError> {
        let bytes = &self.field_with_tag(tag)?.value;
        let Some(json) = bytes.strip_prefix(&NODE_FAULT_POLICY_JSON_MAGIC_V1) else {
            return Err(NodeFaultPayloadError::PolicyJson { tag });
        };
        let value: serde_json::Value = serde_json::from_slice(json)
            .map_err(|_source| NodeFaultPayloadError::PolicyJson { tag })?;
        if !matches!(
            value,
            serde_json::Value::Object(_)
                | serde_json::Value::Array(_)
                | serde_json::Value::String(_)
        ) || !policy_json_value_is_allowed(&value)
        {
            return Err(NodeFaultPayloadError::PolicyJson { tag });
        }
        let canonical = serde_json::to_vec(&value)
            .map_err(|_source| NodeFaultPayloadError::PolicyJson { tag })?;
        if canonical == json {
            Ok(())
        } else {
            Err(NodeFaultPayloadError::PolicyJson { tag })
        }
    }
}

fn policy_json_value_is_allowed(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => true,
        serde_json::Value::Number(number) => number.is_i64() || number.is_u64(),
        serde_json::Value::Array(values) => values.iter().all(policy_json_value_is_allowed),
        serde_json::Value::Object(values) => values.values().all(policy_json_value_is_allowed),
    }
}

/// Typed acknowledgement of one prepared or committed node rule transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeFaultEvidenceV1 {
    /// Command schema that QEMU validated.
    pub command_kind: FaultCommandKind,
    /// Requested rule-table operation or impulse.
    pub operation: NodeFaultOperationV1,
    /// Resolved target category.
    pub target_kind: NodeFaultTargetKindV1,
    /// Original model phase installed in the rule.
    pub model_phase: u16,
    /// Requested binding generation.
    pub generation: u64,
    /// Prior installed generation, or zero when no rule existed.
    pub prior_generation: u64,
    /// Exact resolved action identity.
    pub action_hash: [u8; 32],
    /// Exact resolved target identity.
    pub target_hash: [u8; 32],
    /// Capability schema identity used for validation.
    pub schema_hash: [u8; 32],
    /// SHA-256 of the complete command payload.
    pub request_sha256: [u8; 32],
    /// QEMU rule-table or architecture state before the transaction.
    pub before_sha256: [u8; 32],
    /// QEMU rule-table or architecture state after the transaction.
    pub after_sha256: [u8; 32],
}

impl NodeFaultEvidenceV1 {
    /// Encodes the fixed canonical evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`NodeFaultPayloadError`] when a required identity, generation,
    /// phase, or state digest is invalid.
    pub fn encode(&self) -> Result<[u8; NODE_FAULT_EVIDENCE_V1_BYTES], NodeFaultPayloadError> {
        self.validate()?;
        let mut bytes = [0_u8; NODE_FAULT_EVIDENCE_V1_BYTES];
        bytes[..8].copy_from_slice(&NODE_FAULT_EVIDENCE_MAGIC_V1);
        bytes[8..10].copy_from_slice(&NODE_FAULT_PAYLOAD_VERSION_V1.to_le_bytes());
        bytes[10..12].copy_from_slice(&(self.command_kind as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&(self.operation as u16).to_le_bytes());
        bytes[14..16].copy_from_slice(&(self.target_kind as u16).to_le_bytes());
        bytes[16..18].copy_from_slice(&self.model_phase.to_le_bytes());
        bytes[18..20].copy_from_slice(&0_u16.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.generation.to_le_bytes());
        bytes[28..36].copy_from_slice(&self.prior_generation.to_le_bytes());
        bytes[36..68].copy_from_slice(&self.action_hash);
        bytes[68..100].copy_from_slice(&self.target_hash);
        bytes[100..132].copy_from_slice(&self.schema_hash);
        bytes[132..164].copy_from_slice(&self.request_sha256);
        bytes[164..196].copy_from_slice(&self.before_sha256);
        bytes[196..228].copy_from_slice(&self.after_sha256);
        Ok(bytes)
    }

    /// Decodes and validates a fixed canonical evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`NodeFaultPayloadError`] for invalid lengths, versions, tags,
    /// reserved bytes, identities, generations, or state digests.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeFaultPayloadError> {
        if bytes.len() != NODE_FAULT_EVIDENCE_V1_BYTES
            || bytes[..8] != NODE_FAULT_EVIDENCE_MAGIC_V1
            || u16::from_le_bytes([bytes[8], bytes[9]]) != NODE_FAULT_PAYLOAD_VERSION_V1
            || bytes[18..20] != [0, 0]
        {
            return Err(NodeFaultPayloadError::VersionOrReserved);
        }
        let hash = |start: usize| {
            bytes[start..start + 32]
                .try_into()
                .map_err(|_| NodeFaultPayloadError::Length)
        };
        let value = Self {
            command_kind: FaultCommandKind::from_u16(u16::from_le_bytes([bytes[10], bytes[11]]))
                .map_err(|_| {
                    NodeFaultPayloadError::CommandKind(u16::from_le_bytes([bytes[10], bytes[11]]))
                })?,
            operation: NodeFaultOperationV1::decode(u16::from_le_bytes([bytes[12], bytes[13]]))?,
            target_kind: NodeFaultTargetKindV1::decode(u16::from_le_bytes([bytes[14], bytes[15]]))?,
            model_phase: u16::from_le_bytes([bytes[16], bytes[17]]),
            generation: u64::from_le_bytes(
                bytes[20..28]
                    .try_into()
                    .map_err(|_| NodeFaultPayloadError::Length)?,
            ),
            prior_generation: u64::from_le_bytes(
                bytes[28..36]
                    .try_into()
                    .map_err(|_| NodeFaultPayloadError::Length)?,
            ),
            action_hash: hash(36)?,
            target_hash: hash(68)?,
            schema_hash: hash(100)?,
            request_sha256: hash(132)?,
            before_sha256: hash(164)?,
            after_sha256: hash(196)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), NodeFaultPayloadError> {
        if matches!(
            self.command_kind,
            FaultCommandKind::QueryCapabilities
                | FaultCommandKind::BoundaryProbe
                | FaultCommandKind::MemoryMutation
        ) || self.model_phase == 0
            || self.generation == 0
            || self.action_hash == [0; 32]
            || self.target_hash == [0; 32]
            || self.schema_hash == [0; 32]
            || self.request_sha256 == [0; 32]
            || self.before_sha256 == [0; 32]
            || self.after_sha256 == [0; 32]
        {
            return Err(NodeFaultPayloadError::HeaderValue);
        }
        Ok(())
    }
}

/// Failure to encode or decode a typed node-fault payload.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NodeFaultPayloadError {
    /// The payload length or one nested length is invalid.
    #[error("invalid typed node-fault payload length")]
    Length,
    /// Version or reserved bytes are invalid.
    #[error("invalid typed node-fault version or reserved bytes")]
    VersionOrReserved,
    /// The command kind is not a typed node-rule command.
    #[error("unsupported typed node-fault command kind {0}")]
    CommandKind(u16),
    /// The operation tag is unknown.
    #[error("unknown typed node-fault operation {0}")]
    Operation(u16),
    /// The target-kind tag is unknown.
    #[error("unknown typed node-fault target kind {0}")]
    TargetKind(u16),
    /// One required header value is zero or otherwise invalid.
    #[error("invalid typed node-fault header value")]
    HeaderValue,
    /// Too many or too few fields were supplied.
    #[error("invalid typed node-fault field count")]
    FieldCount,
    /// A field has tag zero.
    #[error("typed node-fault field tag must be nonzero")]
    FieldTag,
    /// Field tags are not strictly increasing.
    #[error("typed node-fault fields are not in canonical tag order")]
    FieldOrder,
    /// The field type tag is unknown.
    #[error("unknown typed node-fault field type {0}")]
    FieldType(u16),
    /// One field value is not canonical for its declared type.
    #[error("invalid typed node-fault value for field {tag}")]
    FieldValue {
        /// Field tag whose encoded value failed validation.
        tag: u16,
    },
    /// A removal command carried mutation parameters.
    #[error("typed node-fault removal must not carry fields")]
    RemoveFields,
    /// Fields do not exactly match the selected command and target schema.
    #[error("typed node-fault fields do not match command schema {command_kind}")]
    Schema {
        /// Numeric command kind whose schema was violated.
        command_kind: u16,
    },
    /// The command cannot operate on the supplied target category.
    #[error("typed node-fault command {command_kind} cannot target kind {target_kind}")]
    TargetSchema {
        /// Numeric command kind.
        command_kind: u16,
        /// Numeric target kind.
        target_kind: u16,
    },
    /// Resolved target coordinates conflict with effect coordinates.
    #[error("typed node-fault effect conflicts with its resolved target")]
    TargetValue,
    /// A closed policy field is not framed canonical JSON.
    #[error("typed node-fault policy field {tag} is not canonical CRUCJSN1 JSON")]
    PolicyJson {
        /// Invalid policy field tag.
        tag: u16,
    },
}

pub(crate) fn emit_fault_node_c_header(out: &mut String) {
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1 {NODE_FAULT_PAYLOAD_VERSION_V1}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES {NODE_FAULT_PAYLOAD_HEADER_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_FIELD_HEADER_V1_BYTES {NODE_FAULT_FIELD_HEADER_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_EVIDENCE_V1_BYTES {NODE_FAULT_EVIDENCE_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_MAX_FIELDS_V1 {NODE_FAULT_MAX_FIELDS_V1}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1 \"CRUCJSN1\""
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1_BYTES 8u"
    );
    for (name, value) in [
        ("UPSERT", NodeFaultOperationV1::Upsert as u16),
        ("REMOVE", NodeFaultOperationV1::Remove as u16),
        ("APPLY", NodeFaultOperationV1::Apply as u16),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_OPERATION_{name} {value}u");
    }
    for (name, value) in [
        ("NODE", NodeFaultTargetKindV1::Node as u16),
        ("VCPU", NodeFaultTargetKindV1::Vcpu as u16),
        ("REGISTER", NodeFaultTargetKindV1::Register as u16),
        ("MEMORY", NodeFaultTargetKindV1::Memory as u16),
        ("INTERRUPT", NodeFaultTargetKindV1::Interrupt as u16),
        ("CLOCK", NodeFaultTargetKindV1::Clock as u16),
        ("ACCELERATOR", NodeFaultTargetKindV1::Accelerator as u16),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_TARGET_{name} {value}u");
    }
    for (name, value) in [
        ("U32", NodeFaultFieldTypeV1::U32 as u16),
        ("U64", NodeFaultFieldTypeV1::U64 as u16),
        ("I64", NodeFaultFieldTypeV1::I64 as u16),
        ("BOOL", NodeFaultFieldTypeV1::Bool as u16),
        ("RATIO", NodeFaultFieldTypeV1::Ratio as u16),
        ("HASH", NodeFaultFieldTypeV1::Hash as u16),
        ("BYTES", NodeFaultFieldTypeV1::Bytes as u16),
        ("HASH_SET", NodeFaultFieldTypeV1::HashSet as u16),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_FIELD_TYPE_{name} {value}u"
        );
    }
    for (name, value) in [
        ("P1", node_fault_field::P1),
        ("P2", node_fault_field::P2),
        ("P3", node_fault_field::P3),
        ("P4", node_fault_field::P4),
        ("P5", node_fault_field::P5),
        ("P6", node_fault_field::P6),
        ("P7", node_fault_field::P7),
        ("P8", node_fault_field::P8),
        ("P9", node_fault_field::P9),
        ("P10", node_fault_field::P10),
        ("P11", node_fault_field::P11),
        ("T1", node_fault_field::T1),
        ("T2", node_fault_field::T2),
        ("T3", node_fault_field::T3),
        ("T4", node_fault_field::T4),
        ("T5", node_fault_field::T5),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_FIELD_{name} {value}u");
    }
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("COMMAND_KIND", 10),
        ("OPERATION", 12),
        ("TARGET_KIND", 14),
        ("MODEL_PHASE", 16),
        ("RESERVED", 18),
        ("GENERATION", 20),
        ("ACTION_HASH", 28),
        ("TARGET_HASH", 60),
        ("SCHEMA_HASH", 92),
        ("FIELD_COUNT", 124),
        ("TRAILING_RESERVED", 126),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_PAYLOAD_{name}_OFFSET {value}u"
        );
    }
    for (name, value) in [("TAG", 0), ("TYPE", 2), ("LENGTH", 4)] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_FIELD_{name}_OFFSET {value}u"
        );
    }
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("COMMAND_KIND", 10),
        ("OPERATION", 12),
        ("TARGET_KIND", 14),
        ("MODEL_PHASE", 16),
        ("RESERVED", 18),
        ("GENERATION", 20),
        ("PRIOR_GENERATION", 28),
        ("ACTION_HASH", 36),
        ("TARGET_HASH", 68),
        ("SCHEMA_HASH", 100),
        ("REQUEST_SHA256", 132),
        ("BEFORE_SHA256", 164),
        ("AFTER_SHA256", 196),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_EVIDENCE_{name}_OFFSET {value}u"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(tag: u16, field_type: NodeFaultFieldTypeV1) -> NodeFaultFieldV1 {
        match field_type {
            NodeFaultFieldTypeV1::U32 => NodeFaultFieldV1::u32(tag, 1),
            NodeFaultFieldTypeV1::U64 => NodeFaultFieldV1::u64(tag, 1),
            NodeFaultFieldTypeV1::I64 => NodeFaultFieldV1::i64(tag, -1),
            NodeFaultFieldTypeV1::Bool => NodeFaultFieldV1::boolean(tag, true),
            NodeFaultFieldTypeV1::Ratio => NodeFaultFieldV1::ratio(tag, 1, 2),
            NodeFaultFieldTypeV1::Hash => NodeFaultFieldV1::hash(tag, [tag as u8; 32]),
            NodeFaultFieldTypeV1::Bytes => NodeFaultFieldV1::bytes(tag, policy_json()),
            NodeFaultFieldTypeV1::HashSet => {
                NodeFaultFieldV1::hash_set(tag, &[[tag as u8; 32]]).expect("canonical hash set")
            }
        }
    }

    fn policy_json() -> Vec<u8> {
        let mut value = NODE_FAULT_POLICY_JSON_MAGIC_V1.to_vec();
        value.extend_from_slice(b"{\"kind\":\"every\"}");
        value
    }

    fn exhaustive_payload(
        command_kind: FaultCommandKind,
        target_kind: NodeFaultTargetKindV1,
        parameters: &[(u16, NodeFaultFieldTypeV1)],
        targets: &[(u16, NodeFaultFieldTypeV1)],
    ) -> NodeFaultPayloadV1 {
        let mut fields = parameters
            .iter()
            .chain(targets)
            .map(|(tag, field_type)| field(*tag, *field_type))
            .collect::<Vec<_>>();
        if command_kind == FaultCommandKind::ClockTransform {
            let kind = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P2)
                .expect("clock kind field exists");
            *kind = NodeFaultFieldV1::u32(node_fault_field::P2, 5);
        }
        if command_kind == FaultCommandKind::CpuInstructionTransform {
            let count = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P5)
                .expect("instruction count field exists");
            *count = NodeFaultFieldV1::u32(node_fault_field::P5, 0);
        }
        if command_kind == FaultCommandKind::MemoryAccessTransform {
            let violate_atomicity = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P9)
                .expect("memory atomicity field exists");
            *violate_atomicity = NodeFaultFieldV1::boolean(node_fault_field::P9, false);
            let has_dma_device = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P10)
                .expect("memory DMA selector-presence field exists");
            *has_dma_device = NodeFaultFieldV1::boolean(node_fault_field::P10, false);
            let dma_device = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P11)
                .expect("memory DMA selector field exists");
            *dma_device = NodeFaultFieldV1::hash(node_fault_field::P11, [0; 32]);
        }
        if command_kind == FaultCommandKind::AcceleratorMemoryEvent {
            let has_transform = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P7)
                .expect("accelerator transform-presence field exists");
            *has_transform = NodeFaultFieldV1::boolean(node_fault_field::P7, false);
            let transform = fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::P8)
                .expect("accelerator transform field exists");
            *transform = NodeFaultFieldV1::bytes(node_fault_field::P8, vec![0]);
        }
        fields.sort_by_key(|value| value.tag);
        NodeFaultPayloadV1 {
            command_kind,
            operation: NodeFaultOperationV1::Upsert,
            target_kind,
            model_phase: 1,
            generation: 1,
            action_hash: [1; 32],
            target_hash: [2; 32],
            schema_hash: [3; 32],
            fields,
        }
    }

    fn payload() -> NodeFaultPayloadV1 {
        NodeFaultPayloadV1 {
            command_kind: FaultCommandKind::CpuService,
            operation: NodeFaultOperationV1::Upsert,
            target_kind: NodeFaultTargetKindV1::Vcpu,
            model_phase: 10,
            generation: 7,
            action_hash: [1; 32],
            target_hash: [2; 32],
            schema_hash: [3; 32],
            fields: vec![
                NodeFaultFieldV1::bytes(1, policy_json()),
                NodeFaultFieldV1::ratio(2, 1, 2),
                NodeFaultFieldV1::u64(3, 10_000),
                NodeFaultFieldV1::u32(4, 1),
                NodeFaultFieldV1::u32(100, 0),
            ],
        }
    }

    #[test]
    fn typed_node_payload_round_trips() {
        let value = payload();
        let encoded = value.encode().expect("valid fixture encodes");
        assert_eq!(NodeFaultPayloadV1::decode(&encoded), Ok(value));
    }

    #[test]
    fn every_typed_node_command_has_an_exact_closed_schema() {
        use NodeFaultFieldTypeV1 as Ty;
        use node_fault_field::*;

        let vcpu = &[(T1, Ty::U32)][..];
        let register = &[
            (T1, Ty::U32),
            (T2, Ty::Hash),
            (T3, Ty::Hash),
            (T4, Ty::U32),
            (T5, Ty::U32),
        ][..];
        let memory = &[
            (T1, Ty::Hash),
            (T2, Ty::U64),
            (T3, Ty::Bool),
            (T4, Ty::U32),
            (T5, Ty::U64),
        ][..];
        let interrupt = &[(T1, Ty::Hash), (T2, Ty::Hash), (T3, Ty::U32), (T4, Ty::U32)][..];
        let hash_target = &[(T1, Ty::Hash)][..];
        let cases: &[(
            FaultCommandKind,
            NodeFaultTargetKindV1,
            &[(u16, Ty)],
            &[(u16, Ty)],
        )] = &[
            (
                FaultCommandKind::NodeLifecycle,
                NodeFaultTargetKindV1::Node,
                &[
                    (P1, Ty::U32),
                    (P2, Ty::U64),
                    (P3, Ty::Bytes),
                    (P4, Ty::U32),
                    (P5, Ty::U32),
                ],
                &[],
            ),
            (
                FaultCommandKind::NodeHang,
                NodeFaultTargetKindV1::Node,
                &[
                    (P1, Ty::U32),
                    (P2, Ty::Bytes),
                    (P3, Ty::Hash),
                    (P4, Ty::Bytes),
                ],
                &[],
            ),
            (
                FaultCommandKind::CpuService,
                NodeFaultTargetKindV1::Vcpu,
                &[
                    (P1, Ty::Bytes),
                    (P2, Ty::Ratio),
                    (P3, Ty::U64),
                    (P4, Ty::U32),
                ],
                vcpu,
            ),
            (
                FaultCommandKind::CpuVcpuState,
                NodeFaultTargetKindV1::Vcpu,
                &[(P1, Ty::U32), (P2, Ty::Bool), (P3, Ty::Hash)],
                vcpu,
            ),
            (
                FaultCommandKind::CpuRegisterTransform,
                NodeFaultTargetKindV1::Register,
                &[
                    (P1, Ty::Hash),
                    (P2, Ty::U32),
                    (P3, Ty::U32),
                    (P4, Ty::U32),
                    (P5, Ty::Bytes),
                    (P6, Ty::Bool),
                    (P7, Ty::Bytes),
                    (P8, Ty::Bytes),
                ],
                register,
            ),
            (
                FaultCommandKind::CpuInstructionTransform,
                NodeFaultTargetKindV1::Vcpu,
                &[
                    (P1, Ty::Bytes),
                    (P2, Ty::U32),
                    (P3, Ty::Hash),
                    (P4, Ty::Bytes),
                    (P5, Ty::U32),
                ],
                vcpu,
            ),
            (
                FaultCommandKind::CpuException,
                NodeFaultTargetKindV1::Vcpu,
                &[(P1, Ty::Bytes)],
                vcpu,
            ),
            (
                FaultCommandKind::InterruptDisposition,
                NodeFaultTargetKindV1::Interrupt,
                &[
                    (P1, Ty::U32),
                    (P2, Ty::U64),
                    (P3, Ty::U32),
                    (P4, Ty::U64),
                    (P5, Ty::U32),
                ],
                interrupt,
            ),
            (
                FaultCommandKind::InterruptStorm,
                NodeFaultTargetKindV1::Interrupt,
                &[
                    (P1, Ty::Hash),
                    (P2, Ty::U32),
                    (P3, Ty::U64),
                    (P4, Ty::U32),
                    (P5, Ty::U32),
                    (P6, Ty::Bytes),
                ],
                interrupt,
            ),
            (
                FaultCommandKind::MemoryAccessTransform,
                NodeFaultTargetKindV1::Memory,
                &[
                    (P1, Ty::U64),
                    (P2, Ty::U64),
                    (P3, Ty::U32),
                    (P4, Ty::Bytes),
                    (P5, Ty::Bool),
                    (P6, Ty::Bytes),
                    (P7, Ty::Bytes),
                    (P8, Ty::U32),
                    (P9, Ty::Bool),
                    (P10, Ty::Bool),
                    (P11, Ty::Hash),
                ],
                memory,
            ),
            (
                FaultCommandKind::MemoryEccEvent,
                NodeFaultTargetKindV1::Memory,
                &[
                    (P1, Ty::U32),
                    (P2, Ty::U64),
                    (P3, Ty::U64),
                    (P4, Ty::Hash),
                    (P5, Ty::Hash),
                    (P6, Ty::Hash),
                    (P7, Ty::Bytes),
                ],
                memory,
            ),
            (
                FaultCommandKind::MemoryRegionState,
                NodeFaultTargetKindV1::Memory,
                &[(P1, Ty::U64), (P2, Ty::U64), (P3, Ty::U32), (P4, Ty::Bytes)],
                memory,
            ),
            (
                FaultCommandKind::MemoryService,
                NodeFaultTargetKindV1::Memory,
                &[
                    (P1, Ty::U64),
                    (P2, Ty::Bool),
                    (P3, Ty::U64),
                    (P4, Ty::Bool),
                    (P5, Ty::U64),
                    (P6, Ty::Bytes),
                ],
                memory,
            ),
            (
                FaultCommandKind::ClockTransform,
                NodeFaultTargetKindV1::Clock,
                &[
                    (P1, Ty::Hash),
                    (P2, Ty::U32),
                    (P3, Ty::I64),
                    (P4, Ty::Ratio),
                    (P5, Ty::U64),
                    (P6, Ty::Bytes),
                    (P7, Ty::U32),
                    (P8, Ty::U32),
                ],
                hash_target,
            ),
            (
                FaultCommandKind::ClockSourceState,
                NodeFaultTargetKindV1::Clock,
                &[(P1, Ty::HashSet), (P2, Ty::Bytes), (P3, Ty::Bytes)],
                hash_target,
            ),
            (
                FaultCommandKind::AcceleratorLifecycle,
                NodeFaultTargetKindV1::Accelerator,
                &[(P1, Ty::Hash), (P2, Ty::U32), (P3, Ty::U32), (P4, Ty::U32)],
                hash_target,
            ),
            (
                FaultCommandKind::AcceleratorResultTransform,
                NodeFaultTargetKindV1::Accelerator,
                &[(P1, Ty::Bytes), (P2, Ty::Bytes)],
                hash_target,
            ),
            (
                FaultCommandKind::AcceleratorMemoryEvent,
                NodeFaultTargetKindV1::Accelerator,
                &[
                    (P1, Ty::U64),
                    (P2, Ty::U64),
                    (P3, Ty::Bool),
                    (P4, Ty::U32),
                    (P5, Ty::Bool),
                    (P6, Ty::U64),
                    (P7, Ty::Bool),
                    (P8, Ty::Bytes),
                ],
                hash_target,
            ),
            (
                FaultCommandKind::AcceleratorService,
                NodeFaultTargetKindV1::Accelerator,
                &[
                    (P1, Ty::Ratio),
                    (P2, Ty::Bool),
                    (P3, Ty::U64),
                    (P4, Ty::Bool),
                    (P5, Ty::U64),
                    (P6, Ty::Bytes),
                ],
                hash_target,
            ),
        ];
        assert_eq!(cases.len(), 19);
        for (command, target, parameters, targets) in cases {
            let payload = exhaustive_payload(*command, *target, parameters, targets);
            let encoded = payload
                .encode()
                .unwrap_or_else(|error| panic!("schema for {command:?} must encode: {error}"));
            assert_eq!(NodeFaultPayloadV1::decode(&encoded), Ok(payload));
        }
    }

    #[test]
    fn typed_node_payload_rejects_noncanonical_fields() {
        let mut value = payload();
        value.fields.reverse();
        assert_eq!(value.encode(), Err(NodeFaultPayloadError::FieldOrder));
    }

    #[test]
    fn typed_node_payload_rejects_noncanonical_policy_json() {
        use node_fault_field::P1;

        for invalid in [
            b"null".as_slice(),
            b"CRUCJSN1null".as_slice(),
            b"CRUCJSN1 null".as_slice(),
            b"CRUCJSN1{\"b\":1,\"a\":2}".as_slice(),
            b"CRUCJSN1{\"a\":1,\"a\":2}".as_slice(),
            b"CRUCJSN1{\"kind\":\"every\",\"value\":1.0}".as_slice(),
        ] {
            let mut value = payload();
            value.fields[0] = NodeFaultFieldV1::bytes(P1, invalid.to_vec());
            assert_eq!(
                value.encode(),
                Err(NodeFaultPayloadError::PolicyJson { tag: P1 })
            );
        }
    }

    #[test]
    fn typed_node_payload_rejects_command_target_mismatch() {
        let mut value = payload();
        value.target_kind = NodeFaultTargetKindV1::Memory;
        assert_eq!(
            value.encode(),
            Err(NodeFaultPayloadError::TargetSchema {
                command_kind: FaultCommandKind::CpuService as u16,
                target_kind: NodeFaultTargetKindV1::Memory as u16,
            })
        );
    }

    #[test]
    fn typed_node_payload_rejects_unknown_discriminant() {
        use node_fault_field::P4;

        let mut value = payload();
        value.fields[3] = NodeFaultFieldV1::u32(P4, 99);
        assert_eq!(
            value.encode(),
            Err(NodeFaultPayloadError::FieldValue { tag: P4 })
        );
    }

    #[test]
    fn typed_node_payload_rejects_invalid_memory_cross_fields() {
        use NodeFaultFieldTypeV1 as Ty;
        use node_fault_field::*;

        let parameters = &[
            (P1, Ty::U64),
            (P2, Ty::U64),
            (P3, Ty::U32),
            (P4, Ty::Bytes),
            (P5, Ty::Bool),
            (P6, Ty::Bytes),
            (P7, Ty::Bytes),
            (P8, Ty::U32),
            (P9, Ty::Bool),
            (P10, Ty::Bool),
            (P11, Ty::Hash),
        ];
        let target = &[
            (T1, Ty::Hash),
            (T2, Ty::U64),
            (T3, Ty::Bool),
            (T4, Ty::U32),
            (T5, Ty::U64),
        ];
        let mut value = exhaustive_payload(
            FaultCommandKind::MemoryAccessTransform,
            NodeFaultTargetKindV1::Memory,
            parameters,
            target,
        );
        let atomicity = value
            .fields
            .iter_mut()
            .find(|field| field.tag == P9)
            .expect("memory atomicity field exists");
        *atomicity = NodeFaultFieldV1::boolean(P9, true);
        assert_eq!(
            value.encode(),
            Err(NodeFaultPayloadError::FieldValue { tag: P3 })
        );
    }

    #[test]
    fn typed_node_remove_is_parameter_free() {
        let mut value = payload();
        value.operation = NodeFaultOperationV1::Remove;
        assert_eq!(value.encode(), Err(NodeFaultPayloadError::RemoveFields));
        value.fields.clear();
        assert!(value.encode().is_ok());
    }

    #[test]
    fn typed_node_evidence_round_trips_every_identity() {
        let evidence = NodeFaultEvidenceV1 {
            command_kind: FaultCommandKind::CpuService,
            operation: NodeFaultOperationV1::Upsert,
            target_kind: NodeFaultTargetKindV1::Vcpu,
            model_phase: 2,
            generation: 9,
            prior_generation: 7,
            action_hash: [1; 32],
            target_hash: [2; 32],
            schema_hash: [3; 32],
            request_sha256: [4; 32],
            before_sha256: [5; 32],
            after_sha256: [6; 32],
        };
        let encoded = evidence
            .encode()
            .unwrap_or_else(|error| panic!("evidence should encode: {error}"));
        assert_eq!(NodeFaultEvidenceV1::decode(&encoded), Ok(evidence));
    }
}
