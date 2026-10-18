//! Canonical typed node-fault payload encoding and decoding.

use super::*;

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

    pub(super) fn validate(&self) -> Result<(), NodeFaultPayloadError> {
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
}
