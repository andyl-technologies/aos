//! Typed acknowledgement evidence for node-fault transactions.

use super::*;

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
                | FaultCommandKind::QueryTargetManifest
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
