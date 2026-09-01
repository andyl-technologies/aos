//! Interrupt-controller capability rows and manifests.

use super::*;

/// One immutable interrupt-controller capability row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultInterruptCapabilityRowV1 {
    /// Stable manifest-row identity.
    pub id: String,
    /// Stable controller identity.
    pub controller: String,
    /// Stable interrupt-source identity.
    pub source: String,
    /// Exact realized controller implementation/version.
    pub controller_version: String,
    /// Architecture interrupt family.
    pub family: FaultInterruptFamilyV1,
    /// Inclusive first vector or INTID this source may produce.
    pub vector_start: u32,
    /// Inclusive last vector or INTID this source may produce.
    pub vector_end: u32,
    /// Inclusive first replacement vector.
    pub replacement_vector_start: u32,
    /// Inclusive last replacement vector.
    pub replacement_vector_end: u32,
    /// Electrical trigger mode.
    pub trigger: FaultInterruptTriggerV1,
    /// Active electrical polarity.
    pub polarity: FaultInterruptPolarityV1,
    /// Sorted unique routable target vCPUs.
    pub target_vcpus: Vec<u32>,
    /// Bit set of implemented fault model phases.
    pub model_phase_mask: u64,
    /// Controller priority value.
    pub priority: u16,
    /// Controller transition used for a dropped delivery.
    pub delivery_drop: FaultInterruptDeliveryDropV1,
    /// Whether the controller and fault overlay have VMState coverage.
    pub vmstate: bool,
}

impl FaultInterruptCapabilityRowV1 {
    fn validate(&self, architecture: FaultCapabilityScope) -> Result<(), FaultAbiError> {
        const INTERRUPT_PHASE_MASK: u64 =
            (1_u64 << (23 - 1)) | (1_u64 << (24 - 1)) | (1_u64 << (26 - 1));
        if !valid_identity(&self.id)
            || !valid_identity(&self.controller)
            || !valid_identity(&self.source)
            || !valid_cpu_model(&self.controller_version)
            || self.family.architecture() != architecture
            || !self.family.vector_valid(self.vector_start)
            || !self.family.vector_valid(self.vector_end)
            || !self.family.vector_valid(self.replacement_vector_start)
            || !self.family.vector_valid(self.replacement_vector_end)
            || self.vector_start > self.vector_end
            || self.replacement_vector_start > self.replacement_vector_end
            || self.target_vcpus.is_empty()
            || self.target_vcpus.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.target_vcpus.windows(2).any(|pair| pair[0] >= pair[1])
            || self.model_phase_mask == 0
            || self.model_phase_mask & !INTERRUPT_PHASE_MASK != 0
            || self.priority > 255
            || !self.vmstate
            || (self.family.fixed_edge() && self.trigger != FaultInterruptTriggerV1::Edge)
            || !matches!(
                (self.trigger, self.delivery_drop),
                (
                    FaultInterruptTriggerV1::Edge,
                    FaultInterruptDeliveryDropV1::ConsumeEdge
                ) | (
                    FaultInterruptTriggerV1::Level,
                    FaultInterruptDeliveryDropV1::RependAssertedLevel
                )
            )
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    fn encode(
        &self,
        architecture: FaultCapabilityScope,
        output: &mut Vec<u8>,
    ) -> Result<(), FaultAbiError> {
        self.validate(architecture)?;
        let id_len =
            u16::try_from(self.id.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let controller_len =
            u16::try_from(self.controller.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let source_len =
            u16::try_from(self.source.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let version_len = u16::try_from(self.controller_version.len())
            .map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let targets_bytes = self
            .target_vcpus
            .len()
            .checked_mul(4)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        let row_len = FAULT_INTERRUPT_ROW_HEADER_V1_BYTES
            .checked_add(self.id.len())
            .and_then(|length| length.checked_add(self.controller.len()))
            .and_then(|length| length.checked_add(self.source.len()))
            .and_then(|length| length.checked_add(self.controller_version.len()))
            .and_then(|length| length.checked_add(targets_bytes))
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        let row_len = u32::try_from(row_len).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let target_count = u16::try_from(self.target_vcpus.len())
            .map_err(|_| FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&(self.family as u16).to_le_bytes());
        output.extend_from_slice(&(self.trigger as u16).to_le_bytes());
        output.extend_from_slice(&(self.polarity as u16).to_le_bytes());
        output.extend_from_slice(&(self.delivery_drop as u16).to_le_bytes());
        output.extend_from_slice(&self.vector_start.to_le_bytes());
        output.extend_from_slice(&self.vector_end.to_le_bytes());
        output.extend_from_slice(&self.replacement_vector_start.to_le_bytes());
        output.extend_from_slice(&self.replacement_vector_end.to_le_bytes());
        output.extend_from_slice(&self.priority.to_le_bytes());
        output.push(u8::from(self.vmstate));
        output.push(0);
        output.extend_from_slice(&self.model_phase_mask.to_le_bytes());
        output.extend_from_slice(&target_count.to_le_bytes());
        output.extend_from_slice(&id_len.to_le_bytes());
        output.extend_from_slice(&controller_len.to_le_bytes());
        output.extend_from_slice(&source_len.to_le_bytes());
        output.extend_from_slice(&version_len.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(&row_len.to_le_bytes());
        output.extend_from_slice(self.id.as_bytes());
        output.extend_from_slice(self.controller.as_bytes());
        output.extend_from_slice(self.source.as_bytes());
        output.extend_from_slice(self.controller_version.as_bytes());
        for target in &self.target_vcpus {
            output.extend_from_slice(&target.to_le_bytes());
        }
        Ok(())
    }
}

/// Exact interrupt manifest for one realized QEMU machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultInterruptCapabilityManifestV1 {
    /// Architecture scope of every row.
    pub architecture: FaultCapabilityScope,
    /// Canonically ordered interrupt routes.
    pub rows: Vec<FaultInterruptCapabilityRowV1>,
}

impl FaultInterruptCapabilityManifestV1 {
    /// Encodes a canonical self-authenticating interrupt manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for an invalid architecture, row, ordering,
    /// size, phase, trigger, vector range, or VMState contract.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.rows.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut body = Vec::new();
        for row in &self.rows {
            row.encode(self.architecture, &mut body)?;
        }
        let maximum_body_bytes = usize::try_from(crate::HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_| FaultAbiError::PayloadLimit)?
            .checked_sub(FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if body.len() > maximum_body_bytes {
            return Err(FaultAbiError::PayloadLimit);
        }
        let row_count =
            u32::try_from(self.rows.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len = u32::try_from(body.len()).map_err(|_| FaultAbiError::PayloadLimit)?;
        let mut output = Vec::with_capacity(FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_INTERRUPT_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_INTERRUPT_MANIFEST_VERSION_V1.to_le_bytes());
        output.extend_from_slice(&(self.architecture as u16).to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&row_count.to_le_bytes());
        output.extend_from_slice(&body_len.to_le_bytes());
        output.extend_from_slice(blake3::hash(&body).as_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes and authenticates a canonical interrupt manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, digest, row fields,
    /// target ordering, architecture mismatches, or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_INTERRUPT_MANIFEST_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16_at(bytes, 8)? != FAULT_INTERRUPT_MANIFEST_VERSION_V1 || u32_at(bytes, 12)? != 0 {
            return Err(FaultAbiError::Version);
        }
        let architecture = FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?;
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count == 0 || row_count > HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let expected_len = FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES
            .checked_add(body_len)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if bytes.len() != expected_len {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let mut offset = 0;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_INTERRUPT_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_INTERRUPT_ROW_HEADER_V1_BYTES];
            let family = FaultInterruptFamilyV1::from_u16(u16_at(header, 0)?)?;
            let trigger = FaultInterruptTriggerV1::from_u16(u16_at(header, 2)?)?;
            let polarity = FaultInterruptPolarityV1::from_u16(u16_at(header, 4)?)?;
            let delivery_drop = FaultInterruptDeliveryDropV1::from_u16(u16_at(header, 6)?)?;
            let vector_start = u32_at(header, 8)?;
            let vector_end = u32_at(header, 12)?;
            let replacement_vector_start = u32_at(header, 16)?;
            let replacement_vector_end = u32_at(header, 20)?;
            let priority = u16_at(header, 24)?;
            let vmstate = match header[26] {
                0 => false,
                1 => true,
                _ => return Err(FaultAbiError::CapabilityInvariant),
            };
            if header[27] != 0 || u16_at(header, 46)? != 0 {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let model_phase_mask = u64_at(header, 28)?;
            let target_count = usize::from(u16_at(header, 36)?);
            let id_len = usize::from(u16_at(header, 38)?);
            let controller_len = usize::from(u16_at(header, 40)?);
            let source_len = usize::from(u16_at(header, 42)?);
            let version_len = usize::from(u16_at(header, 44)?);
            let row_len = usize::try_from(u32_at(header, 48)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let calculated = FAULT_INTERRUPT_ROW_HEADER_V1_BYTES
                .checked_add(id_len)
                .and_then(|length| length.checked_add(controller_len))
                .and_then(|length| length.checked_add(source_len))
                .and_then(|length| length.checked_add(version_len))
                .and_then(|length| length.checked_add(target_count.checked_mul(4)?))
                .ok_or(FaultAbiError::CapabilityInvariant)?;
            if row_len != calculated || body.len().saturating_sub(offset) < row_len {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_INTERRUPT_ROW_HEADER_V1_BYTES;
            let id = take_text(body, &mut cursor, id_len)?;
            let controller = take_text(body, &mut cursor, controller_len)?;
            let source = take_text(body, &mut cursor, source_len)?;
            let controller_version = take_text(body, &mut cursor, version_len)?;
            let mut target_vcpus = Vec::with_capacity(target_count);
            for _ in 0..target_count {
                target_vcpus.push(u32_at(body, cursor)?);
                cursor += 4;
            }
            let row = FaultInterruptCapabilityRowV1 {
                id,
                controller,
                source,
                controller_version,
                family,
                vector_start,
                vector_end,
                replacement_vector_start,
                replacement_vector_end,
                trigger,
                polarity,
                target_vcpus,
                model_phase_mask,
                priority,
                delivery_drop,
                vmstate,
            };
            row.validate(architecture)?;
            rows.push(row);
            offset += row_len;
        }
        if offset != body.len() {
            return Err(FaultAbiError::HeaderLength);
        }
        let manifest = Self { architecture, rows };
        if manifest.encode()?.as_slice() != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(manifest)
    }
}
