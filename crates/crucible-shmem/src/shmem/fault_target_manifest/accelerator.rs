//! Accelerator-device capability rows and manifests.

use super::*;

/// One realized accelerator device and closed job interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAcceleratorCapabilityRowV1 {
    /// Stable public device identity.
    pub id: String,
    /// Exact QEMU device implementation identity.
    pub implementation: String,
    /// Bit zero through two advertise GPU, TPU, and FPGA classes.
    pub class_mask: u16,
    /// Bit zero through three advertise lifecycle, result, memory, and service faults.
    pub fault_family_mask: u16,
    /// First supported queue identifier.
    pub queue_start: u16,
    /// Last supported queue identifier.
    pub queue_end: u16,
    /// Maximum simultaneously pending jobs.
    pub queue_depth: u32,
    /// Maximum input bytes for one job.
    pub maximum_input_bytes: u32,
    /// Maximum output bytes for one job.
    pub maximum_output_bytes: u32,
    /// Bytes in the persistent device-memory address space.
    pub device_memory_bytes: u64,
    /// Supported ECC modes: corrected and uncorrectable are bits zero and one.
    pub ecc_mode_mask: u32,
    /// Number of closed job schemas exposed by this device.
    pub job_kind_count: u32,
    /// Reports complete VMState support for device and fault continuation.
    pub vmstate: bool,
}

impl FaultAcceleratorCapabilityRowV1 {
    fn validate(&self) -> Result<(), FaultAbiError> {
        if !valid_hardware_identity(&self.id)
            || !valid_cpu_model(&self.implementation)
            || self.class_mask == 0
            || self.class_mask & !0x7 != 0
            || self.fault_family_mask != 0xf
            || self.queue_start > self.queue_end
            || self.queue_depth == 0
            || self.maximum_input_bytes == 0
            || self.maximum_output_bytes == 0
            || self.device_memory_bytes == 0
            || self.ecc_mode_mask != 0x3
            || self.job_kind_count == 0
            || !self.vmstate
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), FaultAbiError> {
        self.validate()?;
        let id_len =
            u16::try_from(self.id.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let implementation_len = u16::try_from(self.implementation.len())
            .map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let row_len = FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES
            .checked_add(self.id.len())
            .and_then(|length| length.checked_add(self.implementation.len()))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&self.class_mask.to_le_bytes());
        output.extend_from_slice(&self.fault_family_mask.to_le_bytes());
        output.extend_from_slice(&self.queue_start.to_le_bytes());
        output.extend_from_slice(&self.queue_end.to_le_bytes());
        output.extend_from_slice(&self.queue_depth.to_le_bytes());
        output.extend_from_slice(&self.maximum_input_bytes.to_le_bytes());
        output.extend_from_slice(&self.maximum_output_bytes.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&self.device_memory_bytes.to_le_bytes());
        output.extend_from_slice(&self.ecc_mode_mask.to_le_bytes());
        output.extend_from_slice(&self.job_kind_count.to_le_bytes());
        output.push(u8::from(self.vmstate));
        output.extend_from_slice(&[0; 7]);
        output.extend_from_slice(&id_len.to_le_bytes());
        output.extend_from_slice(&implementation_len.to_le_bytes());
        output.extend_from_slice(&row_len.to_le_bytes());
        output.extend_from_slice(&[0; 8]);
        output.extend_from_slice(self.id.as_bytes());
        output.extend_from_slice(self.implementation.as_bytes());
        Ok(())
    }
}

/// Exact accelerator manifest for one realized QEMU device graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAcceleratorCapabilityManifestV1 {
    /// Canonically ordered realized accelerator rows.
    pub rows: Vec<FaultAcceleratorCapabilityRowV1>,
}

impl FaultAcceleratorCapabilityManifestV1 {
    /// Encodes a canonical, self-authenticating accelerator manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for invalid rows, ordering, bounds, or size.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if self.rows.is_empty()
            || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.rows.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut body = Vec::new();
        for row in &self.rows {
            row.encode(&mut body)?;
        }
        if FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES
            .checked_add(body.len())
            .is_none_or(|length| length > crate::HARD_FAULT_PAYLOAD_BYTES as usize)
        {
            return Err(FaultAbiError::PayloadLimit);
        }
        let mut output =
            Vec::with_capacity(FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_ACCELERATOR_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_ACCELERATOR_MANIFEST_VERSION_V1.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(self.rows.len())
                .map_err(|_| FaultAbiError::CapabilityInvariant)?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| FaultAbiError::PayloadLimit)?
                .to_le_bytes(),
        );
        output.extend_from_slice(blake3::hash(&body).as_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes and authenticates a canonical accelerator manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, rows, digest, or ordering.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_ACCELERATOR_MANIFEST_MAGIC_V1
            || u16_at(bytes, 8)? != FAULT_ACCELERATOR_MANIFEST_VERSION_V1
            || u16_at(bytes, 10)? != 0
            || u32_at(bytes, 12)? != 0
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count == 0
            || row_count > HARD_FAULT_TARGET_MANIFEST_ROWS
            || bytes.len()
                != FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES
                    .checked_add(body_len)
                    .ok_or(FaultAbiError::PayloadLimit)?
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let mut offset = 0;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES];
            if u32_at(header, 20)? != 0 || header[41..48] != [0; 7] || header[56..64] != [0; 8] {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let id_len = usize::from(u16_at(header, 48)?);
            let implementation_len = usize::from(u16_at(header, 50)?);
            let row_len = usize::try_from(u32_at(header, 52)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            if row_len
                != FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES
                    .checked_add(id_len)
                    .and_then(|length| length.checked_add(implementation_len))
                    .ok_or(FaultAbiError::CapabilityInvariant)?
                || body.len().saturating_sub(offset) < row_len
            {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES;
            let id = take_text(body, &mut cursor, id_len)?;
            let implementation = take_text(body, &mut cursor, implementation_len)?;
            let row = FaultAcceleratorCapabilityRowV1 {
                id,
                implementation,
                class_mask: u16_at(header, 0)?,
                fault_family_mask: u16_at(header, 2)?,
                queue_start: u16_at(header, 4)?,
                queue_end: u16_at(header, 6)?,
                queue_depth: u32_at(header, 8)?,
                maximum_input_bytes: u32_at(header, 12)?,
                maximum_output_bytes: u32_at(header, 16)?,
                device_memory_bytes: u64_at(header, 24)?,
                ecc_mode_mask: u32_at(header, 32)?,
                job_kind_count: u32_at(header, 36)?,
                vmstate: bool_at(header, 40)?,
            };
            row.validate()?;
            rows.push(row);
            offset += row_len;
        }
        if offset != body.len() {
            return Err(FaultAbiError::HeaderLength);
        }
        let manifest = Self { rows };
        if manifest.encode()?.as_slice() != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(manifest)
    }
}
