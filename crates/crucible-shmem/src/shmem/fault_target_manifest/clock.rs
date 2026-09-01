//! Guest-visible clock capability rows and manifests.

use super::*;

/// One immutable guest-visible clock source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultClockCapabilityRowV1 {
    /// Stable source identity used by clock targets.
    pub id: String,
    /// QEMU subsystem that implements the source and related timers.
    pub implementation: String,
    /// Closed QEMU clock-source kind.
    pub source_kind: u16,
    /// Underlying deterministic clock domain.
    pub base_domain: u16,
    /// Relationship to a programmable guest timer, or zero for none.
    pub timer_relationship: u16,
    /// Architecturally visible counter width.
    pub width_bits: u32,
    /// Closed wrap and read-error capability bits.
    pub flags: u32,
    /// Exact source-frequency numerator in ticks per second.
    pub frequency_numerator: u64,
    /// Exact source-frequency denominator in ticks per second.
    pub frequency_denominator: u64,
    /// Bit set of exact fault model phases.
    pub model_phase_mask: u64,
    /// Whether the source, transforms, and timer relationship migrate.
    pub vmstate: bool,
    /// Required default handling for a value that moves backward.
    pub monotonicity: u8,
}

impl FaultClockCapabilityRowV1 {
    fn validate(&self) -> Result<(), FaultAbiError> {
        let clock_read = 1_u64 << (28 - 1);
        let arm = 1_u64 << (29 - 1);
        let fire = 1_u64 << (30 - 1);

        if !valid_identity(&self.id)
            || !valid_cpu_model(&self.implementation)
            || !(1..=9).contains(&self.source_kind)
            || !(1..=2).contains(&self.base_domain)
            || self.timer_relationship > 1
            || self.width_bits == 0
            || self.width_bits > 64
            || self.flags & !0x3 != 0
            || self.frequency_numerator == 0
            || self.frequency_denominator == 0
            || self.model_phase_mask == 0
            || self.model_phase_mask & !FAULT_MODEL_PHASES_V1_MASK != 0
            || self.model_phase_mask & clock_read == 0
            || ((self.timer_relationship == 1)
                != (self.model_phase_mask & arm != 0 && self.model_phase_mask & fire != 0))
            || !self.vmstate
            || !(1..=3).contains(&self.monotonicity)
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
        let row_len = FAULT_CLOCK_ROW_HEADER_V1_BYTES
            .checked_add(self.id.len())
            .and_then(|length| length.checked_add(self.implementation.len()))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&self.source_kind.to_le_bytes());
        output.extend_from_slice(&self.base_domain.to_le_bytes());
        output.extend_from_slice(&self.timer_relationship.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(&self.width_bits.to_le_bytes());
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.extend_from_slice(&self.frequency_numerator.to_le_bytes());
        output.extend_from_slice(&self.frequency_denominator.to_le_bytes());
        output.extend_from_slice(&self.model_phase_mask.to_le_bytes());
        output.push(u8::from(self.vmstate));
        output.push(self.monotonicity);
        output.extend_from_slice(&[0; 6]);
        output.extend_from_slice(&id_len.to_le_bytes());
        output.extend_from_slice(&implementation_len.to_le_bytes());
        output.extend_from_slice(&row_len.to_le_bytes());
        output.extend_from_slice(self.id.as_bytes());
        output.extend_from_slice(self.implementation.as_bytes());
        Ok(())
    }
}

/// Exact guest-clock manifest for one realized QEMU machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultClockCapabilityManifestV1 {
    /// Architecture scope shared by every source.
    pub architecture: FaultCapabilityScope,
    /// Canonically ordered guest-visible sources.
    pub rows: Vec<FaultClockCapabilityRowV1>,
}

impl FaultClockCapabilityManifestV1 {
    /// Encodes a canonical self-authenticating guest-clock manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for invalid source fields, ordering, size,
    /// architecture, phase, or VMState coverage.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || self.rows.is_empty()
            || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.rows.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut body = Vec::new();
        for row in &self.rows {
            let architecture_matches = match self.architecture {
                FaultCapabilityScope::X86_64 => {
                    (1..=6).contains(&row.source_kind) || row.source_kind == 9
                }
                FaultCapabilityScope::Aarch64 => (7..=9).contains(&row.source_kind),
                _ => false,
            };
            if !architecture_matches {
                return Err(FaultAbiError::CapabilityInvariant);
            }
            row.encode(&mut body)?;
        }
        if FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES
            .checked_add(body.len())
            .is_none_or(|length| length > crate::HARD_FAULT_PAYLOAD_BYTES as usize)
        {
            return Err(FaultAbiError::PayloadLimit);
        }
        let mut output = Vec::with_capacity(FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_CLOCK_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_CLOCK_MANIFEST_VERSION_V1.to_le_bytes());
        output.extend_from_slice(&(self.architecture as u16).to_le_bytes());
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

    /// Decodes and authenticates a canonical guest-clock manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, digest, source
    /// fields, ordering, architecture, or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_CLOCK_MANIFEST_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16_at(bytes, 8)? != FAULT_CLOCK_MANIFEST_VERSION_V1 || u32_at(bytes, 12)? != 0 {
            return Err(FaultAbiError::Version);
        }
        let architecture = FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?;
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count == 0
            || row_count > HARD_FAULT_TARGET_MANIFEST_ROWS
            || bytes.len()
                != FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES
                    .checked_add(body_len)
                    .ok_or(FaultAbiError::PayloadLimit)?
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let mut offset = 0;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_CLOCK_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_CLOCK_ROW_HEADER_V1_BYTES];
            if u16_at(header, 6)? != 0 || header[42..48] != [0; 6] {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let id_len = usize::from(u16_at(header, 48)?);
            let implementation_len = usize::from(u16_at(header, 50)?);
            let row_len = usize::try_from(u32_at(header, 52)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            if row_len
                != FAULT_CLOCK_ROW_HEADER_V1_BYTES
                    .checked_add(id_len)
                    .and_then(|length| length.checked_add(implementation_len))
                    .ok_or(FaultAbiError::CapabilityInvariant)?
                || body.len().saturating_sub(offset) < row_len
            {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_CLOCK_ROW_HEADER_V1_BYTES;
            let id = take_text(body, &mut cursor, id_len)?;
            let implementation = take_text(body, &mut cursor, implementation_len)?;
            let row = FaultClockCapabilityRowV1 {
                id,
                implementation,
                source_kind: u16_at(header, 0)?,
                base_domain: u16_at(header, 2)?,
                timer_relationship: u16_at(header, 4)?,
                width_bits: u32_at(header, 8)?,
                flags: u32_at(header, 12)?,
                frequency_numerator: u64_at(header, 16)?,
                frequency_denominator: u64_at(header, 24)?,
                model_phase_mask: u64_at(header, 32)?,
                vmstate: bool_at(header, 40)?,
                monotonicity: header[41],
            };
            row.validate()?;
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
