//! Architecture register capability rows and manifests.

use super::*;

/// Closed architecture register group used for coverage and side-effect gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultRegisterGroupV1 {
    /// General-purpose integer register.
    GeneralPurpose = 1,
    /// Program counter or instruction pointer.
    ControlFlow = 2,
    /// Architectural flags or processor state.
    Flags = 3,
    /// Segment selector, base, limit, or attributes.
    Segment = 4,
    /// Translation or privilege control register.
    Control = 5,
    /// Other guest-visible system register.
    System = 6,
    /// Architectural debug register.
    Debug = 7,
    /// x87, MMX, or scalar floating-point state.
    FloatingPoint = 8,
    /// SIMD or vector register state.
    Vector = 9,
    /// Architecture-defined error status or syndrome register.
    Error = 10,
}

impl FaultRegisterGroupV1 {
    /// Decodes one registered architecture group tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::GeneralPurpose),
            2 => Ok(Self::ControlFlow),
            3 => Ok(Self::Flags),
            4 => Ok(Self::Segment),
            5 => Ok(Self::Control),
            6 => Ok(Self::System),
            7 => Ok(Self::Debug),
            8 => Ok(Self::FloatingPoint),
            9 => Ok(Self::Vector),
            10 => Ok(Self::Error),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// The row admits an impulse mutation at a safe boundary.
pub const FAULT_REGISTER_CAPABILITY_IMPULSE: u32 = 1 << 0;
/// The row admits persistent read/write transforms at its declared phases.
pub const FAULT_REGISTER_CAPABILITY_PERSISTENT: u32 = 1 << 1;
/// The architectural value is covered by CPU VMState.
pub const FAULT_REGISTER_CAPABILITY_VMSTATE: u32 = 1 << 2;
/// Every register capability flag understood by codec version 1.
pub const FAULT_REGISTER_CAPABILITIES_V1_MASK: u32 = (1 << 3) - 1;

/// Writing the row requires translation-cache invalidation.
pub const FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH: u32 = 1 << 0;
/// Writing the row requires translated-block invalidation or exit.
pub const FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH: u32 = 1 << 1;
/// Writing the row requires derived CPU-flag recomputation.
pub const FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS: u32 = 1 << 2;
/// Writing the row requires interrupt-state reevaluation.
pub const FAULT_REGISTER_SIDE_EFFECT_INTERRUPT: u32 = 1 << 3;
/// Writing the row requires timer rearming.
pub const FAULT_REGISTER_SIDE_EFFECT_TIMER: u32 = 1 << 4;
/// Writing the row changes the next guest control-flow address.
pub const FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW: u32 = 1 << 5;
/// Every register side-effect bit understood by codec version 1.
pub const FAULT_REGISTER_SIDE_EFFECTS_V1_MASK: u32 = (1 << 6) - 1;

/// One architecture-owned register capability row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultRegisterCapabilityRowV1 {
    /// Stable numeric register ID used inside QEMU.
    pub numeric_id: u32,
    /// Stable user-facing register name.
    pub name: String,
    /// Register width in bits.
    pub width_bits: u32,
    /// Coverage group used by exhaustive live gates.
    pub group: FaultRegisterGroupV1,
    /// Model phases at which this register can be transformed.
    pub model_phase_mask: u64,
    /// Required derived-state actions.
    pub side_effects: u32,
    /// Impulse, persistent, and VMState support bits.
    pub capabilities: u32,
    /// Bits that may be changed by a mutation.
    pub writable_mask: Vec<u8>,
    /// Architecturally reserved bits that must be preserved.
    pub reserved_mask: Vec<u8>,
    /// Architecturally ignored bits that must be preserved on write.
    pub ignored_mask: Vec<u8>,
    /// Guest-visible read-only bits.
    pub read_only_mask: Vec<u8>,
}

impl FaultRegisterCapabilityRowV1 {
    /// Validates this row's identity, masks, phases, and mutation contract.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] when a field is outside
    /// the closed version-1 vocabulary, masks do not partition every register
    /// bit exactly once, or mutation flags contradict writability and VMState.
    pub fn validate(&self) -> Result<(), FaultAbiError> {
        if self.numeric_id == 0
            || !valid_identity(&self.name)
            || self.width_bits == 0
            || self.width_bits > HARD_FAULT_REGISTER_WIDTH_BITS
            || self.model_phase_mask & !FAULT_MODEL_PHASES_V1_MASK != 0
            || self.side_effects & !FAULT_REGISTER_SIDE_EFFECTS_V1_MASK != 0
            || self.capabilities & !FAULT_REGISTER_CAPABILITIES_V1_MASK != 0
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mask_len = usize::try_from(self.width_bits.div_ceil(8))
            .map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let masks = [
            self.writable_mask.as_slice(),
            self.reserved_mask.as_slice(),
            self.ignored_mask.as_slice(),
            self.read_only_mask.as_slice(),
        ];
        if masks.iter().any(|mask| mask.len() != mask_len) {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        for bit in 0..self.width_bits {
            let byte = usize::try_from(bit / 8).map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let mask = 1_u8 << (bit % 8);
            if masks.iter().filter(|value| value[byte] & mask != 0).count() != 1 {
                return Err(FaultAbiError::CapabilityInvariant);
            }
        }
        let trailing_bits = self.width_bits % 8;
        if trailing_bits != 0 {
            let invalid = !((1_u8 << trailing_bits) - 1);
            if masks.iter().any(|mask| mask[mask_len - 1] & invalid != 0) {
                return Err(FaultAbiError::CapabilityInvariant);
            }
        }
        let writable = self.writable_mask.iter().any(|byte| *byte != 0);
        let mutable = self.capabilities
            & (FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_PERSISTENT)
            != 0;
        if writable != mutable
            || (mutable
                && (self.model_phase_mask == 0
                    || self.capabilities & FAULT_REGISTER_CAPABILITY_VMSTATE == 0))
            || (!mutable && (self.model_phase_mask != 0 || self.side_effects != 0))
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), FaultAbiError> {
        self.validate()?;
        let name_len =
            u16::try_from(self.name.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let mask_len = u16::try_from(self.writable_mask.len())
            .map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let row_len = FAULT_REGISTER_ROW_HEADER_V1_BYTES
            .checked_add(self.name.len())
            .and_then(|length| length.checked_add(self.writable_mask.len() * 4))
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        let row_len = u32::try_from(row_len).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&self.numeric_id.to_le_bytes());
        output.extend_from_slice(&(self.group as u16).to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(&self.width_bits.to_le_bytes());
        output.extend_from_slice(&self.model_phase_mask.to_le_bytes());
        output.extend_from_slice(&self.side_effects.to_le_bytes());
        output.extend_from_slice(&self.capabilities.to_le_bytes());
        output.extend_from_slice(&name_len.to_le_bytes());
        output.extend_from_slice(&mask_len.to_le_bytes());
        output.extend_from_slice(&mask_len.to_le_bytes());
        output.extend_from_slice(&mask_len.to_le_bytes());
        output.extend_from_slice(&mask_len.to_le_bytes());
        output.extend_from_slice(&row_len.to_le_bytes());
        output.extend_from_slice(self.name.as_bytes());
        output.extend_from_slice(&self.writable_mask);
        output.extend_from_slice(&self.reserved_mask);
        output.extend_from_slice(&self.ignored_mask);
        output.extend_from_slice(&self.read_only_mask);
        Ok(())
    }
}

/// Exact register manifest for one realized architecture and CPU model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultRegisterCapabilityManifestV1 {
    /// Architecture scope of every row.
    pub architecture: FaultCapabilityScope,
    /// Exact realized QEMU CPU model identity.
    pub cpu_model: String,
    /// Canonically ordered register rows.
    pub rows: Vec<FaultRegisterCapabilityRowV1>,
}

impl FaultRegisterCapabilityManifestV1 {
    /// Encodes a canonical, self-authenticating register manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for an invalid architecture/model, empty or
    /// noncanonical rows, invalid masks, or payload overflow.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        let distinct_names = self
            .rows
            .iter()
            .map(|row| row.name.as_str())
            .collect::<BTreeSet<_>>();
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || !valid_cpu_model(&self.cpu_model)
            || self.rows.is_empty()
            || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self
                .rows
                .windows(2)
                .any(|pair| pair[0].numeric_id >= pair[1].numeric_id)
            || distinct_names.len() != self.rows.len()
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut body = Vec::new();
        body.extend_from_slice(self.cpu_model.as_bytes());
        for row in &self.rows {
            row.encode(&mut body)?;
        }
        let maximum_body_bytes = usize::try_from(crate::HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_| FaultAbiError::PayloadLimit)?
            .checked_sub(FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if body.len() > maximum_body_bytes {
            return Err(FaultAbiError::PayloadLimit);
        }
        let digest = blake3::hash(&body);
        let model_len =
            u16::try_from(self.cpu_model.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let row_count =
            u32::try_from(self.rows.len()).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len = u32::try_from(body.len()).map_err(|_| FaultAbiError::PayloadLimit)?;
        let mut output = Vec::with_capacity(FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_REGISTER_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_REGISTER_MANIFEST_VERSION_V1.to_le_bytes());
        output.extend_from_slice(&(self.architecture as u16).to_le_bytes());
        output.extend_from_slice(&model_len.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(&row_count.to_le_bytes());
        output.extend_from_slice(&body_len.to_le_bytes());
        output.extend_from_slice(digest.as_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes and authenticates a canonical register manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, bounds, ordering,
    /// masks, architecture scope, or digest mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_REGISTER_MANIFEST_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16_at(bytes, 8)? != FAULT_REGISTER_MANIFEST_VERSION_V1 || u16_at(bytes, 14)? != 0 {
            return Err(FaultAbiError::Version);
        }
        let architecture = FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?;
        let model_len = usize::from(u16_at(bytes, 12)?);
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count == 0 || row_count > HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let expected_len = FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES
            .checked_add(body_len)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if bytes.len() != expected_len
            || model_len > body_len
            || model_len > HARD_FAULT_TARGET_NAME_BYTES
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let cpu_model = core::str::from_utf8(&body[..model_len])
            .map_err(|_| FaultAbiError::CapabilityInvariant)?
            .to_owned();
        let mut offset = model_len;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_REGISTER_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_REGISTER_ROW_HEADER_V1_BYTES];
            let numeric_id = u32_at(header, 0)?;
            let group = FaultRegisterGroupV1::from_u16(u16_at(header, 4)?)?;
            if u16_at(header, 6)? != 0 {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let width_bits = u32_at(header, 8)?;
            let model_phase_mask = u64_at(header, 12)?;
            let side_effects = u32_at(header, 20)?;
            let capabilities = u32_at(header, 24)?;
            let name_len = usize::from(u16_at(header, 28)?);
            let writable_len = usize::from(u16_at(header, 30)?);
            let reserved_len = usize::from(u16_at(header, 32)?);
            let ignored_len = usize::from(u16_at(header, 34)?);
            let read_only_len = usize::from(u16_at(header, 36)?);
            let row_len = usize::try_from(u32_at(header, 38)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let calculated = FAULT_REGISTER_ROW_HEADER_V1_BYTES
                .checked_add(name_len)
                .and_then(|length| length.checked_add(writable_len))
                .and_then(|length| length.checked_add(reserved_len))
                .and_then(|length| length.checked_add(ignored_len))
                .and_then(|length| length.checked_add(read_only_len))
                .ok_or(FaultAbiError::CapabilityInvariant)?;
            if row_len != calculated || body.len().saturating_sub(offset) < row_len {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_REGISTER_ROW_HEADER_V1_BYTES;
            let name = take_text(body, &mut cursor, name_len)?;
            let writable_mask = take_bytes(body, &mut cursor, writable_len)?;
            let reserved_mask = take_bytes(body, &mut cursor, reserved_len)?;
            let ignored_mask = take_bytes(body, &mut cursor, ignored_len)?;
            let read_only_mask = take_bytes(body, &mut cursor, read_only_len)?;
            let row = FaultRegisterCapabilityRowV1 {
                numeric_id,
                name,
                width_bits,
                group,
                model_phase_mask,
                side_effects,
                capabilities,
                writable_mask,
                reserved_mask,
                ignored_mask,
                read_only_mask,
            };
            row.validate()?;
            rows.push(row);
            offset += row_len;
        }
        if offset != body.len() {
            return Err(FaultAbiError::HeaderLength);
        }
        let manifest = Self {
            architecture,
            cpu_model,
            rows,
        };
        if manifest.encode()?.as_slice() != bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(manifest)
    }
}
