//! Typed capability manifests for guest-visible QEMU fault targets.
//!
//! Aggregate command capabilities are insufficient for targets whose legal
//! names, widths, masks, and side effects depend on the realized CPU model or
//! QEMU device graph. This module defines the public byte protocol used to
//! query those target rows before launch admission. It contains no QEMU-native
//! layouts or pointers.

use core::fmt::Write as _;
use std::collections::BTreeSet;

use crate::{FaultAbiError, FaultCapabilityScope};

/// Magic prefix for a target-manifest query.
pub const FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1: [u8; 8] = *b"CRUCFTQ1";
/// Encoded byte length of a target-manifest query.
pub const FAULT_TARGET_MANIFEST_QUERY_V1_BYTES: usize = 16;
/// Magic prefix for a register capability manifest.
pub const FAULT_REGISTER_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCRGM1";
/// Register manifest codec version.
pub const FAULT_REGISTER_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed register manifest header length.
pub const FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES: usize = 56;
/// Fixed register row header length before its name and four masks.
pub const FAULT_REGISTER_ROW_HEADER_V1_BYTES: usize = 42;
/// Maximum number of target rows returned by one QEMU process.
pub const HARD_FAULT_TARGET_MANIFEST_ROWS: usize = 4_096;
/// Maximum encoded target name or CPU-model identity length.
pub const HARD_FAULT_TARGET_NAME_BYTES: usize = 96;
/// Maximum register width admitted by the public node-fault contract.
pub const HARD_FAULT_REGISTER_WIDTH_BITS: u32 = 65_536;
/// Every model-phase tag currently defined by the node payload ABI.
pub const FAULT_MODEL_PHASES_V1_MASK: u64 = (1_u64 << 37) - 1;

/// Computes the canonical protocol identity for one fault-object name.
///
/// This function deliberately shares the model's stable identity algorithm so
/// the GPL-side plugin can bind public name hashes to QEMU-private numeric
/// target IDs without depending on the Apache host implementation.
#[must_use]
pub fn fault_object_id_hash_v1(name: &str) -> [u8; 32] {
    let mut hasher = FaultIdentityHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(b"crucible.fault-object.v1");
    hasher.write_bytes(name.as_bytes());
    hasher.finish()
}

/// Selects one closed target-manifest family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultTargetManifestKind {
    /// Architecture register rows for the realized CPU model.
    Register = 1,
}

impl FaultTargetManifestKind {
    fn decode(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Register),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Requests one immutable target manifest from QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultTargetManifestQueryV1 {
    /// Closed manifest family to return.
    pub kind: FaultTargetManifestKind,
}

impl FaultTargetManifestQueryV1 {
    /// Encodes the canonical fixed-width query.
    #[must_use]
    pub fn encode(self) -> [u8; FAULT_TARGET_MANIFEST_QUERY_V1_BYTES] {
        let mut bytes = [0_u8; FAULT_TARGET_MANIFEST_QUERY_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(self.kind as u16).to_le_bytes());
        bytes
    }

    /// Decodes an exact target-manifest query.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for wrong framing, versions, kinds, or
    /// nonzero reserved bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_TARGET_MANIFEST_QUERY_V1_BYTES
            || bytes[..8] != FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != 1 {
            return Err(FaultAbiError::Version);
        }
        if bytes[12..].iter().any(|byte| *byte != 0) {
            return Err(FaultAbiError::ReservedNonzero);
        }
        Ok(Self {
            kind: FaultTargetManifestKind::decode(u16::from_le_bytes([bytes[10], bytes[11]]))?,
        })
    }
}

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
    fn validate(&self) -> Result<(), FaultAbiError> {
        if self.numeric_id == 0
            || !valid_identity(&self.name)
            || self.width_bits == 0
            || self.width_bits > HARD_FAULT_REGISTER_WIDTH_BITS
            || self.model_phase_mask == 0
            || self.model_phase_mask & !FAULT_MODEL_PHASES_V1_MASK != 0
            || self.side_effects & !FAULT_REGISTER_SIDE_EFFECTS_V1_MASK != 0
            || self.capabilities == 0
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

pub(crate) fn emit_fault_target_manifest_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded QEMU target-manifest ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1 \"CRUCFTQ1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_REGISTER_MANIFEST_MAGIC_V1 \"CRUCRGM1\"\n");
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_V1_BYTES",
        FAULT_TARGET_MANIFEST_QUERY_V1_BYTES
    );
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_REGISTER",
        FaultTargetManifestKind::Register as u16
    );
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_MAGIC_OFFSET", 0);
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_VERSION_OFFSET", 8);
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_KIND_OFFSET", 10);
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_RESERVED_OFFSET", 12);
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_RESERVED_BYTES", 4);
    define!(
        "CRUCIBLE_FAULT_REGISTER_MANIFEST_VERSION_V1",
        FAULT_REGISTER_MANIFEST_VERSION_V1
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES",
        FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_ROW_HEADER_V1_BYTES",
        FAULT_REGISTER_ROW_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_HARD_ROWS",
        HARD_FAULT_TARGET_MANIFEST_ROWS
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_NAME_HARD_BYTES",
        HARD_FAULT_TARGET_NAME_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_WIDTH_HARD_BITS",
        HARD_FAULT_REGISTER_WIDTH_BITS
    );
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_MAGIC_OFFSET", 0);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_VERSION_OFFSET", 8);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_ARCHITECTURE_OFFSET", 10);
    define!(
        "CRUCIBLE_FAULT_REGISTER_MANIFEST_CPU_MODEL_LENGTH_OFFSET",
        12
    );
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_RESERVED_OFFSET", 14);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_ROW_COUNT_OFFSET", 16);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_BODY_LENGTH_OFFSET", 20);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_BODY_DIGEST_OFFSET", 24);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_BODY_DIGEST_BYTES", 32);
    define!("CRUCIBLE_FAULT_REGISTER_MANIFEST_BODY_OFFSET", 56);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_NUMERIC_ID_OFFSET", 0);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_GROUP_OFFSET", 4);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_RESERVED_OFFSET", 6);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_WIDTH_BITS_OFFSET", 8);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_MODEL_PHASE_MASK_OFFSET", 12);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_SIDE_EFFECTS_OFFSET", 20);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_CAPABILITIES_OFFSET", 24);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_NAME_LENGTH_OFFSET", 28);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_WRITABLE_LENGTH_OFFSET", 30);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_RESERVED_LENGTH_OFFSET", 32);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_IGNORED_LENGTH_OFFSET", 34);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_READ_ONLY_LENGTH_OFFSET", 36);
    define!("CRUCIBLE_FAULT_REGISTER_ROW_LENGTH_OFFSET", 38);
    for (name, value) in [
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_GENERAL_PURPOSE",
            FaultRegisterGroupV1::GeneralPurpose as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_CONTROL_FLOW",
            FaultRegisterGroupV1::ControlFlow as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_FLAGS",
            FaultRegisterGroupV1::Flags as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_SEGMENT",
            FaultRegisterGroupV1::Segment as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_CONTROL",
            FaultRegisterGroupV1::Control as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_SYSTEM",
            FaultRegisterGroupV1::System as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_DEBUG",
            FaultRegisterGroupV1::Debug as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_FLOATING_POINT",
            FaultRegisterGroupV1::FloatingPoint as u16,
        ),
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_VECTOR",
            FaultRegisterGroupV1::Vector as u16,
        ),
    ] {
        define!(name, value);
    }
    define!(
        "CRUCIBLE_FAULT_REGISTER_CAPABILITY_IMPULSE",
        FAULT_REGISTER_CAPABILITY_IMPULSE
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_CAPABILITY_PERSISTENT",
        FAULT_REGISTER_CAPABILITY_PERSISTENT
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_CAPABILITY_VMSTATE",
        FAULT_REGISTER_CAPABILITY_VMSTATE
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_CAPABILITIES_V1_MASK",
        FAULT_REGISTER_CAPABILITIES_V1_MASK
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH",
        FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH",
        FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS",
        FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_INTERRUPT",
        FAULT_REGISTER_SIDE_EFFECT_INTERRUPT
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_TIMER",
        FAULT_REGISTER_SIDE_EFFECT_TIMER
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW",
        FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECTS_V1_MASK",
        FAULT_REGISTER_SIDE_EFFECTS_V1_MASK
    );
}

fn valid_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= HARD_FAULT_TARGET_NAME_BYTES
        && bytes[0].is_ascii_lowercase()
        && (bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

fn valid_cpu_model(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= HARD_FAULT_TARGET_NAME_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn take_text(bytes: &[u8], offset: &mut usize, length: usize) -> Result<String, FaultAbiError> {
    let raw = take_bytes(bytes, offset, length)?;
    core::str::from_utf8(&raw)
        .map(str::to_owned)
        .map_err(|_| FaultAbiError::CapabilityInvariant)
}

fn take_bytes(bytes: &[u8], offset: &mut usize, length: usize) -> Result<Vec<u8>, FaultAbiError> {
    let end = offset
        .checked_add(length)
        .ok_or(FaultAbiError::HeaderLength)?;
    let value = bytes.get(*offset..end).ok_or(FaultAbiError::HeaderLength)?;
    *offset = end;
    Ok(value.to_vec())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(FaultAbiError::HeaderLength)?;
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| FaultAbiError::HeaderLength)?,
    ))
}

struct FaultIdentityHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl FaultIdentityHasher {
    const fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.mix_word(bytes.len() as u64);
        self.bytes_written = self.bytes_written.wrapping_add(8);
        for chunk in bytes.chunks(8) {
            let mut word = [0_u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }
        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }

    fn finish(&self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (index, lane) in self.lanes.iter().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut word = lane.wrapping_add(self.bytes_written).wrapping_add(salt);
            word ^= word >> 30;
            word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word ^= word >> 27;
            word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            output[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTER_MANIFEST_GOLDEN_HEX: &str =
        include_str!("../../tests/fixtures/fault_register_manifest_v1.hex");

    fn row(name: &str, numeric_id: u32) -> FaultRegisterCapabilityRowV1 {
        FaultRegisterCapabilityRowV1 {
            numeric_id,
            name: name.to_owned(),
            width_bits: 8,
            group: FaultRegisterGroupV1::GeneralPurpose,
            model_phase_mask: 1 << (13 - 1),
            side_effects: 0,
            capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
            writable_mask: vec![0x0f],
            reserved_mask: vec![0x30],
            ignored_mask: vec![0x40],
            read_only_mask: vec![0x80],
        }
    }

    #[test]
    fn query_codec_rejects_unknown_kinds_and_reserved_bytes() {
        let query = FaultTargetManifestQueryV1 {
            kind: FaultTargetManifestKind::Register,
        };
        let encoded = query.encode();
        assert_eq!(FaultTargetManifestQueryV1::decode(&encoded), Ok(query));

        let mut unknown = encoded;
        unknown[10..12].copy_from_slice(&99_u16.to_le_bytes());
        assert_eq!(
            FaultTargetManifestQueryV1::decode(&unknown),
            Err(FaultAbiError::CapabilityInvariant)
        );
        let mut reserved = encoded;
        reserved[15] = 1;
        assert_eq!(
            FaultTargetManifestQueryV1::decode(&reserved),
            Err(FaultAbiError::ReservedNonzero)
        );
    }

    #[test]
    fn register_manifest_round_trips_canonical_rows_and_masks() {
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![row("rax", 1), row("rbx", 2)],
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("manifest should encode: {error}"));
        assert_eq!(
            FaultRegisterCapabilityManifestV1::decode(&encoded),
            Ok(manifest)
        );
    }

    #[test]
    fn register_manifest_golden_vector_is_frozen() {
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![row("rax", 1), row("rbx", 2)],
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("golden manifest should encode: {error}"));
        let actual = encoded
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, REGISTER_MANIFEST_GOLDEN_HEX.trim());
        assert_eq!(
            FaultRegisterCapabilityManifestV1::decode(&encoded),
            Ok(manifest)
        );
    }

    #[test]
    fn register_manifest_rejects_overlap_gaps_order_and_digest_drift() {
        let mut overlapping = row("rax", 1);
        overlapping.reserved_mask[0] |= 1;
        assert_eq!(
            FaultRegisterCapabilityManifestV1 {
                architecture: FaultCapabilityScope::X86_64,
                cpu_model: "crucible-x86-64-v1".to_owned(),
                rows: vec![overlapping],
            }
            .encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let unsorted = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::Aarch64,
            cpu_model: "crucible-aarch64-v1".to_owned(),
            rows: vec![row("x1", 2), row("x0", 1)],
        };
        assert_eq!(unsorted.encode(), Err(FaultAbiError::CapabilityInvariant));

        let duplicate_id = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![row("rax", 1), row("rbx", 1)],
        };
        assert_eq!(
            duplicate_id.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let duplicate_name = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![row("rax", 1), row("rax", 2)],
        };
        assert_eq!(
            duplicate_name.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let valid = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![row("rax", 1)],
        };
        let mut corrupt = valid
            .encode()
            .unwrap_or_else(|error| panic!("manifest should encode: {error}"));
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            FaultRegisterCapabilityManifestV1::decode(&corrupt),
            Err(FaultAbiError::PayloadDigest)
        );
    }
}
