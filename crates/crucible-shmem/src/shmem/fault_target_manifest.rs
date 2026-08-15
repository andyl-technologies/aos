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
/// Magic prefix for an interrupt capability manifest.
pub const FAULT_INTERRUPT_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCIRM1";
/// Interrupt manifest codec version.
pub const FAULT_INTERRUPT_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed interrupt manifest header length.
pub const FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES: usize = 56;
/// Fixed interrupt row header length before identities and target vCPUs.
pub const FAULT_INTERRUPT_ROW_HEADER_V1_BYTES: usize = 52;
/// Magic prefix for a guest-clock capability manifest.
pub const FAULT_CLOCK_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCCLM1";
/// Guest-clock manifest codec version.
pub const FAULT_CLOCK_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed guest-clock manifest header length.
pub const FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES: usize = 56;
/// Fixed guest-clock row header length before its identities.
pub const FAULT_CLOCK_ROW_HEADER_V1_BYTES: usize = 56;
/// Magic prefix for a hardware-error capability manifest.
pub const FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCHWM1";
/// Hardware-error manifest codec version.
pub const FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed hardware-error manifest header length.
pub const FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES: usize = 56;
/// Fixed hardware-error row header length before its six identities.
pub const FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES: usize = 88;
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
    /// Fully routed interrupt rows for the realized machine.
    Interrupt = 2,
    /// Architecture and platform hardware-error delivery rows.
    HardwareError = 3,
    /// Guest-visible architecture and device clock sources.
    Clock = 4,
}

impl FaultTargetManifestKind {
    fn decode(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Interrupt),
            3 => Ok(Self::HardwareError),
            4 => Ok(Self::Clock),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Closed architecture interrupt family used by manifest rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultInterruptFamilyV1 {
    /// x86 local-APIC fixed interrupt.
    X86LocalApicFixed = 1,
    /// x86 inter-processor interrupt.
    X86Ipi = 2,
    /// x86 I/O-APIC route.
    X86IoApic = 3,
    /// x86 legacy PIC route.
    X86Pic = 4,
    /// x86 PCI MSI.
    X86Msi = 5,
    /// x86 PCI MSI-X.
    X86MsiX = 6,
    /// x86 NMI.
    X86Nmi = 7,
    /// x86 local-APIC timer.
    X86Timer = 8,
    /// Arm GIC SGI.
    ArmGicSgi = 9,
    /// Arm GIC PPI.
    ArmGicPpi = 10,
    /// Arm GIC SPI.
    ArmGicSpi = 11,
    /// Arm GIC LPI.
    ArmGicLpi = 12,
    /// Arm architecture timer PPI.
    ArmTimer = 13,
}

impl FaultInterruptFamilyV1 {
    /// Decodes one public wire tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::X86LocalApicFixed),
            2 => Ok(Self::X86Ipi),
            3 => Ok(Self::X86IoApic),
            4 => Ok(Self::X86Pic),
            5 => Ok(Self::X86Msi),
            6 => Ok(Self::X86MsiX),
            7 => Ok(Self::X86Nmi),
            8 => Ok(Self::X86Timer),
            9 => Ok(Self::ArmGicSgi),
            10 => Ok(Self::ArmGicPpi),
            11 => Ok(Self::ArmGicSpi),
            12 => Ok(Self::ArmGicLpi),
            13 => Ok(Self::ArmTimer),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }

    fn architecture(self) -> FaultCapabilityScope {
        match self {
            Self::X86LocalApicFixed
            | Self::X86Ipi
            | Self::X86IoApic
            | Self::X86Pic
            | Self::X86Msi
            | Self::X86MsiX
            | Self::X86Nmi
            | Self::X86Timer => FaultCapabilityScope::X86_64,
            Self::ArmGicSgi
            | Self::ArmGicPpi
            | Self::ArmGicSpi
            | Self::ArmGicLpi
            | Self::ArmTimer => FaultCapabilityScope::Aarch64,
        }
    }

    fn vector_valid(self, vector: u32) -> bool {
        match self {
            Self::X86Nmi => vector == 2,
            Self::X86Pic => vector <= 255,
            Self::X86LocalApicFixed
            | Self::X86Ipi
            | Self::X86IoApic
            | Self::X86Msi
            | Self::X86MsiX
            | Self::X86Timer => (16..=255).contains(&vector),
            Self::ArmGicSgi => vector <= 15,
            Self::ArmGicPpi | Self::ArmTimer => (16..=31).contains(&vector),
            Self::ArmGicSpi => (32..=1_019).contains(&vector),
            Self::ArmGicLpi => (8_192..=16_777_215).contains(&vector),
        }
    }

    fn fixed_edge(self) -> bool {
        matches!(
            self,
            Self::X86Ipi
                | Self::X86Msi
                | Self::X86MsiX
                | Self::X86Nmi
                | Self::ArmGicSgi
                | Self::ArmGicLpi
        )
    }
}

/// Electrical trigger mode for an interrupt row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultInterruptTriggerV1 {
    /// Edge triggered.
    Edge = 1,
    /// Level triggered.
    Level = 2,
}

impl FaultInterruptTriggerV1 {
    /// Decodes one public wire tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Edge),
            2 => Ok(Self::Level),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Active interrupt-source polarity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultInterruptPolarityV1 {
    /// Active high or rising edge.
    ActiveHigh = 1,
    /// Active low or falling edge.
    ActiveLow = 2,
}

impl FaultInterruptPolarityV1 {
    /// Decodes one public wire tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::ActiveHigh),
            2 => Ok(Self::ActiveLow),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Controller-state transition for a dropped delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultInterruptDeliveryDropV1 {
    /// Consume one pending edge without activating it.
    ConsumeEdge = 1,
    /// Re-pend while the unchanged level remains asserted.
    RependAssertedLevel = 2,
}

impl FaultInterruptDeliveryDropV1 {
    /// Decodes one public wire tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::ConsumeEdge),
            2 => Ok(Self::RependAssertedLevel),
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
    fn validate(&self) -> Result<(), FaultAbiError> {
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

/// Guest-visible hardware-error record family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorRecordKindV1 {
    /// x86 machine-check architecture record.
    X86MachineCheck = 1,
    /// AArch64 RAS exception record.
    Aarch64Ras = 2,
    /// Platform memory ECC record.
    MemoryEcc = 3,
}

impl FaultHardwareErrorRecordKindV1 {
    /// Decodes one registered record-family tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::X86MachineCheck),
            2 => Ok(Self::Aarch64Ras),
            3 => Ok(Self::MemoryEcc),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Severity or delivery class of one hardware-error row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorClassV1 {
    /// Corrected record without uncorrectable delivery.
    Corrected = 1,
    /// Recoverable uncorrectable error.
    Recoverable = 2,
    /// Fatal uncorrectable error linked to lifecycle handling.
    Fatal = 3,
    /// Synchronous AArch64 external abort.
    Synchronous = 4,
    /// Asynchronous AArch64 SError.
    Asynchronous = 5,
}

impl FaultHardwareErrorClassV1 {
    /// Decodes one registered error-class tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Corrected),
            2 => Ok(Self::Recoverable),
            3 => Ok(Self::Fatal),
            4 => Ok(Self::Synchronous),
            5 => Ok(Self::Asynchronous),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Real guest-visible mechanism used to publish a hardware error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum FaultHardwareErrorMechanismV1 {
    /// x86 MCA banks and machine-check delivery.
    X86Mca = 1,
    /// ACPI APEI GHES memory error record.
    AcpiGhes = 2,
    /// AArch64 RAS synchronous abort or SError.
    Aarch64Ras = 3,
}

impl FaultHardwareErrorMechanismV1 {
    /// Decodes one registered delivery-mechanism tag.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError::CapabilityInvariant`] for an unknown tag.
    pub fn from_u16(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::X86Mca),
            2 => Ok(Self::AcpiGhes),
            3 => Ok(Self::Aarch64Ras),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Publishes a guest-visible telemetry record without exception delivery.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY: u16 = 1 << 0;
/// Delivers a corrected-error interrupt when the realized mechanism supports it.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT: u16 = 1 << 1;
/// Delivers the complete architecture exception described by the command.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION: u16 = 1 << 2;
/// Every hardware-error visibility bit understood by codec version 1.
pub const FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK: u16 = (1 << 3) - 1;
/// Every x86 CPL or AArch64 exception level represented by a manifest row.
pub const FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK: u16 = (1 << 4) - 1;

/// One immutable architecture or platform hardware-error capability row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultHardwareErrorCapabilityRowV1 {
    /// Stable row identity.
    pub id: String,
    /// Stable architecture bank or platform record identity.
    pub bank: String,
    /// Stable memory-channel identity.
    pub channel: String,
    /// Stable memory-rank identity.
    pub rank: String,
    /// Exact firmware or table prerequisite.
    pub firmware: String,
    /// Exact resulting QEMU and guest-visible state contract.
    pub state: String,
    /// Typed record family.
    pub record_kind: FaultHardwareErrorRecordKindV1,
    /// Error severity or AArch64 delivery class.
    pub error_class: FaultHardwareErrorClassV1,
    /// Real publication and delivery mechanism.
    pub mechanism: FaultHardwareErrorMechanismV1,
    /// Permitted telemetry, interrupt, and exception visibility modes.
    pub visibility_mask: u16,
    /// First numeric architecture bank or platform record.
    pub bank_number: u32,
    /// Number of consecutive banks or records in this row.
    pub bank_count: u32,
    /// Required architecture vector or exception class.
    pub vector: u32,
    /// Status bits that every request must set.
    pub status_required: u64,
    /// Complete mask of status bits a request may set.
    pub status_allowed: u64,
    /// Syndrome bits that every request must set.
    pub syndrome_required: u64,
    /// Complete mask of syndrome bits a request may set.
    pub syndrome_allowed: u64,
    /// Fault-model phases at which the row can apply.
    pub model_phase_mask: u64,
    /// x86 CPL or AArch64 EL bit set admitted by this row.
    pub privilege_mask: u16,
    /// Identifies a corrected rather than uncorrectable record.
    pub corrected: bool,
    /// Allows architecture masking to defer delivery.
    pub maskable: bool,
    /// Confirms that resulting architecture/platform state participates in VMState.
    pub vmstate: bool,
}

impl FaultHardwareErrorCapabilityRowV1 {
    fn validate(&self, architecture: FaultCapabilityScope) -> Result<(), FaultAbiError> {
        let identities = [
            self.id.as_str(),
            self.bank.as_str(),
            self.channel.as_str(),
            self.rank.as_str(),
            self.firmware.as_str(),
            self.state.as_str(),
        ];
        let x86 = architecture == FaultCapabilityScope::X86_64;
        let arm = architecture == FaultCapabilityScope::Aarch64;
        let mechanism_matches = match self.mechanism {
            FaultHardwareErrorMechanismV1::X86Mca => x86,
            FaultHardwareErrorMechanismV1::AcpiGhes | FaultHardwareErrorMechanismV1::Aarch64Ras => {
                arm
            }
        };
        let record_matches = match self.record_kind {
            FaultHardwareErrorRecordKindV1::X86MachineCheck => {
                x86 && self.mechanism == FaultHardwareErrorMechanismV1::X86Mca
            }
            FaultHardwareErrorRecordKindV1::Aarch64Ras => {
                arm && self.mechanism == FaultHardwareErrorMechanismV1::Aarch64Ras
            }
            FaultHardwareErrorRecordKindV1::MemoryEcc => matches!(
                self.mechanism,
                FaultHardwareErrorMechanismV1::X86Mca | FaultHardwareErrorMechanismV1::AcpiGhes
            ),
        };
        let class_matches = match self.mechanism {
            FaultHardwareErrorMechanismV1::X86Mca => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Corrected
                    | FaultHardwareErrorClassV1::Recoverable
                    | FaultHardwareErrorClassV1::Fatal
            ),
            FaultHardwareErrorMechanismV1::AcpiGhes => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Corrected | FaultHardwareErrorClassV1::Recoverable
            ),
            FaultHardwareErrorMechanismV1::Aarch64Ras => matches!(
                self.error_class,
                FaultHardwareErrorClassV1::Synchronous
                    | FaultHardwareErrorClassV1::Asynchronous
                    | FaultHardwareErrorClassV1::Fatal
            ),
        };
        let visibility_valid = self.visibility_mask != 0
            && self.visibility_mask & !FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK == 0
            && if self.corrected {
                self.visibility_mask
                    & (FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
                        | FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT)
                    != 0
                    && self.visibility_mask & FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION == 0
            } else {
                self.visibility_mask == FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
            };
        if identities
            .iter()
            .any(|identity| !valid_hardware_identity(identity))
            || identities
                .iter()
                .any(|identity| identity.len() > HARD_FAULT_TARGET_NAME_BYTES)
            || !mechanism_matches
            || !record_matches
            || !class_matches
            || self.bank_count == 0
            || self.bank_number.checked_add(self.bank_count).is_none()
            || self.status_required & !self.status_allowed != 0
            || self.syndrome_required & !self.syndrome_allowed != 0
            || self.model_phase_mask == 0
            || self.model_phase_mask & !FAULT_MODEL_PHASES_V1_MASK != 0
            || self.privilege_mask == 0
            || self.privilege_mask & !FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK != 0
            || !visibility_valid
            || self.corrected != (self.error_class == FaultHardwareErrorClassV1::Corrected)
            || (x86 && self.vector != 18)
            || (arm && self.vector != if self.maskable { 47 } else { 3 })
            || (self.maskable && self.mechanism != FaultHardwareErrorMechanismV1::Aarch64Ras)
            || (self.error_class == FaultHardwareErrorClassV1::Asynchronous && !self.maskable)
            || (self.error_class == FaultHardwareErrorClassV1::Synchronous && self.maskable)
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
        let identities = [
            self.id.as_str(),
            self.bank.as_str(),
            self.channel.as_str(),
            self.rank.as_str(),
            self.firmware.as_str(),
            self.state.as_str(),
        ];
        let lengths = identities
            .iter()
            .map(|identity| {
                u16::try_from(identity.len()).map_err(|_| FaultAbiError::CapabilityInvariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let identity_bytes = identities.iter().try_fold(0_usize, |total, identity| {
            total
                .checked_add(identity.len())
                .ok_or(FaultAbiError::CapabilityInvariant)
        })?;
        let row_len = FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES
            .checked_add(identity_bytes)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        output.extend_from_slice(&(self.record_kind as u16).to_le_bytes());
        output.extend_from_slice(&(self.error_class as u16).to_le_bytes());
        output.extend_from_slice(&(self.mechanism as u16).to_le_bytes());
        output.extend_from_slice(&self.visibility_mask.to_le_bytes());
        output.extend_from_slice(&self.bank_number.to_le_bytes());
        output.extend_from_slice(&self.bank_count.to_le_bytes());
        output.extend_from_slice(&self.vector.to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&self.status_required.to_le_bytes());
        output.extend_from_slice(&self.status_allowed.to_le_bytes());
        output.extend_from_slice(&self.syndrome_required.to_le_bytes());
        output.extend_from_slice(&self.syndrome_allowed.to_le_bytes());
        output.extend_from_slice(&self.model_phase_mask.to_le_bytes());
        output.extend_from_slice(&self.privilege_mask.to_le_bytes());
        output.push(u8::from(self.corrected));
        output.push(u8::from(self.maskable));
        output.push(u8::from(self.vmstate));
        output.push(0);
        for length in lengths {
            output.extend_from_slice(&length.to_le_bytes());
        }
        output.extend_from_slice(&0_u16.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(row_len)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?
                .to_le_bytes(),
        );
        for identity in identities {
            output.extend_from_slice(identity.as_bytes());
        }
        Ok(())
    }
}

/// Exact hardware-error manifest for one realized QEMU machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultHardwareErrorCapabilityManifestV1 {
    /// Architecture scope of every row.
    pub architecture: FaultCapabilityScope,
    /// Canonically ordered hardware-error rows.
    pub rows: Vec<FaultHardwareErrorCapabilityRowV1>,
}

impl FaultHardwareErrorCapabilityManifestV1 {
    fn validate_completeness(&self) -> Result<(), FaultAbiError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let has = |id: &str| self.rows.iter().any(|row| row.id == id);
        let required: &[&str] = match self.architecture {
            FaultCapabilityScope::X86_64 => &[
                "x86.machine-check.corrected",
                "x86.machine-check.recoverable",
                "x86.machine-check.fatal",
            ],
            FaultCapabilityScope::Aarch64 => &[
                "aarch64.ras.synchronous",
                "aarch64.ras.synchronous-fatal",
                "aarch64.ras.asynchronous",
                "aarch64.ras.asynchronous-fatal",
            ],
            _ => return Err(FaultAbiError::CapabilityInvariant),
        };
        if required.iter().any(|id| !has(id)) {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let has_corrected_memory = has("memory.ecc.corrected");
        let has_uncorrectable_memory = has("memory.ecc.uncorrectable");
        if has_corrected_memory != has_uncorrectable_memory {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(())
    }

    /// Encodes a canonical self-authenticating hardware-error manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for invalid rows, architecture, ordering,
    /// masks, identities, or payload size.
    pub fn encode(&self) -> Result<Vec<u8>, FaultAbiError> {
        if !matches!(
            self.architecture,
            FaultCapabilityScope::X86_64 | FaultCapabilityScope::Aarch64
        ) || self.rows.len() > HARD_FAULT_TARGET_MANIFEST_ROWS
            || self.rows.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        self.validate_completeness()?;
        let mut body = Vec::new();
        for row in &self.rows {
            row.encode(self.architecture, &mut body)?;
        }
        let maximum_body_bytes = usize::try_from(crate::HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_| FaultAbiError::PayloadLimit)?
            .checked_sub(FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES)
            .ok_or(FaultAbiError::PayloadLimit)?;
        if body.len() > maximum_body_bytes {
            return Err(FaultAbiError::PayloadLimit);
        }
        let mut output =
            Vec::with_capacity(FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES + body.len());
        output.extend_from_slice(&FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1);
        output.extend_from_slice(&FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1.to_le_bytes());
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

    /// Decodes and authenticates a canonical hardware-error manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, digest, fields,
    /// identities, ordering, or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() < FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES
            || bytes.len() > crate::HARD_FAULT_PAYLOAD_BYTES as usize
            || bytes[..8] != FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1
        {
            return Err(FaultAbiError::HeaderLength);
        }
        if u16_at(bytes, 8)? != FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1 || u32_at(bytes, 12)? != 0
        {
            return Err(FaultAbiError::Version);
        }
        let architecture = FaultCapabilityScope::from_u16(u16_at(bytes, 10)?)?;
        let row_count =
            usize::try_from(u32_at(bytes, 16)?).map_err(|_| FaultAbiError::CapabilityInvariant)?;
        let body_len =
            usize::try_from(u32_at(bytes, 20)?).map_err(|_| FaultAbiError::PayloadLimit)?;
        if row_count > HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        if bytes.len()
            != FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES
                .checked_add(body_len)
                .ok_or(FaultAbiError::PayloadLimit)?
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let body = &bytes[FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES..];
        if bytes[24..56] != *blake3::hash(body).as_bytes() {
            return Err(FaultAbiError::PayloadDigest);
        }
        let mut offset = 0;
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            if body.len().saturating_sub(offset) < FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES {
                return Err(FaultAbiError::HeaderLength);
            }
            let header = &body[offset..offset + FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES];
            if u32_at(header, 20)? != 0 || header[69] != 0 || u16_at(header, 82)? != 0 {
                return Err(FaultAbiError::ReservedNonzero);
            }
            let corrected = bool_at(header, 66)?;
            let maskable = bool_at(header, 67)?;
            let vmstate = bool_at(header, 68)?;
            let lengths = [70, 72, 74, 76, 78, 80]
                .into_iter()
                .map(|field| u16_at(header, field).map(usize::from))
                .collect::<Result<Vec<_>, _>>()?;
            let row_len = usize::try_from(u32_at(header, 84)?)
                .map_err(|_| FaultAbiError::CapabilityInvariant)?;
            let calculated = lengths
                .iter()
                .try_fold(FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES, |total, length| {
                    total.checked_add(*length)
                });
            if calculated != Some(row_len) || body.len().saturating_sub(offset) < row_len {
                return Err(FaultAbiError::HeaderLength);
            }
            let mut cursor = offset + FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES;
            let id = take_text(body, &mut cursor, lengths[0])?;
            let bank = take_text(body, &mut cursor, lengths[1])?;
            let channel = take_text(body, &mut cursor, lengths[2])?;
            let rank = take_text(body, &mut cursor, lengths[3])?;
            let firmware = take_text(body, &mut cursor, lengths[4])?;
            let state = take_text(body, &mut cursor, lengths[5])?;
            let row = FaultHardwareErrorCapabilityRowV1 {
                id,
                bank,
                channel,
                rank,
                firmware,
                state,
                record_kind: FaultHardwareErrorRecordKindV1::from_u16(u16_at(header, 0)?)?,
                error_class: FaultHardwareErrorClassV1::from_u16(u16_at(header, 2)?)?,
                mechanism: FaultHardwareErrorMechanismV1::from_u16(u16_at(header, 4)?)?,
                visibility_mask: u16_at(header, 6)?,
                bank_number: u32_at(header, 8)?,
                bank_count: u32_at(header, 12)?,
                vector: u32_at(header, 16)?,
                status_required: u64_at(header, 24)?,
                status_allowed: u64_at(header, 32)?,
                syndrome_required: u64_at(header, 40)?,
                syndrome_allowed: u64_at(header, 48)?,
                model_phase_mask: u64_at(header, 56)?,
                privilege_mask: u16_at(header, 64)?,
                corrected,
                maskable,
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

pub(crate) fn emit_fault_target_manifest_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded QEMU target-manifest ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1 \"CRUCFTQ1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_REGISTER_MANIFEST_MAGIC_V1 \"CRUCRGM1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_INTERRUPT_MANIFEST_MAGIC_V1 \"CRUCIRM1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_CLOCK_MANIFEST_MAGIC_V1 \"CRUCCLM1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1 \"CRUCHWM1\"\n");
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_V1_BYTES",
        FAULT_TARGET_MANIFEST_QUERY_V1_BYTES
    );
    define!("CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_REGISTER",
        FaultTargetManifestKind::Register as u16
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_INTERRUPT",
        FaultTargetManifestKind::Interrupt as u16
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_HARDWARE_ERROR",
        FaultTargetManifestKind::HardwareError as u16
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_CLOCK",
        FaultTargetManifestKind::Clock as u16
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
        "CRUCIBLE_FAULT_CLOCK_MANIFEST_VERSION_V1",
        FAULT_CLOCK_MANIFEST_VERSION_V1
    );
    define!(
        "CRUCIBLE_FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES",
        FAULT_CLOCK_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_CLOCK_ROW_HEADER_V1_BYTES",
        FAULT_CLOCK_ROW_HEADER_V1_BYTES
    );
    for (name, value) in [
        ("X86_TSC", 1),
        ("X86_RTC", 2),
        ("X86_PIT", 3),
        ("X86_HPET", 4),
        ("X86_APIC_TIMER", 5),
        ("X86_ACPI_PM_TIMER", 6),
        ("ARM_COUNTER", 7),
        ("ARM_RTC", 8),
        ("DEVICE", 9),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_FAULT_CLOCK_SOURCE_{name} {value}");
    }
    define!("CRUCIBLE_FAULT_CLOCK_BASE_SCHEDULER_VIRTUAL", 1);
    define!("CRUCIBLE_FAULT_CLOCK_BASE_RTC_EPOCH", 2);
    define!("CRUCIBLE_FAULT_CLOCK_TIMER_NONE", 0);
    define!("CRUCIBLE_FAULT_CLOCK_TIMER_PROGRAMMABLE", 1);
    define!("CRUCIBLE_FAULT_CLOCK_SOURCE_WRAPS", 1);
    define!("CRUCIBLE_FAULT_CLOCK_SOURCE_READ_ERROR", 2);
    define!("CRUCIBLE_FAULT_CLOCK_ALLOW_BACKWARD", 1);
    define!("CRUCIBLE_FAULT_CLOCK_CLAMP_MONOTONIC", 2);
    define!("CRUCIBLE_FAULT_CLOCK_FAULT_ON_BACKWARD", 3);
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("RESERVED", 12),
        ("ROW_COUNT", 16),
        ("BODY_LENGTH", 20),
        ("BODY_DIGEST", 24),
        ("BODY", 56),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_CLOCK_MANIFEST_{name}_OFFSET {value}"
        );
    }
    for (name, value) in [
        ("SOURCE_KIND", 0),
        ("BASE_DOMAIN", 2),
        ("TIMER_RELATIONSHIP", 4),
        ("RESERVED0", 6),
        ("WIDTH_BITS", 8),
        ("FLAGS", 12),
        ("FREQUENCY_NUMERATOR", 16),
        ("FREQUENCY_DENOMINATOR", 24),
        ("MODEL_PHASE_MASK", 32),
        ("VMSTATE", 40),
        ("MONOTONICITY", 41),
        ("RESERVED1", 42),
        ("ID_LENGTH", 48),
        ("IMPLEMENTATION_LENGTH", 50),
        ("LENGTH", 52),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_CLOCK_ROW_{name}_OFFSET {value}"
        );
    }
    define!(
        "CRUCIBLE_FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES",
        FAULT_REGISTER_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_REGISTER_ROW_HEADER_V1_BYTES",
        FAULT_REGISTER_ROW_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1",
        FAULT_HARDWARE_ERROR_MANIFEST_VERSION_V1
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES",
        FAULT_HARDWARE_ERROR_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES",
        FAULT_HARDWARE_ERROR_ROW_HEADER_V1_BYTES
    );
    for (name, value) in [
        (
            "X86_MACHINE_CHECK",
            FaultHardwareErrorRecordKindV1::X86MachineCheck as u16,
        ),
        (
            "AARCH64_RAS",
            FaultHardwareErrorRecordKindV1::Aarch64Ras as u16,
        ),
        (
            "MEMORY_ECC",
            FaultHardwareErrorRecordKindV1::MemoryEcc as u16,
        ),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_HARDWARE_ERROR_RECORD_{name} {value}"
        );
    }
    for (name, value) in [
        ("CORRECTED", FaultHardwareErrorClassV1::Corrected as u16),
        ("RECOVERABLE", FaultHardwareErrorClassV1::Recoverable as u16),
        ("FATAL", FaultHardwareErrorClassV1::Fatal as u16),
        ("SYNCHRONOUS", FaultHardwareErrorClassV1::Synchronous as u16),
        (
            "ASYNCHRONOUS",
            FaultHardwareErrorClassV1::Asynchronous as u16,
        ),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_HARDWARE_ERROR_CLASS_{name} {value}"
        );
    }
    for (name, value) in [
        ("X86_MCA", FaultHardwareErrorMechanismV1::X86Mca as u16),
        ("ACPI_GHES", FaultHardwareErrorMechanismV1::AcpiGhes as u16),
        (
            "AARCH64_RAS",
            FaultHardwareErrorMechanismV1::Aarch64Ras as u16,
        ),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_HARDWARE_ERROR_MECHANISM_{name} {value}"
        );
    }
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY",
        FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT",
        FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION",
        FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK",
        FAULT_HARDWARE_ERROR_VISIBILITY_V1_MASK
    );
    define!(
        "CRUCIBLE_FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK",
        FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("RESERVED", 12),
        ("ROW_COUNT", 16),
        ("BODY_LENGTH", 20),
        ("BODY_DIGEST", 24),
        ("BODY", 56),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_{name}_OFFSET {value}"
        );
    }
    for (name, value) in [
        ("RECORD_KIND", 0),
        ("ERROR_CLASS", 2),
        ("MECHANISM", 4),
        ("VISIBILITY", 6),
        ("BANK_NUMBER", 8),
        ("BANK_COUNT", 12),
        ("VECTOR", 16),
        ("RESERVED0", 20),
        ("STATUS_REQUIRED", 24),
        ("STATUS_ALLOWED", 32),
        ("SYNDROME_REQUIRED", 40),
        ("SYNDROME_ALLOWED", 48),
        ("MODEL_PHASE_MASK", 56),
        ("PRIVILEGE_MASK", 64),
        ("CORRECTED", 66),
        ("MASKABLE", 67),
        ("VMSTATE", 68),
        ("RESERVED1", 69),
        ("ID_LENGTH", 70),
        ("BANK_LENGTH", 72),
        ("CHANNEL_LENGTH", 74),
        ("RANK_LENGTH", 76),
        ("FIRMWARE_LENGTH", 78),
        ("STATE_LENGTH", 80),
        ("RESERVED2", 82),
        ("LENGTH", 84),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_HARDWARE_ERROR_ROW_{name}_OFFSET {value}"
        );
    }
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
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_MANIFEST_VERSION_V1",
        FAULT_INTERRUPT_MANIFEST_VERSION_V1
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES",
        FAULT_INTERRUPT_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_ROW_HEADER_V1_BYTES",
        FAULT_INTERRUPT_ROW_HEADER_V1_BYTES
    );
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_MAGIC_OFFSET", 0);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_VERSION_OFFSET", 8);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_ARCHITECTURE_OFFSET", 10);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_RESERVED_OFFSET", 12);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_ROW_COUNT_OFFSET", 16);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_BODY_LENGTH_OFFSET", 20);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_BODY_DIGEST_OFFSET", 24);
    define!("CRUCIBLE_FAULT_INTERRUPT_MANIFEST_BODY_OFFSET", 56);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_FAMILY_OFFSET", 0);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_TRIGGER_OFFSET", 2);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_POLARITY_OFFSET", 4);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_DELIVERY_DROP_OFFSET", 6);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_VECTOR_OFFSET", 8);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_REPLACEMENT_START_OFFSET", 12);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_REPLACEMENT_END_OFFSET", 16);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_PRIORITY_OFFSET", 20);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_VMSTATE_OFFSET", 22);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_RESERVED0_OFFSET", 23);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_MODEL_PHASE_MASK_OFFSET", 24);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_TARGET_COUNT_OFFSET", 32);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_ID_LENGTH_OFFSET", 34);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_CONTROLLER_LENGTH_OFFSET", 36);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_SOURCE_LENGTH_OFFSET", 38);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_VERSION_LENGTH_OFFSET", 40);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_RESERVED1_OFFSET", 42);
    define!("CRUCIBLE_FAULT_INTERRUPT_ROW_LENGTH_OFFSET", 44);
    for (name, value) in [
        (
            "X86_LOCAL_APIC_FIXED",
            FaultInterruptFamilyV1::X86LocalApicFixed as u16,
        ),
        ("X86_IPI", FaultInterruptFamilyV1::X86Ipi as u16),
        ("X86_IO_APIC", FaultInterruptFamilyV1::X86IoApic as u16),
        ("X86_PIC", FaultInterruptFamilyV1::X86Pic as u16),
        ("X86_MSI", FaultInterruptFamilyV1::X86Msi as u16),
        ("X86_MSI_X", FaultInterruptFamilyV1::X86MsiX as u16),
        ("X86_NMI", FaultInterruptFamilyV1::X86Nmi as u16),
        ("X86_TIMER", FaultInterruptFamilyV1::X86Timer as u16),
        ("ARM_GIC_SGI", FaultInterruptFamilyV1::ArmGicSgi as u16),
        ("ARM_GIC_PPI", FaultInterruptFamilyV1::ArmGicPpi as u16),
        ("ARM_GIC_SPI", FaultInterruptFamilyV1::ArmGicSpi as u16),
        ("ARM_GIC_LPI", FaultInterruptFamilyV1::ArmGicLpi as u16),
        ("ARM_TIMER", FaultInterruptFamilyV1::ArmTimer as u16),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INTERRUPT_FAMILY_{name} {value}"
        );
    }
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_TRIGGER_EDGE",
        FaultInterruptTriggerV1::Edge as u16
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_TRIGGER_LEVEL",
        FaultInterruptTriggerV1::Level as u16
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_POLARITY_ACTIVE_HIGH",
        FaultInterruptPolarityV1::ActiveHigh as u16
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_POLARITY_ACTIVE_LOW",
        FaultInterruptPolarityV1::ActiveLow as u16
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_DELIVERY_DROP_CONSUME_EDGE",
        FaultInterruptDeliveryDropV1::ConsumeEdge as u16
    );
    define!(
        "CRUCIBLE_FAULT_INTERRUPT_DELIVERY_DROP_REPEND_ASSERTED_LEVEL",
        FaultInterruptDeliveryDropV1::RependAssertedLevel as u16
    );
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
        (
            "CRUCIBLE_FAULT_REGISTER_GROUP_ERROR",
            FaultRegisterGroupV1::Error as u16,
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

fn valid_hardware_identity(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(valid_identity)
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

fn bool_at(bytes: &[u8], offset: usize) -> Result<bool, FaultAbiError> {
    match bytes.get(offset).copied() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(FaultAbiError::CapabilityInvariant),
    }
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

    fn interrupt_row(id: &str, vector: u32) -> FaultInterruptCapabilityRowV1 {
        FaultInterruptCapabilityRowV1 {
            id: id.to_owned(),
            controller: "local-apic".to_owned(),
            source: "lapic-timer".to_owned(),
            controller_version: "qemu-x86-local-apic-v1".to_owned(),
            family: FaultInterruptFamilyV1::X86Timer,
            vector_start: vector,
            vector_end: vector,
            replacement_vector_start: 32,
            replacement_vector_end: 255,
            trigger: FaultInterruptTriggerV1::Edge,
            polarity: FaultInterruptPolarityV1::ActiveHigh,
            target_vcpus: vec![0, 1],
            model_phase_mask: (1 << (23 - 1)) | (1 << (24 - 1)) | (1 << (26 - 1)),
            priority: 128,
            delivery_drop: FaultInterruptDeliveryDropV1::ConsumeEdge,
            vmstate: true,
        }
    }

    fn hardware_row(id: &str, corrected: bool) -> FaultHardwareErrorCapabilityRowV1 {
        FaultHardwareErrorCapabilityRowV1 {
            id: id.to_owned(),
            bank: "x86.mca.bank".to_owned(),
            channel: "x86.memory.channel".to_owned(),
            rank: "x86.memory.rank".to_owned(),
            firmware: "x86-mca".to_owned(),
            state: "x86-mca-bank-record".to_owned(),
            record_kind: FaultHardwareErrorRecordKindV1::X86MachineCheck,
            error_class: if corrected {
                FaultHardwareErrorClassV1::Corrected
            } else {
                FaultHardwareErrorClassV1::Recoverable
            },
            mechanism: FaultHardwareErrorMechanismV1::X86Mca,
            visibility_mask: if corrected {
                FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
            } else {
                FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
            },
            bank_number: 0,
            bank_count: 10,
            vector: 18,
            status_required: 1 << 63,
            status_allowed: u64::MAX,
            syndrome_required: 0,
            syndrome_allowed: u32::MAX.into(),
            model_phase_mask: 1 << (11 - 1),
            privilege_mask: FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
            corrected,
            maskable: false,
            vmstate: true,
        }
    }

    fn complete_x86_hardware_rows() -> Vec<FaultHardwareErrorCapabilityRowV1> {
        let mut fatal = hardware_row("x86.machine-check.fatal", false);
        fatal.error_class = FaultHardwareErrorClassV1::Fatal;
        fatal.status_required |= 1 << 57;
        vec![
            hardware_row("x86.machine-check.corrected", true),
            fatal,
            hardware_row("x86.machine-check.recoverable", false),
        ]
    }

    #[test]
    fn query_codec_rejects_unknown_kinds_and_reserved_bytes() {
        let query = FaultTargetManifestQueryV1 {
            kind: FaultTargetManifestKind::Register,
        };
        let encoded = query.encode();
        assert_eq!(FaultTargetManifestQueryV1::decode(&encoded), Ok(query));
        let interrupt_query = FaultTargetManifestQueryV1 {
            kind: FaultTargetManifestKind::Interrupt,
        };
        assert_eq!(
            FaultTargetManifestQueryV1::decode(&interrupt_query.encode()),
            Ok(interrupt_query)
        );
        let hardware_query = FaultTargetManifestQueryV1 {
            kind: FaultTargetManifestKind::HardwareError,
        };
        assert_eq!(
            FaultTargetManifestQueryV1::decode(&hardware_query.encode()),
            Ok(hardware_query)
        );
        let clock_query = FaultTargetManifestQueryV1 {
            kind: FaultTargetManifestKind::Clock,
        };
        assert_eq!(
            FaultTargetManifestQueryV1::decode(&clock_query.encode()),
            Ok(clock_query)
        );

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
    fn register_manifest_carries_non_writable_rows_without_mutation_hooks() {
        let read_only = FaultRegisterCapabilityRowV1 {
            numeric_id: 1,
            name: "implementation-status".to_owned(),
            width_bits: 8,
            group: FaultRegisterGroupV1::System,
            model_phase_mask: 0,
            side_effects: 0,
            capabilities: FAULT_REGISTER_CAPABILITY_VMSTATE,
            writable_mask: vec![0],
            reserved_mask: vec![0],
            ignored_mask: vec![0],
            read_only_mask: vec![u8::MAX],
        };
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![read_only.clone()],
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("read-only row should encode: {error}"));
        assert_eq!(
            FaultRegisterCapabilityManifestV1::decode(&encoded),
            Ok(manifest)
        );

        let mut incorrectly_mutable = read_only;
        incorrectly_mutable.capabilities |= FAULT_REGISTER_CAPABILITY_IMPULSE;
        assert_eq!(
            FaultRegisterCapabilityManifestV1 {
                architecture: FaultCapabilityScope::X86_64,
                cpu_model: "crucible-x86-64-v1".to_owned(),
                rows: vec![incorrectly_mutable],
            }
            .encode(),
            Err(FaultAbiError::CapabilityInvariant)
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

    #[test]
    fn interrupt_manifest_round_trips_and_rejects_incomplete_controller_semantics() {
        let manifest = FaultInterruptCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![
                interrupt_row("timer-route-a", 48),
                interrupt_row("timer-route-b", 49),
            ],
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("interrupt manifest should encode: {error}"));
        assert_eq!(
            FaultInterruptCapabilityManifestV1::decode(&encoded),
            Ok(manifest.clone())
        );

        let mut wrong_architecture = manifest.clone();
        wrong_architecture.architecture = FaultCapabilityScope::Aarch64;
        assert_eq!(
            wrong_architecture.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut unsorted_targets = manifest.clone();
        unsorted_targets.rows[0].target_vcpus = vec![1, 0];
        assert_eq!(
            unsorted_targets.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut missing_vmstate = manifest.clone();
        missing_vmstate.rows[0].vmstate = false;
        assert_eq!(
            missing_vmstate.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut corrupt = encoded;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            FaultInterruptCapabilityManifestV1::decode(&corrupt),
            Err(FaultAbiError::PayloadDigest)
        );
    }

    #[test]
    fn hardware_error_manifest_round_trips_real_mca_rows() {
        let manifest = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: complete_x86_hardware_rows(),
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("hardware manifest should encode: {error}"));
        assert_eq!(
            FaultHardwareErrorCapabilityManifestV1::decode(&encoded),
            Ok(manifest)
        );

        let empty = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: Vec::new(),
        };
        let encoded_empty = empty
            .encode()
            .unwrap_or_else(|error| panic!("empty realized manifest should encode: {error}"));
        assert_eq!(
            FaultHardwareErrorCapabilityManifestV1::decode(&encoded_empty),
            Ok(empty)
        );
    }

    #[test]
    fn clock_manifest_round_trips_and_rejects_noncanonical_sources() {
        let row = |id: &str| FaultClockCapabilityRowV1 {
            id: id.to_owned(),
            implementation: "target/i386/tcg".to_owned(),
            source_kind: 1,
            base_domain: 1,
            timer_relationship: 0,
            width_bits: 64,
            flags: 0,
            frequency_numerator: 1_000_000_000,
            frequency_denominator: 1,
            model_phase_mask: 1 << (28 - 1),
            vmstate: true,
            monotonicity: 2,
        };
        let manifest = FaultClockCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![row("x86-tsc")],
        };
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
        assert_eq!(
            FaultClockCapabilityManifestV1::decode(&encoded),
            Ok(manifest.clone())
        );

        let mut duplicate = manifest.clone();
        duplicate.rows.push(row("x86-tsc"));
        assert_eq!(duplicate.encode(), Err(FaultAbiError::CapabilityInvariant));
        let mut invalid_monotonicity = manifest;
        invalid_monotonicity.rows[0].monotonicity = 0;
        assert_eq!(
            invalid_monotonicity.encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );
    }

    #[test]
    fn hardware_error_manifest_rejects_partial_or_mismatched_rows() {
        let manifest = |row| FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![row],
        };

        let mut wrong_architecture = hardware_row("x86.machine-check.corrected", true);
        wrong_architecture.mechanism = FaultHardwareErrorMechanismV1::Aarch64Ras;
        assert_eq!(
            manifest(wrong_architecture).encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut wrong_class = hardware_row("x86.machine-check.corrected", true);
        wrong_class.error_class = FaultHardwareErrorClassV1::Synchronous;
        assert_eq!(
            manifest(wrong_class).encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut exception_corrected = hardware_row("x86.machine-check.corrected", true);
        exception_corrected.visibility_mask = FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION;
        assert_eq!(
            manifest(exception_corrected).encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let mut missing_vmstate = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: complete_x86_hardware_rows(),
        };
        missing_vmstate.rows[0].vmstate = false;
        assert!(missing_vmstate.encode().is_ok());

        let mut invalid_mask = hardware_row("x86.machine-check.corrected", true);
        invalid_mask.status_allowed = 0;
        assert_eq!(
            manifest(invalid_mask).encode(),
            Err(FaultAbiError::CapabilityInvariant)
        );

        let unsorted = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![
                hardware_row("x86.machine-check.recoverable", false),
                hardware_row("x86.machine-check.corrected", true),
            ],
        };
        assert_eq!(unsorted.encode(), Err(FaultAbiError::CapabilityInvariant));

        let valid = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: complete_x86_hardware_rows(),
        };
        let mut corrupt = valid
            .encode()
            .unwrap_or_else(|error| panic!("hardware manifest should encode: {error}"));
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            FaultHardwareErrorCapabilityManifestV1::decode(&corrupt),
            Err(FaultAbiError::PayloadDigest)
        );
    }
}
