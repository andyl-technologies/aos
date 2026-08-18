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

fn array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FaultAbiError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(FaultAbiError::HeaderLength)?
        .try_into()
        .map_err(|_| FaultAbiError::HeaderLength)
}

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
/// Magic prefix for an accelerator-device capability manifest.
pub const FAULT_ACCELERATOR_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCACM1";
/// Accelerator-device manifest codec version.
pub const FAULT_ACCELERATOR_MANIFEST_VERSION_V1: u16 = 1;
/// Fixed accelerator manifest header length.
pub const FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES: usize = 56;
/// Fixed accelerator row header length before its identities.
pub const FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES: usize = 64;
/// Magic prefix for the final QEMU fault-system manifest.
pub const FAULT_SYSTEM_MANIFEST_MAGIC_V1: [u8; 8] = *b"CRUCFSM1";
/// Fault-system manifest codec version.
pub const FAULT_SYSTEM_MANIFEST_VERSION_V1: u16 = 1;
/// Exact encoded length of the fixed fault-system manifest.
pub const FAULT_SYSTEM_MANIFEST_V1_BYTES: usize = 160;
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
    /// Realized accelerator devices, queues, jobs, memory, and fault support.
    Accelerator = 5,
    /// Complete QEMU build, patch-series, shared-memory, and VMState identity.
    System = 6,
}

impl FaultTargetManifestKind {
    fn decode(value: u16) -> Result<Self, FaultAbiError> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Interrupt),
            3 => Ok(Self::HardwareError),
            4 => Ok(Self::Clock),
            5 => Ok(Self::Accelerator),
            6 => Ok(Self::System),
            _ => Err(FaultAbiError::CapabilityInvariant),
        }
    }
}

/// Final, immutable identity of one realized QEMU fault system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultSystemCapabilityManifestV1 {
    /// Semantic version of the complete fault system.
    pub semantic_version: u32,
    /// Aggregate fault VMState format version.
    pub vmstate_format_version: u32,
    /// Exact number of registered VMState sections.
    pub vmstate_section_count: u32,
    /// SHA-256 of ordered NUL-terminated section names and big-endian versions.
    pub vmstate_sections_sha256: [u8; 32],
    /// Immutable emulator package build identity.
    pub emulator_build_id: [u8; 32],
    /// SHA-256 identity of the ordered carried emulator patch bytes.
    pub emulator_patch_series_hash: [u8; 32],
    /// SHA-256 identity of the generated shared-memory ABI header.
    pub shmem_header_hash: [u8; 32],
}

impl FaultSystemCapabilityManifestV1 {
    /// Encodes the fixed, canonical fault-system identity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] if a version, section count, or digest is invalid.
    pub fn encode(self) -> Result<[u8; FAULT_SYSTEM_MANIFEST_V1_BYTES], FaultAbiError> {
        if self.semantic_version != 1
            || self.vmstate_format_version != 1
            || !(9..=10).contains(&self.vmstate_section_count)
            || [
                self.vmstate_sections_sha256,
                self.emulator_build_id,
                self.emulator_patch_series_hash,
                self.shmem_header_hash,
            ]
            .contains(&[0; 32])
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let mut output = [0_u8; FAULT_SYSTEM_MANIFEST_V1_BYTES];
        output[..8].copy_from_slice(&FAULT_SYSTEM_MANIFEST_MAGIC_V1);
        output[8..10].copy_from_slice(&FAULT_SYSTEM_MANIFEST_VERSION_V1.to_le_bytes());
        output[12..16].copy_from_slice(&(FAULT_SYSTEM_MANIFEST_V1_BYTES as u32).to_le_bytes());
        output[16..20].copy_from_slice(&self.semantic_version.to_le_bytes());
        output[20..24].copy_from_slice(&self.vmstate_format_version.to_le_bytes());
        output[24..28].copy_from_slice(&self.vmstate_section_count.to_le_bytes());
        output[32..64].copy_from_slice(&self.vmstate_sections_sha256);
        output[64..96].copy_from_slice(&self.emulator_build_id);
        output[96..128].copy_from_slice(&self.emulator_patch_series_hash);
        output[128..160].copy_from_slice(&self.shmem_header_hash);
        Ok(output)
    }

    /// Decodes and validates the fixed fault-system identity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] for malformed framing, reserved bytes, or identity fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_SYSTEM_MANIFEST_V1_BYTES
            || bytes[..8] != FAULT_SYSTEM_MANIFEST_MAGIC_V1
            || u16_at(bytes, 8)? != FAULT_SYSTEM_MANIFEST_VERSION_V1
            || u16_at(bytes, 10)? != 0
            || u32_at(bytes, 12)? != FAULT_SYSTEM_MANIFEST_V1_BYTES as u32
            || u32_at(bytes, 28)? != 0
        {
            return Err(FaultAbiError::HeaderLength);
        }
        let manifest = Self {
            semantic_version: u32_at(bytes, 16)?,
            vmstate_format_version: u32_at(bytes, 20)?,
            vmstate_section_count: u32_at(bytes, 24)?,
            vmstate_sections_sha256: array_32(bytes, 32)?,
            emulator_build_id: array_32(bytes, 64)?,
            emulator_patch_series_hash: array_32(bytes, 96)?,
            shmem_header_hash: array_32(bytes, 128)?,
        };
        manifest.encode()?;
        Ok(manifest)
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

#[path = "fault_target_manifest/accelerator.rs"]
mod accelerator;
#[path = "fault_target_manifest/c_header.rs"]
mod c_header;
#[path = "fault_target_manifest/clock.rs"]
mod clock;
#[path = "fault_target_manifest/hardware.rs"]
mod hardware;
#[path = "fault_target_manifest/helpers.rs"]
mod helpers;
#[path = "fault_target_manifest/interrupt.rs"]
mod interrupt;
#[path = "fault_target_manifest/register.rs"]
mod register;

pub use accelerator::*;
pub(crate) use c_header::emit_fault_target_manifest_c_header;
pub use clock::*;
pub use hardware::*;
use helpers::*;
pub use interrupt::*;
pub use register::*;

#[cfg(test)]
#[path = "fault_target_manifest_test.rs"]
mod tests;
