//! Canonical terminal evidence for a fault-event transport failure.
//!
//! A terminal record replaces the effect-specific payload when QEMU cannot
//! retain that payload or exhausts a closed runtime resource. The enclosing
//! event keeps the original rule identity, while this record authenticates the
//! attempted payload and reports the exact exhausted limit.

use std::fmt::Write as _;

use crate::FaultAbiError;

/// Magic prefix for a queue or payload retention failure.
pub const FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCQFL1";
/// Magic prefix for a closed runtime-resource exhaustion.
pub const FAULT_RESOURCE_TERMINAL_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCLIM1";
/// Exact encoded size of terminal fault evidence.
pub const FAULT_TERMINAL_EVIDENCE_V1_BYTES: usize = 128;

/// Closed cause for replacement of an effect-specific event payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FaultTerminalReasonV1 {
    /// The bounded QEMU event queue had no unreserved slot.
    EventCapacity = 1,
    /// The attempted evidence payload had an invalid bounded length.
    EvidenceLength = 2,
    /// A typed implementation resource reached its configured or hard limit.
    ResourceLimit = 3,
}

/// Closed implementation resource reported by a resource-limit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FaultTerminalResourceV1 {
    /// Retained fault-event slots.
    EventSlots = 1,
    /// Bounded arithmetic-composition work.
    ArithmeticComposition = 2,
    /// A monotonic sequence or occurrence counter.
    MonotonicCounter = 3,
    /// Installed service-model rules.
    ServiceRuleSlots = 4,
    /// Accumulated service-model bytes.
    AccumulatedServiceBytes = 5,
    /// A virtual-time coordinate.
    VirtualTimeCoordinate = 6,
    /// Persistent sparse mutation cells.
    PersistentSparseCells = 7,
    /// Retained exact-evidence bytes.
    ExactEvidenceBytes = 8,
}

/// Canonical proof that an effect event was replaced and execution stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultTerminalEvidenceV1 {
    /// Why the effect-specific payload could not be retained.
    pub reason: FaultTerminalReasonV1,
    /// Queue occupancy including reservations when the failure was detected.
    pub event_occupancy: u32,
    /// Compiled capacity of the QEMU-side event queue.
    pub event_capacity: u32,
    /// Original effect outcome before replacement with a terminal error.
    pub attempted_outcome: u16,
    /// Exact byte length of the attempted effect-specific evidence.
    pub attempted_payload_length: u64,
    /// SHA-256 digest of the attempted effect-specific evidence.
    pub attempted_payload_sha256: [u8; 32],
    /// Exhausted resource, present only for [`FaultTerminalReasonV1::ResourceLimit`].
    pub resource: Option<FaultTerminalResourceV1>,
    /// Resource usage before the rejected increment.
    pub current: u64,
    /// Increment or target requested by the rejected operation.
    pub requested: u64,
    /// Scenario-configured limit.
    pub configured: u64,
    /// Implementation-hard limit.
    pub hard: u64,
}

impl FaultTerminalEvidenceV1 {
    /// Returns whether bytes begin with either terminal evidence magic.
    #[must_use]
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.get(..8).is_some_and(|magic| {
            magic == FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1
                || magic == FAULT_RESOURCE_TERMINAL_EVIDENCE_MAGIC_V1
        })
    }

    /// Decodes and validates an exact terminal evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when the record has an invalid size, magic,
    /// version, tag, reserved byte, or cause/resource combination.
    pub fn decode(bytes: &[u8]) -> Result<Self, FaultAbiError> {
        if bytes.len() != FAULT_TERMINAL_EVIDENCE_V1_BYTES {
            return Err(FaultAbiError::HeaderLength);
        }
        if bytes[22..24]
            .iter()
            .chain(&bytes[68..72])
            .chain(&bytes[104..128])
            .any(|byte| *byte != 0)
        {
            return Err(FaultAbiError::ReservedNonzero);
        }
        if u16_at(bytes, 66)? != 1 {
            return Err(FaultAbiError::Version);
        }
        let reason = match u32_at(bytes, 8)? {
            1 => FaultTerminalReasonV1::EventCapacity,
            2 => FaultTerminalReasonV1::EvidenceLength,
            3 => FaultTerminalReasonV1::ResourceLimit,
            _ => return Err(FaultAbiError::CapabilityInvariant),
        };
        let resource = match u16_at(bytes, 64)? {
            0 => None,
            1 => Some(FaultTerminalResourceV1::EventSlots),
            2 => Some(FaultTerminalResourceV1::ArithmeticComposition),
            3 => Some(FaultTerminalResourceV1::MonotonicCounter),
            4 => Some(FaultTerminalResourceV1::ServiceRuleSlots),
            5 => Some(FaultTerminalResourceV1::AccumulatedServiceBytes),
            6 => Some(FaultTerminalResourceV1::VirtualTimeCoordinate),
            7 => Some(FaultTerminalResourceV1::PersistentSparseCells),
            8 => Some(FaultTerminalResourceV1::ExactEvidenceBytes),
            _ => return Err(FaultAbiError::CapabilityInvariant),
        };
        let resource_magic = bytes[..8] == FAULT_RESOURCE_TERMINAL_EVIDENCE_MAGIC_V1;
        if (reason == FaultTerminalReasonV1::ResourceLimit) != resource_magic
            || resource_magic != resource.is_some()
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let event_occupancy = u32_at(bytes, 12)?;
        let event_capacity = u32_at(bytes, 16)?;
        let attempted_outcome = u16_at(bytes, 20)?;
        if event_capacity < 2
            || !matches!(attempted_outcome, 1..=6)
            || (reason == FaultTerminalReasonV1::EventCapacity
                && event_occupancy < event_capacity.saturating_sub(1))
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(Self {
            reason,
            event_occupancy,
            event_capacity,
            attempted_outcome,
            attempted_payload_length: u64_at(bytes, 24)?,
            attempted_payload_sha256: bytes[32..64]
                .try_into()
                .map_err(|_| FaultAbiError::HeaderLength)?,
            resource,
            current: u64_at(bytes, 72)?,
            requested: u64_at(bytes, 80)?,
            configured: u64_at(bytes, 88)?,
            hard: u64_at(bytes, 96)?,
        })
    }
}

pub(crate) fn emit_fault_terminal_evidence_c_header(out: &mut String) {
    out.push_str("\n/* Canonical terminal fault-event evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1 \"CRUCQFL1\"\n");
    out.push_str("#define CRUCIBLE_FAULT_RESOURCE_TERMINAL_EVIDENCE_MAGIC_V1 \"CRUCLIM1\"\n");
    for (name, value) in [
        ("VERSION_V1", 1),
        ("V1_BYTES", FAULT_TERMINAL_EVIDENCE_V1_BYTES),
        ("MAGIC_OFFSET", 0),
        ("REASON_OFFSET", 8),
        ("EVENT_OCCUPANCY_OFFSET", 12),
        ("EVENT_CAPACITY_OFFSET", 16),
        ("ATTEMPTED_OUTCOME_OFFSET", 20),
        ("ATTEMPTED_PAYLOAD_LENGTH_OFFSET", 24),
        ("ATTEMPTED_PAYLOAD_SHA256_OFFSET", 32),
        ("RESOURCE_OFFSET", 64),
        ("VERSION_OFFSET", 66),
        ("CURRENT_OFFSET", 72),
        ("REQUESTED_OFFSET", 80),
        ("CONFIGURED_OFFSET", 88),
        ("HARD_OFFSET", 96),
        ("RESERVED_OFFSET", 104),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_TERMINAL_EVIDENCE_{name} {value}"
        );
    }
    for (name, value) in [
        (
            "EVENT_CAPACITY",
            FaultTerminalReasonV1::EventCapacity as u32,
        ),
        (
            "EVIDENCE_LENGTH",
            FaultTerminalReasonV1::EvidenceLength as u32,
        ),
        (
            "RESOURCE_LIMIT",
            FaultTerminalReasonV1::ResourceLimit as u32,
        ),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_FAULT_TERMINAL_REASON_{name} {value}");
    }
    for (name, value) in [
        ("EVENT_SLOTS", FaultTerminalResourceV1::EventSlots as u16),
        (
            "ARITHMETIC_COMPOSITION",
            FaultTerminalResourceV1::ArithmeticComposition as u16,
        ),
        (
            "MONOTONIC_COUNTER",
            FaultTerminalResourceV1::MonotonicCounter as u16,
        ),
        (
            "SERVICE_RULE_SLOTS",
            FaultTerminalResourceV1::ServiceRuleSlots as u16,
        ),
        (
            "ACCUMULATED_SERVICE_BYTES",
            FaultTerminalResourceV1::AccumulatedServiceBytes as u16,
        ),
        (
            "VIRTUAL_TIME_COORDINATE",
            FaultTerminalResourceV1::VirtualTimeCoordinate as u16,
        ),
        (
            "PERSISTENT_SPARSE_CELLS",
            FaultTerminalResourceV1::PersistentSparseCells as u16,
        ),
        (
            "EXACT_EVIDENCE_BYTES",
            FaultTerminalResourceV1::ExactEvidenceBytes as u16,
        ),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_TERMINAL_RESOURCE_{name} {value}"
        );
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, FaultAbiError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, FaultAbiError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FaultAbiError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultAbiError::HeaderLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_queue_and_resource_terminal_records() {
        let mut queue = [0_u8; FAULT_TERMINAL_EVIDENCE_V1_BYTES];
        queue[..8].copy_from_slice(&FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1);
        queue[8..12].copy_from_slice(&(FaultTerminalReasonV1::EventCapacity as u32).to_le_bytes());
        queue[12..16].copy_from_slice(&15_u32.to_le_bytes());
        queue[16..20].copy_from_slice(&16_u32.to_le_bytes());
        queue[20..22].copy_from_slice(&1_u16.to_le_bytes());
        queue[24..32].copy_from_slice(&576_u64.to_le_bytes());
        queue[32..64].fill(7);
        queue[66..68].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            FaultTerminalEvidenceV1::decode(&queue)
                .expect("canonical queue terminal evidence")
                .reason,
            FaultTerminalReasonV1::EventCapacity
        );

        let mut resource = queue;
        resource[..8].copy_from_slice(&FAULT_RESOURCE_TERMINAL_EVIDENCE_MAGIC_V1);
        resource[8..12]
            .copy_from_slice(&(FaultTerminalReasonV1::ResourceLimit as u32).to_le_bytes());
        resource[64..66]
            .copy_from_slice(&(FaultTerminalResourceV1::MonotonicCounter as u16).to_le_bytes());
        assert_eq!(
            FaultTerminalEvidenceV1::decode(&resource)
                .expect("canonical resource terminal evidence")
                .resource,
            Some(FaultTerminalResourceV1::MonotonicCounter)
        );
    }

    #[test]
    fn rejects_mismatched_magic_and_resource_kind() {
        let mut bytes = [0_u8; FAULT_TERMINAL_EVIDENCE_V1_BYTES];
        bytes[..8].copy_from_slice(&FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1);
        bytes[8..12].copy_from_slice(&(FaultTerminalReasonV1::ResourceLimit as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&16_u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..66]
            .copy_from_slice(&(FaultTerminalResourceV1::MonotonicCounter as u16).to_le_bytes());
        bytes[66..68].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            FaultTerminalEvidenceV1::decode(&bytes),
            Err(FaultAbiError::CapabilityInvariant)
        );
    }
}
