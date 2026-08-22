//! Fault-event errors and generated C ABI declarations.

use super::*;

/// Invalid event bytes or event transport state.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FaultEventError {
    /// Durable drained-event record version is unsupported.
    #[error("unsupported durable fault-event checkpoint version")]
    CheckpointVersion,
    /// Durable drained-event record framing is invalid.
    #[error("invalid durable fault-event checkpoint length")]
    CheckpointLength,
    /// Durable drained-event record is not in canonical form.
    #[error("noncanonical durable fault-event checkpoint")]
    CheckpointCanonical,
    /// Durable drained-event record allocation was refused.
    #[error("durable fault-event checkpoint allocation failed")]
    CheckpointAllocation,
    /// Event header length is invalid.
    #[error("invalid fault-event header length")]
    HeaderLength,
    /// Event ABI or semantic version is unsupported.
    #[error("unsupported fault-event version")]
    Version,
    /// Command kind cannot produce rule events.
    #[error("invalid fault-event command kind")]
    CommandKind,
    /// Event outcome tag is unknown.
    #[error("unknown fault-event outcome {0}")]
    Outcome(u16),
    /// Reserved bytes are nonzero.
    #[error("nonzero fault-event reserved bytes")]
    Reserved,
    /// A required event invariant is invalid.
    #[error("invalid fault-event invariant")]
    Invariant,
    /// Payload bounds are invalid.
    #[error("invalid fault-event payload bounds")]
    Bounds,
    /// Transport-owned cursor metadata is corrupt.
    #[error("invalid fault-event arena cursor")]
    Cursor,
    /// BLAKE3 payload authentication failed.
    #[error("fault-event payload authentication failed")]
    PayloadDigest,
    /// SHA-256 evidence authentication failed.
    #[error("fault-event evidence authentication failed")]
    EvidenceDigest,
    /// Generic SPSC transport invariant failed.
    #[error(transparent)]
    Transport(#[from] FaultTransportError),
}

pub(crate) fn emit_fault_event_c_header(out: &mut String) {
    writeln!(
        out,
        "#define CRUCIBLE_FAULT_EVENT_HEADER_V1_BYTES {FAULT_EVENT_HEADER_V1_BYTES}u"
    )
    .ok();
    writeln!(
        out,
        "#define CRUCIBLE_FAULT_EVENT_SLOT_V1_BYTES {FAULT_EVENT_SLOT_V1_BYTES}u"
    )
    .ok();
    writeln!(
        out,
        "#define CRUCIBLE_FAULT_EVENT_CAPACITY {DEFAULT_FAULT_EVENT_CAPACITY}u"
    )
    .ok();
    for (name, value) in [
        ("APPLIED", FaultEventOutcomeV1::Applied as u16),
        ("SUPPRESSED", FaultEventOutcomeV1::Suppressed as u16),
        ("CORRECTED", FaultEventOutcomeV1::Corrected as u16),
        ("ERROR", FaultEventOutcomeV1::Error as u16),
        ("PASSED", FaultEventOutcomeV1::Passed as u16),
        ("RECOVERED", FaultEventOutcomeV1::Recovered as u16),
    ] {
        writeln!(out, "#define CRUCIBLE_FAULT_EVENT_OUTCOME_{name} {value}u").ok();
    }
    out.push_str("\ntypedef struct CRUCIBLE_SHMEM_ALIGNED(64) crucible_fault_event_slot_v1 {\n");
    out.push_str("    uint64_t reservation_start;\n");
    out.push_str("    uint64_t payload_start;\n");
    out.push_str("    uint64_t reservation_end;\n");
    out.push_str("    uint8_t header[CRUCIBLE_FAULT_EVENT_HEADER_V1_BYTES];\n");
    out.push_str("    uint8_t reserved[40];\n");
    out.push_str("} crucible_fault_event_slot_v1;\n\n");
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_event_slot_v1) == CRUCIBLE_FAULT_EVENT_SLOT_V1_BYTES, \"fault event slot size\");").ok();
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_event_slot_v1, reservation_start) == {FAULT_EVENT_SLOT_RESERVATION_START_OFFSET}u, \"fault event reservation_start offset\");").ok();
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_event_slot_v1, payload_start) == {FAULT_EVENT_SLOT_PAYLOAD_START_OFFSET}u, \"fault event payload_start offset\");").ok();
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_event_slot_v1, reservation_end) == {FAULT_EVENT_SLOT_RESERVATION_END_OFFSET}u, \"fault event reservation_end offset\");").ok();
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_event_slot_v1, header) == {FAULT_EVENT_SLOT_HEADER_OFFSET}u, \"fault event header offset\");").ok();
    writeln!(out, "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_event_slot_v1, reserved) == {FAULT_EVENT_SLOT_RESERVED_OFFSET}u, \"fault event reserved offset\");\n").ok();
}
