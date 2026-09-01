//! Generated C declarations for the fault command and result ABI.

use super::*;

pub(crate) fn emit_fault_command_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded QEMU fault command/result ABI. */\n");
    define!("CRUCIBLE_FAULT_COMMAND_ABI_MAJOR", FAULT_COMMAND_ABI_MAJOR);
    define!("CRUCIBLE_FAULT_COMMAND_ABI_MINOR", FAULT_COMMAND_ABI_MINOR);
    define!(
        "CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION",
        FAULT_COMMAND_SEMANTIC_VERSION
    );
    define!(
        "CRUCIBLE_FAULT_DEFAULT_PAYLOAD_BYTES",
        DEFAULT_FAULT_PAYLOAD_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARD_PAYLOAD_BYTES",
        HARD_FAULT_PAYLOAD_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_DEFAULT_PAYLOAD_ARENA_BYTES",
        DEFAULT_FAULT_PAYLOAD_ARENA_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_HARD_PAYLOAD_ARENA_BYTES",
        HARD_FAULT_PAYLOAD_ARENA_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_DEFAULT_COMMAND_CAPACITY",
        DEFAULT_FAULT_COMMAND_CAPACITY
    );
    define!(
        "CRUCIBLE_FAULT_HARD_COMMAND_CAPACITY",
        HARD_FAULT_COMMAND_CAPACITY
    );
    define!(
        "CRUCIBLE_FAULT_COMMAND_HEADER_V1_BYTES",
        FAULT_COMMAND_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_RESULT_HEADER_V1_BYTES",
        FAULT_RESULT_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_ROW_V1_BYTES",
        FAULT_CAPABILITY_ROW_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_COMMAND_SLOT_V1_BYTES",
        FAULT_COMMAND_SLOT_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_RESULT_SLOT_V1_BYTES",
        FAULT_RESULT_SLOT_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES",
        FAULT_PAYLOAD_ARENA_HEADER_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_ALL",
        FaultCapabilityScope::All as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_X86_64",
        FaultCapabilityScope::X86_64 as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_AARCH64",
        FaultCapabilityScope::Aarch64 as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_VIRTIO",
        FaultCapabilityScope::Virtio as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_DEVICE",
        FaultCapabilityScope::Device as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_SCOPE_ACCELERATOR",
        FaultCapabilityScope::Accelerator as u16
    );
    define!(
        "CRUCIBLE_FAULT_CAPABILITY_FEATURES_V1_MASK",
        FAULT_CAPABILITY_FEATURES_V1_MASK
    );
    for (name, value) in [
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION",
            FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS",
            FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION",
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_INSTRUCTION",
            FAULT_CAPABILITY_FEATURE_INSTRUCTION,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_INTERRUPT",
            FAULT_CAPABILITY_FEATURE_INTERRUPT,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR",
            FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_VCPU_SERVICE",
            FAULT_CAPABILITY_FEATURE_VCPU_SERVICE,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE",
            FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_GUEST_CLOCK",
            FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_ACCELERATOR",
            FAULT_CAPABILITY_FEATURE_ACCELERATOR,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_FEATURE_VMSTATE",
            FAULT_CAPABILITY_FEATURE_VMSTATE,
        ),
    ] {
        define!(name, value);
    }

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_COMMAND_ABI_MAJOR_OFFSET",
            FAULT_COMMAND_ABI_MAJOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ABI_MINOR_OFFSET",
            FAULT_COMMAND_ABI_MINOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_KIND_OFFSET",
            FAULT_COMMAND_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_FLAGS_OFFSET",
            FAULT_COMMAND_FLAGS_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PHASE_OFFSET",
            FAULT_COMMAND_PHASE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_RESERVED0_OFFSET",
            FAULT_COMMAND_RESERVED0_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION_OFFSET",
            FAULT_COMMAND_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SEQUENCE_OFFSET",
            FAULT_COMMAND_SEQUENCE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_TARGET_NODE_HASH_OFFSET",
            FAULT_COMMAND_TARGET_NODE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_TARGET_ICOUNT_OFFSET",
            FAULT_COMMAND_TARGET_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET",
            FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_BINDING_HASH_OFFSET",
            FAULT_COMMAND_BINDING_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET",
            FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PRECONDITION_HASH_OFFSET",
            FAULT_COMMAND_PRECONDITION_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_HASH_OFFSET",
            FAULT_COMMAND_PAYLOAD_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET",
            FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET",
            FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_RESERVED1_OFFSET",
            FAULT_COMMAND_RESERVED1_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_ABI_MAJOR_OFFSET",
            FAULT_RESULT_ABI_MAJOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_ABI_MINOR_OFFSET",
            FAULT_RESULT_ABI_MINOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_KIND_OFFSET",
            FAULT_RESULT_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_STATUS_OFFSET",
            FAULT_RESULT_STATUS_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SEMANTIC_VERSION_OFFSET",
            FAULT_RESULT_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SEQUENCE_OFFSET",
            FAULT_RESULT_SEQUENCE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_OBSERVED_ICOUNT_OFFSET",
            FAULT_RESULT_OBSERVED_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_APPLIED_ICOUNT_OFFSET",
            FAULT_RESULT_APPLIED_ICOUNT_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_CAPABILITY_VERSION_OFFSET",
            FAULT_RESULT_CAPABILITY_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PHASE_OFFSET",
            FAULT_RESULT_PHASE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_RESERVED0_OFFSET",
            FAULT_RESULT_RESERVED0_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_BEFORE_HASH_OFFSET",
            FAULT_RESULT_BEFORE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_AFTER_HASH_OFFSET",
            FAULT_RESULT_AFTER_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_EVIDENCE_HASH_OFFSET",
            FAULT_RESULT_EVIDENCE_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_HASH_OFFSET",
            FAULT_RESULT_PAYLOAD_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_OFFSET_OFFSET",
            FAULT_RESULT_PAYLOAD_OFFSET_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_PAYLOAD_LENGTH_OFFSET",
            FAULT_RESULT_PAYLOAD_LENGTH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_RESERVED1_OFFSET",
            FAULT_RESULT_RESERVED1_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_KIND_OFFSET",
            FAULT_CAPABILITY_KIND_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_SCOPE_OFFSET",
            FAULT_CAPABILITY_SCOPE_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET",
            FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_PHASE_MASK_OFFSET",
            FAULT_CAPABILITY_PHASE_MASK_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET",
            FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET",
            FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET",
            FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_CAPABILITY_HASH_OFFSET",
            FAULT_CAPABILITY_HASH_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET",
            FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET",
            FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET",
            FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_SLOT_HEADER_OFFSET",
            FAULT_COMMAND_SLOT_HEADER_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_START_OFFSET",
            FAULT_RESULT_SLOT_RESERVATION_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET",
            FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_END_OFFSET",
            FAULT_RESULT_SLOT_RESERVATION_END_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_RESULT_SLOT_HEADER_OFFSET",
            FAULT_RESULT_SLOT_HEADER_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET",
            FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET,
        ),
        (
            "CRUCIBLE_FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET",
            FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_COMMAND_QUERY_CAPABILITIES",
            FaultCommandKind::QueryCapabilities as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE",
            FaultCommandKind::BoundaryProbe as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_QUERY_TARGET_MANIFEST",
            FaultCommandKind::QueryTargetManifest as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE",
            FaultCommandKind::NodeLifecycle as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_NODE_HANG",
            FaultCommandKind::NodeHang as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_SERVICE",
            FaultCommandKind::CpuService as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE",
            FaultCommandKind::CpuVcpuState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_REGISTER_TRANSFORM",
            FaultCommandKind::CpuRegisterTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_INSTRUCTION_TRANSFORM",
            FaultCommandKind::CpuInstructionTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CPU_EXCEPTION",
            FaultCommandKind::CpuException as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION",
            FaultCommandKind::InterruptDisposition as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM",
            FaultCommandKind::InterruptStorm as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_MUTATION",
            FaultCommandKind::MemoryMutation as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_ACCESS_TRANSFORM",
            FaultCommandKind::MemoryAccessTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_ECC_EVENT",
            FaultCommandKind::MemoryEccEvent as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_REGION_STATE",
            FaultCommandKind::MemoryRegionState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_MEMORY_SERVICE",
            FaultCommandKind::MemoryService as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CLOCK_TRANSFORM",
            FaultCommandKind::ClockTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_CLOCK_SOURCE_STATE",
            FaultCommandKind::ClockSourceState as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_LIFECYCLE",
            FaultCommandKind::AcceleratorLifecycle as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_RESULT_TRANSFORM",
            FaultCommandKind::AcceleratorResultTransform as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_MEMORY_EVENT",
            FaultCommandKind::AcceleratorMemoryEvent as u16,
        ),
        (
            "CRUCIBLE_FAULT_COMMAND_ACCELERATOR_SERVICE",
            FaultCommandKind::AcceleratorService as u16,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }

    for (name, value) in [
        (
            "CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY",
            FAULT_COMMAND_FLAG_PREPARE_ONLY,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY",
            FaultBoundaryPhase::NodeBoundary as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_BEFORE_INSTRUCTION",
            FaultBoundaryPhase::BeforeInstruction as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_AFTER_INSTRUCTION",
            FaultBoundaryPhase::AfterInstruction as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_BEFORE_MEMORY_ACCESS",
            FaultBoundaryPhase::BeforeMemoryAccess as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_AFTER_MEMORY_ACCESS",
            FaultBoundaryPhase::AfterMemoryAccess as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_INTERRUPT",
            FaultBoundaryPhase::Interrupt as u16,
        ),
        (
            "CRUCIBLE_FAULT_PHASE_DEVICE",
            FaultBoundaryPhase::Device as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_APPLIED",
            FaultResultStatus::Applied as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_NOT_APPLICABLE",
            FaultResultStatus::NotApplicable as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PRECONDITION_MISMATCH",
            FaultResultStatus::PreconditionMismatch as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INVALID_TARGET",
            FaultResultStatus::InvalidTarget as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INVALID_PHASE",
            FaultResultStatus::InvalidPhase as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_UNSUPPORTED_CAPABILITY",
            FaultResultStatus::UnsupportedCapability as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PAST_BOUNDARY",
            FaultResultStatus::PastBoundary as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_RESOURCE_LIMIT",
            FaultResultStatus::ResourceLimit as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_GUEST_REJECTED",
            FaultResultStatus::GuestRejected as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_INTERNAL_ERROR",
            FaultResultStatus::InternalError as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_MALFORMED_COMMAND",
            FaultResultStatus::MalformedCommand as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_DUPLICATE_SEQUENCE",
            FaultResultStatus::DuplicateSequence as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_AUTHENTICATION_FAILED",
            FaultResultStatus::AuthenticationFailed as u16,
        ),
        (
            "CRUCIBLE_FAULT_STATUS_PREPARED",
            FaultResultStatus::Prepared as u16,
        ),
    ] {
        let _ = writeln!(out, "#define {name} {value}");
    }
    emit_fault_transport_c_header(out);
}
