//! Generated C declarations for realized QEMU target manifests.

use super::*;

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
    out.push_str("#define CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_MAGIC_V1 \"CRUCACM1\"\n");
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
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_ACCELERATOR",
        FaultTargetManifestKind::Accelerator as u16
    );
    define!(
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_SYSTEM",
        FaultTargetManifestKind::System as u16
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
    define!(
        "CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_VERSION_V1",
        FAULT_ACCELERATOR_MANIFEST_VERSION_V1
    );
    define!(
        "CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES",
        FAULT_ACCELERATOR_MANIFEST_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES",
        FAULT_ACCELERATOR_ROW_HEADER_V1_BYTES
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
