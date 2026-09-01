//! Generated C declarations for instruction-fault evidence.

use super::*;

pub(crate) fn emit_fault_instruction_evidence_c_header(out: &mut String) {
    macro_rules! define {
        ($name:expr, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }

    out.push_str("\n/* Byte-encoded canonical instruction-fault evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_MAGIC_V1 \"CRUCIEV1\"\n");
    define!("CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES",
        FAULT_INSTRUCTION_EVIDENCE_HEADER_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("MUTATION_KIND", 12),
        ("REPLAY_ORDINAL", 16),
        ("REPLAY_TOTAL", 20),
        ("OPCODE_CLASS", 24),
        ("FLAGS", 28),
        ("PC", 32),
        ("PHYSICAL_ADDRESS", 40),
        ("OBSERVED_ICOUNT", 48),
        ("INSTRUCTION_LENGTH", 56),
        ("DETAIL_LENGTH", 60),
        ("INSTRUCTION_SHA256", 64),
        ("BEFORE_STATE_SHA256", 96),
        ("AFTER_STATE_SHA256", 128),
        ("VCPU_INDEX", 160),
        ("DESTINATION_COUNT", 164),
        ("DESTINATIONS", 168),
        ("DECODE_RESERVED", 184),
        ("MANIFEST_SHA256", 192),
        ("CODE_PAGE_SHA256", 224),
        ("BEFORE_RAM_SHA256", 288),
        ("AFTER_RAM_SHA256", 320),
        ("BEFORE_DEVICE_SHA256", 352),
        ("AFTER_DEVICE_SHA256", 384),
        ("BEFORE_CPU_SHA256", 416),
        ("AFTER_CPU_SHA256", 448),
        ("BEFORE_RAM_BYTES", 480),
        ("AFTER_RAM_BYTES", 488),
        ("BEFORE_DEVICE_BYTES", 496),
        ("AFTER_DEVICE_BYTES", 504),
        ("CODE_PAGE_BASES", 512),
        ("CODE_PAGE_COUNT", 528),
        ("HAS_INPUT_STATE_SHA256", 532),
        ("INPUT_STATE_SHA256", 536),
        ("MATCHED_INPUT_STATE_SHA256", 568),
        ("OUTCOME", 600),
        ("RESERVED", 604),
        ("VALUES", 608),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_{name}_OFFSET {value}"
        );
    }
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_EVIDENCE_DECODE_RESERVED_BYTES",
        8
    );
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_RESULT_CORRUPT", 1);
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_SKIP", 2);
    define!("CRUCIBLE_FAULT_INSTRUCTION_MUTATION_REPLAY", 3);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_APPLIED", 1);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_SUPPRESSED", 2);
    define!("CRUCIBLE_FAULT_INSTRUCTION_OUTCOME_ERROR", 4);

    out.push_str("\n/* Canonical x86 port-I/O transcript nested in replay evidence. */\n");
    out.push_str("#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_MAGIC_V1 \"CRUCIOP1\"\n");
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_HEADER_V1_BYTES",
        FAULT_INSTRUCTION_PORT_IO_EVIDENCE_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_ENTRY_V1_BYTES",
        FAULT_INSTRUCTION_PORT_IO_EVIDENCE_ENTRY_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ENTRY_BYTES", 10),
        ("ENTRY_COUNT", 12),
        ("VALUE_BYTES", 16),
        ("RESERVED", 20),
        ("TRANSCRIPT_SHA256", 24),
        ("ENTRIES", 56),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_{name}_OFFSET {value}"
        );
    }
    for (name, value) in [
        ("DIRECTION", 0),
        ("VALUE_SIZE", 1),
        ("COMPLETED", 2),
        ("RESERVED0", 3),
        ("PORT", 4),
        ("VALUE", 8),
        ("RESERVED1", 12),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_ENTRY_{name}_OFFSET {value}"
        );
    }
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_DIRECTION_READ", 0);
    define!("CRUCIBLE_FAULT_INSTRUCTION_PORT_IO_DIRECTION_WRITE", 1);

    out.push_str("\n/* Byte-encoded canonical delivered-exception evidence ABI. */\n");
    out.push_str("#define CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_MAGIC_V1 \"CRUCEEV1\"\n");
    define!("CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_VERSION_V1", 1);
    define!(
        "CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_V1_BYTES",
        FAULT_EXCEPTION_EVIDENCE_V1_BYTES
    );
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("ARCHITECTURE", 10),
        ("MODEL_PHASE", 12),
        ("RESERVED0", 14),
        ("VCPU_INDEX", 16),
        ("REQUESTED_VECTOR", 20),
        ("REQUESTED_SYNDROME", 24),
        ("REQUESTED_FAULT_ADDRESS", 32),
        ("COMMAND_ICOUNT", 40),
        ("HAS_FAULT_ADDRESS", 48),
        ("BEFORE_INSTRUCTION", 49),
        ("RESERVED1", 50),
        ("DELIVERED", 51),
        ("RESERVED2", 52),
        ("DELIVERED_ICOUNT", 56),
        ("ENTRY_PC", 64),
        ("DELIVERED_VECTOR", 72),
        ("DELIVERED_HAS_FAULT_ADDRESS", 76),
        ("RESERVED3", 77),
        ("DELIVERED_SYNDROME", 80),
        ("DELIVERED_FAULT_ADDRESS", 88),
        ("BEFORE_SHA256", 96),
        ("AFTER_SHA256", 128),
        ("RESERVED4", 160),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_FAULT_EXCEPTION_EVIDENCE_{name}_OFFSET {value}"
        );
    }
}
