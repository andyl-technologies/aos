//! Portable C view of the console layout, generated from codec constants.

use std::fmt::Write;

use crucible_protocol::native_console::*;

/// Generates the exact native-console header paired with the shared-memory ABI.
///
/// Word accesses use fixed-width atomic scalars. Each word represents eight
/// little-endian codec bytes; native clients must encode/decode those bytes
/// explicitly rather than cast a Rust or native object into the mapping.
#[must_use]
pub fn generated_native_console_c_header() -> String {
    let mut out = String::from(
        "/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n\
         /* Draft only: requires the coordinated protocol/profile cutover. */\n\
         #ifndef CRUCIBLE_NATIVE_CONSOLE_DRAFT_H\n\
         #define CRUCIBLE_NATIVE_CONSOLE_DRAFT_H\n\
         #include <stdint.h>\n#include <stddef.h>\n#include <stdatomic.h>\n\n",
    );
    for (name, value) in [
        (
            "REQUIRED_SHMEM_ABI",
            NATIVE_CONSOLE_REQUIRED_SHMEM_ABI as usize,
        ),
        (
            "REQUIRED_CONTROL_VERSION",
            NATIVE_CONSOLE_REQUIRED_CONTROL_VERSION as usize,
        ),
        (
            "REQUIRED_SETUP_SCHEMA",
            NATIVE_CONSOLE_REQUIRED_SETUP_SCHEMA as usize,
        ),
        ("RECORD_BYTES", NATIVE_CONSOLE_RECORD_BYTES),
        ("CAPACITY", NATIVE_CONSOLE_CAPACITY as usize),
        ("CLAMP_BYTES", NATIVE_CONSOLE_CLAMP_BYTES),
        (
            "CLAMP_SCHEMA_VERSION",
            NATIVE_CONSOLE_CLAMP_SCHEMA_VERSION as usize,
        ),
        (
            "CONTROL_KIND_ACCEPTANCE",
            NativeConsoleControlKind::Acceptance as usize,
        ),
        (
            "CONTROL_KIND_OBSERVATION",
            NativeConsoleControlKind::Observation as usize,
        ),
        ("OPERATION_STOP_BYTES", NATIVE_CONSOLE_OPERATION_STOP_BYTES),
        ("SEGMENT_BYTES", super::NATIVE_CONSOLE_SEGMENT_BYTES),
        ("SETUP_HEADER_BYTES", NATIVE_CONSOLE_SETUP_HEADER_BYTES),
        (
            "MAX_ISSUED_AUTHORIZATIONS",
            NATIVE_CONSOLE_MAX_ISSUED_AUTHORIZATIONS as usize,
        ),
        ("MAX_STREAMS", NATIVE_CONSOLE_MAX_STREAMS),
        ("CAPABILITY_BITS", NATIVE_CONSOLE_CAPABILITY_BITS as usize),
        ("PLAN_HEADER_BYTES", NATIVE_CONSOLE_PLAN_HEADER_BYTES),
        ("PLAN_ROW_BYTES", NATIVE_CONSOLE_PLAN_ROW_BYTES),
        ("PHASE_GRANT", NativeConsolePhase::Grant as usize),
        ("PHASE_COLD_SETUP", NativeConsolePhase::ColdSetup as usize),
        ("PHASE_RESTORE", NativeConsolePhase::Restore as usize),
        (
            "PHASE_IDLE_SERVICE",
            NativeConsolePhase::IdleService as usize,
        ),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NATIVE_CONSOLE_{name} {value}u");
    }
    for (kind, fields) in [
        (
            "CLAMP",
            &[
                ("PUBLICATION", 0),
                ("ADVANCE", 16),
                ("REQUEST", 24),
                ("CAPTURE", 28),
                ("FAULT_FRONTIER", 32),
                ("CEILING", 40),
                ("LAST_ISSUED_PRESENT", 48),
                ("STOP", 49),
                ("KIND", 50),
                ("LAST_ISSUED", 64),
            ][..],
        ),
        (
            "OPERATION_STOP",
            &[
                ("PUBLICATION", 0),
                ("MAGIC", 8),
                ("RING_END", 16),
                ("NODE_SEQUENCE", 24),
                ("LOGICAL_PS", 32),
                ("RAW_PREFIX", 40),
                ("AUTHORIZATION", 48),
                ("AUTHORIZATION_ADVANCE", 56),
                ("LOGICAL_GENERATION", 64),
                ("PROCESS", 72),
                ("REGION", 80),
                ("SLOT", 96),
                ("VCPU", 100),
                ("CLOSED_GENERATION", 104),
                ("CONTROL_BOUNDARY_ACK", 108),
                ("STOPPED_ADVANCE", 112),
                ("RESERVED", 120),
            ][..],
        ),
        (
            "RECORD",
            &[
                ("SLOT", 8),
                ("STREAM", 12),
                ("REGION", 16),
                ("PROCESS", 32),
                ("AUTHORIZATION", 40),
                ("LOGICAL_GENERATION", 48),
                ("NODE_SEQUENCE", 56),
                ("STREAM_SEQUENCE", 64),
                ("LOGICAL_PS", 72),
                ("RAW_PREFIX", 80),
                ("AUTHORIZATION_ADVANCE", 88),
                ("VCPU", 96),
                ("PHASE", 100),
                ("BYTE", 101),
            ][..],
        ),
        (
            "AUTH",
            &[
                ("PUBLICATION", 0),
                ("REGION", 8),
                ("PROCESS", 24),
                ("AUTHORIZATION", 32),
                ("LOGICAL_GENERATION", 40),
                ("ADVANCE", 48),
                ("PRIOR_SEQUENCE", 56),
                ("PRIOR_RING_END", 64),
                ("ALLOWANCE", 72),
                ("SLOT", 76),
                ("PHASE_TOKEN", 80),
                ("PHASE", 88),
            ][..],
        ),
        (
            "FRONTIER",
            &[
                ("SEQUENCE", 0),
                ("RING_END", 8),
                ("LOGICAL_PS", 16),
                ("RAW_PREFIX", 24),
                ("AUTHORIZATION", 32),
                ("ACCEPTED_ADVANCE", 40),
                ("LOGICAL_GENERATION", 48),
                ("PROCESS", 56),
                ("REGION", 64),
                ("SLOT", 80),
                ("REQUEST", 84),
                ("PLAN_HASH", 88),
                ("SEALED", 120),
            ][..],
        ),
        (
            "CAPABILITY",
            &[
                ("BITS", 8),
                ("SLOT", 12),
                ("REGION", 16),
                ("PROCESS", 32),
                ("PLAN_HASH", 40),
                ("RESOLVED_STREAMS", 72),
                ("CAPACITY", 104),
                ("STRIDE", 108),
            ][..],
        ),
        (
            "PLAN",
            &[
                ("LENGTH", 12),
                ("SLOT", 16),
                ("STREAM_COUNT", 20),
                ("CAPACITY", 24),
                ("CAPABILITY_VERSION", 28),
                ("LOGICAL_GENERATION", 32),
                ("NODE_SEQUENCE_BASE", 40),
            ][..],
        ),
        (
            "STREAM",
            &[
                ("ID", 0),
                ("DEVICE", 4),
                ("DIRECTION", 6),
                ("DEVICE_IDENTITY", 8),
                ("OWNER_MASK", 40),
                ("SEQUENCE_BASE", 48),
            ][..],
        ),
    ] {
        for (name, offset) in fields {
            let _ = writeln!(
                out,
                "#define CRUCIBLE_NATIVE_CONSOLE_{kind}_{name}_OFFSET {offset}u"
            );
        }
    }
    out.push_str("\n/* Atomic words are storage, not a native-structure wire cast. */\n");
    for (name, alignment) in [
        ("record", 64),
        ("capability", 128),
        ("authorization", 128),
        ("frontier", 128),
        ("operation_stop", 128),
    ] {
        let _ = writeln!(
            out,
            "typedef struct {{ _Alignas({alignment}) _Atomic uint64_t words[16]; }} CrucibleNativeConsole_{name};\n\
             _Static_assert(sizeof(CrucibleNativeConsole_{name}) == 128, \"console {name} size\");\n\
             _Static_assert(_Alignof(CrucibleNativeConsole_{name}) == {alignment}, \"console {name} alignment\");\n\
             _Static_assert(offsetof(CrucibleNativeConsole_{name}, words) == 0, \"console {name} words\");"
        );
    }
    out.push_str(
        "typedef struct { _Alignas(128) _Atomic uint64_t words[32]; } CrucibleNativeConsole_clamp;\n\
         _Static_assert(sizeof(CrucibleNativeConsole_clamp) == 256, \"console clamp size\");\n\
         _Static_assert(_Alignof(CrucibleNativeConsole_clamp) == 128, \"console clamp alignment\");\n\
         _Static_assert(offsetof(CrucibleNativeConsole_clamp, words) == 0, \"console clamp words\");\n\
         \n/* Auth and clamp words must be seqlock-snapshotted. Clamp fields precede\n\
         \x20* the original request Release; matching fields alone confer no phase.\n\
         \x20* Frontier words belong inside\n\
         \x20* the original NodeSlot publication interval before its odd ACK.\n\
         \x20* Decoding a phase label does not confer execution authority. */\n\
         #endif\n",
    );
    out
}
