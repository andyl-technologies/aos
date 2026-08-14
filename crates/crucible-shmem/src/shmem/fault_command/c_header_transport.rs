//! Generated C transport structs and nested fault-payload declarations.

use super::*;

pub(super) fn emit_fault_transport_c_header(out: &mut String) {
    out.push_str(
        r#"
typedef struct CRUCIBLE_SHMEM_ALIGNED(64) crucible_fault_command_slot_v1 {
    uint64_t reservation_start;
    uint64_t payload_start;
    uint64_t reservation_end;
    uint8_t header[CRUCIBLE_FAULT_COMMAND_HEADER_V1_BYTES];
    uint8_t reserved[16];
} crucible_fault_command_slot_v1;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_command_slot_v1) == CRUCIBLE_FAULT_COMMAND_SLOT_V1_BYTES, "crucible_fault_command_slot_v1 size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_command_slot_v1) == 64, "crucible_fault_command_slot_v1 alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, reservation_start) == CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET, "crucible_fault_command_slot_v1.reservation_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, payload_start) == CRUCIBLE_FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET, "crucible_fault_command_slot_v1.payload_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, reservation_end) == CRUCIBLE_FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET, "crucible_fault_command_slot_v1.reservation_end offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_command_slot_v1, header) == CRUCIBLE_FAULT_COMMAND_SLOT_HEADER_OFFSET, "crucible_fault_command_slot_v1.header offset");

typedef struct CRUCIBLE_SHMEM_ALIGNED(64) crucible_fault_result_slot_v1 {
    uint64_t reservation_start;
    uint64_t payload_start;
    uint64_t reservation_end;
    uint8_t header[CRUCIBLE_FAULT_RESULT_HEADER_V1_BYTES];
    uint8_t reserved[44];
} crucible_fault_result_slot_v1;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_result_slot_v1) == CRUCIBLE_FAULT_RESULT_SLOT_V1_BYTES, "crucible_fault_result_slot_v1 size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_result_slot_v1) == 64, "crucible_fault_result_slot_v1 alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, reservation_start) == CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_START_OFFSET, "crucible_fault_result_slot_v1.reservation_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, payload_start) == CRUCIBLE_FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET, "crucible_fault_result_slot_v1.payload_start offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, reservation_end) == CRUCIBLE_FAULT_RESULT_SLOT_RESERVATION_END_OFFSET, "crucible_fault_result_slot_v1.reservation_end offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_result_slot_v1, header) == CRUCIBLE_FAULT_RESULT_SLOT_HEADER_OFFSET, "crucible_fault_result_slot_v1.header offset");

typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_fault_payload_arena_header {
    _Atomic uint64_t read_cursor;
    uint8_t pad_read[56];
    _Atomic uint64_t write_cursor;
    uint8_t pad_write[56];
} crucible_fault_payload_arena_header;

CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_payload_arena_header) == CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, "crucible_fault_payload_arena_header size");
CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_payload_arena_header) == 128, "crucible_fault_payload_arena_header alignment");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_payload_arena_header, read_cursor) == CRUCIBLE_FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET, "crucible_fault_payload_arena_header.read_cursor offset");
CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof(crucible_fault_payload_arena_header, write_cursor) == CRUCIBLE_FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET, "crucible_fault_payload_arena_header.write_cursor offset");

/* Headers and rows are byte arrays; use the offsets above with explicit little-endian loads/stores. */
"#,
    );
    crate::fault_memory::emit_memory_fault_c_header(out);
    crate::fault_memory_batch::emit_memory_batch_c_header(out);
    crate::fault_memory_evidence::emit_memory_evidence_c_header(out);
}
