/*
 * Live architecture-error and ECC mutation probe for QEMU Crucible faults.
 *
 * Copyright (c) 2026 ANDYL Technologies
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"
#include "phase2-qemu-fault-event-envelope.h"
#include "phase2-qemu-fault-manifest-bindings.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum probe_mode {
    PROBE_ECC,
    PROBE_ARCHITECTURE,
};

static uint16_t architecture;
static enum probe_mode mode;
static uint16_t command_kind;
static bool result_applied;
static bool event_observed;
static bool finished;
static bool initialized;
static bool command_submitted;
static GByteArray *guest_ready;
static uint8_t *payload;
static size_t payload_len;
static struct qemu_plugin_crucible_fault_command command;

static void fail(const char *message)
{
    g_printerr("CRUCIBLE_HARDWARE_ERROR_MUTATION_LIVE_FAIL: %s\n", message);
    abort();
}

static void put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = value;
    bytes[1] = value >> 8;
}

static void put_u32(uint8_t *bytes, uint32_t value)
{
    for (size_t index = 0; index < sizeof(value); index++) {
        bytes[index] = value >> (8 * index);
    }
}

static void put_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0; index < sizeof(value); index++) {
        bytes[index] = value >> (8 * index);
    }
}

static void append_field(GByteArray *bytes, uint16_t tag, uint16_t type,
                         const void *value, uint32_t length)
{
    uint8_t header[CRUCIBLE_NODE_FAULT_FIELD_HEADER_V1_BYTES] = { 0 };

    put_u16(header + CRUCIBLE_NODE_FAULT_FIELD_TAG_OFFSET, tag);
    put_u16(header + CRUCIBLE_NODE_FAULT_FIELD_TYPE_OFFSET, type);
    put_u32(header + CRUCIBLE_NODE_FAULT_FIELD_LENGTH_OFFSET, length);
    g_byte_array_append(bytes, header, sizeof(header));
    g_byte_array_append(bytes, value, length);
}

static void append_u32(GByteArray *bytes, uint16_t tag, uint32_t value)
{
    uint8_t encoded[4];

    put_u32(encoded, value);
    append_field(bytes, tag, CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 encoded, sizeof(encoded));
}

static void append_u64(GByteArray *bytes, uint16_t tag, uint64_t value)
{
    uint8_t encoded[8];

    put_u64(encoded, value);
    append_field(bytes, tag, CRUCIBLE_NODE_FAULT_FIELD_TYPE_U64,
                 encoded, sizeof(encoded));
}

static void append_bool(GByteArray *bytes, uint16_t tag, bool value)
{
    uint8_t encoded = value;

    append_field(bytes, tag, CRUCIBLE_NODE_FAULT_FIELD_TYPE_BOOL,
                 &encoded, sizeof(encoded));
}

static void append_hash(GByteArray *bytes, uint16_t tag,
                        const uint8_t value[32])
{
    append_field(bytes, tag, CRUCIBLE_NODE_FAULT_FIELD_TYPE_HASH, value, 32);
}

static void append_json(GByteArray *bytes, uint16_t tag, const char *json)
{
    g_autoptr(GByteArray) encoded = g_byte_array_new();

    g_byte_array_append(encoded,
                        (const uint8_t *)CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1,
                        CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1_BYTES);
    g_byte_array_append(encoded, (const uint8_t *)json, strlen(json));
    append_field(bytes, tag, CRUCIBLE_NODE_FAULT_FIELD_TYPE_BYTES,
                 encoded->data, encoded->len);
}

static void append_header(GByteArray *bytes, uint16_t kind,
                          uint16_t target_kind, uint16_t model_phase,
                          uint16_t field_count)
{
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET, kind);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET,
            CRUCIBLE_NODE_FAULT_OPERATION_APPLY);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            target_kind);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET,
            model_phase);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET, 1);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET, kind, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x72, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x73, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET,
            field_count);
    g_byte_array_append(bytes, header, sizeof(header));
}

static uint8_t *build_ecc_payload(
    const struct qemu_plugin_crucible_fault_hardware_error_capability *row,
    uint32_t row_index, uint64_t address, size_t *length)
{
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(512);
    static const char visibility[] = "{\"kind\":\"telemetry_only\"}";
    uint8_t bank[32];
    uint8_t channel[32];
    uint8_t rank[32];
    uint8_t address_space[32];

    crucible_test_identity(bank, 0x31, row_index + 1);
    crucible_test_identity(channel, 0x32, row_index + 1);
    crucible_test_identity(rank, 0x33, row_index + 1);
    memset(address_space, 0x11, sizeof(address_space));
    append_header(bytes, CRUCIBLE_FAULT_COMMAND_MEMORY_ECC_EVENT,
                  CRUCIBLE_NODE_FAULT_TARGET_MEMORY, 9, 13);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1, 1);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2, address);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
               row->syndrome_required == 0 ? 0x100 : row->syndrome_required);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4, bank);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_P5, channel);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_P6, rank);
    append_json(bytes, CRUCIBLE_NODE_FAULT_FIELD_P7, visibility);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P8, 0);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1, address_space);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_T2, address);
    append_bool(bytes, CRUCIBLE_NODE_FAULT_FIELD_T3, false);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T4, 0);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_T5, 1);
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static char *architecture_exception_json(
    const struct qemu_plugin_crucible_fault_hardware_error_capability *row)
{
    if (architecture == 2) {
        uint64_t status = row->status_required | (UINT64_C(1) << 60);

        return g_strdup_printf(
            "{\"architecture\":\"x86_64\",\"before_instruction\":true,"
            "\"fault_address\":null,\"maskable\":false,\"record\":{"
            "\"kind\":\"x86_machine_check\",\"parameters\":{"
            "\"address\":null,\"bank\":%u,\"corrected\":false,"
            "\"global_status\":4,\"misc\":null,\"status\":%" G_GUINT64_FORMAT
            "}},\"syndrome\":0,\"vector\":18}",
            row->bank_number, status);
    }

    return g_strdup(
        "{\"architecture\":\"aarch64\",\"before_instruction\":true,"
        "\"fault_address\":1075838976,\"maskable\":false,\"record\":{"
        "\"kind\":\"aarch64_ras\",\"parameters\":{"
        "\"asynchronous\":false,\"corrected\":false,\"disr\":null,"
        "\"esr\":2483027984,\"far\":1075838976,\"fatal\":false}},"
        "\"syndrome\":2483027984,\"vector\":3}");
}

static uint8_t *build_architecture_payload(
    const struct qemu_plugin_crucible_fault_hardware_error_capability *row,
    size_t *length)
{
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(512);
    g_autofree char *exception = architecture_exception_json(row);

    append_header(bytes, CRUCIBLE_FAULT_COMMAND_CPU_EXCEPTION,
                  CRUCIBLE_NODE_FAULT_TARGET_VCPU, 11, 2);
    append_json(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1, exception);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1, 0);
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void maybe_finish(void)
{
    if (result_applied && event_observed && !finished) {
        finished = true;
        g_printerr(
            "CRUCIBLE_HARDWARE_ERROR_MUTATION_LIVE_PASS architecture=%u mode=%s\n",
            architecture, mode == PROBE_ECC ? "corrected-ecc" :
                                              (architecture == 2 ? "x86-mca" :
                                                                   "aarch64-ras"));
        qemu_plugin_request_shutdown(0);
    }
}

static void poll_events(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t envelope[CRUCIBLE_TEST_EVENT_ENVELOPE_BUFFER_BYTES];
    size_t envelope_len;
    size_t evidence_len;
    const uint8_t *evidence;
    int status;

    do {
        memset(&event, 0, sizeof(event));
        envelope_len = 0;
        status = qemu_plugin_crucible_fault_event_poll(
            &event, envelope, sizeof(envelope), &envelope_len);
        if (status < 0) {
            fail("event polling failed");
        }
        if (status != 1) {
            continue;
        }
        evidence = crucible_test_event_evidence(
            &event, envelope, envelope_len, &evidence_len);
        if (!evidence || event.command_kind != command_kind ||
            event.outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
            evidence_len < 8 ||
            (mode == PROBE_ECC ? memcmp(evidence, "CRUCHWE1", 8) != 0 :
                                 memcmp(evidence, "CRUCEXC1", 8) != 0)) {
            fail("hardware-error event was unauthenticated or malformed");
        }
        event_observed = true;
    } while (status == 1);
    maybe_finish();
}

static void submit(uint64_t sequence, uint64_t target_icount,
                   bool prepare_only, const uint8_t precondition[32])
{
    command.command_flags = prepare_only ?
        CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY : 0;
    command.command_sequence = sequence;
    command.target_icount = target_icount;
    command.authorization_ceiling_icount = target_icount;
    if (precondition) {
        memcpy(command.expected_precondition_hash, precondition, 32);
    } else {
        memset(command.expected_precondition_hash, 0, 32);
    }
    if (qemu_plugin_crucible_fault_submit(&command, payload, payload_len) != 0) {
        fail("hardware-error command submission was rejected");
    }
    qemu_plugin_force_vcpu_exit();
}

static void completion(void *opaque)
{
    struct qemu_plugin_crucible_fault_result result;
    uint8_t result_payload[256];
    size_t result_len = 0;
    int status;

    (void)opaque;
    memset(&result, 0, sizeof(result));
    status = qemu_plugin_crucible_fault_poll(
        &result, result_payload, sizeof(result_payload), &result_len);
    if (status != 1 || result.command_kind != command_kind) {
        fail("hardware-error command completion was absent or malformed");
    }
    if (result.command_sequence == 1 &&
        result.status == CRUCIBLE_FAULT_STATUS_PREPARED) {
        submit(2, result.observed_icount + 16, false, result.before_hash);
    } else if (result.command_sequence == 2 &&
               result.status == CRUCIBLE_FAULT_STATUS_APPLIED) {
        result_applied = true;
    } else {
        g_printerr("hardware result status=%u sequence=%" G_GUINT64_FORMAT
                   " kind=%u payload_len=%zu\n",
                   result.status, result.command_sequence,
                   result.command_kind, result_len);
        fail("hardware-error command returned an unexpected result");
    }
    poll_events();
}

static void tcg_exec(unsigned int cpu_index, uint64_t icount, void *opaque)
{
    (void)cpu_index;
    (void)opaque;
    if (initialized && !command_submitted) {
        uint64_t ready_address = architecture == 2 ? 0x102001 : 0x40300001;

        if (!qemu_plugin_read_memory_vaddr(ready_address, guest_ready, 1) ||
            guest_ready->data[0] != 0x5a) {
            return;
        }
        command_submitted = true;
        submit(1, icount + 64, true, NULL);
    }
    poll_events();
}

static void at_exit(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    poll_events();
    if (!finished) {
        g_printerr("hardware fixture state result=%d event=%d\n",
                   result_applied, event_observed);
        fail("QEMU exited before the hardware mutation was observed");
    }
    g_free(payload);
    g_byte_array_unref(guest_ready);
}

static uint64_t parse_u64_arg(const char *argument, const char *prefix)
{
    char *end = NULL;
    uint64_t value;

    if (!g_str_has_prefix(argument, prefix)) {
        fail("plugin argument order or name is invalid");
    }
    value = g_ascii_strtoull(argument + strlen(prefix), &end, 10);
    if (!end || *end != '\0') {
        fail("plugin argument is not an integer");
    }
    return value;
}

static void initialize_hardware(void)
{
    struct qemu_plugin_crucible_fault_capability capabilities[64];
    struct qemu_plugin_crucible_fault_hardware_error_capability *rows;
    const struct qemu_plugin_crucible_fault_hardware_error_capability *row = NULL;
    const char *binding_error;
    size_t capability_count;
    size_t row_count;
    size_t selected = 0;
    bool requested_capability = false;
    uint16_t manifest_architecture = 0;
    uint64_t address;

    if (initialized) {
        return;
    }
    initialized = true;
    binding_error = crucible_test_bind_all_fault_manifests();
    if (binding_error) {
        fail(binding_error);
    }
    capability_count = qemu_plugin_crucible_fault_capabilities(
        capabilities, G_N_ELEMENTS(capabilities));
    if (capability_count > G_N_ELEMENTS(capabilities)) {
        fail("fault capability manifest exceeded the fixture bound");
    }
    for (size_t index = 0; index < capability_count; index++) {
        if (capabilities[index].command_kind == command_kind) {
            requested_capability = true;
            break;
        }
    }
    if (!requested_capability) {
        fail("patched QEMU omitted the requested hardware capability");
    }
    row_count = qemu_plugin_crucible_fault_hardware_error_manifest(
        NULL, 0, &manifest_architecture);
    rows = g_new0(
        struct qemu_plugin_crucible_fault_hardware_error_capability, row_count);
    if (manifest_architecture != architecture || row_count == 0 ||
        qemu_plugin_crucible_fault_hardware_error_manifest(
            rows, row_count, &manifest_architecture) != row_count) {
        fail("realized hardware-error manifest changed during setup");
    }
    for (size_t index = 0; index < row_count; index++) {
        bool matches = mode == PROBE_ECC ?
            rows[index].record_kind == 3 && rows[index].corrected :
            (architecture == 2 ?
                 rows[index].record_kind == 1 && rows[index].error_class == 2 :
                 rows[index].record_kind == 2 && rows[index].error_class == 4);

        if (matches) {
            row = &rows[index];
            selected = index;
            break;
        }
    }
    if (!row) {
        fail("realized machine omitted the requested hardware-error row");
    }
    address = architecture == 2 ? 0x1000 : 0x40200000;
    payload = mode == PROBE_ECC ?
        build_ecc_payload(row, selected, address, &payload_len) :
        build_architecture_payload(row, &payload_len);
    g_free(rows);

    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = command_kind;
    command.phase = mode == PROBE_ECC ?
        CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY :
        CRUCIBLE_FAULT_PHASE_BEFORE_INSTRUCTION;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    memset(command.target_node_hash, 0x11, 32);
    memset(command.binding_hash, 0x71, 32);
}

static void vcpu_initialized(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    if (vcpu_index == 0) {
        initialize_hardware();
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (!info->system_emulation || argc != 2 ||
        !g_str_has_prefix(argv[1], "mode=")) {
        fail("probe requires system emulation, architecture, and mode");
    }
    architecture = parse_u64_arg(argv[0], "architecture=");
    if (architecture != 2 && architecture != 3) {
        fail("architecture is outside the closed test contract");
    }
    if (strcmp(argv[1], "mode=ecc") == 0) {
        mode = PROBE_ECC;
        command_kind = CRUCIBLE_FAULT_COMMAND_MEMORY_ECC_EVENT;
    } else if (strcmp(argv[1], "mode=architecture") == 0) {
        mode = PROBE_ARCHITECTURE;
        command_kind = CRUCIBLE_FAULT_COMMAND_CPU_EXCEPTION;
    } else {
        fail("mode is outside the closed test contract");
    }
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    guest_ready = g_byte_array_new();
    qemu_plugin_register_tcg_exec_cb(tcg_exec, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_initialized);
    return 0;
}
