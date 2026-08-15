/*
 * Live interrupt-controller mutation probe for QEMU Crucible faults.
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

static uint16_t expected_architecture;
static uint32_t mutation;
static uint16_t disposition_model_phase;
static bool disposition_installed;
static bool storm_installed;
static bool saw_disposition_event;
static bool saw_storm_event;
static bool finished;
static uint8_t *disposition_payload;
static size_t disposition_payload_len;
static uint8_t *storm_payload;
static size_t storm_payload_len;
static struct qemu_plugin_crucible_fault_command command;

static void fail(const char *message)
{
    g_printerr("CRUCIBLE_INTERRUPT_MUTATION_LIVE_FAIL: %s\n", message);
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

static void append_payload_header(GByteArray *bytes, uint16_t command_kind,
                                  uint16_t model_phase, uint64_t generation,
                                  uint16_t field_count)
{
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET,
            command_kind);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET,
            CRUCIBLE_NODE_FAULT_OPERATION_UPSERT);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            CRUCIBLE_NODE_FAULT_TARGET_INTERRUPT);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET,
            model_phase);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET,
            generation);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET,
           command_kind, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x52, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x53, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET,
            field_count);
    g_byte_array_append(bytes, header, sizeof(header));
}

static uint8_t *build_disposition_payload(
    const struct qemu_plugin_crucible_fault_interrupt_capability *row,
    uint32_t row_index, uint32_t vector, uint32_t replacement,
    size_t *length)
{
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(384);
    uint8_t controller[32];
    uint8_t source[32];

    crucible_test_identity(controller, 0x21, row_index + 1);
    crucible_test_identity(source, 0x22, row_index + 1);
    append_payload_header(bytes,
                          CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION,
                          disposition_model_phase, 1, 9);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1, mutation);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2,
               mutation == 2 ? 1 : 0);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
               mutation == 3 ? 2 : 0);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4,
               mutation == 3 ? 1 : 0);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P5,
               mutation == 4 ? replacement : 0);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1, controller);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_T2, source);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T3, row->target_vcpus[0]);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T4, vector);
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static uint8_t *build_storm_payload(
    const struct qemu_plugin_crucible_fault_interrupt_capability *row,
    uint32_t row_index, uint32_t vector, size_t *length)
{
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(384);
    g_autofree char *routing = NULL;
    uint8_t controller[32];
    uint8_t source[32];
    uint32_t priority = row->priority;

    if (row->family == 4) {
        priority = vector & 7;
    } else if (row->family == 7) {
        priority = 0;
    } else if (row->family <= 8) {
        priority = vector >> 4;
    }
    routing = g_strdup_printf(
        "{\"priority\":%u,\"retain_pending\":true,\"target_vcpus\":[%u]}",
        priority, row->target_vcpus[0]);
    crucible_test_identity(controller, 0x21, row_index + 1);
    crucible_test_identity(source, 0x22, row_index + 1);
    append_payload_header(bytes, CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM,
                          23, 2, 10);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1, source);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2, vector);
    append_u64(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3, 1);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4, 1);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_P5, 1);
    append_json(bytes, CRUCIBLE_NODE_FAULT_FIELD_P6, routing);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1, controller);
    append_hash(bytes, CRUCIBLE_NODE_FAULT_FIELD_T2, source);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T3, row->target_vcpus[0]);
    append_u32(bytes, CRUCIBLE_NODE_FAULT_FIELD_T4, vector);
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void maybe_finish(void)
{
    if (disposition_installed && storm_installed && saw_storm_event &&
        (expected_architecture == 3 || saw_disposition_event) && !finished) {
        static const char *const names[] = {
            "invalid", "drop", "delay", "duplicate", "replace",
        };

        finished = true;
        g_printerr(
            "CRUCIBLE_INTERRUPT_MUTATION_LIVE_PASS architecture=%u mutation=%s\n",
            expected_architecture,
            expected_architecture == 3 ? "storm" : names[mutation]);
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
        if (!evidence || event.outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
            evidence_len < 8 || memcmp(evidence, "CRUCIRQ1", 8) != 0) {
            fail("interrupt event was unauthenticated or malformed");
        }
        if (event.command_kind ==
            CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION) {
            saw_disposition_event = true;
        } else if (event.command_kind ==
                   CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM) {
            saw_storm_event = true;
        } else {
            fail("unexpected event kind reached the interrupt fixture");
        }
    } while (status == 1);
    maybe_finish();
}

static void submit(uint16_t kind, uint64_t sequence, uint64_t target_icount,
                   uint8_t binding_byte, bool prepare_only,
                   const uint8_t precondition[32],
                   const uint8_t *payload, size_t payload_len)
{
    command.command_kind = kind;
    command.command_flags = prepare_only ?
        CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY : 0;
    command.command_sequence = sequence;
    command.target_icount = target_icount;
    command.authorization_ceiling_icount = target_icount;
    memset(command.binding_hash, binding_byte, 32);
    if (precondition) {
        memcpy(command.expected_precondition_hash, precondition, 32);
    } else {
        memset(command.expected_precondition_hash, 0, 32);
    }
    if (qemu_plugin_crucible_fault_submit(&command, payload, payload_len) != 0) {
        fail("fault command submission was rejected");
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
    if (status != 1) {
        fail("fault command completion was absent");
    }
    if (result.command_sequence == 1 &&
        result.status == CRUCIBLE_FAULT_STATUS_PREPARED) {
        submit(CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION, 2,
               result.observed_icount + 16, 0x61, false,
               result.before_hash, disposition_payload,
               disposition_payload_len);
    } else if (result.command_sequence == 2 &&
               result.status == CRUCIBLE_FAULT_STATUS_APPLIED) {
        disposition_installed = true;
        submit(CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM, 3,
               result.observed_icount + 16, 0x62, true, NULL,
               storm_payload, storm_payload_len);
    } else if (result.command_sequence == 3 &&
               result.status == CRUCIBLE_FAULT_STATUS_PREPARED) {
        submit(CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM, 4,
               result.observed_icount + 16, 0x62, false,
               result.before_hash, storm_payload, storm_payload_len);
    } else if (result.command_sequence == 4 &&
               result.status == CRUCIBLE_FAULT_STATUS_APPLIED) {
        storm_installed = true;
    } else {
        g_printerr("interrupt result status=%u sequence=%" G_GUINT64_FORMAT
                   " kind=%u payload_len=%zu\n",
                   result.status, result.command_sequence,
                   result.command_kind, result_len);
        fail("fault command returned an unexpected transactional result");
    }
    poll_events();
}

static void tcg_exec(unsigned int cpu_index, uint64_t icount, void *opaque)
{
    (void)cpu_index;
    (void)icount;
    (void)opaque;
    poll_events();
}

static void at_exit(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    poll_events();
    if (!finished) {
        g_printerr("interrupt fixture state disposition=%d storm=%d "
                   "disposition_event=%d storm_event=%d\n",
                   disposition_installed, storm_installed,
                   saw_disposition_event, saw_storm_event);
        fail("QEMU exited before the live interrupt mutation was observed");
    }
    g_free(disposition_payload);
    g_free(storm_payload);
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

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    struct qemu_plugin_crucible_fault_capability capabilities[64];
    struct qemu_plugin_crucible_fault_interrupt_capability *rows;
    const struct qemu_plugin_crucible_fault_interrupt_capability *row = NULL;
    const char *binding_error;
    size_t row_count;
    size_t selected = 0;
    uint16_t architecture = 0;
    uint32_t vector;
    uint32_t replacement;
    uint16_t wanted_family;
    size_t capability_count;
    bool saw_control = false;
    bool saw_storm = false;

    if (!info->system_emulation || argc != 2) {
        fail("probe requires system emulation, architecture, and mutation");
    }
    expected_architecture = parse_u64_arg(argv[0], "architecture=");
    mutation = parse_u64_arg(argv[1], "mutation=");
    if ((expected_architecture != 2 && expected_architecture != 3) ||
        mutation < 1 || mutation > 4) {
        fail("architecture or mutation is outside the closed test contract");
    }
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
        saw_control |= capabilities[index].command_kind ==
            CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION;
        saw_storm |= capabilities[index].command_kind ==
            CRUCIBLE_FAULT_COMMAND_INTERRUPT_STORM;
    }
    if (!saw_control || !saw_storm) {
        fail("patched QEMU omitted an interrupt fault capability");
    }
    row_count = qemu_plugin_crucible_fault_interrupt_manifest(
        NULL, 0, &architecture);
    rows = g_new0(
        struct qemu_plugin_crucible_fault_interrupt_capability, row_count);
    if (architecture != expected_architecture || row_count == 0 ||
        qemu_plugin_crucible_fault_interrupt_manifest(
            rows, row_count, &architecture) != row_count) {
        fail("realized interrupt manifest changed during setup");
    }
    wanted_family = expected_architecture == 2 ? 1 : 13;
    disposition_model_phase = expected_architecture == 2 ? 24 : 26;
    for (size_t index = 0; index < row_count; index++) {
        if (rows[index].family == wanted_family &&
            rows[index].target_vcpu_count != 0 &&
            rows[index].vector_start <= rows[index].vector_end &&
            rows[index].replacement_vector_start <=
                rows[index].replacement_vector_end &&
            (rows[index].model_phase_mask &
             (UINT64_C(1) << (disposition_model_phase - 1)))) {
            row = &rows[index];
            selected = index;
            break;
        }
    }
    if (!row) {
        fail("realized primary interrupt controller lacked delivery mutation");
    }
    vector = row->vector_start;
    if (expected_architecture == 3 &&
        row->vector_start <= 27 && row->vector_end >= 27) {
        vector = 27;
    }
    replacement = row->replacement_vector_start;
    if (replacement == vector && replacement < row->replacement_vector_end) {
        replacement++;
    }
    if (mutation == 4 && replacement == vector) {
        fail("realized controller exposed no distinct replacement vector");
    }
    disposition_payload = build_disposition_payload(
        row, selected, vector, replacement, &disposition_payload_len);
    storm_payload = build_storm_payload(
        row, selected, vector, &storm_payload_len);
    g_free(rows);

    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    memset(command.target_node_hash, 0x11, 32);
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    qemu_plugin_register_tcg_exec_cb(tcg_exec, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    submit(CRUCIBLE_FAULT_COMMAND_INTERRUPT_DISPOSITION, 1, 64,
           0x61, true, NULL, disposition_payload,
           disposition_payload_len);
    return 0;
}
