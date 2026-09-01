/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"
#include "phase2-qemu-fault-event-envelope.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define STATE_EVIDENCE_BYTES 192
#define TARGET_VCPU 0

static uint16_t architecture;
static uint64_t sequence = 1;
static uint32_t transition_index;
static bool applying;
static bool finished;
static uint8_t *payload;
static size_t payload_len;
static struct qemu_plugin_crucible_fault_command command;

static const uint32_t old_states[] = { 1, 2, 1, 3 };
static const uint32_t new_states[] = { 2, 1, 3, 1 };
static const uint16_t operations[] = {
    CRUCIBLE_NODE_FAULT_OPERATION_UPSERT,
    CRUCIBLE_NODE_FAULT_OPERATION_REMOVE,
    CRUCIBLE_NODE_FAULT_OPERATION_UPSERT,
    CRUCIBLE_NODE_FAULT_OPERATION_REMOVE,
};

static uint16_t get_u16(const uint8_t *bytes)
{
    return bytes[0] | (uint16_t)bytes[1] << 8;
}

static uint32_t get_u32(const uint8_t *bytes)
{
    return bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t get_u64(const uint8_t *bytes)
{
    return get_u32(bytes) | (uint64_t)get_u32(bytes + 4) << 32;
}

static void put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = value;
    bytes[1] = value >> 8;
}

static void put_u32(uint8_t *bytes, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); i++) {
        bytes[i] = value >> (8 * i);
    }
}

static void put_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); i++) {
        bytes[i] = value >> (8 * i);
    }
}

static void fail(const char *message)
{
    g_printerr("Crucible vCPU state live test failed: %s\n", message);
    abort();
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

static uint8_t *build_payload(uint16_t operation, uint32_t state,
                              size_t *length)
{
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(256);
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };
    uint8_t target[4];
    uint8_t state_bytes[4];
    uint8_t has_recovery = state != 1;
    uint8_t recovery[32] = { 0 };

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET,
            CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET, operation);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            CRUCIBLE_NODE_FAULT_TARGET_VCPU);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET, 9);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET,
            transition_index + 1);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET,
           transition_index < 2 ? 0x41 : 0x42, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x32, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x33, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET,
            operation == CRUCIBLE_NODE_FAULT_OPERATION_REMOVE ? 0 : 4);
    g_byte_array_append(bytes, header, sizeof(header));

    if (operation != CRUCIBLE_NODE_FAULT_OPERATION_REMOVE) {
        if (has_recovery) {
            memset(recovery, 0x52, sizeof(recovery));
        }
        put_u32(state_bytes, state);
        append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1,
                     CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                     state_bytes, sizeof(state_bytes));
        append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2,
                     CRUCIBLE_NODE_FAULT_FIELD_TYPE_BOOL,
                     &has_recovery, sizeof(has_recovery));
        append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
                     CRUCIBLE_NODE_FAULT_FIELD_TYPE_HASH,
                     recovery, sizeof(recovery));
        put_u32(target, TARGET_VCPU);
        append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1,
                     CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                     target, sizeof(target));
    }
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void poll_transition_event(void)
{
    struct qemu_plugin_crucible_fault_event event = { 0 };
    uint8_t envelope[CRUCIBLE_TEST_EVENT_ENVELOPE_BUFFER_BYTES];
    const uint8_t *evidence;
    size_t envelope_len = 0;
    size_t evidence_len;
    int status = qemu_plugin_crucible_fault_event_poll(
        &event, envelope, sizeof(envelope), &envelope_len);

    if (status != 1) {
        fail("state transition event was absent");
    }
    evidence = crucible_test_event_evidence(
        &event, envelope, envelope_len, &evidence_len);
    if (!evidence ||
        event.command_kind != CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE ||
        event.outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
        evidence_len != STATE_EVIDENCE_BYTES ||
        memcmp(evidence, "CRUCVST1", 8) != 0 ||
        get_u16(evidence + 8) != 1 ||
        get_u16(evidence + 10) != operations[transition_index] ||
        get_u32(evidence + 12) != TARGET_VCPU ||
        get_u32(evidence + 16) != old_states[transition_index] ||
        get_u32(evidence + 20) != new_states[transition_index] ||
        get_u64(evidence + 24) != event.observed_icount ||
        memcmp(evidence + 160, command.binding_hash, 32) != 0) {
        fail("state transition evidence was malformed");
    }
    memset(&event, 0, sizeof(event));
    envelope_len = 0;
    if (qemu_plugin_crucible_fault_event_poll(
            &event, envelope, sizeof(envelope), &envelope_len) != 0) {
        fail("state transition emitted duplicate evidence");
    }
}

static void submit_prepare(uint64_t target_icount)
{
    g_free(payload);
    payload = build_payload(operations[transition_index],
                            new_states[transition_index], &payload_len);
    command.command_flags = CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY;
    command.command_sequence = sequence++;
    command.target_icount = target_icount;
    command.authorization_ceiling_icount = target_icount;
    memset(command.expected_precondition_hash, 0, 32);
    applying = false;
    if (qemu_plugin_crucible_fault_submit(
            &command, payload, payload_len) != 0) {
        fail("state transition preparation was rejected");
    }
    qemu_plugin_force_vcpu_exit();
}

static void completion(void *opaque)
{
    struct qemu_plugin_crucible_fault_result result = { 0 };
    uint8_t result_payload[256];
    size_t result_len = 0;
    int status;

    (void)opaque;
    status = qemu_plugin_crucible_fault_poll(
        &result, result_payload, sizeof(result_payload), &result_len);
    if (status != 1 ||
        result.command_kind != CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE) {
        fail("state command completion was absent or malformed");
    }
    if (!applying && result.status == CRUCIBLE_FAULT_STATUS_PREPARED) {
        command.command_flags = 0;
        command.command_sequence = sequence++;
        command.target_icount = result.observed_icount;
        command.authorization_ceiling_icount = result.observed_icount;
        memcpy(command.expected_precondition_hash, result.before_hash, 32);
        applying = true;
        if (qemu_plugin_crucible_fault_submit(
                &command, payload, payload_len) != 0) {
            fail("prepared state transition commit was rejected");
        }
        qemu_plugin_force_vcpu_exit();
        return;
    }
    if (!applying || result.status != CRUCIBLE_FAULT_STATUS_APPLIED) {
        g_printerr("state result: applying=%d status=%u sequence=%" G_GUINT64_FORMAT
                   " expected_transition=%u observed=%" G_GUINT64_FORMAT
                   " applied=%" G_GUINT64_FORMAT " result_len=%zu request_len=%zu\n",
                   applying, result.status, result.command_sequence,
                   transition_index, result.observed_icount,
                   result.applied_icount, result_len, payload_len);
        fail("state command returned an unexpected transactional result");
    }

    poll_transition_event();
    transition_index++;
    if (transition_index == G_N_ELEMENTS(old_states)) {
        finished = true;
        g_printerr("CRUCIBLE_VCPU_STATE_LIVE_PASS architecture=%u transitions=online-offline-online-stalled-online evidence=CRUCVST1\n",
                   architecture);
        qemu_plugin_request_shutdown(0);
        return;
    }
    submit_prepare(result.observed_icount);
}

static void at_exit(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    if (!finished) {
        fail("QEMU exited before the state trajectory completed");
    }
    g_free(payload);
}

static uint16_t parse_architecture(const char *argument)
{
    char *end = NULL;
    uint64_t value;

    if (!g_str_has_prefix(argument, "architecture=")) {
        fail("architecture argument was absent");
    }
    value = g_ascii_strtoull(argument + strlen("architecture="), &end, 10);
    if (!end || *end != '\0' ||
        value < QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_X86_64 ||
        value > QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_AARCH64) {
        fail("architecture argument is invalid");
    }
    return value;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    struct qemu_plugin_crucible_fault_capability capabilities[64];
    size_t count;
    bool found = false;

    (void)info;
    if (argc != 1) {
        fail("expected exactly one architecture argument");
    }
    architecture = parse_architecture(argv[0]);
    count = qemu_plugin_crucible_fault_capabilities(
        capabilities, G_N_ELEMENTS(capabilities));
    if (count > G_N_ELEMENTS(capabilities)) {
        fail("capability manifest exceeded the fixture bound");
    }
    for (size_t i = 0; i < count; i++) {
        if (capabilities[i].command_kind ==
                CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE &&
            capabilities[i].semantic_version ==
                CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION &&
            strcmp(capabilities[i].name, "qemu.cpu.vcpu-state.v1") == 0) {
            found = true;
        }
    }
    if (!found) {
        fail("patched QEMU omitted qemu.cpu.vcpu-state.v1");
    }

    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_CPU_VCPU_STATE;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    memset(command.target_node_hash, 0x11, 32);
    memset(command.binding_hash, 0x21, 32);
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    submit_prepare(64);
    return 0;
}
