/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define SERVICE_EVIDENCE_BYTES 192

static uint64_t numerator;
static uint64_t denominator;
static uint64_t quantum;
static uint64_t wanted_windows;
static uint64_t observed_windows;
static uint64_t expected_remainder;
static uint16_t architecture;
static bool rule_installed;
static bool finished;
static uint8_t *payload;
static size_t payload_len;
static struct qemu_plugin_crucible_fault_command command;

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
    g_printerr("Crucible vCPU service live test failed: %s\n", message);
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

static uint8_t *build_payload(size_t *length)
{
    static const uint8_t selected_vcpus[] = "CRUCJSN1[0]";
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(256);
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };
    uint8_t ratio[16];
    uint8_t quantum_bytes[8];
    uint8_t discipline[4];

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET,
            CRUCIBLE_FAULT_COMMAND_CPU_SERVICE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET,
            CRUCIBLE_NODE_FAULT_OPERATION_UPSERT);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            CRUCIBLE_NODE_FAULT_TARGET_NODE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET, 10);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET, 1);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET, 0x31, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x32, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x33, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET, 4);
    g_byte_array_append(bytes, header, sizeof(header));

    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_BYTES,
                 selected_vcpus, sizeof(selected_vcpus) - 1);
    put_u64(ratio, numerator);
    put_u64(ratio + 8, denominator);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_RATIO,
                 ratio, sizeof(ratio));
    put_u64(quantum_bytes, quantum);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U64,
                 quantum_bytes, sizeof(quantum_bytes));
    put_u32(discipline, 2);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 discipline, sizeof(discipline));
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void validate_window(const struct qemu_plugin_crucible_fault_event *event,
                            const uint8_t *evidence, size_t evidence_len)
{
    __uint128_t scaled = (__uint128_t)quantum * numerator + expected_remainder;
    uint64_t credit = scaled / denominator;
    uint64_t next_remainder = scaled % denominator;
    uint64_t virtual_before;
    uint64_t virtual_after;

    if (event->command_kind != CRUCIBLE_FAULT_COMMAND_CPU_SERVICE ||
        event->outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
        evidence_len != SERVICE_EVIDENCE_BYTES ||
        memcmp(evidence, "CRUCVCS1", 8) != 0 ||
        get_u32(evidence + 8) != 0 ||
        get_u64(evidence + 16) != observed_windows + 1 ||
        get_u64(evidence + 24) != numerator ||
        get_u64(evidence + 32) != denominator ||
        get_u64(evidence + 40) != quantum ||
        get_u64(evidence + 48) != expected_remainder ||
        get_u64(evidence + 56) != next_remainder ||
        get_u64(evidence + 64) != credit ||
        get_u64(evidence + 72) != credit ||
        get_u64(evidence + 80) != quantum - credit ||
        get_u32(evidence + 120) != 1 ||
        get_u32(evidence + 124) != 1 ||
        get_u64(evidence + 128) != credit ||
        get_u64(evidence + 136) != 0 ||
        get_u64(evidence + 144) != 0 ||
        get_u32(evidence + 184) != 0 ||
        get_u32(evidence + 188) != 0) {
        fail("service-window evidence does not match the exact credit model");
    }
    virtual_before = get_u64(evidence + 88);
    virtual_after = get_u64(evidence + 96);
    if (virtual_after < virtual_before ||
        virtual_after - virtual_before != quantum - credit) {
        fail("denied service was not translated to exact shift-zero virtual time");
    }
    expected_remainder = next_remainder;
    observed_windows++;
}

static void poll_events(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t evidence[SERVICE_EVIDENCE_BYTES];
    size_t evidence_len;
    int status;

    do {
        memset(&event, 0, sizeof(event));
        evidence_len = 0;
        status = qemu_plugin_crucible_fault_event_poll(
            &event, evidence, sizeof(evidence), &evidence_len);
        if (status < 0) {
            fail("event polling failed");
        }
        if (status == 1) {
            validate_window(&event, evidence, evidence_len);
        }
    } while (status == 1);

    if (rule_installed && observed_windows == wanted_windows && !finished) {
        finished = true;
        g_printerr("CRUCIBLE_VCPU_SERVICE_LIVE_PASS architecture=%u ratio=%" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT " quantum=%" G_GUINT64_FORMAT " windows=%" G_GUINT64_FORMAT "\n",
                   architecture, numerator, denominator, quantum,
                   observed_windows);
        qemu_plugin_request_shutdown(0);
    }
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
    if (status != 1 || result.command_kind != CRUCIBLE_FAULT_COMMAND_CPU_SERVICE) {
        fail("service command completion was absent or malformed");
    }
    if (result.status == CRUCIBLE_FAULT_STATUS_PREPARED &&
        result.command_sequence == 1) {
        command.command_flags = 0;
        command.command_sequence = 2;
        command.target_icount = result.observed_icount + 16;
        command.authorization_ceiling_icount = command.target_icount;
        memcpy(command.expected_precondition_hash, result.before_hash, 32);
        if (qemu_plugin_crucible_fault_submit(
                &command, payload, payload_len) != 0) {
            fail("prepared service commit was rejected");
        }
        qemu_plugin_force_vcpu_exit();
    } else if (result.status == CRUCIBLE_FAULT_STATUS_APPLIED &&
               result.command_sequence == 2) {
        rule_installed = true;
    } else {
        fail("service command returned an unexpected transactional result");
    }
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
        fail("QEMU exited before the requested live service trajectory completed");
    }
    g_free(payload);
}

static uint64_t parse_u64_arg(const char *argument, const char *prefix)
{
    char *end = NULL;
    uint64_t value;

    if (!g_str_has_prefix(argument, prefix)) {
        fail("plugin argument order or name is invalid");
    }
    value = g_ascii_strtoull(argument + strlen(prefix), &end, 10);
    if (!end || *end != '\0' || value == 0) {
        fail("plugin argument is not a positive integer");
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
    if (argc != 5) {
        fail("expected architecture, numerator, denominator, quantum, and windows");
    }
    architecture = parse_u64_arg(argv[0], "architecture=");
    numerator = parse_u64_arg(argv[1], "numerator=");
    denominator = parse_u64_arg(argv[2], "denominator=");
    quantum = parse_u64_arg(argv[3], "quantum=");
    wanted_windows = parse_u64_arg(argv[4], "windows=");
    if (architecture < QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_X86_64 ||
        architecture > QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_AARCH64 ||
        numerator > denominator) {
        fail("architecture or ratio is outside the test contract");
    }
    count = qemu_plugin_crucible_fault_capabilities(
        capabilities, G_N_ELEMENTS(capabilities));
    if (count > G_N_ELEMENTS(capabilities)) {
        fail("capability manifest exceeded the live fixture bound");
    }
    for (size_t i = 0; i < count; i++) {
        if (capabilities[i].command_kind == CRUCIBLE_FAULT_COMMAND_CPU_SERVICE &&
            capabilities[i].semantic_version ==
                CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION &&
            strcmp(capabilities[i].name, "qemu.cpu.service.v1") == 0) {
            found = true;
        }
    }
    if (!found) {
        fail("patched QEMU omitted qemu.cpu.service.v1");
    }

    payload = build_payload(&payload_len);
    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_CPU_SERVICE;
    command.command_flags = CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    command.command_sequence = 1;
    memset(command.target_node_hash, 0x11, 32);
    memset(command.binding_hash, 0x21, 32);
    command.target_icount = 64;
    command.authorization_ceiling_icount = command.target_icount;
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    qemu_plugin_register_tcg_exec_cb(tcg_exec, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    if (qemu_plugin_crucible_fault_submit(&command, payload, payload_len) != 0) {
        fail("QEMU rejected the service preparation");
    }
    return 0;
}
