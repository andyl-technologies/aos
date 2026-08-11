/* SPDX-License-Identifier: Apache-2.0 */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define LIFECYCLE_EVIDENCE_BYTES 288

static uint16_t architecture;
static uint32_t volatile_policy;
static uint32_t device_policy;
static bool require_ready;
static bool ready_observed;
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
    g_printerr("Crucible node lifecycle live test failed: %s\n", message);
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
    const char *boot_policy = require_ready ?
        "CRUCJSN1{\"kind\":\"require_ready\",\"parameters\":{\"exhausted\":\"permanent_failure\",\"maximum_attempts\":2,\"ready_marker\":\"guest-ready\",\"retry_delay_nanos\":4096}}" :
        "CRUCJSN1{\"kind\":\"immediate\"}";
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(256);
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };
    uint8_t transition[4];
    uint8_t downtime[8];
    uint8_t volatile_state[4];
    uint8_t device_state[4];

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET,
            CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET,
            CRUCIBLE_NODE_FAULT_OPERATION_APPLY);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            CRUCIBLE_NODE_FAULT_TARGET_NODE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET, 10);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET, 1);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET, 0x41, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x42, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x43, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET, 5);
    g_byte_array_append(bytes, header, sizeof(header));

    put_u32(transition, 3);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 transition, sizeof(transition));
    put_u64(downtime, 32);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U64,
                 downtime, sizeof(downtime));
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_BYTES,
                 boot_policy, strlen(boot_policy));
    put_u32(volatile_state, volatile_policy);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 volatile_state, sizeof(volatile_state));
    put_u32(device_state, device_policy);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P5,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 device_state, sizeof(device_state));
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void validate_event(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t evidence[LIFECYCLE_EVIDENCE_BYTES];
    size_t evidence_len = 0;
    int status;

    memset(&event, 0, sizeof(event));
    status = qemu_plugin_crucible_fault_event_poll(
        &event, evidence, sizeof(evidence), &evidence_len);
    if (status != 1 ||
        event.command_kind != CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE ||
        event.outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
        evidence_len != sizeof(evidence) ||
        memcmp(evidence, "CRUCLIF1", 8) != 0 ||
        get_u16(evidence + 8) != 3 ||
        get_u16(evidence + 10) != 3 ||
        get_u32(evidence + 12) != volatile_policy ||
        get_u32(evidence + 16) != device_policy ||
        get_u32(evidence + 20) !=
            ((volatile_policy == 1 ? 1U : 0U) |
             (device_policy == 1 ? 2U : 0U)) ||
        get_u64(evidence + 40) != 32 ||
        get_u64(evidence + 96) - get_u64(evidence + 32) != 32 ||
        get_u64(evidence + 48) == 0 || get_u64(evidence + 56) == 0 ||
        get_u64(evidence + 112) == 0 || get_u64(evidence + 120) == 0) {
        fail("reset event or lifecycle evidence was absent or malformed");
    }
    if (get_u32(evidence + 192) != (require_ready ? 2U : 1U) ||
        get_u32(evidence + 196) != 1 ||
        get_u32(evidence + 200) != (require_ready ? 2U : 1U) ||
        get_u64(evidence + 208) != (require_ready ? 4096U : 0U) ||
        (require_ready && get_u64(evidence + 216) == UINT64_MAX)) {
        fail("boot policy evidence was absent or malformed");
    }
    for (size_t index = 256; index < sizeof(evidence); index++) {
        if (evidence[index] != 0) {
            fail("nonterminal reset published a terminal pre-exit fingerprint");
        }
    }
    if ((volatile_policy == 1 && get_u64(evidence + 104) != 0) ||
        (volatile_policy == 2 && get_u64(evidence + 104) == 0)) {
        fail("volatile-state policy did not control writable RAM treatment");
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
    if (status != 1 ||
        result.command_kind != CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE) {
        fail("lifecycle command completion was absent or malformed");
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
            fail("prepared lifecycle commit was rejected");
        }
        qemu_plugin_force_vcpu_exit();
        return;
    }
    if (result.status != CRUCIBLE_FAULT_STATUS_APPLIED ||
        result.command_sequence != 2 ||
        result.applied_icount < result.observed_icount ||
        (require_ready && !ready_observed)) {
        fail("reset did not complete through the deferred command path");
    }
    validate_event();
    finished = true;
    g_printerr("CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS architecture=%u volatile_policy=%u device_policy=%u\n",
               architecture, volatile_policy, device_policy);
    qemu_plugin_request_shutdown(0);
}

static void ready_tb_exec(unsigned int vcpu_index, void *opaque)
{
    int status;

    (void)vcpu_index;
    (void)opaque;
    if (!require_ready || ready_observed) {
        return;
    }
    ready_observed = true;
    status = qemu_plugin_crucible_fault_ready_marker(
        "guest-ready", strlen("guest-ready"), qemu_plugin_icount_raw());
    if (status < 0) {
        fail("QEMU rejected a live guest ready-marker observation");
    }
    if (status == 0) {
        ready_observed = false;
    }
}

static void ready_tb_translate(qemu_plugin_id_t id,
                               struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, ready_tb_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

static void at_exit(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    if (!finished) {
        fail("QEMU exited before the reset completion was observed");
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
    if (argc != 3 && argc != 4) {
        fail("expected architecture, state policies, and optional boot policy");
    }
    architecture = parse_u64_arg(argv[0], "architecture=");
    volatile_policy = parse_u64_arg(argv[1], "volatile_policy=");
    device_policy = parse_u64_arg(argv[2], "device_policy=");
    if (argc == 4) {
        if (strcmp(argv[3], "boot_policy=require_ready") != 0) {
            fail("optional boot policy is invalid");
        }
        require_ready = true;
        qemu_plugin_register_vcpu_tb_trans_cb(id, ready_tb_translate);
    }
    if (architecture < QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_X86_64 ||
        architecture > QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_AARCH64 ||
        volatile_policy > 2 || device_policy > 3) {
        fail("architecture or state policy is outside the test contract");
    }
    count = qemu_plugin_crucible_fault_capabilities(
        capabilities, G_N_ELEMENTS(capabilities));
    if (count > G_N_ELEMENTS(capabilities)) {
        fail("capability manifest exceeded the live fixture bound");
    }
    for (size_t i = 0; i < count; i++) {
        if (capabilities[i].command_kind ==
                CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE &&
            capabilities[i].semantic_version ==
                CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION &&
            strcmp(capabilities[i].name, "qemu.node.lifecycle.v1") == 0) {
            found = true;
        }
    }
    if (!found) {
        fail("patched QEMU omitted qemu.node.lifecycle.v1");
    }

    payload = build_payload(&payload_len);
    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE;
    command.command_flags = CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    command.command_sequence = 1;
    memset(command.target_node_hash, 0x11, 32);
    memset(command.binding_hash, 0x21, 32);
    command.target_icount = 64;
    command.authorization_ceiling_icount = command.target_icount;
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    if (qemu_plugin_crucible_fault_submit(&command, payload, payload_len) != 0) {
        fail("QEMU rejected the lifecycle preparation");
    }
    return 0;
}
