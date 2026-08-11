/* SPDX-License-Identifier: Apache-2.0 */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define HANG_EVIDENCE_BYTES 192
#define WATCHDOG_TIMEOUT_NANOS 32
#define WATCHDOG_DOWNTIME_NANOS 8

static uint16_t architecture;
static bool finished;
static bool runnable_scope;
static bool initial_time_advance_started;
static uint64_t initial_virtual_time;
static uint8_t *upsert_payload;
static size_t upsert_payload_len;
static uint8_t *remove_payload;
static size_t remove_payload_len;
static struct qemu_plugin_crucible_fault_command command;
static uint64_t activation_deadline;
static uint64_t activation_raw_icount;

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
    g_printerr("Crucible node hang live test failed: %s\n", message);
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

static uint8_t *build_payload(uint16_t operation, size_t *length)
{
    static const uint8_t node_scope[] =
        "CRUCJSN1{\"kind\":\"node\"}";
    static const uint8_t vcpu_scope[] =
        "CRUCJSN1{\"kind\":\"vcpus\",\"parameters\":[1]}";
    static const uint8_t watchdog[] =
        "CRUCJSN1{\"kind\":\"transition_after\",\"parameters\":{"
        "\"boot_policy\":{\"kind\":\"immediate\"},"
        "\"device_state_policy\":\"device_reset\","
        "\"downtime_nanos\":8,\"timeout_nanos\":32,"
        "\"transition\":\"reset\","
        "\"volatile_state_policy\":\"preserve\"}}";
    g_autoptr(GByteArray) bytes = g_byte_array_sized_new(512);
    uint8_t header[CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES] = { 0 };
    uint8_t vcpu_target[4];
    uint8_t scope_kind[4];
    uint8_t recovery_event[32];

    memcpy(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MAGIC_OFFSET, "CRUCNOD1", 8);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_OFFSET,
            CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET,
            CRUCIBLE_FAULT_COMMAND_NODE_HANG);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_OPERATION_OFFSET, operation);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET,
            runnable_scope ? CRUCIBLE_NODE_FAULT_TARGET_VCPU :
                             CRUCIBLE_NODE_FAULT_TARGET_NODE);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET, 10);
    put_u64(header + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET,
            operation == CRUCIBLE_NODE_FAULT_OPERATION_REMOVE ? 8 : 7);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET, 0x51, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET, 0x52, 32);
    memset(header + CRUCIBLE_NODE_FAULT_PAYLOAD_SCHEMA_HASH_OFFSET, 0x53, 32);
    put_u16(header + CRUCIBLE_NODE_FAULT_PAYLOAD_FIELD_COUNT_OFFSET,
            operation == CRUCIBLE_NODE_FAULT_OPERATION_REMOVE ? 0 :
                (runnable_scope ? 5 : 4));
    g_byte_array_append(bytes, header, sizeof(header));
    if (operation == CRUCIBLE_NODE_FAULT_OPERATION_REMOVE) {
        *length = bytes->len;
        return g_byte_array_free(g_steal_pointer(&bytes), false);
    }

    put_u32(scope_kind, runnable_scope ? 2 : 1);
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P1,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                 scope_kind, sizeof(scope_kind));
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P2,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_BYTES,
                 runnable_scope ? vcpu_scope : node_scope,
                 runnable_scope ? sizeof(vcpu_scope) - 1 :
                                  sizeof(node_scope) - 1);
    memset(recovery_event, 0x61, sizeof(recovery_event));
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P3,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_HASH,
                 recovery_event, sizeof(recovery_event));
    append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_P4,
                 CRUCIBLE_NODE_FAULT_FIELD_TYPE_BYTES,
                 watchdog, sizeof(watchdog) - 1);
    if (runnable_scope) {
        put_u32(vcpu_target, 1);
        append_field(bytes, CRUCIBLE_NODE_FAULT_FIELD_T1,
                     CRUCIBLE_NODE_FAULT_FIELD_TYPE_U32,
                     vcpu_target, sizeof(vcpu_target));
    }
    *length = bytes->len;
    return g_byte_array_free(g_steal_pointer(&bytes), false);
}

static void poll_event(uint8_t evidence[HANG_EVIDENCE_BYTES],
                       struct qemu_plugin_crucible_fault_event *event)
{
    size_t evidence_len = 0;

    memset(event, 0, sizeof(*event));
    if (qemu_plugin_crucible_fault_event_poll(
            event, evidence, HANG_EVIDENCE_BYTES, &evidence_len) != 1 ||
        event->command_kind != CRUCIBLE_FAULT_COMMAND_NODE_HANG ||
        event->outcome != CRUCIBLE_FAULT_EVENT_OUTCOME_APPLIED ||
        evidence_len != HANG_EVIDENCE_BYTES) {
        fail("hang event was absent or malformed");
    }
}

static void validate_activation(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t evidence[HANG_EVIDENCE_BYTES];

    poll_event(evidence, &event);
    if (memcmp(evidence, "CRUCHNG1", 8) != 0 ||
        get_u16(evidence + 10) != 1 ||
        get_u32(evidence + 12) != (runnable_scope ? 2 : 1) ||
        get_u64(evidence + 40) - get_u64(evidence + 24) !=
            WATCHDOG_TIMEOUT_NANOS) {
        fail("hang activation evidence was malformed");
    }
    activation_deadline = get_u64(evidence + 40);
    activation_raw_icount = get_u64(evidence + 56);
}

static void validate_watchdog(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t evidence[HANG_EVIDENCE_BYTES];

    poll_event(evidence, &event);
    if (memcmp(evidence, "CRUCLIF1", 8) != 0 ||
        get_u16(evidence + 10) != 3 || get_u32(evidence + 12) != 1 ||
        get_u32(evidence + 16) != 3 || get_u32(evidence + 20) != 1 ||
        get_u64(evidence + 32) != activation_deadline ||
        get_u64(evidence + 40) != WATCHDOG_DOWNTIME_NANOS ||
        event.observed_icount != activation_raw_icount +
            (runnable_scope ? WATCHDOG_TIMEOUT_NANOS : 0)) {
        fail("watchdog reset was not applied at the exact hang deadline");
    }
}

static void validate_recovery(void)
{
    struct qemu_plugin_crucible_fault_event event;
    uint8_t evidence[HANG_EVIDENCE_BYTES];
    size_t unused = 0;

    poll_event(evidence, &event);
    if (memcmp(evidence, "CRUCHNG1", 8) != 0 ||
        get_u16(evidence + 10) != 2 ||
        get_u32(evidence + 12) != (runnable_scope ? 2 : 1) ||
        get_u64(evidence + 24) + WATCHDOG_TIMEOUT_NANOS !=
            activation_deadline) {
        fail("hang recovery evidence was malformed");
    }
    if (qemu_plugin_crucible_fault_event_poll(
            &event, evidence, sizeof(evidence), &unused) != 0) {
        fail("hang lifecycle emitted an unexpected extra event");
    }
}

static void submit_commit(uint64_t sequence, uint64_t target,
                          const uint8_t precondition[32],
                          const uint8_t *payload, size_t payload_len)
{
    command.command_flags = 0;
    command.command_sequence = sequence;
    command.target_icount = target;
    command.authorization_ceiling_icount = target;
    memcpy(command.expected_precondition_hash, precondition, 32);
    if (qemu_plugin_crucible_fault_submit(
            &command, payload, payload_len) != 0) {
        fail("prepared hang transaction commit was rejected");
    }
    qemu_plugin_force_vcpu_exit();
}

static void completion(void *opaque)
{
    struct qemu_plugin_crucible_fault_result result;
    uint8_t result_payload[512];
    size_t result_len = 0;

    (void)opaque;
    memset(&result, 0, sizeof(result));
    if (qemu_plugin_crucible_fault_poll(
            &result, result_payload, sizeof(result_payload), &result_len) != 1 ||
        result.command_kind != CRUCIBLE_FAULT_COMMAND_NODE_HANG) {
        fail("hang command completion was absent or malformed");
    }
    if (result.status == CRUCIBLE_FAULT_STATUS_PREPARED &&
        result.command_sequence == 1) {
        g_printerr("CRUCIBLE_NODE_HANG_STAGE prepared-upsert observed=%" G_GUINT64_FORMAT "\n",
                   result.observed_icount);
        submit_commit(2, result.observed_icount + 16, result.before_hash,
                      upsert_payload, upsert_payload_len);
        return;
    }
    if (result.status == CRUCIBLE_FAULT_STATUS_APPLIED &&
        result.command_sequence == 2) {
        g_printerr("CRUCIBLE_NODE_HANG_STAGE activated observed=%" G_GUINT64_FORMAT "\n",
                   result.observed_icount);
        validate_activation();
        command.command_flags = CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY;
        command.command_sequence = 3;
        command.target_icount = result.observed_icount + 64;
        command.authorization_ceiling_icount = command.target_icount;
        memset(command.expected_precondition_hash, 0, 32);
        if (qemu_plugin_crucible_fault_submit(
                &command, remove_payload, remove_payload_len) != 0) {
            fail("hung QEMU rejected the recovery preparation");
        }
        qemu_plugin_force_vcpu_exit();
        return;
    }
    if (result.status == CRUCIBLE_FAULT_STATUS_PREPARED &&
        result.command_sequence == 3) {
        g_printerr("CRUCIBLE_NODE_HANG_STAGE prepared-recovery observed=%" G_GUINT64_FORMAT "\n",
                   result.observed_icount);
        validate_watchdog();
        submit_commit(4, result.observed_icount + 16, result.before_hash,
                      remove_payload, remove_payload_len);
        return;
    }
    if (result.status != CRUCIBLE_FAULT_STATUS_APPLIED ||
        result.command_sequence != 4) {
        g_printerr("unexpected hang completion: status=%u sequence=%" G_GUINT64_FORMAT
                   " observed=%" G_GUINT64_FORMAT " applied=%" G_GUINT64_FORMAT "\n",
                   result.status, result.command_sequence,
                   result.observed_icount, result.applied_icount);
        fail("hang recovery transaction did not complete");
    }
    validate_recovery();
    g_printerr("CRUCIBLE_NODE_HANG_STAGE recovered observed=%" G_GUINT64_FORMAT "\n",
               result.observed_icount);
    finished = true;
    g_printerr("CRUCIBLE_NODE_HANG_LIVE_PASS architecture=%u\n", architecture);
    qemu_plugin_request_shutdown(0);
}

static void at_exit(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    if (!finished) {
        fail("QEMU exited before hang recovery completed");
    }
    g_free(upsert_payload);
    g_free(remove_payload);
}

static uint64_t parse_architecture(const char *argument)
{
    char *end = NULL;
    uint64_t value;

    if (!g_str_has_prefix(argument, "architecture=")) {
        fail("architecture plugin argument is invalid");
    }
    value = g_ascii_strtoull(argument + strlen("architecture="), &end, 10);
    if (!end || *end != '\0') {
        fail("architecture plugin argument is not numeric");
    }
    return value;
}

static void submit_initial_command(void)
{
    if (qemu_plugin_crucible_fault_submit(
            &command, upsert_payload, upsert_payload_len) != 0) {
        fail("QEMU rejected the hang preparation");
    }
}

static void time_advanced(int status, int64_t time, void *opaque)
{
    (void)opaque;
    if (status != 0 || time < 0 || (uint64_t)time != initial_virtual_time) {
        fail("initial virtual-time bias failed");
    }
    submit_initial_command();
}

static void vcpu_initialized(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    if (!runnable_scope || vcpu_index != 0 ||
        initial_time_advance_started) {
        return;
    }
    initial_time_advance_started = true;
    if (qemu_plugin_advance_time_ns(initial_virtual_time) != 0) {
        fail("runnable hang could not queue virtual-time bias");
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    struct qemu_plugin_crucible_fault_capability capabilities[64];
    size_t count;
    bool found = false;

    (void)info;
    if (argc != 1 && argc != 3) {
        fail("expected architecture or architecture/scope/time arguments");
    }
    architecture = parse_architecture(argv[0]);
    if (argc == 3) {
        char *end = NULL;

        if (strcmp(argv[1], "scope=vcpu1") != 0 ||
            !g_str_has_prefix(argv[2], "initial_virtual_time=")) {
            fail("runnable hang plugin arguments are invalid");
        }
        runnable_scope = true;
        initial_virtual_time = g_ascii_strtoull(
            argv[2] + strlen("initial_virtual_time="), &end, 10);
        if (!end || *end != '\0' || initial_virtual_time == 0 ||
            initial_virtual_time > INT64_MAX) {
            fail("initial virtual time is invalid");
        }
    }
    count = qemu_plugin_crucible_fault_capabilities(
        capabilities, G_N_ELEMENTS(capabilities));
    for (size_t i = 0; i < MIN(count, G_N_ELEMENTS(capabilities)); i++) {
        if (capabilities[i].command_kind ==
                CRUCIBLE_FAULT_COMMAND_NODE_HANG &&
            strcmp(capabilities[i].name, "qemu.node.hang.v1") == 0) {
            found = true;
        }
    }
    if (!found) {
        fail("patched QEMU omitted qemu.node.hang.v1");
    }
    upsert_payload = build_payload(
        CRUCIBLE_NODE_FAULT_OPERATION_UPSERT, &upsert_payload_len);
    remove_payload = build_payload(
        CRUCIBLE_NODE_FAULT_OPERATION_REMOVE, &remove_payload_len);
    memset(&command, 0, sizeof(command));
    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_NODE_HANG;
    command.command_flags = CRUCIBLE_FAULT_COMMAND_FLAG_PREPARE_ONLY;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    command.command_sequence = 1;
    memset(command.target_node_hash, 0x11, 32);
    memset(command.binding_hash, 0x31, 32);
    command.target_icount = 64;
    command.authorization_ceiling_icount = command.target_icount;
    qemu_plugin_register_crucible_fault_completion_cb(completion, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    if (runnable_scope) {
        if (!qemu_plugin_request_time_control() ||
            qemu_plugin_register_time_advance_cb(time_advanced, NULL) != 0) {
            fail("runnable hang could not own virtual-time bias");
        }
        qemu_plugin_register_vcpu_init_cb(id, vcpu_initialized);
    } else {
        submit_initial_command();
    }
    return 0;
}
