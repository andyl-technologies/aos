/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const uint64_t snapshot_icount = 1024;
static const uint64_t command_icount = 4096;
static const uint64_t proof_icount = 5120;
static bool save_mode;
static bool stopped;
static unsigned int result_count;

static void fail(const char *message)
{
    g_printerr("Crucible fault VMState live test failed: %s\n", message);
    abort();
}

static bool digest_is_nonzero(const uint8_t digest[32])
{
    uint8_t combined = 0;

    for (size_t index = 0; index < 32; index++) {
        combined |= digest[index];
    }
    return combined != 0;
}

static bool identity_is_sha256_hex(const char *identity)
{
    if (!identity || strlen(identity) != 64) {
        return false;
    }
    for (size_t index = 0; index < 64; index++) {
        if (!g_ascii_isxdigit(identity[index])) {
            return false;
        }
    }
    return true;
}

static void stop_at_checkpoint(const char *marker)
{
    if (qemu_plugin_request_vmstop() != 0) {
        fail("exact VM stop request was rejected");
    }
    stopped = true;
    g_printerr("%s\n", marker);
}

static void poll_restored_result(void)
{
    struct qemu_plugin_crucible_fault_result result = { 0 };
    size_t payload_len = 0;
    int status;

    do {
        status = qemu_plugin_crucible_fault_poll(
            &result, NULL, 0, &payload_len);
        if (status < 0) {
            fail("restored command result polling failed");
        }
        if (status == 0) {
            return;
        }
        result_count++;
        if (payload_len != 0 ||
            result.command_kind != CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE ||
            result.status != CRUCIBLE_FAULT_STATUS_APPLIED ||
            result.command_sequence != 1 ||
            result.observed_icount != command_icount ||
            result.applied_icount != command_icount) {
            fail("restored command produced a non-canonical result");
        }
    } while (status == 1);
}

static void execute(unsigned int cpu_index, uint64_t icount, void *opaque)
{
    (void)cpu_index;
    (void)opaque;
    if (stopped) {
        return;
    }
    if (save_mode) {
        if (icount >= snapshot_icount) {
            stop_at_checkpoint("CRUCIBLE_FAULT_VMSTATE_ACTIVE_READY");
        }
        return;
    }

    poll_restored_result();
    if (icount >= proof_icount) {
        if (result_count != 1) {
            fail("restored command did not continue exactly once");
        }
        stop_at_checkpoint(
            "CRUCIBLE_FAULT_VMSTATE_RESTORE_PASS occurrences=1");
    }
}

static void submit_checkpointed_command(void)
{
    struct qemu_plugin_crucible_fault_command command = { 0 };

    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    command.command_sequence = 1;
    memset(command.target_node_hash, 0x31, sizeof(command.target_node_hash));
    command.target_icount = command_icount;
    command.authorization_ceiling_icount = command_icount;
    if (qemu_plugin_crucible_fault_submit(&command, NULL, 0) != 0) {
        fail("checkpoint command submission failed");
    }
}

#include "phase2-qemu-fault-manifest-bindings.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *binding_error;
    struct qemu_plugin_crucible_fault_system_manifest system;
    struct qemu_plugin_crucible_fault_clock_capability *rows;
    uint16_t architecture = 0;
    size_t count;
    bool found_tsc = false;
    bool found_rtc = false;
    bool found_timer = false;

    (void)id;
    (void)info;
    if (argc != 1 ||
        (strcmp(argv[0], "mode=save") != 0 &&
         strcmp(argv[0], "mode=restore") != 0)) {
        fail("expected exactly mode=save or mode=restore");
    }
    save_mode = strcmp(argv[0], "mode=save") == 0;
    if (qemu_plugin_crucible_lifecycle_set_process_generation(7) != 0) {
        fail("process generation did not enable aggregate VMState");
    }
    binding_error = crucible_test_bind_all_fault_manifests();
    if (binding_error) {
        fail(binding_error);
    }
    count = qemu_plugin_crucible_fault_clock_manifest(
        NULL, 0, &architecture);
    if (count == 0 || architecture !=
            QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_X86_64) {
        fail("x86 clock manifest was absent");
    }
    rows = g_new0(struct qemu_plugin_crucible_fault_clock_capability, count);
    if (qemu_plugin_crucible_fault_clock_manifest(
            rows, count, &architecture) != count) {
        fail("clock manifest changed between reads");
    }
    for (size_t index = 0; index < count; index++) {
        found_tsc |= rows[index].source_kind == 1;
        found_rtc |= rows[index].source_kind == 2;
        found_timer |= rows[index].timer_relationship != 0;
        if (!rows[index].id || !rows[index].implementation ||
            rows[index].vmstate != 1 || rows[index].width_bits == 0 ||
            rows[index].frequency_numerator == 0 ||
            rows[index].frequency_denominator == 0) {
            fail("clock manifest row was incomplete");
        }
    }
    if (!found_tsc || !found_rtc || !found_timer) {
        fail("realized x86 clock manifest omitted a required source class");
    }
    if (qemu_plugin_crucible_fault_system_manifest(&system) != 0) {
        fail("final fault-system manifest was unavailable");
    }
    if (system.semantic_version != 1 ||
        system.vmstate_format_version != 1 ||
        (system.vmstate_section_count != 9 &&
         system.vmstate_section_count != 10) ||
        system.reserved != 0 ||
        !digest_is_nonzero(system.vmstate_sections_sha256)) {
        fail("final fault-system VMState identity was invalid");
    }
    if (g_strcmp0(system.system_capability,
                  "qemu.fault-system.complete.v1") != 0 ||
        g_strcmp0(system.vmstate_capability,
                  "qemu.fault-vmstate.v1") != 0 ||
        !identity_is_sha256_hex(system.qemu_build_id) ||
        !identity_is_sha256_hex(system.qemu_patch_series_hash) ||
        !identity_is_sha256_hex(system.shmem_header_hash)) {
        fail("final fault-system build identities were invalid");
    }
    g_printerr("CRUCIBLE_FAULT_VMSTATE_FIXTURE_READY clocks=%zu architecture=%u sections=%u\n",
               count, architecture, system.vmstate_section_count);
    g_free(rows);
    qemu_plugin_register_tcg_exec_cb(execute, NULL);
    if (save_mode) {
        submit_checkpointed_command();
    }
    return 0;
}
