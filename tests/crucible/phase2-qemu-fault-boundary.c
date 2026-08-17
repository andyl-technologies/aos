/*
 * Live fault-command ABI and exact-boundary test plugin.
 *
 * Copyright (c) 2026 ANDYL Technologies
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <qemu-plugin.h>

#include "aos/crucible/crucible_shmem_abi.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const uint64_t target_icount = 100;
static bool completed;

static void fail(const char *message)
{
    g_printerr("CRUCIBLE_FAULT_BOUNDARY_LIVE_FAIL: %s\n", message);
    abort();
}

static void poll_result(unsigned int cpu_index, void *opaque)
{
    struct qemu_plugin_crucible_fault_result result = { 0 };
    size_t payload_length = 0;
    int status;

    (void)cpu_index;
    (void)opaque;
    if (completed) {
        return;
    }
    status = qemu_plugin_crucible_fault_poll(
        &result, NULL, 0, &payload_length);
    if (status == 0) {
        return;
    }
    if (status != 1 || payload_length != 0 ||
        result.command_kind != CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE ||
        result.status != CRUCIBLE_FAULT_STATUS_APPLIED ||
        result.command_sequence != 1 ||
        result.observed_icount != target_icount ||
        result.applied_icount != target_icount) {
        fail("boundary result was not applied at the exact requested icount");
    }
    completed = true;
    g_printerr("CRUCIBLE_FAULT_BOUNDARY_LIVE_PASS\n");
}

static void translate_block(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, poll_result, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

static void exit_plugin(qemu_plugin_id_t id, void *opaque)
{
    (void)id;
    (void)opaque;
    if (!completed) {
        fail("QEMU exited before publishing the boundary result");
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    struct qemu_plugin_crucible_fault_capability capabilities[64];
    struct qemu_plugin_crucible_fault_command command = { 0 };
    size_t capability_count;
    bool found_abi = false;
    bool found_probe = false;

    (void)argc;
    (void)argv;
    if (!info->system_emulation || info->system.smp_vcpus != 1) {
        fail("test requires one system-emulation vCPU");
    }
    capability_count = qemu_plugin_crucible_fault_capabilities(NULL, 0);
    if (capability_count < 2 ||
        capability_count > G_N_ELEMENTS(capabilities) ||
        qemu_plugin_crucible_fault_capabilities(
            capabilities, G_N_ELEMENTS(capabilities)) != capability_count) {
        fail("capability manifest was not copied atomically");
    }
    for (size_t index = 0; index < capability_count; index++) {
        const struct qemu_plugin_crucible_fault_capability *capability =
            &capabilities[index];

        if (capability->command_kind ==
                CRUCIBLE_FAULT_COMMAND_QUERY_CAPABILITIES &&
            strcmp(capability->name, "qemu.fault-command-abi.v1") == 0) {
            found_abi = true;
        }
        if (capability->command_kind == CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE &&
            capability->semantic_version ==
                CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION &&
            capability->phase_mask ==
                1U << (CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY - 1) &&
            capability->maximum_payload_bytes == 0 &&
            capability->scope == QEMU_PLUGIN_CRUCIBLE_FAULT_SCOPE_ALL &&
            strcmp(capability->name, "qemu.fault-boundary-probe.v1") == 0 &&
            strcmp(capability->payload_schema, "empty") == 0) {
            found_probe = true;
        }
    }
    if (!found_abi || !found_probe) {
        fail("required ABI capabilities were absent or malformed");
    }

    command.abi_major = CRUCIBLE_FAULT_COMMAND_ABI_MAJOR;
    command.abi_minor = CRUCIBLE_FAULT_COMMAND_ABI_MINOR;
    command.command_kind = CRUCIBLE_FAULT_COMMAND_BOUNDARY_PROBE;
    command.phase = CRUCIBLE_FAULT_PHASE_NODE_BOUNDARY;
    command.semantic_version = CRUCIBLE_FAULT_COMMAND_SEMANTIC_VERSION;
    command.command_sequence = 1;
    memset(command.target_node_hash, 0x31, sizeof(command.target_node_hash));
    command.target_icount = target_icount;
    command.authorization_ceiling_icount = target_icount;
    if (qemu_plugin_crucible_fault_submit(&command, NULL, 0) != 0) {
        fail("boundary command was rejected during submission");
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block);
    qemu_plugin_register_atexit_cb(id, exit_plugin, NULL);
    return 0;
}
