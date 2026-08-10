/*
 * Live realized-controller manifest probe for QEMU interrupt faults.
 *
 * Copyright (c) 2026 ANDYL Technologies
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint16_t expected_architecture;
static bool completed;

static void fail(const char *message)
{
    g_printerr("CRUCIBLE_INTERRUPT_MANIFEST_LIVE_FAIL: %s\n", message);
    abort();
}

static bool nonempty_ascii(const char *value)
{
    return value && value[0] != '\0' && g_str_is_ascii(value);
}

static void probe_manifest(unsigned int cpu_index, void *opaque)
{
    struct qemu_plugin_crucible_fault_interrupt_capability *rows;
    size_t row_count;
    uint16_t architecture = 0;
    bool saw_primary = false;
    bool saw_timer = false;

    (void)cpu_index;
    (void)opaque;
    if (completed) {
        return;
    }
    completed = true;
    row_count = qemu_plugin_crucible_fault_interrupt_manifest(
        NULL, 0, &architecture);
    if (architecture != expected_architecture || row_count == 0 ||
        row_count > 64) {
        fail("manifest query returned an invalid architecture or row count");
    }
    rows = g_new0(
        struct qemu_plugin_crucible_fault_interrupt_capability, row_count);
    if (qemu_plugin_crucible_fault_interrupt_manifest(
            rows, row_count, &architecture) != row_count ||
        architecture != expected_architecture) {
        fail("manifest copy changed identity or row count");
    }
    for (size_t index = 0; index < row_count; index++) {
        const struct qemu_plugin_crucible_fault_interrupt_capability *row =
            &rows[index];

        if (!nonempty_ascii(row->id) || !nonempty_ascii(row->controller) ||
            !nonempty_ascii(row->source) ||
            !nonempty_ascii(row->controller_version) || !row->vmstate ||
            row->reserved != 0 || row->model_phase_mask == 0 ||
            row->vector_start > row->vector_end ||
            row->replacement_vector_start > row->replacement_vector_end ||
            row->target_vcpu_count == 0 || !row->target_vcpus) {
            fail("manifest row violated its closed structural contract");
        }
        for (size_t target = 1; target < row->target_vcpu_count; target++) {
            if (row->target_vcpus[target - 1] >= row->target_vcpus[target]) {
                fail("manifest target vCPUs were not sorted and unique");
            }
        }
        if (expected_architecture == 2) {
            saw_primary |= row->family == 1;
            saw_timer |= row->family == 8;
        } else {
            saw_primary |= row->family == 11;
            saw_timer |= row->family == 13;
        }
    }
    if (!saw_primary || !saw_timer) {
        fail("realized primary controller or architecture timer row was absent");
    }
    g_printerr(
        "CRUCIBLE_INTERRUPT_MANIFEST_LIVE_PASS architecture=%u rows=%zu\n",
        architecture, row_count);
    g_free(rows);
    _Exit(0);
}

static void translate_block(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, probe_manifest, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (!info->system_emulation || argc != 1 ||
        !g_str_has_prefix(argv[0], "architecture=")) {
        fail("probe requires system emulation and one architecture argument");
    }
    expected_architecture = g_ascii_strtoull(
        argv[0] + strlen("architecture="), NULL, 10);
    if (expected_architecture != 2 && expected_architecture != 3) {
        fail("unsupported architecture argument");
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate_block);
    return 0;
}
