/*
 * Live realized-machine manifest probe for QEMU hardware-error faults.
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
    g_printerr("CRUCIBLE_HARDWARE_ERROR_MANIFEST_LIVE_FAIL: %s\n", message);
    abort();
}

static bool nonempty_ascii(const char *value)
{
    return value && value[0] != '\0' && g_str_is_ascii(value);
}

static void probe_manifest(unsigned int cpu_index, void *opaque)
{
    struct qemu_plugin_crucible_fault_hardware_error_capability *rows;
    size_t row_count;
    uint16_t architecture = 0;
    bool saw_corrected = false;
    bool saw_recoverable = false;
    bool saw_fatal = false;
    uint8_t manifest_sha256[32];

    (void)cpu_index;
    (void)opaque;
    if (completed) {
        return;
    }
    completed = true;
    row_count = qemu_plugin_crucible_fault_hardware_error_manifest(
        NULL, 0, &architecture);
    if (architecture != expected_architecture || row_count < 3 ||
        row_count > 64) {
        fail("manifest query returned an invalid architecture or row count");
    }
    rows = g_new0(
        struct qemu_plugin_crucible_fault_hardware_error_capability,
        row_count);
    if (qemu_plugin_crucible_fault_hardware_error_manifest(
            rows, row_count, &architecture) != row_count ||
        architecture != expected_architecture) {
        fail("manifest copy changed identity or row count");
    }
    for (size_t index = 0; index < row_count; index++) {
        const struct qemu_plugin_crucible_fault_hardware_error_capability *row =
            &rows[index];
        uint8_t id[32] = { 0 };
        uint8_t bank[32] = { 0 };
        uint8_t channel[32] = { 0 };
        uint8_t rank[32] = { 0 };
        uint8_t firmware[32] = { 0 };
        uint8_t state[32] = { 0 };

        if (!nonempty_ascii(row->id) || !nonempty_ascii(row->bank) ||
            !nonempty_ascii(row->channel) || !nonempty_ascii(row->rank) ||
            !nonempty_ascii(row->firmware) || !nonempty_ascii(row->state) ||
            row->bank_count == 0 || row->model_phase_mask == 0 ||
            row->privilege_mask == 0 ||
            /* Patch 0067 serializes every hardware-error state owner. */
            !row->vmstate ||
            row->reserved0 != 0 || row->reserved1 != 0 ||
            row->status_required & ~row->status_allowed ||
            row->syndrome_required & ~row->syndrome_allowed ||
            (index != 0 && strcmp(rows[index - 1].id, row->id) >= 0)) {
            fail("manifest row violated its closed structural contract");
        }
        if (expected_architecture == 2 && row->mechanism != 1) {
            fail("x86 manifest exposed a non-MCA mechanism");
        }
        if (expected_architecture == 3 &&
            row->mechanism != 2 && row->mechanism != 3) {
            fail("AArch64 manifest exposed an unsupported mechanism");
        }
        saw_corrected |= row->error_class == 1;
        saw_recoverable |= row->error_class == 2 || row->error_class == 4;
        saw_fatal |= row->error_class == 3;
        memset(id, (int)index + 1, sizeof(id));
        memset(bank, (int)index + 65, sizeof(bank));
        memset(channel, (int)index + 129, sizeof(channel));
        memset(rank, (int)index + 193, sizeof(rank));
        memset(firmware, (int)index + 17, sizeof(firmware));
        memset(state, (int)index + 33, sizeof(state));
        if (qemu_plugin_crucible_fault_hardware_error_bind(
                index, id, bank, channel, rank, firmware, state) != 0) {
            fail("manifest row identity binding failed");
        }
    }
    memset(manifest_sha256, 0xa5, sizeof(manifest_sha256));
    if (!saw_recoverable || !saw_fatal ||
        (expected_architecture == 2 && !saw_corrected) ||
        qemu_plugin_crucible_fault_hardware_error_bindings_seal(
            manifest_sha256) != 0 ||
        qemu_plugin_crucible_fault_hardware_error_bindings_seal(
            manifest_sha256) == 0) {
        fail("required classes or one-shot binding seal were absent");
    }
    g_printerr(
        "CRUCIBLE_HARDWARE_ERROR_MANIFEST_LIVE_PASS architecture=%u rows=%zu\n",
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
