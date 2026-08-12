/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void fail(const char *message)
{
    g_printerr("Crucible fault VMState live test failed: %s\n", message);
    abort();
}

#include "phase2-qemu-fault-manifest-bindings.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *binding_error;
    struct qemu_plugin_crucible_fault_clock_capability *rows;
    uint16_t architecture = 0;
    size_t count;
    bool found_tsc = false;
    bool found_rtc = false;
    bool found_timer = false;

    (void)id;
    (void)info;
    (void)argv;
    if (argc != 0) {
        fail("unexpected plugin arguments");
    }
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
    g_printerr("CRUCIBLE_FAULT_VMSTATE_FIXTURE_READY clocks=%zu architecture=%u\n",
               count, architecture);
    g_free(rows);
    return 0;
}
