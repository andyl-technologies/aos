/*
 * Live QEMU register-manifest gate plugin.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <glib.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void fail(const char *message)
{
    g_printerr("Crucible register manifest live test failed: %s\n", message);
    abort();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    struct qemu_plugin_crucible_fault_register_capability *rows;
    const char *cpu_model = NULL;
    uint16_t expected_architecture;
    uint16_t architecture = 0;
    size_t required;
    bool gpr = false;
    bool control_flow = false;

    (void)id;
    (void)info;
    if (argc != 1 || !g_str_has_prefix(argv[0], "architecture=")) {
        fail("one architecture argument is required");
    }
    expected_architecture = g_ascii_strtoull(argv[0] + 13, NULL, 10);
    required = qemu_plugin_crucible_fault_register_manifest(
        NULL, 0, &architecture, &cpu_model);
    if (required < 64 || required > 4096 ||
        architecture != expected_architecture || !cpu_model || !*cpu_model) {
        fail("the realized CPU did not publish a bounded typed manifest");
    }
    rows = g_new0(struct qemu_plugin_crucible_fault_register_capability,
                  required);
    if (qemu_plugin_crucible_fault_register_manifest(
            rows, required, &architecture, &cpu_model) != required) {
        fail("the immutable manifest changed between reads");
    }
    for (size_t i = 0; i < required; i++) {
        size_t mask_bytes = (rows[i].width_bits + 7) / 8;

        if (rows[i].numeric_id != i + 1 || !rows[i].name ||
            !*rows[i].name || rows[i].mask_bytes != mask_bytes ||
            !rows[i].writable_mask || !rows[i].reserved_mask ||
            !rows[i].ignored_mask || !rows[i].read_only_mask) {
            fail("a manifest row has invalid canonical framing");
        }
        if (rows[i].group == 1 && rows[i].capabilities & 1) {
            gpr = true;
        }
        if (rows[i].group == 2 && rows[i].side_effects != 0 &&
            rows[i].capabilities & 1) {
            control_flow = true;
        }
    }
    g_free(rows);
    if (!gpr || !control_flow) {
        fail("the manifest omitted live GPR or control-flow mutation support");
    }
    g_printerr("CRUCIBLE_REGISTER_MANIFEST_LIVE_PASS architecture=%u rows=%zu model=%s\n",
               architecture, required, cpu_model);
    qemu_plugin_request_shutdown(0);
    return 0;
}
