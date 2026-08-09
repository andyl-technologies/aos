/*
 * Stock-QEMU negative control for the Crucible fault-submit API.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)id;
    (void)info;
    (void)argc;
    (void)argv;
    return qemu_plugin_crucible_fault_submit(NULL, NULL, 0);
}
