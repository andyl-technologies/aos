/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define STOP_INTERVAL_ICOUNT (UINT64_C(1) << 20)

/* Admit quickly, then leave enough execution between stops to cross firmware. */
static uint64_t next_stop_icount = 64;

static uint64_t next_exact_boundary(void *userdata)
{
    (void)userdata;
    return next_stop_icount;
}

static void stop_at_exact_boundary(uint64_t icount, void *userdata)
{
    int status;

    (void)userdata;
    if (icount < next_stop_icount) {
        return;
    }

    status = qemu_plugin_request_vmstop();
    if (status != 0) {
        g_printerr("CRUCIBLE_CHECKPOINT_DELTA_STOP_FAILED\n");
        qemu_plugin_request_shutdown(1);
        return;
    }
    next_stop_icount = icount + STOP_INTERVAL_ICOUNT;
    g_printerr("CRUCIBLE_CHECKPOINT_DELTA_EXACT_STOP_ADMITTED\n");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)id;
    (void)info;
    (void)argv;
    if (argc != 0) {
        g_printerr("checkpoint delta fixture accepts no arguments\n");
        return -1;
    }

    qemu_plugin_register_sim_shmem_observer_cb(
        stop_at_exact_boundary, next_exact_boundary, NULL);
    return 0;
}
