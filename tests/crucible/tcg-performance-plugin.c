/*
 * Exact stop boundaries for the deterministic TCG performance witness.
 *
 * Copyright (c) Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qemu/qemu-plugin.h>

#include "crucible-resident-ram.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t stop_icount;
static int stop_requested;

static uint64_t ceiling(void *opaque)
{
    return stop_icount;
}

static void control_boundary(unsigned int vcpu, uint64_t raw, void *opaque)
{
    int status = qemu_plugin_request_vmstop();

    fprintf(stderr, "TCG_STOP vcpu=%u raw=%" PRIu64 " tick=%" PRId64
            " status=%d\n", vcpu, raw, qemu_plugin_sim_tick_observed(), status);
    fflush(stderr);
    if (raw != stop_icount || status != 0) {
        qemu_plugin_request_shutdown(41);
    }
}

static void observe(uint64_t raw, void *opaque)
{
    if (raw == stop_icount && !stop_requested) {
        stop_requested = 1;
        if (qemu_plugin_request_control_boundary() != 0) {
            qemu_plugin_request_shutdown(42);
        }
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                         const qemu_info_t *info,
                                         int argc, char **argv)
{
    char *end;

    if (argc != 1 || strncmp(argv[0], "stop=", 5) != 0) {
        return -1;
    }
    errno = 0;
    stop_icount = strtoull(argv[0] + 5, &end, 10);
    if (errno != 0 || *end != '\0' || stop_icount == 0) {
        return -1;
    }

    if (crucible_fixture_install_resident_ram() != 0) {
        return -1;
    }

    qemu_plugin_register_sim_shmem_observer_cb(observe, ceiling, NULL);
    qemu_plugin_register_control_boundary_cb(control_boundary, NULL);
    return 0;
}
