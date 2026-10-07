/*
 * Serialized sim endpoints for native utility-library unit tests.
 * Copyright (c) 2026 Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * No TCG engine is linked. The selected RR body owns timer dispatch and the
 * selected advance body commands the supplied clock; these endpoints cannot
 * move time or manufacture a timer witness. Ordinary qemuutil icount stubs
 * abort instead of providing this explicitly bounded unit topology.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/timer.h"
#include "exec/icount.h"
#include "hw/core/cpu.h"

ICountMode use_icount = ICOUNT_DISABLED;

bool icount_configure(QemuOpts *opts, Error **errp)
{
    error_setg(errp, "cannot configure icount, TCG support not available");
    return false;
}

int64_t icount_get_raw(void)
{
    /* The one halted CPU executes no instructions in this adapter. */
    return 2;
}

void icount_start_warp_timer(void)
{
    g_assert_cmpint(icount_enabled(), ==, ICOUNT_PRECISE);
    /* The selected sim warp path only notifies; it never advances the clock. */
    qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
}

void icount_account_warp_timer(void)
{
    /* Wall-clock warp accounting is outside the selected sim schedule. */
    g_assert_not_reached();
}

void icount_notify_exit(void)
{
    /* There is no executing TCG CPU to interrupt in this unit topology. */
    g_assert_true(first_cpu == NULL || first_cpu->halted);
}
