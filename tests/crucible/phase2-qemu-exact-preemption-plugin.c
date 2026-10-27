/*
 * Exact inter-retirement preemption and pending-command migration witness.
 *
 * Copyright (c) Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <qemu/qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static int submitted;
static int snapshot_source;
static int snapshot_destination;
static int interrupt_mode;
static int advance_requested;
static int control_requested;
static uint64_t logical_grant = 10;
static int continuation;
static int continuation_interrupt;
static unsigned int boundary_index;
static unsigned int executed;
static unsigned int continuation_handoffs;
static const uint64_t boundary_ticks[] = { 1, 10, 49, 99, 100, 150, 151, 201 };
static const uint64_t boundary_raw[] = { 0, 0, 0, 1, 1, 2, 2, 3 };

static void continuation_next_boundary(void)
{
    boundary_index++;
    logical_grant = boundary_ticks[boundary_index];
}

static void continuation_execute(unsigned int vcpu, void *opaque)
{
    executed++;
    fprintf(stderr, "CONTINUATION_EXEC vcpu=%u number=%u raw=%" PRIu64
            " tick=%" PRId64 "\n", vcpu, executed,
            qemu_plugin_icount_raw(), qemu_plugin_sim_tick_observed());
}

static void continuation_translate(struct qemu_plugin_tb *tb, void *opaque)
{
    for (size_t index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
        qemu_plugin_register_vcpu_insn_exec_cb(
            qemu_plugin_tb_get_insn(tb, index), continuation_execute,
            QEMU_PLUGIN_CB_NO_REGS, NULL);
    }
}

static int expect_rejection(const char *name, uint64_t at_tick,
                            uint64_t deadline_tick, uint64_t ceiling_tick,
                            unsigned int kind, uint32_t arg0, uint32_t arg1,
                            uint32_t arg2, int expected)
{
    int rc = qemu_plugin_inject_preemption(at_tick, deadline_tick,
                                           ceiling_tick, kind, arg0, arg1,
                                           arg2);

    fprintf(stderr, "PREEMPTION_REJECT name=%s rc=%d raw=%" PRIu64
            " tick=%" PRId64 "\n", name, rc, qemu_plugin_icount_raw(),
            qemu_plugin_sim_tick_observed());
    fflush(stderr);
    if (rc != expected) {
        qemu_plugin_request_shutdown(36);
        return -1;
    }
    return 0;
}

static int check_rejections(void)
{
    return expect_rejection("before-deadline", 9, 10, 10,
                            QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                            0, 1, 0, -2) ||
           expect_rejection("beyond-ceiling", 11, 10, 10,
                            QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                            0, 1, 0, -2) ||
           expect_rejection("invalid-window", 10, 11, 10,
                            QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                            0, 1, 0, -2) ||
           expect_rejection("unpublished-ceiling", 10, 10, 11,
                            QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                            0, 1, 0, -2) ||
           expect_rejection("invalid-kind", 10, 10, 10, 99,
                            0, 1, 0, -6) ||
           expect_rejection("invalid-switch", 10, 10, 10,
                            QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                            0, 0, 0, -4) ||
           expect_rejection("invalid-interrupt", 10, 10, 10,
                            QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT,
                            1, 256, 0, -5);
}

static void submit_and_pause(void)
{
    unsigned int kind = interrupt_mode ?
        QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT :
        QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH;
    uint32_t arg0 = interrupt_mode ? 1 : 0;
    uint32_t arg1 = interrupt_mode ? 32 : 1;
    int rc;

    if (check_rejections()) {
        return;
    }
    if (snapshot_source &&
        expect_rejection("past-current", 6, 6, 10,
                         QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                         0, 1, 0, -2)) {
        return;
    }
    rc = qemu_plugin_inject_preemption(10, 10, 10, kind,
                                       arg0, arg1, 0);
    fprintf(stderr, "PREEMPTION_SUBMIT rc=%d raw=%" PRIu64
            " tick=%" PRId64 "\n", rc, qemu_plugin_icount_raw(),
            qemu_plugin_sim_tick_observed());
    fflush(stderr);
    if (rc != 0) {
        qemu_plugin_request_shutdown(31);
        return;
    }
    if (expect_rejection("duplicate-pending", 10, 10, 10, kind,
                         arg0, arg1, 0, -3)) {
        return;
    }
    if (snapshot_source) {
        rc = qemu_plugin_request_vmstop();
        fprintf(stderr, "PREEMPTION_VMSTOP rc=%d raw=%" PRIu64
                " tick=%" PRId64 "\n", rc, qemu_plugin_icount_raw(),
                qemu_plugin_sim_tick_observed());
        fflush(stderr);
        if (rc != 0) {
            qemu_plugin_request_shutdown(33);
        }
    }
}

static void advance_complete(int status, int64_t time, void *opaque)
{
    fprintf(stderr, "PREEMPTION_ADVANCE status=%d time=%" PRId64
            " raw=%" PRIu64 " tick=%" PRId64 "\n", status, time,
            qemu_plugin_icount_raw(), qemu_plugin_sim_tick_observed());
    fflush(stderr);
    if (status != 0 || time != 7 || qemu_plugin_icount_raw() != 0 ||
        qemu_plugin_sim_tick_observed() != 7) {
        qemu_plugin_request_shutdown(34);
    } else {
        logical_grant = 10;
        submit_and_pause();
    }
}

static uint64_t raw_ceiling(void *opaque)
{
    if (continuation && !snapshot_source) {
        return boundary_raw[boundary_index];
    }
    if (snapshot_source && !advance_requested) {
        advance_requested = 1;
        int rc = qemu_plugin_advance_time_ticks(7);
        fprintf(stderr, "PREEMPTION_QUEUE_ADVANCE rc=%d\n", rc);
        fflush(stderr);
        if (rc != 0) {
            qemu_plugin_request_shutdown(35);
        }
    } else if (!snapshot_source && !submitted && !snapshot_destination) {
        submitted = 1;
        submit_and_pause();
    }
    return 0;
}

static uint64_t logical_ceiling(void *opaque)
{
    return logical_grant;
}

static void publish(uint64_t raw, void *opaque)
{
    if (continuation && !snapshot_source) {
        int64_t tick = qemu_plugin_sim_tick_observed();

        if (tick < (int64_t)boundary_ticks[boundary_index]) {
            return;
        }
        if (continuation_interrupt && boundary_index == 1 &&
            control_requested) {
            /* Publication may repeat while the admitted control BH is queued. */
            return;
        }
        fprintf(stderr, "CONTINUATION_BOUNDARY index=%u raw=%" PRIu64
                " tick=%" PRId64 " executed=%u\n", boundary_index, raw,
                tick, executed);
        if (tick != (int64_t)boundary_ticks[boundary_index] ||
            raw != boundary_raw[boundary_index] || executed != raw) {
            qemu_plugin_request_shutdown(40);
            return;
        }
        if (boundary_index == 0 &&
            (expect_rejection("continuation-past", 0, 0, 1,
                              QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                              0, 1, 0, -2) ||
             expect_rejection("continuation-unpublished", 2, 2, 2,
                              QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                              0, 1, 0, -2))) {
            return;
        }
        if (boundary_index == 7) {
            qemu_plugin_request_shutdown(0);
            return;
        }
        if (continuation_interrupt && boundary_index == 1) {
            control_requested = 1;
            int rc = qemu_plugin_request_control_boundary();

            fprintf(stderr, "PREEMPTION_CONTROL_REQUEST rc=%d\n", rc);
            if (rc != 0) {
                qemu_plugin_request_shutdown(41);
            }
            return;
        }
        continuation_next_boundary();
        if (continuation_interrupt && boundary_index == 1) {
            int rc = qemu_plugin_inject_preemption(
                10, 10, 10, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT,
                1, 32, 0);

            fprintf(stderr, "CONTINUATION_INPUT rc=%d raw=%" PRIu64
                    " tick=%" PRId64 "\n", rc, raw, tick);
            if (rc != 0) {
                qemu_plugin_request_shutdown(42);
            }
        }
        /* A new private grant must enter through the real control owner. */
        int rc = qemu_plugin_request_control_boundary();

        if (rc != 0) {
            qemu_plugin_request_shutdown(43);
        }
        return;
    }
    fprintf(stderr, "PREEMPTION_PUBLISH raw=%" PRIu64 " tick=%" PRId64 "\n",
            raw, qemu_plugin_sim_tick_observed());
    fflush(stderr);
    if (interrupt_mode && !control_requested &&
        qemu_plugin_sim_tick_observed() == 10) {
        int rc;

        control_requested = 1;
        rc = qemu_plugin_request_control_boundary();
        fprintf(stderr, "PREEMPTION_CONTROL_REQUEST rc=%d\n", rc);
        fflush(stderr);
        if (rc != 0) {
            qemu_plugin_request_shutdown(37);
        }
    }
}

static void control_boundary(unsigned int vcpu, uint64_t raw, void *opaque)
{
    int64_t tick = qemu_plugin_sim_tick_observed();

    if (continuation && (!continuation_interrupt || tick != 10)) {
        fprintf(stderr, "CONTINUATION_CONTROL vcpu=%u raw=%" PRIu64
                " tick=%" PRId64 "\n", vcpu, raw, tick);
        return;
    }
    int rc = qemu_plugin_request_vmstop();

    fprintf(stderr, "PREEMPTION_INTERRUPT_BOUNDARY vcpu=%u raw=%" PRIu64
            " tick=%" PRId64 " vmstop=%d\n", vcpu, raw, tick, rc);
    fflush(stderr);
    if (tick != 10 || raw != 0 || rc != 0) {
        qemu_plugin_request_shutdown(38);
    } else if (continuation_interrupt) {
        continuation_next_boundary();
    }
}

static void handoff(unsigned int from, unsigned int to, uint64_t quantum,
                    uint64_t retired, void *opaque)
{
    int64_t tick = qemu_plugin_sim_tick_observed();
    uint64_t raw = qemu_plugin_icount_raw();

    fprintf(stderr, "PREEMPTION_HANDOFF from=%u to=%u raw=%" PRIu64
            " tick=%" PRId64 " retired=%" PRIu64 "\n",
            from, to, raw, tick, retired);
    fflush(stderr);
    if (continuation && snapshot_destination &&
        continuation_handoffs++ == 1 && from == 1 && to == 0 &&
        raw == 0 && tick == 10 && retired == 0) {
        /* The restored AArch64 secondary is halted; RR returns to the BSP. */
        return;
    }
    if (from != 0 || to != 1 || raw != 0 || tick != 10 || retired != 0) {
        qemu_plugin_request_shutdown(32);
    } else if (!continuation) {
        qemu_plugin_request_shutdown(0);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                            const qemu_info_t *info,
                                            int argc, char **argv)
{
    for (int index = 0; index < argc; index++) {
        snapshot_source |= strcmp(argv[index], "mode=snapshot-source") == 0;
        snapshot_destination |= strcmp(argv[index], "mode=snapshot-destination") == 0;
        interrupt_mode |= strcmp(argv[index], "mode=interrupt") == 0;
        continuation |= strcmp(argv[index], "continuation=on") == 0;
        continuation_interrupt |= strcmp(argv[index], "mode=continuation-interrupt") == 0;
    }
    continuation |= continuation_interrupt;
    if (snapshot_source) {
        logical_grant = 7;
    } else if (continuation) {
        boundary_index = snapshot_destination ? 1 : 0;
        logical_grant = boundary_ticks[boundary_index];
    }
    if (continuation && !snapshot_source) {
        qemu_plugin_register_vcpu_tb_trans_cb(id, continuation_translate, NULL);
    }
    if (snapshot_source &&
        (!qemu_plugin_request_time_control() ||
         qemu_plugin_register_time_advance_cb(advance_complete, NULL) != 0)) {
        return -1;
    }
    qemu_plugin_register_sim_shmem_dispatch_cb(publish, raw_ceiling,
                                                logical_ceiling, NULL);
    qemu_plugin_register_rr_handoff_cb(handoff, NULL);
    if (interrupt_mode || continuation) {
        qemu_plugin_register_control_boundary_cb(control_boundary, NULL);
    }
    return 0;
}
