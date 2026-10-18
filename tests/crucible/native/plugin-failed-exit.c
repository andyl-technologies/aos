/*
 * Original plugin shutdown/runstate bodies with external service providers.
 * Copyright (c) 2026 Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The generated include preserves the real bridge, shutdown state and process
 * status decision. Notification, CPU kick, replay notice and unrelated runstate
 * services are external providers. This unit runs no VM or TCG instruction.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/main-loop.h"
#include "qemu/notify.h"
#include "hw/core/cpu.h"
#include "system/cpus.h"
#include "system/runstate.h"
#include "system/runstate-action.h"

static CPUState external_cpu;
CPUTailQ cpus_queue = QTAILQ_HEAD_INITIALIZER(cpus_queue);
ShutdownAction shutdown_action = SHUTDOWN_ACTION_POWEROFF;
PanicAction panic_action = PANIC_ACTION_EXIT_FAILURE;
static unsigned external_kicks;
static unsigned external_notices;
static unsigned external_trace_notices;
static ShutdownCause external_replay_cause;
static ShutdownCause external_consumed_cause;

/* These providers record effects; none chooses the process exit status. */
void qemu_cpu_kick(CPUState *cpu)
{
    g_assert_true(cpu == &external_cpu);
    external_kicks++;
}

void qemu_notify_event(void)
{
    external_notices++;
}

static void trace_qemu_system_shutdown_request(ShutdownCause cause)
{
    g_assert_cmpint(cause, !=, SHUTDOWN_CAUSE_NONE);
    external_trace_notices++;
}

static void replay_shutdown_request(ShutdownCause cause)
{
    external_replay_cause = cause;
}

static void qemu_system_shutdown(ShutdownCause cause)
{
    external_consumed_cause = cause;
}

/* No other request is admitted in this test topology. Unexpected branches
 * fail instead of silently simulating their execution. */
static int qemu_debug_requested(void)
{
    return 0;
}

static int qemu_suspend_requested(void)
{
    return 0;
}

static ShutdownCause qemu_reset_requested(void)
{
    return SHUTDOWN_CAUSE_NONE;
}

static WakeupReason qemu_wakeup_requested(void)
{
    return QEMU_WAKEUP_REASON_NONE;
}

static int qemu_powerdown_requested(void)
{
    return 0;
}

static void qemu_kill_report(void) {}

static void qemu_system_suspend(void)
{
    g_assert_not_reached();
}

static void qemu_system_wakeup(void)
{
    g_assert_not_reached();
}

static void qemu_system_powerdown(void)
{
    g_assert_not_reached();
}

static void qapi_event_send_wakeup(void)
{
    g_assert_not_reached();
}

int vm_stop(RunState state)
{
    g_assert_not_reached();
}

void pause_all_vcpus(void)
{
    g_assert_not_reached();
}

void resume_all_vcpus(void)
{
    g_assert_not_reached();
}

void qemu_system_reset(ShutdownCause cause)
{
    g_assert_not_reached();
}

bool runstate_check(RunState state)
{
    g_assert_not_reached();
}

void runstate_set(RunState state)
{
    g_assert_not_reached();
}

bool qemu_vmstop_requested(RunState *state)
{
    return false;
}

void main_loop_wait(int nonblocking)
{
    g_assert_not_reached();
}

#include "plugin-failed-exit-bodies.inc"

static void run_exit_control(int failure, bool later_clean, int expected_status)
{
    pid_t child = fork();
    int status;

    g_assert_cmpint(child, >=, 0);
    if (child == 0) {
        qemu_plugin_request_shutdown(failure);
        g_assert_cmpuint(external_notices, ==, 1);
        g_assert_cmpuint(external_trace_notices, ==, 1);
        g_assert_cmpuint(external_kicks, ==, failure ? 1 : 2);
        g_assert_cmpint(external_replay_cause, ==,
                        failure ? SHUTDOWN_CAUSE_HOST_ERROR :
                                  SHUTDOWN_CAUSE_HOST_QMP_QUIT);
        g_assert_cmpint(shutdown_requested, ==, external_replay_cause);
        g_assert_cmpint(force_shutdown, ==, failure == 0);

        if (later_clean) {
            qemu_plugin_request_shutdown(0);
            g_assert_cmpuint(external_notices, ==, 2);
            g_assert_cmpuint(external_trace_notices, ==, 2);
            g_assert_cmpuint(external_kicks, ==, 3);
            g_assert_cmpint(shutdown_requested, ==, SHUTDOWN_CAUSE_HOST_QMP_QUIT);
        }

        int exit_code = qemu_main_loop();
        g_assert_cmpint(external_consumed_cause, ==,
                        later_clean || !failure ? SHUTDOWN_CAUSE_HOST_QMP_QUIT :
                                                SHUTDOWN_CAUSE_HOST_ERROR);
        g_assert_cmpint(shutdown_requested, ==, SHUTDOWN_CAUSE_NONE);
        _exit(exit_code);
    }

    pid_t reaped;
    do {
        reaped = waitpid(child, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    g_assert_cmpint(reaped, ==, child);
    g_assert_true(WIFEXITED(status));
    int actual_status = WEXITSTATUS(status);
    g_test_message("owned child exit: actual=%d expected=%d",
                   actual_status, expected_status);
    if (actual_status != expected_status) {
        g_test_fail();
    }
}

static void failure_exit(void)
{
    run_exit_control(1, false, EXIT_FAILURE);
}

static void clean_exit(void)
{
    run_exit_control(0, false, EXIT_SUCCESS);
}

static void failed_exit_survives_clean_request(void)
{
    run_exit_control(1, true, EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    QTAILQ_INSERT_TAIL(&cpus_queue, &external_cpu, node);
    g_test_add_func("/plugin-exit/failure", failure_exit);
    g_test_add_func("/plugin-exit/clean", clean_exit);
    g_test_add_func("/plugin-exit/failure-then-clean", failed_exit_survives_clean_request);
    return g_test_run();
}
