/*
 * Joined original block wait and idle-advance ownership under explicit providers.
 * Copyright (c) 2026 Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The block backend, coroutine queues, AIO reader/BHs and virtual timer list
 * are native bodies. Registered callbacks belong to the Rust plugin unit.
 * One halted CPU and serialized CPU work are external topology providers;
 * advancing the provided clock is not a TCG or physical guest qualification.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "qemu/plugin.h"
#include "qemu/crucible-idle-wait.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "system/cpu-timers.h"
#include "system/runstate.h"
#include "exec/icount.h"
#include "hw/core/cpu.h"
#include "accel/tcg/tcg-accel-ops-rr.h"
#include <sys/eventfd.h>
#include "block-wait-completion.h"

static bool external_vmstop;
static uint64_t external_clock;
static __thread unsigned qemu_plugin_crucible_exact_boundary_depth;
static __thread CPUState *qemu_plugin_crucible_idle_callback_cpu;
static __thread unsigned qemu_plugin_crucible_idle_callback_depth;
static BlockWaitUnitCallbacks external_callbacks;
static BlockWaitUnitResult observed;
static CPUState external_cpu;
CPUTailQ cpus_queue = QTAILQ_HEAD_INITIALIZER(cpus_queue);
__thread CPUState *current_cpu;
qemu_plugin_vcpu_idle_resume_cb_t qemu_plugin_vcpu_idle_resume_idle_cb;
qemu_plugin_vcpu_idle_resume_cb_t qemu_plugin_vcpu_idle_resume_resume_cb;
static void *idle_userdata;

void qemu_plugin_crucible_callback_registered(qemu_plugin_id_t plugin,
                                              uint64_t mask)
{
    g_assert_cmpuint(plugin, ==, 0);
    g_assert_cmpuint(mask, !=, 0);
}

bool qemu_plugin_crucible_vmstop_pending(void)
{
    return external_vmstop;
}

void qemu_plugin_crucible_exact_boundary_enter(void)
{
    qemu_plugin_crucible_exact_boundary_depth++;
}

void qemu_plugin_crucible_exact_boundary_leave(void)
{
    g_assert_cmpuint(qemu_plugin_crucible_exact_boundary_depth, >, 0);
    qemu_plugin_crucible_exact_boundary_depth--;
}

/* Driver registration is unused; keeping the complete backend still gives the
 * compiler the real private state and every original callback declaration.
 */
#undef type_init
#define type_init(function) \
    static void *const excluded_##function __attribute__((unused)) = function;
#undef block_init
#define block_init(function) \
    static void *const excluded_##function __attribute__((unused)) = function;
#include "block/crucible-shmem.c"

void bdrv_notify_topology_change(BlockDriverState *bs)
{
    /* The transport provider has one response and no reset/topology events. */
    g_assert_not_reached();
}

#define QEMU_PLUGIN_TIME_ADVANCE_RESERVED 1
#define QEMU_PLUGIN_TIME_ADVANCE_ARMED 2
#define QEMU_PLUGIN_TIME_ADVANCE_TIMERS_NOT_READY 0
#define QEMU_PLUGIN_TIME_ADVANCE_TIMERS_WAITING 1
#define QEMU_PLUGIN_TIME_ADVANCE_TIMERS_COMPLETING 2
#define QEMU_PLUGIN_TIME_ADVANCE_TIMERS_SETTLE_READY 3
#define CRUCIBLE_STOP_READER_DRAINED 0
#define CRUCIBLE_STOP_READER_EOF 1
#define CRUCIBLE_STOP_READER_ERROR 2

static bool has_control = true;
static int qemu_plugin_time_advance_pending;
static int qemu_plugin_time_advance_timer_state;
static int qemu_plugin_time_advance_status;
static int64_t qemu_plugin_time_advance_target;
static uintptr_t qemu_plugin_time_advance_barrier;
static bool qemu_plugin_time_advance_callback_active;
static qemu_plugin_time_advance_cb_t qemu_plugin_time_advance_cb;
static void *qemu_plugin_time_advance_userdata;
static NotifierList qemu_plugin_wake_notifiers =
    NOTIFIER_LIST_INITIALIZER(qemu_plugin_wake_notifiers);
static QemuMutex qemu_plugin_crucible_virtual_timer_witness_lock;
static QemuPluginCrucibleVirtualTimerWitnessState
    qemu_plugin_crucible_virtual_timer_witness_state;
static uint64_t qemu_plugin_rr_control_request_generation;
static uint64_t qemu_plugin_rr_control_ack_generation;
static uint64_t qemu_plugin_rr_control_complete_generation;
static uintptr_t qemu_plugin_control_boundary_scheduled;
static int rr_tcg_exec_state = RR_TCG_EXEC_IDLE;

static const char *current_accel_name(void) { return "sim"; }

static bool external_cpu_is_self(CPUState *cpu) { return cpu == first_cpu; }

static bool external_bql_locked(void) { return true; }

static void external_lock(void) {}

static void external_run_on_cpu(CPUState *cpu, run_on_cpu_func function,
                                 run_on_cpu_data data)
{
    g_assert_true(cpu == first_cpu);
    function(cpu, data);
}

static void external_cpu_kick(CPUState *cpu)
{
    g_assert_true(cpu == first_cpu);
    observed.cpu_kicks++;
}

static int external_advance_clock(int64_t target)
{
    g_assert_cmpint(target, >=, external_clock);
    external_clock = target;
    return 0;
}

void rr_crucible_sim_trace_idle_advance(const char *phase, int64_t target) {}

void rr_crucible_sim_trace_idle_stage(const char *phase, int64_t target) {}

void rr_crucible_sim_publish_time_advance_wake(void) {}

void rr_crucible_sim_signal_time_advance_wake(void) {}

static uintptr_t qemu_plugin_schedule_control_boundary(void) { return 0; }

static void qemu_plugin_request_rr_control_boundary(void) {}

void qemu_plugin_crucible_rr_control_boundary_defer(void) {}

bool qemu_plugin_crucible_rr_control_boundary_pending(void) { return false; }

bool qemu_plugin_crucible_vmstop_quiesced(void) { return false; }

int qemu_plugin_crucible_single_threaded_rr(void) { return 1; }

static void qemu_plugin_rearm_deferred_control_boundary(void) {}

static void qemu_plugin_control_drain_notify(void) {}

static void qemu_plugin_trace_control_delivery(const char *phase) {}

static void qemu_plugin_trace_rr_control_boundary_state(const char *phase) {}

static void qemu_plugin_trace_stop_context(int phase) {}

static void tcg_kick_vcpu_thread(CPUState *cpu) { external_cpu_kick(cpu); }

static void qemu_plugin_unregister_wake_fd(int fd)
{
    /* EOF/error is outside these successful single-doorbell schedules. */
    g_assert_not_reached();
}

void qemu_system_shutdown_request(ShutdownCause reason)
{
    g_assert_not_reached();
}

/* These providers serialize one bounded CPU's work. They do not emulate TCG
 * instructions, admit controls, process a fault, or manufacture a guest reply.
 */
static bool rr_crucible_sim_mode(void) { return true; }

static bool external_cpu_has_work(CPUState *cpu) { return false; }

static bool external_cpu_work_list_empty(CPUState *cpu) { return true; }

static bool qemu_crucible_fault_vcpu_service_eligible(CPUState *cpu) { return true; }

static bool external_all_cpu_threads_idle(void) { return true; }

static bool rr_crucible_sim_complete_wake_boundary(void) { return false; }

static void rr_crucible_sim_drain_vcpu_work(void) {}

static void rr_crucible_sim_process_vcpu_events(CPUState *cpu) {}

static void rr_crucible_sim_prepark(bool advance, bool control) {}

static void rr_hot_fork_note_parked(void) {}

static void rr_start_kick_timer(void) {}

static void rr_stop_kick_timer(void) {}

static bool external_force_shutdown_requested(void) { return false; }

static void external_icount_start_warp_timer(void) {}

static void external_icount_handle_deadline(void) {}

QemuPluginCrucibleIdleCallbackDisposition qemu_plugin_fire_vcpu_idle_cb(CPUState *cpu)
{
    g_assert_true(cpu == first_cpu);
    g_assert_null(qemu_plugin_crucible_idle_callback_cpu);
    qemu_plugin_crucible_idle_callback_cpu = cpu;
    qemu_plugin_crucible_idle_callback_depth = 1;
    qemu_plugin_crucible_exact_boundary_enter();
    qemu_plugin_vcpu_idle_resume_idle_cb(0, block_wait_unit_raw(), idle_userdata);
    qemu_plugin_crucible_exact_boundary_leave();
    qemu_plugin_crucible_idle_callback_depth = 0;
    qemu_plugin_crucible_idle_callback_cpu = NULL;
    return QEMU_PLUGIN_CRUCIBLE_IDLE_CALLBACK_COMPLETE;
}

void qemu_plugin_fire_vcpu_resume_cb(CPUState *cpu)
{
    g_assert_not_reached();
}

#define qemu_cpu_is_self external_cpu_is_self
#define bql_locked external_bql_locked
#define replay_mutex_unlock external_lock
#define replay_mutex_lock external_lock
#define bql_unlock external_lock
#define bql_lock external_lock
#define run_on_cpu external_run_on_cpu
#define qemu_cpu_kick external_cpu_kick
#define icount_advance_virtual_time_to_tick external_advance_clock
#define cpu_has_work external_cpu_has_work
#define cpu_work_list_empty external_cpu_work_list_empty
#define all_cpu_threads_idle external_all_cpu_threads_idle
#define qemu_force_shutdown_requested external_force_shutdown_requested
#define icount_start_warp_timer external_icount_start_warp_timer
#define icount_handle_deadline external_icount_handle_deadline
#include "block-wait-completion-bodies.inc"

static int64_t provided_clock(void)
{
    return external_clock;
}

static void due_timer(void *opaque)
{
    observed.due_timer_callbacks++;
}

static int submit_provider(uint64_t epoch, uint32_t request,
                             unsigned operation, uint64_t offset,
                             const uint8_t *data, size_t length, void *userdata)
{
    g_assert_not_reached();
}

static int64_t poll_provider(uint64_t epoch, uint32_t request,
                              uint8_t *data, size_t capacity, void *userdata)
{
    observed.polls++;
    g_assert_cmpuint(epoch, ==, 1);
    g_assert_cmpuint(request, ==, 1);
    if (external_callbacks.current(external_callbacks.userdata) < 200) {
        return QEMU_PLUGIN_BLK_POLL_PENDING;
    }
    g_assert_cmpuint(capacity, ==, 1);
    data[0] = 0x5a;
    observed.delivered++;
    return 1;
}

static void complete_provider(int status, int64_t target, void *userdata)
{
    observed.completion_callbacks++;
    external_callbacks.complete(status, target, external_callbacks.userdata);
}

static void coroutine_entry(void *opaque)
{
    BlockDriverState *bs = opaque;
    uint8_t byte = 0;

    observed.result = crucible_shmem_poll_until_ready(bs, 1, 1, &byte, 1);
    if (observed.result >= 0) {
        g_assert_cmpuint(byte, ==, 0x5a);
    }
    observed.completed_coordinate =
        external_callbacks.current(external_callbacks.userdata);
}

__attribute__((visibility("default"))) uint64_t block_wait_unit_raw(void)
{
    return 2;
}

__attribute__((visibility("default"))) int64_t block_wait_unit_deadline(void)
{
    return qemu_clock_deadline_ps_all_absolute(QEMU_CLOCK_VIRTUAL,
                                               QEMU_TIMER_ATTR_ALL);
}

__attribute__((visibility("default"))) int block_wait_unit_enqueue(int64_t target)
{
    return qemu_plugin_advance_time_ticks(target);
}

__attribute__((visibility("default"))) int block_wait_unit_arm_timer(
    int64_t deadline, uint64_t tick, uint64_t *generation)
{
    return qemu_plugin_crucible_arm_virtual_timer_witness(deadline, tick, generation);
}

__attribute__((visibility("default"))) int block_wait_unit_query_timer(
    uint64_t generation, void *record)
{
    return qemu_plugin_crucible_query_virtual_timer_witness(generation, record);
}

uint64_t qemu_plugin_icount_raw(void)
{
    return block_wait_unit_raw();
}

__attribute__((visibility("default"))) int block_wait_unit_run(
    const BlockWaitUnitCallbacks *callbacks, bool initially_due_timer,
    BlockWaitUnitResult *result)
{
    BDRVCrucibleShmemState state = { 0 };
    BlockDriverState bs = { .opaque = &state };
    Coroutine *coroutine;
    QEMUTimer *timer = NULL;
    Error *error = NULL;
    int fd;

    external_callbacks = *callbacks;
    external_clock = 100;
    use_icount = ICOUNT_PRECISE;
    observed = (BlockWaitUnitResult) { .result = QEMU_PLUGIN_BLK_POLL_PENDING };
    QTAILQ_INSERT_TAIL(&cpus_queue, &external_cpu, node);
    external_cpu.halted = true;
    current_cpu = &external_cpu;
    if (qemu_init_main_loop(&error) < 0) {
        error_free(error);
        return -1;
    }
    qemu_timer_enable_tcg_ps_clock(provided_clock, NULL);
    qemu_mutex_init(&qemu_plugin_crucible_virtual_timer_witness_lock);
    qemu_timer_register_crucible_virtual_timer_witness(
        qemu_plugin_crucible_virtual_timer_witness_begin,
        qemu_plugin_crucible_virtual_timer_witness_complete);
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    qemu_mutex_init(&state.pending_lock);
    qemu_co_queue_init(&state.pending_requests);
    state.wake_notifier.notify = crucible_shmem_wake;
    qemu_plugin_wake_notifier_add(&state.wake_notifier);
    qemu_plugin_register_blk_cb(submit_provider, poll_provider, NULL);
    qemu_plugin_register_blk_wait_cb(callbacks->wait, callbacks->userdata);
    qemu_plugin_register_time_advance_cb(complete_provider, NULL);
    qemu_plugin_vcpu_idle_resume_idle_cb = callbacks->idle;
    idle_userdata = callbacks->userdata;
    if (initially_due_timer) {
        timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, due_timer, NULL);
        timer_mod_ps_wide(timer, 100);
    }

    coroutine = qemu_coroutine_create(coroutine_entry, &bs);
    qemu_coroutine_enter(coroutine);
    g_assert_cmpuint(observed.polls, ==, 1);
    g_assert_false(qemu_co_queue_empty(&state.pending_requests));
    callbacks->publish(200, callbacks->userdata);
    fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        return -errno;
    }
    aio_set_fd_handler(qemu_get_aio_context(), fd, qemu_plugin_wake_fd_read,
                       NULL, NULL, NULL, (void *)(intptr_t)fd);
    g_assert_cmpint(eventfd_write(fd, 1), ==, 0);

    for (unsigned pass = 0; pass < 128 && observed.delivered == 0; pass++) {
        main_loop_wait(true);
        rr_wait_io_event();
        if (qemu_plugin_time_advance_timer_state ==
                QEMU_PLUGIN_TIME_ADVANCE_TIMERS_SETTLE_READY) {
            qemu_plugin_time_advance_settle_at_rr_idle();
        }
    }
    int status = observed.delivered == 1 ? 0 : -ETIMEDOUT;
    if (status != 0) {
        /* Unpark through the original failed-wake path before stack teardown.
         * Preserve the pre-cancellation observation as the result of the case.
         */
        BlockWaitUnitResult before_cleanup = observed;
        crucible_shmem_wake(&state.wake_notifier,
                            (void *)(intptr_t)QEMU_PLUGIN_WAKE_EVENT_FAILED);
        observed = before_cleanup;
    }
    aio_set_fd_handler(qemu_get_aio_context(), fd, NULL, NULL, NULL, NULL, NULL);
    close(fd);
    if (timer) {
        timer_free(timer);
    }
    g_assert_true(qemu_co_queue_empty(&state.pending_requests));
    qemu_plugin_wake_notifier_remove(&state.wake_notifier);
    qemu_mutex_destroy(&state.pending_lock);
    *result = observed;
    return status;
}
