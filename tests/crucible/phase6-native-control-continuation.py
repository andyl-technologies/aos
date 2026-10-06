# SPDX-License-Identifier: GPL-2.0-or-later
"""Compose selected native control bodies across a real unchanged-ceiling park.

The selected QEMU fixture supplies bounded CPU/device topology. This extension
executes its genuine registered reader, control generation/scheduling bodies,
running RR ceiling wait and claim, nested all-halted idle control wait,
initial one-shot SDK futex wait, poll-ready handoff, and QemuEvent algorithm.
Pthreads, eventfd, poll and futex are real. A bounded AIO slice provider replaces
GLib dispatch; CPU execution and Rust bridge settlement are explicit providers.
No guest, linked QEMU translation unit, or physical failure attribution is proved.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import signal
import subprocess


EXTRA = r"""
#include <pthread.h>
#include <poll.h>
#include <sys/eventfd.h>
#include "qemu/futex.h"

#ifndef HAVE_FUTEX
#error "The control continuation fixture requires QEMU's Linux futex backend"
#endif

/* Selected thread.h's futex QemuEvent representation. */
typedef struct QemuEvent {
    unsigned value;
    bool initialized;
} QemuEvent;
#define EV_SET 0
#define EV_FREE 1
#define EV_BUSY -1
void qemu_event_init(QemuEvent *event, bool initial);
void qemu_event_destroy(QemuEvent *event);
void qemu_event_set(QemuEvent *event);
void qemu_event_reset(QemuEvent *event);
void qemu_event_wait(QemuEvent *event);
int qemu_plugin_register_wake_fd(int fd);

typedef int Notifier;
typedef struct MainLoopPoll { int state; uint32_t timeout; } MainLoopPoll;
enum { MAIN_LOOP_POLL_FILL, MAIN_LOOP_POLL_OK, MAIN_LOOP_POLL_ERR,
       MAIN_LOOP_POLL_DONE };
static pthread_mutex_t fixture_bql = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fixture_replay = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fixture_state = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fixture_changed = PTHREAD_COND_INITIALIZER;
static pthread_cond_t fixture_halt = PTHREAD_COND_INITIALIZER;
static _Thread_local bool rr_replay_mutex_owned;
static QemuEvent rr_dispatch_ceiling_event, rr_main_loop_resume_event;
static bool rr_dispatch_ceiling_event_initialized;
static uint64_t rr_main_loop_dispatch_requested;
static uint64_t rr_main_loop_dispatch_completed;
static uint64_t rr_main_loop_dispatch_acknowledged;
static uint64_t rr_external_main_loop_work_published;
static uint64_t rr_external_main_loop_work_polling;
static uint64_t rr_external_main_loop_work_completed;
static uint64_t rr_chained_main_loop_work_published;
static uint64_t rr_chained_main_loop_work_polling;
static uint64_t rr_chained_main_loop_work_completed;
static uint64_t rr_vcpu_main_loop_work_published;
static uint64_t rr_vcpu_main_loop_work_completed;
static bool rr_main_loop_poll_priming, rr_main_loop_dispatch_active;
static int qemu_plugin_wake_fd = -1;
static int original_fd, aio_fd;
static void (*registered_reader)(void *);
static void *registered_opaque;
static unsigned host_writes, reader_bytes, reader_drains, reader_calls;
static unsigned rr_parks, idle_parks, callback_return_notifications;
static bool rr_finished, source_delivered, pump_ready, pump_cleared;
static bool refuse_first, force_handoff, idle_case, fixture_finished;
static bool sdk_case, sdk_arm_gap, sdk_unlock_seen;
static bool two_epochs, two_epochs_handoff, epoch_gate_seen, epoch_gate_released;
static bool epoch_rr_outer_ready;
static unsigned epoch_callback_returns, epoch_no_request, epoch_settled;
static uint32_t epoch_observed_tokens[3];
static uint32_t sdk_wake_signal;
static long sdk_thread_id;
static unsigned sdk_pin_calls, sdk_unpin_calls;
static enum qemu_plugin_crucible_idle_wait_status sdk_status;
static pthread_mutex_t qemu_plugin_crucible_idle_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t *qemu_plugin_crucible_active_idle_wake_signal;
static _Thread_local CPUState *qemu_plugin_crucible_idle_callback_cpu;
static _Thread_local unsigned qemu_plugin_crucible_idle_callback_depth;
static _Thread_local bool qemu_plugin_crucible_idle_wait_issued;
static _Thread_local QemuPluginCrucibleIdleCallbackDisposition
    qemu_plugin_crucible_idle_callback_disposition;
static qemu_plugin_vcpu_idle_resume_cb_t qemu_plugin_vcpu_idle_resume_idle_cb;
static void *qemu_plugin_vcpu_idle_resume_userdata;
static uint32_t shared_request = 54008, shared_ack = 54008;
static const uint64_t idle_deadline = 31;

/* CPU-list membership and calibrated ceiling are explicit topology providers. */
#define QTAILQ_IN_USE(member, field) ((member)->in_list)
static unsigned cpu_list_generation_id_get(void) { return 7; }
static bool crucible_sim_shmem_dispatch_registered(void) { return idle_case; }
static uint64_t crucible_sim_shmem_max_advance_icount(void) { return 17; }
static int qemu_poll_ns(GPollFD *descriptors, unsigned count, int64_t timeout)
{
    g_assert_cmpuint(count, ==, 1);
    g_assert_cmpint(timeout, ==, 0);
    return g_poll(descriptors, count, 0);
}

static void rr_crucible_sim_handoff_main_loop(void);
static void rr_crucible_sim_notify_dispatch_ceiling(void);
static void qemu_plugin_wake_fd_read(void *opaque);
void qemu_plugin_crucible_kick_idle_wait(CPUState *target);
QemuPluginCrucibleIdleCallbackDisposition qemu_plugin_fire_vcpu_idle_cb(CPUState *target);
enum qemu_plugin_crucible_idle_wait_status
qemu_plugin_crucible_wait_idle_wake(unsigned int index, uint32_t *signal,
                                    uint32_t expected);

/* Bounded CPU/object providers; only the selected SDK owns its wait lifecycle. */
#define OBJECT(target) (target)
static void object_ref(CPUState *target)
{ g_assert_true(target == &cpu); sdk_pin_calls++; }
static void object_unref(CPUState *target)
{ g_assert_true(target == &cpu); sdk_unpin_calls++; }
static bool cpu_work_list_empty(CPUState *target) { return true; }
static bool cpu_thread_is_idle(CPUState *target) { return target->halted; }
static bool cpu_has_work(CPUState *target) { return false; }
static void qemu_mutex_lock(pthread_mutex_t *mutex)
{ g_assert_cmpint(pthread_mutex_lock(mutex), ==, 0); }
static void qemu_mutex_unlock(pthread_mutex_t *mutex)
{ g_assert_cmpint(pthread_mutex_unlock(mutex), ==, 0); }
static pthread_mutex_t *fixture_lock_guard(pthread_mutex_t *mutex)
{ qemu_mutex_lock(mutex); return mutex; }
static void fixture_unlock_guard(pthread_mutex_t **mutex)
{ qemu_mutex_unlock(*mutex); }
#define QEMU_LOCK_GUARD(mutex) \
    __attribute__((cleanup(fixture_unlock_guard))) pthread_mutex_t *fixture_guard = \
        fixture_lock_guard(mutex)

static void fixture_notify_aio(void)
{
    g_assert_cmpint(eventfd_write(aio_fd, 1), ==, 0);
}

static void aio_notify(void *context) { fixture_notify_aio(); }
static bool rr_crucible_sim_quantum_dispatch_fence(void) { return true; }
static bool rr_crucible_sim_wake_boundary_pending(void) { return false; }
static bool rr_crucible_sim_external_main_loop_work_pending(void)
{
    return qatomic_load_acquire(&rr_external_main_loop_work_published) !=
           qatomic_load_acquire(&rr_external_main_loop_work_completed);
}
static void trace_crucible_sim_main_loop_poll_ready(uint64_t generation,
                                                   int result, int64_t timeout)
{ g_assert_cmpint(result, >, 0); }
static int qemu_get_thread_id(void) { return 0; }
static void trace_crucible_sim_rr_dispatch_ceiling_wait(int id, void *value,
                                                       size_t size)
{
    pthread_mutex_lock(&fixture_state);
    rr_parks++;
    pthread_cond_broadcast(&fixture_changed);
    pthread_mutex_unlock(&fixture_state);
}
static void replay_mutex_lock(void)
{ g_assert_cmpint(pthread_mutex_lock(&fixture_replay), ==, 0); }
static void replay_mutex_unlock(void)
{ g_assert_cmpint(pthread_mutex_unlock(&fixture_replay), ==, 0); }
static void rr_replay_mutex_lock(void)
{
    g_assert_false(rr_replay_mutex_owned);
    replay_mutex_lock();
    rr_replay_mutex_owned = true;
}
static void rr_replay_mutex_unlock(void)
{
    if (rr_replay_mutex_owned) {
        replay_mutex_unlock();
        rr_replay_mutex_owned = false;
    }
}
static void bql_lock(void)
{
    g_assert_cmpint(pthread_mutex_lock(&fixture_bql), ==, 0);
    locked = true;
}
static void bql_unlock(void)
{
    locked = false;
    g_assert_cmpint(pthread_mutex_unlock(&fixture_bql), ==, 0);
    if (sdk_arm_gap && current_cpu == &cpu &&
        qemu_plugin_crucible_idle_callback_depth == 1) {
        /* Hold the actor after original unlock, before its original raw wait. */
        pthread_mutex_lock(&fixture_state);
        sdk_unlock_seen = true;
        pthread_cond_broadcast(&fixture_changed);
        while (!source_delivered) {
            pthread_cond_wait(&fixture_changed, &fixture_state);
        }
        pthread_mutex_unlock(&fixture_state);
    }
}
static void qemu_cond_broadcast(void *condition)
{ g_assert_cmpint(pthread_cond_broadcast(&fixture_halt), ==, 0); }
static void qemu_cpu_kick(CPUState *target)
{
    kicks++;
    if (sdk_case) {
        /* Durable CPU work and native idle kick model the original kick edge. */
        qatomic_set(&target->exit_request, true);
        qemu_plugin_crucible_kick_idle_wait(target);
    }
    qemu_cond_broadcast(target->halt_cond);
}
static void qemu_cond_wait_bql(void *condition)
{
    g_assert_true(locked);
    if (idle_case) {
        pthread_mutex_lock(&fixture_state);
        idle_parks++;
        pthread_cond_broadcast(&fixture_changed);
        pthread_mutex_unlock(&fixture_state);
    }
    locked = false;
    g_assert_cmpint(pthread_cond_wait(&fixture_halt, &fixture_bql), ==, 0);
    locked = true;
}
static void hold_epoch_schedule(void)
{
    /* Control only this external schedule; native generations remain untouched. */
    pthread_mutex_lock(&fixture_state);
    epoch_gate_seen = true;
    pthread_cond_broadcast(&fixture_changed);
    while (!epoch_gate_released) {
        pthread_cond_wait(&fixture_changed, &fixture_state);
    }
    pthread_mutex_unlock(&fixture_state);
}

static void qemu_plugin_control_drain_notify(void)
{
    if (qemu_plugin_control_drain_callback_depth == 0 && control_calls) {
        callback_return_notifications++;
    }
    if (two_epochs && qemu_plugin_control_drain_callback_depth == 0) {
        unsigned returned = qatomic_load_acquire(
            &qemu_plugin_control_boundary_generation);

        pthread_mutex_lock(&fixture_state);
        epoch_callback_returns = returned;
        pthread_cond_broadcast(&fixture_changed);
        pthread_mutex_unlock(&fixture_state);
        if (returned == 2 && !two_epochs_handoff) {
            /* The actual registered callback returned before this notification. */
            hold_epoch_schedule();
        }
    }
}
/* This composition never enters network, stop or timer provider branches. */
static void emit_batch(void) { g_assert_not_reached(); }
static void finish_stop(void) { g_assert_not_reached(); }
static void service_events(void) { g_assert_not_reached(); }
static int qemu_plugin_control_drain_wake_state(void)
{
    struct pollfd descriptor = { original_fd, POLLIN, 0 };
    int result = poll(&descriptor, 1, 0);
    g_assert_cmpint(result, >=, 0);
    return result == 0 ? 0 : 1;
}
static void aio_set_fd_handler(void *context, int fd,
    void (*reader)(void *), void *write_cb, void *poll_cb,
    void *poll_ready_cb, void *opaque)
{
    g_assert_null(registered_reader);
    g_assert_cmpint(fd, ==, original_fd);
    registered_reader = reader;
    registered_opaque = opaque;
}
static ssize_t fixture_read(int fd, void *buffer, size_t size)
{
    ssize_t result = read(fd, buffer, size);
    if (fd == original_fd && result > 0) {
        reader_bytes += result;
    } else if (fd == original_fd && result < 0 && errno == EAGAIN) {
        reader_drains++;
    }
    return result;
}
#define read fixture_read
"""

CHECKS = r"""
#undef read
static void release_pump(void *opaque)
{
    /* External bridge-owner transition, not another callback or doorbell. */
    pump_ready = pump_cleared = true;
}

static void observe_control(unsigned int index, uint64_t raw, void *opaque)
{
    g_assert_true(locked);
    g_assert_null(current_cpu);
    g_assert_cmpuint(raw, ==, 17);
    g_assert_cmpuint(qemu_plugin_rr_control_request_generation, ==, 1);
    g_assert_cmpuint(qemu_plugin_rr_control_ack_generation, ==, 1);
    g_assert_cmpuint(qemu_plugin_rr_control_complete_generation, ==, 1);
    g_assert_cmpuint(qemu_plugin_control_drain_callback_depth, ==, 1);
    control_calls++;
    if (refuse_first && control_calls == 1) {
        g_assert_false(pump_ready);
        aio_bh_schedule_oneshot(NULL, release_pump, NULL);
        return;
    }
    g_assert_true(pump_ready);
    shared_ack = shared_request + 1;
}

static void dispatch_slice(void)
{
    QEMUBH slice[G_N_ELEMENTS(events)];
    unsigned count = event_write;

    memcpy(slice, events, count * sizeof(*slice));
    event_write = 0;
    while (count) {
        QEMUBH bh = slice[--count];
        bh.callback(bh.opaque);
    }
}

static void *main_loop(void *opaque)
{
    locked = false;
    current_cpu = NULL;
    while (!qatomic_load_acquire(&fixture_finished)) {
        struct pollfd descriptors[] = {
            { original_fd, POLLIN, 0 }, { aio_fd, POLLIN, 0 }
        };
        int result = poll(descriptors, 2, -1);
        g_assert_cmpint(result, >, 0);
        if (qatomic_load_acquire(&fixture_finished)) {
            break;
        }

        /* Native poll-ready publication precedes both admission locks. */
        rr_crucible_sim_main_loop_poll_ready(result, -1);
        if (force_handoff && (descriptors[0].revents & POLLIN) &&
            !source_delivered) {
            /* Control scheduling only: let RR claim the real ready source. */
            while (qatomic_load_acquire(&rr_main_loop_dispatch_requested) == 0) {
                sched_yield();
            }
        }
        if (two_epochs && reader_calls == 1 &&
            (descriptors[0].revents & POLLIN)) {
            /* Require an actual ready-source RR handoff for the middle epoch. */
            while (qatomic_load_acquire(&rr_main_loop_dispatch_requested) == 0) {
                sched_yield();
            }
        }
        replay_mutex_lock();
        bql_lock();
        if (descriptors[0].revents & POLLIN) {
            reader_calls++;
            registered_reader(registered_opaque);
            pthread_mutex_lock(&fixture_state);
            source_delivered = true;
            pthread_cond_broadcast(&fixture_changed);
            pthread_mutex_unlock(&fixture_state);
        }
        if (descriptors[1].revents & POLLIN) {
            eventfd_t value;
            g_assert_cmpint(eventfd_read(aio_fd, &value), ==, 0);
        }
        MainLoopPoll poll_state = { .state = MAIN_LOOP_POLL_OK };
        rr_crucible_sim_main_loop_poll(NULL, &poll_state);
        dispatch_slice();
        poll_state.state = MAIN_LOOP_POLL_DONE;
        rr_crucible_sim_main_loop_poll(NULL, &poll_state);
        bql_unlock();
        replay_mutex_unlock();
        if (two_epochs_handoff &&
            qatomic_load_acquire(&qemu_plugin_control_boundary_generation) == 2) {
            /* Gate the external loop after the original pass releases its locks. */
            hold_epoch_schedule();
        }
        rr_crucible_sim_main_loop_replay_released();
    }
    return NULL;
}

static void observe_sdk_idle(unsigned int index, uint64_t raw, void *opaque)
{
    g_assert_cmpuint(index, ==, 0);
    g_assert_cmpuint(raw, ==, 17);
    g_assert_true(locked);
    g_assert_cmpuint(qemu_plugin_crucible_idle_callback_depth, ==, 1);
    sdk_status = qemu_plugin_crucible_wait_idle_wake(index, &sdk_wake_signal, 0);
}

static void *rr_owner(void *opaque)
{
    locked = false;
    current_cpu = &cpu;
    if (sdk_case) {
        bql_lock();
        qatomic_store_release(&sdk_thread_id, syscall(SYS_gettid));
        QemuPluginCrucibleIdleCallbackDisposition disposition =
            qemu_plugin_fire_vcpu_idle_cb(&cpu);
        g_assert_cmpint(disposition, ==, QEMU_PLUGIN_CRUCIBLE_IDLE_CALLBACK_RESCAN);
        g_assert_true(sdk_status == QEMU_PLUGIN_CRUCIBLE_IDLE_WAIT_WOKEN ||
                      sdk_status == QEMU_PLUGIN_CRUCIBLE_IDLE_WAIT_VALUE_CHANGED);
        g_assert_cmpuint(sdk_pin_calls, ==, 1);
        g_assert_cmpuint(sdk_unpin_calls, ==, 1);
        g_assert_null(qemu_plugin_crucible_active_idle_wake_signal);
        g_assert_cmpuint(qemu_plugin_crucible_idle_callback_depth, ==, 0);
    } else if (idle_case) {
        QemuPluginCrucibleIdleWaitProduction wait = {
            .cpu = &cpu, .vcpu_index = 0, .cpu_list_generation = 7,
        };
        uint64_t target = 0;
        bool target_bound = false;

        /* rr_wait_io_event enters the idle callback without replay ownership. */
        bql_lock();
        g_assert_false(rr_replay_mutex_owned);
        g_assert_true(cpu.halted);
        g_assert_cmpuint(raw_icount, <, idle_deadline);
        /* The SDK's original nested loop, not a second manual callback. */
        while (qemu_plugin_crucible_idle_wait_for_control_boundary(
                   &wait, 0, &target, &target_bound)) {
        }
        g_assert_true(target_bound);
        g_assert_cmpuint(target, ==, 1);
    } else {
        rr_replay_mutex_lock();
        bql_lock();
        rr_crucible_sim_wait_at_dispatch_ceiling();
        g_assert_true(qemu_plugin_crucible_rr_control_boundary_pending());
        /* Exact outer-loop order: release replay ownership before RR claim/wait. */
        rr_replay_mutex_unlock();
        rr_crucible_sim_acknowledge_control_boundary();
    }
    g_assert_cmpuint(raw_icount, ==, 17);
    g_assert_false(qemu_plugin_crucible_control_boundary_outstanding());
    bql_unlock();
    pthread_mutex_lock(&fixture_state);
    rr_finished = true;
    pthread_cond_broadcast(&fixture_changed);
    pthread_mutex_unlock(&fixture_state);
    return NULL;
}

static void await_sdk_futex_park(void)
{
    /* Observe only this owned actor's actual kernel syscall, not native authority. */
    for (unsigned attempt = 0; attempt < 100000; attempt++) {
        long tid = qatomic_load_acquire(&sdk_thread_id);
        char path[80], line[256];
        long number;
        unsigned long address, operation, expected;
        if (tid == 0) {
            sched_yield();
            continue;
        }
        g_assert_cmpint(snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall", tid), >, 0);
        FILE *file = fopen(path, "r");
        g_assert_nonnull(file);
        char *read_result = fgets(line, sizeof(line), file);
        g_assert_cmpint(fclose(file), ==, 0);
        if (read_result && sscanf(line, "%ld %lx %lx %lx", &number, &address,
                                 &operation, &expected) == 4 &&
            number == SYS_futex && address == (uintptr_t)&sdk_wake_signal &&
            operation == FUTEX_WAIT && expected == 0) {
            return;
        }
        sched_yield();
    }
    g_error("owned SDK actor did not enter its original FUTEX_WAIT");
}


/* Modeled shared request/ACK only; delivery uses the original registered native C. */
static void observe_epoch_control(unsigned int index, uint64_t raw, void *opaque)
{
    uint32_t token = qatomic_load_acquire(&shared_request);

    g_assert_true(locked);
    g_assert_null(current_cpu);
    g_assert_cmpuint(raw, ==, 17);
    g_assert_cmpuint(qemu_plugin_control_drain_callback_depth, ==, 1);
    g_assert_cmpuint(control_calls, <, G_N_ELEMENTS(epoch_observed_tokens));
    epoch_observed_tokens[control_calls++] = token;
    if (token & 1) {
        g_assert_cmpuint(token, ==, 3301);
        epoch_no_request++;
        return;
    }

    g_assert_true(token == 3300 || token == 3302);
    g_assert_cmpuint(qatomic_load_acquire(&shared_ack), ==, token);
    qatomic_store_release(&shared_ack, token + 1);
    qatomic_store_release(&shared_request, token + 1);
    epoch_settled++;
}

static void *epoch_rr_owner(void *opaque)
{
    locked = false;
    current_cpu = &cpu;
    bql_lock();
    qatomic_store_release(&sdk_thread_id, syscall(SYS_gettid));
    QemuPluginCrucibleIdleCallbackDisposition disposition =
        qemu_plugin_fire_vcpu_idle_cb(&cpu);

    g_assert_cmpint(disposition, ==, QEMU_PLUGIN_CRUCIBLE_IDLE_CALLBACK_RESCAN);
    g_assert_true(sdk_status == QEMU_PLUGIN_CRUCIBLE_IDLE_WAIT_WOKEN ||
                  sdk_status == QEMU_PLUGIN_CRUCIBLE_IDLE_WAIT_VALUE_CHANGED);
    g_assert_cmpuint(control_calls, ==, 1);
    g_assert_null(qemu_plugin_crucible_active_idle_wake_signal);
    g_assert_cmpuint(sdk_pin_calls, ==, 1);
    g_assert_cmpuint(sdk_unpin_calls, ==, 1);

    /* Re-enter the original outer RR ordering after the SDK releases its wait. */
    bql_unlock();
    rr_replay_mutex_lock();
    bql_lock();
    pthread_mutex_lock(&fixture_state);
    epoch_rr_outer_ready = true;
    pthread_cond_broadcast(&fixture_changed);
    pthread_mutex_unlock(&fixture_state);
    while (control_calls < 3) {
        rr_crucible_sim_wait_at_dispatch_ceiling();
        if (qemu_plugin_crucible_rr_control_boundary_pending()) {
            rr_replay_mutex_unlock();
            rr_crucible_sim_acknowledge_control_boundary();
            bql_unlock();
            rr_replay_mutex_lock();
            bql_lock();
        }
    }
    rr_replay_mutex_unlock();
    g_assert_false(qemu_plugin_crucible_control_boundary_outstanding());
    bql_unlock();
    return NULL;
}

static void wake_modeled_scheduler(void)
{
    qatomic_fetch_add(&sdk_wake_signal, 1);
    g_assert_cmpint(qemu_futex(&sdk_wake_signal, FUTEX_WAKE, 1,
                             NULL, NULL, 0), >=, 0);
}

static void ring_epoch_doorbell(void)
{
    host_writes++;
    g_assert_cmpint(eventfd_write(original_fd, 1), ==, 0);
}

static void run_two_epochs(pthread_t *rr_thread)
{
    qatomic_store_release(&shared_request, 3300);
    qatomic_store_release(&shared_ack, 3300);
    g_assert_cmpint(pthread_create(rr_thread, NULL, epoch_rr_owner, NULL), ==, 0);
    await_sdk_futex_park();
    wake_modeled_scheduler();
    ring_epoch_doorbell();

    pthread_mutex_lock(&fixture_state);
    while (!epoch_rr_outer_ready || epoch_callback_returns < 1) {
        pthread_cond_wait(&fixture_changed, &fixture_state);
    }
    pthread_mutex_unlock(&fixture_state);
    g_assert_cmpuint(qatomic_load_acquire(&shared_request), ==, 3301);

    /* A distinct constructed notification observes the settled odd request. */
    ring_epoch_doorbell();
    pthread_mutex_lock(&fixture_state);
    while (!epoch_gate_seen) {
        pthread_cond_wait(&fixture_changed, &fixture_state);
    }
    pthread_mutex_unlock(&fixture_state);
    g_assert_cmpuint(qatomic_load_acquire(&shared_request), ==, 3301);

    /* Model the separate same-ceiling wake before publishing the next request. */
    wake_modeled_scheduler();
    g_assert_cmpuint(qatomic_load_acquire(&shared_request), ==, 3301);
    qatomic_store_release(&shared_ack, 3302);
    qatomic_store_release(&shared_request, 3302);
    wake_modeled_scheduler();
    ring_epoch_doorbell();
    pthread_mutex_lock(&fixture_state);
    epoch_gate_released = true;
    pthread_cond_broadcast(&fixture_changed);
    pthread_mutex_unlock(&fixture_state);
    g_assert_cmpint(pthread_join(*rr_thread, NULL), ==, 0);
}

static void verify_two_epochs(const char *name)
{
    g_assert_cmpuint(host_writes, ==, 3);
    g_assert_cmpuint(reader_calls, ==, 3);
    g_assert_cmpuint(reader_bytes, ==, 3 * sizeof(eventfd_t));
    g_assert_cmpuint(reader_drains, ==, 3);
    g_assert_cmpuint(control_calls, ==, 3);
    g_assert_cmpuint(epoch_callback_returns, ==, 3);
    g_assert_cmpuint(epoch_settled, ==, 2);
    g_assert_cmpuint(epoch_no_request, ==, 1);
    g_assert_cmpuint(epoch_observed_tokens[0], ==, 3300);
    g_assert_cmpuint(epoch_observed_tokens[1], ==, 3301);
    g_assert_cmpuint(epoch_observed_tokens[2], ==, 3302);
    g_assert_cmpuint(qatomic_load_acquire(&shared_ack), ==, 3303);
    g_assert_cmpuint(qemu_plugin_rr_control_request_generation, ==, 3);
    g_assert_cmpuint(qemu_plugin_rr_control_ack_generation, ==, 3);
    g_assert_cmpuint(qemu_plugin_rr_control_complete_generation, ==, 3);
    g_assert_cmpuint(qemu_plugin_control_boundary_scheduled, ==, 0);
    g_assert_cmpuint(event_write, ==, 0);
    g_assert_cmpuint(rr_main_loop_dispatch_requested, >=, 1);
    g_assert_cmpuint(rr_main_loop_dispatch_completed, ==,
                     rr_main_loop_dispatch_requested);
    g_assert_cmpuint(rr_main_loop_dispatch_acknowledged, ==,
                     rr_main_loop_dispatch_requested);
    g_assert_false(qemu_plugin_crucible_control_boundary_outstanding());
    printf("case=%s host_writes=3 reader_calls=3 drains=3 callbacks=3 "
           "observed_tokens=3300,3301,3302 settled=2 no_request=1 "
           "modeled_ack=3303 native_epochs=3 handoff=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 " pins=%u/%u\n", name,
           rr_main_loop_dispatch_requested, rr_main_loop_dispatch_completed,
           rr_main_loop_dispatch_acknowledged, sdk_pin_calls, sdk_unpin_calls);
}

int main(int argc, char **argv)
{
    bool before_park = argc == 2 &&
        (strcmp(argv[1], "reader-before-park") == 0 ||
         strcmp(argv[1], "idle-reader-before-park") == 0 ||
         strcmp(argv[1], "sdk-reader-before-arm") == 0);
    pthread_t main_thread, rr_thread;

    g_assert_cmpint(argc, ==, 2);
    two_epochs = strncmp(argv[1], "two-epochs-", 11) == 0;
    two_epochs_handoff = strcmp(argv[1], "two-epochs-before-handoff") == 0;
    sdk_case = two_epochs || strncmp(argv[1], "sdk-reader-", 11) == 0;
    sdk_arm_gap = strcmp(argv[1], "sdk-reader-arm-gap") == 0;
    idle_case = sdk_case || strncmp(argv[1], "idle-reader-", 12) == 0;
    refuse_first = strcmp(argv[1], "pending-settlement") == 0;
    force_handoff = refuse_first || strcmp(argv[1], "reader-after-handoff") == 0;
    pump_ready = !refuse_first;
    locked = false;
    current_cpu = NULL;
    cpu.halt_cond = &fixture_halt;
    cpu.created = cpu.in_list = true;
    cpu.halted = idle_case;
    qemu_plugin_control_boundary_cb = two_epochs ? observe_epoch_control : observe_control;
    qemu_plugin_vcpu_idle_resume_idle_cb = observe_sdk_idle;
    original_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    aio_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    g_assert_cmpint(original_fd, >=, 0);
    g_assert_cmpint(aio_fd, >=, 0);
    qemu_event_init(&rr_dispatch_ceiling_event, false);
    qemu_event_init(&rr_main_loop_resume_event, false);
    rr_dispatch_ceiling_event_initialized = true;
    bql_lock();
    g_assert_cmpint(qemu_plugin_register_wake_fd(original_fd), ==, 0);
    bql_unlock();
    g_assert_nonnull(registered_reader);
    g_assert_cmpint(pthread_create(&main_thread, NULL, main_loop, NULL), ==, 0);

    if (two_epochs) {
        run_two_epochs(&rr_thread);
        qatomic_store_release(&fixture_finished, true);
        fixture_notify_aio();
        g_assert_cmpint(pthread_join(main_thread, NULL), ==, 0);
        verify_two_epochs(argv[1]);
        qemu_event_destroy(&rr_dispatch_ceiling_event);
        qemu_event_destroy(&rr_main_loop_resume_event);
        g_assert_cmpint(close(original_fd), ==, 0);
        g_assert_cmpint(close(aio_fd), ==, 0);
        return 0;
    }
    if (!before_park) {
        g_assert_cmpint(pthread_create(&rr_thread, NULL, rr_owner, NULL), ==, 0);
        if (sdk_case && !sdk_arm_gap) {
            await_sdk_futex_park();
        } else {
            pthread_mutex_lock(&fixture_state);
            while (sdk_arm_gap ? !sdk_unlock_seen :
                   (idle_case ? idle_parks : rr_parks) == 0) {
                pthread_cond_wait(&fixture_changed, &fixture_state);
            }
            pthread_mutex_unlock(&fixture_state);
        }
        if (!idle_case) {
            /* Wait for the real event CAS, not just the earlier trace hook. */
            while (qatomic_load_acquire(&rr_dispatch_ceiling_event.value) !=
                   (unsigned)EV_BUSY) {
                sched_yield();
            }
        }
    }
    host_writes++;
    if (sdk_case) {
        /* Model request_control_boundary's original release increment/wake.
         * The completed-clamp caller also wakes on its preceding same-ceiling
         * publication; this controller needs only the control-request wake. */
        qatomic_fetch_add(&sdk_wake_signal, 1);
        g_assert_cmpint(qemu_futex(&sdk_wake_signal, FUTEX_WAKE, 1, NULL, NULL, 0), >=, 0);
    }
    g_assert_cmpint(eventfd_write(original_fd, 1), ==, 0);
    if (before_park) {
        pthread_mutex_lock(&fixture_state);
        while (!source_delivered) {
            pthread_cond_wait(&fixture_changed, &fixture_state);
        }
        pthread_mutex_unlock(&fixture_state);
        g_assert_cmpint(pthread_create(&rr_thread, NULL, rr_owner, NULL), ==, 0);
    }
    g_assert_cmpint(pthread_join(rr_thread, NULL), ==, 0);
    if (refuse_first) {
        /* Observe the later provider transition through a real AIO slice. */
        bql_lock();
        bool cleared = pump_cleared;
        bql_unlock();
        while (!cleared) {
            sched_yield();
            bql_lock();
            cleared = pump_cleared;
            bql_unlock();
        }
    }
    qatomic_store_release(&fixture_finished, true);
    fixture_notify_aio();
    g_assert_cmpint(pthread_join(main_thread, NULL), ==, 0);
    g_assert_cmpuint(event_write, ==, 0);
    g_assert_false(qemu_plugin_crucible_control_boundary_outstanding());
    g_assert_cmpuint(qemu_plugin_control_boundary_scheduled, ==, 0);
    g_assert_cmpuint(rr_main_loop_dispatch_requested, <=, 1);
    g_assert_cmpuint(rr_main_loop_dispatch_completed, ==,
                     rr_main_loop_dispatch_requested);
    g_assert_cmpuint(rr_main_loop_dispatch_acknowledged, ==,
                     rr_main_loop_dispatch_requested);
    if (force_handoff) {
        g_assert_cmpuint(rr_main_loop_dispatch_requested, ==, 1);
    }
    g_assert_cmpuint(host_writes, ==, 1);
    g_assert_cmpuint(reader_calls, ==, 1);
    g_assert_cmpuint(reader_bytes, ==, sizeof(eventfd_t));
    g_assert_cmpuint(reader_drains, ==, 1);
    g_assert_cmpuint(control_calls, ==, 1);
    g_assert_cmpuint(callback_return_notifications, ==, 1);
    if (sdk_arm_gap) {
        /* The original reader's native kick observed the armed futex word. */
        g_assert_cmpuint(sdk_wake_signal, ==, 2);
    }
    printf("case=%s host_writes=%u reader_calls=%u reader_bytes=%u "
           "drains=%u callbacks=%u native_complete=%" PRIu64 " "
           "modeled_request=%u modeled_ack=%u pump_ready=%d "
           "handoff=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " idle_parks=%u raw=%" PRIu64 " ceiling=%" PRIu64
           " modeled_idle_deadline=%" PRIu64 " sdk_status=%d pins=%u/%u\n",
           argv[1], host_writes, reader_calls, reader_bytes, reader_drains,
           control_calls, qemu_plugin_rr_control_complete_generation,
           shared_request, shared_ack, pump_ready,
           rr_main_loop_dispatch_requested, rr_main_loop_dispatch_completed,
           rr_main_loop_dispatch_acknowledged, idle_parks, raw_icount,
           crucible_sim_shmem_max_advance_icount(), idle_deadline,
           sdk_status, sdk_pin_calls, sdk_unpin_calls);
    fflush(stdout);
    g_assert_cmpuint(shared_ack, ==, shared_request + 1);
    qemu_event_destroy(&rr_dispatch_ceiling_event);
    qemu_event_destroy(&rr_main_loop_resume_event);
    g_assert_cmpint(close(original_fd), ==, 0);
    g_assert_cmpint(close(aio_fd), ==, 0);
    return 0;
}
"""


def replace_definition(text, definition, signature, replacement):
    original = definition(text, signature)
    assert text.count(original) == 1
    return text.replace(original, replacement)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu-source", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case", required=True, choices=["all",
        "reader-before-park", "reader-after-park", "reader-after-handoff",
        "idle-reader-before-park", "idle-reader-after-park",
        "sdk-reader-before-arm", "sdk-reader-arm-gap", "sdk-reader-after-futex",
        "pending-settlement", "two-epochs-after-return", "two-epochs-before-handoff"])
    arguments = parser.parse_args()
    root = arguments.qemu_source.resolve()
    support = runpy.run_path(str(root / "tests/unit/test-crucible-control-deferred.py"))
    definition = support["definition"]
    network = support["SUPPORT"]
    prelude = network["PRELUDE"]
    prelude = prelude.replace("bool running, stop, stopped, unplug, exit_request;",
        "bool running, stop, stopped, unplug, exit_request;\n    bool created, in_list;\n    unsigned interrupt_request;")
    # Match the selected native per-thread callback scope during unlocked waits.
    for name in ("qemu_plugin_crucible_exact_boundary_depth",
                 "qemu_plugin_crucible_control_boundary_depth"):
        prelude = prelude.replace(f"static unsigned {name};",
                                  f"static _Thread_local unsigned {name};")
    prelude = prelude.replace("static CPUState cpu, *first_cpu = &cpu, *current_cpu;",
        "static CPUState cpu, *first_cpu = &cpu;\nstatic _Thread_local CPUState *current_cpu;")
    prelude = prelude.replace("static bool locked = true, self = true, has_control = true, mttcg;",
        "static _Thread_local bool locked = true, self = true;\nstatic bool has_control = true, mttcg;")
    replacements = ["static void replay_mutex_unlock(void)",
        "static void replay_mutex_lock(void)", "static void bql_unlock(void)",
        "static void bql_lock(void)", "static void qemu_cpu_kick(CPUState *target)",
        "static void qemu_cond_broadcast(void *condition)",
        "static bool crucible_sim_shmem_dispatch_registered(void)",
        "static void rr_crucible_sim_notify_dispatch_ceiling(void)",
        "static void qemu_plugin_control_drain_notify(void)"]
    for signature in replacements:
        prelude = replace_definition(prelude, definition, signature, "")
    prelude = prelude.replace("#include <assert.h>",
                              "#include <assert.h>\n#include <inttypes.h>\n#include <sched.h>")
    prelude = prelude.replace("static void tcg_kick_vcpu_thread(CPUState *target)",
        "static void qemu_cpu_kick(CPUState *target);\nstatic void tcg_kick_vcpu_thread(CPUState *target)")
    prelude = prelude.replace("static void aio_bh_schedule_oneshot(void *context, void (*cb)(void *), void *opaque)",
        "static void fixture_notify_aio(void);\nstatic void aio_bh_schedule_oneshot(void *context, void (*cb)(void *), void *opaque)")
    old = "    events[event_write++] = (QEMUBH){cb, opaque};"
    assert prelude.count(old) == 1
    prelude = prelude.replace(old, old + "\n    fixture_notify_aio();")
    extra = support["EXTRA"]
    for signature in ["static void qemu_cond_wait_bql(void *condition)",
                      "static int qemu_plugin_control_drain_wake_state(void)"]:
        extra = replace_definition(extra, definition, signature, "")
    # Unused time-advance branches retain their original explicit-refusal provider.
    bodies = support["production_bodies"]()
    original_bodies_hash = hashlib.sha256(bodies.encode()).hexdigest()
    selections = {
        "util/event.c": ["void qemu_event_init(", "void qemu_event_destroy(",
            "void qemu_event_set(", "void qemu_event_reset(", "void qemu_event_wait("],
        "accel/tcg/tcg-accel-ops-rr.c": [
            "static void rr_crucible_sim_wait_at_dispatch_ceiling(void)",
            "void rr_crucible_sim_notify_dispatch_ceiling(void)",
            "static void rr_crucible_sim_main_loop_poll_ready(",
            "static void rr_crucible_sim_main_loop_poll(Notifier *notifier, void *opaque)",
            "static void rr_crucible_sim_main_loop_replay_released(void)",
            "static uint64_t rr_crucible_sim_begin_main_loop_handoff(void)",
            "static void rr_crucible_sim_finish_main_loop_handoff(uint64_t generation)",
            "static void rr_crucible_sim_handoff_main_loop(void)\n{"],
        "plugins/api-system.c": [
            "int qemu_plugin_register_wake_fd(int fd)",
            "static bool qemu_plugin_crucible_idle_cpu_is_current_member(",
            "static bool qemu_plugin_crucible_idle_wait_for_control_boundary(",
            "void qemu_plugin_crucible_kick_idle_wait(CPUState *cpu)",
            "static void qemu_plugin_crucible_idle_pin_cpu(void *opaque)",
            "static void qemu_plugin_crucible_idle_unpin_cpu(void *opaque)",
            "static bool qemu_plugin_crucible_idle_arm_wait(void *opaque,",
            "static void qemu_plugin_crucible_idle_unlock_bql(void *opaque)",
            "static void qemu_plugin_crucible_idle_lock_bql(void *opaque)",
            "static int qemu_plugin_crucible_idle_raw_wait(",
            "static void qemu_plugin_crucible_idle_disarm_wait(void *opaque)",
            "static bool qemu_plugin_crucible_idle_validate_cpu(void *opaque)"],
        "plugins/crucible-idle-wait.c": [
            "enum qemu_plugin_crucible_idle_wait_status\nqemu_plugin_crucible_idle_wait_once("]}
    extracted = []
    source = (root / "plugins/api-system.c").read_text()
    start = source.index("typedef struct QemuPluginCrucibleIdleWaitProduction {")
    end = source.index("} QemuPluginCrucibleIdleWaitProduction;", start)
    end += len("} QemuPluginCrucibleIdleWaitProduction;")
    bodies += "\n\n" + source[start:end]
    for path, signatures in selections.items():
        source = (root / path).read_text()
        for signature in signatures:
            body = definition(source, signature)
            extracted.append({"path": path, "signature": signature,
                              "sha256": hashlib.sha256(body.encode()).hexdigest()})
            bodies += "\n\n" + body
    bodies = bodies.replace("void rr_crucible_sim_notify_dispatch_ceiling(void)",
                             "static void rr_crucible_sim_notify_dispatch_ceiling(void)")
    # Preserve the exact original table and public SDK callback wrappers.
    api_source = (root / "plugins/api-system.c").read_text()
    table_start = api_source.index("static const QemuPluginCrucibleIdleWaitOps\n")
    table_end = api_source.index("};", table_start) + 2
    bodies += "\n\n" + api_source[table_start:table_end]
    for signature in [
        "enum qemu_plugin_crucible_idle_wait_status\nqemu_plugin_crucible_wait_idle_wake(",
        "QemuPluginCrucibleIdleCallbackDisposition\nqemu_plugin_fire_vcpu_idle_cb("]:
        body = definition(api_source, signature)
        extracted.append({"path": "plugins/api-system.c", "signature": signature,
                          "sha256": hashlib.sha256(body.encode()).hexdigest()})
        bodies += "\n\n" + body
    headers = (root / "include/plugins/qemu-plugin.h").read_text()
    types = definition(headers, "enum qemu_plugin_crucible_idle_wait_status {") + ";\n"
    headers = (root / "include/qemu/plugin.h").read_text()
    start = headers.index("typedef enum QemuPluginCrucibleIdleCallbackDisposition {")
    end = headers.index("} QemuPluginCrucibleIdleCallbackDisposition;", start)
    types += headers[start:end + len("} QemuPluginCrucibleIdleCallbackDisposition;")] + "\n"
    headers = (root / "include/qemu/crucible-idle-wait.h").read_text()
    start = headers.index("typedef struct QemuPluginCrucibleIdleWaitOps {")
    end = headers.index("} QemuPluginCrucibleIdleWaitOps;", start)
    types += headers[start:end + len("} QemuPluginCrucibleIdleWaitOps;")] + "\n"
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    generated = arguments.output_dir / "control-continuation.c"
    # Native event.c obtains platform macros through osdep.h before futex.h.
    # The bounded prelude bypasses osdep.h, so load its original config input.
    platform = '#include "config-host.h"\n#ifndef CONFIG_LINUX\n'
    platform += '#error "The control continuation fixture requires configured Linux"\n#endif\n'
    generated.write_text(platform + prelude + types + EXTRA + extra + bodies + CHECKS)
    extraction = {
        "original_control_deferred_bodies_sha256": original_bodies_hash,
        "additional_bodies": extracted,
        "storage_qualifier_change": "rr_crucible_sim_notify_dispatch_ceiling is static in the standalone fixture; its body is unchanged",
        "providers": [
            "Selected net-output fixture CPU/device and time-advance topology; unused branches abort",
            "Real pthread replay/BQL locks and condition wait; bounded AIO slices replace GLib",
            "Controlled after-handoff schedule delays main-loop lock acquisition until the actual RR ready-source claim; it changes no native predicate",
            "Real kernel eventfd/poll; registration captures the actual selected reader",
            "Idle cases use the actual nested idle control wait and membership helper; one halted CPU, list generation and unchanged raw ceiling are explicit providers",
            "SDK cases execute original idle callback scope, one-shot public wait, arm/disarm, real initial futex wait and kick, then original nested idle wait",
            "Owned /proc/self/task/tid/syscall is only a controlled fixture handshake proving the third SDK actor entered FUTEX_WAIT",
            "Controller release increment and non-private futex wake model NodeSlot.request_control_boundary before its only doorbell; production completed-clamp also has an earlier same-ceiling wake",
            "CPU durable-work/object pin providers and published futex word model external topology/protocol; full Rust idle callback and guest/timer execution remain outside the native fixture",
            "Actual QemuEvent bodies and selected Linux futex header",
            "No active generic wake epoch, queued CPU work, lifecycle stop or guest execution; SDK cases model the durable exit-request wake in their CPU kick provider",
            "Scalar modeled shared request/ack and bridge readiness; no Rust bridge or shared-memory proof",
            "Two-epoch schedules gate only the external callback-return notification or main-loop release seam; native generations are never written by the test",
            "Two successful shared requests3300/3302 include a constructed third doorbell observing odd3301; this is not a physical3998 notification attribution",
        ],
    }
    (arguments.output_dir / "extracted-bodies.json").write_text(json.dumps(extraction, indent=2) + "\n")
    binary = arguments.output_dir / "control-continuation"
    command = [os.environ["CC"], *shlex.split(os.environ.get("CFLAGS", "")),
        "-Wno-missing-prototypes", "-Wno-unused-function", "-Wno-unused-variable",
        str(generated), "-o", str(binary), *shlex.split(os.environ.get("LDFLAGS", ""))]
    (arguments.output_dir / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    subprocess.run(command, check=True)
    if arguments.case != "all":
        subprocess.run([str(binary), arguments.case], cwd=arguments.output_dir,
                       check=True, timeout=10)
        return

    for case in ("reader-before-park", "reader-after-park", "reader-after-handoff",
                 "idle-reader-before-park", "idle-reader-after-park",
                 "sdk-reader-before-arm", "sdk-reader-arm-gap", "sdk-reader-after-futex",
                 "two-epochs-after-return", "two-epochs-before-handoff"):
        result = subprocess.run([str(binary), case], cwd=arguments.output_dir,
                                capture_output=True, text=True, check=True, timeout=10)
        (arguments.output_dir / f"{case}.stdout").write_text(result.stdout)
        (arguments.output_dir / f"{case}.stderr").write_text(result.stderr)
        print(result.stdout, end="")
        print(f"NATIVE_CONTROL_DELIVERY_PASS case={case}")

    # A void callback promises delivery, not completion of the modeled bridge.
    # Keep this contract experiment separate from the native delivery cases.
    result = subprocess.run([str(binary), "pending-settlement"],
                            cwd=arguments.output_dir, capture_output=True,
                            text=True, check=False, timeout=10)
    (arguments.output_dir / "pending-settlement.stdout").write_text(result.stdout)
    (arguments.output_dir / "pending-settlement.stderr").write_text(result.stderr)
    rows = [line for line in result.stdout.splitlines()
            if line.startswith("case=pending-settlement ")]
    if (result.returncode != -signal.SIGABRT or len(rows) != 1
            or "modeled_ack=54008 " not in rows[0]
            or "assertion failed (shared_ack == shared_request + 1)" not in result.stderr):
        raise SystemExit("conditional refusal did not reach its original ACK assertion")
    print(rows[0])
    print("CONDITIONAL_SETTLEMENT_REFUSAL_PASS: modeled bridge only; no native retry contract")


if __name__ == "__main__":
    main()
