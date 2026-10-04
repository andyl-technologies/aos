# SPDX-License-Identifier: GPL-2.0-or-later
"""Compose selected native control bodies across a real unchanged-ceiling park.

The selected QEMU fixture supplies bounded CPU/device topology. This extension
executes its genuine registered reader, control generation/scheduling bodies,
running RR ceiling wait and claim, poll-ready handoff, and QemuEvent algorithm.
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
static unsigned rr_parks, callback_return_notifications;
static bool rr_finished, source_delivered, pump_ready, pump_cleared;
static bool refuse_first, force_handoff, fixture_finished;
static uint32_t shared_request = 54008, shared_ack = 54008;

static void rr_crucible_sim_handoff_main_loop(void);
static void rr_crucible_sim_notify_dispatch_ceiling(void);
static void qemu_plugin_wake_fd_read(void *opaque);

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
}
static void qemu_cond_broadcast(void *condition)
{ g_assert_cmpint(pthread_cond_broadcast(&fixture_halt), ==, 0); }
static void qemu_cpu_kick(CPUState *target)
{ kicks++; qemu_cond_broadcast(target->halt_cond); }
static void qemu_cond_wait_bql(void *condition)
{
    g_assert_true(locked);
    locked = false;
    g_assert_cmpint(pthread_cond_wait(&fixture_halt, &fixture_bql), ==, 0);
    locked = true;
}
static void qemu_plugin_control_drain_notify(void)
{
    if (qemu_plugin_control_drain_callback_depth == 0 && control_calls) {
        callback_return_notifications++;
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
        rr_crucible_sim_main_loop_replay_released();
    }
    return NULL;
}

static void *rr_owner(void *opaque)
{
    locked = false;
    current_cpu = &cpu;
    rr_replay_mutex_lock();
    bql_lock();
    rr_crucible_sim_wait_at_dispatch_ceiling();
    g_assert_true(qemu_plugin_crucible_rr_control_boundary_pending());
    /* Exact outer-loop order: release replay ownership before RR claim/wait. */
    rr_replay_mutex_unlock();
    rr_crucible_sim_acknowledge_control_boundary();
    g_assert_cmpuint(raw_icount, ==, 17);
    g_assert_false(qemu_plugin_crucible_control_boundary_outstanding());
    bql_unlock();
    pthread_mutex_lock(&fixture_state);
    rr_finished = true;
    pthread_cond_broadcast(&fixture_changed);
    pthread_mutex_unlock(&fixture_state);
    return NULL;
}

int main(int argc, char **argv)
{
    bool before_park = argc == 2 && strcmp(argv[1], "reader-before-park") == 0;
    pthread_t main_thread, rr_thread;

    g_assert_cmpint(argc, ==, 2);
    refuse_first = strcmp(argv[1], "pending-settlement") == 0;
    force_handoff = refuse_first || strcmp(argv[1], "reader-after-handoff") == 0;
    pump_ready = !refuse_first;
    locked = false;
    current_cpu = NULL;
    cpu.halt_cond = &fixture_halt;
    qemu_plugin_control_boundary_cb = observe_control;
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

    if (!before_park) {
        g_assert_cmpint(pthread_create(&rr_thread, NULL, rr_owner, NULL), ==, 0);
        pthread_mutex_lock(&fixture_state);
        while (rr_parks == 0) {
            pthread_cond_wait(&fixture_changed, &fixture_state);
        }
        pthread_mutex_unlock(&fixture_state);
        /* Wait for the real event CAS, not just the earlier trace hook. */
        while (qatomic_load_acquire(&rr_dispatch_ceiling_event.value) !=
               (unsigned)EV_BUSY) {
            sched_yield();
        }
    }
    host_writes++;
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
    printf("case=%s host_writes=%u reader_calls=%u reader_bytes=%u "
           "drains=%u callbacks=%u native_complete=%" PRIu64 " "
           "modeled_request=%u modeled_ack=%u pump_ready=%d "
           "handoff=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
           argv[1], host_writes, reader_calls, reader_bytes, reader_drains,
           control_calls, qemu_plugin_rr_control_complete_generation,
           shared_request, shared_ack, pump_ready,
           rr_main_loop_dispatch_requested, rr_main_loop_dispatch_completed,
           rr_main_loop_dispatch_acknowledged);
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
        "pending-settlement"])
    arguments = parser.parse_args()
    root = arguments.qemu_source.resolve()
    support = runpy.run_path(str(root / "tests/unit/test-crucible-control-deferred.py"))
    definition = support["definition"]
    network = support["SUPPORT"]
    prelude = network["PRELUDE"]
    prelude = prelude.replace("static CPUState cpu, *first_cpu = &cpu, *current_cpu;",
        "static CPUState cpu, *first_cpu = &cpu;\nstatic _Thread_local CPUState *current_cpu;")
    prelude = prelude.replace("static bool locked = true, self = true, has_control = true, mttcg;",
        "static _Thread_local bool locked = true, self = true;\nstatic bool has_control = true, mttcg;")
    replacements = ["static void replay_mutex_unlock(void)",
        "static void replay_mutex_lock(void)", "static void bql_unlock(void)",
        "static void bql_lock(void)", "static void qemu_cpu_kick(CPUState *target)",
        "static void qemu_cond_broadcast(void *condition)",
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
        "plugins/api-system.c": ["int qemu_plugin_register_wake_fd(int fd)"]}
    extracted = []
    for path, signatures in selections.items():
        source = (root / path).read_text()
        for signature in signatures:
            body = definition(source, signature)
            extracted.append({"path": path, "signature": signature,
                              "sha256": hashlib.sha256(body.encode()).hexdigest()})
            bodies += "\n\n" + body
    bodies = bodies.replace("void rr_crucible_sim_notify_dispatch_ceiling(void)",
                             "static void rr_crucible_sim_notify_dispatch_ceiling(void)")
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    generated = arguments.output_dir / "control-continuation.c"
    generated.write_text(prelude + EXTRA + extra + bodies + CHECKS)
    extraction = {
        "original_control_deferred_bodies_sha256": original_bodies_hash,
        "additional_bodies": extracted,
        "storage_qualifier_change": "rr_crucible_sim_notify_dispatch_ceiling is static in the standalone fixture; its body is unchanged",
        "providers": [
            "Selected net-output fixture CPU/device and time-advance topology; unused branches abort",
            "Real pthread replay/BQL locks and condition wait; bounded AIO slices replace GLib",
            "Controlled after-handoff schedule delays main-loop lock acquisition until the actual RR ready-source claim; it changes no native predicate",
            "Real kernel eventfd/poll; registration captures the actual selected reader",
            "Actual QemuEvent bodies and selected Linux futex header",
            "No active generic wake epoch, CPU work, lifecycle stop or guest execution",
            "Scalar modeled shared request/ack and bridge readiness; no Rust bridge or shared-memory proof",
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

    for case in ("reader-before-park", "reader-after-park", "reader-after-handoff"):
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
