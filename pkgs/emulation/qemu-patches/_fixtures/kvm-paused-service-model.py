"""Compile original paused CPU service and producer boundaries with real threads.

The CPU/device roster and BQL interfaces are explicit test plumbing. Real pthread
locking, actual extracted source transitions and actual child exit are exercised;
this cannot qualify KVM hardware, complete devices or the installed node runtime.
"""

from pathlib import Path
import json
import re
import subprocess
import sys


def function(body, name):
    declaration = re.search(
        r"^(?:static )?(?:G_NORETURN )?(?:bool|int|void) " + name + r"\(",
        body,
        re.M,
    )
    if declaration is None:
        raise ValueError(f"missing actual source function {name}")
    end = body.index("\n}\n", declaration.start()) + 3
    return body[declaration.start():end] + "\n"


def record(body, name):
    declaration = body.index("struct " + name + " {")
    beginning = body.rfind("\n", 0, declaration) + 1
    end = body.index(";", body.index("\n}", declaration)) + 1
    return body[beginning:end] + "\n"


PREFIX = r'''
/* Source extraction and thread plumbing, never native KVM qualification. */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qemu/queue.h"

typedef pthread_mutex_t QemuMutex;
typedef pthread_cond_t QemuCond;
typedef struct CPUState CPUState;
typedef union run_on_cpu_data { void *host_ptr; } run_on_cpu_data;
typedef void (*run_on_cpu_func)(CPUState *, run_on_cpu_data);
typedef int (*QemuCpuPausedServiceFunc)(CPUState *, uint64_t, uint64_t);
@SLOT@
@WORK@
struct CPUState {
    int cpu_index;
    bool created, stopped, unplug, stop, halted, thread_kicked, exit_request;
    QemuMutex work_mutex;
    QSIMPLEQ_HEAD(, qemu_work_item) work_list;
    QemuCpuPausedService crucible_paused_service;
    QemuCond *halt_cond;
    bool crucible_node_ingress_armed, crucible_node_work_tracking;
    uint64_t crucible_node_next_work_id;
};

static CPUState native_cpu;
static QemuMutex bql = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qemu_work_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t qemu_pause_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t halt_cond = PTHREAD_COND_INITIALIZER;
static _Thread_local CPUState *current_cpu;
static _Thread_local bool has_bql;
static unsigned device_callbacks, ordinary_callbacks, kicks;
static int callback_result;
static bool hold_callback, hold_ordinary, run_event_wait;
static int started[2], release_callback[2];

#define G_NORETURN __attribute__((noreturn))
#define g_assert(condition) assert(condition)
#define g_new0(type, count) calloc(count, sizeof(type))
#define g_free(pointer) free(pointer)
#define QEMU_CPU_NODE_INGRESS_WORK 1

static void qemu_mutex_lock(QemuMutex *mutex)
{
    assert(pthread_mutex_lock(mutex) == 0);
}

static void qemu_mutex_unlock(QemuMutex *mutex)
{
    assert(pthread_mutex_unlock(mutex) == 0);
}

static bool bql_locked(void) { return has_bql; }
static void bql_lock(void) { qemu_mutex_lock(&bql); has_bql = true; }
static void bql_unlock(void) { has_bql = false; qemu_mutex_unlock(&bql); }
static bool qemu_cpu_is_self(CPUState *cpu) { return current_cpu == cpu; }
#define qatomic_load_acquire(pointer) __atomic_load_n(pointer, __ATOMIC_ACQUIRE)
#define qatomic_store_release(pointer, value) \
    __atomic_store_n(pointer, value, __ATOMIC_RELEASE)
#define qatomic_set(pointer, value) __atomic_store_n(pointer, value, __ATOMIC_RELAXED)
#define qatomic_set_mb(pointer, value) __atomic_store_n(pointer, value, __ATOMIC_SEQ_CST)
#define qatomic_read(pointer) __atomic_load_n(pointer, __ATOMIC_RELAXED)

static void error_report(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
    fflush(stderr);
}

static void qemu_cpu_kick(CPUState *cpu)
{
    assert(cpu == &native_cpu);
    kicks++;
    assert(pthread_cond_broadcast(cpu->halt_cond) == 0);
}
static void cpu_exit(CPUState *cpu) { assert(cpu == &native_cpu); }
static bool node_ingress_owned(CPUState *cpu) { abort(); }
static bool qemu_cpu_node_source_failed(void) { abort(); }
static void node_ingress_fault_locked(CPUState *cpu, uint32_t kind,
                                      uint32_t code, uint64_t payload,
                                      struct qemu_work_item *work)
{
    /* These tests never enroll the unrelated SIM ingress interface. */
    abort();
}

static void start_exclusive(void) {}
static void end_exclusive(void) {}
static void qemu_cond_broadcast(pthread_cond_t *condition)
{
    assert(pthread_cond_broadcast(condition) == 0);
}

static void qemu_cond_wait(pthread_cond_t *condition, QemuMutex *mutex)
{
    assert(pthread_cond_wait(condition, mutex) == 0);
}

static bool cpu_is_stopped(CPUState *cpu) { return cpu->stopped; }
static bool cpu_has_work(CPUState *cpu) { return false; }
static struct { bool (*cpu_thread_is_idle)(CPUState *); } model_accel;
static typeof(model_accel) *cpus_accel = &model_accel;
static void qemu_plugin_vcpu_idle_cb(CPUState *cpu) {}
static void qemu_plugin_vcpu_resume_cb(CPUState *cpu) {}
'''

TESTS = r'''
static void ordinary(CPUState *cpu, run_on_cpu_data data)
{
    char marker;

    assert(cpu == &native_cpu);
    ordinary_callbacks++;
    if (hold_ordinary) {
        assert(write(started[1], "O", 1) == 1);
        assert(read(release_callback[0], &marker, 1) == 1);
    }
    puts("ORDINARY_CALLBACK_EXECUTED");
    fflush(stdout);
}

static int device(CPUState *cpu, uint64_t operation_id, uint64_t sequence)
{
    char marker;

    assert(cpu == &native_cpu && qemu_cpu_is_self(cpu));
    assert(!bql_locked());
    assert(operation_id == cpu->crucible_paused_service.operation_id);
    assert(sequence == cpu->crucible_paused_service.exit_sequence);
    device_callbacks++;
    if (hold_callback) {
        assert(write(started[1], "S", 1) == 1);
        assert(read(release_callback[0], &marker, 1) == 1);
    }
    return callback_result;
}

static void reset(void)
{
    memset(&native_cpu, 0, sizeof(native_cpu));
    assert(pthread_mutex_init(&native_cpu.work_mutex, NULL) == 0);
    QSIMPLEQ_INIT(&native_cpu.work_list);
    device_callbacks = ordinary_callbacks = kicks = 0;
    callback_result = 0;
    hold_callback = false;
    hold_ordinary = false;
    run_event_wait = false;
    native_cpu.halt_cond = &halt_cond;
    native_cpu.cpu_index = 2;
    assert(qemu_cpu_paused_service_enroll(&native_cpu, 71, device) == 0);
    native_cpu.created = native_cpu.stopped = true;
}

static void *worker(void *argument)
{
    current_cpu = &native_cpu;
    bql_lock();
    process_queued_cpu_work(&native_cpu);
    if (run_event_wait) {
        assert(write(started[1], "D", 1) == 1);
        qemu_process_cpu_events(&native_cpu);
    }
    bql_unlock();
    current_cpu = NULL;
    return NULL;
}

static void execute_original(void)
{
    pthread_t thread;

    bql_unlock();
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    bql_lock();
}

static int collect(void)
{
    int result = -100;

    assert(qemu_cpu_paused_service_collect(&native_cpu, 71, 1, 19, &result) == 0);
    return result;
}

static void units(void)
{
    int result;
    char marker;
    pthread_t thread;

    reset();
    assert(qemu_cpu_paused_service_enroll(&native_cpu, 71, device) == -EBUSY);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 72, 1, 19) == -EINVAL);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 0, 19) == -EINVAL);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 0) == -EINVAL);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 2, 19) == -ESTALE);

    native_cpu.stopped = false;
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == -EINVAL);
    native_cpu.stopped = true;
    native_cpu.crucible_paused_service.ordinary_depth = 1;
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == -EBUSY);
    native_cpu.crucible_paused_service.ordinary_depth = 0;

    /* A real ordinary callback can be running after its queue became empty.
     * Its protected depth must still refuse service admission while BQL is
     * released, without waiting for that callback under BQL. */
    assert(pipe(started) == 0 && pipe(release_callback) == 0);
    hold_ordinary = true;
    async_safe_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    bql_unlock();
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    assert(read(started[0], &marker, 1) == 1);
    bql_lock();
    assert(QSIMPLEQ_EMPTY(&native_cpu.work_list));
    assert(native_cpu.crucible_paused_service.ordinary_depth == 1);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == -EBUSY);
    assert(write(release_callback[1], "R", 1) == 1);
    bql_unlock();
    assert(pthread_join(thread, NULL) == 0);
    bql_lock();
    hold_ordinary = false;
    assert(close(started[0]) == 0 && close(started[1]) == 0);
    assert(close(release_callback[0]) == 0 && close(release_callback[1]) == 0);

    async_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == -EBUSY);
    execute_original();
    assert(ordinary_callbacks == 2 && device_callbacks == 0);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == 0);
    assert(qatomic_load_acquire(&native_cpu.crucible_paused_service.pending));
    assert(kicks == 1);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 20) == -ESTALE);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 2, 20) == -EBUSY);
    assert(qemu_cpu_paused_service_collect(&native_cpu, 71, 1, 19, &result) == -EAGAIN);

    execute_original();
    assert(device_callbacks == 1 && ordinary_callbacks == 2);
    assert(native_cpu.crucible_paused_service.active);
    assert(collect() == 0);
    assert(!native_cpu.crucible_paused_service.active);
    assert(cpu_work_list_empty(&native_cpu) && cpu_thread_is_idle(&native_cpu));
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == 0);
    execute_original();
    assert(collect() == 0 && device_callbacks == 1);

    callback_result = -EIO;
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 2, 20) == 0);
    execute_original();
    assert(qemu_cpu_paused_service_collect(&native_cpu, 71, 2, 20, &result) == 0);
    assert(result == -EIO && native_cpu.crucible_paused_service.active);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 3, 21) == -EBUSY);
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 2, 20) == 0);
    execute_original();
    assert(device_callbacks == 2);

    /* Original unconfigured producer execution remains ordinary. */
    memset(&native_cpu.crucible_paused_service, 0,
           sizeof(native_cpu.crucible_paused_service));
    current_cpu = &native_cpu;
    do_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 }, &bql);
    current_cpu = NULL;
    async_safe_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    execute_original();
    assert(ordinary_callbacks == 4);

    reset();
    assert(pipe(started) == 0 && pipe(release_callback) == 0);
    hold_callback = run_event_wait = true;
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == 0);
    bql_unlock();
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    assert(read(started[0], &marker, 1) == 1 && marker == 'S');
    bql_lock();
    /* Genuine source idle observers must not mistake pending=false for an
     * idle CPU while the original callback executes outside BQL. */
    assert(!qatomic_load_acquire(&native_cpu.crucible_paused_service.pending));
    assert(!cpu_work_list_empty(&native_cpu) && !cpu_thread_is_idle(&native_cpu));
    assert(write(release_callback[1], "R", 1) == 1);
    bql_unlock();
    assert(read(started[0], &marker, 1) == 1 && marker == 'D');
    bql_lock();
    assert(native_cpu.crucible_paused_service.done);
    assert(!cpu_work_list_empty(&native_cpu) && !cpu_thread_is_idle(&native_cpu));
    native_cpu.stop = true;
    assert(collect() == 0);
    bql_unlock();
    assert(pthread_join(thread, NULL) == 0);
    bql_lock();
    assert(!native_cpu.stop && native_cpu.stopped);
    assert(cpu_work_list_empty(&native_cpu) && cpu_thread_is_idle(&native_cpu));
    assert(kicks == 2); /* Exactly submit and first authentic collection. */
    assert(collect() == 0 && kicks == 2);
    assert(close(started[0]) == 0 && close(started[1]) == 0);
    assert(close(release_callback[0]) == 0 && close(release_callback[1]) == 0);
    puts("Actual extracted slot/thread transitions PASS; native qualification absent");
}

static void fatal(const char *boundary)
{
    char marker;
    pthread_t thread;

    reset();
    assert(qemu_cpu_paused_service_submit(&native_cpu, 71, 1, 19) == 0);
    if (!strcmp(boundary, "queued")) {
        async_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    } else if (!strcmp(boundary, "safe-queued")) {
        async_safe_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    } else if (!strcmp(boundary, "direct")) {
        current_cpu = &native_cpu;
        do_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 }, &bql);
    } else if (!strcmp(boundary, "teardown")) {
        free_queued_cpu_work(&native_cpu);
    } else if (!strcmp(boundary, "inflight")) {
        assert(pipe(started) == 0 && pipe(release_callback) == 0);
        hold_callback = true;
        bql_unlock();
        assert(pthread_create(&thread, NULL, worker, NULL) == 0);
        assert(read(started[0], &marker, 1) == 1);
        bql_lock();
        assert(native_cpu.crucible_paused_service.executing);
        assert(!cpu_work_list_empty(&native_cpu) && !cpu_thread_is_idle(&native_cpu));
        async_run_on_cpu(&native_cpu, ordinary, (run_on_cpu_data){ 0 });
    } else {
        abort();
    }
    /* Any producer that returned or dispatched would falsely report success. */
    puts("CONFLICT_RETURNED_AS_SUCCESS");
    fflush(stdout);
    exit(0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    bql_lock();
    if (!strcmp(argv[1], "units")) {
        units();
    } else {
        fatal(argv[1]);
    }
    bql_unlock();
    return 0;
}
'''


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: slot-model.py QEMU_SOURCE AOS_CC OUTPUT_DIR")
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    output.mkdir(parents=True, exist_ok=True)
    common = (source / "cpu-common.c").read_text()
    events = (source / "system/cpus.c").read_text()
    header = (source / "include/hw/core/cpu.h").read_text()
    names = [
        "paused_service_conflict_locked",
        "qemu_cpu_paused_service_reclaim_guard",
        "paused_service_work_begin_locked",
        "paused_service_work_end_locked",
        "qemu_cpu_paused_service_enroll",
        "qemu_cpu_paused_service_submit",
        "qemu_cpu_paused_service_collect",
        "paused_service_process",
        "queue_work_on_cpu",
        "do_run_on_cpu",
        "async_run_on_cpu",
        "async_safe_run_on_cpu",
        "free_queued_cpu_work",
        "process_queued_cpu_work",
    ]
    original_notice = common[:common.index('#include "qemu/osdep.h"')]
    generated = original_notice + PREFIX.replace(
        "@SLOT@", record(header, "QemuCpuPausedService")
    ).replace("@WORK@", record(common, "qemu_work_item"))
    generated += "\n".join(function(common, name) for name in names)
    generated += "\n".join(function(events, name) for name in [
        "cpu_work_list_empty", "cpu_thread_is_idle", "qemu_cpu_stop",
        "qemu_process_cpu_events_common", "qemu_process_cpu_events",
    ]) + TESTS
    (output / "slot.c").write_text(generated)
    binary = output / "slot"
    subprocess.run(
        [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-parameter", "-pthread", "-I", str(source / "include"),
         str(output / "slot.c"), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary), "units"], check=True, timeout=20)

    # Explicit host-side custody model: an actual child handle is retained until
    # wait authenticates death; its immutable original request is never replaced
    # with NoEffects or a fresh nonce after a producer conflict.
    original = {
        "nonce": "original/service-slot/operation-1",
        "native_id": 71,
        "operation_id": 1,
        "exit_sequence": 19,
        "grant": {"start": 10, "end": 20},
        "earlier_outputs": ["opaque-original-output"],
    }
    encoded = json.dumps(original, sort_keys=True).encode()
    for boundary in ["queued", "safe-queued", "direct", "teardown", "inflight"]:
        with subprocess.Popen(
            [str(binary), boundary], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as child:
            retained = {"child": child, "original": encoded, "effects": "Unknown"}
            stdout, stderr = child.communicate(timeout=20)
            assert retained["child"] is child and child.returncode == 125
            assert retained["original"] == encoded and retained["effects"] == "Unknown"
            assert b"ORDINARY_CALLBACK_EXECUTED" not in stdout
            assert b"CONFLICT_RETURNED_AS_SUCCESS" not in stdout
            assert b"native=71 operation=1 exit=19" in stderr
            assert b"whole child containment required" in stderr
            print(f"Actual child fault/death {boundary}: original host model custody Unknown")


if __name__ == "__main__":
    main()
