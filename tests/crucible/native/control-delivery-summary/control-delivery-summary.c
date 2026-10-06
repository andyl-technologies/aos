/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private actual-body diagnostic controls; no guest or full RR owner proof. */
#include "config-host.h"
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qemu/atomic.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#ifndef CONFIG_LINUX
#error "This private diagnostic fixture requires configured Linux"
#endif

/* BQL custody is modeled by a real mutex and its per-thread owned flag. */
static pthread_mutex_t fixture_bql = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool fixture_locked;
static unsigned fixture_owner_reads, fixture_state_reads;
static int rr_tcg_exec_state = 2;
static bool fixture_mode = true;
static uint64_t qemu_plugin_rr_control_request_generation;
static uint64_t qemu_plugin_rr_control_ack_generation;
static uint64_t qemu_plugin_rr_control_complete_generation;
static uintptr_t qemu_plugin_control_boundary_scheduled;
static uintptr_t qemu_plugin_rr_control_schedule_token;
static uintptr_t qemu_plugin_control_boundary_schedule_sequence;
static bool qemu_plugin_control_boundary_deferred;
static unsigned marker_cancels, drain_invalidations, boundary_traces;
static unsigned write_calls;
static int write_result;

static bool bql_locked(void)
{
    return fixture_locked;
}

static bool rr_crucible_sim_mode(void)
{
    return fixture_mode;
}

static uint64_t icount_crucible_rr_current_vcpu(void)
{
    g_assert_true(fixture_locked);
    fixture_owner_reads++;
    return 7;
}

static unsigned runstate_get(void)
{
    g_assert_true(fixture_locked);
    fixture_state_reads++;
    return 4;
}

/* Only the final write endpoint is fault-injected; real FD checks stay intact. */
static ssize_t fixture_write(int fd, const void *buffer, size_t bytes)
{
    write_calls++;
    if (write_result < 0) {
        errno = EINTR;
        return -1;
    }
    if (write_result > 0) {
        return write(fd, buffer, MIN(bytes, (size_t)write_result));
    }
    return write(fd, buffer, bytes);
}

void rr_crucible_sim_control_summary_configure(void);
bool rr_crucible_sim_control_summary_enabled(void);
void rr_crucible_sim_control_summary_dump(
    uint64_t request, uint64_t ack, uint64_t complete,
    uintptr_t rr_token, uintptr_t token, bool deferred);
void qemu_plugin_crucible_rr_control_boundary_cancel(void);

#define write fixture_write
#include "control-delivery-summary-native.inc"
#undef write

/* The RR trace endpoint is an explicit provider calling the actual cache body. */
static void rr_crucible_sim_trace_control_delivery(
    const char *phase, uint64_t request, uint64_t ack, uint64_t complete,
    uintptr_t rr_token, uintptr_t token, bool deferred, uintptr_t sequence)
{
    (void)sequence;
    rr_control_summary_retain(phase, request, ack, complete,
                              rr_token, token, deferred);
}

static void qemu_crucible_fault_lifecycle_ready_marker_cancel(void)
{
    marker_cancels++;
}

static void qemu_plugin_control_drain_invalidate(void)
{
    drain_invalidations++;
}

static void rr_crucible_sim_trace_control_boundary(
    const char *phase, uint64_t request, uint64_t ack, uint64_t complete,
    uintptr_t token)
{
    g_assert_cmpstr(phase, ==, "cancel");
    g_assert_cmpuint(request, ==, ack);
    g_assert_cmpuint(request, ==, complete);
    g_assert_cmpuint(token, ==, 9);
    boundary_traces++;
}

#include "control-delivery-summary-cancel.inc"

static void initialize(void)
{
    g_assert_cmpint(pthread_mutex_lock(&fixture_bql), ==, 0);
    fixture_locked = true;
    qemu_plugin_rr_control_request_generation = 3302;
    qemu_plugin_rr_control_ack_generation = 1;
    qemu_plugin_rr_control_complete_generation = 1;
    qemu_plugin_control_boundary_scheduled = 9;
    qemu_plugin_rr_control_schedule_token = 9;
    qemu_plugin_control_boundary_deferred = true;
    errno = EDOM;
    rr_crucible_sim_control_summary_configure();
    g_assert_cmpint(errno, ==, EDOM);
}

static void assert_original_cancel(void)
{
    g_assert_cmpuint(qemu_plugin_rr_control_ack_generation, ==, 3302);
    g_assert_cmpuint(qemu_plugin_rr_control_complete_generation, ==, 3302);
    g_assert_cmpuint(qemu_plugin_control_boundary_scheduled, ==, 0);
    g_assert_cmpuint(qemu_plugin_rr_control_schedule_token, ==, 0);
    g_assert_false(qemu_plugin_control_boundary_deferred);
    g_assert_cmpuint(marker_cancels, ==, 1);
    g_assert_cmpuint(drain_invalidations, ==, 1);
    g_assert_cmpuint(boundary_traces, ==, 1);
}

static void cancel(void)
{
    errno = EDOM;
    qemu_plugin_crucible_rr_control_boundary_cancel();
    g_assert_cmpint(errno, ==, EDOM);
    assert_original_cancel();
}

static void *foreign_thread(void *unused)
{
    (void)unused;
    g_assert_false(bql_locked());
    errno = ECHILD;
    rr_crucible_sim_control_summary_configure();
    rr_control_summary_retain("request", 10, 9, 9, 1, 1, false);
    rr_crucible_sim_control_summary_dump(10, 9, 9, 1, 1, false);
    g_assert_cmpint(errno, ==, ECHILD);
    return NULL;
}

static void foreign_control(void)
{
    pthread_t thread;
    g_assert_cmpint(pthread_create(&thread, NULL, foreign_thread, NULL), ==, 0);
    g_assert_cmpint(pthread_join(thread, NULL), ==, 0);
    g_assert_true(rr_control_summary.enabled);
    g_assert_cmpuint(rr_control_summary.observations, ==, 0);
    g_assert_cmpuint(write_calls, ==, 0);
    g_assert_cmpuint(fixture_owner_reads, ==, 0);
    g_assert_cmpuint(fixture_state_reads, ==, 0);
    cancel();
}

static void fixed_cache_control(void)
{
    unsigned round, phase;
    for (round = 0; round < 1000; round++) {
        for (phase = 0; phase < ARRAY_SIZE(rr_control_summary_phases); phase++) {
            rr_control_summary_retain(rr_control_summary_phases[phase],
                UINT64_MAX, UINT64_MAX, UINT64_MAX, UINTPTR_MAX,
                UINTPTR_MAX, true);
        }
    }
    g_assert_cmpuint(rr_control_summary.observations, ==, 12000);
    cancel();
    g_assert_cmpuint(write_calls, ==, 1);
    unsigned reads = fixture_owner_reads;
    rr_control_summary_retain("request", 0, 0, 0, 0, 0, false);
    rr_crucible_sim_control_summary_dump(0, 0, 0, 0, 0, false);
    g_assert_cmpuint(write_calls, ==, 1);
    g_assert_cmpuint(fixture_owner_reads, ==, reads);
}

static void width_control(void)
{
    RRControlSummarySample sample = {
        .observation = UINT64_MAX,
        .request = UINT64_MAX,
        .ack = UINT64_MAX,
        .complete = UINT64_MAX,
        .rr_token = UINTPTR_MAX,
        .token = UINTPTR_MAX,
        .owner = UINT64_MAX,
        .state = UINT_MAX,
        .runstate = UINT_MAX,
        .deferred = true,
        .available = true,
    };
    char row[RR_CONTROL_SUMMARY_MAX_ROW_BYTES + 1];
    size_t bytes = 0;
    unsigned phase;

    for (phase = 0; phase < ARRAY_SIZE(rr_control_summary_phases); phase++) {
        g_assert_true(rr_control_summary_format_row(
            row, sizeof(row), "latest", rr_control_summary_phases[phase],
            &sample, INT_MAX, &bytes));
        g_assert_cmpuint(bytes, <=, RR_CONTROL_SUMMARY_MAX_ROW_BYTES);
        g_assert_cmpint(row[bytes - 1], ==, '\n');
        g_assert_cmpint(row[bytes], ==, 0);
    }
    g_assert_false(rr_control_summary_format_row(
        row, 1, "latest", "claim", &sample, INT_MAX, &bytes));
    cancel();
}

static void fork_control(void)
{
    cancel();
    g_assert_true(rr_control_summary.dumped);
    pid_t child = fork();
    g_assert_cmpint(child, >=, 0);
    if (child == 0) {
        /* No native generations reset: only actual PID binds a new cache. */
        rr_control_summary_retain("request", 3302, 3302, 3302, 0, 0, false);
        g_assert_cmpint(rr_control_summary.pid, ==, getpid());
        g_assert_cmpuint(rr_control_summary.observations, ==, 1);
        rr_crucible_sim_control_summary_dump(3302, 3302, 3302, 0, 0, false);
        g_assert_cmpuint(write_calls, ==, 2);
        _exit(0);
    }
    int status;
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
    g_assert_cmpuint(write_calls, ==, 1);
}

static void sink_control(const char *mode)
{
    int original = dup(STDERR_FILENO);
    g_assert_cmpint(original, >=, 0);
    if (strcmp(mode, "pipe") == 0) {
        int descriptors[2];
        g_assert_cmpint(pipe(descriptors), ==, 0);
        g_assert_cmpint(dup2(descriptors[1], STDERR_FILENO), ==, STDERR_FILENO);
        close(descriptors[1]);
        cancel();
        g_assert_cmpuint(write_calls, ==, 0);
        g_assert_cmpint(dup2(original, STDERR_FILENO), ==, STDERR_FILENO);
        char byte;
        g_assert_cmpint(read(descriptors[0], &byte, 1), ==, 0);
        close(descriptors[0]);
    } else if (strcmp(mode, "readonly") == 0) {
        /* Open the same owned regular file read-only through the original FD. */
        int readonly = open("/proc/self/fd/2", O_RDONLY);
        g_assert_cmpint(readonly, >=, 0);
        g_assert_cmpint(dup2(readonly, STDERR_FILENO), ==, STDERR_FILENO);
        close(readonly);
        cancel();
        g_assert_cmpuint(write_calls, ==, 0);
        g_assert_cmpint(dup2(original, STDERR_FILENO), ==, STDERR_FILENO);
    } else {
        g_assert_cmpstr(mode, ==, "closed");
        close(STDERR_FILENO);
        cancel();
        g_assert_cmpuint(write_calls, ==, 0);
        g_assert_cmpint(dup2(original, STDERR_FILENO), ==, STDERR_FILENO);
    }
    close(original);
    rr_crucible_sim_control_summary_dump(0, 0, 0, 0, 0, false);
    g_assert_cmpuint(write_calls, ==, 0);
}

int main(int argc, char **argv)
{
    g_assert_cmpint(argc, ==, 2);
    const char *mode = argv[1];
    initialize();
    if (strcmp(mode, "default") == 0 || strcmp(mode, "invalid") == 0 ||
        strcmp(mode, "not-sim") == 0) {
        if (strcmp(mode, "not-sim") == 0) {
            fixture_mode = false;
            rr_crucible_sim_control_summary_configure();
        }
        g_assert_false(rr_control_summary.enabled);
        cancel();
        g_assert_cmpuint(fixture_owner_reads, ==, 0);
        g_assert_cmpuint(fixture_state_reads, ==, 0);
        g_assert_cmpuint(rr_control_summary.observations, ==, 0);
        g_assert_cmpuint(write_calls, ==, 0);
    } else if (strcmp(mode, "foreign") == 0) {
        foreign_control();
    } else if (strcmp(mode, "fixed-cache") == 0) {
        fixed_cache_control();
    } else if (strcmp(mode, "width") == 0) {
        width_control();
    } else if (strcmp(mode, "fork") == 0) {
        fork_control();
    } else if (strcmp(mode, "pipe") == 0 || strcmp(mode, "readonly") == 0 ||
               strcmp(mode, "closed") == 0) {
        sink_control(mode);
    } else {
        if (strcmp(mode, "interrupted-write") == 0) {
            write_result = -1;
        } else if (strcmp(mode, "short-write") == 0) {
            write_result = 2;
        } else {
            g_assert_cmpstr(mode, ==, "pre-cancel");
        }
        qemu_plugin_trace_control_delivery("request");
        cancel();
        g_assert_cmpuint(write_calls, ==, 1);
        qemu_plugin_crucible_rr_control_boundary_cancel();
        g_assert_cmpuint(write_calls, ==, 1);
        g_assert_cmpuint(marker_cancels, ==, 2);
        g_assert_cmpuint(drain_invalidations, ==, 2);
        g_assert_cmpuint(boundary_traces, ==, 1);
        g_assert_cmpuint(qemu_plugin_rr_control_complete_generation, ==, 3302);
    }
    fixture_locked = false;
    g_assert_cmpint(pthread_mutex_unlock(&fixture_bql), ==, 0);
    printf("CONTROL_SUMMARY_PASS case=%s\n", mode);
    return 0;
}
