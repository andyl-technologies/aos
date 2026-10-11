/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Exercise the actual hook with synthetic send results and native sockets. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "tcg-profile-boot.c"

static int profiler_enabled = 1;
static unsigned int stop_calls;
static size_t successful_prefix;
static int synthetic_error;
static int reentrant_descriptor = -1;
static atomic_uint registered_threads;

void ProfilerRegisterThread(void)
{
    atomic_fetch_add(&registered_threads, 1);
}

int ProfilingIsEnabledForAllThreads(void)
{
    return profiler_enabled;
}

void ProfilerStop(void)
{
    stop_calls++;
    profiler_enabled = 0;
    if (reentrant_descriptor >= 0) {
        struct iovec vector = { .iov_base = (void *)"tail", .iov_len = 4 };
        struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1 };

        assert(sendmsg(reentrant_descriptor, &message, MSG_NOSIGNAL) == 4);
    }
}

static ssize_t synthetic_send(int descriptor, const struct msghdr *message, int flags)
{
    size_t length = 0;

    (void)descriptor;
    assert(flags == MSG_NOSIGNAL);
    if (synthetic_error) {
        errno = synthetic_error;
        return -1;
    }
    for (size_t index = 0; index < message->msg_iovlen; index++) {
        length += message->msg_iov[index].iov_len;
    }
    if (successful_prefix && successful_prefix < length) {
        length = successful_prefix;
    }
    errno = ERANGE;
    return (ssize_t)length;
}

static ssize_t send_bytes(int descriptor, const void *bytes, size_t length)
{
    struct iovec vector = { .iov_base = (void *)bytes, .iov_len = length };
    struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1 };

    return sendmsg(descriptor, &message, MSG_NOSIGNAL);
}

static int bound_socket(const char *path)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int descriptor = socket(AF_UNIX, SOCK_DGRAM, 0);

    assert(descriptor >= 0);
    assert(strlen(path) < sizeof(address.sun_path));
    strcpy(address.sun_path, path);
    assert(bind(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0);
    return descriptor;
}

static void reset_case(void)
{
    marker_position = 0;
    marker_count = 0;
    serial_bytes = 0;
    profiler_stopped = 0;
    profiler_enabled = 1;
    stop_calls = 0;
    successful_prefix = 0;
    synthetic_error = 0;
    reentrant_descriptor = -1;
    if (unlink(report_path) != 0) {
        assert(errno == ENOENT);
    }
}

static void *masked_worker(void *unused)
{
    sigset_t mask;

    (void)unused;
    assert(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0);
    assert(sigismember(&mask, SIGPROF) == 0);
    assert(sigismember(&mask, SIGUSR1) == 1);
    return NULL;
}

static void *concurrent_writer(void *opaque)
{
    int descriptor = *(int *)opaque;

    assert(send_bytes(descriptor, "noise", 5) == 5);
    return NULL;
}

int main(void)
{
    char directory[] = "/tmp/tcg-boot-hook-XXXXXX";
    char target_path[108], wrong_path[108], telemetry[256];
    const size_t marker_length = sizeof(boot_marker) - 1;

    assert(mkdtemp(directory));
    assert(snprintf(target_path, sizeof(target_path), "%s/serial", directory) > 0);
    assert(snprintf(wrong_path, sizeof(wrong_path), "%s/other", directory) > 0);
    assert(snprintf(telemetry, sizeof(telemetry), "%s/stop.json", directory) > 0);
    assert(setenv("TCG_PROFILE_BOOT_SOCKET", target_path, 1) == 0);
    assert(setenv("TCG_PROFILE_BOOT_REPORT", telemetry, 1) == 0);
    pthread_once(&serial_resolve_once, resolve_serial_hook);
    real_send_message = synthetic_send;
    int target = bound_socket(target_path);
    int wrong = bound_socket(wrong_path);

    /* A complete marker on another socket must never end profiling. */
    reset_case();
    assert(send_bytes(wrong, boot_marker, marker_length) == (ssize_t)marker_length);
    assert(marker_count == 0 && serial_bytes == 0 && stop_calls == 0);

    /* An unsuccessful call cannot commit bytes or change the syscall errno. */
    reset_case();
    synthetic_error = EAGAIN;
    assert(send_bytes(target, boot_marker, marker_length) == -1);
    assert(errno == EAGAIN);
    assert(marker_count == 0 && serial_bytes == 0 && stop_calls == 0);

    /* Successful short writes consume only the returned prefix. */
    reset_case();
    successful_prefix = 4;
    assert(send_bytes(target, boot_marker, marker_length) == 4);
    assert(errno == ERANGE && serial_bytes == 4 && stop_calls == 0);
    successful_prefix = 0;
    assert(send_bytes(target, boot_marker + 4, marker_length - 4) ==
           (ssize_t)marker_length - 4);
    assert(errno == ERANGE && serial_bytes == marker_length && stop_calls == 1);
    assert(marker_count == 1 && profiler_stopped && !profiler_enabled);

    /* Split tokens across multiple iovecs and calls use the same recognizer. */
    reset_case();
    struct iovec vectors[] = {
        { .iov_base = (void *)boot_marker, .iov_len = 3 },
        { .iov_base = (void *)(boot_marker + 3), .iov_len = 8 },
        { .iov_base = (void *)(boot_marker + 11), .iov_len = marker_length - 11 },
    };
    struct msghdr message = { .msg_iov = vectors, .msg_iovlen = 3 };
    successful_prefix = marker_length - 1;
    assert(sendmsg(target, &message, MSG_NOSIGNAL) == (ssize_t)marker_length - 1);
    assert(stop_calls == 0);
    successful_prefix = 0;
    assert(send_bytes(target, boot_marker + marker_length - 1, 1) == 1);
    assert(stop_calls == 1 && marker_count == 1);
    assert(send_bytes(target, "ordinary tail", 13) == 13);
    assert(stop_calls == 1);

    /* Prefix mismatch fallback and profiler I/O reentrancy cannot deadlock. */
    reset_case();
    assert(send_bytes(target, "\nCRUCIBLE_BAD_PREFIX", 19) == 19);
    reentrant_descriptor = target;
    assert(send_bytes(target, boot_marker, marker_length) == (ssize_t)marker_length);
    assert(stop_calls == 1 && marker_count == 1);
    assert(serial_bytes == 19 + marker_length);

    /* Concurrent successful writers cannot corrupt the stream recognizer. */
    reset_case();
    pthread_t writers[2];
    for (size_t index = 0; index < 2; index++) {
        assert(pthread_create(&writers[index], NULL, concurrent_writer, &target) == 0);
    }
    for (size_t index = 0; index < 2; index++) {
        assert(pthread_join(writers[index], NULL) == 0);
    }
    assert(serial_bytes == 10 && stop_calls == 0);
    assert(send_bytes(target, boot_marker, marker_length) == (ssize_t)marker_length);
    assert(serial_bytes == 10 + marker_length && stop_calls == 1);

    /* Duplicate tokens fail closed rather than silently qualifying a profile. */
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct rlimit no_core = { 0, 0 };

        assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
        reset_case();
        assert(send_bytes(target, boot_marker, marker_length) == (ssize_t)marker_length);
        (void)send_bytes(target, boot_marker, marker_length);
        _exit(2);
    }
    int child_status;
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGABRT);

    /* Worker inheritance preserves non-sampling masks and registers once. */
    pthread_t worker;
    sigset_t blocked, original;
    atomic_store(&registered_threads, 0);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPROF);
    sigaddset(&blocked, SIGUSR1);
    assert(pthread_sigmask(SIG_BLOCK, &blocked, &original) == 0);
    assert(pthread_create(&worker, NULL, masked_worker, NULL) == 0);
    assert(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(atomic_load(&registered_threads) == 1);

    assert(close(target) == 0 && close(wrong) == 0);
    assert(unlink(target_path) == 0 && unlink(wrong_path) == 0);
    assert(unlink(telemetry) == 0 && rmdir(directory) == 0);
    puts("PASS: successful bytes, split markers, wrong FD, errno, reentrancy and worker masks");
    return 0;
}
