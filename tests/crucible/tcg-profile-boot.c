/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Diagnostic-only boot interval sampling; no QEMU headers or private APIs. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Preserve the proven worker registration and inherited SIGPROF handling. */
#include "tcg-profile-threads.c"

extern void ProfilerStop(void);
extern int ProfilingIsEnabledForAllThreads(void);

typedef ssize_t (*SendMessage)(int, const struct msghdr *, int);

static const unsigned char boot_marker[] = "\nCRUCIBLE_TCG_BOOT_READY_V1\n";
static SendMessage real_send_message;
static pthread_once_t serial_resolve_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t serial_write_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int inside_serial_write;
static char serial_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static char report_path[4096];
static size_t marker_prefix[sizeof(boot_marker) - 1];
static size_t marker_position;
static uint64_t serial_bytes;
static unsigned int marker_count;
static int profiler_stopped;

static void boot_profile_fatal(const char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    abort();
}

static uint64_t monotonic_ns(void)
{
    struct timespec timestamp;

    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
        boot_profile_fatal("boot profiler: monotonic clock failed");
    }
    return (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
           (uint64_t)timestamp.tv_nsec;
}

static void resolve_serial_hook(void)
{
    const char *configured_socket = getenv("TCG_PROFILE_BOOT_SOCKET");
    const char *configured_report = getenv("TCG_PROFILE_BOOT_REPORT");
    const size_t marker_length = sizeof(boot_marker) - 1;

    real_send_message = (SendMessage)dlsym(RTLD_NEXT, "sendmsg");
    if (!real_send_message) {
        boot_profile_fatal("boot profiler: unable to resolve sendmsg");
    }
    if (!configured_socket || !configured_report ||
        strlen(configured_socket) >= sizeof(serial_path) ||
        strlen(configured_report) >= sizeof(report_path)) {
        boot_profile_fatal("boot profiler: missing or overlong diagnostic paths");
    }
    strcpy(serial_path, configured_socket);
    strcpy(report_path, configured_report);

    /* Prefix fallback also recognizes adjacent tokens sharing a newline. */
    for (size_t index = 1, matched = 0; index < marker_length; index++) {
        while (matched && boot_marker[index] != boot_marker[matched]) {
            matched = marker_prefix[matched - 1];
        }
        if (boot_marker[index] == boot_marker[matched]) {
            matched++;
        }
        marker_prefix[index] = matched;
    }
}

static int is_serial_socket(int descriptor)
{
    struct sockaddr_un address;
    socklen_t length = sizeof(address);
    const size_t path_offset = offsetof(struct sockaddr_un, sun_path);

    memset(&address, 0, sizeof(address));
    if (getsockname(descriptor, (struct sockaddr *)&address, &length) != 0 ||
        address.sun_family != AF_UNIX || length <= path_offset ||
        length > sizeof(address) || address.sun_path[0] == '\0') {
        return 0;
    }
    size_t path_length = length - path_offset;
    if (address.sun_path[path_length - 1] == '\0') {
        path_length--;
    }
    return strlen(serial_path) == path_length &&
           memcmp(address.sun_path, serial_path, path_length) == 0;
}

static unsigned int consume_serial_bytes(const unsigned char *bytes, size_t length)
{
    const size_t marker_length = sizeof(boot_marker) - 1;
    unsigned int completed = 0;

    for (size_t index = 0; index < length; index++) {
        while (marker_position && bytes[index] != boot_marker[marker_position]) {
            marker_position = marker_prefix[marker_position - 1];
        }
        if (bytes[index] == boot_marker[marker_position]) {
            marker_position++;
        }
        if (marker_position == marker_length) {
            completed++;
            marker_position = marker_prefix[marker_length - 1];
        }
    }
    return completed;
}

static void record_stop(uint64_t emission_return, uint64_t stop_entry,
                        uint64_t stop_return, int enabled_before, int enabled_after)
{
    char record[1024];
    int length = snprintf(record, sizeof(record),
                          "{\"marker_count\":%u,\"successful_serial_bytes\":%llu,"
                          "\"emission_return_ns\":%llu,\"stop_entry_ns\":%llu,"
                          "\"stop_return_ns\":%llu,\"enabled_before\":%d,"
                          "\"enabled_after\":%d,\"disable_ns_exact\":null,"
                          "\"disable_ns_bounds\":[%llu,%llu]}\n",
                          marker_count, (unsigned long long)serial_bytes,
                          (unsigned long long)emission_return,
                          (unsigned long long)stop_entry,
                          (unsigned long long)stop_return,
                          enabled_before, enabled_after,
                          (unsigned long long)stop_entry,
                          (unsigned long long)stop_return);
    if (length <= 0 || (size_t)length >= sizeof(record)) {
        boot_profile_fatal("boot profiler: invalid stop telemetry");
    }
    int descriptor = open(report_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        boot_profile_fatal("boot profiler: cannot create exclusive stop telemetry");
    }
    size_t written = 0;
    while (written < (size_t)length) {
        ssize_t result = write(descriptor, record + written, (size_t)length - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            boot_profile_fatal("boot profiler: cannot write stop telemetry");
        }
        written += (size_t)result;
    }
    if (close(descriptor) != 0) {
        boot_profile_fatal("boot profiler: cannot close stop telemetry");
    }
}

ssize_t sendmsg(int descriptor, const struct msghdr *message, int flags)
{
    int incoming_errno = errno;

    pthread_once(&serial_resolve_once, resolve_serial_hook);
    if (inside_serial_write || !is_serial_socket(descriptor)) {
        errno = incoming_errno;
        return real_send_message(descriptor, message, flags);
    }

    /* This private pthread mutex never enters QEMU's registered lock inventory.
     * Holding it across the write preserves successful byte ordering between
     * concurrent callers. The reentrancy bypass keeps profiler output independent.
     */
    inside_serial_write = 1;
    if (pthread_mutex_lock(&serial_write_lock) != 0) {
        boot_profile_fatal("boot profiler: serial hook lock failed");
    }
    errno = incoming_errno;
    ssize_t result = real_send_message(descriptor, message, flags);
    int outgoing_errno = errno;

    if (result > 0) {
        uint64_t emission_return = monotonic_ns();
        size_t remaining = (size_t)result;
        unsigned int completed = 0;

        /* A short send commits only its successful prefix, across all iovecs. */
        for (size_t index = 0; index < message->msg_iovlen && remaining; index++) {
            size_t length = message->msg_iov[index].iov_len;
            if (length > remaining) {
                length = remaining;
            }
            completed += consume_serial_bytes(message->msg_iov[index].iov_base, length);
            remaining -= length;
        }
        if (remaining || UINT64_MAX - serial_bytes < (uint64_t)result) {
            boot_profile_fatal("boot profiler: inconsistent successful byte count");
        }
        serial_bytes += (uint64_t)result;
        marker_count += completed;
        if (marker_count > 1) {
            boot_profile_fatal("boot profiler: duplicate serial marker");
        }
        if (completed && !profiler_stopped) {
            int enabled_before = ProfilingIsEnabledForAllThreads();
            uint64_t stop_entry = monotonic_ns();

            ProfilerStop();
            uint64_t stop_return = monotonic_ns();
            int enabled_after = ProfilingIsEnabledForAllThreads();
            profiler_stopped = 1;
            record_stop(emission_return, stop_entry, stop_return,
                        enabled_before, enabled_after);
            if (!enabled_before || enabled_after) {
                boot_profile_fatal("boot profiler: unexpected profiler phase state");
            }
        }
    }

    if (pthread_mutex_unlock(&serial_write_lock) != 0) {
        boot_profile_fatal("boot profiler: serial hook unlock failed");
    }
    inside_serial_write = 0;
    errno = outgoing_errno;
    return result;
}
