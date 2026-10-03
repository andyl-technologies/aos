/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed specimen-only filter reader. The retained Rust owner must hold the
 * original deployment cut and exclude another eligible specimen generation.
 * A pidfd alone cannot make numeric PTRACE_SEIZE atomic. Kernel MAC permits
 * this principal to trace only the two isolated specimen types, never a
 * production nspawn/guest type. No PID/path/command selector is accepted.
 *
 * This child owns every trace stop it creates. EXITKILL fences child death;
 * failures retain the original deployment IDs for quarantine, never adoption.
 * No memory/register read/write, generic signal, credential or signing API.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "collector_identity.h"

#if !defined(__x86_64__)
#error "installed specimen filter artifact is reviewed only for x86_64"
#endif
#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER 0x420c
#endif
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

#define QUERY_BYTES 144U
#define STACK_LIMIT 65536U
#define REPLY_HEADER 80U
#define FILTER_LIMIT 32U
#define INSTRUCTION_LIMIT 4096U
#define SPECIMEN_CGROUP "/aos.slice/aos-sandboxes.slice/aos-sandbox-55555555555555555555555555555555.service"
#define PIDFD_INFO UINT32_C(0xc048ff0b)

/* Exact Linux pidfs ABI already used by aos-sandbox-linux. */
struct process_info {
    uint64_t mask, cgroup;
    uint32_t pid, tgid, ppid, ruid, rgid, euid, egid;
    uint32_t suid, sgid, fsuid, fsgid;
    int32_t exit_code;
    uint32_t coredump, spare;
};
_Static_assert(sizeof(struct process_info) == 72, "pidfs v1 ABI");
_Static_assert(sizeof(struct sock_filter) == 8, "classic BPF ABI");

static uint32_t get32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16
        | (uint32_t)bytes[2] << 8 | bytes[3];
}

static uint64_t get64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index)
        value = value << 8 | bytes[index];
    return value;
}

static void put32(uint8_t *bytes, uint32_t value)
{
    for (size_t index = 0; index < 4; ++index)
        bytes[3 - index] = (uint8_t)(value >> (index * 8));
}

static void put64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0; index < 8; ++index)
        bytes[7 - index] = (uint8_t)(value >> (index * 8));
}

static int receive_query(uint8_t bytes[QUERY_BYTES], int loans[2], pid_t parent)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(2 * sizeof(int))
            + CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct iovec vector = {.iov_base = bytes, .iov_len = QUERY_BYTES};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct pollfd channel = {.fd = STDIN_FILENO, .events = POLLIN};
    if (poll(&channel, 1, 30000) != 1 || !(channel.revents & POLLIN))
        return -1;
    ssize_t count = recvmsg(STDIN_FILENO, &message, MSG_CMSG_CLOEXEC);
    bool valid = count == QUERY_BYTES && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    size_t rights = 0, credentials = 0, pidfds = 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        size_t offset = (size_t)((uint8_t *)header - control.bytes);
        if (offset > message.msg_controllen
            || header->cmsg_len > message.msg_controllen - offset
            || header->cmsg_len < CMSG_LEN(0)) {
            valid = false;
            break;
        }
        if (header->cmsg_level != SOL_SOCKET) {
            valid = false;
            continue;
        }
        if (header->cmsg_type == SCM_RIGHTS) {
            size_t entries = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int *fds = (int *)CMSG_DATA(header);
            valid &= header->cmsg_len == CMSG_LEN(2 * sizeof(int));
            for (size_t index = 0; index < entries; ++index) {
                if (rights < 2)
                    loans[rights] = fds[index];
                else {
                    close(fds[index]);
                    valid = false;
                }
                ++rights;
            }
        } else if (header->cmsg_type == SCM_CREDENTIALS) {
            struct ucred peer = {0};
            if (header->cmsg_len != CMSG_LEN(sizeof(peer))) {
                valid = false;
                continue;
            }
            memcpy(&peer, CMSG_DATA(header), sizeof(peer));
            valid &= peer.pid == parent && peer.uid == geteuid() && peer.gid == getegid();
            ++credentials;
        } else if (header->cmsg_type == SCM_PIDFD) {
            int pidfd;
            if (header->cmsg_len != CMSG_LEN(sizeof(pidfd))) {
                valid = false;
                continue;
            }
            memcpy(&pidfd, CMSG_DATA(header), sizeof(pidfd));
            close(pidfd);
            ++pidfds;
        } else
            valid = false;
    }
    return valid && rights == 2 && credentials == 1 && pidfds == 1
        && getppid() == parent ? 0 : -1;
}

static int process_start(uint32_t pid, uint64_t *start)
{
    char path[64], stat[4096];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    if (read_text(path, stat, sizeof(stat)) != 0)
        return -1;
    char *field = strrchr(stat, ')');
    if (field == NULL || field[1] != ' ')
        return -1;
    field += 2;
    for (size_t index = 3; index < 22; ++index) {
        field = strchr(field, ' ');
        if (field == NULL)
            return -1;
        ++field;
    }
    char *end = NULL;
    errno = 0;
    *start = strtoull(field, &end, 10);
    return errno == 0 && end != field && *end == ' ' && *start != 0 ? 0 : -1;
}

static int require_id_map(uint32_t pid, const char *kind, uint32_t shift,
    uint32_t count)
{
    char path[64], bytes[512], *field, *end;
    snprintf(path, sizeof(path), "/proc/%u/%s", pid, kind);
    if (read_text(path, bytes, sizeof(bytes)) != 0)
        return -1;

    const uint32_t expected[3] = {0, shift, count};
    field = bytes;
    for (size_t index = 0; index < 3; ++index) {
        while (*field == ' ' || *field == '\t')
            ++field;
        /* strtoull accepts signs; the physical map grammar does not. */
        if (*field < '0' || *field > '9')
            return -1;
        errno = 0;
        unsigned long long value = strtoull(field, &end, 10);
        if (errno != 0 || value != expected[index] || end == field)
            return -1;
        field = end;
        if (index < 2 && *field != ' ' && *field != '\t')
            return -1;
    }
    return strcmp(field, "\n") == 0 ? 0 : -1;
}

static int require_target(const uint8_t query[QUERY_BYTES], const int loans[2],
    bool traced, struct process_info *observed)
{
    struct process_info info = {.mask = 7};
    uint64_t start = 0;
    if (ioctl(loans[0], PIDFD_INFO, &info) != 0 || (info.mask & 7) != 7
        || info.pid <= 1 || info.pid != info.tgid || info.cgroup == 0
        || process_start(info.pid, &start) != 0 || start != get64(query + 48))
        return -1;
    struct pollfd alive = {.fd = loans[0], .events = POLLIN};
    if (poll(&alive, 1, 0) != 0)
        return -1;

    char path[128], status[8192], cgroup[1024];
    const char *context = query[40] == 1
        ? "system_u:system_r:aos_sandbox_deployment_specimen_t:s0"
        : "system_u:system_r:aos_nspawn_deployment_specimen_t:s0";
    snprintf(path, sizeof(path), "/proc/%u/attr/current", info.pid);
    if (require_text(path, context) != 0)
        return -1;
    snprintf(path, sizeof(path), "/proc/%u/cgroup", info.pid);
    if (read_text(path, cgroup, sizeof(cgroup)) != 0)
        return -1;
    const char *prefix = "0::" SPECIMEN_CGROUP;
    size_t length = strlen(prefix);
    if (strncmp(cgroup, prefix, length) != 0 || cgroup[length] != '/')
        return -1;
    const char *subgroup = cgroup + length;
    if (query[40] == 2 && strcmp(subgroup, "/supervisor\n") != 0)
        return -1;
    if (query[40] == 1 && strncmp(subgroup, "/payload/", 9) != 0
        && strcmp(subgroup, "/payload\n") != 0)
        return -1;

    snprintf(path, sizeof(path), "/proc/%u/status", info.pid);
    if (read_text(path, status, sizeof(status)) != 0)
        return -1;
    uint64_t tracer = 0, seccomp = 0, threads = 0, no_new_privileges = 0;
    if (status_number(status, "TracerPid:", 10, &tracer) != 0
        || tracer != (traced ? (uint64_t)getpid() : 0)
        || status_number(status, "Seccomp:", 10, &seccomp) != 0 || seccomp != 2
        || status_number(status, "Threads:", 10, &threads) != 0 || threads != 1
        || status_number(status, "NoNewPrivs:", 10, &no_new_privileges) != 0
        || no_new_privileges != 1)
        return -1;

    if (query[40] == 1
        && (require_id_map(info.pid, "uid_map", get32(query + 72), get32(query + 76)) != 0
            || require_id_map(info.pid, "gid_map", get32(query + 72), get32(query + 76)) != 0))
        return -1;

    struct stat root, expected;
    snprintf(path, sizeof(path), "/proc/%u/root", info.pid);
    int root_fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        return -1;
    bool same = fstat(root_fd, &root) == 0 && fstat(loans[1], &expected) == 0
        && S_ISDIR(expected.st_mode) && root.st_dev == expected.st_dev
        && root.st_ino == expected.st_ino
        && (uint64_t)root.st_dev == get64(query + 56)
        && (uint64_t)root.st_ino == get64(query + 64);
    close(root_fd);
    if (!same)
        return -1;

    const unsigned long ioctls[4] = {0xff09, 0xff03, 0xff04, 0xff05};
    for (size_t index = 0; index < 4; ++index) {
        int fd = ioctl(loans[0], ioctls[index], 0UL);
        struct stat namespace;
        bool valid = fd >= 0 && fstat(fd, &namespace) == 0
            && (uint64_t)namespace.st_dev == get64(query + 80 + index * 16)
            && (uint64_t)namespace.st_ino == get64(query + 88 + index * 16);
        if (fd >= 0)
            close(fd);
        if (!valid)
            return -1;
    }
    struct process_info after = {.mask = 7};
    if (ioctl(loans[0], PIDFD_INFO, &after) != 0
        || memcmp(&info, &after, sizeof(info)) != 0 || poll(&alive, 1, 0) != 0)
        return -1;
    *observed = info;
    return 0;
}

static int await_trace_stop(pid_t target)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return -1;
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(target, &status, __WALL | WNOHANG);
        if (waited == target)
            return WIFSTOPPED(status) && (unsigned int)status >> 16 == PTRACE_EVENT_STOP ? 0 : -1;
        if (waited < 0 && errno != EINTR)
            return -1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec - start.tv_sec >= 30)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
}

int main(int argc, char **argv)
{
    (void)argv;
    uint8_t query[QUERY_BYTES] = {0};
    uint8_t reply[REPLY_HEADER + STACK_LIMIT] = {0};
    int loans[2] = {-1, -1};
    pid_t parent = getppid(), target = 0;
    bool seized = false, stopped = false;
    int result = EXIT_FAILURE;
    if (argc != 1 || parent <= 1 || require_collector() != 0
        || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent
        || close_range(3, ~0U, 0) != 0 || receive_query(query, loans, parent) != 0
        || memcmp(query, "AOSIFQ01", 8) != 0 || (query[40] != 1 && query[40] != 2)
        || memcmp(query + 41, (uint8_t[7]){0}, 7) != 0
        || memcmp(query + 8, (uint8_t[32]){0}, 32) == 0
        || get32(query + 72) < 65536 || get32(query + 76) < 65536
        || (uint64_t)get32(query + 72) + get32(query + 76) > UINT32_MAX)
        goto cleanup;
    struct process_info before, after;
    if (require_target(query, loans, false, &before) != 0)
        goto cleanup;
    target = (pid_t)before.pid;

    /* This numeric effect additionally depends on the retained single-specimen
     * launch exclusion and kernel MAC cut; the pidfd check is not atomic. */
    if (ptrace(PTRACE_SEIZE, target, NULL, (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0)
        goto cleanup;
    seized = true;
    if (require_target(query, loans, true, &after) != 0
        || memcmp(&before, &after, sizeof(before)) != 0
        || ptrace(PTRACE_INTERRUPT, target, NULL, NULL) != 0
        || await_trace_stop(target) != 0)
        goto cleanup;
    stopped = true;
    if (require_target(query, loans, true, &after) != 0
        || memcmp(&before, &after, sizeof(before)) != 0)
        goto cleanup;

    uint8_t *stack = reply + REPLY_HEADER;
    memcpy(stack, "AOSIFS01", 8);
    put32(stack + 8, AUDIT_ARCH_X86_64);
    size_t used = 16, count = 0;
    for (; count < FILTER_LIMIT; ++count) {
        errno = 0;
        long length = ptrace(PTRACE_SECCOMP_GET_FILTER, target, (void *)count, NULL);
        if (length < 0 && errno == ENOENT)
            break;
        if (length <= 0 || length > INSTRUCTION_LIMIT
            || used + 4 + (size_t)length * 8 > STACK_LIMIT)
            goto cleanup;
        struct sock_filter instructions[INSTRUCTION_LIMIT];
        if (ptrace(PTRACE_SECCOMP_GET_FILTER, target, (void *)count, instructions) != length)
            goto cleanup;
        put32(stack + used, (uint32_t)length);
        used += 4;
        for (long index = 0; index < length; ++index) {
            stack[used] = (uint8_t)(instructions[index].code >> 8);
            stack[used + 1] = (uint8_t)instructions[index].code;
            stack[used + 2] = instructions[index].jt;
            stack[used + 3] = instructions[index].jf;
            put32(stack + used + 4, instructions[index].k);
            used += 8;
        }
    }
    if (count == FILTER_LIMIT) {
        /* Exactly 32 filters is representable; prove there is no 33rd filter
         * instead of refusing the valid boundary or silently dropping it. */
        errno = 0;
        if (ptrace(PTRACE_SECCOMP_GET_FILTER, target, (void *)count, NULL) != -1
            || errno != ENOENT)
            goto cleanup;
    }
    if (count == 0
        || require_target(query, loans, true, &after) != 0
        || memcmp(&before, &after, sizeof(before)) != 0)
        goto cleanup;
    stack[12] = (uint8_t)(count >> 8);
    stack[13] = (uint8_t)count;

    /* Final exact identity check precedes DETACH. A failed detach never emits
     * a success frame; EXITKILL fences this child's still-retained trace. */
    if (ptrace(PTRACE_DETACH, target, NULL, NULL) != 0)
        goto cleanup;
    seized = false;
    stopped = false;
    if (require_target(query, loans, false, &after) != 0
        || memcmp(&before, &after, sizeof(before)) != 0)
        goto cleanup;
    memcpy(reply, "AOSIFR01", 8);
    memcpy(reply + 8, query + 8, 32);
    put32(reply + 40, before.pid);
    put32(reply + 44, query[40]);
    put64(reply + 48, get64(query + 48));
    put64(reply + 56, before.cgroup);
    put64(reply + 64, get64(query + 56));
    put64(reply + 72, get64(query + 64));
    struct pollfd channel = {.fd = STDIN_FILENO, .events = POLLOUT};
    if (poll(&channel, 1, 30000) == 1 && (channel.revents & POLLOUT)
        && send(STDIN_FILENO, reply, REPLY_HEADER + used, MSG_NOSIGNAL) == (ssize_t)(REPLY_HEADER + used))
        result = EXIT_SUCCESS;
cleanup:
    if (seized) {
        if (!stopped && ptrace(PTRACE_INTERRUPT, target, NULL, NULL) == 0)
            stopped = await_trace_stop(target) == 0;
        if (stopped)
            (void)ptrace(PTRACE_DETACH, target, NULL, NULL);
    }
    for (size_t index = 0; index < 2; ++index) {
        if (loans[index] >= 0)
            close(loans[index]);
    }
    return result;
}
