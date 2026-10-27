/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed same-principal specimen network child. Only its own network namespace
 * changes; Root never enters it. The genuine Rust owner owes the already
 * current Prepared floor permit and original image/unit/population custody
 * before spawning this child. This private exchange is not a permit factory.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "collector_identity.h"

#if !defined(__x86_64__)
#error "deployment network child is reviewed only for x86_64"
#endif
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif
#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#define CHANNEL_FD 3
#define NONCE_BYTES 32U
#define REQUEST_BYTES 40U
#define REPLY_BYTES 72U
#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif
#define PIDFD_INFO UINT32_C(0xc048ff0b)
#define COLLECTOR_CGROUP "0::/aos.slice/aos-control.slice/aos-sandbox-installed-filter-collector.service"

/* The same exact Linux pidfs v1 ABI used by the existing fixed filter reader.
 * Only getppid() selects a process here; no numeric PID is accepted by IPC.
 */
struct parent_info {
    uint64_t mask, cgroup;
    uint32_t pid, tgid, ppid, ruid, rgid, euid, egid;
    uint32_t suid, sgid, fsuid, fsgid;
    int32_t exit_code;
    uint32_t coredump, spare;
};
_Static_assert(sizeof(struct parent_info) == 72, "pidfs v1 ABI");

struct deadline {
    struct timespec end;
};

static void put64(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0; index < 8; ++index)
        bytes[7 - index] = (uint8_t)(value >> (index * 8));
}

static int remaining_ms(const struct deadline *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    int64_t nanoseconds = (int64_t)(deadline->end.tv_sec - now.tv_sec) * 1000000000
        + deadline->end.tv_nsec - now.tv_nsec;
    if (nanoseconds <= 0 || nanoseconds > INT64_C(30000000000))
        return -1;
    return (int)((nanoseconds + 999999) / 1000000);
}

static int wait_channel(short events, int parent_fd, const struct deadline *deadline)
{
    for (;;) {
        int timeout = remaining_ms(deadline);
        if (timeout <= 0)
            return -1;
        struct pollfd descriptors[2] = {
            {.fd = CHANNEL_FD, .events = events},
            {.fd = parent_fd, .events = POLLIN},
        };
        int ready = poll(descriptors, 2, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || descriptors[1].revents != 0
            || descriptors[0].revents != events)
            return -1;
        return 0;
    }
}

static int require_parent(int parent_fd, pid_t parent, const struct parent_info *original)
{
    struct parent_info observed = {.mask = 7};
    struct pollfd alive = {.fd = parent_fd, .events = POLLIN};
    if (getppid() != parent || ioctl(parent_fd, PIDFD_INFO, &observed) != 0
        || (observed.mask & 7) != 7 || observed.pid != (uint32_t)parent
        || observed.tgid != (uint32_t)parent || observed.ppid != 1 || observed.cgroup == 0
        || observed.ruid != 0 || observed.euid != 0 || observed.suid != 0
        || observed.rgid != 0 || observed.egid != 0 || observed.sgid != 0
        || observed.fsuid != 0 || observed.fsgid != 0
        || poll(&alive, 1, 0) != 0
        || (original != NULL && memcmp(original, &observed, sizeof(observed)) != 0))
        return -1;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/attr/current", observed.pid);
    if (require_text(path, COLLECTOR_CONTEXT) != 0)
        return -1;
    snprintf(path, sizeof(path), "/proc/%u/cgroup", observed.pid);
    return require_text(path, COLLECTOR_CGROUP);
}

static int require_channel(pid_t parent)
{
    int kind = 0, domain = 0, enabled = 1;
    socklen_t size = sizeof(kind);
    struct ucred creator = {0};
    if (getsockopt(CHANNEL_FD, SOL_SOCKET, SO_TYPE, &kind, &size) != 0
        || size != sizeof(kind) || kind != SOCK_SEQPACKET)
        return -1;
    size = sizeof(domain);
    if (getsockopt(CHANNEL_FD, SOL_SOCKET, SO_DOMAIN, &domain, &size) != 0
        || size != sizeof(domain) || domain != AF_UNIX)
        return -1;
    size = sizeof(creator);
    if (getsockopt(CHANNEL_FD, SOL_SOCKET, SO_PEERCRED, &creator, &size) != 0
        || size != sizeof(creator) || creator.pid != parent || creator.uid != 0
        || creator.gid != 0
        || setsockopt(CHANNEL_FD, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0
        || setsockopt(CHANNEL_FD, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled)) != 0)
        return -1;
    return 0;
}

static int receive_nonce(uint8_t bytes[REQUEST_BYTES], const char magic[8],
    int parent_fd, pid_t parent, const struct parent_info *original,
    const struct deadline *deadline)
{
    if (wait_channel(POLLIN, parent_fd, deadline) != 0)
        return -1;
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))
            + CMSG_SPACE(8 * sizeof(int))];
    } control = {0};
    struct iovec vector = {.iov_base = bytes, .iov_len = REQUEST_BYTES};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    ssize_t received = recvmsg(CHANNEL_FD, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    bool valid = received == REQUEST_BYTES && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    size_t credentials = 0, pidfds = 0;
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
        if (header->cmsg_type == SCM_CREDENTIALS) {
            struct ucred subject = {0};
            if (header->cmsg_len != CMSG_LEN(sizeof(subject))) {
                valid = false;
                continue;
            }
            memcpy(&subject, CMSG_DATA(header), sizeof(subject));
            valid &= subject.pid == parent && subject.uid == 0 && subject.gid == 0;
            ++credentials;
        } else if (header->cmsg_type == SCM_PIDFD) {
            int subject_fd;
            if (header->cmsg_len != CMSG_LEN(sizeof(subject_fd))) {
                valid = false;
                continue;
            }
            memcpy(&subject_fd, CMSG_DATA(header), sizeof(subject_fd));
            valid &= require_parent(subject_fd, parent, original) == 0;
            close(subject_fd);
            ++pidfds;
        } else if (header->cmsg_type == SCM_RIGHTS) {
            size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int *descriptors = (int *)CMSG_DATA(header);
            for (size_t index = 0; index < count; ++index)
                close(descriptors[index]);
            valid = false;
        } else {
            valid = false;
        }
    }
    return valid && credentials == 1 && pidfds == 1
        && memcmp(bytes, magic, 8) == 0
        && memcmp(bytes + 8, (uint8_t[NONCE_BYTES]){0}, NONCE_BYTES) != 0
        && require_parent(parent_fd, parent, original) == 0 ? 0 : -1;
}

static int open_actual_net(struct stat *identity)
{
    int descriptor = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    struct statfs filesystem;
    if (descriptor < 0)
        return -1;
    if (fstat(descriptor, identity) != 0 || fstatfs(descriptor, &filesystem) != 0
        || (unsigned long)filesystem.f_type != NSFS_MAGIC
        || ioctl(descriptor, NS_GET_NSTYPE, 0UL) != CLONE_NEWNET
        || identity->st_dev == 0 || identity->st_ino == 0) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int send_namespace(const uint8_t request[REQUEST_BYTES], int namespace_fd,
    const struct stat *old, const struct stat *created, int parent_fd,
    const struct deadline *deadline)
{
    if (wait_channel(POLLOUT, parent_fd, deadline) != 0)
        return -1;
    uint8_t reply[REPLY_BYTES] = {0};
    memcpy(reply, "AOSNRP01", 8);
    memcpy(reply + 8, request + 8, NONCE_BYTES);
    put64(reply + 40, (uint64_t)old->st_dev);
    put64(reply + 48, (uint64_t)old->st_ino);
    put64(reply + 56, (uint64_t)created->st_dev);
    put64(reply + 64, (uint64_t)created->st_ino);
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct iovec vector = {.iov_base = reply, .iov_len = sizeof(reply)};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
    if (rights == NULL)
        return -1;
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(namespace_fd));
    memcpy(CMSG_DATA(rights), &namespace_fd, sizeof(namespace_fd));
    return sendmsg(CHANNEL_FD, &message, MSG_NOSIGNAL | MSG_DONTWAIT) == REPLY_BYTES ? 0 : -1;
}

int main(int argc, char **argv)
{
    (void)argv;
    int result = EXIT_FAILURE, parent_fd = -1, original_net = -1, created_net = -1;
    int final_net = -1;
    pid_t parent = getppid();
    uint8_t request[REQUEST_BYTES] = {0}, acknowledgement[REQUEST_BYTES] = {0};
    struct deadline deadline;
    struct parent_info original = {.mask = 7};
    struct stat old, created, still_created;
    if (argc != 1 || parent <= 1 || require_collector() != 0
        || prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) != 1
        || require_text("/proc/self/cgroup", COLLECTOR_CGROUP) != 0
        || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent
        || close_range(4, ~0U, 0) != 0 || require_channel(parent) != 0
        || clock_gettime(CLOCK_MONOTONIC, &deadline.end) != 0)
        goto cleanup;
    deadline.end.tv_sec += 30;
    parent_fd = (int)syscall(SYS_pidfd_open, parent, 0U);
    if (parent_fd < 0 || require_parent(parent_fd, parent, NULL) != 0
        || ioctl(parent_fd, PIDFD_INFO, &original) != 0
        || require_parent(parent_fd, parent, &original) != 0
        || receive_nonce(request, "AOSNRQ01", parent_fd, parent, &original, &deadline) != 0)
        goto cleanup;

    original_net = open_actual_net(&old);
    if (original_net < 0 || require_collector() != 0
        || require_parent(parent_fd, parent, &original) != 0 || remaining_ms(&deadline) <= 0
        || unshare(CLONE_NEWNET) != 0)
        goto cleanup;
    created_net = open_actual_net(&created);
    if (created_net < 0 || (old.st_dev == created.st_dev && old.st_ino == created.st_ino)
        || require_collector() != 0 || require_parent(parent_fd, parent, &original) != 0
        || send_namespace(request, created_net, &old, &created, parent_fd, &deadline) != 0
        || receive_nonce(acknowledgement, "AOSNAK01", parent_fd, parent, &original, &deadline) != 0
        || memcmp(request + 8, acknowledgement + 8, NONCE_BYTES) != 0)
        goto cleanup;
    final_net = open_actual_net(&still_created);
    if (final_net < 0 || still_created.st_dev != created.st_dev
        || still_created.st_ino != created.st_ino || require_collector() != 0
        || require_parent(parent_fd, parent, &original) != 0 || remaining_ms(&deadline) <= 0)
        goto cleanup;
    result = EXIT_SUCCESS;

cleanup:
    if (final_net >= 0)
        close(final_net);
    if (created_net >= 0)
        close(created_net);
    if (original_net >= 0)
        close(original_net);
    if (parent_fd >= 0)
        close(parent_fd);
    return result;
}
