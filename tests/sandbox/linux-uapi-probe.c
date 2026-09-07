/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Architecture-neutral syscall-presence probe for the sandbox Linux boundary.
 *
 * Return values other than ENOSYS prove that the running kernel recognizes the
 * syscall. EPERM, EACCES, EBADF, and EINVAL remain useful results when a build
 * sandbox or missing capability deliberately prevents the requested effect.
 */

#define _GNU_SOURCE

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__NR_pidfd_open) || !defined(__NR_pidfd_send_signal) ||          \
    !defined(__NR_pidfd_getfd) || !defined(__NR_openat2) ||                  \
    !defined(__NR_open_tree) || !defined(__NR_open_tree_attr) ||             \
    !defined(__NR_move_mount) || !defined(__NR_fsopen) ||                    \
    !defined(__NR_fsconfig) || !defined(__NR_fsmount) ||                     \
    !defined(__NR_fspick) || !defined(__NR_mount_setattr) ||                 \
    !defined(__NR_statmount) || !defined(__NR_listmount)
#error "Linux headers do not expose the complete AOS sandbox syscall surface"
#endif

static unsigned int missing_count;
static bool first_result = true;

static void report(const char *name, long result, int error, bool result_is_fd)
{
    const bool present = result >= 0 || error != ENOSYS;

    if (result_is_fd && result >= 0)
        close((int)result);
    if (!present)
        missing_count++;

    printf("%s{\"name\":\"%s\",\"present\":%s,\"errno\":%d}",
           first_result ? "" : ",", name, present ? "true" : "false",
           result >= 0 ? 0 : error);
    first_result = false;
}

#define PROBE(name, expression, result_is_fd)                                \
    do {                                                                      \
        long probe_result;                                                    \
        int probe_errno;                                                      \
        errno = 0;                                                            \
        probe_result = (long)(expression);                                    \
        probe_errno = errno;                                                  \
        report((name), probe_result, probe_errno, (result_is_fd));            \
    } while (false)

int main(void)
{
    struct open_how how = {
        .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_NO_MAGICLINKS,
    };
    struct mount_attr mount_attributes = {
        .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    struct mnt_id_req mount_request = {
        .size = MNT_ID_REQ_SIZE_VER1,
        .mnt_id = LSMT_ROOT,
        .param = STATMOUNT_MNT_BASIC,
    };
    struct statmount mount_status = {0};
    uint64_t mount_ids[4] = {0};
    int pidfd;

    printf("{\"schema_version\":\"aos.sandbox.linux-uapi-probe/v1\","
           "\"architecture\":\"");
#if defined(__x86_64__)
    printf("x86_64");
#elif defined(__aarch64__)
    printf("aarch64");
#else
    printf("unknown");
#endif
    printf("\",\"probes\":[");

    errno = 0;
    pidfd = (int)syscall(__NR_pidfd_open, getpid(), 0U);
    report("pidfd_open", pidfd, errno, false);
    PROBE("pidfd_send_signal",
          syscall(__NR_pidfd_send_signal, pidfd, 0, NULL, 0U), false);
    PROBE("pidfd_getfd", syscall(__NR_pidfd_getfd, pidfd, STDIN_FILENO, 0U),
          true);
    if (pidfd >= 0)
        close(pidfd);

    PROBE("openat2",
          syscall(__NR_openat2, AT_FDCWD, ".", &how, sizeof(how)), true);
    PROBE("open_tree",
          syscall(__NR_open_tree, AT_FDCWD, ".", OPEN_TREE_CLOEXEC), true);
    PROBE("open_tree_attr",
          syscall(__NR_open_tree_attr, AT_FDCWD, ".", OPEN_TREE_CLOEXEC,
                  &mount_attributes, sizeof(mount_attributes)),
          true);
    PROBE("move_mount",
          syscall(__NR_move_mount, -1, "", -1, "", MOVE_MOUNT_F_EMPTY_PATH),
          false);
    PROBE("fsopen", syscall(__NR_fsopen, "tmpfs", FSOPEN_CLOEXEC), true);
    PROBE("fsconfig",
          syscall(__NR_fsconfig, -1, FSCONFIG_SET_FLAG, "nodev", NULL, 0),
          false);
    PROBE("fsmount", syscall(__NR_fsmount, -1, FSMOUNT_CLOEXEC, 0U), true);
    PROBE("fspick", syscall(__NR_fspick, AT_FDCWD, ".", FSPICK_CLOEXEC), true);
    PROBE("mount_setattr",
          syscall(__NR_mount_setattr, -1, "", AT_EMPTY_PATH,
                  &mount_attributes, sizeof(mount_attributes)),
          false);
    PROBE("statmount",
          syscall(__NR_statmount, &mount_request, &mount_status,
                  sizeof(mount_status), 0U),
          false);
    mount_request.param = 0;
    PROBE("listmount",
          syscall(__NR_listmount, &mount_request, mount_ids,
                  sizeof(mount_ids) / sizeof(mount_ids[0]), 0U),
          false);

    printf("],\"missing_count\":%u}\n", missing_count);
    return missing_count == 0 ? 0 : 1;
}
