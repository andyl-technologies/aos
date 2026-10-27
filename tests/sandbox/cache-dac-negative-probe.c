/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Qualifies Cache name denial after a controller-UID SCM_RIGHTS handoff.
 * The receiver remains UID 0 but drops every capability before name lookup.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CONTROLLER_UID 811
#define CACHE_ROOT "/var/lib/aos/sandbox/cache-residency-objects"

static int send_root(int socket_fd)
{
    int root_fd;
    char byte = 'C';
    struct iovec payload = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(root_fd))] = {0};
    struct msghdr message = {
        .msg_iov = &payload,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *rights;

    if (setgroups(0, NULL) != 0 || setresgid(CONTROLLER_UID, CONTROLLER_UID,
                                             CONTROLLER_UID) != 0 ||
        setresuid(CONTROLLER_UID, CONTROLLER_UID, CONTROLLER_UID) != 0)
        return -1;
    root_fd = open(CACHE_ROOT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0)
        return -1;

    rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(root_fd));
    memcpy(CMSG_DATA(rights), &root_fd, sizeof(root_fd));
    if (sendmsg(socket_fd, &message, 0) != 1) {
        close(root_fd);
        return -1;
    }
    close(root_fd);
    return 0;
}

static int receive_root(int socket_fd)
{
    int root_fd = -1;
    char byte;
    struct iovec payload = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(root_fd))] = {0};
    struct msghdr message = {
        .msg_iov = &payload,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *rights;

    if (recvmsg(socket_fd, &message, 0) != 1 || byte != 'C' ||
        (message.msg_flags & MSG_CTRUNC) != 0)
        return -1;
    rights = CMSG_FIRSTHDR(&message);
    if (rights == NULL || rights->cmsg_level != SOL_SOCKET ||
        rights->cmsg_type != SCM_RIGHTS || rights->cmsg_len != CMSG_LEN(sizeof(root_fd)) ||
        CMSG_NXTHDR(&message, rights) != NULL)
        return -1;
    memcpy(&root_fd, CMSG_DATA(rights), sizeof(root_fd));
    return root_fd;
}

static int drop_and_check_capabilities(void)
{
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct data[2] = {0};
    int capability;

    if (getuid() != 0 || geteuid() != 0)
        return -1;
    for (capability = 0; capability < 64; capability++) {
        int held = prctl(PR_CAPBSET_READ, capability);

        if (held < 0 && errno == EINVAL)
            break;
        if (held < 0 || (held == 1 && prctl(PR_CAPBSET_DROP, capability) != 0))
            return -1;
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(SYS_capset, &header, data) != 0 ||
        syscall(SYS_capget, &header, data) != 0)
        return -1;
    if (data[0].effective != 0 || data[0].permitted != 0 ||
        data[0].inheritable != 0 || data[1].effective != 0 ||
        data[1].permitted != 0 || data[1].inheritable != 0)
        return -1;
    for (capability = 0; capability < 64; capability++) {
        int held = prctl(PR_CAPBSET_READ, capability);

        if (held < 0 && errno == EINVAL)
            break;
        if (held != 0)
            return -1;
    }
    return 0;
}

int main(void)
{
    int sockets[2];
    pid_t sender;
    int status;
    int root_fd;
    struct stat root_stat;
    struct stat child_stat;
    int child_fd;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
        goto failure;
    sender = fork();
    if (sender < 0)
        goto failure;
    if (sender == 0) {
        close(sockets[0]);
        _exit(send_root(sockets[1]) == 0 ? 0 : 1);
    }
    close(sockets[1]);
    root_fd = receive_root(sockets[0]);
    if (root_fd < 0 || waitpid(sender, &status, 0) != sender ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        fstat(root_fd, &root_stat) != 0 ||
        !S_ISDIR(root_stat.st_mode) || root_stat.st_uid != CONTROLLER_UID ||
        (root_stat.st_mode & 07777) != 0700)
        goto failure;

    if (drop_and_check_capabilities() != 0)
        goto failure;
    errno = 0;
    if (fstatat(root_fd, ".owner.lock", &child_stat, AT_SYMLINK_NOFOLLOW) != -1 ||
        errno != EACCES)
        goto failure;
    errno = 0;
    child_fd = openat(root_fd, "owner-state", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (child_fd != -1 || errno != EACCES)
        goto failure;

    puts("cap-empty-root-cache-named-lookup-denied:PASS");
    close(root_fd);
    close(sockets[0]);
    return 0;

failure:
    fprintf(stderr, "cache DAC negative qualification failed: %s\n", strerror(errno));
    return 1;
}
