#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATX_MNT_ID_UNIQUE 0x00004000U

struct mount_identity {
    uint64_t mount_id;
    uint64_t device;
    uint64_t inode;
    uint64_t user_namespace;
    uint64_t mount_namespace;
};

static void fail(const char *step)
{
    perror(step);
    exit(EXIT_FAILURE);
}

static uint64_t namespace_inode(const char *path)
{
    struct stat identity;

    if (stat(path, &identity) != 0) {
        fail("stat namespace");
    }
    return (uint64_t)identity.st_ino;
}

static uint64_t unique_mount_id(int descriptor)
{
    struct statx identity = {0};

    if (syscall(SYS_statx, descriptor, "", AT_EMPTY_PATH,
            STATX_MNT_ID_UNIQUE, &identity) != 0) {
        fail("statx detached mount");
    }
    if ((identity.stx_mask & STATX_MNT_ID_UNIQUE) == 0
        || identity.stx_mnt_id == 0) {
        fprintf(stderr, "kernel omitted unique mount ID\n");
        exit(EXIT_FAILURE);
    }
    return identity.stx_mnt_id;
}

static struct mount_identity observe_mount(int descriptor)
{
    struct stat root;
    struct mount_identity identity;

    if (fstat(descriptor, &root) != 0) {
        fail("fstat mount root");
    }
    if (!S_ISDIR(root.st_mode) || root.st_dev == 0 || root.st_ino == 0) {
        fprintf(stderr, "detached root identity is invalid\n");
        exit(EXIT_FAILURE);
    }
    identity.mount_id = unique_mount_id(descriptor);
    identity.device = (uint64_t)root.st_dev;
    identity.inode = (uint64_t)root.st_ino;
    identity.user_namespace = namespace_inode("/proc/self/ns/user");
    identity.mount_namespace = namespace_inode("/proc/self/ns/mnt");
    return identity;
}

static void write_mapping(const char *path, const char *value)
{
    int descriptor = open(path, O_WRONLY | O_CLOEXEC);
    size_t length = strlen(value);

    if (descriptor < 0) {
        fail("open namespace mapping");
    }
    if (write(descriptor, value, length) != (ssize_t)length) {
        fail("write namespace mapping");
    }
    if (close(descriptor) != 0) {
        fail("close namespace mapping");
    }
}

static void enter_child_namespaces(int separate_user_namespace)
{
    char mapping[64];

    if (separate_user_namespace) {
        uid_t parent_uid = getuid();
        gid_t parent_gid = getgid();

        if (unshare(CLONE_NEWUSER) != 0) {
            fail("unshare user namespace");
        }
        write_mapping("/proc/self/setgroups", "deny\n");
        if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", parent_uid)
            >= (int)sizeof(mapping)) {
            fprintf(stderr, "UID map overflow\n");
            exit(EXIT_FAILURE);
        }
        write_mapping("/proc/self/uid_map", mapping);
        if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", parent_gid)
            >= (int)sizeof(mapping)) {
            fprintf(stderr, "GID map overflow\n");
            exit(EXIT_FAILURE);
        }
        write_mapping("/proc/self/gid_map", mapping);
    }
    if (unshare(CLONE_NEWNS) != 0) {
        fail("unshare mount namespace");
    }
}

static int create_detached_tmpfs(void)
{
    int context = (int)syscall(SYS_fsopen, "tmpfs", FSOPEN_CLOEXEC);
    int mount_descriptor;

    if (context < 0) {
        fail("fsopen tmpfs");
    }
    if (syscall(SYS_fsconfig, context, FSCONFIG_SET_STRING,
            "size", "4096", 0) != 0
        || syscall(SYS_fsconfig, context, FSCONFIG_CMD_CREATE,
            NULL, NULL, 0) != 0) {
        fail("fsconfig tmpfs");
    }
    mount_descriptor = (int)syscall(SYS_fsmount, context, FSMOUNT_CLOEXEC, 0);
    if (mount_descriptor < 0) {
        fail("fsmount tmpfs");
    }
    if (close(context) != 0) {
        fail("close filesystem context");
    }
    return mount_descriptor;
}

static void send_mount(int socket_fd, int mount_fd,
    const struct mount_identity *identity)
{
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec body = {.iov_base = (void *)identity,
        .iov_len = sizeof(*identity)};
    struct msghdr message = {.msg_iov = &body, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *rights = CMSG_FIRSTHDR(&message);

    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(rights), &mount_fd, sizeof(mount_fd));
    if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(*identity)) {
        fail("send detached mount");
    }
}

static int receive_mount(int socket_fd, struct mount_identity *identity)
{
    char control[CMSG_SPACE(sizeof(int) * 2)] = {0};
    struct iovec body = {.iov_base = identity, .iov_len = sizeof(*identity)};
    struct msghdr message = {.msg_iov = &body, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *rights;
    int descriptor;

    if (recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC) !=
        (ssize_t)sizeof(*identity)) {
        fail("receive detached mount");
    }
    rights = CMSG_FIRSTHDR(&message);
    if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0
        || rights == NULL || CMSG_NXTHDR(&message, rights) != NULL
        || rights->cmsg_level != SOL_SOCKET
        || rights->cmsg_type != SCM_RIGHTS
        || rights->cmsg_len != CMSG_LEN(sizeof(int))) {
        fprintf(stderr, "inexact detached-mount descriptor table\n");
        exit(EXIT_FAILURE);
    }
    memcpy(&descriptor, CMSG_DATA(rights), sizeof(descriptor));
    return descriptor;
}

static void run_transfer(int separate_user_namespace)
{
    char destination[] = "/run/aos-root-init-transfer-XXXXXX";
    struct mount_identity sent;
    struct mount_identity received;
    struct mount_identity attached;
    int sockets[2];
    int mount_fd;
    int status;
    pid_t child;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        fail("socketpair");
    }
    child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        close(sockets[0]);
        enter_child_namespaces(separate_user_namespace);
        mount_fd = create_detached_tmpfs();
        sent = observe_mount(mount_fd);
        send_mount(sockets[1], mount_fd, &sent);
        close(mount_fd);
        close(sockets[1]);
        _exit(EXIT_SUCCESS);
    }

    close(sockets[1]);
    mount_fd = receive_mount(sockets[0], &sent);
    close(sockets[0]);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
        || WEXITSTATUS(status) != EXIT_SUCCESS) {
        fprintf(stderr, "mount producer did not exit cleanly\n");
        exit(EXIT_FAILURE);
    }
    received = observe_mount(mount_fd);
    if (sent.mount_id != received.mount_id
        || sent.device != received.device || sent.inode != received.inode
        || sent.mount_namespace == received.mount_namespace
        || (separate_user_namespace != 0) !=
            (sent.user_namespace != received.user_namespace)) {
        fprintf(stderr, "transferred mount or namespace identity changed\n");
        exit(EXIT_FAILURE);
    }
    if (mkdtemp(destination) == NULL) {
        fail("create private mount destination");
    }
    if (syscall(SYS_move_mount, mount_fd, "", AT_FDCWD, destination,
            MOVE_MOUNT_F_EMPTY_PATH) != 0) {
        int error = errno;

        if (!separate_user_namespace || (error != EPERM && error != EXDEV)) {
            errno = error;
            fail("attach transferred mount");
        }
        printf("cross-userns detached transfer denied: %d\n", error);
    } else {
        int attached_fd = open(destination, O_PATH | O_DIRECTORY | O_CLOEXEC);

        if (attached_fd < 0) {
            fail("open attached mount root");
        }
        attached = observe_mount(attached_fd);
        close(attached_fd);
        if (attached.mount_id != sent.mount_id
            || attached.device != sent.device || attached.inode != sent.inode) {
            fprintf(stderr, "attached mount identity changed\n");
            exit(EXIT_FAILURE);
        }
        if (umount2(destination, MNT_DETACH) != 0) {
            fail("detach probe mount");
        }
        printf("cross-userns=%d detached transfer attached: mount=%llu\n",
            separate_user_namespace,
            (unsigned long long)sent.mount_id);
    }
    close(mount_fd);
    if (rmdir(destination) != 0) {
        fail("remove private mount destination");
    }
}

int main(void)
{
    if (unshare(CLONE_NEWNS) != 0) {
        fail("isolate probe mount namespace");
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fail("make probe mounts private");
    }
    run_transfer(0);
    run_transfer(1);
    return EXIT_SUCCESS;
}
