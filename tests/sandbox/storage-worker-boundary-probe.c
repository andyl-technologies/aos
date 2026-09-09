#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HOST_NAMESPACE_FD 3
#define HOST_NAMESPACE_FD_NAME "host-mount-namespace"
#define DENIED_PATH "/run/aos-storage-worker-host-write-denied"
#define SETID_PATH "/run/aos-storage-worker-setid-denied"
#define DIRECT_SETID_PATH "/run/aos-storage-worker-direct-setid-denied"

#ifndef __NR_fchmodat2
#error "missing fchmodat2 syscall number in Linux headers"
#endif

static int expected_denial(int error)
{
    return error == EACCES || error == EPERM || error == EROFS;
}

static int authenticate_mount_namespace(int descriptor, struct stat *identity)
{
    struct statfs filesystem;
    int namespace_type;

    if (fstat(descriptor, identity) != 0) {
        perror("stat mount namespace descriptor");
        return -1;
    }
    if (!S_ISREG(identity->st_mode)) {
        fprintf(stderr, "mount namespace descriptor is not a regular nsfs file\n");
        return -1;
    }
    if (fstatfs(descriptor, &filesystem) != 0) {
        perror("stat mount namespace filesystem");
        return -1;
    }
    if ((unsigned long)filesystem.f_type != NSFS_MAGIC) {
        fprintf(stderr, "mount namespace descriptor is not on nsfs\n");
        return -1;
    }

    namespace_type = ioctl(descriptor, NS_GET_NSTYPE);
    if (namespace_type < 0) {
        perror("read mount namespace type");
        return -1;
    }
    if (namespace_type != CLONE_NEWNS) {
        fprintf(stderr, "namespace descriptor has unexpected type %d\n",
            namespace_type);
        return -1;
    }

    return 0;
}

static int authenticate_passed_namespace(struct stat *identity)
{
    char expected_pid[32];
    const char *listen_fd_names = getenv("LISTEN_FDNAMES");
    const char *listen_fds = getenv("LISTEN_FDS");
    const char *listen_pid = getenv("LISTEN_PID");
    int written;

    written = snprintf(expected_pid, sizeof(expected_pid), "%ld", (long)getpid());
    if (written < 0 || (size_t)written >= sizeof(expected_pid)) {
        fprintf(stderr, "failed to format process identity\n");
        return -1;
    }
    if (listen_pid == NULL || strcmp(listen_pid, expected_pid) != 0
        || listen_fds == NULL || strcmp(listen_fds, "1") != 0
        || listen_fd_names == NULL
        || strcmp(listen_fd_names, HOST_NAMESPACE_FD_NAME) != 0) {
        fprintf(stderr, "unexpected systemd file descriptor contract\n");
        return -1;
    }

    return authenticate_mount_namespace(HOST_NAMESPACE_FD, identity);
}

static int enter_host_mount_namespace(const struct stat *expected)
{
    struct stat current;
    int current_fd;

    if (setns(HOST_NAMESPACE_FD, CLONE_NEWNS) != 0) {
        perror("enter host mount namespace");
        return -1;
    }

    current_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (current_fd < 0) {
        perror("open current mount namespace");
        return -1;
    }
    if (authenticate_mount_namespace(current_fd, &current) != 0) {
        close(current_fd);
        return -1;
    }
    if (expected->st_dev != current.st_dev || expected->st_ino != current.st_ino) {
        fprintf(stderr, "current mount namespace does not match retained identity\n");
        close(current_fd);
        return -1;
    }
    if (close(current_fd) != 0) {
        perror("close current mount namespace");
        return -1;
    }
    if (close(HOST_NAMESPACE_FD) != 0) {
        perror("close retained host mount namespace");
        return -1;
    }

    return 0;
}

static int create_file(const char *path, mode_t mode)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);

    if (descriptor < 0) {
        return -1;
    }
    return descriptor;
}

int main(int argc, char **argv)
{
    struct stat host_namespace_identity;
    int descriptor;

    if (argc != 1) {
        fprintf(stderr, "usage: storage-worker-boundary-probe\n");
        return 64;
    }
    (void)argv;
    if (authenticate_passed_namespace(&host_namespace_identity) != 0
        || enter_host_mount_namespace(&host_namespace_identity) != 0) {
        return 1;
    }

    errno = 0;
    descriptor = create_file(DENIED_PATH, 0600);
    if (descriptor >= 0 || !expected_denial(errno)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        fprintf(stderr, "host write outside Landlock grant was not denied: %s\n",
            strerror(errno));
        return 2;
    }

    errno = 0;
    descriptor = create_file(DIRECT_SETID_PATH, 04755);
    if (descriptor >= 0 || !expected_denial(errno)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        fprintf(stderr, "direct setid creation was not denied: %s\n",
            strerror(errno));
        return 3;
    }

    errno = 0;
    if (chmod(SETID_PATH, 04755) == 0 || errno != EPERM) {
        fprintf(stderr, "setid chmod was not rejected by seccomp: %s\n",
            strerror(errno));
        return 4;
    }

    errno = 0;
    if (syscall(__NR_fchmodat2, AT_FDCWD, SETID_PATH, 04755, 0) == 0
        || errno != EPERM) {
        fprintf(stderr, "setid fchmodat2 was not rejected by seccomp: %s\n",
            strerror(errno));
        return 5;
    }

    errno = 0;
    if (mount("none", "/run", "tmpfs", 0, NULL) == 0 || errno != EPERM) {
        fprintf(stderr, "classic mount syscall was not rejected by seccomp: %s\n",
            strerror(errno));
        return 6;
    }

    return 0;
}
