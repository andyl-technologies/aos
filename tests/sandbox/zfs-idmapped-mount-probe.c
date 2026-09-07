/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Applies a real user-namespace ID map to a cloned ZFS mount and proves that
 * the VFS translates an on-disk uid through that mount. The caller supplies
 * an already-mounted ZFS dataset, an empty target directory, and a regular
 * file in the source dataset.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__NR_mount_setattr) || !defined(__NR_move_mount) ||             \
    !defined(__NR_open_tree)
#error "Linux headers do not expose the idmapped-mount syscall surface"
#endif

#define IDMAP_BASE 100000U
#define IDMAP_LENGTH 65536U

static void fail(const char *operation)
{
    fprintf(stderr, "zfs-idmapped-mount-probe: %s: %s\n", operation,
            strerror(errno));
    exit(EXIT_FAILURE);
}

static void write_all(int fd, const char *buffer, size_t length,
                      const char *operation)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, length - offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            fail(operation);
        }
        offset += (size_t)written;
    }
}

static void write_proc_file(pid_t pid, const char *name, const char *value)
{
    char path[128];
    int length;
    int fd;

    length = snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        fail("constructing namespace mapping path");
    }
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        fail(path);
    write_all(fd, value, strlen(value), path);
    if (close(fd) < 0)
        fail("closing namespace mapping");
}

static int open_mapped_user_namespace(void)
{
    int ready[2];
    int release[2];
    char byte;
    char namespace_path[128];
    pid_t child;
    int namespace_fd;
    int status;

    if (pipe2(ready, O_CLOEXEC) < 0 || pipe2(release, O_CLOEXEC) < 0)
        fail("pipe2");
    child = fork();
    if (child < 0)
        fail("fork");
    if (child == 0) {
        if (close(ready[0]) < 0 || close(release[1]) < 0)
            fail("closing child pipe ends");
        if (unshare(CLONE_NEWUSER) < 0)
            fail("unshare(CLONE_NEWUSER)");
        write_all(ready[1], "R", 1, "signalling user namespace readiness");
        if (read(release[0], &byte, 1) != 1)
            fail("waiting for user namespace release");
        _exit(EXIT_SUCCESS);
    }

    if (close(ready[1]) < 0 || close(release[0]) < 0)
        fail("closing parent pipe ends");
    if (read(ready[0], &byte, 1) != 1)
        fail("waiting for user namespace readiness");
    write_proc_file(child, "setgroups", "deny\n");
    write_proc_file(child, "uid_map", "0 100000 65536\n");
    write_proc_file(child, "gid_map", "0 100000 65536\n");

    if (snprintf(namespace_path, sizeof(namespace_path), "/proc/%ld/ns/user",
                 (long)child) < 0) {
        errno = EINVAL;
        fail("constructing user namespace path");
    }
    namespace_fd = open(namespace_path, O_RDONLY | O_CLOEXEC);
    if (namespace_fd < 0)
        fail("opening mapped user namespace");
    write_all(release[1], "X", 1, "releasing user namespace child");
    if (close(release[1]) < 0)
        fail("closing user namespace release pipe");
    if (waitpid(child, &status, 0) < 0)
        fail("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        errno = ECHILD;
        fail("user namespace child");
    }
    return namespace_fd;
}

int main(int argc, char **argv)
{
    struct mount_attr attributes = {0};
    struct stat source_status;
    struct stat mapped_status;
    char mapped_file[4096];
    const char *file_name;
    int mapped_length;
    int user_namespace_fd;
    int mount_fd;

    if (argc != 4) {
        fprintf(stderr, "usage: %s SOURCE_MOUNT TARGET_MOUNT SOURCE_FILE\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    if (chown(argv[3], IDMAP_BASE, IDMAP_BASE) < 0)
        fail("chown source fixture");
    if (stat(argv[3], &source_status) < 0)
        fail("stat source fixture");
    if (source_status.st_uid != IDMAP_BASE || source_status.st_gid != IDMAP_BASE) {
        errno = EBADE;
        fail("source ownership did not persist on ZFS");
    }

    user_namespace_fd = open_mapped_user_namespace();
    mount_fd = (int)syscall(__NR_open_tree, AT_FDCWD, argv[1],
                            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (mount_fd < 0)
        fail("open_tree ZFS mount clone");
    attributes.attr_set = MOUNT_ATTR_IDMAP;
    attributes.userns_fd = (unsigned long long)user_namespace_fd;
    if (syscall(__NR_mount_setattr, mount_fd, "", AT_EMPTY_PATH, &attributes,
                sizeof(attributes)) < 0)
        fail("mount_setattr MOUNT_ATTR_IDMAP on ZFS");
    if (syscall(__NR_move_mount, mount_fd, "", AT_FDCWD, argv[2],
                MOVE_MOUNT_F_EMPTY_PATH) < 0)
        fail("move_mount idmapped ZFS clone");

    file_name = strrchr(argv[3], '/');
    if (file_name == NULL || file_name[1] == '\0') {
        errno = EINVAL;
        fail("locating source fixture basename");
    }
    mapped_length = snprintf(mapped_file, sizeof(mapped_file), "%s/%s", argv[2],
                             file_name + 1);
    if (mapped_length < 0 || (size_t)mapped_length >= sizeof(mapped_file)) {
        errno = ENAMETOOLONG;
        fail("constructing mapped fixture path");
    }
    if (stat(mapped_file, &mapped_status) < 0)
        fail("stat idmapped fixture");
    if (mapped_status.st_uid != 0 || mapped_status.st_gid != 0) {
        errno = EBADE;
        fail("idmapped ZFS ownership translation");
    }

    printf("{\"schema_version\":\"aos.sandbox.zfs-idmapped-mount/v1\","
           "\"source_uid\":%lu,\"source_gid\":%lu,"
           "\"mapped_uid\":%lu,\"mapped_gid\":%lu,"
           "\"idmapped_mount\":true}\n",
           (unsigned long)source_status.st_uid,
           (unsigned long)source_status.st_gid,
           (unsigned long)mapped_status.st_uid,
           (unsigned long)mapped_status.st_gid);
    return EXIT_SUCCESS;
}
