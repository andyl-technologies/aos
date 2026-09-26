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
#include <grp.h>
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

struct namespace_observation {
    uid_t existing_uid;
    gid_t existing_gid;
    uid_t created_uid;
    gid_t created_gid;
    int error_number;
    unsigned int error_step;
};

static void child_error(int fd, struct namespace_observation *observation,
                        unsigned int step)
{
    ssize_t written;

    observation->error_number = errno;
    observation->error_step = step;
    written = write(fd, observation, sizeof(*observation));
    if (written != (ssize_t)sizeof(*observation))
        _exit(EXIT_FAILURE);
    _exit(EXIT_FAILURE);
}

static void read_exact(int fd, void *buffer, size_t length,
                       const char *operation)
{
    char *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t received = read(fd, bytes + offset, length - offset);

        if (received < 0) {
            if (errno == EINTR)
                continue;
            fail(operation);
        }
        if (received == 0) {
            errno = EIO;
            fail(operation);
        }
        offset += (size_t)received;
    }
}

static struct namespace_observation observe_from_mapped_namespace(
    int user_namespace_fd, const char *existing_file, const char *created_file)
{
    struct namespace_observation observation = {0};
    struct stat status;
    int result_pipe[2];
    pid_t child;
    int created_fd;
    int wait_status;

    if (pipe2(result_pipe, O_CLOEXEC) < 0)
        fail("creating namespace observation pipe");
    child = fork();
    if (child < 0)
        fail("forking namespace observer");
    if (child == 0) {
        if (close(result_pipe[0]) < 0)
            child_error(result_pipe[1], &observation, 1);
        if (setgroups(0, NULL) < 0)
            child_error(result_pipe[1], &observation, 2);
        if (setns(user_namespace_fd, CLONE_NEWUSER) < 0)
            child_error(result_pipe[1], &observation, 3);
        if (setresgid(0, 0, 0) < 0)
            child_error(result_pipe[1], &observation, 4);
        if (setresuid(0, 0, 0) < 0)
            child_error(result_pipe[1], &observation, 5);
        if (stat(existing_file, &status) < 0)
            child_error(result_pipe[1], &observation, 6);
        observation.existing_uid = status.st_uid;
        observation.existing_gid = status.st_gid;

        created_fd = open(created_file,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (created_fd < 0)
            child_error(result_pipe[1], &observation, 7);
        if (close(created_fd) < 0)
            child_error(result_pipe[1], &observation, 8);
        if (stat(created_file, &status) < 0)
            child_error(result_pipe[1], &observation, 9);
        observation.created_uid = status.st_uid;
        observation.created_gid = status.st_gid;

        write_all(result_pipe[1], (const char *)&observation,
                  sizeof(observation), "returning namespace observation");
        _exit(EXIT_SUCCESS);
    }

    if (close(result_pipe[1]) < 0)
        fail("closing parent namespace observation pipe");
    read_exact(result_pipe[0], &observation, sizeof(observation),
               "reading namespace observation");
    if (close(result_pipe[0]) < 0)
        fail("closing namespace observation pipe");
    if (waitpid(child, &wait_status, 0) < 0)
        fail("waiting for namespace observer");
    if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != EXIT_SUCCESS) {
        fprintf(stderr,
                "zfs-idmapped-mount-probe: namespace observation step %u "
                "failed: %s\n",
                observation.error_step, strerror(observation.error_number));
        exit(EXIT_FAILURE);
    }
    return observation;
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
    struct namespace_observation namespace_observation;
    struct stat created_mapped_status;
    struct stat created_source_status;
    struct stat source_status;
    struct stat mapped_status;
    char created_mapped_file[4096];
    char created_source_file[4096];
    char mapped_file[4096];
    const char *file_name;
    int created_mapped_length;
    int created_source_length;
    int mapped_length;
    int user_namespace_fd;
    int mount_fd;

    if (argc != 4) {
        fprintf(stderr, "usage: %s SOURCE_MOUNT TARGET_MOUNT SOURCE_FILE\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    if (stat(argv[3], &source_status) < 0)
        fail("stat source fixture");
    if (source_status.st_uid != 0 || source_status.st_gid != 0) {
        errno = EBADE;
        fail("source fixture is not canonically root-owned on ZFS");
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
    if (mapped_status.st_uid != IDMAP_BASE ||
        mapped_status.st_gid != IDMAP_BASE) {
        errno = EBADE;
        fprintf(stderr,
                "zfs-idmapped-mount-probe: host idmapped ownership was "
                "%lu:%lu, expected %u:%u\n",
                (unsigned long)mapped_status.st_uid,
                (unsigned long)mapped_status.st_gid, IDMAP_BASE, IDMAP_BASE);
        fail("host idmapped ZFS ownership translation");
    }

    created_mapped_length = snprintf(created_mapped_file,
                                     sizeof(created_mapped_file),
                                     "%s/idmap-created", argv[2]);
    created_source_length = snprintf(created_source_file,
                                     sizeof(created_source_file),
                                     "%s/idmap-created", argv[1]);
    if (created_mapped_length < 0 ||
        (size_t)created_mapped_length >= sizeof(created_mapped_file) ||
        created_source_length < 0 ||
        (size_t)created_source_length >= sizeof(created_source_file)) {
        errno = ENAMETOOLONG;
        fail("constructing created fixture paths");
    }
    namespace_observation = observe_from_mapped_namespace(
        user_namespace_fd, mapped_file, created_mapped_file);
    if (stat(argv[3], &source_status) < 0)
        fail("restat source fixture after idmapped access");
    if (stat(created_source_file, &created_source_status) < 0)
        fail("stat created source fixture");
    if (stat(created_mapped_file, &created_mapped_status) < 0)
        fail("stat created idmapped fixture");

    if (namespace_observation.existing_uid != 0 ||
        namespace_observation.existing_gid != 0 ||
        namespace_observation.created_uid != 0 ||
        namespace_observation.created_gid != 0 || source_status.st_uid != 0 ||
        source_status.st_gid != 0 ||
        created_source_status.st_uid != 0 || created_source_status.st_gid != 0 ||
        created_mapped_status.st_uid != IDMAP_BASE ||
        created_mapped_status.st_gid != IDMAP_BASE) {
        errno = EBADE;
        fprintf(stderr,
                "zfs-idmapped-mount-probe: ownership mismatch: sandbox "
                "existing=%lu:%lu created=%lu:%lu; source created=%lu:%lu; "
                "host mapped created=%lu:%lu\n",
                (unsigned long)namespace_observation.existing_uid,
                (unsigned long)namespace_observation.existing_gid,
                (unsigned long)namespace_observation.created_uid,
                (unsigned long)namespace_observation.created_gid,
                (unsigned long)created_source_status.st_uid,
                (unsigned long)created_source_status.st_gid,
                (unsigned long)created_mapped_status.st_uid,
                (unsigned long)created_mapped_status.st_gid);
        fail("idmapped ZFS ownership translation");
    }

    printf("{\"schema_version\":\"aos.sandbox.zfs-idmapped-mount/v1\","
           "\"source_uid\":%lu,\"source_gid\":%lu,"
           "\"host_mapped_uid\":%lu,\"host_mapped_gid\":%lu,"
           "\"sandbox_mapped_uid\":%lu,\"sandbox_mapped_gid\":%lu,"
           "\"created_source_uid\":%lu,\"created_source_gid\":%lu,"
           "\"idmapped_mount\":true}\n",
           (unsigned long)source_status.st_uid,
           (unsigned long)source_status.st_gid,
           (unsigned long)mapped_status.st_uid,
           (unsigned long)mapped_status.st_gid,
           (unsigned long)namespace_observation.existing_uid,
           (unsigned long)namespace_observation.existing_gid,
           (unsigned long)created_source_status.st_uid,
           (unsigned long)created_source_status.st_gid);
    return EXIT_SUCCESS;
}
