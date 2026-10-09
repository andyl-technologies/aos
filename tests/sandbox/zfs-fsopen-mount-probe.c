/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Proves that the packaged OpenZFS kernel module supports descriptor-first
 * fsopen/fsconfig/fsmount construction for a canmount=off,mountpoint=none
 * dataset or snapshot, followed by move_mount onto an already-open slot.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__NR_fsconfig) || !defined(__NR_fsmount) ||                 \
    !defined(__NR_fsopen) || !defined(__NR_mount_setattr) ||             \
    !defined(__NR_move_mount)
#error "Linux headers do not expose the descriptor-first mount syscall surface"
#endif

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif

static void fail(const char *operation)
{
    fprintf(stderr, "zfs-fsopen-mount-probe: %s: %s\n", operation,
            strerror(errno));
    exit(EXIT_FAILURE);
}

static unsigned long long unique_mount_id(int fd, const char *operation)
{
    struct statx status = {0};

    if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
              STATX_MNT_ID_UNIQUE, &status) < 0)
        fail(operation);
    if ((status.stx_mask & STATX_MNT_ID_UNIQUE) == 0 || status.stx_mnt_id == 0) {
        errno = ENODATA;
        fail(operation);
    }
    return status.stx_mnt_id;
}

int main(int argc, char **argv)
{
    struct mount_attr read_only_attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                    MOUNT_ATTR_NOEXEC,
    };
    struct stat root_status;
    const char *source;
    const char *target;
    unsigned long long underlying_mount_id;
    unsigned long long detached_mount_id = 0;
    unsigned long long zfs_mount_id;
    bool snapshot_read_only;
    int filesystem_fd;
    int detached_mount_fd;
    int target_fd;
    int mounted_root_fd;
    int payload_fd;
    int write_fd;
    char payload[64];

    snapshot_read_only = argc == 4 &&
                         strcmp(argv[1], "--readonly-snapshot") == 0;
    if (argc != 3 && !snapshot_read_only) {
        fprintf(stderr,
                "usage: %s [--readonly-snapshot] DATASET TARGET_DIRECTORY\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    source = argv[snapshot_read_only ? 2 : 1];
    target = argv[snapshot_read_only ? 3 : 2];

    target_fd = open(target, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (target_fd < 0)
        fail("open destination slot");
    underlying_mount_id = unique_mount_id(target_fd, "inspect destination slot");

    filesystem_fd = (int)syscall(__NR_fsopen, "zfs", FSOPEN_CLOEXEC);
    if (filesystem_fd < 0)
        fail("fsopen zfs");
    if (syscall(__NR_fsconfig, filesystem_fd, FSCONFIG_SET_STRING,
                "source", source, 0) < 0)
        fail("fsconfig zfs source");
    if (syscall(__NR_fsconfig, filesystem_fd, FSCONFIG_CMD_CREATE,
                NULL, NULL, 0) < 0)
        fail("fsconfig create zfs");

    detached_mount_fd = (int)syscall(__NR_fsmount, filesystem_fd,
                                     FSMOUNT_CLOEXEC, 0);
    if (detached_mount_fd < 0)
        fail("fsmount zfs");
    if (snapshot_read_only) {
        detached_mount_id = unique_mount_id(detached_mount_fd,
                                             "inspect detached snapshot root");
        if (syscall(__NR_mount_setattr, detached_mount_fd, "",
                    AT_EMPTY_PATH | AT_RECURSIVE, &read_only_attributes,
                    sizeof(read_only_attributes)) < 0)
            fail("secure read-only snapshot mount");
        payload_fd = openat(detached_mount_fd, "payload",
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (payload_fd < 0)
            fail("read detached snapshot payload");
        if (read(payload_fd, payload, sizeof(payload)) <= 0)
            fail("read snapshot payload bytes");
        write_fd = openat(detached_mount_fd, "payload",
                          O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (write_fd >= 0 || errno != EROFS) {
            errno = EBADE;
            fail("detached snapshot mount allowed writable payload");
        }
    }
    if (syscall(__NR_move_mount, detached_mount_fd, "", target_fd, "",
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) < 0)
        fail("move_mount zfs onto destination descriptor");

    mounted_root_fd = open(target, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mounted_root_fd < 0)
        fail("open attached ZFS root");
    zfs_mount_id = unique_mount_id(mounted_root_fd, "inspect attached ZFS root");
    if (zfs_mount_id == underlying_mount_id) {
        errno = EBADE;
        fail("attached mount retained underlying mount identity");
    }
    if (snapshot_read_only && zfs_mount_id != detached_mount_id) {
        errno = EBADE;
        fail("attached snapshot changed detached mount identity");
    }
    if (fstat(mounted_root_fd, &root_status) < 0)
        fail("fstat attached ZFS root");

    printf("{\"schema_version\":\"aos.sandbox.zfs-fsopen-mount/v1\","
           "\"underlying_mount_id\":%llu,\"zfs_mount_id\":%llu,"
           "\"root_device\":%llu,\"root_inode\":%llu,"
           "\"descriptor_attached\":true,\"snapshot_read_only\":%s}\n",
           underlying_mount_id, zfs_mount_id,
           (unsigned long long)root_status.st_dev,
           (unsigned long long)root_status.st_ino,
           snapshot_read_only ? "true" : "false");
    return EXIT_SUCCESS;
}
