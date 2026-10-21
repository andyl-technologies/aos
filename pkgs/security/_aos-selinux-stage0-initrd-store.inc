// SPDX-License-Identifier: Apache-2.0
// Bounded mutable initrd bookkeeping around the original EROFS store entries.

static void pin_initial_store_entry(int lower_store_fd, const char *basename) {
    static const char nix_base32[] = "0123456789abcdfghijklmnpqrsvwxyz";
    static const char name_characters[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+._?=-";
    size_t length = strlen(basename);
    char logical[PATH_MAX];
    struct stat physical;
    struct stat pinned;
    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    int original;
    int clone;

    if (length < 34 || length >= NAME_MAX || basename[32] != '-' ||
        strspn(basename, nix_base32) != 32 ||
        strspn(basename + 33, name_characters) != length - 33 ||
        snprintf(logical, sizeof(logical), "/nix/store/%s", basename) >= (int)sizeof(logical)) {
        fail_closed("initial store entry has a noncanonical name");
    }

    original = (int)syscall(SYS_openat2, lower_store_fd, basename, &how, sizeof(how));
    if (original < 0 || fstat(original, &physical) < 0 ||
        physical.st_uid != 0 || physical.st_gid != 0 ||
        (!S_ISDIR(physical.st_mode) && !S_ISREG(physical.st_mode))) {
        fail_closed("initial store entry %s is not an immutable file or directory", basename);
    }

    if (S_ISDIR(physical.st_mode)) {
        ensure_directory(logical, 0755);
    } else {
        int placeholder = open(logical, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0444);

        if (placeholder < 0 || close(placeholder) < 0) {
            fail_closed("create initial store file placeholder %s: %s", logical, strerror(errno));
        }
    }

    clone = (int)syscall(SYS_open_tree, original, "",
                         AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (clone < 0 ||
        syscall(SYS_mount_setattr, clone, "", AT_EMPTY_PATH, &attributes, sizeof(attributes)) < 0 ||
        syscall(SYS_move_mount, clone, "", AT_FDCWD, logical, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        fail_closed("pin initial store entry %s: %s", logical, strerror(errno));
    }
    if (close(clone) < 0 || close(original) < 0 || stat(logical, &pinned) < 0 ||
        pinned.st_dev != physical.st_dev || pinned.st_ino != physical.st_ino) {
        fail_closed("initial store entry %s lost its original inode", logical);
    }
    require_filesystem(logical, EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NOSUID | ST_NODEV, 0);
}

static void prepare_initial_store_state(void) {
    DIR *lower;
    unsigned long count = 0;

    require_filesystem("/nix/store", EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NODEV, 0);
    lower = opendir("/nix/store");
    if (lower == NULL) {
        fail_closed("retain immutable initial store: %s", strerror(errno));
    }

    // The ordinary cpio initrd has mutable Nix bookkeeping. The labeled EROFS
    // stage needs the same finite database and retained-object space, while
    // every shipped entry remains its original read-only physical mount.
    // No closure bytes are copied into this writable filesystem.
    mount_filesystem("tmpfs", "/nix/store", "tmpfs", MS_NOSUID | MS_NODEV,
                     "size=320M,nr_inodes=131072,mode=0755", TMPFS_MAGIC,
                     ST_NOSUID | ST_NODEV, ST_RDONLY | ST_NOEXEC);
    mount_filesystem("tmpfs", "/nix/var", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                     "size=64M,nr_inodes=16384,mode=0755", TMPFS_MAGIC,
                     ST_NOSUID | ST_NODEV | ST_NOEXEC, ST_RDONLY);

    for (;;) {
        struct dirent *entry;

        errno = 0;
        entry = readdir(lower);
        if (entry == NULL) {
            if (errno != 0) {
                fail_closed("enumerate immutable initial store: %s", strerror(errno));
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, ".links") == 0) {
            continue;
        }
        if (++count > 8192) {
            fail_closed("initial immutable store exceeds its entry bound");
        }
        pin_initial_store_entry(dirfd(lower), entry->d_name);
    }
    if (count == 0 || closedir(lower) < 0) {
        fail_closed("initial immutable store is empty or cannot be closed");
    }
    log_status("initial store retains %lu immutable entries with bounded writable bookkeeping", count);
}
