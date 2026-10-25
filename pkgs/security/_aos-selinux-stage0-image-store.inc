// SPDX-License-Identifier: Apache-2.0
// Retains shipped immutable DATA as well as PID 1's executable closure.

static void pin_image_store(int lower_store_fd) {
    struct stat root_status;
    struct stat lower_status;
    unsigned long count = 0;
    DIR *entries;
    int reader;

    if (stat("/", &root_status) < 0 || fstat(lower_store_fd, &lower_status) < 0 ||
        !S_ISDIR(lower_status.st_mode) || lower_status.st_uid != 0 ||
        lower_status.st_gid != 0 || lower_status.st_dev != root_status.st_dev) {
        fail_closed("image store is not on the authenticated root filesystem");
    }
    reader = openat(lower_store_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (reader < 0) {
        fail_closed("open authenticated image store inventory: %s", strerror(errno));
    }
    entries = fdopendir(reader);
    if (entries == NULL) {
        close(reader);
        fail_closed("retain authenticated image store inventory: %s", strerror(errno));
    }

    // Only the signed physical inventory is enumerated. The writable overlay
    // can still receive new paths, but cannot replace a shipped profile or ELF.
    for (;;) {
        struct dirent *entry;
        struct stat status;

        errno = 0;
        entry = readdir(entries);
        if (entry == NULL) {
            if (errno != 0) {
                fail_closed("read authenticated image store inventory: %s", strerror(errno));
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, ".links") == 0) {
            continue;
        }
        if (++count > MAX_IMAGE_STORE_ROOTS) {
            fail_closed("authenticated image store exceeds its root bound");
        }
        if (fstatat(dirfd(entries), entry->d_name, &status, AT_SYMLINK_NOFOLLOW) < 0) {
            fail_closed("inspect authenticated image store entry: %s", strerror(errno));
        }
        // Symlink outputs have no independent file custody. Immutable readers
        // require their canonical target, whose shipped root is pinned here.
        if (S_ISLNK(status.st_mode)) {
            continue;
        }
        pin_runtime_root(lower_store_fd, entry->d_name, strlen(entry->d_name));
    }

    if (closedir(entries) < 0) {
        fail_closed("close authenticated image store inventory: %s", strerror(errno));
    }
    log_status("authenticated image store pinned: %lu roots", count);
}
