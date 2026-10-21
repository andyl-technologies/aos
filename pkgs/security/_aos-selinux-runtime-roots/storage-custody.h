/* SPDX-License-Identifier: MIT */
/* Empty fixed targets for PID1's readonly Storage credential mounts. */

#define STORAGE_CUSTODY_CONTEXT "system_u:object_r:aos_sandbox_storage_custody_mount_t"
#define STORAGE_FLOOR_CONTEXT "system_u:object_r:aos_method46_storage_floor_t"

static bool empty_custody_target_metadata(const struct stat *status, dev_t device) {
        return S_ISREG(status->st_mode) && (status->st_mode & 07777) == 0400 &&
                status->st_uid == 0 && status->st_gid == 0 && status->st_nlink == 1 &&
                status->st_size == 0 && status->st_dev == device;
}

static int open_custody_target(int parent, const char *name, bool create) {
        struct open_how how = {
                .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                        RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
        };
        int fd = (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));

        if (fd >= 0 || errno != ENOENT || !create)
                return fd;
        if (write_creation_context(STORAGE_CUSTODY_CONTEXT) < 0)
                return -1;

        /* Targets contain no data. Their final mode and label apply at birth;
         * existing files are never truncated, relabeled, chowned or repaired. */
        const mode_t previous_mask = umask(0);
        how.flags |= O_CREAT | O_EXCL;
        how.mode = 0400;
        fd = (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));
        const int saved_errno = errno;
        umask(previous_mask);
        if (write_creation_context(NULL) < 0) {
                if (fd >= 0)
                        close(fd);
                return -1;
        }
        errno = saved_errno;
        return fd;
}

static int inspect_custody_target(int fd, const char *name, uint64_t mount_id,
                                  dev_t device, struct stat *status) {
        char context[MAXIMUM_CONTEXT_BYTES];
        uint64_t observed_mount;

        if (fstat(fd, status) < 0)
                return -1;
        if (!empty_custody_target_metadata(status, device)) {
                errorf("Storage custody target '%s' is not an empty fixed 0:0 0400 inode", name);
                errno = EPERM;
                return -1;
        }
        if (directory_mount_id(fd, name, &observed_mount) < 0)
                return -1;
        if (observed_mount != mount_id) {
                errorf("Storage custody target '%s' crosses the protected mount", name);
                errno = EXDEV;
                return -1;
        }
        if (read_directory_context(fd, context) < 0)
                return -1;
        if (strcmp(context, STORAGE_CUSTODY_CONTEXT) != 0) {
                errorf("Storage custody target '%s' has an unexpected raw label", name);
                errno = EPERM;
                return -1;
        }
        return 0;
}

static int prepare_custody_target(int parent, const char *name, uint64_t mount_id,
                                  dev_t device, bool create) {
        struct stat before, after;
        int fd = open_custody_target(parent, name, create);
        int reopened = -1;
        int result = -1;

        if (fd < 0) {
                errorf("cannot open fixed Storage custody target '%s': %s", name, strerror(errno));
                return -1;
        }
        if (inspect_custody_target(fd, name, mount_id, device, &before) < 0)
                goto out;
        if (create && (fsync(fd) < 0 || sync_directory(parent, "Storage custody") < 0))
                goto out;

        reopened = open_custody_target(parent, name, false);
        if (reopened < 0 || inspect_custody_target(reopened, name, mount_id, device, &after) < 0)
                goto out;
        if (before.st_dev != after.st_dev || before.st_ino != after.st_ino) {
                errorf("Storage custody target '%s' changed identity", name);
                errno = ESTALE;
                goto out;
        }
        result = 0;
out:
        if (reopened >= 0)
                close(reopened);
        close(fd);
        return result;
}

static int prepare_custody_directory(int parent, const struct directory_spec *spec,
                                     const char *const names[3], uint64_t mount_id,
                                     dev_t device, bool create) {
        struct directory_identity identity;
        int directory = owner_directory_step(parent, spec, mount_id, device, false, &identity);
        bool fresh = false;
        int result = -1;

        if (directory == -1) {
                if (!create)
                        return 0;
                struct directory_spec birth = *spec;
                birth.mode = 0700;
                if (create_directory(parent, &birth) < 0 ||
                    open_existing_directory(parent, &birth, mount_id, device, &directory) < 0 ||
                    directory < 0)
                        return -1;
                fresh = true;
        }
        if (directory < 0)
                return -1;
        if (inspect_owned_names(directory, spec->display_path, names, 3, false) < 0)
                goto out;
        for (size_t index = 0; index < 3; ++index) {
                if (prepare_custody_target(directory, names[index], mount_id, device, fresh) < 0)
                        goto out;
        }
        /* Only this newly created held inode may be sealed. An existing 0700
         * directory, including an interrupted birth, is refused without repair. */
        if (fresh && (fchmod(directory, spec->mode) < 0 ||
                      sync_directory(directory, spec->display_path) < 0 ||
                      sync_directory(parent, "Storage custody parent") < 0))
                goto out;
        if (inspect_directory(directory, spec, mount_id, device, &identity) < 0 ||
            reopen_matches(parent, spec, mount_id, device, &identity) < 0)
                goto out;
        result = 0;
out:
        close(directory);
        return result;
}

static int prepare_storage_custody(int broker, uint64_t mount_id, dev_t device, bool create) {
        static const struct directory_spec broker_custody = {
                "custody", "/var/lib/aos/sandbox-storage/broker-session/custody",
                STORAGE_CUSTODY_CONTEXT, 0500, 0, 0,
        };
        static const struct directory_spec host = {
                "host", "/var/lib/aos/sandbox-storage/broker-session/host",
                STORAGE_FLOOR_CONTEXT, 0700, 0, 0,
        };
        static const struct directory_spec host_custody = {
                "custody", "/var/lib/aos/sandbox-storage/broker-session/host/custody",
                STORAGE_CUSTODY_CONTEXT, 0500, 0, 0,
        };
        static const char *const broker_names[3] = {
                "broker-session-manifest", "broker-hello-signing-key", "broker-outcome-signing-key",
        };
        static const char *const client_names[3] = {
                "broker-session-manifest", "client-hello-signing-key", "client-record-signing-key",
        };
        struct directory_identity identity;
        int host_directory;
        int result = -1;

        if (prepare_custody_directory(broker, &broker_custody, broker_names, mount_id, device, create) < 0)
                return -1;
        host_directory = owner_directory_step(broker, &host, mount_id, device, create, &identity);
        if (host_directory == -1 && !create)
                return 0;
        if (host_directory < 0)
                return -1;
        if (prepare_custody_directory(host_directory, &host_custody, client_names, mount_id, device, create) < 0 ||
            inspect_directory(host_directory, &host, mount_id, device, &identity) < 0 ||
            reopen_matches(broker, &host, mount_id, device, &identity) < 0)
                goto out;
        result = 0;
out:
        close(host_directory);
        return result;
}
