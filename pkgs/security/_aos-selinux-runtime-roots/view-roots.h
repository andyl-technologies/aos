/* SPDX-License-Identifier: MIT */
/* Fixed Source/Cache roots on the image-selected ext4 or ZFS substrate.
 * Included after the shared retained-directory and fresh-only helpers. */

#ifndef AOS_SOURCE_VIEW_REQUIRED
#define AOS_SOURCE_VIEW_REQUIRED 0
#endif
#ifndef AOS_CACHE_VIEW_REQUIRED
#define AOS_CACHE_VIEW_REQUIRED 0
#endif
#ifndef AOS_CACHE_SIGNER_VIEW_REQUIRED
#define AOS_CACHE_SIGNER_VIEW_REQUIRED 0
#endif
#ifndef AOS_VIEW_ZFS_STATE
#define AOS_VIEW_ZFS_STATE 0
#endif
#ifndef AOS_VIEW_ZFS_SOURCE
#define AOS_VIEW_ZFS_SOURCE ""
#endif
#define AOS_ZFS_SUPER_MAGIC 0x2fc12fc1UL

struct view_mount_response {
        struct statmount status;
        char strings[1024];
};

static bool view_mount_string_matches(const struct view_mount_response *response,
                                      uint32_t offset, const char *expected) {
        const size_t start = offsetof(struct statmount, str);
        size_t size;
        const char *value;

        if (response->status.size < start || response->status.size > sizeof(*response))
                return false;
        size = response->status.size - start;
        if (offset >= size)
                return false;
        value = (const char *)response + start + offset;
        return memchr(value, '\0', size - offset) != NULL && strcmp(value, expected) == 0;
}

static int validate_view_mount_response(const struct view_mount_response *response,
                                        uint64_t mount_id, dev_t device, bool zfs) {
        const uint64_t required = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
                STATMOUNT_FS_TYPE | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT |
                (zfs ? STATMOUNT_SB_SOURCE : 0);
        const uint64_t allowed = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC |
                MOUNT_ATTR_NOSYMFOLLOW | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME |
                MOUNT_ATTR_NODIRATIME;

        if ((response->status.mask & required) != required ||
            response->status.mnt_id != mount_id ||
            makedev(response->status.sb_dev_major, response->status.sb_dev_minor) != device ||
            response->status.sb_magic != (zfs ? AOS_ZFS_SUPER_MAGIC : EXT4_SUPER_MAGIC) ||
            (response->status.mnt_attr & (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)) !=
                    (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV) ||
            (response->status.mnt_attr & ~allowed) != 0 ||
            !view_mount_string_matches(response, response->status.fs_type, zfs ? "zfs" : "ext4") ||
            !view_mount_string_matches(response, response->status.mnt_root, "/") ||
            !view_mount_string_matches(response, response->status.mnt_point, zfs ? "/var/lib" : "/var") ||
            (zfs && !view_mount_string_matches(response, response->status.sb_source, AOS_VIEW_ZFS_SOURCE))) {
                errorf("view state is not the exact image-selected writable mount");
                errno = EXDEV;
                return -1;
        }
        return 0;
}

static int verify_view_mount(uint64_t mount_id, dev_t device, bool zfs) {
        struct view_mount_response response;
        struct mnt_id_req request = {
                .size = MNT_ID_REQ_SIZE_VER0,
                .mnt_id = mount_id,
                .param = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_FS_TYPE |
                        STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT |
                        (zfs ? STATMOUNT_SB_SOURCE : 0),
        };

        memset(&response, 0, sizeof(response));
        if (syscall(__NR_statmount, &request, &response, sizeof(response), 0U) < 0) {
                errorf("cannot observe the retained view-state mount: %s", strerror(errno));
                return -1;
        }
        return validate_view_mount_response(&response, mount_id, device, zfs);
}

static int verify_view_temporary_mount(uint64_t mount_id, dev_t device) {
        struct view_mount_response response;
        const uint64_t required = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
                STATMOUNT_FS_TYPE | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT;
        const uint64_t flags = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
        struct mnt_id_req request = {
                .size = MNT_ID_REQ_SIZE_VER0, .mnt_id = mount_id, .param = required,
        };

        memset(&response, 0, sizeof(response));
        if (syscall(__NR_statmount, &request, &response, sizeof(response), 0U) < 0 ||
            (response.status.mask & required) != required || response.status.mnt_id != mount_id ||
            makedev(response.status.sb_dev_major, response.status.sb_dev_minor) != device ||
            response.status.sb_magic != TMPFS_MAGIC || response.status.mnt_attr != flags ||
            !view_mount_string_matches(&response, response.status.fs_type, "tmpfs") ||
            !view_mount_string_matches(&response, response.status.mnt_root, "/") ||
            !view_mount_string_matches(&response, response.status.mnt_point, "/run")) {
                errorf("view mount targets are not on the exact writable /run tmpfs");
                errno = EXDEV;
                return -1;
        }
        return 0;
}

static int view_fixed_name_matches(const char *path, const struct directory_spec *spec,
                                    uint64_t mount_id, dev_t device, ino_t inode) {
        struct directory_identity identity;
        int fd = openat2_directory(AT_FDCWD, path, RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS);
        int result = -1;

        if (fd < 0)
                return -1;
        if (inspect_directory(fd, spec, mount_id, device, &identity) == 0 && identity.inode == inode)
                result = 0;
        close(fd);
        return result;
}

static const struct directory_spec view_parent_spec = {
        "sandbox", "/var/lib/aos/sandbox", "system_u:object_r:aos_sandbox_view_parent_t", 0755, 0, 0,
};
static const struct directory_spec view_source_specs[] = {
        {"source-domains", "/var/lib/aos/sandbox/source-domains",
         "system_u:object_r:aos_sandbox_source_journal_t", 0700, AOS_CONTROLLER_UID, AOS_CONTROLLER_GID},
        {"cache-residency-journals", "/var/lib/aos/sandbox/cache-residency-journals",
         "system_u:object_r:aos_sandbox_cache_journal_t", 0700, AOS_CONTROLLER_UID, AOS_CONTROLLER_GID},
        {"cache-residency-objects", "/var/lib/aos/sandbox/cache-residency-objects",
         "system_u:object_r:aos_sandbox_cache_object_t", 0700, AOS_CONTROLLER_UID, AOS_CONTROLLER_GID},
};
static const bool view_source_enabled[] = {
        AOS_SOURCE_VIEW_REQUIRED, AOS_CACHE_VIEW_REQUIRED, AOS_CACHE_SIGNER_VIEW_REQUIRED,
};
static const struct directory_spec view_run_parent_spec = {
        "aos", "/run/aos", "system_u:object_r:var_run_t", 0755, 0, 0,
};
static const struct directory_spec view_target_specs[] = {
        {"sandbox-source-signer-journal", "/run/aos/sandbox-source-signer-journal",
         "system_u:object_r:aos_sandbox_source_view_mount_t", 0700, 0, 0},
        {"sandbox-policy-cache-journals", "/run/aos/sandbox-policy-cache-journals",
         "system_u:object_r:aos_sandbox_cache_view_mount_t", 0700, 0, 0},
        {"sandbox-cache-signer-journals", "/run/aos/sandbox-cache-signer-journals",
         "system_u:object_r:aos_sandbox_cache_view_mount_t", 0700, 0, 0},
        {"sandbox-cache-signer-objects", "/run/aos/sandbox-cache-signer-objects",
         "system_u:object_r:aos_sandbox_cache_view_mount_t", 0700, 0, 0},
};
static const bool view_target_enabled[] = {
        AOS_SOURCE_VIEW_REQUIRED, AOS_CACHE_VIEW_REQUIRED,
        AOS_CACHE_SIGNER_VIEW_REQUIRED, AOS_CACHE_SIGNER_VIEW_REQUIRED,
};

/* Existing checked view scripts are serialized by their fixed unit order.
 * EEXIST during a just-missing creation remains refusal, never adoption. */
static int walk_view_tree(int base, const struct directory_spec *parent_spec,
                          const struct directory_spec *children, const bool *enabled,
                          size_t count, uint64_t mount_id, dev_t device, bool create) {
        struct directory_identity parent_identity, child_identity;
        int parent = -1, child = -1;
        int result = -1;

        parent = owner_directory_step(base, parent_spec, mount_id, device, create, &parent_identity);
        if (parent == -1 && !create)
                return 0;
        if (parent < 0)
                return -1;
        if (inspect_directory(parent, parent_spec, mount_id, device, &parent_identity) < 0)
                goto out;
        for (size_t index = 0; index < count; ++index) {
                if (!enabled[index])
                        continue;
                child = owner_directory_step(parent, &children[index], mount_id, device, create,
                                             &child_identity);
                if (child == -1 && !create)
                        continue;
                if (child < 0)
                        goto out;
                if (inspect_directory(child, &children[index], mount_id, device, &child_identity) < 0 ||
                    (child_identity.device == parent_identity.device &&
                     child_identity.inode == parent_identity.inode) ||
                    reopen_matches(parent, &children[index], mount_id, device, &child_identity) < 0)
                        goto out;
                close(child);
                child = -1;
        }
        result = reopen_matches(base, parent_spec, mount_id, device, &parent_identity);
out:
        if (child >= 0)
                close(child);
        close(parent);
        return result;
}

static int provision_view_roots(void) {
        static const uint64_t fixed_resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
        static const struct directory_spec run_spec = {
                "run", "/run", "system_u:object_r:var_run_t", 0755, 0, 0,
        };
        static const struct directory_spec var_spec = {
                "var", "/var", VAR_CONTEXT, 0755, 0, 0,
        };
        struct directory_identity aos_identity, run_identity, lib_identity, var_identity;
        struct stat lib_stat, run_stat, var_stat, device_stat;
        struct statfs lib_fs, run_fs;
        uint64_t lib_mount, run_mount, var_mount;
        int lib_fd = -1, run_fd = -1, var_fd = -1, aos_fd = -1;
        int result = -1;

        lib_fd = openat2_directory(AT_FDCWD, "/var/lib", fixed_resolve);
        run_fd = openat2_directory(AT_FDCWD, "/run", fixed_resolve);
        var_fd = openat2_directory(AT_FDCWD, "/var", fixed_resolve);
        if (lib_fd < 0 || run_fd < 0 || var_fd < 0 || fstat(var_fd, &var_stat) < 0 ||
            directory_mount_id(var_fd, "/var", &var_mount) < 0 ||
            inspect_directory(var_fd, &var_spec, var_mount, var_stat.st_dev, &var_identity) < 0 ||
            fstat(lib_fd, &lib_stat) < 0 ||
            fstat(run_fd, &run_stat) < 0 || fstatfs(lib_fd, &lib_fs) < 0 ||
            fstatfs(run_fd, &run_fs) < 0 ||
            directory_mount_id(lib_fd, "/var/lib", &lib_mount) < 0 ||
            directory_mount_id(run_fd, "/run", &run_mount) < 0)
                goto out;
        if (lib_stat.st_uid != 0 || lib_stat.st_gid != 0 ||
            (lib_stat.st_mode & 07777) != 0755 ||
            lib_fs.f_type != (AOS_VIEW_ZFS_STATE ? AOS_ZFS_SUPER_MAGIC : EXT4_SUPER_MAGIC) ||
            run_fs.f_type != TMPFS_MAGIC || run_mount == lib_mount) {
                errorf("view state/temporary root is not the supported protected substrate");
                errno = EXDEV;
                goto out;
        }
        if (AOS_VIEW_ZFS_STATE) {
                if (verify_view_mount(lib_mount, lib_stat.st_dev, true) < 0)
                        goto out;
        } else {
                if (select_var_device(&device_stat) < 0 || var_mount != lib_mount ||
                    var_stat.st_dev != device_stat.st_rdev || var_stat.st_ino != 2 ||
                    verify_ext4_mount(var_mount, var_stat.st_dev) < 0 ||
                    verify_view_mount(lib_mount, lib_stat.st_dev, false) < 0)
                        goto out;
        }
        if (inspect_directory(lib_fd, &var_lib_spec, lib_mount, lib_stat.st_dev, &lib_identity) < 0 ||
            inspect_directory(run_fd, &run_spec, run_mount, run_stat.st_dev, &run_identity) < 0 ||
            verify_view_temporary_mount(run_mount, run_stat.st_dev) < 0)
                goto out;
        if (open_existing_directory(lib_fd, &aos_spec, lib_mount, lib_stat.st_dev, &aos_fd) < 0)
                goto out;
        if (aos_fd >= 0 && walk_view_tree(aos_fd, &view_parent_spec, view_source_specs,
                                        view_source_enabled, 3, lib_mount, lib_stat.st_dev, false) < 0)
                goto out;
        if (walk_view_tree(run_fd, &view_run_parent_spec, view_target_specs, view_target_enabled,
                           4, run_mount, run_stat.st_dev, false) < 0)
                goto out;

        /* Both state and temporary peers were preflighted before first creation. */
        if (aos_fd >= 0)
                close(aos_fd);
        aos_fd = open_or_create_directory(lib_fd, &aos_spec, lib_mount, lib_stat.st_dev, &aos_identity);
        if (aos_fd < 0 ||
            walk_view_tree(aos_fd, &view_parent_spec, view_source_specs, view_source_enabled,
                           3, lib_mount, lib_stat.st_dev, true) < 0 ||
            walk_view_tree(run_fd, &view_run_parent_spec, view_target_specs, view_target_enabled,
                           4, run_mount, run_stat.st_dev, true) < 0 ||
            verify_view_mount(lib_mount, lib_stat.st_dev, AOS_VIEW_ZFS_STATE) < 0 ||
            reopen_matches(lib_fd, &aos_spec, lib_mount, lib_stat.st_dev, &aos_identity) < 0 ||
            verify_view_temporary_mount(run_mount, run_stat.st_dev) < 0 ||
            view_fixed_name_matches("/var/lib", &var_lib_spec, lib_mount, lib_stat.st_dev, lib_stat.st_ino) < 0 ||
            view_fixed_name_matches("/var", &var_spec, var_mount, var_stat.st_dev, var_stat.st_ino) < 0 ||
            view_fixed_name_matches("/run", &run_spec, run_mount, run_stat.st_dev, run_stat.st_ino) < 0)
                goto out;
        result = 0;
out:
        if (aos_fd >= 0)
                close(aos_fd);
        if (var_fd >= 0)
                close(var_fd);
        if (run_fd >= 0)
                close(run_fd);
        if (lib_fd >= 0)
                close(lib_fd);
        char creation_context[MAXIMUM_CONTEXT_BYTES];
        if (write_creation_context(NULL) < 0 ||
            read_bounded_text("/proc/thread-self/attr/fscreate", creation_context, sizeof(creation_context)) < 0 ||
            creation_context[0] != '\0' || verify_selinux_authority() < 0)
                result = -1;
        return result;
}
