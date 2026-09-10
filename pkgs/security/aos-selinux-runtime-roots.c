/* SPDX-License-Identifier: MIT */
/* Provision fixed SELinux runtime roots without relabeling existing objects. */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define VAR_CONTEXT "system_u:object_r:var_t"
#define VAR_LIB_CONTEXT "system_u:object_r:var_lib_t"
#define NETWORK_ROOT_CONTEXT "system_u:object_r:aos_sandbox_network_root_t"
#define NETWORK_STATE_CONTEXT "system_u:object_r:aos_sandbox_network_state_t"
#define INSPECTOR_ROOT_CONTEXT "system_u:object_r:aos_sandbox_network_store_t"
#define EXPECTED_STAGING_CONTEXT "system_u:object_r:aos_sandbox_network_expected_staging_t"
#define EXPECTED_FINAL_CONTEXT "system_u:object_r:aos_sandbox_network_expected_final_t"
#define SPENT_STAGING_CONTEXT "system_u:object_r:aos_sandbox_network_spent_staging_t"
#define SPENT_FINAL_CONTEXT "system_u:object_r:aos_sandbox_network_spent_final_t"
#define EXPECTED_PROCESS_CONTEXT "system_u:system_r:aos_sandbox_runtime_roots_t"
#define MAXIMUM_POLICY_BYTES (64U * 1024U * 1024U)
#define MAXIMUM_CONTEXT_BYTES 256U

extern const unsigned char _binary_expected_policy_bin_start[];
extern const unsigned char _binary_expected_policy_bin_end[];

struct directory_spec {
        const char *name;
        const char *display_path;
        const char *context;
        mode_t mode;
};

struct directory_identity {
        dev_t device;
        ino_t inode;
        uint64_t mount_id;
        const char *display_path;
};

static const struct directory_spec var_lib_spec = {
        "lib", "/var/lib", VAR_LIB_CONTEXT, 0755,
};
static const struct directory_spec aos_spec = {
        "aos", "/var/lib/aos", VAR_LIB_CONTEXT, 0755,
};
static const struct directory_spec network_spec = {
        "sandbox-network", "/var/lib/aos/sandbox-network", NETWORK_ROOT_CONTEXT, 0700,
};
static const struct directory_spec broker_state_spec = {
        "broker-state", "/var/lib/aos/sandbox-network/broker-state", NETWORK_STATE_CONTEXT, 0700,
};
static const struct directory_spec inspector_spec = {
        "namespace-inspector", "/var/lib/aos/sandbox-network/namespace-inspector",
        INSPECTOR_ROOT_CONTEXT, 0700,
};
static const struct directory_spec inspector_children[] = {
        {"expected-staging", "/var/lib/aos/sandbox-network/namespace-inspector/expected-staging",
         EXPECTED_STAGING_CONTEXT, 0700},
        {"expected-final", "/var/lib/aos/sandbox-network/namespace-inspector/expected-final",
         EXPECTED_FINAL_CONTEXT, 0700},
        {"spent-staging", "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging",
         SPENT_STAGING_CONTEXT, 0700},
        {"spent-final", "/var/lib/aos/sandbox-network/namespace-inspector/spent-final",
         SPENT_FINAL_CONTEXT, 0700},
};

static void errorf(const char *format, ...) {
        va_list arguments;

        fputs("aos-selinux-runtime-roots: ", stderr);
        va_start(arguments, format);
        vfprintf(stderr, format, arguments);
        va_end(arguments);
        fputc('\n', stderr);
}

static ssize_t read_retry(int fd, void *buffer, size_t length) {
        ssize_t amount;

        do {
                amount = read(fd, buffer, length);
        } while (amount < 0 && errno == EINTR);

        return amount;
}

static ssize_t write_retry(int fd, const void *buffer, size_t length) {
        ssize_t amount;

        do {
                amount = write(fd, buffer, length);
        } while (amount < 0 && errno == EINTR);

        return amount;
}

static int read_bounded_text(const char *path, char *buffer, size_t capacity) {
        char trailing;
        ssize_t amount;
        ssize_t extra;
        int fd;
        int result = -1;

        if (capacity < 2) {
                errno = EINVAL;
                return -1;
        }
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return -1;

        amount = read_retry(fd, buffer, capacity - 1);
        if (amount < 0)
                goto out;
        extra = read_retry(fd, &trailing, 1);
        if (extra < 0)
                goto out;
        if (extra != 0) {
                errno = EOVERFLOW;
                goto out;
        }

        while (amount > 0 && (buffer[amount - 1] == '\n' || buffer[amount - 1] == '\0'))
                amount--;
        if (memchr(buffer, '\0', (size_t)amount) != NULL ||
            memchr(buffer, '\n', (size_t)amount) != NULL) {
                errno = EINVAL;
                goto out;
        }
        buffer[amount] = '\0';
        result = 0;

out:
        if (close(fd) < 0 && result == 0)
                result = -1;
        return result;
}

static int write_creation_context(const char *context) {
        const char *value = context == NULL ? "" : context;
        const size_t length = context == NULL ? 0 : strlen(value) + 1;
        size_t offset = 0;
        int fd;
        int result = -1;

        fd = open("/proc/thread-self/attr/fscreate", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return -1;
        do {
                ssize_t amount = write_retry(fd, value + offset, length - offset);

                if (amount < 0)
                        goto out;
                if (length != 0 && amount == 0) {
                        errno = EIO;
                        goto out;
                }
                offset += (size_t)amount;
        } while (offset < length);
        result = 0;

out:
        if (close(fd) < 0 && result == 0)
                result = -1;
        return result;
}

static int read_directory_context(int fd, char context[MAXIMUM_CONTEXT_BYTES]) {
        ssize_t amount = fgetxattr(fd, "security.selinux", context, MAXIMUM_CONTEXT_BYTES - 1);

        if (amount < 0)
                return -1;
        while (amount > 0 && context[amount - 1] == '\0')
                amount--;
        if (amount == 0 || (size_t)amount >= MAXIMUM_CONTEXT_BYTES ||
            memchr(context, '\0', (size_t)amount) != NULL) {
                errno = EINVAL;
                return -1;
        }
        context[amount] = '\0';
        return 0;
}

static int compare_loaded_policy(void) {
        unsigned char buffer[16384];
        const unsigned char *expected = _binary_expected_policy_bin_start;
        const ptrdiff_t expected_difference =
                _binary_expected_policy_bin_end - _binary_expected_policy_bin_start;
        struct statfs kernel_filesystem;
        size_t expected_size;
        size_t offset = 0;
        int kernel_fd = -1;
        int result = -1;

        if (expected_difference <= 0 ||
            (uintmax_t)expected_difference > MAXIMUM_POLICY_BYTES) {
                errorf("the embedded expected SELinux policy has an invalid size");
                errno = EPERM;
                return -1;
        }
        expected_size = (size_t)expected_difference;

        kernel_fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (kernel_fd < 0) {
                errorf("cannot open the loaded SELinux policy readback: %s", strerror(errno));
                goto out;
        }
        if (fstatfs(kernel_fd, &kernel_filesystem) < 0) {
                errorf("cannot identify the loaded SELinux policy filesystem: %s", strerror(errno));
                goto out;
        }
        if (kernel_filesystem.f_type != SELINUX_MAGIC) {
                errorf("loaded SELinux policy readback is not on selinuxfs");
                errno = EPERM;
                goto out;
        }
        offset = 0;
        for (;;) {
                ssize_t amount = read_retry(kernel_fd, buffer, sizeof(buffer));

                if (amount < 0) {
                        errorf("cannot read the loaded SELinux policy: %s", strerror(errno));
                        goto out;
                }
                if (amount == 0)
                        break;
                if (offset + (size_t)amount > expected_size ||
                    memcmp(expected + offset, buffer, (size_t)amount) != 0) {
                        errorf("loaded SELinux policy differs from the immutable production policy");
                        errno = EPERM;
                        goto out;
                }
                offset += (size_t)amount;
        }
        if (offset != expected_size) {
                errorf("loaded SELinux policy has %zu bytes, expected %zu", offset, expected_size);
                errno = EPERM;
                goto out;
        }

        result = 0;

out:
        if (kernel_fd >= 0 && close(kernel_fd) < 0 && result == 0) {
                errorf("cannot close the loaded SELinux policy readback: %s", strerror(errno));
                result = -1;
        }
        return result;
}

static int verify_selinux_authority(void) {
        char creation_context[MAXIMUM_CONTEXT_BYTES];
        char enforce[8];
        char process_context[MAXIMUM_CONTEXT_BYTES];

        if (read_bounded_text("/sys/fs/selinux/enforce", enforce, sizeof(enforce)) < 0) {
                errorf("cannot read SELinux enforcement state: %s", strerror(errno));
                return -1;
        }
        if (strcmp(enforce, "1") != 0) {
                errorf("SELinux is not enforcing");
                errno = EPERM;
                return -1;
        }
        if (compare_loaded_policy() < 0)
                return -1;
        if (read_bounded_text("/proc/self/attr/current", process_context,
                              sizeof(process_context)) < 0) {
                errorf("cannot read the raw process context: %s", strerror(errno));
                return -1;
        }
        if (strcmp(process_context, EXPECTED_PROCESS_CONTEXT) != 0) {
                errorf("process context is '%s', expected '%s'", process_context,
                       EXPECTED_PROCESS_CONTEXT);
                errno = EPERM;
                return -1;
        }
        if (read_bounded_text("/proc/thread-self/attr/fscreate", creation_context,
                              sizeof(creation_context)) < 0) {
                errorf("cannot inspect the inherited SELinux creation context: %s",
                       strerror(errno));
                return -1;
        }
        if (creation_context[0] != '\0') {
                errorf("refusing inherited SELinux creation context '%s'", creation_context);
                errno = EPERM;
                return -1;
        }

        return 0;
}

static int openat2_directory(int parent_fd, const char *path, uint64_t resolve) {
        struct open_how how = {
                .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                .resolve = resolve,
        };

        return (int)syscall(SYS_openat2, parent_fd, path, &how, sizeof(how));
}

static int sync_directory(int fd, const char *path) {
        if (fsync(fd) < 0) {
                errorf("cannot durably admit '%s': %s", path, strerror(errno));
                return -1;
        }

        return 0;
}

static int directory_mount_id(int fd, const char *path, uint64_t *mount_id) {
        struct statx stx;

        memset(&stx, 0, sizeof(stx));
        if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_MNT_ID_UNIQUE, &stx) < 0) {
                errorf("cannot inspect mount identity for '%s': %s", path, strerror(errno));
                return -1;
        }
        if ((stx.stx_mask & STATX_MNT_ID_UNIQUE) == 0 || stx.stx_mnt_id == 0) {
                errorf("kernel omitted the non-reusable mount identity for '%s'", path);
                errno = ENOTSUP;
                return -1;
        }

        *mount_id = stx.stx_mnt_id;
        return 0;
}

static int verify_ext4_mount(uint64_t mount_id, dev_t device) {
        static const uint64_t required =
                STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_FS_TYPE;
        struct {
                struct statmount status;
                char strings[256];
        } response;
        struct mnt_id_req request = {
                .size = MNT_ID_REQ_SIZE_VER0,
                .mnt_id = mount_id,
                .param = required,
        };
        const size_t strings_offset = offsetof(struct statmount, str);
        const char *filesystem_type;
        size_t strings_size, filesystem_type_size;

        memset(&response, 0, sizeof(response));
        if (syscall(__NR_statmount, &request, &response, sizeof(response), 0U) < 0) {
                errorf("cannot inspect the exact /var mount driver: %s", strerror(errno));
                return -1;
        }
        if ((response.status.mask & required) != required || response.status.mnt_id != mount_id ||
            response.status.sb_magic != EXT4_SUPER_MAGIC ||
            makedev(response.status.sb_dev_major, response.status.sb_dev_minor) != device) {
                errorf("/var statmount identity is not the selected ext4 filesystem");
                errno = EXDEV;
                return -1;
        }
        if (response.status.mnt_attr != (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)) {
                errorf("/var does not have the exact nosuid,nodev mount attributes");
                errno = EPERM;
                return -1;
        }
        if (response.status.size < strings_offset || response.status.size > sizeof(response)) {
                errorf("kernel returned an invalid /var statmount response size");
                errno = EOVERFLOW;
                return -1;
        }

        strings_size = response.status.size - strings_offset;
        if (response.status.fs_type >= strings_size) {
                errorf("kernel omitted the exact /var filesystem driver name");
                errno = EOVERFLOW;
                return -1;
        }
        filesystem_type = (const char *)&response + strings_offset + response.status.fs_type;
        filesystem_type_size = strings_size - response.status.fs_type;
        if (memchr(filesystem_type, '\0', filesystem_type_size) == NULL ||
            strcmp(filesystem_type, "ext4") != 0) {
                errorf("/var filesystem driver is not exactly ext4");
                errno = EINVAL;
                return -1;
        }

        return 0;
}

static int inspect_directory(int fd, const struct directory_spec *spec, uint64_t expected_mount_id,
                             dev_t expected_device, struct directory_identity *identity) {
        struct stat st;
        char observed_context[MAXIMUM_CONTEXT_BYTES];
        uint64_t mount_id;

        if (fstat(fd, &st) < 0) {
                errorf("cannot stat '%s': %s", spec->display_path, strerror(errno));
                return -1;
        }
        if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
            (st.st_mode & 07777) != spec->mode) {
                errorf("'%s' is not the exact root:root %04o directory", spec->display_path,
                       spec->mode);
                errno = EPERM;
                return -1;
        }
        if (st.st_dev != expected_device) {
                errorf("'%s' is on an unexpected filesystem device", spec->display_path);
                errno = EXDEV;
                return -1;
        }
        if (directory_mount_id(fd, spec->display_path, &mount_id) < 0)
                return -1;
        if (mount_id != expected_mount_id) {
                errorf("'%s' crosses the protected /var mount", spec->display_path);
                errno = EXDEV;
                return -1;
        }

        if (read_directory_context(fd, observed_context) < 0) {
                errorf("cannot read the raw SELinux label on '%s': %s", spec->display_path,
                       strerror(errno));
                return -1;
        }
        if (strcmp(observed_context, spec->context) != 0) {
                errorf("'%s' has raw SELinux label '%s', expected '%s'", spec->display_path,
                       observed_context, spec->context);
                errno = EPERM;
                return -1;
        }

        identity->device = st.st_dev;
        identity->inode = st.st_ino;
        identity->mount_id = mount_id;
        identity->display_path = spec->display_path;
        return 0;
}

static int create_directory(int parent_fd, const struct directory_spec *spec) {
        mode_t previous_mask;
        int saved_errno;

        if (write_creation_context(spec->context) < 0) {
                errorf("cannot select the SELinux creation label for '%s': %s", spec->display_path,
                       strerror(errno));
                return -1;
        }

        previous_mask = umask(0);
        if (mkdirat(parent_fd, spec->name, spec->mode) < 0) {
                saved_errno = errno;
                umask(previous_mask);
                if (write_creation_context(NULL) < 0)
                        errorf("cannot clear the SELinux creation label: %s", strerror(errno));
                if (saved_errno == EEXIST)
                        errorf("'%s' appeared during provisioning; refusing the race",
                               spec->display_path);
                else
                        errorf("cannot create '%s': %s", spec->display_path,
                               strerror(saved_errno));
                errno = saved_errno;
                return -1;
        }
        umask(previous_mask);

        if (write_creation_context(NULL) < 0) {
                errorf("cannot clear the SELinux creation label after creating '%s': %s",
                       spec->display_path, strerror(errno));
                return -1;
        }

        return 0;
}

static int open_or_create_directory(int parent_fd, const struct directory_spec *spec,
                                    uint64_t mount_id, dev_t device,
                                    struct directory_identity *identity) {
        static const uint64_t resolve =
                RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
        int fd;

        fd = openat2_directory(parent_fd, spec->name, resolve);
        if (fd < 0 && errno == ENOENT) {
                if (create_directory(parent_fd, spec) < 0)
                        return -1;
                fd = openat2_directory(parent_fd, spec->name, resolve);
        }
        if (fd < 0) {
                errorf("cannot open '%s' without aliases or mount crossings: %s",
                       spec->display_path, strerror(errno));
                return -1;
        }
        if (inspect_directory(fd, spec, mount_id, device, identity) < 0)
                goto fail;

        if (sync_directory(fd, spec->display_path) < 0 ||
            sync_directory(parent_fd, "the admitted directory parent") < 0) {
                goto fail;
        }
        if (inspect_directory(fd, spec, mount_id, device, identity) < 0)
                goto fail;

        return fd;

fail:
        close(fd);
        return -1;
}

static bool name_in_set(const char *name, const char *const *allowed, size_t allowed_count) {
        for (size_t index = 0; index < allowed_count; index++) {
                if (strcmp(name, allowed[index]) == 0)
                        return true;
        }

        return false;
}

static int inspect_owned_names(int fd, const char *path, const char *const *allowed,
                               size_t allowed_count, bool detect_legacy) {
        static const char *const legacy_names[] = {
                "network-state.journal",
                "network-state.journal.lock",
                "network-state.journal.compact.tmp",
                "network-namespaces.journal",
                "network-namespaces.journal.lock",
                "network-namespaces.journal.compact.tmp",
        };
        DIR *directory;
        struct dirent *entry;
        int enumeration_fd;

        enumeration_fd = openat2_directory(
                fd, ".", RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS |
                                 RESOLVE_NO_XDEV);
        if (enumeration_fd < 0) {
                errorf("cannot enumerate '%s': %s", path, strerror(errno));
                return -1;
        }
        directory = fdopendir(enumeration_fd);
        if (directory == NULL) {
                close(enumeration_fd);
                errorf("cannot enumerate '%s': %s", path, strerror(errno));
                return -1;
        }

        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                        continue;
                if (name_in_set(entry->d_name, allowed, allowed_count))
                        continue;
                if (detect_legacy && name_in_set(entry->d_name, legacy_names,
                                                 sizeof(legacy_names) / sizeof(legacy_names[0]))) {
                        errorf("migration required: legacy state entry '%s/%s' is present", path,
                               entry->d_name);
                        errno = EXDEV;
                        closedir(directory);
                        return -1;
                }

                errorf("unexpected entry '%s/%s' corrupts the protected topology", path,
                       entry->d_name);
                errno = EINVAL;
                closedir(directory);
                return -1;
        }
        if (errno != 0) {
                int saved_errno = errno;

                closedir(directory);
                errorf("cannot enumerate '%s': %s", path, strerror(saved_errno));
                errno = saved_errno;
                return -1;
        }

        closedir(directory);
        return 0;
}

static int identities_are_distinct(const struct directory_identity *identities, size_t count) {
        for (size_t left = 0; left < count; left++) {
                for (size_t right = left + 1; right < count; right++) {
                        if (identities[left].device == identities[right].device &&
                            identities[left].inode == identities[right].inode) {
                                errorf("'%s' aliases '%s'", identities[left].display_path,
                                       identities[right].display_path);
                                errno = ELOOP;
                                return -1;
                        }
                }
        }

        return 0;
}

static int reopen_matches(int parent_fd, const struct directory_spec *spec, uint64_t mount_id,
                          dev_t device, const struct directory_identity *expected) {
        static const uint64_t resolve =
                RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
        struct directory_identity observed;
        int fd;
        int result = -1;

        fd = openat2_directory(parent_fd, spec->name, resolve);
        if (fd < 0) {
                errorf("cannot re-resolve '%s': %s", spec->display_path, strerror(errno));
                return -1;
        }
        if (inspect_directory(fd, spec, mount_id, device, &observed) < 0)
                goto out;
        if (observed.device != expected->device || observed.inode != expected->inode ||
            observed.mount_id != expected->mount_id) {
                errorf("'%s' changed identity during provisioning", spec->display_path);
                errno = ESTALE;
                goto out;
        }

        result = 0;

out:
        close(fd);
        return result;
}

static int reopen_var_matches(int root_fd, const struct directory_spec *spec, uint64_t mount_id,
                              dev_t device, const struct directory_identity *expected) {
        struct directory_identity observed;
        int fd;
        int result = -1;

        fd = openat2_directory(root_fd, spec->name,
                               RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS);
        if (fd < 0) {
                errorf("cannot re-resolve '%s': %s", spec->display_path, strerror(errno));
                return -1;
        }
        if (inspect_directory(fd, spec, mount_id, device, &observed) < 0)
                goto out;
        if (observed.device != expected->device || observed.inode != expected->inode ||
            observed.mount_id != expected->mount_id) {
                errorf("'%s' changed identity during provisioning", spec->display_path);
                errno = ESTALE;
                goto out;
        }

        result = 0;

out:
        close(fd);
        return result;
}

static int inspect_existing_network_names(int aos_fd) {
        static const uint64_t resolve =
                RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
        static const char *const allowed[] = {"broker-state", "namespace-inspector"};
        int fd;
        int result;

        fd = openat2_directory(aos_fd, network_spec.name, resolve);
        if (fd < 0 && errno == ENOENT)
                return 0;
        if (fd < 0) {
                errorf("cannot inspect existing '%s': %s", network_spec.display_path,
                       strerror(errno));
                return -1;
        }

        result = inspect_owned_names(fd, network_spec.display_path, allowed,
                                     sizeof(allowed) / sizeof(allowed[0]), true);
        close(fd);
        return result;
}

static int open_existing_directory(int parent_fd, const struct directory_spec *spec,
                                   uint64_t mount_id, dev_t device, int *result_fd) {
        static const uint64_t resolve =
                RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
        struct directory_identity identity;
        int fd;

        *result_fd = -1;
        fd = openat2_directory(parent_fd, spec->name, resolve);
        if (fd < 0 && errno == ENOENT)
                return 0;
        if (fd < 0) {
                errorf("cannot preflight '%s' without aliases or mount crossings: %s",
                       spec->display_path, strerror(errno));
                return -1;
        }
        if (inspect_directory(fd, spec, mount_id, device, &identity) < 0) {
                close(fd);
                return -1;
        }

        *result_fd = fd;
        return 0;
}

static int preflight_network_topology(int lib_fd, uint64_t mount_id, dev_t device) {
        static const char *const network_children[] = {"broker-state", "namespace-inspector"};
        static const char *const inspector_child_names[] = {
                "expected-staging", "expected-final", "spent-staging", "spent-final",
        };
        int aos_fd = -1, network_fd = -1, broker_fd = -1, inspector_fd = -1;
        int child_fd = -1;
        int result = -1;

        if (open_existing_directory(lib_fd, &aos_spec, mount_id, device, &aos_fd) < 0)
                goto out;
        if (aos_fd < 0) {
                result = 0;
                goto out;
        }
        if (open_existing_directory(aos_fd, &network_spec, mount_id, device, &network_fd) < 0)
                goto out;
        if (network_fd < 0) {
                result = 0;
                goto out;
        }
        if (inspect_owned_names(network_fd, network_spec.display_path, network_children,
                                sizeof(network_children) / sizeof(network_children[0]), true) < 0)
                goto out;
        if (open_existing_directory(network_fd, &broker_state_spec, mount_id, device,
                                    &broker_fd) < 0 ||
            open_existing_directory(network_fd, &inspector_spec, mount_id, device,
                                    &inspector_fd) < 0)
                goto out;
        if (inspector_fd < 0) {
                result = 0;
                goto out;
        }
        if (inspect_owned_names(inspector_fd, inspector_spec.display_path, inspector_child_names,
                                sizeof(inspector_child_names) / sizeof(inspector_child_names[0]),
                                false) < 0)
                goto out;
        for (size_t index = 0; index < sizeof(inspector_children) / sizeof(inspector_children[0]);
             index++) {
                if (open_existing_directory(inspector_fd, &inspector_children[index], mount_id,
                                            device, &child_fd) < 0)
                        goto out;
                if (child_fd >= 0) {
                        close(child_fd);
                        child_fd = -1;
                }
        }

        result = 0;

out:
        if (child_fd >= 0)
                close(child_fd);
        if (inspector_fd >= 0)
                close(inspector_fd);
        if (broker_fd >= 0)
                close(broker_fd);
        if (network_fd >= 0)
                close(network_fd);
        if (aos_fd >= 0)
                close(aos_fd);
        return result;
}

static int select_var_device(struct stat *device_st) {
        static const char *const candidates[] = {
                "/dev/mapper/var",
                "/dev/disk/by-partlabel/var",
        };

        for (size_t index = 0; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
                if (stat(candidates[index], device_st) == 0) {
                        if (!S_ISBLK(device_st->st_mode)) {
                                errorf("'%s' exists but is not a block device", candidates[index]);
                                errno = ENOTBLK;
                                return -1;
                        }
                        return 0;
                }
                if (errno != ENOENT) {
                        errorf("cannot inspect selected /var device '%s': %s", candidates[index],
                               strerror(errno));
                        return -1;
                }
        }

        errorf("neither fixed /var block-device identity is present");
        errno = ENOENT;
        return -1;
}

static int provision(const char *root_path, bool prepare_network_roots) {
        static const struct directory_spec var_spec = {
                "var", "/var", VAR_CONTEXT, 0755,
        };
        static const char *const network_children[] = {"broker-state", "namespace-inspector"};
        static const char *const inspector_child_names[] = {
                "expected-staging", "expected-final", "spent-staging", "spent-final",
        };
        struct directory_identity identities[10];
        struct stat root_st, device_st, var_st;
        struct statfs filesystem;
        uint64_t root_mount_id, var_mount_id;
        int root_fd = -1, var_fd = -1, lib_fd = -1, aos_fd = -1, network_fd = -1;
        int broker_fd = -1, inspector_fd = -1;
        int inspector_child_fds[4] = {-1, -1, -1, -1};
        int result = -1;

        root_fd = openat2_directory(AT_FDCWD, root_path,
                                    RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS);
        if (root_fd < 0 || fstat(root_fd, &root_st) < 0 || !S_ISDIR(root_st.st_mode)) {
                errorf("cannot open the exact real-root directory '%s': %s", root_path,
                       strerror(errno));
                goto out;
        }
        if (directory_mount_id(root_fd, root_path, &root_mount_id) < 0)
                goto out;

        if (select_var_device(&device_st) < 0)
                goto out;

        var_fd = openat2_directory(root_fd, "var",
                                   RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS);
        if (var_fd < 0 || fstat(var_fd, &var_st) < 0) {
                errorf("cannot open the mounted /var root: %s", strerror(errno));
                goto out;
        }
        if (fstatfs(var_fd, &filesystem) < 0 || filesystem.f_type != EXT4_SUPER_MAGIC) {
                errorf("/var is not ext4");
                errno = EINVAL;
                goto out;
        }
        if (var_st.st_dev != device_st.st_rdev || var_st.st_ino != 2) {
                errorf("/var is not the root of the selected block device");
                errno = EXDEV;
                goto out;
        }
        if (directory_mount_id(var_fd, var_spec.display_path, &var_mount_id) < 0)
                goto out;
        if (var_mount_id == root_mount_id) {
                errorf("/var is not a distinct mount");
                errno = EXDEV;
                goto out;
        }
        if (verify_ext4_mount(var_mount_id, var_st.st_dev) < 0)
                goto out;
        if (inspect_directory(var_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) < 0)
                goto out;
        /* The helper never creates the /var mountpoint on the immutable EROFS root. */
        if (sync_directory(var_fd, var_spec.display_path) < 0 ||
            inspect_directory(var_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) < 0)
                goto out;

        lib_fd = open_or_create_directory(var_fd, &var_lib_spec, var_mount_id, var_st.st_dev,
                                          &identities[1]);
        if (lib_fd < 0)
                goto out;
        if (identities_are_distinct(identities, 2) < 0)
                goto out;
        if (reopen_var_matches(root_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) <
                    0 ||
            reopen_matches(var_fd, &var_lib_spec, var_mount_id, var_st.st_dev, &identities[1]) < 0)
                goto out;
        if (!prepare_network_roots) {
                if (verify_ext4_mount(var_mount_id, var_st.st_dev) < 0 ||
                    inspect_directory(var_fd, &var_spec, var_mount_id, var_st.st_dev,
                                      &identities[0]) < 0)
                        goto out;
                result = 0;
                goto out;
        }

        /* Refuse every poisoned existing object before creating a missing peer. */
        if (preflight_network_topology(lib_fd, var_mount_id, var_st.st_dev) < 0)
                goto out;

        aos_fd = open_or_create_directory(lib_fd, &aos_spec, var_mount_id, var_st.st_dev,
                                          &identities[2]);
        if (aos_fd < 0)
                goto out;
        if (inspect_existing_network_names(aos_fd) < 0)
                goto out;
        network_fd = open_or_create_directory(aos_fd, &network_spec, var_mount_id, var_st.st_dev,
                                              &identities[3]);
        if (network_fd < 0)
                goto out;

        if (inspect_owned_names(network_fd, network_spec.display_path, network_children,
                                sizeof(network_children) / sizeof(network_children[0]), true) < 0)
                goto out;
        broker_fd = open_or_create_directory(network_fd, &broker_state_spec, var_mount_id,
                                             var_st.st_dev, &identities[4]);
        if (broker_fd < 0)
                goto out;
        inspector_fd = open_or_create_directory(network_fd, &inspector_spec, var_mount_id,
                                                var_st.st_dev, &identities[5]);
        if (inspector_fd < 0)
                goto out;

        if (inspect_owned_names(inspector_fd, inspector_spec.display_path, inspector_child_names,
                                sizeof(inspector_child_names) / sizeof(inspector_child_names[0]),
                                false) < 0)
                goto out;
        for (size_t index = 0; index < sizeof(inspector_children) / sizeof(inspector_children[0]);
             index++) {
                inspector_child_fds[index] = open_or_create_directory(
                        inspector_fd, &inspector_children[index], var_mount_id, var_st.st_dev,
                        &identities[index + 6]);
                if (inspector_child_fds[index] < 0)
                        goto out;
        }

        if (identities_are_distinct(identities, sizeof(identities) / sizeof(identities[0])) < 0)
                goto out;

        /* Recheck every retained inode and parent-to-child path binding before success. */
        if (inspect_directory(var_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) < 0 ||
            inspect_directory(lib_fd, &var_lib_spec, var_mount_id, var_st.st_dev, &identities[1]) <
                    0 ||
            inspect_directory(aos_fd, &aos_spec, var_mount_id, var_st.st_dev, &identities[2]) < 0 ||
            inspect_directory(network_fd, &network_spec, var_mount_id, var_st.st_dev,
                              &identities[3]) < 0 ||
            inspect_directory(broker_fd, &broker_state_spec, var_mount_id, var_st.st_dev,
                              &identities[4]) < 0 ||
            inspect_directory(inspector_fd, &inspector_spec, var_mount_id, var_st.st_dev,
                              &identities[5]) < 0)
                goto out;
        for (size_t index = 0; index < sizeof(inspector_children) / sizeof(inspector_children[0]);
             index++) {
                if (inspect_directory(inspector_child_fds[index], &inspector_children[index],
                                      var_mount_id, var_st.st_dev, &identities[index + 6]) < 0)
                        goto out;
        }
        if (inspect_owned_names(network_fd, network_spec.display_path, network_children,
                                sizeof(network_children) / sizeof(network_children[0]), true) < 0 ||
            inspect_owned_names(inspector_fd, inspector_spec.display_path, inspector_child_names,
                                sizeof(inspector_child_names) / sizeof(inspector_child_names[0]),
                                false) < 0)
                goto out;
        if (reopen_var_matches(root_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) < 0 ||
            reopen_matches(var_fd, &var_lib_spec, var_mount_id, var_st.st_dev, &identities[1]) < 0 ||
            reopen_matches(lib_fd, &aos_spec, var_mount_id, var_st.st_dev, &identities[2]) < 0 ||
            reopen_matches(aos_fd, &network_spec, var_mount_id, var_st.st_dev, &identities[3]) < 0 ||
            reopen_matches(network_fd, &broker_state_spec, var_mount_id, var_st.st_dev,
                           &identities[4]) < 0 ||
            reopen_matches(network_fd, &inspector_spec, var_mount_id, var_st.st_dev,
                           &identities[5]) < 0)
                goto out;
        for (size_t index = 0; index < sizeof(inspector_children) / sizeof(inspector_children[0]);
             index++) {
                if (reopen_matches(inspector_fd, &inspector_children[index], var_mount_id,
                                   var_st.st_dev, &identities[index + 6]) < 0)
                        goto out;
        }
        if (identities_are_distinct(identities, sizeof(identities) / sizeof(identities[0])) < 0)
                goto out;
        if (verify_ext4_mount(var_mount_id, var_st.st_dev) < 0 ||
            inspect_directory(var_fd, &var_spec, var_mount_id, var_st.st_dev, &identities[0]) < 0)
                goto out;

        result = 0;

out:
        if (write_creation_context(NULL) < 0) {
                errorf("cannot clear the SELinux creation label on exit: %s", strerror(errno));
                result = -1;
        }
        {
                char creation_context[MAXIMUM_CONTEXT_BYTES];

                if (read_bounded_text("/proc/thread-self/attr/fscreate", creation_context,
                                      sizeof(creation_context)) < 0 ||
                    creation_context[0] != '\0') {
                        errorf("SELinux creation context was not cleared on exit");
                        result = -1;
                }
        }
        if (result == 0 && verify_selinux_authority() < 0)
                result = -1;
        for (size_t index = 0; index < sizeof(inspector_child_fds) / sizeof(inspector_child_fds[0]);
             index++) {
                if (inspector_child_fds[index] >= 0)
                        close(inspector_child_fds[index]);
        }
        if (inspector_fd >= 0)
                close(inspector_fd);
        if (broker_fd >= 0)
                close(broker_fd);
        if (network_fd >= 0)
                close(network_fd);
        if (aos_fd >= 0)
                close(aos_fd);
        if (lib_fd >= 0)
                close(lib_fd);
        if (var_fd >= 0)
                close(var_fd);
        if (root_fd >= 0)
                close(root_fd);
        return result;
}

int main(int argc, char **argv) {
        bool prepare_network_roots;

        if (argc != 4 || strcmp(argv[1], "--root") != 0 ||
            (strcmp(argv[2], "/sysroot") != 0 && strcmp(argv[2], "/") != 0)) {
                errorf("usage: aos-selinux-runtime-roots --root /sysroot|/ "
                       "--prepare-var-base|--prepare-sandbox-network-roots");
                return 2;
        }
        if (strcmp(argv[3], "--prepare-var-base") == 0)
                prepare_network_roots = false;
        else if (strcmp(argv[3], "--prepare-sandbox-network-roots") == 0)
                prepare_network_roots = true;
        else {
                errorf("unknown preparation phase '%s'", argv[3]);
                return 2;
        }
        if ((!prepare_network_roots && strcmp(argv[2], "/sysroot") != 0) ||
            (prepare_network_roots && strcmp(argv[2], "/") != 0)) {
                errorf("preparation phase and root are not the supported fixed pair");
                return 2;
        }
        if (verify_selinux_authority() < 0)
                return 1;
        if (provision(argv[2], prepare_network_roots) < 0)
                return 1;

        printf("aos-selinux-runtime-roots: verified %s in %s\n", argv[3],
               EXPECTED_PROCESS_CONTEXT);
        return 0;
}
