// SPDX-License-Identifier: Apache-2.0
// Immutable SELinux stage-0 policy loader and pre-systemd PID 1 guard.

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/if_alg.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef AOS_GUARD_PATH
#error "AOS_GUARD_PATH must name the physical inner stage-1 guard"
#endif

#ifndef AOS_SYSTEMD_PATH
#error "AOS_SYSTEMD_PATH must name the physical stage-1 systemd"
#endif

#ifndef AOS_ADMISSION_UNIT
#define AOS_ADMISSION_UNIT ""
#endif

#ifndef AOS_QUALIFICATION_POST_PIN_GATE
#define AOS_QUALIFICATION_POST_PIN_GATE ""
#endif

#include "systemd_runtime_manifest.h"

#define AOS_ROOT_HANDOFF_PATH "/usr/lib/systemd/aos-selinux-root-handoff"
#define AOS_EMPTY_PRELOAD_PATH "/usr/lib/systemd/aos-empty-ld-so-preload"
#define AOS_HANDOFF_MARKER_PATH "/run/aos/selinux-root-handoff"
#define AOS_HANDOFF_PARAMETER "aos.selinux.root_handoff=1"
#define AOS_HANDOFF_SWITCH "--aos-root-handoff=switch-root"
#define AOS_HANDOFF_REEXEC "--aos-root-handoff=reexec"
#define AOS_RUNTIME_ROOTS_LAUNCH "--launch-runtime-roots"
#define AOS_MANIFEST_MAGIC "AOS_AUTHENTICATED_RUNTIME_CLOSURE"
#define AOS_MANIFEST_VERSION "2"
#define AOS_PHYSICAL_STORE_ROOT "/nix.lower/store"
#define AOS_PHYSICAL_STORE_PREFIX AOS_PHYSICAL_STORE_ROOT "/"
#define MAX_RUNTIME_ROOTS 1024U

#define SELINUX_ROOT "/sys/fs/selinux"
#define EXPECTED_KERNEL_CONTEXT "system_u:system_r:kernel_t"
#define EXPECTED_INIT_CONTEXT "system_u:system_r:init_t"
#define EXPECTED_INIT_EXEC_CONTEXT "system_u:object_r:init_exec_t"
#define EXPECTED_LOADER_CONTEXT "system_u:object_r:ld_so_t"
#define EXPECTED_RUNTIME_ROOTS_EXEC_CONTEXT \
    "system_u:object_r:aos_sandbox_runtime_roots_exec_t"

extern const unsigned char _binary_loaded_policy_bin_start[];
extern const unsigned char _binary_loaded_policy_bin_end[];
extern const unsigned char _binary_expected_policy_bin_start[];
extern const unsigned char _binary_expected_policy_bin_end[];
extern const unsigned char _binary_systemd_runtime_manifest_bin_start[];
extern const unsigned char _binary_systemd_runtime_manifest_bin_end[];
extern char **environ;

static void write_diagnostic(const char *prefix, const char *format, va_list arguments) {
    dprintf(STDERR_FILENO, "%s", prefix);
    vdprintf(STDERR_FILENO, format, arguments);
    dprintf(STDERR_FILENO, "\n");
}

__attribute__((noreturn)) static void fail_closed(const char *format, ...) {
    va_list arguments;

    va_start(arguments, format);
    write_diagnostic("AOS SELinux stage0 failure: ", format, arguments);
    va_end(arguments);

    if (getpid() == 1) {
        dprintf(STDERR_FILENO, "AOS SELinux stage0: PID 1 frozen fail-closed\n");
        sync();
        for (;;) {
            pause();
        }
    }
    _exit(EXIT_FAILURE);
}

static void log_status(const char *format, ...) {
    va_list arguments;

    va_start(arguments, format);
    write_diagnostic("AOS SELinux stage0: ", format, arguments);
    va_end(arguments);
}

static void require_pid_one(void) {
    if (getpid() != 1) {
        fail_closed("loader must run as PID 1, observed PID %ld", (long)getpid());
    }
}

static void ensure_directory(const char *path, mode_t mode) {
    struct stat metadata;

    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        fail_closed("mkdir %s: %s", path, strerror(errno));
    }
    if (stat(path, &metadata) < 0) {
        fail_closed("stat %s: %s", path, strerror(errno));
    }
    if (!S_ISDIR(metadata.st_mode)) {
        fail_closed("%s is not a directory", path);
    }
}

static void require_filesystem(
    const char *path,
    long expected_magic,
    unsigned long required_flags,
    unsigned long forbidden_flags) {
    struct statfs status;
    struct statvfs mount_status;

    if (statfs(path, &status) < 0) {
        fail_closed("statfs %s: %s", path, strerror(errno));
    }
    if ((long)status.f_type != expected_magic) {
        fail_closed(
            "%s has filesystem magic 0x%lx, expected 0x%lx",
            path,
            (unsigned long)status.f_type,
            (unsigned long)expected_magic);
    }
    if (statvfs(path, &mount_status) < 0) {
        fail_closed("statvfs %s: %s", path, strerror(errno));
    }
    if ((mount_status.f_flag & required_flags) != required_flags) {
        fail_closed("%s is missing required mount flags", path);
    }
    if ((mount_status.f_flag & forbidden_flags) != 0) {
        fail_closed("%s carries a forbidden mount flag", path);
    }
}

static void require_private_root_mount(void) {
    char *line = NULL;
    size_t capacity = 0;
    bool found_root = false;
    struct statfs proc_status;
    FILE *mountinfo = fopen("/proc/self/mountinfo", "re");

    if (mountinfo == NULL || fstatfs(fileno(mountinfo), &proc_status) < 0 ||
        proc_status.f_type != PROC_SUPER_MAGIC) {
        if (mountinfo != NULL) {
            fclose(mountinfo);
        }
        fail_closed("open authentic mountinfo for namespace verification: %s", strerror(errno));
    }
    while (getline(&line, &capacity, mountinfo) >= 0) {
        char *save = NULL;
        char *token = strtok_r(line, " ", &save);
        unsigned int field = 1;
        bool root_line = false;

        while (token != NULL) {
            if (field == 5) {
                root_line = strcmp(token, "/") == 0;
            } else if (field == 7 && root_line) {
                if (strcmp(token, "-") != 0) {
                    free(line);
                    fclose(mountinfo);
                    fail_closed("root mount still has a propagation relationship");
                }
                found_root = true;
                break;
            }
            token = strtok_r(NULL, " ", &save);
            field++;
        }
        if (found_root) {
            break;
        }
    }
    free(line);
    if (fclose(mountinfo) < 0) {
        fail_closed("close mountinfo after namespace verification: %s", strerror(errno));
    }
    if (!found_root) {
        fail_closed("mountinfo does not describe a private root mount");
    }
}

static void isolate_root_handoff_mount_namespace(void) {
    if (unshare(CLONE_NEWNS) < 0) {
        fail_closed("create private root-handoff mount namespace: %s", strerror(errno));
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        fail_closed("make root-handoff mounts recursively private: %s", strerror(errno));
    }
    require_private_root_mount();
}

static void mount_filesystem(
    const char *source,
    const char *target,
    const char *filesystem,
    unsigned long flags,
    const char *data,
    long expected_magic,
    unsigned long required_flags,
    unsigned long forbidden_flags) {
    if (mount(source, target, filesystem, flags, data) < 0) {
        fail_closed("mount %s on %s: %s", filesystem, target, strerror(errno));
    }
    require_filesystem(target, expected_magic, required_flags, forbidden_flags);
}

static void move_mounted_tree(
    const char *source,
    const char *target,
    long expected_magic,
    unsigned long required_flags,
    unsigned long forbidden_flags) {
    if (mount(source, target, NULL, MS_MOVE, NULL) < 0) {
        fail_closed("move mount %s to %s: %s", source, target, strerror(errno));
    }
    require_filesystem(target, expected_magic, required_flags, forbidden_flags);
}

static void attach_console(void) {
    int console = open("/dev/console", O_WRONLY | O_NOCTTY);

    if (console < 0) {
        return;
    }
    if (dup2(console, STDOUT_FILENO) < 0 || dup2(console, STDERR_FILENO) < 0) {
        close(console);
        return;
    }
    if (console > STDERR_FILENO) {
        close(console);
    }
}

static size_t read_bounded_text_file(
    const char *path,
    char *buffer,
    size_t capacity,
    bool allow_trailing_nul) {
    size_t offset = 0;
    int descriptor;

    if (capacity < 2) {
        fail_closed("internal buffer for %s is too small", path);
    }

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fail_closed("open %s: %s", path, strerror(errno));
    }
    while (offset < capacity - 1) {
        ssize_t amount = read(descriptor, buffer + offset, capacity - 1 - offset);

        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            int saved_errno = errno;

            close(descriptor);
            fail_closed("read %s: %s", path, strerror(saved_errno));
        }
        if (amount == 0) {
            break;
        }
        offset += (size_t)amount;
    }
    if (offset == capacity - 1) {
        char extra;
        ssize_t extra_amount;

        do {
            extra_amount = read(descriptor, &extra, 1);
        } while (extra_amount < 0 && errno == EINTR);

        if (extra_amount < 0) {
            int saved_errno = errno;

            close(descriptor);
            fail_closed("read %s EOF: %s", path, strerror(saved_errno));
        }
        if (extra_amount != 0) {
            close(descriptor);
            fail_closed("%s exceeds the bounded input size", path);
        }
    }
    if (close(descriptor) < 0) {
        fail_closed("close %s: %s", path, strerror(errno));
    }

    if (offset > 0 && buffer[offset - 1] == '\0') {
        if (!allow_trailing_nul) {
            fail_closed("%s contains an unexpected trailing NUL", path);
        }
        offset--;
    }
    if (memchr(buffer, '\0', offset) != NULL) {
        fail_closed("%s contains an embedded NUL", path);
    }
    buffer[offset] = '\0';
    return offset;
}

static void trim_line_ending(char *value) {
    size_t length = strlen(value);

    while (length > 0 && (value[length - 1] == '\n' || value[length - 1] == '\r')) {
        value[--length] = '\0';
    }
}

static void require_text_file(const char *path, const char *expected) {
    char observed[256];

    read_bounded_text_file(path, observed, sizeof(observed), false);
    trim_line_ending(observed);
    if (strcmp(observed, expected) != 0) {
        fail_closed("%s contains %s, expected %s", path, observed, expected);
    }
}

static bool parameter_has_key(const char *parameter, const char *key) {
    size_t key_length = strlen(key);

    return strcmp(parameter, key) == 0 ||
           (strncmp(parameter, key, key_length) == 0 && parameter[key_length] == '=');
}

static void require_exact_parameter(
    char *command_line,
    const char *key,
    const char *expected) {
    char *cursor = NULL;
    char *parameter;
    unsigned int matches = 0;
    unsigned int exact_matches = 0;

    for (parameter = strtok_r(command_line, " \t\n", &cursor);
         parameter != NULL;
         parameter = strtok_r(NULL, " \t\n", &cursor)) {
        if (!parameter_has_key(parameter, key)) {
            continue;
        }
        matches++;
        if (strcmp(parameter, expected) == 0) {
            exact_matches++;
        }
    }

    if (matches != 1 || exact_matches != 1) {
        fail_closed(
            "kernel parameter %s must occur exactly once as %s",
            key,
            expected);
    }
}

static void validate_command_line(void) {
    char original[4096];
    char scratch[4096];

    read_bounded_text_file("/proc/cmdline", original, sizeof(original), false);

    memcpy(scratch, original, sizeof(scratch));
    require_exact_parameter(scratch, "selinux", "selinux=1");
    memcpy(scratch, original, sizeof(scratch));
    require_exact_parameter(scratch, "security", "security=selinux");
    memcpy(scratch, original, sizeof(scratch));
    require_exact_parameter(scratch, "enforcing", "enforcing=1");
    memcpy(scratch, original, sizeof(scratch));
    require_exact_parameter(
        scratch,
        "aos.selinux.root_handoff",
        AOS_HANDOFF_PARAMETER);
}

static size_t embedded_size(
    const unsigned char *start,
    const unsigned char *end,
    const char *description) {
    ptrdiff_t difference = end - start;

    if (difference <= 0) {
        fail_closed("embedded %s is empty", description);
    }
    return (size_t)difference;
}

static void load_policy(void) {
    const unsigned char *policy = _binary_loaded_policy_bin_start;
    size_t policy_size = embedded_size(
        policy,
        _binary_loaded_policy_bin_end,
        "loaded policy");
    ssize_t written;
    int descriptor = open(SELINUX_ROOT "/load", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);

    if (descriptor < 0) {
        fail_closed("open SELinux policy load node: %s", strerror(errno));
    }
    do {
        written = write(descriptor, policy, policy_size);
    } while (written < 0 && errno == EINTR);
    if (written < 0) {
        int saved_errno = errno;

        close(descriptor);
        fail_closed("kernel rejected SELinux policy: %s", strerror(saved_errno));
    }
    if ((size_t)written != policy_size) {
        close(descriptor);
        fail_closed(
            "kernel accepted a partial SELinux policy (%ld of %zu bytes)",
            (long)written,
            policy_size);
    }
    if (close(descriptor) < 0) {
        fail_closed("close SELinux policy load node: %s", strerror(errno));
    }
}

static void compare_kernel_policy(void) {
    const unsigned char *expected = _binary_expected_policy_bin_start;
    size_t expected_size = embedded_size(
        expected,
        _binary_expected_policy_bin_end,
        "expected policy");
    size_t offset = 0;
    unsigned char buffer[16384];
    int descriptor = open(SELINUX_ROOT "/policy", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (descriptor < 0) {
        fail_closed("open SELinux policy readback: %s", strerror(errno));
    }
    for (;;) {
        ssize_t amount = read(descriptor, buffer, sizeof(buffer));

        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            int saved_errno = errno;

            close(descriptor);
            fail_closed("read SELinux policy readback: %s", strerror(saved_errno));
        }
        if (amount == 0) {
            break;
        }
        if (offset + (size_t)amount > expected_size ||
            memcmp(expected + offset, buffer, (size_t)amount) != 0) {
            close(descriptor);
            fail_closed("kernel SELinux policy differs from the trusted expectation");
        }
        offset += (size_t)amount;
    }
    if (close(descriptor) < 0) {
        fail_closed("close SELinux policy readback: %s", strerror(errno));
    }
    if (offset != expected_size) {
        fail_closed(
            "kernel SELinux policy has %zu bytes, expected %zu",
            offset,
            expected_size);
    }
}

static void validate_loaded_policy(void) {
    compare_kernel_policy();
    require_text_file(SELINUX_ROOT "/enforce", "1");
    require_text_file(SELINUX_ROOT "/reject_unknown", "1");
    require_text_file(SELINUX_ROOT "/deny_unknown", "1");
}

static void read_current_context(char *context, size_t capacity) {
    read_bounded_text_file("/proc/self/attr/current", context, capacity, true);
    trim_line_ending(context);
}

static void require_current_context(const char *expected) {
    char observed[256];

    read_current_context(observed, sizeof(observed));
    if (strcmp(observed, expected) != 0) {
        fail_closed("PID 1 context is %s, expected %s", observed, expected);
    }
}

static void read_file_context(
    const char *path,
    const char *expected,
    char *context,
    size_t capacity) {
    size_t expected_size = strlen(expected);
    ssize_t amount;

    if (expected_size >= capacity) {
        fail_closed("expected SELinux context exceeds the bounded input size");
    }
    amount = getxattr(path, "security.selinux", context, capacity);

    if (amount < 0) {
        fail_closed("read SELinux xattr on %s: %s", path, strerror(errno));
    }
    if ((size_t)amount > capacity) {
        fail_closed("SELinux xattr on %s exceeds the bounded input size", path);
    }
    if (!((size_t)amount == expected_size ||
          ((size_t)amount == expected_size + 1 && context[expected_size] == '\0')) ||
        memcmp(context, expected, expected_size) != 0) {
        fail_closed("%s does not carry the exact expected SELinux context bytes", path);
    }
    context[expected_size] = '\0';
}

static void verify_physical_target(
    const char *alias,
    const char *expected_path,
    const char *expected_context,
    char *observed_context,
    size_t context_capacity) {
    char resolved[PATH_MAX];

    if (realpath(alias, resolved) == NULL) {
        fail_closed("resolve %s: %s", alias, strerror(errno));
    }
    if (strcmp(resolved, expected_path) != 0) {
        fail_closed("%s resolves to %s, expected %s", alias, resolved, expected_path);
    }

    read_file_context(
        resolved,
        expected_context,
        observed_context,
        context_capacity);
    if (strcmp(observed_context, expected_context) != 0) {
        fail_closed(
            "%s has context %s, expected %s",
            resolved,
            observed_context,
            expected_context);
    }
}

static int open_verified_physical_store_target(
    const char *root_prefix,
    const char *expected_path,
    const char *expected_context,
    char *observed_context,
    size_t context_capacity) {
    const size_t prefix_length = strlen(AOS_PHYSICAL_STORE_PREFIX);
    const size_t expected_context_size = strlen(expected_context);
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC | O_NOCTTY,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    struct stat metadata;
    ssize_t context_size;
    int descriptor;
    int store_fd;
    char store_root[PATH_MAX];

    if (strncmp(expected_path, AOS_PHYSICAL_STORE_PREFIX, prefix_length) != 0 ||
        expected_path[prefix_length] == '\0' ||
        expected_context_size >= context_capacity) {
        fail_closed("physical store target contract is not canonical");
    }
    if (strcmp(root_prefix, "/") == 0) {
        if (snprintf(store_root, sizeof(store_root), "%s", AOS_PHYSICAL_STORE_ROOT) >=
            (int)sizeof(store_root)) {
            fail_closed("physical lower-store path exceeds PATH_MAX");
        }
    } else if (strcmp(root_prefix, "/sysroot") == 0) {
        if (snprintf(
                store_root,
                sizeof(store_root),
                "%s%s",
                root_prefix,
                AOS_PHYSICAL_STORE_ROOT) >= (int)sizeof(store_root)) {
            fail_closed("prefixed physical lower-store path exceeds PATH_MAX");
        }
    } else {
        fail_closed("physical store root prefix is not the supported fixed pair");
    }
    store_fd = open(
        store_root,
        O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (store_fd < 0) {
        fail_closed(
            "open physical lower store %s for executable custody: %s",
            store_root,
            strerror(errno));
    }
    descriptor = (int)syscall(
        SYS_openat2,
        store_fd,
        expected_path + prefix_length,
        &how,
        sizeof(how));
    if (descriptor < 0) {
        int saved_errno = errno;

        close(store_fd);
        fail_closed("open constrained physical target %s: %s", expected_path, strerror(saved_errno));
    }
    close(store_fd);

    if (fstat(descriptor, &metadata) < 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || metadata.st_gid != 0 ||
        (metadata.st_mode & 0111) == 0) {
        close(descriptor);
        fail_closed("physical target %s is not a root-owned executable", expected_path);
    }
    context_size = fgetxattr(
        descriptor,
        "security.selinux",
        observed_context,
        context_capacity);
    if (!((size_t)context_size == expected_context_size ||
          ((size_t)context_size == expected_context_size + 1 &&
           observed_context[expected_context_size] == '\0')) ||
        memcmp(observed_context, expected_context, expected_context_size) != 0) {
        close(descriptor);
        fail_closed("physical target %s has the wrong SELinux label", expected_path);
    }
    observed_context[expected_context_size] = '\0';
    return descriptor;
}

static unsigned long read_decimal_file(const char *path) {
    char value[64];
    char *end = NULL;
    unsigned long number;

    read_bounded_text_file(path, value, sizeof(value), false);
    trim_line_ending(value);
    errno = 0;
    number = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fail_closed("%s does not contain a canonical decimal number", path);
    }
    return number;
}

static unsigned long class_index(const char *class_name) {
    char path[PATH_MAX];

    if (snprintf(
            path,
            sizeof(path),
            SELINUX_ROOT "/class/%s/index",
            class_name) >= (int)sizeof(path)) {
        fail_closed("SELinux class path is too long");
    }
    return read_decimal_file(path);
}

static unsigned long permission_mask(const char *class_name, const char *permission) {
    char path[PATH_MAX];
    unsigned long index;

    if (snprintf(
            path,
            sizeof(path),
            SELINUX_ROOT "/class/%s/perms/%s",
            class_name,
            permission) >= (int)sizeof(path)) {
        fail_closed("SELinux permission path is too long");
    }
    index = read_decimal_file(path);
    if (index == 0 || index > 32) {
        fail_closed("SELinux permission %s.%s has invalid index %lu", class_name, permission, index);
    }
    return 1UL << (index - 1);
}

static size_t selinux_transaction(
    const char *node,
    const char *request,
    char *response,
    size_t capacity,
    bool allow_trailing_nul) {
    char path[PATH_MAX];
    size_t request_size = strlen(request);
    size_t response_size = 0;
    ssize_t amount;
    int descriptor;

    if (capacity < 2) {
        fail_closed("internal transaction buffer is too small");
    }
    if (snprintf(path, sizeof(path), SELINUX_ROOT "/%s", node) >= (int)sizeof(path)) {
        fail_closed("SELinux transaction path is too long");
    }
    descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fail_closed("open %s transaction: %s", node, strerror(errno));
    }
    do {
        amount = write(descriptor, request, request_size);
    } while (amount < 0 && errno == EINTR);
    if (amount < 0) {
        int saved_errno = errno;

        close(descriptor);
        fail_closed("write %s transaction: %s", node, strerror(saved_errno));
    }
    if ((size_t)amount != request_size) {
        close(descriptor);
        fail_closed(
            "partial %s transaction request (%ld of %zu bytes)",
            node,
            (long)amount,
            request_size);
    }
    while (response_size < capacity - 1) {
        do {
            amount = read(
                descriptor,
                response + response_size,
                capacity - 1 - response_size);
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) {
            int saved_errno = errno;

            close(descriptor);
            fail_closed("read %s transaction: %s", node, strerror(saved_errno));
        }
        if (amount == 0) {
            break;
        }
        response_size += (size_t)amount;
    }
    if (response_size == capacity - 1) {
        char extra;

        do {
            amount = read(descriptor, &extra, 1);
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) {
            int saved_errno = errno;

            close(descriptor);
            fail_closed("read %s transaction EOF: %s", node, strerror(saved_errno));
        }
        if (amount != 0) {
            close(descriptor);
            fail_closed("%s transaction response exceeds the bounded input size", node);
        }
    }
    if (close(descriptor) < 0) {
        fail_closed("close %s transaction: %s", node, strerror(errno));
    }
    if (response_size > 0 && response[response_size - 1] == '\0') {
        if (!allow_trailing_nul) {
            fail_closed("%s transaction response contains an unexpected trailing NUL", node);
        }
        response_size--;
    }
    if (memchr(response, '\0', response_size) != NULL) {
        fail_closed("%s transaction response contains an embedded NUL", node);
    }
    response[response_size] = '\0';
    trim_line_ending(response);
    return response_size;
}

static void compute_transition(
    const char *source_context,
    const char *file_context,
    char *result_context,
    size_t capacity) {
    char request[768];
    unsigned long process_class = class_index("process");

    if (snprintf(
            request,
            sizeof(request),
            "%s %s %lu",
            source_context,
            file_context,
            process_class) >= (int)sizeof(request)) {
        fail_closed("SELinux transition request is too long");
    }
    selinux_transaction("create", request, result_context, capacity, true);
}

static bool access_has_permission(
    const char *source_context,
    const char *target_context,
    const char *class_name,
    const char *permission) {
    char request[768];
    char response[256];
    unsigned long object_class = class_index(class_name);
    unsigned long required = permission_mask(class_name, permission);
    unsigned long allowed;
    unsigned long decided;
    unsigned long audit_allow;
    unsigned long audit_deny;
    unsigned long sequence;
    unsigned long flags;
    int consumed = 0;

    if (snprintf(
            request,
            sizeof(request),
            "%s %s %lu",
            source_context,
            target_context,
            object_class) >= (int)sizeof(request)) {
        fail_closed("SELinux access request is too long");
    }
    selinux_transaction("access", request, response, sizeof(response), false);
    if (sscanf(
            response,
            "%lx %lx %lx %lx %lu %lx%n",
            &allowed,
            &decided,
            &audit_allow,
            &audit_deny,
            &sequence,
            &flags,
            &consumed) != 6 ||
        response[consumed] != '\0') {
        fail_closed("SELinux access response is malformed: %s", response);
    }
    if ((decided & required) != required) {
        fail_closed(
            "SELinux access response did not decide %s.%s",
            class_name,
            permission);
    }
    return (allowed & required) == required;
}

static void require_permission(
    bool expected,
    const char *source_context,
    const char *target_context,
    const char *class_name,
    const char *permission) {
    bool observed = access_has_permission(
        source_context,
        target_context,
        class_name,
        permission);

    if (observed != expected) {
        fail_closed(
            "%s -> %s %s.%s is %s, expected %s",
            source_context,
            target_context,
            class_name,
            permission,
            observed ? "allowed" : "denied",
            expected ? "allowed" : "denied");
    }
}

static void verify_first_exec(const char *guard_context) {
    char transition[256];

    compute_transition(EXPECTED_KERNEL_CONTEXT, guard_context, transition, sizeof(transition));
    if (strcmp(transition, EXPECTED_INIT_CONTEXT) != 0) {
        fail_closed("guard transition yields %s, expected %s", transition, EXPECTED_INIT_CONTEXT);
    }

    require_permission(
        true,
        EXPECTED_KERNEL_CONTEXT,
        EXPECTED_INIT_CONTEXT,
        "process",
        "transition");
    require_permission(
        true,
        EXPECTED_INIT_CONTEXT,
        guard_context,
        "file",
        "entrypoint");
    require_permission(
        true,
        EXPECTED_KERNEL_CONTEXT,
        guard_context,
        "file",
        "execute");
    require_permission(
        false,
        EXPECTED_KERNEL_CONTEXT,
        guard_context,
        "file",
        "execute_no_trans");
}

static void verify_systemd_exec(const char *systemd_context) {
    char transition[256];

    compute_transition(EXPECTED_INIT_CONTEXT, systemd_context, transition, sizeof(transition));
    if (strcmp(transition, EXPECTED_INIT_CONTEXT) != 0) {
        fail_closed("systemd exec yields %s, expected %s", transition, EXPECTED_INIT_CONTEXT);
    }
    require_permission(
        true,
        EXPECTED_INIT_CONTEXT,
        systemd_context,
        "file",
        "execute");
    require_permission(
        true,
        EXPECTED_INIT_CONTEXT,
        systemd_context,
        "file",
        "execute_no_trans");
}

struct manifest_cursor {
    const unsigned char *next;
    const unsigned char *end;
};

static const char *next_manifest_field(struct manifest_cursor *cursor, size_t *length) {
    const unsigned char *terminator;

    if (cursor->next >= cursor->end) {
        fail_closed("runtime-closure manifest is truncated");
    }
    terminator = memchr(cursor->next, '\0', (size_t)(cursor->end - cursor->next));
    if (terminator == NULL) {
        fail_closed("runtime-closure manifest field is unterminated");
    }
    *length = (size_t)(terminator - cursor->next);
    if (*length == 0) {
        fail_closed("runtime-closure manifest contains an empty field");
    }

    {
        const char *field = (const char *)cursor->next;

        cursor->next = terminator + 1;
        return field;
    }
}

static void require_manifest_field(
    struct manifest_cursor *cursor,
    const char *expected,
    const char *description) {
    size_t length;
    const char *field = next_manifest_field(cursor, &length);

    if (length != strlen(expected) || memcmp(field, expected, length) != 0) {
        fail_closed("runtime-closure manifest has the wrong %s", description);
    }
}

static void sha256_kernel(const void *data, size_t length, unsigned char digest[32]) {
    struct sockaddr_alg algorithm = {
        .salg_family = AF_ALG,
        .salg_type = "hash",
        .salg_name = "sha256",
    };
    int operation;
    int socket_fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

    if (socket_fd < 0) {
        fail_closed("open kernel SHA-256 socket: %s", strerror(errno));
    }
    if (bind(socket_fd, (struct sockaddr *)&algorithm, sizeof(algorithm)) < 0) {
        int saved_errno = errno;

        close(socket_fd);
        fail_closed("bind kernel SHA-256 socket: %s", strerror(saved_errno));
    }
    operation = accept4(socket_fd, NULL, NULL, SOCK_CLOEXEC);
    if (operation < 0) {
        int saved_errno = errno;

        close(socket_fd);
        fail_closed("accept kernel SHA-256 operation: %s", strerror(saved_errno));
    }
    if (send(operation, data, length, 0) != (ssize_t)length ||
        read(operation, digest, 32) != 32) {
        int saved_errno = errno;

        close(operation);
        close(socket_fd);
        fail_closed("compute runtime-closure SHA-256: %s", strerror(saved_errno));
    }
    close(operation);
    close(socket_fd);
}

static void format_digest(const unsigned char digest[32], char hexadecimal[65]) {
    static const char digits[] = "0123456789abcdef";

    for (size_t index = 0; index < 32; index++) {
        hexadecimal[index * 2] = digits[digest[index] >> 4];
        hexadecimal[index * 2 + 1] = digits[digest[index] & 0x0f];
    }
    hexadecimal[64] = '\0';
}

static int open_physical_runtime_root(int lower_store_fd, const char *basename) {
    struct open_how how = {
        .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };

    return (int)syscall(SYS_openat2, lower_store_fd, basename, &how, sizeof(how));
}

static void pin_runtime_root(int lower_store_fd, const char *basename, size_t length) {
    static const char nix_base32[] = "0123456789abcdfghijklmnpqrsvwxyz";
    static const char store_name_characters[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+._?=-";
    char logical[PATH_MAX];
    struct stat logical_status;
    struct stat physical_status;
    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    int mount_fd;
    int physical_fd;

    if (length < 34 || length >= NAME_MAX || basename[32] != '-' ||
        strspn(basename, nix_base32) != 32 ||
        strspn(basename + 33, store_name_characters) != length - 33) {
        fail_closed("runtime-closure manifest contains a noncanonical basename");
    }
    if (snprintf(logical, sizeof(logical), "/nix/store/%.*s", (int)length, basename) >=
        (int)sizeof(logical)) {
        fail_closed("runtime-closure logical path is too long");
    }

    physical_fd = open_physical_runtime_root(lower_store_fd, basename);
    if (physical_fd < 0) {
        fail_closed("open physical runtime root %.*s: %s", (int)length, basename, strerror(errno));
    }
    if (fstat(physical_fd, &physical_status) < 0 || !S_ISDIR(physical_status.st_mode) ||
        physical_status.st_uid != 0 || physical_status.st_gid != 0) {
        close(physical_fd);
        fail_closed("physical runtime root %.*s is not a root-owned directory", (int)length, basename);
    }
    if (lstat(logical, &logical_status) < 0 || !S_ISDIR(logical_status.st_mode) ||
        S_ISLNK(logical_status.st_mode)) {
        close(physical_fd);
        fail_closed("logical runtime root %s is missing, whiteouted, or not a directory", logical);
    }
    if (physical_status.st_dev == logical_status.st_dev &&
        physical_status.st_ino == logical_status.st_ino) {
        close(physical_fd);
        require_filesystem(
            logical,
            EROFS_SUPER_MAGIC_V1,
            ST_RDONLY | ST_NOSUID | ST_NODEV,
            0);
        return;
    }

    mount_fd = (int)syscall(
        SYS_open_tree,
        physical_fd,
        "",
        AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (mount_fd < 0) {
        int saved_errno = errno;

        close(physical_fd);
        fail_closed("clone physical runtime root %.*s: %s", (int)length, basename, strerror(saved_errno));
    }
    if (syscall(SYS_mount_setattr, mount_fd, "", AT_EMPTY_PATH, &attributes, sizeof(attributes)) < 0 ||
        syscall(SYS_move_mount, mount_fd, "", AT_FDCWD, logical, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        int saved_errno = errno;

        close(mount_fd);
        close(physical_fd);
        fail_closed("pin runtime root %s: %s", logical, strerror(saved_errno));
    }
    close(mount_fd);

    if (stat(logical, &logical_status) < 0 ||
        physical_status.st_dev != logical_status.st_dev ||
        physical_status.st_ino != logical_status.st_ino) {
        close(physical_fd);
        fail_closed("pinned runtime root %s does not match its physical inode", logical);
    }
    close(physical_fd);
    require_filesystem(logical, EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NOSUID | ST_NODEV, 0);
}

static void pin_empty_loader_preload(void) {
    struct stat source;
    struct stat target;

    if (lstat(AOS_EMPTY_PRELOAD_PATH, &source) < 0 || !S_ISREG(source.st_mode) ||
        source.st_size != 0 || source.st_uid != 0 || source.st_gid != 0) {
        fail_closed("authenticated empty ld.so.preload source is invalid");
    }
    if (lstat("/etc/ld.so.preload", &target) < 0 || !S_ISREG(target.st_mode) ||
        S_ISLNK(target.st_mode)) {
        fail_closed("/etc/ld.so.preload is missing or not a regular file");
    }
    if (source.st_dev != target.st_dev || source.st_ino != target.st_ino) {
        if (mount(AOS_EMPTY_PRELOAD_PATH, "/etc/ld.so.preload", NULL, MS_BIND, NULL) < 0 ||
            mount(NULL, "/etc/ld.so.preload", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) < 0) {
            fail_closed("pin authenticated empty /etc/ld.so.preload: %s", strerror(errno));
        }
    }
    if (stat("/etc/ld.so.preload", &target) < 0 || target.st_size != 0 ||
        source.st_dev != target.st_dev || source.st_ino != target.st_ino) {
        fail_closed("pinned /etc/ld.so.preload does not match its authenticated source");
    }

    errno = 0;
    if (lstat("/etc/ld.so.cache", &target) == 0 || errno != ENOENT) {
        fail_closed("/etc/ld.so.cache must be absent in the protected loader namespace");
    }
}

static void read_mount_namespace_identity(char identity[64]) {
    ssize_t length = readlink("/proc/self/ns/mnt", identity, 63);

    if (length <= 0 || length >= 63) {
        fail_closed("read private mount namespace identity: %s", strerror(errno));
    }
    identity[length] = '\0';
    if (strncmp(identity, "mnt:[", strlen("mnt:[")) != 0 || identity[length - 1] != ']') {
        fail_closed("private mount namespace identity is malformed");
    }
}

static void await_qualification_post_pin_gate(const char *phase) {
    char continue_path[PATH_MAX];
    char ready_path[PATH_MAX];
    struct stat metadata;
    int ready;

    if (AOS_QUALIFICATION_POST_PIN_GATE[0] == '\0') {
        return;
    }
    if (snprintf(
            ready_path,
            sizeof(ready_path),
            "%s.%s.ready",
            AOS_QUALIFICATION_POST_PIN_GATE,
            phase) >= (int)sizeof(ready_path) ||
        snprintf(
            continue_path,
            sizeof(continue_path),
            "%s.%s.continue",
            AOS_QUALIFICATION_POST_PIN_GATE,
            phase) >= (int)sizeof(continue_path)) {
        fail_closed("qualification post-pin gate path exceeds PATH_MAX");
    }

    ready = open(
        ready_path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0444);
    if (ready < 0 || dprintf(ready, "ready\n") < 0 || fsync(ready) < 0 || close(ready) < 0) {
        fail_closed("publish qualification post-pin readiness: %s", strerror(errno));
    }

    for (;;) {
        errno = 0;
        if (lstat(continue_path, &metadata) == 0) {
            if (!S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode) ||
                metadata.st_uid != 0 || metadata.st_gid != 0 ||
                (metadata.st_mode & 07777) != 0444 || metadata.st_size != 9) {
                fail_closed("qualification post-pin continuation has invalid metadata");
            }
            require_text_file(continue_path, "continue");
            return;
        }
        if (errno != ENOENT) {
            fail_closed("inspect qualification post-pin continuation: %s", strerror(errno));
        }
        usleep(1000);
    }
}

static void pin_runtime_closure(const char *phase) {
    const unsigned char *manifest = _binary_systemd_runtime_manifest_bin_start;
    size_t manifest_size = embedded_size(
        manifest,
        _binary_systemd_runtime_manifest_bin_end,
        "systemd runtime-closure manifest");
    struct manifest_cursor cursor = {.next = manifest, .end = manifest + manifest_size};
    const unsigned char *digest_start;
    unsigned char binary_digest[32];
    char hexadecimal_digest[65];
    char mount_namespace[64];
    char count_text[32];
    size_t count_length;
    size_t digest_length;
    unsigned long count;
    const char *basenames[MAX_RUNTIME_ROOTS];
    size_t basename_lengths[MAX_RUNTIME_ROOTS];
    char *end = NULL;
    int lower_store_fd;

    require_manifest_field(&cursor, AOS_MANIFEST_MAGIC, "magic");
    require_manifest_field(&cursor, AOS_MANIFEST_VERSION, "version");
    require_manifest_field(&cursor, AOS_PHYSICAL_SYSTEMD_PATH, "systemd path");
    require_manifest_field(&cursor, AOS_PHYSICAL_INTERPRETER_PATH, "interpreter path");
    require_manifest_field(
        &cursor,
        AOS_PHYSICAL_RUNTIME_ROOTS_PATH,
        "runtime-root provisioner path");
    require_manifest_field(
        &cursor,
        AOS_EXPECTED_POLICY_SHA256,
        "immutable policy identity");
    {
        const char *field = next_manifest_field(&cursor, &count_length);

        if (count_length >= sizeof(count_text)) {
            fail_closed("runtime-closure manifest count is too long");
        }
        memcpy(count_text, field, count_length);
        count_text[count_length] = '\0';
    }
    errno = 0;
    count = strtoul(count_text, &end, 10);
    if (errno != 0 || end == count_text || *end != '\0' || count == 0 ||
        count > MAX_RUNTIME_ROOTS || count != AOS_RUNTIME_CLOSURE_COUNT) {
        fail_closed("runtime-closure manifest count is invalid");
    }

    for (unsigned long index = 0; index < count; index++) {
        basenames[index] = next_manifest_field(&cursor, &basename_lengths[index]);
        if (index > 0) {
            size_t shared = basename_lengths[index - 1] < basename_lengths[index]
                ? basename_lengths[index - 1]
                : basename_lengths[index];
            int ordering = memcmp(basenames[index - 1], basenames[index], shared);

            if (ordering > 0 ||
                (ordering == 0 && basename_lengths[index - 1] >= basename_lengths[index])) {
                fail_closed("runtime-closure manifest basenames are duplicate or not ordered");
            }
        }
    }

    digest_start = cursor.next;
    {
        const char *digest = next_manifest_field(&cursor, &digest_length);

        if (cursor.next != cursor.end || digest_length != 64 ||
            memcmp(digest, AOS_RUNTIME_CLOSURE_DIGEST, 64) != 0) {
            fail_closed("runtime-closure manifest digest field is invalid");
        }
        sha256_kernel(manifest, (size_t)(digest_start - manifest), binary_digest);
        format_digest(binary_digest, hexadecimal_digest);
        if (memcmp(digest, hexadecimal_digest, 64) != 0) {
            fail_closed("runtime-closure manifest digest does not authenticate its fields");
        }
    }

    lower_store_fd = open("/nix.lower/store", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (lower_store_fd < 0) {
        fail_closed("open physical lower store: %s", strerror(errno));
    }
    for (unsigned long index = 0; index < count; index++) {
        pin_runtime_root(lower_store_fd, basenames[index], basename_lengths[index]);
    }
    close(lower_store_fd);

    pin_empty_loader_preload();
    read_mount_namespace_identity(mount_namespace);

    ensure_directory("/run/aos", 0755);
    {
        int marker = open(
            AOS_HANDOFF_MARKER_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
            0444);

        if (marker < 0 || dprintf(
                marker,
                "version=1\nphase=%s\nsystemd=%s\nmanifest_sha256=%s\nmanifest_count=%lu\nmount_namespace=%s\n",
                phase,
                AOS_PHYSICAL_SYSTEMD_PATH,
                hexadecimal_digest,
                count,
                mount_namespace) < 0 || fsync(marker) < 0 || close(marker) < 0) {
            fail_closed("write root-handoff diagnostic marker: %s", strerror(errno));
        }
    }

    await_qualification_post_pin_gate(phase);
}

static void require_clean_loader_environment(void) {
    for (char **variable = environ; *variable != NULL; variable++) {
        if (strncmp(*variable, "LD_", 3) == 0 ||
            strncmp(*variable, "GLIBC_TUNABLES=", strlen("GLIBC_TUNABLES=")) == 0) {
            fail_closed("loader-control environment is present");
        }
    }
}

static void require_absent_loader_control_files(void) {
    static const char *const paths[] = {
        "/etc/ld.so.preload",
        "/etc/ld.so.cache",
    };

    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
        struct stat metadata;

        errno = 0;
        if (lstat(paths[index], &metadata) == 0 || errno != ENOENT) {
            fail_closed("inner-stage loader-control path must be absent: %s", paths[index]);
        }
    }
}

static int require_serialization_descriptor(int argc, char **argv) {
    int descriptor = -1;

    for (int index = 2; index < argc; index++) {
        const char *value = NULL;
        char *end = NULL;
        long parsed;

        if (strncmp(argv[index], "--deserialize=", strlen("--deserialize=")) == 0) {
            value = argv[index] + strlen("--deserialize=");
        } else if (strcmp(argv[index], "--deserialize") == 0 && index + 1 < argc) {
            value = argv[++index];
        } else {
            continue;
        }
        if (descriptor >= 0) {
            fail_closed("serialization descriptor occurs more than once");
        }
        errno = 0;
        parsed = strtol(value, &end, 10);
        if (errno != 0 || end == value || *end != '\0' || parsed < 3 || parsed > INT_MAX) {
            fail_closed("serialization descriptor is not canonical");
        }
        descriptor = (int)parsed;
    }
    if (descriptor < 0 || fcntl(descriptor, F_GETFD) < 0 ||
        (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0) {
        fail_closed("serialization descriptor is absent, closed, or close-on-exec");
    }
    return descriptor;
}

static void run_root_handoff(int argc, char **argv) {
    char systemd_context[256];
    const char *phase;
    struct stat lower_status;
    struct stat mapper_status;
    struct stat root_status;
    int interpreter_fd;
    int systemd_fd;

    isolate_root_handoff_mount_namespace();
    attach_console();
    require_current_context(EXPECTED_INIT_CONTEXT);
    validate_command_line();
    validate_loaded_policy();
    require_clean_loader_environment();
    require_serialization_descriptor(argc, argv);

    if (strcmp(argv[1], AOS_HANDOFF_SWITCH) == 0) {
        phase = "switch-root";
    } else if (strcmp(argv[1], AOS_HANDOFF_REEXEC) == 0) {
        phase = "reexec";
    } else {
        fail_closed("unknown root-handoff phase");
    }

    require_filesystem("/", EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NODEV, 0);
    require_filesystem(
        "/nix.lower",
        EROFS_SUPER_MAGIC_V1,
        ST_RDONLY | ST_NODEV,
        0);
    if (stat("/", &root_status) < 0 || stat("/nix.lower", &lower_status) < 0 ||
        stat("/dev/mapper/root", &mapper_status) < 0 || !S_ISBLK(mapper_status.st_mode) ||
        root_status.st_dev != lower_status.st_dev || root_status.st_dev != mapper_status.st_rdev) {
        fail_closed("root handoff is not executing on the verified /dev/mapper/root filesystem");
    }
    verify_physical_target(
        AOS_ROOT_HANDOFF_PATH,
        AOS_ROOT_HANDOFF_PATH,
        EXPECTED_INIT_EXEC_CONTEXT,
        systemd_context,
        sizeof(systemd_context));
    systemd_fd = open_verified_physical_store_target(
        "/",
        AOS_PHYSICAL_SYSTEMD_PATH,
        EXPECTED_INIT_EXEC_CONTEXT,
        systemd_context,
        sizeof(systemd_context));
    verify_systemd_exec(systemd_context);
    interpreter_fd = open_verified_physical_store_target(
        "/",
        AOS_PHYSICAL_INTERPRETER_PATH,
        EXPECTED_LOADER_CONTEXT,
        systemd_context,
        sizeof(systemd_context));
    require_permission(
        true,
        EXPECTED_INIT_CONTEXT,
        EXPECTED_LOADER_CONTEXT,
        "file",
        "execute");
    close(interpreter_fd);

    pin_runtime_closure(phase);
    log_status("runtime closure pinned; %s handoff to physical systemd", phase);

    argv[1] = (char *)AOS_PHYSICAL_SYSTEMD_PATH;
    execveat(systemd_fd, "", &argv[1], environ, AT_EMPTY_PATH);
    fail_closed("exec retained physical root systemd: %s", strerror(errno));
}

static void run_runtime_roots_launcher(int argc, char **argv) {
    char guard_path[PATH_MAX];
    char lower_path[PATH_MAX];
    char executable_context[256];
    char *provisioner_arguments[5];
    const char *root_prefix;
    struct stat lower_status;
    struct stat root_status;
    int provisioner_fd;

    if (argc != 6 || strcmp(argv[2], AOS_RUNTIME_ROOTS_PATH) != 0 ||
        strcmp(argv[3], "--root") != 0 ||
        (strcmp(argv[4], "/") != 0 && strcmp(argv[4], "/sysroot") != 0) ||
        (strcmp(argv[5], "--prepare-var-base") != 0 &&
         strcmp(argv[5], "--prepare-sandbox-network-roots") != 0)) {
        fail_closed(
            "runtime-root launch arguments do not match the authenticated contract");
    }
    if ((strcmp(argv[4], "/sysroot") == 0) !=
        (strcmp(argv[5], "--prepare-var-base") == 0)) {
        fail_closed("runtime-root launch phase and root are not the supported fixed pair");
    }
    root_prefix = argv[4];

    isolate_root_handoff_mount_namespace();
    attach_console();
    require_current_context(EXPECTED_INIT_CONTEXT);
    validate_command_line();
    validate_loaded_policy();
    require_clean_loader_environment();

    if (strcmp(root_prefix, "/") == 0) {
        if (snprintf(guard_path, sizeof(guard_path), "%s", AOS_ROOT_HANDOFF_PATH) >=
                (int)sizeof(guard_path) ||
            snprintf(lower_path, sizeof(lower_path), "/nix.lower") >=
                (int)sizeof(lower_path)) {
            fail_closed("runtime-root physical path exceeds PATH_MAX");
        }
    } else if (snprintf(
                   guard_path,
                   sizeof(guard_path),
                   "%s%s",
                   root_prefix,
                   AOS_ROOT_HANDOFF_PATH) >= (int)sizeof(guard_path) ||
               snprintf(
                   lower_path,
                   sizeof(lower_path),
                   "%s/nix.lower",
                   root_prefix) >= (int)sizeof(lower_path)) {
        fail_closed("prefixed runtime-root physical path exceeds PATH_MAX");
    }

    require_filesystem(root_prefix, EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NODEV, 0);
    require_filesystem(lower_path, EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NODEV, 0);
    if (stat(root_prefix, &root_status) < 0 || stat(lower_path, &lower_status) < 0 ||
        root_status.st_dev != lower_status.st_dev) {
        fail_closed("runtime-root launcher is not using one authenticated EROFS device");
    }
    verify_physical_target(
        guard_path,
        guard_path,
        EXPECTED_INIT_EXEC_CONTEXT,
        executable_context,
        sizeof(executable_context));
    provisioner_fd = open_verified_physical_store_target(
        root_prefix,
        AOS_PHYSICAL_RUNTIME_ROOTS_PATH,
        EXPECTED_RUNTIME_ROOTS_EXEC_CONTEXT,
        executable_context,
        sizeof(executable_context));

    provisioner_arguments[0] = (char *)AOS_PHYSICAL_RUNTIME_ROOTS_PATH;
    provisioner_arguments[1] = "--root";
    provisioner_arguments[2] = argv[4];
    provisioner_arguments[3] = argv[5];
    provisioner_arguments[4] = NULL;
    execveat(provisioner_fd, "", provisioner_arguments, environ, AT_EMPTY_PATH);
    fail_closed("exec retained physical runtime-root provisioner: %s", strerror(errno));
}

static void mount_inner_stage(void) {
    ensure_directory("/dev", 0755);
    mount_filesystem(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        MS_NOSUID | MS_NOEXEC,
        "mode=0755",
        TMPFS_MAGIC,
        ST_NOSUID | ST_NOEXEC,
        0);
    attach_console();

    ensure_directory("/proc", 0555);
    ensure_directory("/sys", 0555);
    ensure_directory("/run", 0755);
    ensure_directory("/newroot", 0755);

    mount_filesystem(
        "proc",
        "/proc",
        "proc",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        NULL,
        PROC_SUPER_MAGIC,
        ST_NOSUID | ST_NOEXEC | ST_NODEV,
        0);
    mount_filesystem(
        "sysfs",
        "/sys",
        "sysfs",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        NULL,
        SYSFS_MAGIC,
        ST_NOSUID | ST_NOEXEC | ST_NODEV,
        0);
    mount_filesystem(
        "tmpfs",
        "/run",
        "tmpfs",
        MS_NOSUID | MS_NODEV,
        "mode=0755",
        TMPFS_MAGIC,
        ST_NOSUID | ST_NODEV,
        ST_NOEXEC);

    {
        struct stat image_metadata;

        if (lstat("/aos-stage1.erofs", &image_metadata) < 0) {
            fail_closed("stat inner stage-1 image: %s", strerror(errno));
        }
        if (!S_ISREG(image_metadata.st_mode) || image_metadata.st_size <= 0) {
            fail_closed("inner stage-1 image is not a nonempty regular file");
        }
    }
    mount_filesystem(
        "/aos-stage1.erofs",
        "/newroot",
        "erofs",
        MS_RDONLY | MS_NODEV,
        NULL,
        EROFS_SUPER_MAGIC_V1,
        ST_RDONLY | ST_NODEV,
        ST_NOSUID);

    move_mounted_tree("/dev", "/newroot/dev", TMPFS_MAGIC, ST_NOSUID | ST_NOEXEC, 0);
    move_mounted_tree(
        "/proc",
        "/newroot/proc",
        PROC_SUPER_MAGIC,
        ST_NOSUID | ST_NOEXEC | ST_NODEV,
        0);
    move_mounted_tree(
        "/sys",
        "/newroot/sys",
        SYSFS_MAGIC,
        ST_NOSUID | ST_NOEXEC | ST_NODEV,
        0);
    move_mounted_tree(
        "/run",
        "/newroot/run",
        TMPFS_MAGIC,
        ST_NOSUID | ST_NODEV,
        ST_NOEXEC);

    if (chdir("/newroot") < 0 || chroot(".") < 0 || chdir("/") < 0) {
        fail_closed("enter labeled stage-1 root: %s", strerror(errno));
    }

    mount_filesystem(
        "selinuxfs",
        SELINUX_ROOT,
        "selinuxfs",
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        NULL,
        SELINUX_MAGIC,
        ST_NOSUID | ST_NOEXEC | ST_NODEV,
        0);
}

static void run_outer_loader(void) {
    char guard_context[256];
    char *guard_arguments[] = {"/sbin/init", "--inner-guard", NULL};

    mount_inner_stage();
    validate_command_line();
    require_text_file(SELINUX_ROOT "/enforce", "1");
    verify_physical_target(
        "/sbin/init",
        AOS_GUARD_PATH,
        EXPECTED_INIT_EXEC_CONTEXT,
        guard_context,
        sizeof(guard_context));

    load_policy();
    validate_loaded_policy();
    require_current_context(EXPECTED_KERNEL_CONTEXT);
    verify_physical_target(
        "/sbin/init",
        AOS_GUARD_PATH,
        EXPECTED_INIT_EXEC_CONTEXT,
        guard_context,
        sizeof(guard_context));
    verify_first_exec(guard_context);

    log_status("policy exact and enforcing; entering init_t guard");
    execve("/sbin/init", guard_arguments, environ);
    fail_closed("exec inner stage-1 guard: %s", strerror(errno));
}

static void run_inner_guard(void) {
    char systemd_context[256];
    char unit_argument[320];
    char *systemd_arguments[3] = {"/usr/bin/systemd", NULL, NULL};

    attach_console();
    require_current_context(EXPECTED_INIT_CONTEXT);
    validate_loaded_policy();
    require_filesystem(
        "/",
        EROFS_SUPER_MAGIC_V1,
        ST_RDONLY | ST_NODEV,
        ST_NOSUID);
    require_clean_loader_environment();
    require_absent_loader_control_files();
    verify_physical_target(
        "/usr/bin/systemd",
        AOS_SYSTEMD_PATH,
        EXPECTED_INIT_EXEC_CONTEXT,
        systemd_context,
        sizeof(systemd_context));
    verify_systemd_exec(systemd_context);

    if (AOS_ADMISSION_UNIT[0] != '\0') {
        if (snprintf(
                unit_argument,
                sizeof(unit_argument),
                "--unit=%s",
                AOS_ADMISSION_UNIT) >= (int)sizeof(unit_argument)) {
            fail_closed("admission unit name is too long");
        }
        systemd_arguments[1] = unit_argument;
    }

    log_status("PID 1 is init_t; handing off to physically labeled systemd");
    execve("/usr/bin/systemd", systemd_arguments, environ);
    fail_closed("exec stage-1 systemd: %s", strerror(errno));
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], AOS_RUNTIME_ROOTS_LAUNCH) == 0) {
        run_runtime_roots_launcher(argc, argv);
    }

    require_pid_one();

    if (argc >= 3 &&
        (strcmp(argv[1], AOS_HANDOFF_SWITCH) == 0 ||
         strcmp(argv[1], AOS_HANDOFF_REEXEC) == 0)) {
        run_root_handoff(argc, argv);
    }
    if (argc == 2 && strcmp(argv[1], "--inner-guard") == 0) {
        run_inner_guard();
    }
    if (argc != 1) {
        fail_closed("unexpected loader arguments");
    }
    run_outer_loader();
}
