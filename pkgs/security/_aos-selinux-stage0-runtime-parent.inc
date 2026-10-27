// SPDX-License-Identifier: Apache-2.0
// Fixed initial tmpfs parents; included after the fail-closed reporter.

static void label_initial_runtime_directory(int descriptor, const char *path) {
    static const char expected[] = "system_u:object_r:var_run_t";
    static const char initial[] = "system_u:object_r:tmpfs_t";
    char context[256];
    struct stat metadata;
    struct statfs filesystem;
    ssize_t length;

    if (fstat(descriptor, &metadata) < 0 || !S_ISDIR(metadata.st_mode) ||
        fstatfs(descriptor, &filesystem) < 0 || filesystem.f_type != TMPFS_MAGIC ||
        metadata.st_uid != 0 || metadata.st_gid != 0 ||
        (metadata.st_mode & 07777) != 0755) {
        fail_closed("initial runtime directory %s is not root-owned mode 0755", path);
    }
    length = fgetxattr(descriptor, "security.selinux", context, sizeof(context));
    if (length <= 0 || (size_t)length > sizeof(context)) {
        fail_closed("read initial runtime directory label %s: %s", path, strerror(errno));
    }
    if (context[length - 1] == '\0') {
        length--;
    }
    if ((size_t)length == sizeof(expected) - 1 &&
        memcmp(context, expected, sizeof(expected) - 1) == 0) {
        return;
    }
    if ((size_t)length != sizeof(initial) - 1 ||
        memcmp(context, initial, sizeof(initial) - 1) != 0) {
        fail_closed("initial runtime directory %s has an unexpected label", path);
    }
    if (fsetxattr(descriptor, "security.selinux", expected, sizeof(expected), 0) < 0) {
        fail_closed("label initial runtime directory %s: %s", path, strerror(errno));
    }
    length = fgetxattr(descriptor, "security.selinux", context, sizeof(context));
    if (length > 0 && context[length - 1] == '\0') {
        length--;
    }
    if ((size_t)length != sizeof(expected) - 1 ||
        memcmp(context, expected, sizeof(expected) - 1) != 0) {
        fail_closed("initial runtime directory %s did not retain its label", path);
    }
}

