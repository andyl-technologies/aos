// SPDX-License-Identifier: Apache-2.0
// Exercises the production bootstrap label helper with controlled kernel replies.
#include <assert.h>
#include <errno.h>
#include <linux/magic.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/xattr.h>

static jmp_buf failure;
static struct stat metadata;
static long filesystem_magic;
static const char *observed_label;
static unsigned int reads;
static unsigned int writes;
static unsigned int failing_read;
static bool failing_write;
static bool substituted_write;

static void fail_closed(const char *format, ...) {
    (void)format;
    longjmp(failure, 1);
}

static int mock_fstat(int descriptor, struct stat *result) {
    assert(descriptor == 17);
    *result = metadata;
    return 0;
}

static int mock_fstatfs(int descriptor, struct statfs *result) {
    assert(descriptor == 17);
    memset(result, 0, sizeof(*result));
    result->f_type = filesystem_magic;
    return 0;
}

static ssize_t mock_fgetxattr(int descriptor, const char *name, void *buffer, size_t size) {
    assert(descriptor == 17);
    assert(strcmp(name, "security.selinux") == 0);
    reads++;
    if (reads == failing_read) {
        errno = EACCES;
        return -1;
    }
    size_t length = strlen(observed_label) + 1;
    assert(length <= size);
    memcpy(buffer, observed_label, length);
    return (ssize_t)length;
}

static int mock_fsetxattr(int descriptor, const char *name, const void *value,
                         size_t size, int flags) {
    assert(descriptor == 17);
    assert(strcmp(name, "security.selinux") == 0);
    assert(strcmp(value, "system_u:object_r:var_run_t") == 0);
    assert(size == sizeof("system_u:object_r:var_run_t"));
    assert(flags == 0);
    writes++;
    if (failing_write) {
        errno = EACCES;
        return -1;
    }
    observed_label = substituted_write ? "system_u:object_r:tmpfs_t" : value;
    return 0;
}

#define fstat mock_fstat
#define fstatfs mock_fstatfs
#define fgetxattr mock_fgetxattr
#define fsetxattr mock_fsetxattr
#include "_aos-selinux-stage0-runtime-parent.inc"
#undef fstat
#undef fstatfs
#undef fgetxattr
#undef fsetxattr

static void reset(void) {
    metadata = (struct stat){.st_mode = S_IFDIR | 0755, .st_uid = 0, .st_gid = 0};
    filesystem_magic = TMPFS_MAGIC;
    observed_label = "system_u:object_r:tmpfs_t";
    reads = writes = failing_read = 0;
    failing_write = substituted_write = false;
}

static void check(bool accepted, unsigned int expected_writes) {
    bool refused = setjmp(failure) != 0;
    if (!refused) {
        label_initial_runtime_directory(17, "/run/aos");
    }
    assert(refused != accepted);
    assert(writes == expected_writes);
}

int main(void) {
    reset();
    check(true, 1);
    assert(reads == 2);

    reset();
    observed_label = "system_u:object_r:var_run_t";
    check(true, 0);

    reset();
    observed_label = "system_u:object_r:init_tmpfs_t";
    check(false, 0);

    reset();
    metadata.st_uid = 1;
    check(false, 0);

    reset();
    metadata.st_gid = 1;
    check(false, 0);

    reset();
    metadata.st_mode = S_IFDIR | 0775;
    check(false, 0);

    reset();
    metadata.st_mode = S_IFREG | 0755;
    check(false, 0);

    reset();
    filesystem_magic = EXT4_SUPER_MAGIC;
    check(false, 0);

    reset();
    failing_read = 1;
    check(false, 0);

    reset();
    failing_write = true;
    check(false, 1);

    reset();
    failing_read = 2;
    check(false, 1);

    reset();
    substituted_write = true;
    check(false, 1);

    puts("initial runtime parent label checks passed");
    return 0;
}
