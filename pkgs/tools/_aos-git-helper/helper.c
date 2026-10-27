// SPDX-License-Identifier: Apache-2.0
/*
 * Closed native Git execution mechanics, separate from Git's implementation.
 *
 * The retained parent admits the plan and private repository, owns the original
 * image/namespace/currentness cut and supervises the original child deadline.
 * This program checks fixed descriptor mechanics; it never creates authority,
 * publishes, releases aggregate quota or proves complete descendant/FD drain.
 *
 * Plan: AOSGHP01 | verb:1 | format:1 | reserved:6 | stdin:8 | stdout:8 |
 *       expanded:8 | objects:8 | seconds:8 | git-verity:32 | helper-verity:32.
 * All integers are big-endian; descriptors are stdin0/stdout1/stderr2,
 * sealed-plan3/private-directory4/Git-image5/original-helper-image6.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/fsverity.h>
#include <linux/openat2.h>
#include <linux/securebits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#if !defined(AOS_GIT_PROGRAM) || !defined(AOS_GIT_HELPER_PROGRAM) || \
    !defined(AOS_GIT_EXEC_DIRECTORY) || !defined(AOS_GIT_EMPTY_HOOKS) || \
    !defined(AOS_GIT_EMPTY_TEMPLATE)
#error "The AOS recipe must provide all five fixed installed names"
#endif

#ifndef STATX_MNT_ID_UNIQUE
#error "The selected AOS Linux UAPI must include unique mount identity"
#endif

_Static_assert(sizeof(AOS_GIT_PROGRAM) <= 4096, "Git name exceeds fixed bound");
_Static_assert(sizeof(AOS_GIT_HELPER_PROGRAM) <= 4096, "Helper name exceeds fixed bound");
_Static_assert(sizeof(AOS_GIT_EXEC_DIRECTORY) <= 4096, "Exec directory exceeds fixed bound");
_Static_assert(sizeof(AOS_GIT_EMPTY_HOOKS) <= 4096, "Hooks directory exceeds fixed bound");
_Static_assert(sizeof(AOS_GIT_EMPTY_TEMPLATE) <= 4096, "Template directory exceeds fixed bound");

enum {
    PLAN_BYTES = 120,
    DIGEST_BYTES = 32,
    ARGUMENT_SLOTS = 96,
    OPTION_BYTES = 64,
    OID_BYTES = 65,
    DENIAL_BYTES = 16,
};

static const uint64_t maximum_stream_bytes = UINT64_C(268435456);
static const uint64_t maximum_objects = UINT64_C(262144);

enum git_verb {
    UPLOAD = 1,
    RECEIVE = 2,
    FSCK = 3,
    ENUMERATE = 4,
    REFERENCES = 5,
    PACK = 6,
    INDEX_PACK = 7,
    UPDATE_REFERENCES = 8,
    INIT_BARE = 9,
    IS_ANCESTOR = 10,
    ADVERTISE_UPLOAD = 11,
    ADVERTISE_RECEIVE = 12,
};

enum denial_stage {
    STARTUP = 1,
    RESTRICTION = 2,
    DESCRIPTORS = 3,
    PLAN = 4,
    INPUT = 5,
    IMAGES = 6,
    PREPARATION = 7,
    BUDGET = 8,
    BOOKENDS = 9,
    EXEC = 10,
};

enum denial_reason {
    MALFORMED = 1,
    UNEXPECTED_DESCRIPTOR = 2,
    MISSING_SEALS = 3,
    LIMIT = 4,
    MISMATCH = 5,
    UNSUPPORTED = 6,
    SYSTEM = 7,
    INTERNAL = 8,
};

struct failure {
    enum denial_stage stage;
    enum denial_reason reason;
    uint32_t original_errno;
};

struct plan {
    enum git_verb verb;
    unsigned format;
    uint64_t input_bytes;
    uint64_t output_bytes;
    uint64_t expanded_bytes;
    uint64_t object_limit;
    uint64_t seconds;
    uint8_t git_digest[DIGEST_BYTES];
    uint8_t helper_digest[DIGEST_BYTES];
};

struct file_identity {
    uint32_t device_major;
    uint32_t device_minor;
    uint64_t inode;
    uint64_t size;
    uint64_t mount_id;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
    int64_t mtime_seconds;
    uint32_t mtime_nanoseconds;
    int64_t ctime_seconds;
    uint32_t ctime_nanoseconds;
};

struct oid_lines {
    uint8_t current[OID_BYTES];
    uint8_t previous[OID_BYTES];
    size_t width;
    size_t used;
    uint64_t count;
    uint64_t limit;
};

struct ancestor_input {
    char first[OID_BYTES];
    char second[OID_BYTES];
};

struct git_command {
    const char *arguments[ARGUMENT_SLOTS];
    size_t count;
    char input_option[OPTION_BYTES];
    struct ancestor_input ancestors;
};

/* First failure is retained; later cleanup cannot rewrite denial precedence. */
static bool refuse(struct failure *failure, enum denial_stage stage,
                   enum denial_reason reason, int original_errno)
{
    if (failure->stage == 0) {
        failure->stage = stage;
        failure->reason = reason;
        failure->original_errno = original_errno > 0 ? (uint32_t)original_errno : 0;
    }
    return false;
}

static uint64_t read_big_endian(const uint8_t *bytes, size_t length)
{
    uint64_t value = 0;
    for (size_t index = 0; index < length; index++)
        value = (value << 8) | bytes[index];
    return value;
}

static bool has_nonzero_byte(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0;
    for (size_t index = 0; index < length; index++)
        combined |= bytes[index];
    return combined != 0;
}

static bool decode_plan(const uint8_t *bytes, size_t length,
                        struct plan *plan, struct failure *failure)
{
    if (length != PLAN_BYTES || memcmp(bytes, "AOSGHP01", 8) != 0 ||
        bytes[8] < UPLOAD || bytes[8] > ADVERTISE_RECEIVE ||
        (bytes[9] != 1 && bytes[9] != 2) || has_nonzero_byte(bytes + 10, 6))
        return refuse(failure, PLAN, MALFORMED, 0);

    *plan = (struct plan) {
        .verb = (enum git_verb)bytes[8],
        .format = bytes[9],
        .input_bytes = read_big_endian(bytes + 16, 8),
        .output_bytes = read_big_endian(bytes + 24, 8),
        .expanded_bytes = read_big_endian(bytes + 32, 8),
        .object_limit = read_big_endian(bytes + 40, 8),
        .seconds = read_big_endian(bytes + 48, 8),
    };
    memcpy(plan->git_digest, bytes + 56, DIGEST_BYTES);
    memcpy(plan->helper_digest, bytes + 88, DIGEST_BYTES);

    rlim_t expanded = (rlim_t)plan->expanded_bytes;
    if (plan->input_bytes > maximum_stream_bytes || plan->output_bytes == 0 ||
        plan->output_bytes > maximum_stream_bytes || plan->expanded_bytes == 0 ||
        plan->expanded_bytes == UINT64_MAX || expanded == RLIM_INFINITY ||
        (uint64_t)expanded != plan->expanded_bytes || plan->object_limit == 0 ||
        plan->object_limit > maximum_objects || plan->seconds == 0 || plan->seconds > 300)
        return refuse(failure, PLAN, LIMIT, 0);

    if (!has_nonzero_byte(plan->git_digest, DIGEST_BYTES) ||
        !has_nonzero_byte(plan->helper_digest, DIGEST_BYTES))
        return refuse(failure, PLAN, MISMATCH, 0);
    return true;
}

static bool identities_equal(const struct file_identity *left,
                             const struct file_identity *right)
{
    return left->device_major == right->device_major &&
           left->device_minor == right->device_minor && left->inode == right->inode &&
           left->size == right->size && left->mount_id == right->mount_id &&
           left->mode == right->mode && left->uid == right->uid &&
           left->gid == right->gid && left->links == right->links &&
           left->mtime_seconds == right->mtime_seconds &&
           left->mtime_nanoseconds == right->mtime_nanoseconds &&
           left->ctime_seconds == right->ctime_seconds &&
           left->ctime_nanoseconds == right->ctime_nanoseconds;
}

static bool is_image_metadata(const struct file_identity *identity)
{
    return S_ISREG(identity->mode) && identity->uid == 0 && identity->links == 1 &&
           (identity->mode & 0222) == 0 && (identity->mode & 0111) != 0 &&
           identity->size > 0 && identity->size <= maximum_stream_bytes;
}

static bool is_private_directory(const struct file_identity *identity)
{
    return S_ISDIR(identity->mode) && identity->uid == 0 &&
           (identity->mode & 0777) == 0700;
}

static bool is_sealed_metadata(const struct file_identity *identity, uint32_t owner,
                               uint64_t expected_size)
{
    return S_ISREG(identity->mode) && identity->uid == owner &&
           identity->links == 0 && identity->size == expected_size;
}

static bool has_full_seals(int seals)
{
    int required = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    return seals >= 0 && (seals & required) == required;
}

static bool is_readonly_access_flags(int flags)
{
    /* O_PATH has O_RDONLY's zero access bits without a readable OFD. */
    return (flags & O_PATH) == 0 && (flags & O_ACCMODE) == O_RDONLY;
}

static bool input_length_allowed(enum git_verb verb, uint64_t bytes, unsigned format)
{
    switch (verb) {
    case UPLOAD:
    case RECEIVE:
    case UPDATE_REFERENCES:
        return bytes > 0;
    case FSCK:
    case ENUMERATE:
    case REFERENCES:
    case INIT_BARE:
    case ADVERTISE_UPLOAD:
    case ADVERTISE_RECEIVE:
        return bytes == 0;
    case PACK:
        return true;
    case INDEX_PACK:
        return bytes >= 12;
    case IS_ANCESTOR:
        return bytes == (format == 1 ? 82U : 130U);
    }
    return false;
}

static bool is_lower_hex(uint8_t byte)
{
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
}

static bool admit_oid_bytes(struct oid_lines *lines, const uint8_t *bytes,
                            size_t length, struct failure *failure)
{
    if (lines->width != 40 && lines->width != 64)
        return refuse(failure, INPUT, INTERNAL, 0);
    for (size_t index = 0; index < length; index++) {
        if (lines->used < lines->width) {
            if (!is_lower_hex(bytes[index]))
                return refuse(failure, INPUT, MALFORMED, 0);
            lines->current[lines->used++] = bytes[index];
            continue;
        }

        if (bytes[index] != '\n' || lines->count >= lines->limit ||
            (lines->count != 0 && memcmp(lines->previous, lines->current, lines->width) >= 0))
            return refuse(failure, INPUT, MALFORMED, 0);
        memcpy(lines->previous, lines->current, lines->width);
        lines->count++;
        lines->used = 0;
    }
    return true;
}

static bool admit_pack_header(const uint8_t *bytes, size_t length,
                              uint64_t object_limit, struct failure *failure)
{
    if (length != 12 || memcmp(bytes, "PACK", 4) != 0 ||
        (read_big_endian(bytes + 4, 4) != 2 && read_big_endian(bytes + 4, 4) != 3) ||
        read_big_endian(bytes + 8, 4) > object_limit)
        return refuse(failure, INPUT, MALFORMED, 0);
    return true;
}

static bool admit_ancestors(const uint8_t *bytes, size_t length, size_t width,
                            struct ancestor_input *ancestors, struct failure *failure)
{
    if ((width != 40 && width != 64) || length != 2 * (width + 1))
        return refuse(failure, INPUT, MALFORMED, 0);
    for (size_t index = 0; index < width; index++) {
        if (!is_lower_hex(bytes[index]) || !is_lower_hex(bytes[width + 1 + index]))
            return refuse(failure, INPUT, MALFORMED, 0);
    }
    if (bytes[width] != '\n' || bytes[2 * width + 1] != '\n')
        return refuse(failure, INPUT, MALFORMED, 0);

    memcpy(ancestors->first, bytes, width);
    memcpy(ancestors->second, bytes + width + 1, width);
    ancestors->first[width] = '\0';
    ancestors->second[width] = '\0';
    return true;
}

static bool append_argument(struct git_command *command, const char *argument,
                            struct failure *failure)
{
    if (command->count + 1 >= ARGUMENT_SLOTS)
        return refuse(failure, PREPARATION, INTERNAL, 0);
    command->arguments[command->count++] = argument;
    command->arguments[command->count] = NULL;
    return true;
}

static bool append_literals(struct git_command *command, const char *const *arguments,
                            struct failure *failure)
{
    for (size_t index = 0; arguments[index] != NULL; index++) {
        if (!append_argument(command, arguments[index], failure))
            return false;
    }
    return true;
}

static bool input_size_option(char output[OPTION_BYTES], const char *prefix,
                              uint64_t value, struct failure *failure)
{
    char reversed[20];
    size_t digits = 0;
    size_t prefix_bytes = strlen(prefix);
    do {
        reversed[digits++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    if (prefix_bytes + digits + 1 > OPTION_BYTES)
        return refuse(failure, PREPARATION, INTERNAL, 0);

    memcpy(output, prefix, prefix_bytes);
    for (size_t index = 0; index < digits; index++)
        output[prefix_bytes + index] = reversed[digits - index - 1];
    output[prefix_bytes + digits] = '\0';
    return true;
}

static const char *const common_arguments[] = {
    AOS_GIT_PROGRAM, "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--git-dir=.",
    "-c", "core.hooksPath=" AOS_GIT_EMPTY_HOOKS,
    "-c", "core.fsmonitor=false", "-c", "core.logAllRefUpdates=false",
    "-c", "pack.threads=1", "-c", "pack.writeReverseIndex=false",
    "-c", "maintenance.auto=false", "-c", "protocol.allow=never", NULL,
};

static const char *const receive_arguments[] = {
    "-c", "receive.autogc=false", "-c", "receive.updateServerInfo=false",
    "-c", "receive.unpackLimit=0", "-c", "receive.fsckObjects=true",
    "-c", "receive.advertiseAtomic=true", "-c", "receive.advertisePushOptions=false", NULL,
};

static const char *const common_environment[] = {
    "PATH=" AOS_GIT_EXEC_DIRECTORY, "GIT_EXEC_PATH=" AOS_GIT_EXEC_DIRECTORY,
    "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1",
    "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", NULL,
};

static const char *const upload_environment[] = {
    "PATH=" AOS_GIT_EXEC_DIRECTORY, "GIT_EXEC_PATH=" AOS_GIT_EXEC_DIRECTORY,
    "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1",
    "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_PROTOCOL=version=2", NULL,
};

static const char *const *fixed_environment(enum git_verb verb)
{
    return verb == UPLOAD || verb == ADVERTISE_UPLOAD ? upload_environment : common_environment;
}

static bool build_command(const struct plan *plan, const struct ancestor_input *ancestors,
                          struct git_command *command, struct failure *failure)
{
    memset(command, 0, sizeof(*command));
    if (!append_literals(command, common_arguments, failure))
        return false;

    switch (plan->verb) {
    case UPLOAD:
        return append_literals(command, (const char *const[]) {
            "upload-pack", "--strict", "--stateless-rpc", ".", NULL,
        }, failure);
    case RECEIVE:
    case ADVERTISE_RECEIVE:
        if (!append_literals(command, receive_arguments, failure))
            return false;
        if (plan->verb == RECEIVE &&
            (!input_size_option(command->input_option, "receive.maxInputSize=", plan->input_bytes, failure) ||
             !append_argument(command, "-c", failure) ||
             !append_argument(command, command->input_option, failure)))
            return false;
        if (!append_literals(command, (const char *const[]) {
            "receive-pack", "--stateless-rpc", NULL,
        }, failure))
            return false;
        if (plan->verb == ADVERTISE_RECEIVE && !append_argument(command, "--advertise-refs", failure))
            return false;
        return append_argument(command, ".", failure);
    case FSCK:
        return append_literals(command, (const char *const[]) {
            "fsck", "--full", "--strict", "--no-reflogs", NULL,
        }, failure);
    case ENUMERATE:
        return append_literals(command, (const char *const[]) {
            "cat-file", "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)", NULL,
        }, failure);
    case REFERENCES:
        return append_literals(command, (const char *const[]) {
            "for-each-ref", "--format=%(refname) %(objectname)", NULL,
        }, failure);
    case PACK:
        return append_literals(command, (const char *const[]) {
            "pack-objects", "--stdout", "--threads=1", "--no-reuse-delta", "--no-reuse-object", NULL,
        }, failure);
    case INDEX_PACK:
        if (!append_literals(command, (const char *const[]) {
            "index-pack", "--stdin", "--fix-thin", "--strict", "--fsck-objects",
            "--threads=1", "--no-rev-index", NULL,
        }, failure) ||
            !input_size_option(command->input_option, "--max-input-size=", plan->input_bytes, failure))
            return false;
        return append_argument(command, command->input_option, failure);
    case UPDATE_REFERENCES:
        return append_literals(command, (const char *const[]) {
            "update-ref", "--no-deref", "--stdin", NULL,
        }, failure);
    case INIT_BARE:
        return append_literals(command, (const char *const[]) {
            "init", "--bare", plan->format == 1 ? "--object-format=sha1" : "--object-format=sha256",
            "--ref-format=files", "--template=" AOS_GIT_EMPTY_TEMPLATE, ".", NULL,
        }, failure);
    case IS_ANCESTOR:
        command->ancestors = *ancestors;
        return append_literals(command, (const char *const[]) {
            "merge-base", "--is-ancestor", command->ancestors.first, command->ancestors.second, NULL,
        }, failure);
    case ADVERTISE_UPLOAD:
        return append_literals(command, (const char *const[]) {
            "upload-pack", "--strict", "--stateless-rpc", "--advertise-refs", ".", NULL,
        }, failure);
    }
    return refuse(failure, PREPARATION, MALFORMED, 0);
}

static void encode_failure(const struct failure *failure, uint8_t record[DENIAL_BYTES])
{
    memcpy(record, "AOSGHE01", 8);
    record[8] = (uint8_t)failure->stage;
    record[9] = (uint8_t)failure->reason;
    record[10] = 0;
    record[11] = 0;
    for (size_t index = 0; index < 4; index++)
        record[12 + index] = (uint8_t)(failure->original_errno >> (8 * (3 - index)));
}

#ifndef AOS_GIT_HELPER_PLAN_TEST

struct retained_images {
    int named_git;
    int directories[3];
    struct file_identity git;
    struct file_identity helper;
    struct file_identity repository;
    struct file_identity named;
    struct file_identity directory_identities[3];
    struct file_identity git_link;
};

static const char *const fixed_directories[] = {
    AOS_GIT_EXEC_DIRECTORY, AOS_GIT_EMPTY_HOOKS, AOS_GIT_EMPTY_TEMPLATE,
};

static bool original_syscall_failure(struct failure *failure, enum denial_stage stage)
{
    int original_errno = errno;
    return refuse(failure, stage,
                  original_errno == ENOSYS || original_errno == EOPNOTSUPP ? UNSUPPORTED : SYSTEM,
                  original_errno);
}

static bool observe_identity_at(int directory, const char *name, int flags,
                                struct file_identity *identity,
                                enum denial_stage stage, struct failure *failure)
{
    struct statx metadata;
    unsigned mask = STATX_BASIC_STATS | STATX_MNT_ID_UNIQUE;
    if (statx(directory, name, flags | AT_NO_AUTOMOUNT, mask, &metadata) < 0)
        return original_syscall_failure(failure, stage);
    if ((metadata.stx_mask & mask) != mask || metadata.stx_mnt_id == 0)
        return refuse(failure, stage, UNSUPPORTED, 0);

    *identity = (struct file_identity) {
        .device_major = metadata.stx_dev_major,
        .device_minor = metadata.stx_dev_minor,
        .inode = metadata.stx_ino,
        .size = metadata.stx_size,
        .mount_id = metadata.stx_mnt_id,
        .mode = metadata.stx_mode,
        .uid = metadata.stx_uid,
        .gid = metadata.stx_gid,
        .links = metadata.stx_nlink,
        .mtime_seconds = metadata.stx_mtime.tv_sec,
        .mtime_nanoseconds = metadata.stx_mtime.tv_nsec,
        .ctime_seconds = metadata.stx_ctime.tv_sec,
        .ctime_nanoseconds = metadata.stx_ctime.tv_nsec,
    };
    return true;
}

static bool observe_identity(int descriptor, struct file_identity *identity,
                             enum denial_stage stage, struct failure *failure)
{
    return observe_identity_at(descriptor, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                               identity, stage, failure);
}

static bool require_identity(int descriptor, const struct file_identity *expected,
                             enum denial_stage stage, struct failure *failure)
{
    struct file_identity observed;
    if (!observe_identity(descriptor, &observed, stage, failure))
        return false;
    if (!identities_equal(expected, &observed))
        return refuse(failure, stage, MISMATCH, 0);
    return true;
}

static bool require_readonly_access(int descriptor, enum denial_stage stage,
                                    struct failure *failure)
{
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0)
        return original_syscall_failure(failure, stage);
    if (!is_readonly_access_flags(flags))
        return refuse(failure, stage, UNEXPECTED_DESCRIPTOR, 0);
    return true;
}

static bool read_exact_at(int descriptor, uint8_t *output, size_t bytes, uint64_t start,
                          enum denial_stage stage, struct failure *failure)
{
    size_t offset = 0;
    while (offset < bytes) {
        ssize_t observed = pread(descriptor, output + offset, bytes - offset, (off_t)(start + offset));
        if (observed < 0) {
            if (errno == EINTR)
                continue;
            return original_syscall_failure(failure, stage);
        }
        if (observed == 0)
            return refuse(failure, stage, MISMATCH, 0);
        offset += (size_t)observed;
    }
    return true;
}

static bool require_sealed_input(int descriptor, uint64_t expected_size,
                                 enum denial_stage stage, struct failure *failure)
{
    struct file_identity identity;
    if (!observe_identity(descriptor, &identity, stage, failure) ||
        !require_readonly_access(descriptor, stage, failure))
        return false;
    if (!is_sealed_metadata(&identity, geteuid(), expected_size))
        return refuse(failure, stage, UNEXPECTED_DESCRIPTOR, 0);

    int seals = fcntl(descriptor, F_GET_SEALS);
    if (seals < 0)
        return original_syscall_failure(failure, stage);
    if (!has_full_seals(seals))
        return refuse(failure, stage, MISSING_SEALS, 0);

    off_t position = lseek(descriptor, 0, SEEK_CUR);
    if (position < 0)
        return original_syscall_failure(failure, stage);
    if (position != 0)
        return refuse(failure, stage, MISMATCH, 0);
    return true;
}

static bool require_restrictions(struct failure *failure)
{
    int no_new_privileges = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (no_new_privileges < 0)
        return original_syscall_failure(failure, RESTRICTION);
    if (no_new_privileges != 1 || getpgrp() != getpid())
        return refuse(failure, RESTRICTION, MISMATCH, 0);

    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct capabilities[2];
    if (syscall(SYS_capget, &header, capabilities) < 0)
        return original_syscall_failure(failure, RESTRICTION);
    for (size_t index = 0; index < 2; index++) {
        if (capabilities[index].effective != 0 || capabilities[index].permitted != 0 ||
            capabilities[index].inheritable != 0)
            return refuse(failure, RESTRICTION, MISMATCH, 0);
    }
    for (int capability = 0; capability <= CAP_LAST_CAP; capability++) {
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (ambient < 0)
            return original_syscall_failure(failure, RESTRICTION);
        if (ambient != 0)
            return refuse(failure, RESTRICTION, MISMATCH, 0);
    }

    if (geteuid() == 0) {
        int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        int required = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                       SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED;
        if (securebits < 0)
            return original_syscall_failure(failure, RESTRICTION);
        if (securebits != required)
            return refuse(failure, RESTRICTION, MISMATCH, 0);
    }
    return true;
}

static bool require_fixed_descriptors(struct retained_images *images, struct failure *failure)
{
    if (syscall(SYS_close_range, 7U, UINT_MAX, 0) < 0)
        return original_syscall_failure(failure, DESCRIPTORS);

    for (int descriptor = 1; descriptor <= 2; descriptor++) {
        struct stat metadata;
        int flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || fstat(descriptor, &metadata) < 0)
            return original_syscall_failure(failure, DESCRIPTORS);
        if (!S_ISFIFO(metadata.st_mode) || (flags & O_ACCMODE) != O_WRONLY)
            return refuse(failure, DESCRIPTORS, UNEXPECTED_DESCRIPTOR, 0);
    }
    for (int descriptor = 0; descriptor <= 6; descriptor++) {
        if (descriptor == 1 || descriptor == 2)
            continue;
        if (!require_readonly_access(descriptor, DESCRIPTORS, failure))
            return false;
        if (descriptor >= 3) {
            int flags = fcntl(descriptor, F_GETFD);
            if (flags < 0)
                return original_syscall_failure(failure, DESCRIPTORS);
            if (flags != 0)
                return refuse(failure, DESCRIPTORS, UNEXPECTED_DESCRIPTOR, 0);
        }
    }

    struct file_identity plan_identity;
    if (!observe_identity(3, &plan_identity, DESCRIPTORS, failure) ||
        !observe_identity(4, &images->repository, DESCRIPTORS, failure) ||
        !observe_identity(5, &images->git, DESCRIPTORS, failure) ||
        !observe_identity(6, &images->helper, DESCRIPTORS, failure))
        return false;
    if (!S_ISREG(plan_identity.mode) || plan_identity.uid != geteuid() || plan_identity.links != 0 ||
        !is_private_directory(&images->repository) || !is_image_metadata(&images->git) ||
        !is_image_metadata(&images->helper))
        return refuse(failure, DESCRIPTORS, UNEXPECTED_DESCRIPTOR, 0);
    return true;
}

static bool require_input(const struct plan *plan, struct ancestor_input *ancestors,
                          struct failure *failure)
{
    if (plan->input_bytes == 0) {
        struct stat metadata;
        if (fstat(0, &metadata) < 0)
            return original_syscall_failure(failure, INPUT);
        if (!S_ISCHR(metadata.st_mode) || major(metadata.st_rdev) != 1 || minor(metadata.st_rdev) != 3)
            return refuse(failure, INPUT, UNEXPECTED_DESCRIPTOR, 0);
    } else if (!require_sealed_input(0, plan->input_bytes, INPUT, failure)) {
        return false;
    }

    size_t width = plan->format == 1 ? 40 : 64;
    if (!input_length_allowed(plan->verb, plan->input_bytes, plan->format))
        return refuse(failure, INPUT, MALFORMED, 0);
    switch (plan->verb) {
    case UPLOAD:
    case RECEIVE:
    case UPDATE_REFERENCES:
        return true;
    case FSCK:
    case ENUMERATE:
    case REFERENCES:
    case INIT_BARE:
    case ADVERTISE_UPLOAD:
    case ADVERTISE_RECEIVE:
        return true;
    case PACK: {
        struct oid_lines lines = { .width = width, .limit = plan->object_limit };
        uint8_t bytes[4096];
        uint64_t offset = 0;
        while (offset < plan->input_bytes) {
            uint64_t remaining = plan->input_bytes - offset;
            size_t length = remaining < sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
            if (!read_exact_at(0, bytes, length, offset, INPUT, failure) ||
                !admit_oid_bytes(&lines, bytes, length, failure))
                return false;
            offset += length;
        }
        return lines.used == 0 || refuse(failure, INPUT, MALFORMED, 0);
    }
    case INDEX_PACK: {
        uint8_t bytes[12];
        if (plan->input_bytes < sizeof(bytes))
            return refuse(failure, INPUT, MALFORMED, 0);
        return read_exact_at(0, bytes, sizeof(bytes), 0, INPUT, failure) &&
               admit_pack_header(bytes, sizeof(bytes), plan->object_limit, failure);
    }
    case IS_ANCESTOR: {
        uint8_t bytes[2 * OID_BYTES];
        size_t length = 2 * (width + 1);
        if (plan->input_bytes != length)
            return refuse(failure, INPUT, MALFORMED, 0);
        return read_exact_at(0, bytes, length, 0, INPUT, failure) &&
               admit_ancestors(bytes, length, width, ancestors, failure);
    }
    }
    return refuse(failure, INPUT, MALFORMED, 0);
}

static bool require_readonly_backing(int descriptor, enum denial_stage stage,
                                     struct failure *failure)
{
    struct statvfs filesystem;
    if (fstatvfs(descriptor, &filesystem) < 0)
        return original_syscall_failure(failure, stage);
    if ((filesystem.f_flag & ST_RDONLY) == 0)
        return refuse(failure, stage, MISMATCH, 0);
    return true;
}

static int open_fixed_name(const char *name, bool directory,
                           enum denial_stage stage, struct failure *failure)
{
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (directory ? O_DIRECTORY : 0),
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    int descriptor = (int)syscall(SYS_openat2, AT_FDCWD, name, &how, sizeof(how));
    if (descriptor < 0)
        original_syscall_failure(failure, stage);
    return descriptor;
}

static bool require_image(int descriptor, const uint8_t expected[DIGEST_BYTES],
                          enum denial_stage stage, struct failure *failure)
{
    struct {
        struct fsverity_digest header;
        uint8_t digest[DIGEST_BYTES];
    } measurement = { .header.digest_size = DIGEST_BYTES };
    uint8_t elf_magic[SELFMAG];

    if (!require_readonly_backing(descriptor, stage, failure) ||
        !read_exact_at(descriptor, elf_magic, sizeof(elf_magic), 0, stage, failure))
        return false;
    if (memcmp(elf_magic, ELFMAG, SELFMAG) != 0)
        return refuse(failure, stage, MISMATCH, 0);
    if (ioctl(descriptor, FS_IOC_MEASURE_VERITY, &measurement) < 0)
        return original_syscall_failure(failure, stage);
    if (measurement.header.digest_algorithm != FS_VERITY_HASH_ALG_SHA256 ||
        measurement.header.digest_size != DIGEST_BYTES ||
        memcmp(measurement.digest, expected, DIGEST_BYTES) != 0)
        return refuse(failure, stage, MISMATCH, 0);
    return true;
}

static bool require_directory_entries(int descriptor, bool git_entry,
                                      enum denial_stage stage, struct failure *failure)
{
    int enumeration = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (enumeration < 0)
        return original_syscall_failure(failure, stage);
    DIR *directory = fdopendir(enumeration);
    if (directory == NULL) {
        int original_errno = errno;
        close(enumeration);
        return refuse(failure, stage, SYSTEM, original_errno);
    }

    size_t count = 0;
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                valid = original_syscall_failure(failure, stage);
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!git_entry || count != 0 || strcmp(entry->d_name, "git") != 0) {
            valid = refuse(failure, stage, MISMATCH, 0);
            break;
        }
        count++;
    }
    if (valid && count != (git_entry ? 1U : 0U))
        valid = refuse(failure, stage, MISMATCH, 0);
    if (closedir(directory) < 0)
        valid = original_syscall_failure(failure, stage);
    return valid;
}

static bool observe_git_link(int directory, struct file_identity *identity,
                             enum denial_stage stage, struct failure *failure)
{
    char target[4096];
    if (!observe_identity_at(directory, "git", AT_SYMLINK_NOFOLLOW, identity, stage, failure))
        return false;
    if (!S_ISLNK(identity->mode) || identity->uid != 0 || identity->links != 1)
        return refuse(failure, stage, MISMATCH, 0);

    ssize_t bytes = readlinkat(directory, "git", target, sizeof(target));
    if (bytes < 0)
        return original_syscall_failure(failure, stage);
    size_t expected_bytes = sizeof(AOS_GIT_PROGRAM) - 1;
    if ((size_t)bytes != expected_bytes || memcmp(target, AOS_GIT_PROGRAM, expected_bytes) != 0)
        return refuse(failure, stage, MISMATCH, 0);
    return true;
}

static bool retain_images(const struct plan *plan, struct retained_images *images,
                          struct failure *failure)
{
    if (!require_image(5, plan->git_digest, IMAGES, failure) ||
        !require_image(6, plan->helper_digest, IMAGES, failure))
        return false;
    images->named_git = open_fixed_name(AOS_GIT_PROGRAM, false, IMAGES, failure);
    if (images->named_git < 0 ||
        !observe_identity(images->named_git, &images->named, IMAGES, failure))
        return false;
    if (!identities_equal(&images->git, &images->named))
        return refuse(failure, IMAGES, MISMATCH, 0);
    if (!require_image(images->named_git, plan->git_digest, IMAGES, failure))
        return false;

    for (size_t index = 0; index < 3; index++) {
        images->directories[index] = open_fixed_name(fixed_directories[index], true, IMAGES, failure);
        if (images->directories[index] < 0 ||
            !observe_identity(images->directories[index], &images->directory_identities[index], IMAGES, failure))
            return false;
        const struct file_identity *identity = &images->directory_identities[index];
        if (!S_ISDIR(identity->mode) || identity->uid != 0 || (identity->mode & 0222) != 0)
            return refuse(failure, IMAGES, MISMATCH, 0);
        if (!require_readonly_backing(images->directories[index], IMAGES, failure) ||
            !require_directory_entries(images->directories[index], index == 0, IMAGES, failure))
            return false;
    }
    return observe_git_link(images->directories[0], &images->git_link, IMAGES, failure);
}

static bool reduce_limit(int resource, rlim_t ceiling, struct failure *failure)
{
    struct rlimit limits;
    if (getrlimit(resource, &limits) < 0)
        return original_syscall_failure(failure, BUDGET);
    if (limits.rlim_max != RLIM_INFINITY && limits.rlim_max < ceiling)
        ceiling = limits.rlim_max;
    limits.rlim_cur = ceiling;
    limits.rlim_max = ceiling;
    if (setrlimit(resource, &limits) < 0)
        return original_syscall_failure(failure, BUDGET);
    return true;
}

static bool apply_limits(const struct plan *plan, struct failure *failure)
{
    if (!reduce_limit(RLIMIT_CORE, 0, failure) ||
        !reduce_limit(RLIMIT_FSIZE, (rlim_t)plan->expanded_bytes, failure) ||
        !reduce_limit(RLIMIT_CPU, (rlim_t)(plan->seconds + 1), failure))
        return false;

    /* Git resets its own alarm. The original parent remains the only deadline. */
    struct sigaction disposition = { .sa_handler = SIG_DFL };
    sigset_t alarm_signal;
    if (sigemptyset(&disposition.sa_mask) < 0 || sigemptyset(&alarm_signal) < 0 ||
        sigaddset(&alarm_signal, SIGALRM) < 0 || sigaction(SIGALRM, &disposition, NULL) < 0 ||
        sigprocmask(SIG_UNBLOCK, &alarm_signal, NULL) < 0)
        return original_syscall_failure(failure, BUDGET);
    umask(0077);
    return true;
}

static bool close_roles_on_exec(struct failure *failure)
{
    for (int descriptor = 3; descriptor <= 6; descriptor++) {
        if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0)
            return original_syscall_failure(failure, BUDGET);
    }
    return true;
}

static bool recheck_fixed_name(const char *name, bool directory,
                               const struct file_identity *expected, struct failure *failure)
{
    int descriptor = open_fixed_name(name, directory, BOOKENDS, failure);
    if (descriptor < 0)
        return false;
    bool valid = require_identity(descriptor, expected, BOOKENDS, failure) &&
                 require_readonly_backing(descriptor, BOOKENDS, failure);
    if (close(descriptor) < 0)
        valid = original_syscall_failure(failure, BOOKENDS);
    return valid;
}

static bool recheck_images(const struct plan *plan, const struct retained_images *images,
                           struct failure *failure)
{
    if (!require_identity(5, &images->git, BOOKENDS, failure) ||
        !require_identity(6, &images->helper, BOOKENDS, failure) ||
        !require_identity(4, &images->repository, BOOKENDS, failure) ||
        !require_identity(images->named_git, &images->named, BOOKENDS, failure) ||
        !require_image(5, plan->git_digest, BOOKENDS, failure) ||
        !require_image(6, plan->helper_digest, BOOKENDS, failure) ||
        !require_image(images->named_git, plan->git_digest, BOOKENDS, failure) ||
        !recheck_fixed_name(AOS_GIT_PROGRAM, false, &images->git, failure))
        return false;

    for (size_t index = 0; index < 3; index++) {
        if (!require_identity(images->directories[index], &images->directory_identities[index], BOOKENDS, failure) ||
            !require_readonly_backing(images->directories[index], BOOKENDS, failure) ||
            !require_directory_entries(images->directories[index], index == 0, BOOKENDS, failure) ||
            !recheck_fixed_name(fixed_directories[index], true, &images->directory_identities[index], failure))
            return false;
    }
    struct file_identity link;
    if (!observe_git_link(images->directories[0], &link, BOOKENDS, failure))
        return false;
    if (!identities_equal(&images->git_link, &link))
        return refuse(failure, BOOKENDS, MISMATCH, 0);

    struct file_identity working_directory;
    if (!observe_identity_at(AT_FDCWD, ".", AT_SYMLINK_NOFOLLOW, &working_directory, BOOKENDS, failure))
        return false;
    if (!identities_equal(&images->repository, &working_directory))
        return refuse(failure, BOOKENDS, MISMATCH, 0);
    return require_sealed_input(3, PLAN_BYTES, BOOKENDS, failure) &&
           (plan->input_bytes == 0 || require_sealed_input(0, plan->input_bytes, BOOKENDS, failure));
}

static void close_readback(struct retained_images *images)
{
    if (images->named_git >= 0)
        close(images->named_git);
    for (size_t index = 0; index < 3; index++) {
        if (images->directories[index] >= 0)
            close(images->directories[index]);
    }
}

static int report_denial(const struct failure *failure)
{
    uint8_t record[DENIAL_BYTES];
    encode_failure(failure, record);
    size_t written = 0;
    while (written < sizeof(record)) {
        ssize_t result = write(2, record + written, sizeof(record) - written);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            break;
        written += (size_t)result;
    }
    return failure->stage == EXEC ? 127 : 126;
}

int main(int argc, char **argv, char **environment)
{
    struct failure failure = {0};
    struct plan plan;
    struct ancestor_input ancestors = {0};
    struct git_command command;
    struct retained_images images = { .named_git = -1, .directories = {-1, -1, -1} };
    uint8_t bytes[PLAN_BYTES];

    if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL ||
        strcmp(argv[0], AOS_GIT_HELPER_PROGRAM) != 0 ||
        environment == NULL || environment[0] != NULL) {
        refuse(&failure, STARTUP, MALFORMED, 0);
        goto denied;
    }
    if (!require_restrictions(&failure) || !require_fixed_descriptors(&images, &failure) ||
        !require_sealed_input(3, PLAN_BYTES, PLAN, &failure) ||
        !read_exact_at(3, bytes, sizeof(bytes), 0, PLAN, &failure) ||
        !decode_plan(bytes, sizeof(bytes), &plan, &failure) ||
        !require_input(&plan, &ancestors, &failure) || !retain_images(&plan, &images, &failure))
        goto denied;

    if (plan.verb == INIT_BARE && !require_directory_entries(4, false, PREPARATION, &failure))
        goto denied;
    if (fchdir(4) < 0) {
        original_syscall_failure(&failure, PREPARATION);
        goto denied;
    }
    if (!build_command(&plan, &ancestors, &command, &failure) ||
        !apply_limits(&plan, &failure) || !close_roles_on_exec(&failure) ||
        !recheck_images(&plan, &images, &failure))
        goto denied;

    /* Same PID, original pidfd/reaper/cgroup. CLOEXEC closes only after exec. */
    execveat(5, "", (char *const *)command.arguments,
             (char *const *)fixed_environment(plan.verb), AT_EMPTY_PATH);
    original_syscall_failure(&failure, EXEC);

denied:
    close_readback(&images);
    return report_denial(&failure);
}

#endif

#ifdef AOS_GIT_HELPER_PLAN_TEST

/* This main is compiled into a separate, uninstalled pure DATA test binary. */
static unsigned failed_checks;

static void check(bool condition, const char *case_name)
{
    if (!condition) {
        fprintf(stderr, "Git helper pure DATA check failed: %s\n", case_name);
        failed_checks++;
    }
}

static void put_big_endian(uint8_t *bytes, uint64_t value)
{
    for (size_t index = 0; index < 8; index++)
        bytes[index] = (uint8_t)(value >> (8 * (7 - index)));
}

static void golden_plan(uint8_t bytes[PLAN_BYTES])
{
    memset(bytes, 0, PLAN_BYTES);
    memcpy(bytes, "AOSGHP01", 8);
    bytes[8] = UPLOAD;
    bytes[9] = 1;
    put_big_endian(bytes + 16, 4096);
    put_big_endian(bytes + 24, 65536);
    put_big_endian(bytes + 32, 1048576);
    put_big_endian(bytes + 40, 8);
    put_big_endian(bytes + 48, 3);
    memset(bytes + 56, 0x11, DIGEST_BYTES);
    memset(bytes + 88, 0x22, DIGEST_BYTES);
}

static void test_exact_plan_and_denials(void)
{
    uint8_t bytes[PLAN_BYTES];
    struct plan plan;
    struct failure failure = {0};
    golden_plan(bytes);

    check(decode_plan(bytes, sizeof(bytes), &plan, &failure), "golden plan decodes");
    check(plan.input_bytes == 4096 && plan.output_bytes == 65536 &&
          plan.expanded_bytes == 1048576 && plan.object_limit == 8 && plan.seconds == 3 &&
          plan.git_digest[0] == 0x11 && plan.helper_digest[31] == 0x22,
          "all golden offsets are exact big-endian DATA");

    const size_t malformed_offsets[] = {0, 8, 9, 10, 15};
    for (size_t index = 0; index < sizeof(malformed_offsets) / sizeof(malformed_offsets[0]); index++) {
        golden_plan(bytes);
        bytes[malformed_offsets[index]] = 0xff;
        failure = (struct failure){0};
        check(!decode_plan(bytes, sizeof(bytes), &plan, &failure) &&
              failure.stage == PLAN && failure.reason == MALFORMED, "malformed plan field rejects");
    }
    failure = (struct failure){0};
    check(!decode_plan(bytes, PLAN_BYTES - 1, &plan, &failure), "short plan rejects before read");

    const struct { size_t offset; uint64_t value; } invalid_limits[] = {
        {16, UINT64_C(268435457)}, {24, 0}, {24, UINT64_C(268435457)},
        {32, 0}, {32, UINT64_MAX}, {40, 0}, {40, UINT64_C(262145)}, {48, 0}, {48, 301},
    };
    for (size_t index = 0; index < sizeof(invalid_limits) / sizeof(invalid_limits[0]); index++) {
        golden_plan(bytes);
        put_big_endian(bytes + invalid_limits[index].offset, invalid_limits[index].value);
        failure = (struct failure){0};
        check(!decode_plan(bytes, sizeof(bytes), &plan, &failure) &&
              failure.reason == LIMIT, "nonfinite or excessive plan budget rejects");
    }
    for (size_t offset = 56; offset <= 88; offset += DIGEST_BYTES) {
        golden_plan(bytes);
        memset(bytes + offset, 0, DIGEST_BYTES);
        failure = (struct failure){0};
        check(!decode_plan(bytes, sizeof(bytes), &plan, &failure) &&
              failure.reason == MISMATCH, "zero image digest rejects");
    }
}

static void test_all_closed_arguments_and_environment(void)
{
    const char *const expected_common[] = {
        AOS_GIT_PROGRAM, "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--git-dir=.",
        "-c", "core.hooksPath=" AOS_GIT_EMPTY_HOOKS,
        "-c", "core.fsmonitor=false", "-c", "core.logAllRefUpdates=false",
        "-c", "pack.threads=1", "-c", "pack.writeReverseIndex=false",
        "-c", "maintenance.auto=false", "-c", "protocol.allow=never",
    };
    const struct {
        enum git_verb verb;
        unsigned format;
        const char *tail[24];
    } cases[] = {
        {UPLOAD, 1, {"upload-pack", "--strict", "--stateless-rpc", ".", NULL}},
        {RECEIVE, 1, {"-c", "receive.autogc=false", "-c", "receive.updateServerInfo=false",
                     "-c", "receive.unpackLimit=0", "-c", "receive.fsckObjects=true",
                     "-c", "receive.advertiseAtomic=true", "-c", "receive.advertisePushOptions=false",
                     "-c", "receive.maxInputSize=4096", "receive-pack", "--stateless-rpc", ".", NULL}},
        {FSCK, 1, {"fsck", "--full", "--strict", "--no-reflogs", NULL}},
        {ENUMERATE, 1, {"cat-file", "--batch-all-objects",
                       "--batch-check=%(objectname) %(objecttype) %(objectsize)", NULL}},
        {REFERENCES, 1, {"for-each-ref", "--format=%(refname) %(objectname)", NULL}},
        {PACK, 1, {"pack-objects", "--stdout", "--threads=1", "--no-reuse-delta", "--no-reuse-object", NULL}},
        {INDEX_PACK, 1, {"index-pack", "--stdin", "--fix-thin", "--strict", "--fsck-objects",
                        "--threads=1", "--no-rev-index", "--max-input-size=4096", NULL}},
        {UPDATE_REFERENCES, 1, {"update-ref", "--no-deref", "--stdin", NULL}},
        {INIT_BARE, 1, {"init", "--bare", "--object-format=sha1", "--ref-format=files",
                       "--template=" AOS_GIT_EMPTY_TEMPLATE, ".", NULL}},
        {INIT_BARE, 2, {"init", "--bare", "--object-format=sha256", "--ref-format=files",
                       "--template=" AOS_GIT_EMPTY_TEMPLATE, ".", NULL}},
        {IS_ANCESTOR, 1, {"merge-base", "--is-ancestor", "aa", "bb", NULL}},
        {ADVERTISE_UPLOAD, 1, {"upload-pack", "--strict", "--stateless-rpc", "--advertise-refs", ".", NULL}},
        {ADVERTISE_RECEIVE, 1, {"-c", "receive.autogc=false", "-c", "receive.updateServerInfo=false",
                               "-c", "receive.unpackLimit=0", "-c", "receive.fsckObjects=true",
                               "-c", "receive.advertiseAtomic=true", "-c", "receive.advertisePushOptions=false",
                               "receive-pack", "--stateless-rpc", "--advertise-refs", ".", NULL}},
    };
    const char *const expected_environment[] = {
        "PATH=" AOS_GIT_EXEC_DIRECTORY, "GIT_EXEC_PATH=" AOS_GIT_EXEC_DIRECTORY,
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1",
        "GIT_NO_LAZY_FETCH=1", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        struct plan plan = { .verb = cases[index].verb, .format = cases[index].format, .input_bytes = 4096 };
        struct ancestor_input ancestors = { .first = "aa", .second = "bb" };
        struct git_command command;
        struct failure failure = {0};
        bool built = build_command(&plan, &ancestors, &command, &failure);
        check(built, "each closed verb builds");
        if (!built)
            continue;

        size_t position = 0;
        for (size_t argument = 0; argument < sizeof(expected_common) / sizeof(expected_common[0]); argument++)
            check(strcmp(command.arguments[position++], expected_common[argument]) == 0, "exact common argv");
        for (size_t argument = 0; cases[index].tail[argument] != NULL; argument++)
            check(strcmp(command.arguments[position++], cases[index].tail[argument]) == 0, "exact verb argv");
        check(position == command.count && command.arguments[position] == NULL, "exact bounded argv terminator");

        const char *const *environment = fixed_environment(plan.verb);
        for (size_t entry = 0; entry < 8; entry++)
            check(strcmp(environment[entry], expected_environment[entry]) == 0, "exact common environment");
        if (plan.verb == UPLOAD || plan.verb == ADVERTISE_UPLOAD)
            check(strcmp(environment[8], "GIT_PROTOCOL=version=2") == 0 && environment[9] == NULL,
                  "only upload receives protocol2");
        else
            check(environment[8] == NULL, "non-upload environment ends at eight entries");
    }
}

static void test_readonly_access_flags(void)
{
    const int readable_flags[] = {
        O_RDONLY, O_RDONLY | O_DIRECTORY, O_RDONLY | O_NONBLOCK,
    };
    const int denied_flags[] = {
        O_PATH, O_PATH | O_DIRECTORY, O_PATH | O_NOFOLLOW, O_RDWR, O_WRONLY,
    };

    for (size_t index = 0; index < sizeof(readable_flags) / sizeof(readable_flags[0]); index++)
        check(is_readonly_access_flags(readable_flags[index]), "ordinary readonly flags admit");

    for (size_t index = 0; index < sizeof(denied_flags) / sizeof(denied_flags[0]); index++)
        check(!is_readonly_access_flags(denied_flags[index]), "path-only or writable flags deny");
}

static void test_metadata_and_full_identity(void)
{
    struct file_identity image = {
        .device_major = 1, .device_minor = 2, .inode = 3, .size = 4, .mount_id = 5,
        .mode = S_IFREG | 0555, .uid = 0, .gid = 7, .links = 1,
        .mtime_seconds = 8, .mtime_nanoseconds = 9, .ctime_seconds = 10, .ctime_nanoseconds = 11,
    };
    check(is_image_metadata(&image), "projected immutable image metadata");
    check(identities_equal(&image, &image), "same full identity DATA");

    for (size_t field = 0; field < 13; field++) {
        struct file_identity changed = image;
        switch (field) {
        case 0: changed.device_major++; break;
        case 1: changed.device_minor++; break;
        case 2: changed.inode++; break;
        case 3: changed.size++; break;
        case 4: changed.mount_id++; break;
        case 5: changed.mode++; break;
        case 6: changed.uid++; break;
        case 7: changed.gid++; break;
        case 8: changed.links++; break;
        case 9: changed.mtime_seconds++; break;
        case 10: changed.mtime_nanoseconds++; break;
        case 11: changed.ctime_seconds++; break;
        case 12: changed.ctime_nanoseconds++; break;
        }
        check(!identities_equal(&image, &changed), "every full identity field participates");
    }

    struct file_identity input = { .mode = S_IFREG | 0600, .uid = 81, .links = 0, .size = PLAN_BYTES };
    check(is_sealed_metadata(&input, 81, PLAN_BYTES), "projected sealed anonymous metadata");
    check(!is_sealed_metadata(&input, 82, PLAN_BYTES) && !is_sealed_metadata(&input, 81, PLAN_BYTES + 1),
          "wrong sealed owner or width denies");
    input.links = 1;
    check(!is_sealed_metadata(&input, 81, PLAN_BYTES), "named inode is not sealed anonymous input");
    struct file_identity directory = { .mode = S_IFDIR | 0700, .uid = 0 };
    check(is_private_directory(&directory), "projected private directory metadata");
    directory.mode |= 0020;
    check(!is_private_directory(&directory), "nonprivate directory metadata denies");

    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    check(has_full_seals(seals), "all four seals required");
    check(!has_full_seals((seals & ~F_SEAL_WRITE) | F_SEAL_FUTURE_WRITE) && !has_full_seals(-1),
          "future-write or failed seal read does not substitute");
}

static void test_bounded_input_shapes(void)
{
    for (enum git_verb verb = UPLOAD; verb <= ADVERTISE_RECEIVE; verb++) {
        bool requires_zero = verb == FSCK || verb == ENUMERATE || verb == REFERENCES ||
                             verb == INIT_BARE || verb == ADVERTISE_UPLOAD || verb == ADVERTISE_RECEIVE;
        check(input_length_allowed(verb, 0, 1) == (requires_zero || verb == PACK), "zero input policy");
        check(input_length_allowed(verb, 1, 1) ==
              (verb == UPLOAD || verb == RECEIVE || verb == UPDATE_REFERENCES || verb == PACK), "nonempty input policy");
    }

    uint8_t objects[82];
    memset(objects, 'a', 40);
    objects[40] = '\n';
    memset(objects + 41, 'b', 40);
    objects[81] = '\n';
    struct oid_lines lines = { .width = 40, .limit = 2 };
    struct failure failure = {0};
    check(admit_oid_bytes(&lines, objects, 17, &failure) &&
          admit_oid_bytes(&lines, objects + 17, sizeof(objects) - 17, &failure) &&
          lines.count == 2 && lines.used == 0, "bounded sorted OIDs across chunk boundary");
    lines = (struct oid_lines){ .width = 40, .limit = 2 };
    failure = (struct failure){0};
    memset(objects + 41, 'a', 40);
    check(!admit_oid_bytes(&lines, objects, sizeof(objects), &failure), "duplicate pack OID denies");

    uint8_t pack_header[12] = {'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 8};
    failure = (struct failure){0};
    check(admit_pack_header(pack_header, sizeof(pack_header), 8, &failure), "PACK2 bounded header DATA");
    pack_header[7] = 3;
    check(admit_pack_header(pack_header, sizeof(pack_header), 8, &failure), "PACK3 bounded header DATA");
    failure = (struct failure){0};
    pack_header[11] = 9;
    check(!admit_pack_header(pack_header, sizeof(pack_header), 8, &failure), "PACK object ceiling denies");

    for (size_t width = 40; width <= 64; width += 24) {
        uint8_t bytes[2 * OID_BYTES];
        memset(bytes, 'a', width);
        bytes[width] = '\n';
        memset(bytes + width + 1, 'b', width);
        bytes[2 * width + 1] = '\n';
        struct ancestor_input ancestors;
        failure = (struct failure){0};
        check(admit_ancestors(bytes, 2 * (width + 1), width, &ancestors, &failure) &&
              strlen(ancestors.first) == width && strlen(ancestors.second) == width, "exact ancestor OID widths");
        bytes[0] = '-';
        failure = (struct failure){0};
        check(!admit_ancestors(bytes, 2 * (width + 1), width, &ancestors, &failure), "ancestor option syntax denies");
    }
}

static void test_first_failure_and_redacted_record(void)
{
    struct failure failure = {0};
    refuse(&failure, PLAN, LIMIT, EINVAL);
    refuse(&failure, EXEC, SYSTEM, EIO);
    uint8_t record[DENIAL_BYTES];
    encode_failure(&failure, record);

    check(memcmp(record, "AOSGHE01", 8) == 0 && record[8] == PLAN && record[9] == LIMIT &&
          record[10] == 0 && record[11] == 0 && read_big_endian(record + 12, 4) == EINVAL,
          "first typed failure retains original errno in exact sixteen-byte DATA");
}

int main(void)
{
    test_exact_plan_and_denials();
    test_all_closed_arguments_and_environment();
    test_readonly_access_flags();
    test_metadata_and_full_identity();
    test_bounded_input_shapes();
    test_first_failure_and_redacted_record();

    if (failed_checks != 0)
        return 1;
    puts("Git helper pure DATA tests passed");
    return 0;
}

#endif
