#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PROBE_DIRECTORY "/var/lib/aos/sandbox-storage"
#define PROBE_NAME "seccomp-probe"
#define PROBE_PATH PROBE_DIRECTORY "/" PROBE_NAME
#define BOOT_ID_DIRECTORY "/proc/sys/kernel/random"
#define BOOT_ID_NAME "boot_id"
#define BOOT_ID_TEXT_BYTES 36
#define BOOT_ID_MAXIMUM_BYTES (BOOT_ID_TEXT_BYTES + 1)
#define SETID_MODE 04755
#define SETID_PROBE_NAME "seccomp-probe-setid-attempt"

#ifndef PR_GET_AOS_NO_SETID
#define PR_GET_AOS_NO_SETID 83
#endif

#ifndef __NR_openat2
#error "missing openat2 syscall number in Linux headers"
#endif

#ifndef __NR_fchmod
#error "missing fchmod syscall number in Linux headers"
#endif

#ifndef __NR_fchmodat
#error "missing fchmodat syscall number in Linux headers"
#endif

#ifndef __NR_fchmodat2
#error "missing fchmodat2 syscall number in Linux headers"
#endif

#if !defined(__NR_io_uring_setup) || !defined(__NR_io_uring_enter) \
    || !defined(__NR_io_uring_register)
#error "missing io_uring syscall numbers in Linux headers"
#endif

static int verify_fixture(int descriptor)
{
    struct stat metadata;

    if (fstat(descriptor, &metadata) != 0) {
        perror("stat seccomp probe fixture");
        return -1;
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != 0
        || metadata.st_gid != 0 || (metadata.st_mode & 07777) != 0600) {
        fprintf(stderr,
            "seccomp probe fixture is not a root-owned regular mode-0600 file\n");
        return -1;
    }

    return 0;
}

static int expect_denied(const char *operation, long result)
{
    if (result == -1 && errno == EPERM)
        return 0;

    fprintf(stderr, "%s was not rejected with EPERM: %s\n", operation,
        result == -1 ? strerror(errno) : "operation succeeded");
    return -1;
}

static int verify_denial_preserved_mode(int descriptor, const char *operation)
{
    if (verify_fixture(descriptor) != 0) {
        fprintf(stderr, "%s changed the protected fixture\n", operation);
        return -1;
    }

    return 0;
}

static bool is_lowercase_hex(char byte)
{
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
}

static int verify_canonical_boot_id(const char *bytes, ssize_t length)
{
    size_t index;
    bool nonzero = false;

    if (length == BOOT_ID_MAXIMUM_BYTES && bytes[BOOT_ID_TEXT_BYTES] == '\n')
        length--;
    if (length != BOOT_ID_TEXT_BYTES) {
        fprintf(stderr, "kernel boot ID has a noncanonical length\n");
        return -1;
    }

    for (index = 0; index < BOOT_ID_TEXT_BYTES; index++) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (bytes[index] != '-') {
                fprintf(stderr, "kernel boot ID has noncanonical separators\n");
                return -1;
            }
            continue;
        }
        if (!is_lowercase_hex(bytes[index])) {
            fprintf(stderr, "kernel boot ID is not lowercase hexadecimal\n");
            return -1;
        }
        nonzero = nonzero || bytes[index] != '0';
    }
    if (!nonzero) {
        fprintf(stderr, "kernel boot ID is nil\n");
        return -1;
    }

    return 0;
}

static int probe_boot_id(void)
{
    const struct open_how read_only = {
        .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    const struct open_how write_only = {
        .flags = O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    struct stat metadata;
    struct statfs filesystem;
    struct statvfs mount;
    char bytes[BOOT_ID_MAXIMUM_BYTES + 1];
    ssize_t length;
    int close_error;
    int directory;
    int descriptor;
    int writable;

    directory = open(BOOT_ID_DIRECTORY,
        O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        perror("open procfs root");
        return -1;
    }
    descriptor = syscall(__NR_openat2, directory, BOOT_ID_NAME, &read_only,
        sizeof(read_only));
    if (descriptor < 0) {
        perror("strict read-only openat2 kernel boot ID");
        close(directory);
        return -1;
    }

    if (fstat(descriptor, &metadata) != 0) {
        perror("stat kernel boot ID");
        close(descriptor);
        close(directory);
        return -1;
    }
    if (!S_ISREG(metadata.st_mode)) {
        fprintf(stderr, "kernel boot ID is not a regular file\n");
        close(descriptor);
        close(directory);
        return -1;
    }
    if (fstatfs(descriptor, &filesystem) != 0
        || filesystem.f_type != PROC_SUPER_MAGIC) {
        fprintf(stderr, "kernel boot ID is not backed by procfs\n");
        close(descriptor);
        close(directory);
        return -1;
    }
    if (fstatvfs(descriptor, &mount) != 0 || !(mount.f_flag & ST_RDONLY)) {
        fprintf(stderr, "kernel boot ID mount is not read-only\n");
        close(descriptor);
        close(directory);
        return -1;
    }

    length = read(descriptor, bytes, sizeof(bytes));
    if (length < 0) {
        perror("read kernel boot ID");
        close(descriptor);
        close(directory);
        return -1;
    }
    if (length > BOOT_ID_MAXIMUM_BYTES
        || verify_canonical_boot_id(bytes, length) != 0) {
        close(descriptor);
        close(directory);
        return -1;
    }

    errno = 0;
    writable = syscall(__NR_openat2, directory, BOOT_ID_NAME, &write_only,
        sizeof(write_only));
    if (writable >= 0) {
        fprintf(stderr, "kernel boot ID unexpectedly opened writable\n");
        close(writable);
        close(descriptor);
        close(directory);
        return -1;
    }
    if (errno != EROFS && errno != EACCES && errno != EPERM) {
        fprintf(stderr, "kernel boot ID writable open failed unexpectedly: %s\n",
            strerror(errno));
        close(descriptor);
        close(directory);
        return -1;
    }

    close_error = 0;
    if (close(descriptor) != 0) {
        perror("close kernel boot ID file descriptor");
        close_error = -1;
    }
    if (close(directory) != 0) {
        perror("close kernel boot ID directory descriptor");
        close_error = -1;
    }
    if (close_error != 0)
        return -1;

    return 0;
}

static int probe_chmod(int descriptor)
{
#ifdef __NR_chmod
    errno = 0;
    if (expect_denied("chmod",
            syscall(__NR_chmod, PROBE_PATH, SETID_MODE)) != 0
        || verify_denial_preserved_mode(descriptor, "chmod") != 0) {
        return -1;
    }
#else
    fprintf(stderr,
        "AOS_STORAGE_BROKER_SECCOMP_PROBE_NOTE chmod-syscall-unavailable\n");
#endif

    return 0;
}

int main(int argc, char **argv)
{
    const struct open_how read_only = {
        .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    const struct open_how setid_create = {
        .flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        .mode = SETID_MODE,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    int directory;
    int descriptor;

    if (argc != 1) {
        fprintf(stderr, "usage: storage-broker-seccomp-probe\n");
        return 64;
    }
    (void)argv;

    if (prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL) != 1) {
        fprintf(stderr, "Storage broker did not inherit the no-setid guard\n");
        return 1;
    }

    errno = 0;
    if (expect_denied("io_uring_setup",
            syscall(__NR_io_uring_setup, 0, NULL)) != 0)
        return 1;
    errno = 0;
    if (expect_denied("io_uring_enter",
            syscall(__NR_io_uring_enter, -1, 0, 0, 0, NULL, 0)) != 0)
        return 1;
    errno = 0;
    if (expect_denied("io_uring_register",
            syscall(__NR_io_uring_register, -1, 0, NULL, 0)) != 0)
        return 1;

    if (probe_boot_id() != 0)
        return 1;

    directory = open(PROBE_DIRECTORY,
        O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        perror("open seccomp probe directory");
        return 1;
    }

    errno = 0;
    if (expect_denied("openat2 setid creation",
            syscall(__NR_openat2, directory, SETID_PROBE_NAME,
                &setid_create, sizeof(setid_create))) != 0) {
        close(directory);
        return 1;
    }

    descriptor = syscall(__NR_openat2, directory, PROBE_NAME, &read_only,
        sizeof(read_only));
    if (descriptor < 0) {
        perror("strict read-only openat2 seccomp probe");
        close(directory);
        return 1;
    }
    if (verify_fixture(descriptor) != 0 || probe_chmod(descriptor) != 0) {
        close(descriptor);
        close(directory);
        return 1;
    }

    errno = 0;
    if (expect_denied("fchmod",
            syscall(__NR_fchmod, descriptor, SETID_MODE)) != 0
        || verify_denial_preserved_mode(descriptor, "fchmod") != 0) {
        close(descriptor);
        close(directory);
        return 1;
    }

    errno = 0;
    if (expect_denied("fchmodat",
            syscall(__NR_fchmodat, directory, PROBE_NAME, SETID_MODE)) != 0
        || verify_denial_preserved_mode(descriptor, "fchmodat") != 0) {
        close(descriptor);
        close(directory);
        return 1;
    }

    errno = 0;
    if (expect_denied("fchmodat2",
            syscall(__NR_fchmodat2, directory, PROBE_NAME, SETID_MODE, 0)) != 0
        || verify_denial_preserved_mode(descriptor, "fchmodat2") != 0) {
        close(descriptor);
        close(directory);
        return 1;
    }

    if (close(descriptor) != 0 || close(directory) != 0) {
        perror("close seccomp probe descriptor");
        return 1;
    }

#ifdef __NR_chmod
    puts("AOS_STORAGE_BROKER_SECCOMP_PROBE_PASS no-setid io-uring-denied openat2-setid-denied boot-id-read-only openat2 chmod fchmod fchmodat fchmodat2");
#else
    puts("AOS_STORAGE_BROKER_SECCOMP_PROBE_PASS no-setid io-uring-denied openat2-setid-denied boot-id-read-only openat2 chmod-unavailable fchmod fchmodat fchmodat2");
#endif

    return 0;
}
