/* Emit the loaded SELinux policy as serialized by the selected AOS kernel. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

enum { MAX_POLICY_BYTES = 16 * 1024 * 1024 };

static void fail(const char *operation) {
    fprintf(stderr, "kernel policy readback failed: %s: %s\n", operation,
            strerror(errno));
    fflush(stderr);
    _exit(1);
}

static size_t read_policy(const char *path, unsigned char *buffer) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0)
        fail(path);

    size_t length = 0;
    for (;;) {
        ssize_t amount = read(descriptor, buffer + length,
                              MAX_POLICY_BYTES - length);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount < 0)
            fail(path);
        if (amount == 0)
            break;

        length += (size_t)amount;
        if (length == MAX_POLICY_BYTES) {
            errno = EOVERFLOW;
            fail("policy exceeds readback bound");
        }
    }
    if (close(descriptor) < 0)
        fail("close policy input");
    return length;
}

static void write_all(int descriptor, const unsigned char *buffer,
                      size_t length, const char *operation) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t amount = write(descriptor, buffer + offset, length - offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            fail(operation);
        offset += (size_t)amount;
    }
}

static void require_enforcing(void) {
    int descriptor = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0)
        fail("open SELinux enforcement state");

    char state;
    if (read(descriptor, &state, 1) != 1 || state != '1') {
        errno = EPERM;
        fail("require enforcing SELinux policy");
    }
    if (close(descriptor) < 0)
        fail("close SELinux enforcement state");
}

int main(void) {
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0)
        fail("mount devtmpfs");

    int console = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (console < 0 || dup2(console, STDOUT_FILENO) < 0 ||
        dup2(console, STDERR_FILENO) < 0)
        fail("attach serial console");
    if (console > STDERR_FILENO)
        close(console);

    if (mount("proc", "/proc", "proc", 0, NULL) < 0 ||
        mount("sysfs", "/sys", "sysfs", 0, NULL) < 0 ||
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL) < 0)
        fail("mount SELinux policy filesystems");

    unsigned char *policy = malloc(MAX_POLICY_BYTES);
    if (policy == NULL)
        fail("allocate policy buffer");
    size_t source_length = read_policy("/source-policy.33", policy);
    if (source_length == 0) {
        errno = EINVAL;
        fail("empty source policy");
    }

    int load = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (load < 0)
        fail("open SELinux policy loader");
    write_all(load, policy, source_length, "load source policy");
    if (close(load) < 0)
        fail("close SELinux policy loader");
    require_enforcing();

    size_t readback_length = read_policy("/sys/fs/selinux/policy", policy);

    /* Devtmpfs exposes vport0p1; the named symlink requires absent udev. */
    int export = open("/dev/vport0p1", O_WRONLY | O_CLOEXEC);
    if (export < 0)
        fail("open policy export port");
    write_all(export, policy, readback_length, "export kernel policy");
    if (close(export) < 0)
        fail("close policy export port");

    printf("AOS_POLICY_READBACK_COMPLETE=%zu\n", readback_length);
    fflush(stdout);
    for (;;)
        pause();
}
