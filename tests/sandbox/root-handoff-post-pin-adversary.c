/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Keeps the qualification attack in one process: replacing the parent's loader
 * must not prevent the attacker from finishing its remaining mount operations.
 * All directories and the console are retained before switch-root removes the
 * initrd paths. This helper is included only in the adversarial VM fixture.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *operation)
{
    fprintf(stderr, "AOS post-pin attack failed: %s: %s\n", operation,
            strerror(errno));
    exit(EXIT_FAILURE);
}

static void format_path(char *output, size_t capacity, const char *format,
                        const char *value)
{
    int length = snprintf(output, capacity, format, value);

    if (length < 0 || (size_t)length >= capacity) {
        errno = ENAMETOOLONG;
        fail("format retained path");
    }
}

static void retain_directory(int target, const char *path)
{
    int source = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    if (source < 0 || dup2(source, target) < 0)
        fail(path);
    if (source != target)
        close(source);
}

static void write_file(const char *path, const char *text, mode_t mode)
{
    size_t length = strlen(text);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (fd < 0 || write(fd, text, length) != (ssize_t)length ||
        fchmod(fd, mode) < 0 || fsync(fd) < 0 || close(fd) < 0)
        fail(path);
}

static void notify_ready(void)
{
    const char *path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    size_t length;

    if (!path || (path[0] != '/' && path[0] != '@') || fd < 0) {
        errno = EINVAL;
        fail("notification socket");
    }
    length = strlen(path);
    if (length >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        fail("notification socket path");
    }
    memcpy(address.sun_path, path, length + 1);
    if (path[0] == '@')
        address.sun_path[0] = '\0';
    if (sendto(fd, "READY=1", 7, MSG_NOSIGNAL,
               (struct sockaddr *)&address,
               offsetof(struct sockaddr_un, sun_path) + length + (path[0] == '/')) != 7)
        fail("notify readiness");
    close(fd);
}

static void await_file(const char *path)
{
    struct timespec start;
    struct timespec now;
    const struct timespec pause = {.tv_nsec = 10000000};

    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        fail("read initial monotonic clock");
    for (;;) {
        struct stat metadata;

        if (stat(path, &metadata) == 0)
            return;
        if (errno != ENOENT)
            fail(path);
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            fail("read monotonic clock");
        if (now.tv_sec - start.tv_sec > 600) {
            errno = ETIMEDOUT;
            fail(path);
        }
        nanosleep(&pause, NULL);
    }
}

static void namespace_identity(const char *path, char output[64])
{
    ssize_t length = readlink(path, output, 63);

    if (length < 0 || length >= 63)
        fail(path);
    output[length] = '\0';
}

static void bind_and_verify(const char *source, const char *target,
                            const char *expected)
{
    char observed[128];
    size_t length = strlen(expected);
    int fd;
    ssize_t received;

    if (mount(source, target, NULL, MS_BIND, NULL) < 0)
        fail(target);
    fd = open(target, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail(target);
    received = read(fd, observed, sizeof(observed));
    if (received < 0)
        fail("read attacked file");
    close(fd);
    if ((size_t)received != length || memcmp(observed, expected, length) != 0) {
        errno = EIO;
        fail("verify attacked file bytes");
    }
}

int main(int argc, char **argv)
{
    char path[4096];
    char loader_target[4096];
    char parent_namespace[64];
    char pid1_namespace[64];
    char proof[192];
    const char *phase;
    const char *root;
    int console;

    if (argc != 6 || (strcmp(argv[1], "switch-root") != 0 &&
                      strcmp(argv[1], "reexec") != 0)) {
        fprintf(stderr, "usage: %s PHASE SYSTEMD GLIBC LIBCAP LOADER\n", argv[0]);
        return EXIT_FAILURE;
    }
    phase = argv[1];
    root = strcmp(phase, "switch-root") == 0 ? "/sysroot" : "";
    console = open("/dev/console", O_WRONLY | O_CLOEXEC);
    if (console < 0 || dup2(console, STDERR_FILENO) < 0)
        fail("retain console");
    close(console);

    retain_directory(8, "/proc");
    snprintf(path, sizeof(path), "%s/usr/lib/aos/nix/store/%s", root, argv[2]);
    retain_directory(3, path);
    snprintf(path, sizeof(path), "%s/nix/store/%s", root, argv[3]);
    retain_directory(4, path);
    snprintf(path, sizeof(path), "%s/nix/store/%s", root, argv[4]);
    retain_directory(5, path);
    retain_directory(6, root[0] ? root : "/");
    retain_directory(7, "/run");
    if (fchdir(8) < 0)
        fail("retain procfs working directory");
    if (mkdir("self/fd/7/aos", 0755) < 0 && errno != EEXIST)
        fail("create attack directory");

    if (strcmp(phase, "switch-root") == 0) {
        write_file("self/fd/7/aos/post-pin-systemd", "AOS_POST_PIN_ATTACKER_SYSTEMD\n", 0555);
        write_file("self/fd/7/aos/post-pin-loader", "AOS_POST_PIN_ATTACKER_LOADER\n", 0555);
        write_file("self/fd/7/aos/post-pin-dso", "AOS_POST_PIN_ATTACKER_DSO\n", 0555);
        write_file("self/fd/7/aos/post-pin-preload", "/run/aos/post-pin-attacker.so\n", 0444);
    }
    format_path(loader_target, sizeof(loader_target), "self/fd/4/lib/%s", argv[5]);
    notify_ready();

    if (strcmp(phase, "reexec") == 0)
        await_file("self/fd/7/aos/post-pin-reexec.arm");
    format_path(path, sizeof(path), "self/fd/7/aos/root-handoff-post-pin.%s.ready", phase);
    await_file(path);
    namespace_identity("self/ns/mnt", parent_namespace);
    namespace_identity("1/ns/mnt", pid1_namespace);
    if (strcmp(parent_namespace, pid1_namespace) == 0) {
        errno = EINVAL;
        fail("PID1 did not isolate its mount namespace");
    }

    bind_and_verify("self/fd/7/aos/post-pin-systemd", "self/fd/3/lib/systemd/systemd",
                    "AOS_POST_PIN_ATTACKER_SYSTEMD\n");
    bind_and_verify("self/fd/7/aos/post-pin-loader", loader_target,
                    "AOS_POST_PIN_ATTACKER_LOADER\n");
    bind_and_verify("self/fd/7/aos/post-pin-dso", "self/fd/5/lib/libcap.so.2",
                    "AOS_POST_PIN_ATTACKER_DSO\n");
    bind_and_verify("self/fd/7/aos/post-pin-preload", "self/fd/6/etc/ld.so.preload",
                    "/run/aos/post-pin-attacker.so\n");

    snprintf(proof, sizeof(proof), "parent_namespace=%s\npid1_namespace=%s\n",
             parent_namespace, pid1_namespace);
    format_path(path, sizeof(path), "self/fd/7/aos/post-pin-%s.done", phase);
    write_file(path, proof, 0444);
    format_path(path, sizeof(path), "self/fd/7/aos/root-handoff-post-pin.%s.pending", phase);
    write_file(path, "continue\n", 0444);
    {
        char continuation[4096];

        format_path(continuation, sizeof(continuation),
                    "self/fd/7/aos/root-handoff-post-pin.%s.continue", phase);
        if (link(path, continuation) < 0 || unlink(path) < 0)
            fail("publish complete continuation");
    }
    fprintf(stderr, "AOS post-pin parent attack complete: %s %s != %s\n",
            phase, parent_namespace, pid1_namespace);
    return EXIT_SUCCESS;
}
