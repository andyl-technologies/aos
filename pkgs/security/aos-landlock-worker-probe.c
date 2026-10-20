/* Disposable-VM negative/positive controls for the actual pure-worker profile.
 * This is a source-built fixture, not a Source issuer or substitute algorithm. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int passed(const char *mode)
{
    printf("PASS:%s:%ld\n", mode, (long)getpid());
    return fflush(stdout) ? 2 : 0;
}

int main(int argc, char **argv, char **environment)
{
    char mode[32];
    struct rlimit nofile;
    size_t count;
    int fd;

    if (argc != 13 || strcmp(argv[1], "--worker-digest")
        || strcmp(argv[3], "--algorithm-digest")
        || strcmp(argv[5], "--maximum-input-bytes")
        || strcmp(argv[7], "--maximum-elements")
        || strcmp(argv[9], "--maximum-output-bytes")
        || strcmp(argv[11], "--maximum-diagnostic-bytes")
        || strlen(argv[2]) != 64 || strlen(argv[4]) != 64 || environment[0] || getuid() == 0 || geteuid() == 0
        || (fcntl(STDIN_FILENO, F_GETFL) & O_ACCMODE) != O_RDONLY
        || fcntl(3, F_GETFD) != -1 || errno != EBADF
        || getrlimit(RLIMIT_NOFILE, &nofile) || nofile.rlim_cur != 32
        || nofile.rlim_max != 32) {
        return 3;
    }
    count = read(STDIN_FILENO, mode, sizeof(mode) - 1);
    if (count == 0 || count >= sizeof(mode)) {
        return 4;
    }
    mode[count] = '\0';
    if (!strcmp(mode, "success")) {
        return passed(mode);
    }
    if (!strcmp(mode, "network")) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0 || errno != EPERM) {
            return 5;
        }
        return passed(mode);
    }
    if (!strcmp(mode, "clone")) {
        pid_t child = fork();
        if (child >= 0 || errno != EPERM) {
            return 6;
        }
        return passed(mode);
    }
    if (!strcmp(mode, "filesystem")) {
        fd = open("/var/lib/pure-worker-secret", O_RDONLY);
        if (fd >= 0 || errno != EACCES) {
            return 7;
        }
        fd = open("/var/lib/pure-worker-escape", O_WRONLY | O_CREAT, 0600);
        if (fd >= 0 || errno != EACCES) {
            return 8;
        }
        return passed(mode);
    }
    if (!strcmp(mode, "descriptors")) {
        int opened[32];
        size_t used = 0;
        while (used < 32 && (fd = open(argv[0], O_RDONLY)) >= 0) {
            opened[used++] = fd;
        }
        if (used != 29 || errno != EMFILE) {
            return 9;
        }
        while (used) {
            close(opened[--used]);
        }
        return passed(mode);
    }
    if (!strcmp(mode, "address-space")) {
        void *allocation = mmap(NULL, 256UL * 1024 * 1024, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (allocation != MAP_FAILED || errno != ENOMEM) {
            return 10;
        }
        return passed(mode);
    }
    if (!strcmp(mode, "memory")) {
        /* 256MiB address space permits this request; 32MiB cgroup memory
         * cannot hold its physically touched pages. Actual death is required. */
        volatile unsigned char *allocation;
        static const char started[] = "MEMORY:started\n";
        static const char mapped[] = "MEMORY:mapped\n";
        if (write(STDOUT_FILENO, started, sizeof(started) - 1) != (ssize_t)(sizeof(started) - 1)) {
            return 15;
        }
        allocation = mmap(NULL, 128UL * 1024 * 1024,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (allocation == MAP_FAILED) {
            return 11;
        }
        if (write(STDOUT_FILENO, mapped, sizeof(mapped) - 1) != (ssize_t)(sizeof(mapped) - 1)) {
            return 16;
        }
        for (count = 0; count < 128UL * 1024 * 1024; count += 4096) {
            allocation[count] = 1;
        }
        return 12;
    }
    if (!strcmp(mode, "output")) {
        memset(mode, 'x', sizeof(mode));
        for (;;) {
            if (write(STDOUT_FILENO, mode, sizeof(mode)) < 0) {
                return 13;
            }
        }
    }
    if (!strcmp(mode, "cpu") || !strcmp(mode, "cancel")) {
        static const char started[] = "CPU:started\n";
        if (!strcmp(mode, "cpu") && write(STDOUT_FILENO, started, sizeof(started) - 1) != (ssize_t)(sizeof(started) - 1)) {
            return 17;
        }
        for (;;) {
            __asm__ volatile ("" ::: "memory");
        }
    }
    return 14;
}
