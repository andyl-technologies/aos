/* SPDX-License-Identifier: Apache-2.0
 * VM-only hostile UID-zero/MAC and cgroup prerequisite, not an execution grant.
 * The fixture policy adds only a measured entry into the existing Owner; its
 * actual Owner->Tenant transition and protected object denials are production.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROOT "/run/aos-guest-owner-fixture"
#define CGROUP "/sys/fs/cgroup/aos-guest-owner-fixture"
#define OWNER "system_u:system_r:aos_sandbox_guest_owner_t:s0"
#define TENANT "system_u:system_r:aos_sandbox_payload_t:s0"

static volatile unsigned char protected_memory = 0x5a;

static void
require(bool accepted)
{
        if (!accepted)
                _exit(101);
}

static void
write_exact(const char *path, const char *value)
{
        int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
        require(fd >= 0);
        size_t length = strlen(value);
        require(write(fd, value, length) == (ssize_t) length);
        require(close(fd) == 0);
}

static bool
exact_state(const char *path, const char *expected)
{
        char value[128] = {0};
        int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return false;
        ssize_t length = read(fd, value, sizeof(value));
        close(fd);
        size_t wanted = strlen(expected);
        return length >= 0 &&
               ((size_t) length == wanted || ((size_t) length == wanted + 1 && value[wanted] == '\n')) &&
               memcmp(value, expected, wanted) == 0;
}

static void
denied_open(const char *path, int flags)
{
        errno = 0;
        /* Follow procfd aliases: ELOOP from O_NOFOLLOW would not prove MAC. */
        int fd = open(path, flags|O_CLOEXEC);
        require(fd < 0 && (errno == EACCES || errno == EPERM));
}

static bool
populated(void)
{
        char value[256] = {0};
        int fd = open(CGROUP "/cgroup.events", O_RDONLY|O_CLOEXEC);
        require(fd >= 0);
        ssize_t length = read(fd, value, sizeof(value) - 1);
        require(length > 0 && close(fd) == 0);
        require(strstr(value, "populated 0\n") || strstr(value, "populated 1\n"));
        return strstr(value, "populated 1\n") != NULL;
}

static int
tenant(pid_t parent, uintptr_t address)
{
        require(getuid() == 0 && geteuid() == 0 && getgid() == 0);
        require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
        require(exact_state("/proc/thread-self/attr/current", TENANT));
        for (int fd = 3; fd < 4096; fd++) {
                errno = 0;
                require(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
        }
        for (int fd = 0; fd < 3; fd++) {
                struct stat inode;
                require(fstat(fd, &inode) == 0 && S_ISFIFO(inode.st_mode));
        }

        denied_open(ROOT "/private/trust", O_RDONLY);
        denied_open(ROOT "/private/ledger", O_WRONLY);
        denied_open(ROOT "/manager/unit.service", O_WRONLY);
        denied_open(ROOT "/config/nsswitch.conf", O_WRONLY);
        denied_open(ROOT "/store/loader", O_WRONLY);
        denied_open(ROOT "/owner", O_WRONLY);
        denied_open(CGROUP "/cgroup.procs", O_WRONLY);
        denied_open(CGROUP "/cgroup.threads", O_WRONLY);
        denied_open(CGROUP "/cgroup.kill", O_WRONLY);
        denied_open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
        errno = 0;
        require(rename(ROOT "/store", ROOT "/substituted-store") < 0 &&
                (errno == EACCES || errno == EPERM));

        char path[128];
        require(snprintf(path, sizeof(path), "/proc/%d/mem", parent) > 0);
        denied_open(path, O_RDWR);
        require(snprintf(path, sizeof(path), "/proc/%d/fd/3", parent) > 0);
        denied_open(path, O_RDONLY);
        errno = 0;
        require(ptrace(PTRACE_ATTACH, parent, 0, 0) < 0 &&
                (errno == EACCES || errno == EPERM));
        unsigned char reflected = 0;
        struct iovec local = { &reflected, 1 }, remote = { (void *) address, 1 };
        errno = 0;
        require(process_vm_readv(parent, &local, 1, &remote, 1, 0) < 0 &&
                (errno == EACCES || errno == EPERM));
        errno = 0;
        require(kill(parent, SIGTERM) < 0 && (errno == EACCES || errno == EPERM));

        // A public pathname cannot re-enter the trusted helper domain.
        pid_t attempt = fork();
        require(attempt >= 0);
        if (attempt == 0) {
                execl(ROOT "/owner", ROOT "/owner", "owner", (char *) NULL);
                _exit(errno == EACCES || errno == EPERM ? 0 : 102);
        }
        int status;
        require(waitpid(attempt, &status, 0) == attempt && WIFEXITED(status) && WEXITSTATUS(status) == 0);

        // Job control can escape a PGID, but never this MAC-held subtree.
        int ready[2];
        require(pipe2(ready, O_CLOEXEC) == 0);
        pid_t descendant = fork();
        require(descendant >= 0);
        if (descendant == 0) {
                require(setsid() >= 0);
                require(write(ready[1], "x", 1) == 1);
                for (;;)
                        pause();
        }
        char started;
        require(read(ready[0], &started, 1) == 1);
        close(ready[0]);
        close(ready[1]);
        return 0;
}

static int
owner(void)
{
        require(geteuid() == 0 && exact_state("/proc/thread-self/attr/current", OWNER));
        require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
        require(exact_state("/sys/fs/selinux/enforce", "1"));
        require(exact_state("/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition", "1"));
        // Make same-UID proc/ptrace attacks DAC-eligible. Yama is separately
        // disabled by the VM; this fixture must observe the actual MAC denial.
        require(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);
        int secret = open(ROOT "/private/trust", O_RDONLY|O_CLOEXEC);
        require(secret == 3);
        int release[2], stream[2];
        require(pipe2(release, O_CLOEXEC) == 0 && pipe2(stream, O_CLOEXEC) == 0);
        pid_t child = fork();
        require(child >= 0);
        if (child == 0) {
                char byte;
                require(read(release[0], &byte, 1) == 1);
                require(dup2(stream[0], 0) == 0 && dup2(stream[1], 1) == 1 && dup2(stream[1], 2) == 2);
                write_exact("/proc/thread-self/attr/exec", TENANT);
                require(syscall(SYS_close_range, 3U, ~0U, 0U) == 0);
                char parent[32], address[32];
                snprintf(parent, sizeof(parent), "%d", getppid());
                snprintf(address, sizeof(address), "%llu", (unsigned long long) (uintptr_t) &protected_memory);
                char *arguments[] = { ROOT "/tenant", "tenant", parent, address, NULL };
                execve(arguments[0], arguments, (char *const[]){ NULL });
                _exit(103);
        }
        int pidfd = (int) syscall(SYS_pidfd_open, child, 0U);
        require(pidfd >= 0);
        char membership[32];
        snprintf(membership, sizeof(membership), "%d\n", child);
        write_exact(CGROUP "/cgroup.procs", membership);
        require(write(release[1], "x", 1) == 1);
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        require(populated()); // Leader exit is deliberately insufficient.
        write_exact(CGROUP "/cgroup.kill", "1\n");
        struct timespec pause_time = { .tv_nsec = 1000000 };
        for (unsigned int waits = 0; populated(); waits++) {
                require(waits < 5000);
                nanosleep(&pause_time, NULL);
        }
        close(pidfd);
        close(secret);
        return 0;
}

int
main(int argc, char **argv)
{
        if (argc == 2 && strcmp(argv[1], "enter") == 0) {
                require(geteuid() == 0 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
                write_exact("/proc/thread-self/attr/exec", OWNER);
                require(syscall(SYS_close_range, 3U, ~0U, 0U) == 0);
                execl(ROOT "/owner", ROOT "/owner", "owner", (char *) NULL);
                return 104;
        }
        if (argc == 2 && strcmp(argv[1], "owner") == 0)
                return owner();
        if (argc == 4 && strcmp(argv[1], "tenant") == 0)
                return tenant((pid_t) strtol(argv[2], NULL, 10), (uintptr_t) strtoull(argv[3], NULL, 10));
        return 105;
}
