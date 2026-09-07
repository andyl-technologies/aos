/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct status_fields {
        long no_new_privileges;
        long seccomp;
};

static bool errno_is(long result, int expected) {
        return result == -1 && errno == expected;
}

static int read_status(pid_t pid, struct status_fields *fields) {
        char path[64];
        char line[256];
        FILE *stream;

        if (snprintf(path, sizeof(path), "/proc/%ld/status", (long) pid) < 0)
                return -1;
        stream = fopen(path, "re");
        if (!stream)
                return -1;
        fields->no_new_privileges = -1;
        fields->seccomp = -1;
        while (fgets(line, sizeof(line), stream)) {
                (void) sscanf(line, "NoNewPrivs:%ld", &fields->no_new_privileges);
                (void) sscanf(line, "Seccomp:%ld", &fields->seccomp);
        }
        if (fclose(stream) != 0)
                return -1;
        return fields->no_new_privileges >= 0 && fields->seccomp >= 0 ? 0 : -1;
}

static int read_uid_map(unsigned long *inside, unsigned long *outside, unsigned long *length) {
        FILE *stream = fopen("/proc/self/uid_map", "re");
        int matched;

        if (!stream)
                return -1;
        matched = fscanf(stream, "%lu %lu %lu", inside, outside, length);
        if (fclose(stream) != 0)
                return -1;
        return matched == 3 ? 0 : -1;
}

static bool ordinary_fork_works(void) {
        pid_t child = fork();
        int status;

        if (child < 0)
                return false;
        if (child == 0)
                _exit(EXIT_SUCCESS);
        return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char **argv) {
        struct status_fields self_status = { .no_new_privileges = -1, .seccomp = -1 };
        struct status_fields pid1_status = { .no_new_privileges = -1, .seccomp = -1 };
        struct stat net_namespace = { 0 };
        unsigned long uid_inside = 0;
        unsigned long uid_outside = 0;
        unsigned long uid_length = 0;
        bool mount_denied;
        bool unshare_denied;
        bool setns_denied;
        bool clone_namespace_denied;
        bool clone3_hidden;
        bool fork_allowed;
        bool settings_ignored;
        bool hostile_mount_absent;
        bool uid_map_expected;
        bool passed;
        char temporary[4096];
        char generation_temporary[4096];
        FILE *report;
        FILE *generation_file;
        unsigned long boot_generation = 0;
        int written;
        bool io_ok;
        char generation_newline;

        if (argc != 3) {
                fprintf(stderr, "usage: nspawn-platform-probe REPORT GENERATION\n");
                return EXIT_FAILURE;
        }
        if (strlen(argv[1]) > sizeof(temporary) - 5) {
                fprintf(stderr, "report path is too long\n");
                return EXIT_FAILURE;
        }
        if (strlen(argv[2]) > sizeof(generation_temporary) - 5) {
                fprintf(stderr, "generation path is too long\n");
                return EXIT_FAILURE;
        }

        generation_file = fopen(argv[2], "re");
        if (generation_file) {
                io_ok = fscanf(generation_file, "%lu%c", &boot_generation, &generation_newline) == 2
                        && generation_newline == '\n' && fgetc(generation_file) == EOF;
                if (fclose(generation_file) != 0)
                        io_ok = false;
                if (!io_ok || boot_generation == ~0UL)
                        return EXIT_FAILURE;
        } else if (errno != ENOENT) {
                return EXIT_FAILURE;
        }
        boot_generation++;
        written = snprintf(generation_temporary, sizeof(generation_temporary), "%s.tmp", argv[2]);
        if (written < 0 || (size_t) written >= sizeof(generation_temporary))
                return EXIT_FAILURE;
        generation_file = fopen(generation_temporary, "we");
        if (!generation_file)
                return EXIT_FAILURE;
        io_ok = fprintf(generation_file, "%lu\n", boot_generation) >= 0;
        if (io_ok && fflush(generation_file) != 0)
                io_ok = false;
        if (io_ok && fsync(fileno(generation_file)) != 0)
                io_ok = false;
        if (fclose(generation_file) != 0)
                io_ok = false;
        if (!io_ok) {
                (void) unlink(generation_temporary);
                return EXIT_FAILURE;
        }
        if (rename(generation_temporary, argv[2]) != 0)
                return EXIT_FAILURE;

        errno = 0;
        mount_denied = errno_is(mount(NULL, NULL, NULL, 0, NULL), EPERM);
        errno = 0;
        unshare_denied = errno_is(syscall(SYS_unshare, 0), EPERM);
        errno = 0;
        setns_denied = errno_is(syscall(SYS_setns, -1, 0), EPERM);
        errno = 0;
        clone_namespace_denied = errno_is(
                syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, NULL, NULL, NULL, 0), EPERM);
        errno = 0;
        clone3_hidden = errno_is(syscall(SYS_clone3, NULL, 0), ENOSYS);
        fork_allowed = ordinary_fork_works();
        settings_ignored = getenv("AOS_HOSTILE_NSPAWN_SETTINGS") == NULL;
        hostile_mount_absent = access("/host-etc", F_OK) < 0 && errno == ENOENT;
        uid_map_expected = read_uid_map(&uid_inside, &uid_outside, &uid_length) == 0
                && uid_inside == 0 && uid_outside == 655360 && uid_length == 65536;

        passed = read_status(getpid(), &self_status) == 0
                && read_status(1, &pid1_status) == 0
                && stat("/proc/self/ns/net", &net_namespace) == 0
                && getpid() != 1
                && self_status.no_new_privileges == 1
                && self_status.seccomp == 2
                && pid1_status.no_new_privileges == 1
                && pid1_status.seccomp == 2
                && mount_denied
                && unshare_denied
                && setns_denied
                && clone_namespace_denied
                && clone3_hidden
                && fork_allowed
                && settings_ignored
                && hostile_mount_absent
                && uid_map_expected;

        written = snprintf(temporary, sizeof(temporary), "%s.tmp", argv[1]);
        if (written < 0 || (size_t) written >= sizeof(temporary))
                return EXIT_FAILURE;
        report = fopen(temporary, "we");
        if (!report)
                return EXIT_FAILURE;
        if (fprintf(report,
                    "{\n"
                    "  \"schema\":\"aos.sandbox.nspawn-platform-proof/v1\",\n"
                    "  \"passed\":%s,\n"
                    "  \"boot_generation\":%lu,\n"
                    "  \"payload_pid\":%ld,\n"
                    "  \"pid1_no_new_privileges\":%ld,\n"
                    "  \"pid1_seccomp_mode\":%ld,\n"
                    "  \"service_no_new_privileges\":%ld,\n"
                    "  \"service_seccomp_mode\":%ld,\n"
                    "  \"mount_denied_eperm\":%s,\n"
                    "  \"unshare_denied_eperm\":%s,\n"
                    "  \"setns_denied_eperm\":%s,\n"
                    "  \"clone_namespace_denied_eperm\":%s,\n"
                    "  \"clone3_hidden_enosys\":%s,\n"
                    "  \"ordinary_fork_allowed\":%s,\n"
                    "  \"hostile_settings_ignored\":%s,\n"
                    "  \"hostile_mount_absent\":%s,\n"
                    "  \"uid_map\":{\"inside\":%lu,\"outside\":%lu,\"length\":%lu},\n"
                    "  \"network_namespace_inode\":%llu\n"
                    "}\n",
                    passed ? "true" : "false",
                    boot_generation,
                    (long) getpid(),
                    pid1_status.no_new_privileges,
                    pid1_status.seccomp,
                    self_status.no_new_privileges,
                    self_status.seccomp,
                    mount_denied ? "true" : "false",
                    unshare_denied ? "true" : "false",
                    setns_denied ? "true" : "false",
                    clone_namespace_denied ? "true" : "false",
                    clone3_hidden ? "true" : "false",
                    fork_allowed ? "true" : "false",
                    settings_ignored ? "true" : "false",
                    hostile_mount_absent ? "true" : "false",
                    uid_inside,
                    uid_outside,
                    uid_length,
                    (unsigned long long) net_namespace.st_ino) < 0) {
                (void) fclose(report);
                return EXIT_FAILURE;
        }
        io_ok = fflush(report) == 0;
        if (io_ok && fsync(fileno(report)) != 0)
                io_ok = false;
        if (fclose(report) != 0)
                io_ok = false;
        if (!io_ok) {
                (void) unlink(temporary);
                return EXIT_FAILURE;
        }
        if (rename(temporary, argv[1]) != 0) {
                (void) unlink(temporary);
                return EXIT_FAILURE;
        }
        return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
