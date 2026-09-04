/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PIDFD_GET_MNT_NAMESPACE 0xff03
#define PIDFD_GET_NET_NAMESPACE 0xff04
#define PIDFD_GET_PID_NAMESPACE 0xff05
#define PIDFD_GET_USER_NAMESPACE 0xff09
#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)
#define PIDFD_INFO_CGROUPID (1ULL << 2)
#define MAX_PATH 4096
#define MAX_DIRECTORIES 64
#define MAX_DIRECTORY_ENTRIES 4096
#define MAX_CANDIDATES 4096
#define MAX_PARSED_BYTES (1024 * 1024)
#define MAX_CMDLINE_BYTES 32768
#define MAX_DEPTH 32
#define DISCOVERY_SECONDS 30

struct raw_pidfd_info {
        unsigned long long mask;
        unsigned long long cgroup_id;
        unsigned int pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
        int exit_code;
        unsigned int coredump_mask, spare;
};
_Static_assert(sizeof(struct raw_pidfd_info) == 72, "Linux 6.18 pidfd info ABI changed");

struct identity { unsigned long long device, inode; };
struct observation {
        pid_t pid;
        int pidfd, rootfd, cgroupfd, mntfd, netfd, pidnsfd, userfd;
        struct identity root, mnt, net, pidns, user;
};

struct supervisor {
        pid_t pid;
        int pidfd, exefd, cgroupfd;
        unsigned long long cgroup_id;
};

struct budget {
        struct timespec deadline;
        unsigned directories, entries, candidates;
        size_t bytes;
};

static void close_observation(struct observation *o) {
        int *fds[] = { &o->pidfd, &o->rootfd, &o->cgroupfd, &o->mntfd, &o->netfd,
                       &o->pidnsfd, &o->userfd };
        size_t i;
        for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
                if (*fds[i] >= 0) { (void) close(*fds[i]); *fds[i] = -1; }
}

static void close_supervisor(struct supervisor *s) {
        if (s->pidfd >= 0) (void) close(s->pidfd);
        if (s->exefd >= 0) (void) close(s->exefd);
        if (s->cgroupfd >= 0) (void) close(s->cgroupfd);
        s->pidfd = s->exefd = s->cgroupfd = -1;
}

static int before_deadline(const struct budget *budget) {
        struct timespec now;
        if (clock_gettime(CLOCK_BOOTTIME, &now) < 0) return 0;
        return now.tv_sec < budget->deadline.tv_sec ||
                (now.tv_sec == budget->deadline.tv_sec && now.tv_nsec < budget->deadline.tv_nsec);
}

static int start_budget(struct budget *budget, time_t seconds) {
        memset(budget, 0, sizeof(*budget));
        if (clock_gettime(CLOCK_BOOTTIME, &budget->deadline) < 0 ||
            budget->deadline.tv_sec > LONG_MAX - seconds) return -1;
        budget->deadline.tv_sec += seconds;
        return 0;
}

static void reset_scan_work(struct budget *budget) {
        budget->directories = 0;
        budget->entries = 0;
        budget->candidates = 0;
        budget->bytes = 0;
}

static int charge(struct budget *budget, unsigned *counter, unsigned maximum, size_t bytes) {
        if (!before_deadline(budget) || *counter >= maximum ||
            bytes > MAX_PARSED_BYTES - budget->bytes) return -1;
        (*counter)++;
        budget->bytes += bytes;
        return 0;
}

static int charge_bytes(struct budget *budget, size_t bytes) {
        if (!budget) return 0;
        if (!before_deadline(budget) || bytes > MAX_PARSED_BYTES - budget->bytes) return -1;
        budget->bytes += bytes;
        return 0;
}

static int pidfd_info(int pidfd, struct raw_pidfd_info *info) {
        memset(info, 0, sizeof(*info));
        info->mask = PIDFD_INFO_PID | PIDFD_INFO_CGROUPID;
        if (ioctl(pidfd, PIDFD_GET_INFO, info) < 0) return -1;
        return (info->mask & (PIDFD_INFO_PID | PIDFD_INFO_CGROUPID)) ==
                (PIDFD_INFO_PID | PIDFD_INFO_CGROUPID) ? 0 : -1;
}

static int identity_fd(int fd, struct identity *id) {
        struct stat st = { 0 };
        if (fstat(fd, &st) < 0) return -1;
        id->device = (unsigned long long) st.st_dev;
        id->inode = (unsigned long long) st.st_ino;
        return 0;
}

static int identity_path(const char *path, struct identity *id) {
        struct stat st = { 0 };
        if (stat(path, &st) < 0) return -1;
        id->device = (unsigned long long) st.st_dev;
        id->inode = (unsigned long long) st.st_ino;
        return 0;
}

static bool same_identity(struct identity a, struct identity b) {
        return a.device == b.device && a.inode == b.inode;
}

static int read_status(pid_t pid, pid_t supervisor, bool *nested_one, struct budget *budget) {
        char path[64], line[512];
        FILE *stream;
        long parent = -1;
        unsigned long nested = 0;
        bool found = false;

        {
                int written = snprintf(path, sizeof(path), "/proc/%ld/status", (long) pid);
                if (written < 0 || (size_t) written >= sizeof(path)) return -1;
        }
        stream = fopen(path, "re");
        if (!stream) return -1;
        while (fgets(line, sizeof(line), stream)) {
                char *cursor;
                if (charge_bytes(budget, strlen(line)) < 0) { (void) fclose(stream); return -1; }
                (void) sscanf(line, "PPid:%ld", &parent);
                if (strncmp(line, "NSpid:\t", 7) != 0) continue;
                cursor = line + 7;
                while (*cursor != '\0') {
                        char *end;
                        unsigned long value;
                        errno = 0;
                        value = strtoul(cursor, &end, 10);
                        if (cursor == end) break;
                        if (errno != 0) { (void) fclose(stream); return -1; }
                        nested = value;
                        found = true;
                        cursor = end;
                }
        }
        {
                int valid = !ferror(stream) &&
                        (supervisor == 0 || parent == (long) supervisor);
                if (fclose(stream) != 0) valid = 0;
                if (!valid) return -1;
        }
        *nested_one = found && nested == 1;
        return 0;
}

static int exact_cgroup(pid_t pid, const char *expected) {
        char path[64], line[MAX_PATH];
        FILE *stream;
        int lines = 0, written;
        char wanted[MAX_PATH];
        written = snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long) pid);
        if (written < 0 || (size_t) written >= sizeof(path)) return 0;
        written = snprintf(wanted, sizeof(wanted), "0::%s\n", expected);
        if (written < 0 || (size_t) written >= sizeof(wanted)) return 0;
        stream = fopen(path, "re");
        if (!stream) return 0;
        while (fgets(line, sizeof(line), stream)) {
                lines++;
                if (strcmp(line, wanted) != 0) { (void) fclose(stream); return 0; }
        }
        if (ferror(stream)) { (void) fclose(stream); return 0; }
        return fclose(stream) == 0 && lines == 1;
}

static int pidfd_alive(int pidfd) {
        struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
        if (poll(&pfd, 1, 0) < 0 || (pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) return 0;
        return syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0U) == 0;
}

static int command_has_fixed_profile(pid_t pid, const char *machine) {
        char path[64], buffer[MAX_CMDLINE_BYTES + 1], expected_machine[128];
        size_t length = 0, offset;
        unsigned settings = 0, registration = 0, incarnation = 0;
        int fd, written;

        written = snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long) pid);
        if (written < 0 || (size_t) written >= sizeof(path)) return 0;
        written = snprintf(expected_machine, sizeof(expected_machine), "--machine=%s", machine);
        if (written < 0 || (size_t) written >= sizeof(expected_machine)) return 0;
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        for (;;) {
                ssize_t result = read(fd, buffer + length, sizeof(buffer) - length);
                if (result < 0 && errno == EINTR) continue;
                if (result < 0) { (void) close(fd); return 0; }
                if (result == 0) break;
                length += (size_t) result;
                if (length >= MAX_CMDLINE_BYTES) {
                        (void) close(fd);
                        return 0;
                }
        }
        if (close(fd) < 0 || length == 0 || buffer[length - 1] != '\0') return 0;
        for (offset = 0; offset < length;) {
                size_t remaining = length - offset;
                size_t argument_length = strnlen(buffer + offset, remaining);
                if (argument_length == remaining) return 0;
                settings += strcmp(buffer + offset, "--settings=no") == 0;
                registration += strcmp(buffer + offset, "--register=no") == 0;
                incarnation += strcmp(buffer + offset, expected_machine) == 0;
                offset += argument_length + 1;
        }
        return settings == 1 && registration == 1 && incarnation == 1;
}

static int executable_matches(pid_t pid, int retained_exefd) {
        struct identity retained, current;
        char path[64];
        int current_fd, written, matches;

        written = snprintf(path, sizeof(path), "/proc/%ld/exe", (long) pid);
        if (written < 0 || (size_t) written >= sizeof(path)) return 0;
        current_fd = open(path, O_PATH | O_CLOEXEC);
        if (current_fd < 0) return 0;
        matches = identity_fd(retained_exefd, &retained) == 0 &&
                identity_fd(current_fd, &current) == 0 && same_identity(retained, current);
        if (close(current_fd) < 0) matches = 0;
        return matches;
}

static int pin_supervisor(pid_t pid, const char *expected_executable,
                          const char *expected_cgroup, const char *machine,
                          struct supervisor *supervisor) {
        struct raw_pidfd_info first, second;
        struct identity expected_exe, observed_exe;
        struct stat cgroup_status = { 0 };
        char path[MAX_PATH];
        int written;

        *supervisor = (struct supervisor) { .pid = pid, .pidfd = -1, .exefd = -1, .cgroupfd = -1 };
        supervisor->pidfd = (int) syscall(SYS_pidfd_open, pid, 0U);
        if (supervisor->pidfd < 0 || pidfd_info(supervisor->pidfd, &first) < 0 ||
            first.pid != (unsigned) pid || first.tgid != (unsigned) pid ||
            !exact_cgroup(pid, expected_cgroup) || !command_has_fixed_profile(pid, machine)) goto fail;
        written = snprintf(path, sizeof(path), "/proc/%ld/exe", (long) pid);
        if (written < 0 || (size_t) written >= sizeof(path)) goto fail;
        supervisor->exefd = open(path, O_PATH | O_CLOEXEC);
        if (supervisor->exefd < 0 || identity_fd(supervisor->exefd, &observed_exe) < 0 ||
            identity_path(expected_executable, &expected_exe) < 0 || !same_identity(observed_exe, expected_exe)) goto fail;
        written = snprintf(path, sizeof(path), "/sys/fs/cgroup%s", expected_cgroup);
        if (written < 0 || (size_t) written >= sizeof(path)) goto fail;
        supervisor->cgroupfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (supervisor->cgroupfd < 0 || fstat(supervisor->cgroupfd, &cgroup_status) < 0 ||
            first.cgroup_id != (unsigned long long) cgroup_status.st_ino) goto fail;
        supervisor->cgroup_id = first.cgroup_id;
        if (pidfd_info(supervisor->pidfd, &second) < 0 || second.pid != first.pid ||
            second.tgid != first.tgid || second.ppid != first.ppid ||
            second.cgroup_id != first.cgroup_id || !pidfd_alive(supervisor->pidfd)) goto fail;
        return 0;
fail:
        close_supervisor(supervisor);
        return -1;
}

static int supervisor_alive(const struct supervisor *supervisor, const char *expected_cgroup,
                            const char *machine) {
        struct raw_pidfd_info info;
        struct stat status = { 0 };
        return pidfd_info(supervisor->pidfd, &info) == 0 &&
                info.pid == (unsigned) supervisor->pid && info.tgid == (unsigned) supervisor->pid &&
                info.cgroup_id == supervisor->cgroup_id &&
                fstat(supervisor->cgroupfd, &status) == 0 &&
                (unsigned long long) status.st_ino == supervisor->cgroup_id &&
                exact_cgroup(supervisor->pid, expected_cgroup) &&
                executable_matches(supervisor->pid, supervisor->exefd) &&
                command_has_fixed_profile(supervisor->pid, machine) &&
                pidfd_alive(supervisor->pidfd);
}

static int observe(pid_t pid, pid_t supervisor, const char *root, const char *netns,
                   const char *cgroup, struct observation *o) {
        struct identity expected_root = { 0 }, expected_net = { 0 };
        struct raw_pidfd_info first, second;
        struct stat cgroup_status = { 0 };
        char root_path[64];
        char cgroup_path[MAX_PATH];
        bool nested_one = false;
        int written;
        *o = (struct observation) { .pid = pid, .pidfd = -1, .rootfd = -1, .cgroupfd = -1, .mntfd = -1,
                                    .netfd = -1, .pidnsfd = -1, .userfd = -1 };
        o->pidfd = (int) syscall(SYS_pidfd_open, pid, 0U);
        if (o->pidfd < 0 || pidfd_info(o->pidfd, &first) < 0 ||
            first.pid != (unsigned) pid || first.tgid != (unsigned) pid ||
            first.ppid != (unsigned) supervisor || !pidfd_alive(o->pidfd) ||
            read_status(pid, supervisor, &nested_one, NULL) < 0 || !nested_one || !exact_cgroup(pid, cgroup)) goto fail;
        written = snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup%s", cgroup);
        if (written < 0 || (size_t) written >= sizeof(cgroup_path)) goto fail;
        o->cgroupfd = open(cgroup_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (o->cgroupfd < 0 || fstat(o->cgroupfd, &cgroup_status) < 0 ||
            first.cgroup_id != (unsigned long long) cgroup_status.st_ino) goto fail;
        {
                int written = snprintf(root_path, sizeof(root_path), "/proc/%ld/root", (long) pid);
                if (written < 0 || (size_t) written >= sizeof(root_path)) goto fail;
        }
        o->rootfd = open(root_path, O_PATH | O_CLOEXEC);
        if (o->rootfd < 0 || identity_fd(o->rootfd, &o->root) < 0 ||
            identity_path(root, &expected_root) < 0 || !same_identity(o->root, expected_root)) goto fail;
        o->mntfd = ioctl(o->pidfd, PIDFD_GET_MNT_NAMESPACE);
        o->netfd = ioctl(o->pidfd, PIDFD_GET_NET_NAMESPACE);
        o->pidnsfd = ioctl(o->pidfd, PIDFD_GET_PID_NAMESPACE);
        o->userfd = ioctl(o->pidfd, PIDFD_GET_USER_NAMESPACE);
        if (o->mntfd < 0 || o->netfd < 0 || o->pidnsfd < 0 || o->userfd < 0 ||
            identity_fd(o->mntfd, &o->mnt) < 0 || identity_fd(o->netfd, &o->net) < 0 ||
            identity_fd(o->pidnsfd, &o->pidns) < 0 || identity_fd(o->userfd, &o->user) < 0 ||
            identity_path(netns, &expected_net) < 0 || !same_identity(o->net, expected_net) ||
            !pidfd_alive(o->pidfd)) goto fail;
        if (pidfd_info(o->pidfd, &second) < 0 || second.pid != first.pid ||
            second.tgid != first.tgid || second.ppid != first.ppid ||
            second.cgroup_id != first.cgroup_id || !exact_cgroup(pid, cgroup) ||
            !pidfd_alive(o->pidfd)) goto fail;
        return 0;
fail:
        close_observation(o);
        return -1;
}

static int candidates_file(const char *path, pid_t supervisor, pid_t *candidate, int *count,
                           struct budget *budget) {
        FILE *stream = fopen(path, "re");
        char line[64];
        if (!stream) return -1;
        while (fgets(line, sizeof(line), stream)) {
                char *end;
                long value;
                bool nested_one = false;
                size_t length = strlen(line);
                if (charge(budget, &budget->candidates, MAX_CANDIDATES, length) < 0) {
                        (void) fclose(stream);
                        return -1;
                }
                errno = 0;
                value = strtol(line, &end, 10);
                if (errno != 0 || end == line || (*end != '\n' && *end != '\0')) {
                        (void) fclose(stream);
                        return -1;
                }
                if (value <= 0 || value > INT_MAX ||
                    read_status((pid_t) value, 0, &nested_one, budget) < 0) {
                        (void) fclose(stream);
                        return -1;
                }
                if (nested_one) {
                        *candidate = (pid_t) value;
                        (*count)++;
                }
        }
        if (ferror(stream)) { (void) fclose(stream); return -1; }
        (void) supervisor;
        return fclose(stream);
}

static int scan_tree(const char *path, pid_t supervisor, pid_t *candidate, int *count,
                     unsigned depth, struct budget *budget) {
        DIR *dir;
        struct dirent *entry;
        char child[MAX_PATH];
        if (depth > MAX_DEPTH || charge(budget, &budget->directories, MAX_DIRECTORIES, strlen(path)) < 0)
                return -1;
        dir = opendir(path);
        if (!dir) return -1;
        errno = 0;
        while ((entry = readdir(dir)) != NULL) {
                struct stat st = { 0 };
                int written;
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                if (charge(budget, &budget->entries, MAX_DIRECTORY_ENTRIES, strlen(entry->d_name)) < 0) {
                        (void) closedir(dir);
                        return -1;
                }
                written = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
                if (written < 0 || (size_t) written >= sizeof(child)) { (void) closedir(dir); return -1; }
                if (!strcmp(entry->d_name, "cgroup.procs")) {
                        if (candidates_file(child, supervisor, candidate, count, budget) < 0) { (void) closedir(dir); return -1; }
                } else {
                        if (lstat(child, &st) < 0) { (void) closedir(dir); return -1; }
                        if (S_ISDIR(st.st_mode) && scan_tree(child, supervisor, candidate, count, depth + 1, budget) < 0) {
                                (void) closedir(dir); return -1;
                        }
                }
                errno = 0;
        }
        if (errno != 0) { (void) closedir(dir); return -1; }
        return closedir(dir);
}

static int discover(const char *cgroup, pid_t supervisor, pid_t *candidate, struct budget *budget) {
        char path[MAX_PATH];
        int count = 0;
        int written = snprintf(path, sizeof(path), "/sys/fs/cgroup%s", cgroup);
        if (written < 0 || (size_t) written >= sizeof(path) ||
            scan_tree(path, supervisor, candidate, &count, 0, budget) < 0)
                return -1;
        return count;
}

static int read_generation(const char *path, unsigned long *generation) {
        FILE *stream = fopen(path, "re");
        char newline;
        int valid;
        if (!stream) return -1;
        valid = fscanf(stream, "%lu%c", generation, &newline) == 2 && newline == '\n' &&
                fgetc(stream) == EOF;
        if (fclose(stream) != 0) valid = 0;
        return valid ? 0 : -1;
}

static int report(const char *path, const char *state, unsigned long generation,
                  const struct observation *old, const struct observation *cur) {
        char temporary[MAX_PATH];
        FILE *stream;
        int valid;
        int written = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
        if (written < 0 || (size_t) written >= sizeof(temporary)) return -1;
        stream = fopen(temporary, "we");
        if (!stream) return -1;
        valid = fprintf(stream,
                    "{\"state\":\"%s\",\"boot_generation\":%lu,\"old_pid\":%ld,\"pid\":%ld,"
                    "\"root\":{\"device\":%llu,\"inode\":%llu},"
                    "\"mount_namespace\":{\"device\":%llu,\"inode\":%llu},"
                    "\"network_namespace\":{\"device\":%llu,\"inode\":%llu},"
                    "\"pid_namespace\":{\"device\":%llu,\"inode\":%llu},"
                    "\"user_namespace\":{\"device\":%llu,\"inode\":%llu}}\n",
                    state, generation, old ? (long) old->pid : 0L, (long) cur->pid,
                    cur->root.device, cur->root.inode, cur->mnt.device, cur->mnt.inode,
                    cur->net.device, cur->net.inode, cur->pidns.device, cur->pidns.inode,
                    cur->user.device, cur->user.inode) >= 0;
        if (valid && fflush(stream) != 0) valid = 0;
        if (valid && fsync(fileno(stream)) != 0) valid = 0;
        if (fclose(stream) != 0) valid = 0;
        if (!valid) { (void) unlink(temporary); return -1; }
        if (rename(temporary, path) < 0) {
                (void) unlink(temporary);
                return -1;
        }
        return 0;
}

int main(int argc, char **argv) {
        struct observation old = { .pidfd = -1, .rootfd = -1, .cgroupfd = -1, .mntfd = -1, .netfd = -1, .pidnsfd = -1, .userfd = -1 };
        struct observation cur = { .pidfd = -1, .rootfd = -1, .cgroupfd = -1, .mntfd = -1, .netfd = -1, .pidnsfd = -1, .userfd = -1 };
        struct supervisor pinned = { .pidfd = -1, .exefd = -1, .cgroupfd = -1 };
        struct budget budget;
        struct timespec interval = { .tv_sec = 0, .tv_nsec = 100000000L };
        sigset_t signals;
        char *end;
        long supervisor;
        unsigned long generation = 0;
        int received, result;
        pid_t candidate = 0;
        if (argc != 10) return EXIT_FAILURE;
        errno = 0; supervisor = strtol(argv[1], &end, 10);
        if (errno || *argv[1] == '\0' || *end || supervisor <= 0 || supervisor > INT_MAX) return EXIT_FAILURE;
        if (sigemptyset(&signals) < 0 || sigaddset(&signals, SIGUSR1) < 0 ||
            sigprocmask(SIG_BLOCK, &signals, NULL) < 0) goto fail;
        if (pin_supervisor((pid_t) supervisor, argv[6], argv[5], argv[9], &pinned) < 0 ||
            start_budget(&budget, DISCOVERY_SECONDS) < 0) goto fail;
        reset_scan_work(&budget);
        result = discover(argv[4], (pid_t) supervisor, &candidate, &budget);
        if (result != 1 || observe(candidate, (pid_t) supervisor, argv[2], argv[3], argv[4], &cur) < 0 ||
            !supervisor_alive(&pinned, argv[5], argv[9]) ||
            read_generation(argv[7], &generation) < 0 || generation != 1 ||
            report(argv[8], "observing", generation, NULL, &cur) < 0) goto fail;
        if (sigwait(&signals, &received) != 0 || received != SIGUSR1) goto fail;
        if (!supervisor_alive(&pinned, argv[5], argv[9])) goto fail;
        if (!pidfd_alive(cur.pidfd) || syscall(SYS_pidfd_send_signal, cur.pidfd, SIGRTMIN + 5, NULL, 0U) < 0) goto fail;
        old = cur;
        cur = (struct observation) { .pidfd = -1, .rootfd = -1, .cgroupfd = -1, .mntfd = -1, .netfd = -1, .pidnsfd = -1, .userfd = -1 };
        if (start_budget(&budget, DISCOVERY_SECONDS) < 0) goto fail;
        while (before_deadline(&budget)) {
                candidate = 0;
                reset_scan_work(&budget);
                result = discover(argv[4], (pid_t) supervisor, &candidate, &budget);
                if (result < 0) goto fail;
                if (result == 1 && candidate != old.pid &&
                    observe(candidate, (pid_t) supervisor, argv[2], argv[3], argv[4], &cur) == 0 &&
                    read_generation(argv[7], &generation) == 0 && generation == 2) break;
                close_observation(&cur);
                if (nanosleep(&interval, NULL) < 0 && errno != EINTR) goto fail;
        }
        if (cur.pidfd < 0 || pidfd_alive(old.pidfd) || !pidfd_alive(cur.pidfd) ||
            !supervisor_alive(&pinned, argv[5], argv[9]) ||
            same_identity(old.mnt, cur.mnt) ||
            same_identity(old.pidns, cur.pidns) || same_identity(old.user, cur.user) ||
            !same_identity(old.net, cur.net) || !same_identity(old.root, cur.root) ||
            report(argv[8], "rebooted", generation, &old, &cur) < 0) goto fail;
        for (;;) pause();
fail:
        fprintf(stderr, "nspawn host observer validation or lifecycle proof failed\n");
        close_observation(&cur);
        close_observation(&old);
        close_supervisor(&pinned);
        return EXIT_FAILURE;
}
