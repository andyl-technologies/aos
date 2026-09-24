/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_fchmodat2
#error "fchmodat2 is required for the AOS no-set-ID probe"
#endif

#ifndef PR_GET_AOS_NO_SETID
#define PR_GET_AOS_NO_SETID 83
#endif

#ifndef PR_SET_AOS_NO_SETID
#define PR_SET_AOS_NO_SETID 82
#endif

#if PR_SET_AOS_NO_SETID != 82 || PR_GET_AOS_NO_SETID != 83
#error "AOS no-set-ID prctl value does not match the pinned kernel ABI"
#endif

static int open_relative(int directory, const char *name, int flags, mode_t mode) {
        struct open_how how = {
                .flags = flags,
                .mode = mode,
                .resolve = RESOLVE_BENEATH,
        };

        return syscall(SYS_openat2, directory, name, &how, sizeof(how));
}

static int create_relative(int directory, const char *name, mode_t mode) {
        return open_relative(directory, name, O_WRONLY | O_CREAT | O_EXCL, mode);
}

static int expect_denied(int result, const char *operation) {
        if (result == -1 && errno == EPERM)
                return 0;

        fprintf(stderr, "%s: expected EPERM, got result %d and errno %d\n",
                operation, result, errno);
        return -1;
}

static int expect_creation_denied(int directory, const char *name, mode_t mode) {
        int descriptor = create_relative(directory, name, mode);

        return expect_denied(descriptor, name);
}

static int guard_is_active(void) {
        int enabled = prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL);

        if (enabled == 1)
                return 0;

        fprintf(stderr, "AOS no-set-ID guard is not active: %d, errno %d\n", enabled, errno);
        return -1;
}

static int check_inherited_guard(const char *directory_path) {
        int directory;

        if (guard_is_active() < 0)
                return EXIT_FAILURE;

        directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) {
                perror("open inherited probe directory");
                return EXIT_FAILURE;
        }

        if (expect_creation_denied(directory, "inherited-suid", 04700) < 0)
                return EXIT_FAILURE;

        close(directory);
        printf("AOS_NO_SETID_INHERITED_OK\n");
        return EXIT_SUCCESS;
}

static int check_fork_exec_inheritance(const char *self, const char *directory_path) {
        pid_t child = fork();
        int status;

        if (child < 0) {
                perror("fork");
                return -1;
        }
        if (child == 0) {
                char *const arguments[] = {(char *)self, "--inherited", (char *)directory_path, NULL};

                execv(self, arguments);
                perror("execv");
                _exit(EXIT_FAILURE);
        }

        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                fprintf(stderr, "fork/exec inherited guard probe failed\n");
                return -1;
        }

        return 0;
}

static int check_guarded_operations(const char *self) {
        char directory_path[] = "/tmp/aos-no-setid-XXXXXX";
        int directory, descriptor;

        if (guard_is_active() < 0)
                return EXIT_FAILURE;

        if (!mkdtemp(directory_path)) {
                perror("mkdtemp");
                return EXIT_FAILURE;
        }

        directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) {
                perror("open probe directory");
                return EXIT_FAILURE;
        }

        descriptor = create_relative(directory, "ordinary", 0600);
        if (descriptor < 0) {
                perror("openat2 ordinary creation");
                return EXIT_FAILURE;
        }

        if (fchmod(descriptor, 04700) != -1 || errno != EPERM) {
                fprintf(stderr, "fchmod unexpectedly changed set-ID mode\n");
                return EXIT_FAILURE;
        }

        if (expect_denied(syscall(__NR_fchmodat2, directory, "ordinary", 04700, 0),
                          "fchmodat2 set-ID mode") < 0)
                return EXIT_FAILURE;

        if (expect_creation_denied(directory, "suid", 04700) < 0 ||
            expect_creation_denied(directory, "sgid", 02700) < 0)
                return EXIT_FAILURE;

        if (expect_denied(open_relative(directory, ".", O_TMPFILE | O_RDWR, 04700),
                          "openat2 O_TMPFILE set-ID mode") < 0)
                return EXIT_FAILURE;

        if (expect_denied(mknodat(directory, "fifo", S_IFIFO | 04700, 0),
                          "mknodat set-ID FIFO") < 0)
                return EXIT_FAILURE;

        if (check_fork_exec_inheritance(self, directory_path) < 0)
                return EXIT_FAILURE;

        close(descriptor);
        close(directory);
        printf("AOS_NO_SETID_GUARD_OK\n");
        return EXIT_SUCCESS;
}

static int check_namespace_transition(int namespace_flag, const char *name) {
        pid_t child = fork();
        int status;

        if (child < 0) {
                perror("fork namespace probe");
                return -1;
        }
        if (child == 0) {
                int original = -1;

                if (namespace_flag == CLONE_NEWNS) {
                        original = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
                        if (original < 0) {
                                perror("open original mount namespace");
                                _exit(EXIT_FAILURE);
                        }
                }

                if (unshare(namespace_flag) < 0) {
                        perror(name);
                        _exit(EXIT_FAILURE);
                }
                if (guard_is_active() < 0)
                        _exit(EXIT_FAILURE);

                if (original >= 0) {
                        if (setns(original, namespace_flag) < 0) {
                                perror("setns original mount namespace");
                                _exit(EXIT_FAILURE);
                        }
                        if (guard_is_active() < 0)
                                _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                fprintf(stderr, "%s transition did not preserve the guard\n", name);
                return -1;
        }

        return 0;
}

static int check_direct_kernel_guard(void) {
        char directory_path[] = "/tmp/aos-no-setid-direct-XXXXXX";
        struct stat file_stat;
        int directory, descriptor, sgid_parent;
        int original_fsuid;

        if (prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL) != 0) {
                fprintf(stderr, "root control unexpectedly began with the guard active\n");
                return EXIT_FAILURE;
        }

        if (!mkdtemp(directory_path)) {
                perror("mkdtemp direct guard");
                return EXIT_FAILURE;
        }
        directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) {
                perror("open direct guard directory");
                return EXIT_FAILURE;
        }

        descriptor = create_relative(directory, "suid-control", 04700);
        if (descriptor < 0 || fstat(descriptor, &file_stat) < 0 || !(file_stat.st_mode & S_ISUID)) {
                perror("unguarded SUID creation control");
                return EXIT_FAILURE;
        }
        close(descriptor);

        descriptor = create_relative(directory, "normal-control", 0600);
        if (descriptor < 0) {
                perror("prepare normal mode control");
                return EXIT_FAILURE;
        }
        close(descriptor);

        if (syscall(__NR_fchmodat2, directory, "normal-control", 04700, 0) < 0 ||
            fstatat(directory, "normal-control", &file_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
            !(file_stat.st_mode & S_ISUID) ||
            syscall(__NR_fchmodat2, directory, "normal-control", 0600, 0) < 0) {
                perror("unguarded fchmodat2 control");
                return EXIT_FAILURE;
        }

        descriptor = open_relative(directory, ".", O_TMPFILE | O_RDWR, 0600);
        if (descriptor < 0) {
                perror("unguarded O_TMPFILE control");
                return EXIT_FAILURE;
        }
        close(descriptor);

        if (mknodat(directory, "ordinary-fifo", S_IFIFO | 0600, 0) < 0) {
                perror("unguarded mknodat control");
                return EXIT_FAILURE;
        }

        if (mkdirat(directory, "sgid-parent", 0700) < 0 ||
            fchmodat(directory, "sgid-parent", 02700, 0) < 0) {
                perror("prepare SGID parent");
                return EXIT_FAILURE;
        }
        sgid_parent = openat(directory, "sgid-parent", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (sgid_parent < 0 || fstat(sgid_parent, &file_stat) < 0 || !(file_stat.st_mode & S_ISGID)) {
                perror("verify SGID parent");
                return EXIT_FAILURE;
        }
        if (mkdirat(sgid_parent, "unguarded-child", 0700) < 0 ||
            fstatat(sgid_parent, "unguarded-child", &file_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
            !(file_stat.st_mode & S_ISGID)) {
                perror("unguarded SGID inheritance control");
                return EXIT_FAILURE;
        }

        if (prctl(PR_SET_AOS_NO_SETID, 1UL, 0UL, 0UL, 0UL) < 0 || guard_is_active() < 0) {
                perror("enable direct guard");
                return EXIT_FAILURE;
        }

        if (expect_denied(mkdirat(sgid_parent, "child", 0700), "SGID parent mkdir") < 0 ||
            expect_creation_denied(directory, "direct-suid", 04700) < 0 ||
            expect_creation_denied(directory, "direct-sgid", 02700) < 0 ||
            expect_denied(mknodat(directory, "fifo", S_IFIFO | 04700, 0), "mknodat set-ID FIFO") < 0 ||
            expect_denied(open_relative(directory, ".", O_TMPFILE | O_RDWR, 04700),
                          "openat2 O_TMPFILE set-ID mode") < 0)
                return EXIT_FAILURE;

        if (expect_denied(syscall(__NR_fchmodat2, directory, "normal-control", 04700, 0),
                          "direct fchmodat2 set-ID mode") < 0 ||
            fstatat(directory, "normal-control", &file_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
            (file_stat.st_mode & (S_ISUID | S_ISGID))) {
                fprintf(stderr, "direct fchmodat2 changed the ordinary file mode\n");
                return EXIT_FAILURE;
        }

        original_fsuid = setfsuid(65534);
        if (setfsuid((uid_t)-1) != 65534 || guard_is_active() < 0) {
                fprintf(stderr, "fsuid transition did not preserve the guard\n");
                return EXIT_FAILURE;
        }
        setfsuid((uid_t)original_fsuid);
        if (setfsuid((uid_t)-1) != original_fsuid || guard_is_active() < 0) {
                fprintf(stderr, "restored fsuid did not retain the guard\n");
                return EXIT_FAILURE;
        }

        if (check_namespace_transition(CLONE_NEWNS, "mount namespace") < 0 ||
            check_namespace_transition(CLONE_NEWUSER, "user namespace") < 0)
                return EXIT_FAILURE;

        close(sgid_parent);
        close(directory);
        printf("AOS_NO_SETID_DIRECT_OK\n");
        return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
        if (argc == 1)
                return check_guarded_operations(argv[0]);
        if (argc == 3 && strcmp(argv[1], "--inherited") == 0)
                return check_inherited_guard(argv[2]);
        if (argc == 2 && strcmp(argv[1], "--direct") == 0)
                return check_direct_kernel_guard();

        fprintf(stderr, "invalid no-set-ID guard probe arguments\n");
        return EXIT_FAILURE;
}
