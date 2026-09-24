/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_GET_AOS_NO_SETID
#define PR_GET_AOS_NO_SETID 83
#endif

#if PR_GET_AOS_NO_SETID != 83
#error "AOS no-set-ID prctl value does not match the pinned kernel ABI"
#endif

static int create_relative(int directory, const char *name, mode_t mode) {
        struct open_how how = {
                .flags = O_WRONLY | O_CREAT | O_EXCL,
                .mode = mode,
                .resolve = RESOLVE_BENEATH,
        };

        return syscall(SYS_openat2, directory, name, &how, sizeof(how));
}

static int expect_creation_denied(int directory, const char *name, mode_t mode) {
        int descriptor = create_relative(directory, name, mode);

        if (descriptor >= 0) {
                close(descriptor);
                fprintf(stderr, "openat2 unexpectedly created %s with set-ID mode\n", name);
                return -1;
        }
        if (errno != EPERM) {
                perror("openat2 set-ID creation");
                return -1;
        }

        return 0;
}

int main(void) {
        char directory_path[] = "/tmp/aos-no-setid-XXXXXX";
        int directory, descriptor;

        if (prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL) != 1) {
                fprintf(stderr, "AOS no-set-ID guard is not active\n");
                return EXIT_FAILURE;
        }

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

        if (expect_creation_denied(directory, "suid", 04700) < 0 ||
            expect_creation_denied(directory, "sgid", 02700) < 0)
                return EXIT_FAILURE;

        close(descriptor);
        close(directory);
        printf("AOS_NO_SETID_GUARD_OK\n");
        return EXIT_SUCCESS;
}
