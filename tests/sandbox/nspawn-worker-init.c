/* SPDX-License-Identifier: Apache-2.0 */
/* Checks the first payload exec boundary before starting guest systemd. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <unistd.h>

#ifndef AOS_QUALIFICATION_SYSTEMD
#error "The fixture must pin the AOS guest systemd executable"
#endif

int main(int argc, char **argv) {
    struct rlimit limit;
    struct statvfs store;

    if (argc < 1 || getpid() != 1 || geteuid() != 0) {
        fputs("qualification init is not guest root PID 1\n", stderr);
        return EXIT_FAILURE;
    }
    if (getenv("LISTEN_PID") || getenv("LISTEN_FDS") || getenv("LISTEN_FDNAMES")) {
        fputs("supervisor setup descriptor environment reached guest PID 1\n", stderr);
        return EXIT_FAILURE;
    }
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || limit.rlim_max > 4096) {
        fputs("guest descriptor ceiling exceeds the qualification profile\n", stderr);
        return EXIT_FAILURE;
    }
    if (statvfs("/nix/store", &store) < 0 || !(store.f_flag & ST_RDONLY)) {
        fputs("prepared read-only Nix-store mount did not survive root setup\n", stderr);
        return EXIT_FAILURE;
    }

    /* This fixture requests no payload activation sockets. Check every slot
     * allowed by its hard limit, including slots above the current soft limit.
     * No directory enumeration descriptor is opened during this scan. */
    for (int fd = 3; fd < (int) limit.rlim_max; fd++) {
        errno = 0;
        if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) {
            fprintf(stderr, "unexpected descriptor %d reached guest PID 1\n", fd);
            return EXIT_FAILURE;
        }
    }

    argv[0] = AOS_QUALIFICATION_SYSTEMD;
    execv(AOS_QUALIFICATION_SYSTEMD, argv);
    perror("exec guest systemd");
    return EXIT_FAILURE;
}
