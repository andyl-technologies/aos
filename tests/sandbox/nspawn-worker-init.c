/* SPDX-License-Identifier: Apache-2.0 */
/* Checks the first payload exec boundary before starting guest systemd. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef AOS_QUALIFICATION_SYSTEMD
#error "The fixture must pin the AOS guest systemd executable"
#endif

static uint64_t read_be64(const unsigned char *bytes) {
    uint64_t value = 0;

    for (size_t index = 0; index < 8; index++) {
        value = (value << 8) | bytes[index];
    }

    return value;
}

int main(int argc, char **argv) {
    struct rlimit limit;
    struct statvfs store;
    struct stat provisioning = {0};

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
    errno = 0;
    if (reboot(RB_DISABLE_CAD) != -1 || errno != EPERM) {
        fputs("guest reboot probe did not receive its nonfatal denial\n", stderr);
        return EXIT_FAILURE;
    }

    /* The production directory profile requires three input Guest roles.
     * This worker-only fixture receives deliberately invalid credential bytes,
     * checks the actual first-exec handoff, then closes them. It does not run or
     * authenticate the production Agent. Setup roles must never reach PID 1. */
    for (int fd = 3; fd <= 5; fd++) {
        struct stat identity;
        if (fstat(fd, &identity) < 0) {
            perror("fixed Guest descriptor");
            return EXIT_FAILURE;
        }

        if (fd == 3) {
            int type;
            socklen_t length = sizeof(type);
            if (!S_ISSOCK(identity.st_mode) ||
                getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0 ||
                length != sizeof(type) || type != SOCK_SEQPACKET) {
                fputs("Guest channel is not a sequence-packet socket\n", stderr);
                return EXIT_FAILURE;
            }
        } else {
            int required = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
            int seals = fcntl(fd, F_GET_SEALS);
            if (!S_ISREG(identity.st_mode) || identity.st_size != (fd == 4 ? 258 : 152) ||
                seals < 0 || (seals & required) != required) {
                fputs("Guest fixture credential shape or seals differ\n", stderr);
                return EXIT_FAILURE;
            }
        }
        if (fd == 4) {
            provisioning = identity;
        }
    }

    /* nspawn also delivers the payload's actual cgroup directory and a sealed
     * record binding it to the same provisioning inode. These are explicit
     * Guest roles, not leaked supervisor setup descriptors. */
    struct stat cgroup, visible_cgroup, binding;
    struct statfs cgroup_filesystem;
    unsigned char record[48];
    int required_seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    int binding_seals = fcntl(7, F_GET_SEALS);
    int cgroup_flags = fcntl(6, F_GETFL);

    if (fstat(6, &cgroup) < 0 || stat("/sys/fs/cgroup", &visible_cgroup) < 0 ||
        fstatfs(6, &cgroup_filesystem) < 0 || !S_ISDIR(cgroup.st_mode) ||
        cgroup.st_uid != 0 || (cgroup.st_mode & 0022) != 0 ||
        cgroup_filesystem.f_type != 0x63677270 || cgroup_flags < 0 ||
        (cgroup_flags & O_ACCMODE) != O_RDONLY ||
        cgroup.st_dev != visible_cgroup.st_dev || cgroup.st_ino != visible_cgroup.st_ino) {
        fputs("Guest cgroup descriptor differs from its payload hierarchy\n", stderr);
        return EXIT_FAILURE;
    }
    if (fstat(7, &binding) < 0 || !S_ISREG(binding.st_mode) || binding.st_size != 48 ||
        binding_seals < 0 || (binding_seals & required_seals) != required_seals ||
        pread(7, record, sizeof(record), 0) != (ssize_t) sizeof(record) ||
        memcmp(record, "AOSGCG01", 8) != 0 ||
        read_be64(record + 8) != (uint64_t) provisioning.st_dev ||
        read_be64(record + 16) != (uint64_t) provisioning.st_ino ||
        read_be64(record + 24) != (uint64_t) provisioning.st_size ||
        read_be64(record + 32) != (uint64_t) cgroup.st_dev ||
        read_be64(record + 40) != (uint64_t) cgroup.st_ino) {
        fputs("Guest cgroup custody record differs from its retained descriptors\n", stderr);
        return EXIT_FAILURE;
    }

    for (int fd = 3; fd <= 7; fd++) {
        if (close(fd) < 0) {
            perror("close Guest fixture descriptor");
            return EXIT_FAILURE;
        }
    }

    /* Check every slot allowed by the hard limit, including those above the
     * soft limit. This scan opens no directory enumeration descriptor. */
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
