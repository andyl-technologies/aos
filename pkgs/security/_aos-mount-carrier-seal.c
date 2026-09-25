// SPDX-License-Identifier: Apache-2.0
// Seal and measure one exact executable inode in the carrier build guest.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SHA256_BYTES 32U

static int fail(const char *operation) {
    fprintf(stderr, "Mount carrier sealing failed: %s: %s\n", operation, strerror(errno));
    return 1;
}

int main(int argc, char **argv) {
    struct fsverity_enable_arg enable = {
        .version = 1,
        .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
        .block_size = 4096,
    };
    struct {
        struct fsverity_digest header;
        uint8_t bytes[SHA256_BYTES];
    } measurement = {
        .header.digest_size = SHA256_BYTES,
    };
    struct stat metadata;
    char context[128];
    size_t context_size;
    ssize_t observed_size;
    int descriptor;
    int directory_mode;

    if (argc != 4 || (strcmp(argv[1], "seal") != 0 &&
                      strcmp(argv[1], "measure") != 0 &&
                      strcmp(argv[1], "directory") != 0)) {
        fprintf(stderr, "usage: aos-mount-carrier-seal seal|measure|directory PATH SELINUX_CONTEXT\n");
        return 2;
    }
    directory_mode = strcmp(argv[1], "directory") == 0;

    descriptor = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                                   (directory_mode ? O_DIRECTORY : 0));
    if (descriptor < 0)
        return fail("open carrier inode");
    if (fstat(descriptor, &metadata) < 0)
        return fail("stat carrier inode");
    if (metadata.st_uid != 0 || metadata.st_gid != 0 ||
        (directory_mode
             ? !S_ISDIR(metadata.st_mode) || (metadata.st_mode & 07777) != 0755
             : !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
                   (metadata.st_mode & 07777) != 0555 || metadata.st_size <= 0)) {
        errno = EPERM;
        return fail("carrier inode metadata");
    }

    context_size = strlen(argv[3]);
    if (context_size == 0 || context_size >= sizeof(context)) {
        errno = EINVAL;
        return fail("expected SELinux context");
    }
    observed_size = fgetxattr(descriptor, "security.selinux", context, sizeof(context));
    if (observed_size != (ssize_t)context_size ||
        memcmp(context, argv[3], context_size) != 0) {
        errno = EPERM;
        return fail("carrier SELinux context");
    }

    if (directory_mode) {
        if (close(descriptor) < 0)
            return fail("close carrier directory");
        return 0;
    }

    if (strcmp(argv[1], "seal") == 0) {
        if (fsync(descriptor) < 0)
            return fail("sync executable before sealing");
        if (ioctl(descriptor, FS_IOC_ENABLE_VERITY, &enable) < 0)
            return fail("enable fs-verity");
    }
    if (ioctl(descriptor, FS_IOC_MEASURE_VERITY, &measurement) < 0)
        return fail("measure fs-verity");
    if (measurement.header.digest_algorithm != FS_VERITY_HASH_ALG_SHA256 ||
        measurement.header.digest_size != SHA256_BYTES) {
        errno = EPROTO;
        return fail("fs-verity measurement profile");
    }

    for (size_t index = 0; index < SHA256_BYTES; index++)
        printf("%02x", measurement.bytes[index]);
    putchar('\n');
    if (close(descriptor) < 0)
        return fail("close executable");
    return 0;
}
