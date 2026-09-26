#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int require_self_network_namespace(void)
{
    struct stat metadata;
    int descriptor;

    descriptor = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        fprintf(stderr,
            "network lifecycle Landlock probe: self Network namespace open failed: %s\n",
            strerror(errno));
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0) {
        fprintf(stderr,
            "network lifecycle Landlock probe: self Network namespace stat failed: %s\n",
            strerror(errno));
        close(descriptor);
        return -1;
    }
    close(descriptor);
    return 0;
}

static int require_denied(const char *path)
{
    int descriptor;
    int denied_errno;

    errno = 0;
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    denied_errno = errno;
    if (descriptor >= 0) {
        close(descriptor);
        fprintf(stderr,
            "network lifecycle Landlock probe: unexpectedly opened %s\n",
            path);
        return -1;
    }
    if (denied_errno != EACCES) {
        fprintf(stderr,
            "network lifecycle Landlock probe: %s failed with %s instead of EACCES\n",
            path, strerror(denied_errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int index;

    if (argc != 6) {
        fprintf(stderr,
            "usage: network-lifecycle-landlock-probe AUTHORITY STATE CREDENTIAL PROC_ROOT PROC_FD\n");
        return 2;
    }
    if (require_self_network_namespace() != 0) {
        return 1;
    }
    for (index = 1; index < argc; index++) {
        if (require_denied(argv[index]) != 0) {
            return 1;
        }
    }

    fprintf(stderr, "LIFECYCLE_LANDLOCK_OK\n");
    return 0;
}
