#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#define SENTINEL_DESCRIPTOR 9

static int retain_sentinel(const char *path)
{
    int source;

    source = open(path, O_RDONLY | O_CLOEXEC);
    if (source < 0) {
        fprintf(stderr, "network lifecycle sentinel: open failed: %s\n",
            strerror(errno));
        return -1;
    }
    if (source != SENTINEL_DESCRIPTOR) {
        if (dup3(source, SENTINEL_DESCRIPTOR, O_CLOEXEC) < 0) {
            fprintf(stderr, "network lifecycle sentinel: dup3 failed: %s\n",
                strerror(errno));
            close(source);
            return -1;
        }
        close(source);
    }
    return 0;
}

static int publish_pid(const char *path)
{
    char text[32];
    int descriptor;
    int length;
    ssize_t written;

    descriptor = open(path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        fprintf(stderr, "network lifecycle sentinel: PID file open failed: %s\n",
            strerror(errno));
        return -1;
    }
    length = snprintf(text, sizeof(text), "%ld\n", (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(text)) {
        close(descriptor);
        return -1;
    }
    written = write(descriptor, text, (size_t)length);
    if (written != (ssize_t)length || fsync(descriptor) != 0
        || close(descriptor) != 0) {
        fprintf(stderr, "network lifecycle sentinel: PID file write failed: %s\n",
            strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
            "usage: network-lifecycle-sentinel-holder SENTINEL PID_FILE\n");
        return 2;
    }
    if (getuid() != 0 || geteuid() != 0) {
        fprintf(stderr, "network lifecycle sentinel: root identity required\n");
        return 1;
    }
    if (retain_sentinel(argv[1]) != 0) {
        return 1;
    }
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "network lifecycle sentinel: PR_SET_DUMPABLE failed: %s\n",
            strerror(errno));
        return 1;
    }
    if (publish_pid(argv[2]) != 0) {
        return 1;
    }

    for (;;) {
        pause();
    }
}
