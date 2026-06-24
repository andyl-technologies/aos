#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *stream) {
    fputs("usage: aos-selinux-run --context CONTEXT -- COMMAND [ARG...]\n",
          stream);
}

static int write_full(int fd, const char *buffer, size_t length) {
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }

    return 0;
}

int main(int argc, char **argv) {
    const char *context = NULL;
    int command_index = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            command_index = i + 1;
            break;
        }
        if (strcmp(argv[i], "--context") == 0) {
            if (i + 1 >= argc) {
                fputs("aos-selinux-run: --context requires a value\n",
                      stderr);
                usage(stderr);
                return 2;
            }
            context = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        }
        fprintf(stderr, "aos-selinux-run: unknown argument '%s'\n", argv[i]);
        usage(stderr);
        return 2;
    }

    if (context == NULL || context[0] == '\0') {
        fputs("aos-selinux-run: missing SELinux context\n", stderr);
        usage(stderr);
        return 2;
    }
    if (command_index <= 0 || command_index >= argc) {
        fputs("aos-selinux-run: missing command after --\n", stderr);
        usage(stderr);
        return 2;
    }

    int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr,
                "aos-selinux-run: failed to open /proc/self/attr/current: %s\n",
                strerror(errno));
        return 126;
    }

    size_t context_len = strlen(context) + 1;
    if (write_full(fd, context, context_len) < 0) {
        fprintf(stderr,
                "aos-selinux-run: failed to set SELinux context '%s': %s\n",
                context, strerror(errno));
        close(fd);
        return 126;
    }
    if (close(fd) < 0) {
        fprintf(stderr,
                "aos-selinux-run: failed to close /proc/self/attr/current: %s\n",
                strerror(errno));
        return 126;
    }

    execvp(argv[command_index], &argv[command_index]);
    fprintf(stderr, "aos-selinux-run: failed to exec '%s': %s\n",
            argv[command_index], strerror(errno));
    return errno == ENOENT ? 127 : 126;
}
