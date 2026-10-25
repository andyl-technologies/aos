/* Exercises the package's actual ID-map helper with denied failure cleanup. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct list_head {
    int unused;
};

static pid_t original_parent;
static int failure_mode;
static int mapping_attempts;
static int kill_attempts;

static int fixture_unshare(int flags)
{
    (void)flags;
    return 0;
}

static int fixture_kill(pid_t pid, int signal)
{
    (void)pid;
    (void)signal;
    kill_attempts++;
    errno = EPERM;
    return -1;
}

static int map_ids(struct list_head *idmap, pid_t pid)
{
    (void)idmap;
    (void)pid;
    mapping_attempts++;
    if (failure_mode == 1) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static ssize_t read_all(int fd, void *buffer, size_t count)
{
    return read(fd, buffer, count);
}

static int write_all(int fd, const void *buffer, size_t count)
{
    if (failure_mode == 2 && getpid() == original_parent) {
        errno = EACCES;
        return -1;
    }
    return write(fd, buffer, count) == (ssize_t)count ? 0 : -1;
}

/* Reproduce procfs ptrace rejection without restricting the child's own FD. */
static int fixture_open(const char *path, int flags)
{
    if (failure_mode == 3 && getpid() == original_parent &&
        strncmp(path, "/proc/", 6) == 0 && strcmp(path, "/proc/self/ns/user") != 0) {
        errno = EACCES;
        return -1;
    }
    return open(path, flags);
}

static int count_descriptors(void)
{
    int count = 0;

    for (int descriptor = 0; descriptor < 256; descriptor++)
        if (fcntl(descriptor, F_GETFD) >= 0)
            count++;
    return count;
}

/* Namespace creation and mapping are injected; socket I/O, fork and reap are real. */
#define unshare fixture_unshare
#define kill fixture_kill
#define open fixture_open
#include IDMAP_SOURCE
#undef open

#ifdef HAVE_NAMESPACE_FD_HANDOFF
/* Malformed peer messages must reject every received FD without leaking it. */
static int check_namespace_handoff(void)
{
    for (int scenario = 0; scenario < 7; scenario++) {
        int baseline = count_descriptors();
        int channel[2];
        int source = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
        if (source < 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel))
            return 10;

        if (scenario == 0) {
            if (send_userns_fd(channel[0], source))
                return 11;
        } else {
            char ready = scenario == 5 ? '0' : '1';
            int count = scenario == 5 ? 1 : scenario - 1;
            int descriptors[4] = {source, source, source, source};
            struct iovec iov = {.iov_base = &ready, .iov_len = 1};
            union {
                struct cmsghdr alignment;
                char bytes[CMSG_SPACE(sizeof(descriptors))];
            } control = {0};
            struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};

            if (count > 0 && scenario != 6) {
                message.msg_control = control.bytes;
                message.msg_controllen = CMSG_SPACE(count * sizeof(int));
                struct cmsghdr *header = CMSG_FIRSTHDR(&message);
                header->cmsg_level = SOL_SOCKET;
                header->cmsg_type = SCM_RIGHTS;
                header->cmsg_len = CMSG_LEN(count * sizeof(int));
                memcpy(CMSG_DATA(header), descriptors, count * sizeof(int));
            }
            if (scenario != 6 && sendmsg(channel[0], &message, MSG_NOSIGNAL) != 1)
                return 12;
        }
        close(channel[0]);

        errno = 0;
        int received = receive_userns_fd(channel[1]);
        bool valid = scenario == 0 || scenario == 2;
        if (valid) {
            if (received < 0 || !(fcntl(received, F_GETFD) & FD_CLOEXEC))
                return 13;
            close(received);
        } else if (received >= 0 || errno != EPROTO) {
            return 14;
        }

        close(channel[1]);
        close(source);
        if (count_descriptors() != baseline)
            return 15;
    }
    return 0;
}
#endif

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    original_parent = getpid();
    failure_mode = atoi(argv[1]);
    int baseline = count_descriptors();
    struct list_head mappings = {0};
    int descriptor = get_userns_fd_from_idmap(&mappings);

    if (mapping_attempts != 1 || kill_attempts != (failure_mode == 1))
        return 3;
    if ((descriptor >= 0) != (failure_mode == 0 || failure_mode == 3))
        return 4;
    if (descriptor >= 0) {
        if (!(fcntl(descriptor, F_GETFD) & FD_CLOEXEC))
            return 6;
        close(descriptor);
    }
    if (count_descriptors() != baseline)
        return 7;

    /* The helper must reap its original child on every tested path. */
    errno = 0;
    if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD)
        return 5;
#ifdef HAVE_NAMESPACE_FD_HANDOFF
    return check_namespace_handoff();
#else
    return 0;
#endif
}
