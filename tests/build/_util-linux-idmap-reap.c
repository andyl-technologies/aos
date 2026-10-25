/* Exercises the package's actual ID-map helper with denied failure cleanup. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
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

/* Namespace creation and mapping are injected; socket I/O, fork and reap are real. */
#define unshare fixture_unshare
#define kill fixture_kill
#include IDMAP_SOURCE

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    original_parent = getpid();
    failure_mode = atoi(argv[1]);
    struct list_head mappings = {0};
    int descriptor = get_userns_fd_from_idmap(&mappings);

    if (mapping_attempts != 1 || kill_attempts != (failure_mode == 1))
        return 3;
    if ((descriptor >= 0) != (failure_mode == 0))
        return 4;
    if (descriptor >= 0)
        close(descriptor);

    /* The helper must reap its original child on every tested path. */
    errno = 0;
    if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD)
        return 5;
    return 0;
}
