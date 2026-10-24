/* SPDX-License-Identifier: Apache-2.0 */
/* A-only fixed specimen PID 1. This is not the production guest bootstrap,
 * Agent, runtime identity or an execution/output API. It keeps the real nspawn
 * maps/capabilities/seccomp profile; it never clears caps to imitate phase0.
 * Readback proves only mechanics on this exact root/executable. Slice B still
 * requires actual production boot and authenticated guest evidence. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int notify_ready(void)
{
    /* This is nspawn's fixed notify plumbing, not an executable/configuration
     * selector. Only its existing container-side notification path is used. */
    const char *path = getenv("NOTIFY_SOCKET");
    /* Pinned systemd 261.2 nspawn.c NSPAWN_NOTIFY_SOCKET_PATH. */
    if (path == NULL || strcmp(path, "/run/host/notify") != 0)
        return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    int channel = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (channel < 0)
        return -1;
    static const char ready[] = "READY=1\nSTATUS=Deployment specimen mechanics only";
    ssize_t sent = sendto(channel, ready, sizeof(ready) - 1, MSG_NOSIGNAL,
        (const struct sockaddr *)&address,
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1));
    close(channel);
    return sent == (ssize_t)(sizeof(ready) - 1) ? 0 : -1;
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || getpid() != 1 || getuid() != 0 || geteuid() != 0
        || prctl(PR_GET_SECCOMP) != 2 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        || close_range(3, ~0U, 0) != 0)
        return EXIT_FAILURE;

    sigset_t events;
    sigemptyset(&events);
    sigaddset(&events, SIGTERM);
    sigaddset(&events, SIGINT);
    sigaddset(&events, SIGCHLD);
    /* This is the pinned nspawn boot-mode stop signal, not guest commands. */
    sigaddset(&events, SIGRTMIN + 3);
    if (sigprocmask(SIG_BLOCK, &events, NULL) != 0 || notify_ready() != 0)
        return EXIT_FAILURE;
    for (;;) {
        int event = 0;
        if (sigwait(&events, &event) != 0)
            return EXIT_FAILURE;
        if (event == SIGTERM || event == SIGINT || event == SIGRTMIN + 3)
            return EXIT_SUCCESS;
        if (event == SIGCHLD) {
            while (waitpid(-1, NULL, WNOHANG) > 0) {}
        }
    }
}
