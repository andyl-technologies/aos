/* Activates one of the fixed Network sockets in the enforcing-MAC VM. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    static const char inspector_path[] =
        "/run/aos/sandbox-network-namespace-inspector/control.sock";
    static const char broker_path[] = "/run/aos/sandbox-network/control.sock";
    static const char lifecycle_path[] =
        "/run/aos/sandbox-network-lifecycle-worker/control.sock";
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const char *path = inspector_path;
    size_t path_length;
    int socket_fd;
    int connected;

    if (argc == 2 && strcmp(argv[1], "--broker") == 0)
        path = broker_path;
    else if (argc == 2 && strcmp(argv[1], "--lifecycle") == 0)
        path = lifecycle_path;
    else if (argc != 1)
        return 2;

    path_length = strlen(path) + 1;
    if (path_length > sizeof(address.sun_path))
        return 1;
    memcpy(address.sun_path, path, path_length);

    socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (socket_fd < 0) {
        perror("Network qualification socket");
        return 1;
    }

    connected = connect(socket_fd, (const struct sockaddr *)&address,
                        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length));
    if (connected == 0)
        sleep(2);
    else
        perror("Network qualification connect");

    if (close(socket_fd) != 0)
        return 1;
    return connected == 0 ? 0 : 1;
}
