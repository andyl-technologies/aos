/* Opens one fixed inspector socket for the enforcing-MAC VM qualification. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void)
{
    static const char path[] =
        "/run/aos/sandbox-network-namespace-inspector/control.sock";
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int socket_fd;
    int connected;

    if (sizeof(path) > sizeof(address.sun_path))
        return 1;
    memcpy(address.sun_path, path, sizeof(path));

    socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (socket_fd < 0) {
        perror("inspector qualification socket");
        return 1;
    }

    connected = connect(socket_fd, (const struct sockaddr *)&address,
                        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + sizeof(path)));
    if (connected == 0)
        sleep(2);
    else
        perror("inspector qualification connect");

    if (close(socket_fd) != 0)
        return 1;
    return connected == 0 ? 0 : 1;
}
