/* SPDX-License-Identifier: Apache-2.0 */

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char *seed_argv[4];
    int fd;

    if (argc != 4)
        return 1;

    do {
        fd = open("/dev/null", O_RDONLY);
        if (fd < 0)
            return 1;
    } while (fd < 300);

    seed_argv[0] = argv[1];
    seed_argv[1] = argv[2];
    seed_argv[2] = argv[3];
    seed_argv[3] = NULL;
    execv(argv[1], seed_argv);
    return 1;
}
