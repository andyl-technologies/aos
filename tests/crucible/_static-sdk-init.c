/* SPDX-License-Identifier: Apache-2.0 */
/* Provides ordinary Linux devices before replacing PID1 with the SDK guest. */
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc;

    /* The initramfs already contains /dev; devtmpfs supplies /dev/null. */
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") != 0) {
        perror("SDK guest init: mount devtmpfs");
        return 1;
    }

    /* exec preserves PID1, kernel-provided environment, argv and stdio. */
    execv("/sdk-init", argv);
    perror("SDK guest init: exec /sdk-init");
    return 1;
}
