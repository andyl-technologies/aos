/* SPDX-License-Identifier: Apache-2.0 */
/* Verifies the explicit AArch64 cross runner's argv and environment contract. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const loader_environment[] = {
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_PROFILE",
    "LD_ORIGIN_PATH",
};

int main(int argc, char **argv) {
    size_t index;

    if (argc != 3 || strcmp(argv[1], "first argument") != 0 ||
        strcmp(argv[2], "second argument") != 0) {
        fputs("cross runner did not preserve target arguments\n", stderr);
        return 20;
    }
    if (strstr(argv[0], "linux-cross-runner-") == NULL) {
        fputs("cross runner did not preserve target argv[0]\n", stderr);
        return 22;
    }

    for (index = 0;
         index < sizeof(loader_environment) / sizeof(loader_environment[0]);
         index++) {
        if (getenv(loader_environment[index]) != NULL) {
            fprintf(stderr, "cross runner leaked %s to the target\n",
                    loader_environment[index]);
            return 21;
        }
    }

    puts("AOS cross runner probe passed");
    return 37;
}
