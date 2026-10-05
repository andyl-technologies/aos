/* SPDX-License-Identifier: Apache-2.0 */
/* A real exec target with no SDK or doorbell; its parent authenticates bytes. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "out-probe-no-sdk-v1"))
        return 2;

    return fputs("out-probe-child-v1\n", stdout) < 0 ? 3 : 0;
}
