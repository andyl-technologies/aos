/* SPDX-License-Identifier: Apache-2.0 */
/* Reproduces OpenLDAP's Autoconf working-memcmp test on the target. */

#include <string.h>

int main(void) {
    char c0 = '\100';
    char c1 = '\200';
    char c2 = '\201';
    char first_buffer[21];
    char second_buffer[21];
    int offset;

    /* Some historical memcmp implementations were not 8-bit clean. */
    if (memcmp(&c0, &c2, 1) >= 0 || memcmp(&c1, &c2, 1) >= 0) {
        return 1;
    }

    /* Preserve the upstream unaligned 16-byte comparison coverage. */
    for (offset = 0; offset < 4; offset++) {
        char *first = first_buffer + offset;
        char *second = second_buffer + offset;

        strcpy(first, "--------01111111");
        strcpy(second, "--------10000000");
        if (memcmp(first, second, 16) >= 0) {
            return 1;
        }
    }

    return 0;
}
