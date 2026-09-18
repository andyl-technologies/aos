/* SPDX-License-Identifier: Apache-2.0 */
/* Verifies that the cross runner preserves loader and executable identity. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int aos_origin_library_value(void);

int main(int argc, char **argv) {
    char executable[4096];
    ssize_t length;

    if (argc != 1) {
        fputs("cross runner origin probe received unexpected arguments\n", stderr);
        return 30;
    }
    if (aos_origin_library_value() != 73) {
        fputs("cross runner did not load the sibling $ORIGIN library\n", stderr);
        return 31;
    }

    length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length < 0 || (size_t)length >= sizeof(executable)) {
        fputs("cross runner could not resolve /proc/self/exe\n", stderr);
        return 32;
    }
    executable[length] = '\0';
    if (strcmp(executable, argv[0]) != 0) {
        fprintf(stderr, "cross runner changed executable identity: %s != %s\n",
                executable, argv[0]);
        return 33;
    }

    puts("AOS cross runner origin probe passed");
    return 0;
}
