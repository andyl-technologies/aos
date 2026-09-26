/* SPDX-License-Identifier: Apache-2.0 */
/* Reproduces MIT Kerberos 1.22.1's configure.ac positional printf probe. */
#include <stdio.h>
#include <string.h>
const char expected[] = "200 100";
int main()
{
    char buf[30];
    sprintf(buf, "%2$x %1$d", 100, 512);
    if (strcmp(expected, buf)) {
        fprintf(stderr, "bad result: <%s> wanted: <%s>\n",
                buf, expected);
        return 1;
    }
    return 0;
}
