/* SPDX-License-Identifier: Apache-2.0 */
/* One host process exercises the evaluated runner; it never launches a VM. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    const char *mode = getenv("HEADLESS_CONTROL_MODE");
    const char *pid_path = getenv("HEADLESS_CONTROL_PID");
    if (!mode || !pid_path)
        return 2;

    FILE *pid_file = fopen(pid_path, "w");
    if (!pid_file)
        return 3;
    if (fprintf(pid_file, "%ld\n", (long)getpid()) < 0 || fclose(pid_file))
        return 4;

    if (!strcmp(mode, "sentinel")) {
        for (;;)
            pause();
    }
    if (!strcmp(mode, "no-marker"))
        return 0;
    if (!strcmp(mode, "slow-pass")) {
        struct timespec delay = { .tv_sec = 3, .tv_nsec = 0 };
        while (nanosleep(&delay, &delay))
            ;
    }

    puts("TEST_RESULT:PASS");
    fflush(stdout);
    if (!strcmp(mode, "nonzero"))
        return 7;
    if (!strcmp(mode, "contradictory")) {
        puts("TEST_RESULT:FAIL");
        return 0;
    }
    if (!strcmp(mode, "ignore-term"))
        signal(SIGTERM, SIG_IGN);
    if (!strcmp(mode, "hang") || !strcmp(mode, "ignore-term")) {
        for (;;)
            pause();
    }
    return strcmp(mode, "pass") && strcmp(mode, "slow-pass") ? 5 : 0;
}
