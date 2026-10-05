/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Check that sampling reaches a CPU worker with QEMU-like inherited masks. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static void *busy_worker(void *unused)
{
    struct timespec start, now;
    volatile uint64_t value = 1;

    (void)unused;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        for (unsigned int index = 0; index < 100000; index++) {
            value = value * UINT64_C(6364136223846793005) + 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec - start.tv_sec +
             (now.tv_nsec - start.tv_nsec) / 1e9 < 2.0);
    return NULL;
}

int main(void)
{
    pthread_t worker;
    sigset_t blocked, original;

    sigfillset(&blocked);
    sigdelset(&blocked, SIGSEGV);
    sigdelset(&blocked, SIGFPE);
    sigdelset(&blocked, SIGILL);
    if (pthread_sigmask(SIG_SETMASK, &blocked, &original) != 0 ||
        pthread_create(&worker, NULL, busy_worker, NULL) != 0 ||
        pthread_sigmask(SIG_SETMASK, &original, NULL) != 0 ||
        pthread_join(worker, NULL) != 0) {
        return 1;
    }
    puts("PASS");
    return 0;
}
