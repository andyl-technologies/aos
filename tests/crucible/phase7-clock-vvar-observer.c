/* SPDX-License-Identifier: Apache-2.0 */
/* Observes published kernel bases while performing an ordinary guest API read. */
#define _GNU_SOURCE

#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <x86intrin.h>

#include "phase7-clock-vvar-layout.h"

enum { ANCHOR_WORDS = 16, MAX_ATTEMPTS = 16, VVAR_PAGES = 6, PAGE_BYTES = 4096 };

struct clock_return {
    int64_t seconds;
    int64_t fraction;
    uint64_t value;
};

static uint64_t ordered_tsc(void)
{
    _mm_lfence();
    uint64_t value = __rdtsc();
    _mm_lfence();
    return value;
}

static void read_barrier(void)
{
    __asm__ volatile("" ::: "memory");
    _mm_lfence();
}

static int snapshot_base(const volatile struct clock_vvar_base *base, uint64_t *words)
{
    uint32_t sequence = base->sequence;
    if (sequence & 1)
        return 0;

    read_barrier();
    words[0] = 1;
    words[1] = sequence;
    words[2] = (uint64_t)base->mode;
    words[3] = base->cycle_last;
    words[4] = base->max_cycles;
    words[5] = base->mask;
    words[6] = base->multiplier;
    words[7] = base->shift;
    words[8] = base->clocks[CLOCK_REALTIME].seconds;
    words[9] = base->clocks[CLOCK_REALTIME].shifted_nanoseconds;
    words[10] = base->clocks[CLOCK_MONOTONIC].seconds;
    words[11] = base->clocks[CLOCK_MONOTONIC].shifted_nanoseconds;
    return 1;
}

static int snapshot_unchanged(const volatile struct clock_vvar_base *base, uint64_t *words)
{
    read_barrier();
    words[15] = base->sequence;
    return words[15] == words[1];
}

static int read_return(const char *clock, struct clock_return *returned)
{
    memset(returned, 0, sizeof(*returned));
    if (!strcmp(clock, "realtime") || !strcmp(clock, "monotonic")) {
        struct timespec value;
        clockid_t id = !strcmp(clock, "realtime") ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        if (clock_gettime(id, &value))
            return -1;
        returned->seconds = value.tv_sec;
        returned->fraction = value.tv_nsec;
    } else if (!strcmp(clock, "gettimeofday")) {
        struct timeval value;
        if (gettimeofday(&value, NULL))
            return -1;
        returned->seconds = value.tv_sec;
        returned->fraction = value.tv_usec;
    } else if (!strcmp(clock, "tsc")) {
        returned->value = ordered_tsc();
    } else {
        return -1;
    }
    return 0;
}

static int observe(const volatile struct clock_vvar_base *base, const char *clock,
                   struct clock_return *returned, uint64_t *words)
{
    for (unsigned attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (!snapshot_base(base, words)) {
            /* Let a writer on another vCPU finish instead of spinning through
             * the bounded attempts within one round-robin quantum. */
            if (sched_yield())
                return -1;
            continue;
        }

        words[12] = ordered_tsc();
        if (read_return(clock, returned))
            return -1;
        words[13] = ordered_tsc();
        if (!snapshot_unchanged(base, words)) {
            if (sched_yield())
                return -1;
            continue;
        }

        /* Other modes and time namespaces require separate source audits. */
        if (words[2] != 1 || sched_getcpu() != 0)
            return -1;
        words[14] = attempt;
        return 0;
    }
    return -1;
}

#ifndef CLOCK_VVAR_UNIT_TEST
int main(int argc, char **argv)
{
    struct utsname kernel;
    unsigned long image = getauxval(AT_SYSINFO_EHDR);
    if (argc != 2 || uname(&kernel) || strcmp(kernel.release, "7.2.3") ||
        getauxval(AT_PAGESZ) != PAGE_BYTES || image < VVAR_PAGES * PAGE_BYTES ||
        sched_getcpu() != 0) {
        fputs("clock VVAR observer: kernel/layout/CPU guard refused\n", stderr);
        return 1;
    }

    /* The audited x86 mapper places the time page six pages before the image. */
    const volatile struct clock_vvar_base *base =
        (const volatile struct clock_vvar_base *)(image - VVAR_PAGES * PAGE_BYTES);
    struct clock_return returned;
    uint64_t words[ANCHOR_WORDS];
    if (observe(base, argv[1], &returned, words)) {
        fputs("clock VVAR observer: coherent TSC observation refused\n", stderr);
        return 1;
    }

    /* A private bounded scalar record; the Rust guest owns SDK marker encoding. */
    printf("%" PRId64 " %" PRId64 " %" PRIu64, returned.seconds, returned.fraction, returned.value);
    for (unsigned index = 0; index < ANCHOR_WORDS; ++index)
        printf(" %" PRIu64, words[index]);
    putchar('\n');
    return ferror(stdout) ? 1 : 0;
}
#endif
