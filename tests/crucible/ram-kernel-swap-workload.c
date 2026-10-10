/* SPDX-License-Identifier: Apache-2.0 */
/* Ordinary guest userspace: nonzero page materialization and fixed sweeps. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

enum { PAGE_BYTES = 4096, WORKING_MIB = 384, SWEEPS = 32 };

static int prepare_console(void)
{
    /* Initramfs PID 1 may inherit no standard descriptors. Only guest init mounts. */
    if (getpid() != 1) {
        return 0;
    }
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL) != 0) {
        return -1;
    }
    int console = open("/dev/ttyS0", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (console < 0) {
        return -1;
    }
    if (dup2(console, STDOUT_FILENO) < 0 || dup2(console, STDERR_FILENO) < 0
        || fcntl(STDOUT_FILENO, F_SETFD, 0) < 0 || fcntl(STDERR_FILENO, F_SETFD, 0) < 0) {
        if (console > STDERR_FILENO) {
            close(console);
        }
        return -1;
    }
    return console > STDERR_FILENO ? close(console) : 0;
}

static uint64_t word(size_t page, unsigned round, unsigned edge)
{
    /* Odd values cannot alias the kernel's shared zero page. */
    return ((UINT64_C(42) ^ ((uint64_t)page << 20) ^
             ((uint64_t)round << 4) ^ ((uint64_t)edge << 1)) << 1) | 1;
}

static void write_pages(volatile uint64_t *memory, size_t pages, unsigned round)
{
    for (size_t page = 0; page < pages; page++) {
        size_t first = page * (PAGE_BYTES / sizeof(uint64_t));
        memory[first] = word(page, round, 0);
        memory[first + PAGE_BYTES / sizeof(uint64_t) - 1] = word(page, round, 1);
    }
}

static int verify_pages(volatile uint64_t *memory, size_t pages, unsigned round,
                        uint64_t *checksum)
{
    uint64_t result = 0;
    for (size_t page = 0; page < pages; page++) {
        size_t first = page * (PAGE_BYTES / sizeof(uint64_t));
        uint64_t left = memory[first];
        uint64_t right = memory[first + PAGE_BYTES / sizeof(uint64_t) - 1];
        if (left != word(page, round, 0) || right != word(page, round, 1)) {
            return -1;
        }
        result = (result << 7) | (result >> 57);
        result ^= left ^ (right << 1);
    }
    *checksum = result;
    return 0;
}

static int run(int self_test)
{
    if (!self_test && prepare_console() != 0) {
        return 1;
    }
    size_t bytes = self_test ? 3 * PAGE_BYTES : (size_t)WORKING_MIB << 20;
    size_t pages = bytes / PAGE_BYTES;
    volatile uint64_t *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        perror("workload mmap");
        return 1;
    }
    if (madvise((void *)memory, bytes, MADV_NOHUGEPAGE) != 0) {
        perror("workload base-page policy");
        munmap((void *)memory, bytes);
        return 1;
    }

    uint64_t checksum = 0;
    write_pages(memory, pages, 0);
    if (verify_pages(memory, pages, 0, &checksum) != 0) {
        fprintf(stderr, "materialization verification failed\n");
        munmap((void *)memory, bytes);
        return 1;
    }
    if (self_test) {
        memory[PAGE_BYTES / sizeof(uint64_t)] ^= 2;
        if (verify_pages(memory, pages, 0, &checksum) == 0) {
            munmap((void *)memory, bytes);
            return 1;
        }
        write_pages(memory, pages, 0);
    } else {
        if (printf("KERNEL_SWAP_MATERIALIZED bytes=%zu pages=%zu seed=42 checksum=%016" PRIx64 "\n",
                   bytes, pages, checksum) < 0 || fflush(stdout) != 0) {
            perror("materialization marker");
            munmap((void *)memory, bytes);
            return 1;
        }
    }

    for (unsigned round = 1; round <= SWEEPS; round++) {
        if (!self_test) {
            struct timespec remaining = { .tv_sec = 0, .tv_nsec = 1000000 };
            while (nanosleep(&remaining, &remaining) != 0) {
                if (errno != EINTR) {
                    perror("workload virtual timer");
                    munmap((void *)memory, bytes);
                    return 1;
                }
            }
        }
        if (verify_pages(memory, pages, round - 1, &checksum) != 0) {
            fprintf(stderr, "sweep predecessor verification failed\n");
            munmap((void *)memory, bytes);
            return 1;
        }
        write_pages(memory, pages, round);
        if (verify_pages(memory, pages, round, &checksum) != 0) {
            fprintf(stderr, "sweep verification failed\n");
            munmap((void *)memory, bytes);
            return 1;
        }
        if (!self_test) {
            if (printf("KERNEL_SWAP_SWEEP round=%u checksum=%016" PRIx64 "\n", round, checksum) < 0
                || fflush(stdout) != 0) {
                perror("sweep marker");
                munmap((void *)memory, bytes);
                return 1;
            }
        }
    }
    if (munmap((void *)memory, bytes) != 0) {
        perror("workload munmap");
        return 1;
    }
    if (puts(self_test ? "KERNEL_SWAP_WORKLOAD_SELF_TEST_PASS"
                       : "KERNEL_SWAP_WORKLOAD_COMPLETE sweeps=32") < 0 || fflush(stdout) != 0) {
        perror("completion marker");
        return 1;
    }
    if (!self_test && getpid() == 1) {
        /* An ordinary init stays alive after completion instead of panicking Linux. */
        for (;;) {
            pause();
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        return run(0);
    }
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return run(1);
    }
    fprintf(stderr, "fixed workload accepts only --self-test\n");
    return 2;
}
