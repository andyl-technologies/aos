/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A real masked worker emits the marker between distinct CPU-heavy phases. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int serial_descriptor;

__attribute__((noinline)) static void boot_phase_busy(void)
{
    struct timespec start, now;
    volatile uint64_t value = 1;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
    do {
        for (unsigned int index = 0; index < 100000; index++) {
            value = value * UINT64_C(6364136223846793005) + 1;
        }
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
    } while (now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9 < 1.0);
}

__attribute__((noinline)) static void after_marker_busy(void)
{
    struct timespec start, now;
    volatile uint64_t value = 7;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
    do {
        for (unsigned int index = 0; index < 100000; index++) {
            value ^= value >> 13;
            value = value * UINT64_C(2862933555777941757) + 3;
        }
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
    } while (now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9 < 1.0);
}

static int emit_marker(void)
{
    const char *parts[] = { "\nCRUCIBLE_TCG_", "BOOT_READY_V1\n" };

    for (size_t index = 0; index < 2; index++) {
        size_t length = strlen(parts[index]);
        struct iovec vector = { .iov_base = (void *)parts[index], .iov_len = length };
        struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1 };

        if (sendmsg(serial_descriptor, &message, MSG_NOSIGNAL) != (ssize_t)length) {
            return -1;
        }
    }
    return 0;
}

static void *worker(void *unused)
{
    (void)unused;
    boot_phase_busy();
    if (emit_marker() != 0) {
        return (void *)(uintptr_t)1;
    }
    after_marker_busy();
    return NULL;
}

int main(void)
{
    const char *path = getenv("TCG_PROFILE_BOOT_SOCKET");
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int listener, client;
    pthread_t thread;
    sigset_t blocked, original;
    void *worker_result;

    if (!path || strlen(path) >= sizeof(address.sun_path)) {
        return 1;
    }
    strcpy(address.sun_path, path);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) {
        return 2;
    }
    serial_descriptor = accept(listener, NULL, NULL);
    if (serial_descriptor < 0) {
        return 3;
    }

    sigfillset(&blocked);
    sigdelset(&blocked, SIGSEGV);
    sigdelset(&blocked, SIGFPE);
    sigdelset(&blocked, SIGILL);
    if (pthread_sigmask(SIG_SETMASK, &blocked, &original) != 0 ||
        pthread_create(&thread, NULL, worker, NULL) != 0 ||
        pthread_sigmask(SIG_SETMASK, &original, NULL) != 0 ||
        pthread_join(thread, &worker_result) != 0 || worker_result) {
        return 4;
    }
    if (close(serial_descriptor) != 0 || close(client) != 0 ||
        close(listener) != 0 || unlink(path) != 0) {
        return 5;
    }
    puts("PASS: masked worker completed both CPU phases");
    return 0;
}
