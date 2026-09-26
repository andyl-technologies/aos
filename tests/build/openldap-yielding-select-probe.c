/* SPDX-License-Identifier: Apache-2.0 */
/* Measures OpenLDAP's implicitly-yielding select property on the target. */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

static int pipe_descriptors[2];
static pthread_cond_t worker_started = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static int worker_is_started;

static void fail_pthread_operation(const char *operation, int error, int status) {
    errno = error;
    perror(operation);
    exit(status);
}

static void *select_task(void *unused) {
    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
    fd_set read_descriptors;
    int status;

    (void)unused;

    status = pthread_mutex_lock(&worker_mutex);
    if (status != 0) {
        fail_pthread_operation("pthread_mutex_lock", status, 13);
    }

    worker_is_started = 1;
    status = pthread_cond_signal(&worker_started);
    if (status != 0) {
        fail_pthread_operation("pthread_cond_signal", status, 14);
    }

    status = pthread_mutex_unlock(&worker_mutex);
    if (status != 0) {
        fail_pthread_operation("pthread_mutex_unlock", status, 15);
    }

    FD_ZERO(&read_descriptors);
    FD_SET(pipe_descriptors[0], &read_descriptors);

    status = select(FD_SETSIZE, &read_descriptors, NULL, NULL, &timeout);
    if (status < 0) {
        perror("select");
        exit(16);
    }
    if (status > 0) {
        fputs("select reported data on an unread pipe\n", stderr);
        exit(20);
    }

    /* A zero exit means select blocked every thread until its timeout. */
    exit(0);
}

int main(void) {
    const struct timespec scheduling_window = {
        .tv_sec = 0,
        .tv_nsec = 100000000,
    };
    pthread_t worker;
    int status;

    if (pipe(pipe_descriptors) != 0) {
        perror("pipe");
        return 10;
    }
    if (pipe_descriptors[0] >= FD_SETSIZE) {
        fputs("pipe descriptor exceeds select capacity\n", stderr);
        return 21;
    }

    status = pthread_mutex_lock(&worker_mutex);
    if (status != 0) {
        fail_pthread_operation("pthread_mutex_lock", status, 11);
    }

    status = pthread_create(&worker, NULL, select_task, NULL);
    if (status != 0) {
        fail_pthread_operation("pthread_create", status, 12);
    }

    while (!worker_is_started) {
        status = pthread_cond_wait(&worker_started, &worker_mutex);
        if (status != 0) {
            fail_pthread_operation("pthread_cond_wait", status, 17);
        }
    }

    status = pthread_mutex_unlock(&worker_mutex);
    if (status != 0) {
        fail_pthread_operation("pthread_mutex_unlock", status, 18);
    }

    /* Give the runnable worker a scheduling opportunity to enter select. */
    if (nanosleep(&scheduling_window, NULL) != 0) {
        perror("nanosleep");
        return 19;
    }

    /* Exit 2 retains the positive-result convention of OpenLDAP's probe. */
    return 2;
}
