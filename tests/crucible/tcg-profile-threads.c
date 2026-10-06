/* SPDX-License-Identifier: GPL-2.0-or-later */
/* GPL-compatible diagnostic interposer loaded only into profiled QEMU runs. */
/* Profiling-only loader: sample threads that normally inherit SIGPROF blocked. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

extern void ProfilerRegisterThread(void);

typedef int (*CreateThread)(pthread_t *, const pthread_attr_t *,
                            void *(*)(void *), void *);

struct ThreadStart {
    void *(*routine)(void *);
    void *argument;
};

static CreateThread real_pthread_create;
static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;

static void resolve_thread_create(void)
{
    real_pthread_create = (CreateThread)dlsym(RTLD_NEXT, "pthread_create");
    if (!real_pthread_create) {
        fputs("profiling loader: unable to resolve pthread_create\n", stderr);
        abort();
    }
}

static void *start_profiled_thread(void *opaque)
{
    struct ThreadStart start = *(struct ThreadStart *)opaque;
    sigset_t sampling_signal;

    free(opaque);
    sigemptyset(&sampling_signal);
    sigaddset(&sampling_signal, SIGPROF);
    if (pthread_sigmask(SIG_UNBLOCK, &sampling_signal, NULL) != 0) {
        fputs("profiling loader: unable to unblock SIGPROF\n", stderr);
        abort();
    }
    ProfilerRegisterThread();

    return start.routine(start.argument);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *(*routine)(void *), void *argument)
{
    struct ThreadStart *start;
    int result;

    pthread_once(&resolve_once, resolve_thread_create);
    start = malloc(sizeof(*start));
    if (!start) {
        return EAGAIN;
    }
    start->routine = routine;
    start->argument = argument;

    result = real_pthread_create(thread, attributes, start_profiled_thread, start);
    if (result != 0) {
        free(start);
    }
    return result;
}
