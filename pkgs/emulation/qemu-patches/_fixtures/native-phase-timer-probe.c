/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU-only source-query probe. The actual V6 plugin supplies its original
 * scope and invokes the query in the actual held native getter/stopped seam.
 * These negative calls neither register authority nor authorize callbacks.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qemu-plugin.h"

typedef int (*TimerBirthQuery)(
    const uint8_t scope[32], uint64_t generation,
    QemuPluginCrucibleNodeTimerBirthInventory *summary,
    QemuPluginCrucibleNodeTimerList *lists, uint32_t list_capacity,
    QemuPluginCrucibleNodeTimerBirth *timers, uint32_t timer_capacity);

typedef void *(*SymbolLookup)(void *handle, const char *name);
static _Atomic(TimerBirthQuery) original_query;

static void probe_failed(const char *reason)
{
    dprintf(STDERR_FILENO, "phase-timer-fixture FAIL: %s\n", reason);
    /* The independent host supervisor owns physical failure and containment. */
    _exit(92);
}

static void require_zero_failure(
    int status, int expected,
    const QemuPluginCrucibleNodeTimerBirthInventory *summary)
{
    static const QemuPluginCrucibleNodeTimerBirthInventory zero;

    if (status != expected || memcmp(summary, &zero, sizeof(*summary))) {
        probe_failed("refused query returned a valid or partial source summary");
    }
}

static void *bounded_rows(uint32_t count, size_t size)
{
    void *rows = calloc(count ? count : 1, size);

    if (!rows) {
        probe_failed("fixture allocation failed");
    }
    return rows;
}

static int probe_timer_birth_query(
    const uint8_t scope[32], uint64_t generation,
    QemuPluginCrucibleNodeTimerBirthInventory *summary,
    QemuPluginCrucibleNodeTimerList *lists, uint32_t list_capacity,
    QemuPluginCrucibleNodeTimerBirth *timers, uint32_t timer_capacity)
{
    TimerBirthQuery query = atomic_load_explicit(&original_query,
                                                memory_order_acquire);
    QemuPluginCrucibleNodeTimerBirthInventory negative, repeated;
    QemuPluginCrucibleNodeTimerList *second_lists;
    QemuPluginCrucibleNodeTimerBirth *second_timers;
    uint8_t wrong_scope[32];
    uint64_t wrong_generation;
    unsigned int capacity_checks = 0;
    int status;

    if (!query) {
        probe_failed("actual native symbol was not retained");
    }
    status = query(scope, generation, summary, lists, list_capacity,
                   timers, timer_capacity);
    if (status != 0) {
        return status;
    }
    if (summary->version != 1 || summary->size != sizeof(*summary) ||
        !summary->gate_generation || summary->gate_generation != generation ||
        summary->list_count > list_capacity ||
        summary->timer_count > timer_capacity ||
        list_capacity > 64 || timer_capacity > 4096 ||
        memcmp(summary->prepared_scope_hash, scope, 32)) {
        probe_failed("actual source summary exceeds its original bounded shape");
    }
    second_lists = bounded_rows(list_capacity, sizeof(*second_lists));
    second_timers = bounded_rows(timer_capacity, sizeof(*second_timers));

    memcpy(wrong_scope, scope, sizeof(wrong_scope));
    wrong_scope[0] ^= 1;
    memset(&negative, 0xa5, sizeof(negative));
    status = query(wrong_scope, generation, &negative, second_lists,
                   list_capacity, second_timers, timer_capacity);
    require_zero_failure(status, -ESTALE, &negative);

    memset(&negative, 0xa5, sizeof(negative));
    status = query(scope, 0, &negative, second_lists, list_capacity,
                   second_timers, timer_capacity);
    require_zero_failure(status, -EINVAL, &negative);
    wrong_generation = generation == UINT64_MAX ? generation - 1 : generation + 1;
    memset(&negative, 0xa5, sizeof(negative));
    status = query(scope, wrong_generation, &negative, second_lists,
                   list_capacity, second_timers, timer_capacity);
    require_zero_failure(status, -EAGAIN, &negative);

    /* Missing rows are refused without consuming or relabeling original arms.
     * An empty timer roster cannot witness a timer-capacity refusal. */
    if (summary->timer_count) {
        memset(&negative, 0xa5, sizeof(negative));
        status = query(scope, generation, &negative, second_lists,
                       list_capacity, second_timers, summary->timer_count - 1);
        require_zero_failure(status, -ENOSPC, &negative);
        capacity_checks++;
    }
    if (summary->list_count > 1) {
        memset(&negative, 0xa5, sizeof(negative));
        status = query(scope, generation, &negative, second_lists,
                       summary->list_count - 1, second_timers, timer_capacity);
        require_zero_failure(status, -ENOSPC, &negative);
        capacity_checks++;
    }

    status = query(scope, generation, &repeated, second_lists,
                   list_capacity, second_timers, timer_capacity);
    if (status || memcmp(summary, &repeated, sizeof(repeated)) ||
        memcmp(lists, second_lists, summary->list_count * sizeof(*lists)) ||
        (summary->timer_count &&
         memcmp(timers, second_timers, summary->timer_count * sizeof(*timers)))) {
        probe_failed("negative calls changed original HOLD, arm birth or FIFO");
    }
    dprintf(STDERR_FILENO,
            "phase-timer-fixture PASS scope=ESTALE missingG=EINVAL "
            "wrongG=EAGAIN capacity_checks=%u held=%llu time=%llu "
            "lists=%u timers=%u original-retry=identical\n",
            capacity_checks, (unsigned long long)generation,
            (unsigned long long)summary->current_ps,
            summary->list_count, summary->timer_count);

    free(second_timers);
    free(second_lists);
    /* Preserve the first actual query's bytes for the native plugin journal. */
    return 0;
}

void *dlsym(void *handle, const char *name)
{
    SymbolLookup lookup;
    void *symbol;

    lookup = (SymbolLookup)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!lookup) {
        probe_failed("actual source-built libc resolver is unavailable");
    }
    symbol = lookup(handle, name);
    if (symbol && !strcmp(name, "qemu_plugin_crucible_node_query_timer_births")) {
        atomic_store_explicit(&original_query, (TimerBirthQuery)symbol,
                              memory_order_release);
        return (void *)probe_timer_birth_query;
    }
    return symbol;
}
