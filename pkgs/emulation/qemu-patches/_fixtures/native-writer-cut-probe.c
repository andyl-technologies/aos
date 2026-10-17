/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Negative native writer-cut mechanism probe. This library is loaded only into
 * the emulator, never an Apache host process. The real plugin's original V4
 * registration supplies the scope; the fixture cannot mint native authority.
 * These source-specific checks do not qualify all-source readiness or capture.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qemu-plugin.h"

typedef int (*WriterQuery)(
    const uint8_t scope[32], uint64_t generation,
    QemuPluginCrucibleNodeWriterCut *cut,
    QemuPluginCrucibleNodeWriterCpu *cpus, uint32_t cpu_capacity,
    QemuPluginCrucibleNodeWriterWork *work, uint32_t work_capacity,
    QemuPluginCrucibleNodeWriterAio *aio, uint32_t aio_capacity,
    QemuPluginCrucibleNodeWriterBh *bhs, uint32_t bh_capacity,
    QemuPluginCrucibleNodeWriterHandler *handlers, uint32_t handler_capacity);

typedef void *(*SymbolLookup)(void *handle, const char *name);
static _Atomic(WriterQuery) original_query;

static void probe_failed(const char *reason)
{
    dprintf(STDERR_FILENO, "writer-fixture FAIL: %s\n", reason);
    /* No result is published after a failed original-custody check. The host's
     * real child supervisor retains the physical failure and original ledger. */
    _exit(91);
}

static void require_zero_failure(int status, int expected,
                                 const QemuPluginCrucibleNodeWriterCut *cut)
{
    static const QemuPluginCrucibleNodeWriterCut zero;

    if (status != expected || memcmp(cut, &zero, sizeof(*cut)) != 0) {
        probe_failed("negative source call returned a valid or partial summary");
    }
}

static void *bounded_rows(size_t count, size_t size)
{
    void *rows = calloc(count ? count : 1, size);

    if (!rows) {
        probe_failed("fixture allocation failed");
    }
    return rows;
}

static int probe_writer_query(
    const uint8_t scope[32], uint64_t generation,
    QemuPluginCrucibleNodeWriterCut *cut,
    QemuPluginCrucibleNodeWriterCpu *cpus, uint32_t cpu_capacity,
    QemuPluginCrucibleNodeWriterWork *work, uint32_t work_capacity,
    QemuPluginCrucibleNodeWriterAio *aio, uint32_t aio_capacity,
    QemuPluginCrucibleNodeWriterBh *bhs, uint32_t bh_capacity,
    QemuPluginCrucibleNodeWriterHandler *handlers, uint32_t handler_capacity)
{
    WriterQuery query = atomic_load_explicit(&original_query,
                                             memory_order_acquire);
    QemuPluginCrucibleNodeWriterCut negative, repeated;
    QemuPluginCrucibleNodeWriterCpu *second_cpus;
    QemuPluginCrucibleNodeWriterWork *second_work;
    QemuPluginCrucibleNodeWriterAio *second_aio;
    QemuPluginCrucibleNodeWriterBh *second_bhs;
    QemuPluginCrucibleNodeWriterHandler *second_handlers;
    uint8_t wrong_scope[32];
    uint32_t pending_bhs = 0;
    int status;

    if (!query) {
        probe_failed("original native source symbol was not retained");
    }
    status = query(scope, generation, cut, cpus, cpu_capacity,
                            work, work_capacity, aio, aio_capacity,
                            bhs, bh_capacity, handlers, handler_capacity);
    if (status != 0) {
        /* Preparation can legitimately be incomplete at the first getter. */
        return status;
    }
    if (cut->version != 1 || cut->size != sizeof(*cut) ||
        cut->coverage != 7 || cut->flags != 15 || cut->reserved != 0 ||
        cut->gate_generation == 0 || cut->admissions_in_flight != 0 ||
        cut->cpu_count > cpu_capacity || cut->work_count > work_capacity ||
        cut->aio_count > aio_capacity || cut->bh_count > bh_capacity ||
        cut->handler_count > handler_capacity || cut->aio_count == 0 ||
        cpu_capacity > 1024 || work_capacity > 4096 || aio_capacity > 64 ||
        bh_capacity > 4096 || handler_capacity > 4096 ||
        memcmp(cut->prepared_scope_hash, scope, 32) != 0) {
        probe_failed("authentic partial cut has an invalid bounded shape");
    }

    second_cpus = bounded_rows(cpu_capacity, sizeof(*second_cpus));
    second_work = bounded_rows(work_capacity, sizeof(*second_work));
    second_aio = bounded_rows(aio_capacity, sizeof(*second_aio));
    second_bhs = bounded_rows(bh_capacity, sizeof(*second_bhs));
    second_handlers = bounded_rows(handler_capacity, sizeof(*second_handlers));

    memcpy(wrong_scope, scope, sizeof(wrong_scope));
    wrong_scope[0] ^= 1;
    memset(&negative, 0xa5, sizeof(negative));
    status = query(wrong_scope, cut->gate_generation, &negative,
                            second_cpus, cpu_capacity,
                            second_work, work_capacity,
                            second_aio, aio_capacity,
                            second_bhs, bh_capacity,
                            second_handlers, handler_capacity);
    require_zero_failure(status, -ESTALE, &negative);

    /* A realized AioContext is required by the genuine source summary. Zero
     * capacity is valid syntax, but cannot fit that original retained roster. */
    memset(&negative, 0xa5, sizeof(negative));
    status = query(scope, cut->gate_generation, &negative,
                            second_cpus, cpu_capacity,
                            second_work, work_capacity, NULL, 0,
                            second_bhs, bh_capacity,
                            second_handlers, handler_capacity);
    require_zero_failure(status, -ENOSPC, &negative);

    status = query(scope, cut->gate_generation, &repeated,
                            second_cpus, cpu_capacity,
                            second_work, work_capacity,
                            second_aio, aio_capacity,
                            second_bhs, bh_capacity,
                            second_handlers, handler_capacity);
    if (status != 0 || repeated.gate_generation != cut->gate_generation ||
        repeated.flags != 15 || repeated.coverage != 7 ||
        repeated.current_ps != cut->current_ps ||
        repeated.raw_icount != cut->raw_icount ||
        repeated.cpu_count != cut->cpu_count ||
        repeated.work_count != cut->work_count ||
        repeated.aio_count != cut->aio_count ||
        repeated.bh_count != cut->bh_count ||
        repeated.handler_count != cut->handler_count ||
        memcmp(repeated.prepared_scope_hash, scope, 32) != 0 ||
        memcmp(repeated.roster_hash, cut->roster_hash, 32) != 0) {
        probe_failed("negative calls lost the original HOLD or queue roster");
    }
    for (uint32_t index = 0; index < cut->cpu_count; index++) {
        if (cpus[index].cpu_index != second_cpus[index].cpu_index ||
            cpus[index].work_count != second_cpus[index].work_count ||
            cpus[index].next_work_sequence !=
                second_cpus[index].next_work_sequence) {
            probe_failed("original CPU FIFO changed during negative checks");
        }
    }
    for (uint32_t index = 0; index < cut->work_count; index++) {
        if (memcmp(&work[index], &second_work[index], sizeof(work[index]))) {
            probe_failed("original native CPU work identity was not retained");
        }
    }
    for (uint32_t index = 0; index < cut->aio_count; index++) {
        if (aio[index].context_id != second_aio[index].context_id) {
            probe_failed("original Aio identity was not retained");
        }
    }
    for (uint32_t index = 0; index < cut->bh_count; index++) {
        if (memcmp(&bhs[index], &second_bhs[index], sizeof(bhs[index]))) {
            probe_failed("original native BH identity or pending flags changed");
        }
        pending_bhs += !!(bhs[index].flags & 1);
    }
    for (uint32_t index = 0; index < cut->handler_count; index++) {
        if (memcmp(&handlers[index], &second_handlers[index],
                   sizeof(handlers[index]))) {
            probe_failed("original native handler identity changed");
        }
    }
    dprintf(STDERR_FILENO,
            "writer-fixture PASS scope=ESTALE capacity=ENOSPC held=%llu "
            "time=%llu raw=%llu work=%u pending_bhs=%u coverage=7 flags=15\n",
            (unsigned long long)cut->gate_generation,
            (unsigned long long)cut->current_ps,
            (unsigned long long)cut->raw_icount,
            cut->work_count, pending_bhs);

    free(second_handlers);
    free(second_bhs);
    free(second_aio);
    free(second_work);
    free(second_cpus);
    /* Preserve the first authentic object. A fresh observation above is a
     * fixture check, never a replacement for the plugin's original journal. */
    return 0;
}

void *dlsym(void *handle, const char *name)
{
    SymbolLookup original_lookup;
    void *symbol;

    /* Resolve libc directly through its versioned entry point, avoiding
     * recursion through this fixture's dlsym interposition. */
    original_lookup = (SymbolLookup)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!original_lookup) {
        probe_failed("source-built libc symbol lookup is unavailable");
    }
    symbol = original_lookup(handle, name);
    if (!strcmp(name, "qemu_plugin_crucible_node_query_writer_cut") && symbol) {
        atomic_store_explicit(&original_query, (WriterQuery)symbol,
                              memory_order_release);
        return (void *)probe_writer_query;
    }
    return symbol;
}
