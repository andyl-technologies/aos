/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QEMU-only observation of the actual retained preparation cut. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qemu-plugin.h"

typedef int (*InitializationQuery)(
    const uint8_t scope[32], const uint8_t commitment[32],
    QemuPluginCrucibleNodeInitializationCut *cut,
    QemuPluginCrucibleNodeInitializationRow *rows, uint32_t capacity);
typedef void *(*SymbolLookup)(void *handle, const char *name);

static _Atomic(InitializationQuery) original_query;
static bool retained;
static QemuPluginCrucibleNodeInitializationCut original_cut;
static QemuPluginCrucibleNodeInitializationRow original_rows[64];

static void probe_failed(const char *reason)
{
    dprintf(STDERR_FILENO, "initialization-cut-fixture FAIL: %s\n", reason);
    _exit(92);
}

static void require_refusal(
    int status, int expected,
    const QemuPluginCrucibleNodeInitializationCut *cut)
{
    static const QemuPluginCrucibleNodeInitializationCut zero;

    if (status != expected || memcmp(cut, &zero, sizeof(*cut))) {
        probe_failed("negative query returned source authority or partial data");
    }
}

static int probe_initialization_query(
    const uint8_t scope[32], const uint8_t commitment[32],
    QemuPluginCrucibleNodeInitializationCut *cut,
    QemuPluginCrucibleNodeInitializationRow *rows, uint32_t capacity)
{
    InitializationQuery query = atomic_load_explicit(&original_query,
                                                    memory_order_acquire);
    QemuPluginCrucibleNodeInitializationCut negative, repeated;
    QemuPluginCrucibleNodeInitializationRow repeated_rows[64];
    uint8_t foreign[32];
    int status;

    if (!query) {
        probe_failed("missing actual native query");
    }
    status = query(scope, commitment, cut, rows, capacity);
    if (status != 0) {
        return status;
    }
    if (cut->version != 1 || cut->size != sizeof(*cut) ||
        cut->row_count > capacity || capacity > 64 ||
        !cut->hold_generation || memcmp(cut->prepared_scope_hash, scope, 32) ||
        memcmp(cut->initialization_commitment, commitment, 32)) {
        probe_failed("actual source cut has invalid shape");
    }
    if (!retained) {
        /* This witness deliberately requires real HOME effects; an empty
         * source cut cannot substitute for the three construction callbacks. */
        if (cut->row_count != 3) {
            probe_failed("startup callbacks ran before original preparation cut");
        }
        original_cut = *cut;
        memcpy(original_rows, rows, cut->row_count * sizeof(*rows));
        retained = true;
    }
    if (memcmp(cut, &original_cut, sizeof(*cut)) ||
        memcmp(rows, original_rows, cut->row_count * sizeof(*rows))) {
        probe_failed("original native cut changed across query retry");
    }

    memcpy(foreign, scope, 32);
    foreign[0] ^= 1;
    memset(&negative, 0xa5, sizeof(negative));
    require_refusal(query(foreign, commitment, &negative, repeated_rows, 64),
                    -ESTALE, &negative);

    memcpy(foreign, commitment, 32);
    foreign[0] ^= 1;
    memset(&negative, 0xa5, sizeof(negative));
    require_refusal(query(scope, foreign, &negative, repeated_rows, 64),
                    -ESTALE, &negative);

    memset(&negative, 0xa5, sizeof(negative));
    require_refusal(query(scope, commitment, &negative, repeated_rows, 2),
                    -ENOSPC, &negative);

    status = query(scope, commitment, &repeated, repeated_rows, 64);
    if (status || memcmp(cut, &repeated, sizeof(repeated)) ||
        memcmp(rows, repeated_rows, cut->row_count * sizeof(*rows))) {
        probe_failed("negative calls changed the held original callbacks");
    }
    dprintf(STDERR_FILENO,
            "initialization-cut-fixture PASS scope=ESTALE commitment=ESTALE "
            "capacity=ENOSPC rows=3 held=%llu original-retry=identical\n",
            (unsigned long long)cut->hold_generation);
    return 0;
}

void *dlsym(void *handle, const char *name)
{
    SymbolLookup lookup;
    void *symbol;

    lookup = (SymbolLookup)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    if (!lookup) {
        probe_failed("missing actual libc symbol resolver");
    }
    symbol = lookup(handle, name);
    if (symbol && !strcmp(name,
                        "qemu_plugin_crucible_node_query_initialization_cut")) {
        atomic_store_explicit(&original_query, (InitializationQuery)symbol,
                              memory_order_release);
        return (void *)probe_initialization_query;
    }
    return symbol;
}
