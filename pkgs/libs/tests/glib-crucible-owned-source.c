/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercises the actual GLib owned-storage API; this supplies no native issuer. */

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
    GSource source;
    guint64 retained_payload;
} TestSource;

static GSource *expected_source;
static unsigned int finalized;

static void
finalize_source(GSource *source)
{
    if (source == expected_source) {
        finalized++;
    }
}

static GSourceFuncs source_functions = {
    .finalize = finalize_source,
};

static int
run_controls(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    gsize required = g_source_crucible_storage_bytes(sizeof(TestSource));
    unsigned char *mapping;
    unsigned char *storage;
    GSource *source;
    unsigned char saved[256];

    if (page_size <= 0 || required < sizeof(TestSource) ||
        required > (gsize) page_size || required > sizeof(saved) ||
        g_source_crucible_storage_bytes(sizeof(GSource) - 1) != 0) {
        return 1;
    }

    /* The private state must fit the queried extent immediately before a real
     * guard page. Final unref must retain the original caller-owned mapping. */
    mapping = mmap(NULL, (size_t) page_size * 3, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return 2;
    }
    if (mprotect(mapping + page_size, (size_t) page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, (size_t) page_size * 3);
        return 3;
    }
    storage = mapping + page_size * 2 - required;
    memset(storage, 0xa5, required);
    memcpy(saved, storage, required);

    /* Invalid geometry and callback-table overlap refuse before zeroing any
     * caller storage; they cannot partially initialize an original source. */
    if (g_source_crucible_new_owned(&source_functions, sizeof(TestSource),
                                    storage, required - 1) != NULL ||
        memcmp(saved, storage, required) != 0 ||
        g_source_crucible_new_owned(&source_functions, sizeof(TestSource),
                                    storage + 1, required) != NULL ||
        memcmp(saved, storage, required) != 0 ||
        g_source_crucible_new_owned((GSourceFuncs *) storage,
                                    sizeof(TestSource), storage,
                                    required) != NULL ||
        memcmp(saved, storage, required) != 0) {
        munmap(mapping, (size_t) page_size * 3);
        return 4;
    }

    source = g_source_crucible_new_owned(&source_functions, sizeof(TestSource),
                                        storage, required);
    if (source != (GSource *) storage || source->ref_count != 1 ||
        g_source_get_priority(source) != G_PRIORITY_DEFAULT ||
        g_source_get_ready_time(source) != -1 ||
        ((TestSource *) source)->retained_payload != 0) {
        munmap(mapping, (size_t) page_size * 3);
        return 5;
    }
    ((TestSource *) source)->retained_payload = 0x127ac5;
    expected_source = source;
    g_source_unref(source);
    if (finalized != 1 || ((TestSource *) storage)->retained_payload != 0x127ac5) {
        munmap(mapping, (size_t) page_size * 3);
        return 6;
    }
    if (munmap(mapping, (size_t) page_size * 3) != 0) {
        return 7;
    }

    /* The ordinary allocator path still owns and frees its own source. */
    source = g_source_new(&source_functions, sizeof(TestSource));
    if (source == NULL) {
        return 8;
    }
    expected_source = source;
    g_source_unref(source);
    return finalized == 2 ? 0 : 9;
}

int
main(void)
{
    int status = run_controls();

    if (status != 0) {
        fprintf(stderr, "owned-source control failed: %d\n", status);
        return status;
    }
    return puts("glib owned-source controls passed") == EOF;
}
