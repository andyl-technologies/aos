#include "probe.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <zstd.h>

static int sqlite_query(void) {
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    int answer = 0;

    if (sqlite3_open(":memory:", &database) != SQLITE_OK) {
        sqlite3_close(database);
        return 0;
    }

    if (sqlite3_prepare_v2(database, "SELECT 19 + 23", -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW) {
        answer = sqlite3_column_int(statement, 0);
    }

    sqlite3_finalize(statement);
    sqlite3_close(database);
    return answer;
}

static int zstd_round_trip(void) {
    const char payload[] = "Declared AOS SQLite and multithreaded zstd";
    char compressed[256];
    char restored[sizeof(payload)];
    ZSTD_CCtx *context = ZSTD_createCCtx();
    if (context == NULL) {
        return 0;
    }

    /* The store family requires the AOS library's multithreaded variant. */
    size_t configured = ZSTD_CCtx_setParameter(context, ZSTD_c_nbWorkers, 1);
    size_t size = ZSTD_compress2(context, compressed, sizeof(compressed), payload, sizeof(payload));
    ZSTD_freeCCtx(context);
    if (ZSTD_isError(configured) || ZSTD_isError(size)) {
        fprintf(stderr, "zstd configuration: %s; compression: %s\n",
                ZSTD_getErrorName(configured), ZSTD_getErrorName(size));
        return 0;
    }

    size_t restored_size = ZSTD_decompress(restored, sizeof(restored), compressed, size);
    return restored_size == sizeof(payload) && memcmp(payload, restored, sizeof(payload)) == 0;
}

int native_library_probe(void) {
    if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER ||
        ZSTD_versionNumber() != ZSTD_VERSION_NUMBER ||
        !sqlite3_compileoption_used("ENABLE_FTS5") || !sqlite3_threadsafe()) {
        fprintf(stderr, "SQLite: runtime=%d headers=%d FTS5=%d threads=%d; zstd: runtime=%u headers=%u\n",
                sqlite3_libversion_number(), SQLITE_VERSION_NUMBER,
                sqlite3_compileoption_used("ENABLE_FTS5"), sqlite3_threadsafe(),
                ZSTD_versionNumber(), ZSTD_VERSION_NUMBER);
        return 0;
    }

    if (!zstd_round_trip()) {
        return 0;
    }

    return sqlite_query();
}
