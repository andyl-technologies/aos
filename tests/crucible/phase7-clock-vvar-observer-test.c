/* SPDX-License-Identifier: Apache-2.0 */
/* Exercises production observation helpers with schema fixtures, not a VM. */
#define CLOCK_VVAR_UNIT_TEST
#include "phase7-clock-vvar-observer.c"

#include <assert.h>

int main(void)
{
    struct clock_vvar_base base = {
        .sequence = 2, .mode = 1, .cycle_last = 100, .max_cycles = 10000,
        .mask = UINT64_MAX, .multiplier = 4, .shift = 2,
    };
    base.clocks[CLOCK_REALTIME].seconds = 123;
    base.clocks[CLOCK_MONOTONIC].seconds = 7;
    uint64_t words[ANCHOR_WORDS];

    assert(snapshot_base(&base, words));
    assert(words[8] == 123 && words[10] == 7 && snapshot_unchanged(&base, words));

    base.sequence = 3;
    assert(!snapshot_base(&base, words));
    struct clock_return returned;
    assert(observe(&base, "realtime", &returned, words) == -1);

    base.sequence = 4;
    assert(!snapshot_unchanged(&base, words));
    base.mode = 0;
    assert(observe(&base, "realtime", &returned, words) == -1);
    assert(read_return("unknown", &returned) == -1);

    puts("PASS VVAR observer helper positive=1 refusal=5 (schema fixtures only)");
    return 0;
}
