/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CRUCIBLE_CLOCK_VVAR_LAYOUT_H
#define CRUCIBLE_CLOCK_VVAR_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

/* Private fixture layout, checked against the configured Linux 7.2.3 headers. */
struct clock_vvar_timestamp {
    uint64_t seconds;
    uint64_t shifted_nanoseconds;
};

struct clock_vvar_base {
    uint32_t sequence;
    int32_t mode;
    uint64_t cycle_last;
    uint64_t max_cycles;
    uint64_t mask;
    uint32_t multiplier;
    uint32_t shift;
    struct clock_vvar_timestamp clocks[12];
};

_Static_assert(sizeof(struct clock_vvar_base) == 232, "unexpected VVAR clock size");
_Static_assert(offsetof(struct clock_vvar_base, clocks) == 40, "unexpected VVAR base offset");

#endif
