/* SPDX-License-Identifier: GPL-2.0-only */
/* Build-only checks against the exact configured kernel's private data layout. */
#include <vdso/datapage.h>
#include <vdso/clocksource.h>
#include <asm/vdso/vsyscall.h>

#define CHECK_OFFSET(field, expected) \
    _Static_assert(__builtin_offsetof(struct vdso_clock, field) == expected, "VVAR field offset differs")

_Static_assert(__builtin_offsetof(struct vdso_time_data, clock_data) == 0, "VVAR architecture prefix differs");
_Static_assert(sizeof(struct vdso_clock) == 232, "VVAR size differs");
_Static_assert(VDSO_CLOCKMODE_TSC == 1, "VVAR TSC mode differs");
_Static_assert(VDSO_TIME_PAGE_OFFSET == 0, "VVAR time page differs");
_Static_assert(__VDSO_PAGES == 6 && PAGE_SIZE == 4096, "VVAR mapping differs");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 && VDSO_BASES == 12, "VVAR clock indices differ");

CHECK_OFFSET(seq, 0);
CHECK_OFFSET(clock_mode, 4);
CHECK_OFFSET(cycle_last, 8);
CHECK_OFFSET(max_cycles, 16);
CHECK_OFFSET(mask, 24);
CHECK_OFFSET(mult, 32);
CHECK_OFFSET(shift, 36);
CHECK_OFFSET(basetime, 40);
