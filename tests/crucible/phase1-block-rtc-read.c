#define _GNU_SOURCE

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define mktimegm timegm
#define NANOSECONDS_PER_SECOND 1000000000LL
#define TYPE_MC146818_RTC "mc146818rtc"
#define g_assert_not_reached() abort()

typedef enum QEMUClockType {
  QEMU_CLOCK_REALTIME = 0,
  QEMU_CLOCK_VIRTUAL = 1,
  QEMU_CLOCK_HOST = 2,
  QEMU_CLOCK_VIRTUAL_RT = 3,
} QEMUClockType;

typedef struct QemuOpts {
  const char *base;
  const char *clock;
  const char *driftfix;
} QemuOpts;

static const time_t fixed_epoch = 1704067200;
static int64_t clock_ns[4];
static unsigned int clock_reads[4];
static unsigned int error_reports;
static unsigned int warning_reports;
static unsigned int replay_blockers;

static int64_t
qemu_clock_get_ns(QEMUClockType clock)
{
  clock_reads[clock]++;
  return clock_ns[clock];
}

static int64_t
qemu_clock_get_ms(QEMUClockType clock)
{
  clock_reads[clock]++;
  return clock_ns[clock] / 1000000;
}

static const char *
qemu_opt_get(QemuOpts *opts, const char *name)
{
  if (strcmp(name, "base") == 0) {
    return opts->base;
  }
  if (strcmp(name, "clock") == 0) {
    return opts->clock;
  }
  if (strcmp(name, "driftfix") == 0) {
    return opts->driftfix;
  }
  return NULL;
}

static void
error_report(const char *format, ...)
{
  (void)format;
  error_reports++;
}

static void
error_printf(const char *format, ...)
{
  (void)format;
}

static void
warn_report(const char *format, ...)
{
  (void)format;
  warning_reports++;
}

static void
replay_add_blocker(const char *blocker)
{
  (void)blocker;
  replay_blockers++;
}

static void
object_register_sugar_prop(const char *type, const char *prop,
                           const char *value, bool optional)
{
  (void)type;
  (void)prop;
  (void)value;
  (void)optional;
}

static void *
object_class_by_name(const char *name)
{
  (void)name;
  return (void *)1;
}

#include "system/rtc.c"

static void
reset_clocks(void)
{
  clock_ns[QEMU_CLOCK_REALTIME] = 900 * NANOSECONDS_PER_SECOND;
  clock_ns[QEMU_CLOCK_VIRTUAL] = 42 * NANOSECONDS_PER_SECOND;
  clock_ns[QEMU_CLOCK_HOST] = 555 * NANOSECONDS_PER_SECOND;
  clock_ns[QEMU_CLOCK_VIRTUAL_RT] = 0;
  memset(clock_reads, 0, sizeof(clock_reads));
  error_reports = 0;
  warning_reports = 0;
  replay_blockers = 0;
}

static void
configure_fixed_host_rtc(void)
{
  QemuOpts opts = {
      .base = "2024-01-01T00:00:00",
      .clock = "host",
      .driftfix = NULL,
  };

  reset_clocks();
  crucible_sim_rtc_virtual_clock = false;
  configure_rtc(&opts);
  memset(clock_reads, 0, sizeof(clock_reads));
}

static time_t
tm_to_utc_seconds(const struct tm *tm)
{
  struct tm copy = *tm;
  return mktimegm(&copy);
}

static time_t
stock_ref_timedate(QEMUClockType clock)
{
  time_t value = qemu_clock_get_ms(clock) / 1000;

  switch (clock) {
  case QEMU_CLOCK_REALTIME:
    value -= rtc_realtime_clock_offset;
    /* fall through */
  case QEMU_CLOCK_VIRTUAL:
    value += rtc_ref_start_datetime;
    break;
  case QEMU_CLOCK_HOST:
    if (rtc_base_type == RTC_BASE_DATETIME) {
      value -= rtc_host_datetime_offset;
    }
    break;
  default:
    abort();
  }

  return value;
}

static int64_t
mc146818_guest_rtc_ns(time_t base_rtc, int64_t last_update)
{
  return base_rtc * NANOSECONDS_PER_SECOND + qemu_clock_get_ns(rtc_clock) -
         last_update;
}

static int
test_sim_substitutes_virtual_time_after_configure(void)
{
  struct tm tm;
  time_t seconds;
  time_t diff;

  configure_fixed_host_rtc();
  qemu_rtc_enable_sim_virtual_clock();

  if (rtc_clock != QEMU_CLOCK_VIRTUAL) {
    fprintf(stderr, "sim RTC enable did not force rtc_clock virtual\n");
    return 1;
  }

  qemu_get_timedate(&tm, 0);
  seconds = tm_to_utc_seconds(&tm);
  if (seconds != fixed_epoch + 42) {
    fprintf(stderr, "sim RTC did not expose fixed epoch plus virtual time: %lld\n",
            (long long)seconds);
    return 1;
  }
  if (clock_reads[QEMU_CLOCK_VIRTUAL] != 1 ||
      clock_reads[QEMU_CLOCK_HOST] != 0 ||
      clock_reads[QEMU_CLOCK_REALTIME] != 0) {
    fprintf(stderr,
            "sim timedate read wrong clocks: virtual=%u host=%u realtime=%u\n",
            clock_reads[QEMU_CLOCK_VIRTUAL], clock_reads[QEMU_CLOCK_HOST],
            clock_reads[QEMU_CLOCK_REALTIME]);
    return 1;
  }

  diff = qemu_timedate_diff(&tm);
  if (diff != 0 || clock_reads[QEMU_CLOCK_VIRTUAL] != 2 ||
      clock_reads[QEMU_CLOCK_HOST] != 0 ||
      clock_reads[QEMU_CLOCK_REALTIME] != 0) {
    fprintf(stderr,
            "sim timedate diff was not virtual-only: diff=%lld virtual=%u host=%u realtime=%u\n",
            (long long)diff, clock_reads[QEMU_CLOCK_VIRTUAL],
            clock_reads[QEMU_CLOCK_HOST], clock_reads[QEMU_CLOCK_REALTIME]);
    return 1;
  }

  return 0;
}

static int
test_sim_covers_direct_cmos_rtc_clock_path(void)
{
  int64_t direct_guest_ns;
  int64_t last_update;

  configure_fixed_host_rtc();
  qemu_rtc_enable_sim_virtual_clock();

  last_update = qemu_clock_get_ns(rtc_clock);
  memset(clock_reads, 0, sizeof(clock_reads));
  clock_ns[QEMU_CLOCK_HOST] = 600 * NANOSECONDS_PER_SECOND;
  clock_ns[QEMU_CLOCK_VIRTUAL] = 45 * NANOSECONDS_PER_SECOND;

  direct_guest_ns = mc146818_guest_rtc_ns(fixed_epoch + 42, last_update);
  if (direct_guest_ns != (fixed_epoch + 45) * NANOSECONDS_PER_SECOND ||
      clock_reads[QEMU_CLOCK_VIRTUAL] != 1 ||
      clock_reads[QEMU_CLOCK_HOST] != 0) {
    fprintf(stderr,
            "direct CMOS RTC path did not use virtual clock: ns=%lld virtual=%u host=%u\n",
            (long long)direct_guest_ns, clock_reads[QEMU_CLOCK_VIRTUAL],
            clock_reads[QEMU_CLOCK_HOST]);
    return 1;
  }

  return 0;
}

static int
test_non_sim_keeps_upstream_host_clock(void)
{
  struct tm tm;
  time_t seconds;
  time_t diff;
  int64_t direct_guest_ns;

  configure_fixed_host_rtc();
  clock_ns[QEMU_CLOCK_HOST] = 600 * NANOSECONDS_PER_SECOND;

  qemu_get_timedate(&tm, 0);
  seconds = tm_to_utc_seconds(&tm);
  if (seconds != fixed_epoch + 45 || clock_reads[QEMU_CLOCK_HOST] != 1 ||
      clock_reads[QEMU_CLOCK_VIRTUAL] != 0) {
    fprintf(stderr,
            "non-sim RTC did not retain upstream host clock: seconds=%lld host=%u virtual=%u\n",
            (long long)seconds, clock_reads[QEMU_CLOCK_HOST],
            clock_reads[QEMU_CLOCK_VIRTUAL]);
    return 1;
  }

  diff = qemu_timedate_diff(&tm);
  if (diff != 0 || clock_reads[QEMU_CLOCK_HOST] != 2 ||
      clock_reads[QEMU_CLOCK_VIRTUAL] != 0) {
    fprintf(stderr,
            "non-sim RTC diff did not retain upstream host baseline: diff=%lld host=%u virtual=%u\n",
            (long long)diff, clock_reads[QEMU_CLOCK_HOST],
            clock_reads[QEMU_CLOCK_VIRTUAL]);
    return 1;
  }

  memset(clock_reads, 0, sizeof(clock_reads));
  direct_guest_ns = mc146818_guest_rtc_ns(fixed_epoch, 555 * NANOSECONDS_PER_SECOND);
  if (direct_guest_ns != (fixed_epoch + 45) * NANOSECONDS_PER_SECOND ||
      clock_reads[QEMU_CLOCK_HOST] != 1 || clock_reads[QEMU_CLOCK_VIRTUAL] != 0) {
    fprintf(stderr,
            "non-sim direct CMOS path did not retain host clock: ns=%lld host=%u virtual=%u\n",
            (long long)direct_guest_ns, clock_reads[QEMU_CLOCK_HOST],
            clock_reads[QEMU_CLOCK_VIRTUAL]);
    return 1;
  }

  return 0;
}

static int
test_stock_negative_control_reads_host_without_sim_enable(void)
{
  int64_t direct_guest_ns;

  configure_fixed_host_rtc();
  clock_ns[QEMU_CLOCK_HOST] = 600 * NANOSECONDS_PER_SECOND;

  direct_guest_ns = mc146818_guest_rtc_ns(fixed_epoch, 555 * NANOSECONDS_PER_SECOND);
  if (direct_guest_ns != (fixed_epoch + 45) * NANOSECONDS_PER_SECOND ||
      clock_reads[QEMU_CLOCK_HOST] != 1 || clock_reads[QEMU_CLOCK_VIRTUAL] != 0) {
    fprintf(stderr,
            "stock negative control did not read host clock: ns=%lld host=%u virtual=%u\n",
            (long long)direct_guest_ns, clock_reads[QEMU_CLOCK_HOST],
            clock_reads[QEMU_CLOCK_VIRTUAL]);
    return 1;
  }
  if (stock_ref_timedate(QEMU_CLOCK_HOST) != fixed_epoch + 45) {
    fprintf(stderr, "stock timedate baseline did not use host elapsed time\n");
    return 1;
  }

  return 0;
}

int
main(void)
{
  if (test_sim_substitutes_virtual_time_after_configure() != 0 ||
      test_sim_covers_direct_cmos_rtc_clock_path() != 0 ||
      test_non_sim_keeps_upstream_host_clock() != 0 ||
      test_stock_negative_control_reads_host_without_sim_enable() != 0) {
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_get_timedate_fixture=true");
  puts("configure_rtc_fixed_epoch_exercised=true");
  puts("sim_rtc_enable_forces_virtual_clock=true");
  puts("sim_rtc_reads_virtual_clock=true");
  puts("sim_direct_cmos_reads_virtual_clock=true");
  puts("sim_rtc_host_clock_reads=0");
  puts("sim_rtc_realtime_clock_reads=0");
  puts("sim_timedate_diff_virtual=true");
  puts("fixed_epoch_plus_virtual_time=true");
  puts("non_sim_rtc_reads_host_clock=true");
  puts("non_sim_direct_cmos_reads_host_clock=true");
  puts("non_sim_timedate_diff_upstream=true");
  puts("stock_negative_control_reads_host=true");
  return 0;
}
