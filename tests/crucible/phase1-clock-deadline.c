#include <stdint.h>
#include <stdio.h>

enum {
  QEMU_CLOCK_REALTIME = 0,
  QEMU_CLOCK_VIRTUAL = 1,
  QEMU_CLOCK_HOST = 2,
  QEMU_TIMER_ATTR_ALL = -1,
};

static int virtual_deadline_reads;
static int realtime_deadline_reads;
static int host_deadline_reads;
static int virtual_clock_reads;
static int realtime_clock_reads;
static int host_clock_reads;
static int unexpected_attr_reads;
static int64_t current_virtual_ns = 1000;
static int64_t virtual_deadline_delta_ns = 123456;

int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  if (attrs != QEMU_TIMER_ATTR_ALL) {
    unexpected_attr_reads++;
  }

  if (clock == QEMU_CLOCK_VIRTUAL) {
    virtual_deadline_reads++;
    return virtual_deadline_delta_ns;
  }
  if (clock == QEMU_CLOCK_REALTIME) {
    realtime_deadline_reads++;
    return 7;
  }
  if (clock == QEMU_CLOCK_HOST) {
    host_deadline_reads++;
    return 11;
  }
  return -1;
}

int64_t
qemu_clock_get_ns(int clock)
{
  if (clock == QEMU_CLOCK_VIRTUAL) {
    virtual_clock_reads++;
    return current_virtual_ns;
  }
  if (clock == QEMU_CLOCK_REALTIME) {
    realtime_clock_reads++;
    return 7;
  }
  if (clock == QEMU_CLOCK_HOST) {
    host_clock_reads++;
    return 11;
  }
  return -1;
}

#include "plugins/api-system.c"

static int
test_virtual_deadline_is_absolute_virtual_time_only(void)
{
  current_virtual_ns = 1000;
  virtual_deadline_delta_ns = 123456;
  virtual_deadline_reads = 0;
  realtime_deadline_reads = 0;
  host_deadline_reads = 0;
  virtual_clock_reads = 0;
  realtime_clock_reads = 0;
  host_clock_reads = 0;
  unexpected_attr_reads = 0;

  const int64_t deadline = qemu_plugin_clock_deadline_ns();
  if (deadline != 124456 || virtual_deadline_reads != 1 ||
      virtual_clock_reads != 1 ||
      realtime_deadline_reads != 0 || host_deadline_reads != 0 ||
      realtime_clock_reads != 0 || host_clock_reads != 0 ||
      unexpected_attr_reads != 0) {
    fprintf(stderr,
            "deadline source mismatch: deadline=%lld virtual_deadline=%d "
            "virtual_clock=%d realtime_deadline=%d host_deadline=%d "
            "realtime_clock=%d host_clock=%d bad_attrs=%d\n",
            (long long)deadline, virtual_deadline_reads,
            virtual_clock_reads, realtime_deadline_reads, host_deadline_reads,
            realtime_clock_reads, host_clock_reads, unexpected_attr_reads);
    return 1;
  }
  return 0;
}

static int
test_no_armed_timer_sentinel(void)
{
  virtual_deadline_delta_ns = -1;
  virtual_deadline_reads = 0;
  virtual_clock_reads = 0;

  const int64_t deadline = qemu_plugin_clock_deadline_ns();
  if (deadline != -1 || virtual_deadline_reads != 1 ||
      virtual_clock_reads != 0) {
    fprintf(stderr,
            "no-armed-timer sentinel mismatch: deadline=%lld deadline_reads=%d "
            "clock_reads=%d\n",
            (long long)deadline, virtual_deadline_reads, virtual_clock_reads);
    return 1;
  }
  return 0;
}

int
main(void)
{
  if (test_virtual_deadline_is_absolute_virtual_time_only() != 0 ||
      test_no_armed_timer_sentinel() != 0) {
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_clock_deadline_fixture=true");
  puts("deadline_symbol=qemu_plugin_clock_deadline_ns");
  puts("deadline_source=QEMU_CLOCK_VIRTUAL");
  puts("deadline_absolute_time=124456");
  puts("realtime_deadline_reads=0");
  puts("host_deadline_reads=0");
  puts("realtime_clock_reads=0");
  puts("host_clock_reads=0");
  puts("no_armed_timer_sentinel=-1");
  puts("stock_negative_control_deadline_symbol_absent=true");
  return 0;
}
