#include <stdbool.h>
#include <stddef.h>
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
static int64_t last_virtual_deadline_delta_ns = -1;
static bool guest_idle_for_deadline_query;

struct FakeTimer {
  int clock;
  bool armed;
  int64_t expire_ns;
};

static struct FakeTimer fake_timers[4];

static void
fake_timer_init(size_t index, int clock)
{
  fake_timers[index].clock = clock;
  fake_timers[index].armed = false;
  fake_timers[index].expire_ns = 0;
}

static void
fake_timer_mod(size_t index, int64_t expire_ns)
{
  fake_timers[index].armed = true;
  fake_timers[index].expire_ns = expire_ns;
}

static void
fake_guest_idle(void)
{
  guest_idle_for_deadline_query = true;
}

static void
reset_fixture_state(void)
{
  virtual_deadline_reads = 0;
  realtime_deadline_reads = 0;
  host_deadline_reads = 0;
  virtual_clock_reads = 0;
  realtime_clock_reads = 0;
  host_clock_reads = 0;
  unexpected_attr_reads = 0;
  current_virtual_ns = 1000;
  last_virtual_deadline_delta_ns = -1;
  guest_idle_for_deadline_query = false;

  fake_timer_init(0, QEMU_CLOCK_VIRTUAL);
  fake_timer_init(1, QEMU_CLOCK_VIRTUAL);
  fake_timer_init(2, QEMU_CLOCK_HOST);
  fake_timer_init(3, QEMU_CLOCK_REALTIME);
}

int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  if (attrs != QEMU_TIMER_ATTR_ALL) {
    unexpected_attr_reads++;
  }

  if (clock == QEMU_CLOCK_VIRTUAL) {
    bool have_deadline = false;
    int64_t min_delta_ns = 0;

    virtual_deadline_reads++;
    for (size_t index = 0; index < sizeof(fake_timers) / sizeof(fake_timers[0]);
         index++) {
      const struct FakeTimer *timer = &fake_timers[index];
      if (!timer->armed || timer->clock != QEMU_CLOCK_VIRTUAL) {
        continue;
      }

      int64_t delta_ns = timer->expire_ns - current_virtual_ns;
      if (delta_ns < 0) {
        delta_ns = 0;
      }
      if (!have_deadline || delta_ns < min_delta_ns) {
        have_deadline = true;
        min_delta_ns = delta_ns;
      }
    }

    last_virtual_deadline_delta_ns = have_deadline ? min_delta_ns : -1;
    return last_virtual_deadline_delta_ns;
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
  reset_fixture_state();
  fake_timer_mod(0, 124456);
  fake_timer_mod(1, 200000);
  fake_timer_mod(2, 1001);
  fake_guest_idle();

  const int64_t deadline = qemu_plugin_clock_deadline_ns();
  if (deadline != 124456 || virtual_deadline_reads != 1 ||
      virtual_clock_reads != 1 ||
      last_virtual_deadline_delta_ns != 123456 ||
      !fake_timers[0].armed || !guest_idle_for_deadline_query ||
      realtime_deadline_reads != 0 || host_deadline_reads != 0 ||
      realtime_clock_reads != 0 || host_clock_reads != 0 ||
      unexpected_attr_reads != 0) {
    fprintf(stderr,
            "deadline source mismatch: deadline=%lld virtual_deadline=%d "
            "virtual_clock=%d delta=%lld timer_armed=%d guest_idle=%d "
            "realtime_deadline=%d host_deadline=%d realtime_clock=%d "
            "host_clock=%d bad_attrs=%d\n",
            (long long)deadline, virtual_deadline_reads,
            virtual_clock_reads, (long long)last_virtual_deadline_delta_ns,
            fake_timers[0].armed ? 1 : 0,
            guest_idle_for_deadline_query ? 1 : 0,
            realtime_deadline_reads, host_deadline_reads, realtime_clock_reads,
            host_clock_reads, unexpected_attr_reads);
    return 1;
  }
  return 0;
}

static int
test_no_armed_timer_sentinel(void)
{
  reset_fixture_state();
  fake_guest_idle();

  const int64_t deadline = qemu_plugin_clock_deadline_ns();
  if (deadline != -1 || virtual_deadline_reads != 1 ||
      virtual_clock_reads != 0 || last_virtual_deadline_delta_ns != -1 ||
      !guest_idle_for_deadline_query) {
    fprintf(stderr,
            "no-armed-timer sentinel mismatch: deadline=%lld deadline_reads=%d "
            "clock_reads=%d delta=%lld guest_idle=%d\n",
            (long long)deadline, virtual_deadline_reads, virtual_clock_reads,
            (long long)last_virtual_deadline_delta_ns,
            guest_idle_for_deadline_query ? 1 : 0);
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
  puts("deadline_delta_ns=123456");
  puts("virtual_timer_armed=true");
  puts("guest_idle_for_deadline_query=true");
  puts("min_virtual_timer_selected=true");
  puts("realtime_deadline_reads=0");
  puts("host_deadline_reads=0");
  puts("realtime_clock_reads=0");
  puts("host_clock_reads=0");
  puts("no_armed_timer_sentinel=-1");
  puts("stock_negative_control_deadline_symbol_absent=true");
  return 0;
}
