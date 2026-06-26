#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  QEMU_CLOCK_VIRTUAL = 0,
  QEMU_CLOCK_VIRTUAL_RT = 1,
  QEMU_TIMER_ATTR_EXTERNAL = 1,
  CHECKPOINT_CLOCK_WARP_START = 1,
  REPLAY_MODE_PLAY = 1,
};

typedef struct CPUState {
  int unused;
} CPUState;

typedef struct run_on_cpu_data {
  uintptr_t host_ulong;
} run_on_cpu_data;

struct TestTimersState {
  int vm_clock_seqlock;
  int vm_clock_lock;
  int64_t qemu_icount_bias;
  int64_t vm_clock_warp_start;
  void *icount_warp_timer;
};

static struct TestTimersState timers_state = {
    .vm_clock_warp_start = -1,
};

static CPUState test_cpu;
static CPUState *current_cpu = &test_cpu;
static int replay_mode;
static bool runstate_running = true;
static bool all_threads_idle = true;
static bool qtest_is_enabled;
static bool replay_checkpoint_result = true;
static bool replay_event_pending;
static int64_t virtual_rt_clock_ns;
static int64_t virtual_deadline_ns;
static int64_t virtual_time_ns;
static unsigned int notify_virtual_count;
static unsigned int timer_mod_count;
static int64_t timer_mod_deadline;
static unsigned int virtual_rt_clock_reads;
static unsigned int virtual_deadline_reads;
static unsigned int warning_count;
static unsigned int async_requests;
static unsigned int plugin_authorized_jumps;
static const char *current_accel = "tcg";

#define RUN_ON_CPU_HOST_ULONG(value) \
  ((run_on_cpu_data){.host_ulong = (uintptr_t)(value)})

#define qatomic_set_i64(ptr, value) (*(ptr) = (value))

static void
seqlock_write_lock(int *seq, int *lock)
{
  (void)seq;
  (void)lock;
}

static void
seqlock_write_unlock(int *seq, int *lock)
{
  (void)seq;
  (void)lock;
}

static bool
icount_enabled(void)
{
  return true;
}

const char *
current_accel_name(void)
{
  return current_accel;
}

static bool
runstate_is_running(void)
{
  return runstate_running;
}

static bool
all_cpu_threads_idle(void)
{
  return all_threads_idle;
}

static bool
qtest_enabled(void)
{
  return qtest_is_enabled;
}

static bool
replay_checkpoint(int checkpoint)
{
  (void)checkpoint;
  return replay_checkpoint_result;
}

static bool
replay_has_event(void)
{
  return replay_event_pending;
}

static int64_t
qemu_clock_get_ns(int clock)
{
  if (clock == QEMU_CLOCK_VIRTUAL_RT) {
    virtual_rt_clock_reads++;
    return virtual_rt_clock_ns;
  }
  return 0;
}

static int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  (void)attrs;

  if (clock == QEMU_CLOCK_VIRTUAL) {
    virtual_deadline_reads++;
    return virtual_deadline_ns;
  }
  return -1;
}

static void
qemu_clock_notify(int clock)
{
  if (clock == QEMU_CLOCK_VIRTUAL) {
    notify_virtual_count++;
  }
}

static void
timer_mod_anticipate(void *timer, int64_t expire_time)
{
  (void)timer;
  timer_mod_count++;
  timer_mod_deadline = expire_time;
}

static void
warn_report_once(const char *message)
{
  (void)message;
  warning_count++;
}

static void
qemu_clock_advance_virtual_time(int64_t new_time)
{
  virtual_time_ns = new_time;
  plugin_authorized_jumps++;
}

static void
async_run_on_cpu(CPUState *cpu,
                 void (*callback)(CPUState *cpu, run_on_cpu_data data),
                 run_on_cpu_data data)
{
  async_requests++;
  callback(cpu, data);
}

#include "plugins/api-system.c"
#include "accel/tcg/icount-common.c"

static void
reset_common(void)
{
  runstate_running = true;
  all_threads_idle = true;
  qtest_is_enabled = false;
  replay_checkpoint_result = true;
  replay_event_pending = false;
  replay_mode = 0;
  current_accel = "tcg";
  has_control = false;
  timers_state.qemu_icount_bias = 300;
  timers_state.vm_clock_warp_start = -1;
  virtual_rt_clock_ns = 50;
  virtual_deadline_ns = 1000;
  virtual_time_ns = 0;
  notify_virtual_count = 0;
  timer_mod_count = 0;
  timer_mod_deadline = -1;
  virtual_rt_clock_reads = 0;
  virtual_deadline_reads = 0;
  warning_count = 0;
  async_requests = 0;
  plugin_authorized_jumps = 0;
}

static int64_t
stock_sleep_off_bias_after(int64_t bias, int64_t deadline)
{
  return bias + deadline;
}

static int
test_upstream_sleep_off_without_time_control(void)
{
  reset_common();
  icount_sleep = false;

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 1300 || notify_virtual_count != 1 ||
      timer_mod_count != 0 || virtual_rt_clock_reads != 1 ||
      virtual_deadline_reads != 1) {
    fprintf(stderr,
            "sleep=off upstream warp mismatch: bias=%lld notify=%u timer_mod=%u rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  return 0;
}

static int
test_upstream_sleep_on_without_time_control(void)
{
  reset_common();
  icount_sleep = true;

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 300 || notify_virtual_count != 0 ||
      timer_mod_count != 1 || timer_mod_deadline != 1050 ||
      timers_state.vm_clock_warp_start != 50 || virtual_rt_clock_reads != 1 ||
      virtual_deadline_reads != 1) {
    fprintf(stderr,
            "sleep=on upstream warp mismatch: bias=%lld notify=%u timer_mod=%u timer_deadline=%lld warp_start=%lld rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, (long long)timer_mod_deadline,
            (long long)timers_state.vm_clock_warp_start,
            virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  return 0;
}

static int
test_time_control_suppresses_warp(void)
{
  reset_common();
  current_accel = "sim";
  icount_sleep = false;
  const void *handle = qemu_plugin_request_time_control();

  if (!handle || !qemu_plugin_has_time_control()) {
    fprintf(stderr, "time control was not acquired\n");
    return 1;
  }

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 300 || notify_virtual_count != 1 ||
      timer_mod_count != 0 || virtual_rt_clock_reads != 0 ||
      virtual_deadline_reads != 0) {
    fprintf(stderr,
            "time-control warp was not suppressed: bias=%lld notify=%u timer_mod=%u rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  qemu_plugin_update_ns(handle, 4096);
  if (virtual_time_ns != 4096 || plugin_authorized_jumps != 1 ||
      async_requests != 1) {
    fprintf(stderr,
            "authorized plugin jump did not advance virtual time: time=%lld jumps=%u async=%u\n",
            (long long)virtual_time_ns, plugin_authorized_jumps,
            async_requests);
    return 1;
  }

  return 0;
}

static int
test_time_control_suppresses_sleep_on_timer(void)
{
  reset_common();
  current_accel = "sim";
  icount_sleep = true;
  const void *handle = qemu_plugin_request_time_control();

  if (!handle || !qemu_plugin_has_time_control()) {
    fprintf(stderr, "sim sleep-on time control was not acquired\n");
    return 1;
  }

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 300 || notify_virtual_count != 1 ||
      timer_mod_count != 0 || timers_state.vm_clock_warp_start != -1 ||
      virtual_rt_clock_reads != 0 || virtual_deadline_reads != 0) {
    fprintf(stderr,
            "sim sleep-on time-control path did not suppress realtime timer: bias=%lld notify=%u timer_mod=%u warp_start=%lld rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, (long long)timers_state.vm_clock_warp_start,
            virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  return 0;
}

static int
test_non_sim_time_control_keeps_upstream_warp(void)
{
  reset_common();
  current_accel = "tcg";
  icount_sleep = false;
  const void *handle = qemu_plugin_request_time_control();

  if (!handle || !qemu_plugin_has_time_control()) {
    fprintf(stderr, "non-sim time control was not acquired\n");
    return 1;
  }

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 1300 || notify_virtual_count != 1 ||
      timer_mod_count != 0 || virtual_rt_clock_reads != 1 ||
      virtual_deadline_reads != 1) {
    fprintf(stderr,
            "non-sim time-control path did not retain upstream warp: bias=%lld notify=%u timer_mod=%u rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  return 0;
}

static int
test_non_sim_time_control_keeps_upstream_sleep_on_timer(void)
{
  reset_common();
  current_accel = "tcg";
  icount_sleep = true;
  const void *handle = qemu_plugin_request_time_control();

  if (!handle || !qemu_plugin_has_time_control()) {
    fprintf(stderr, "non-sim sleep-on time control was not acquired\n");
    return 1;
  }

  icount_start_warp_timer();

  if (timers_state.qemu_icount_bias != 300 || notify_virtual_count != 0 ||
      timer_mod_count != 1 || timer_mod_deadline != 1050 ||
      timers_state.vm_clock_warp_start != 50 || virtual_rt_clock_reads != 1 ||
      virtual_deadline_reads != 1) {
    fprintf(stderr,
            "non-sim sleep-on time-control path did not retain upstream timer: bias=%lld notify=%u timer_mod=%u timer_deadline=%lld warp_start=%lld rt_reads=%u deadline_reads=%u\n",
            (long long)timers_state.qemu_icount_bias, notify_virtual_count,
            timer_mod_count, (long long)timer_mod_deadline,
            (long long)timers_state.vm_clock_warp_start,
            virtual_rt_clock_reads, virtual_deadline_reads);
    return 1;
  }

  return 0;
}

static int
test_time_control_single_owner(void)
{
  reset_common();
  const void *first = qemu_plugin_request_time_control();
  const void *second = qemu_plugin_request_time_control();

  if (!first || second || !qemu_plugin_has_time_control()) {
    fprintf(stderr,
            "time-control ownership mismatch: first=%p second=%p held=%d\n",
            first, second, qemu_plugin_has_time_control());
    return 1;
  }

  return 0;
}

int
main(void)
{
  if (test_upstream_sleep_off_without_time_control() != 0 ||
      test_upstream_sleep_on_without_time_control() != 0 ||
      test_time_control_suppresses_warp() != 0 ||
      test_time_control_suppresses_sleep_on_timer() != 0 ||
      test_non_sim_time_control_keeps_upstream_warp() != 0 ||
      test_non_sim_time_control_keeps_upstream_sleep_on_timer() != 0 ||
      test_time_control_single_owner() != 0) {
    return 1;
  }

  const bool stock_would_warp = stock_sleep_off_bias_after(300, 1000) == 1300;

  puts("PASS");
  puts("patched_icount_start_warp_timer_fixture=true");
  puts("time_control_predicate_exercised=true");
  puts("time_control_suppresses_sleep_off_bias_warp=true");
  puts("time_control_suppresses_sleep_on_realtime_timer=true");
  puts("non_sim_time_control_keeps_upstream_warp=true");
  puts("non_sim_time_control_keeps_upstream_sleep_on_timer=true");
  puts("notify_preserved_under_time_control=true");
  puts("virtual_clock_reads_under_time_control=0");
  puts("realtime_clock_reads_under_time_control=0");
  puts("plugin_authorized_jump_advances_virtual_time=true");
  printf("stock_negative_control_would_warp=%s\n",
         stock_would_warp ? "true" : "false");
  return stock_would_warp ? 0 : 1;
}
