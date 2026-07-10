#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef struct AioContext AioContext;
typedef struct CPUState CPUState;
typedef struct NetClientState NetClientState;
typedef struct NetQueue NetQueue;
typedef void QEMUBHFunc(void *opaque);
typedef void (*qemu_plugin_time_advance_cb_t)(int status, int64_t time,
                                              void *userdata);

typedef struct run_on_cpu_data {
  unsigned long host_ulong;
} run_on_cpu_data;

struct AioContext {
  int unused;
};

struct CPUState {
  unsigned int interrupt_request;
};

static AioContext main_aio_context;
static CPUState fake_cpu;
CPUState *current_cpu = &fake_cpu;
CPUState *first_cpu = &fake_cpu;

#define RUN_ON_CPU_HOST_ULONG(value)                                         \
  ((run_on_cpu_data){.host_ulong = (unsigned long)(value)})
#define QEMU_CLOCK_VIRTUAL 1
#define QEMU_TIMER_ATTR_ALL 0
#define QEMU_NET_PACKET_FLAG_NONE 0
#define qatomic_read(ptr) (*(ptr))
#define qatomic_load_acquire(ptr) (*(ptr))
#define qatomic_set(ptr, value) (*(ptr) = (value))
#define qatomic_store_release(ptr, value) (*(ptr) = (value))
#define qatomic_cmpxchg(ptr, old_value, new_value)                           \
  ((*(ptr) == (old_value)) ? (*(ptr) = (new_value), (old_value)) : *(ptr))

static void (*queued_cpu_work)(CPUState *, run_on_cpu_data);
static run_on_cpu_data queued_cpu_data;
static QEMUBHFunc *queued_completion_bh;
static void *queued_completion_opaque;
static int64_t virtual_now_ns;
static int64_t timer_deadline_ns;
static bool timer_armed;
static bool timer_bh_pending;
static bool timer_bh_visible;
static uint64_t current_icount;
static uint64_t timer_callback_icount;
static uint64_t bh_callback_icount;
static unsigned int async_queue_calls;
static unsigned int clock_advance_calls;
static unsigned int run_timers_calls;
static unsigned int completion_bh_schedules;
static unsigned int completion_calls;
static unsigned int cpu_kick_calls;
static int completion_status;
static int64_t completion_target;
static bool completion_observed_timer_bh;

enum {
  TIMER_IRQ_BIT = 1u << 0,
};

static void
async_run_on_cpu(CPUState *cpu, void (*fn)(CPUState *, run_on_cpu_data),
                 run_on_cpu_data data)
{
  if (cpu == first_cpu) {
    async_queue_calls++;
    queued_cpu_work = fn;
    queued_cpu_data = data;
  }
}

static void
run_queued_cpu_work(void)
{
  void (*work)(CPUState *, run_on_cpu_data) = queued_cpu_work;

  queued_cpu_work = NULL;
  if (work != NULL) {
    work(first_cpu, queued_cpu_data);
  }
}

void
aio_bh_schedule_oneshot(AioContext *ctx, QEMUBHFunc *cb, void *opaque)
{
  if (ctx == &main_aio_context) {
    completion_bh_schedules++;
    queued_completion_bh = cb;
    queued_completion_opaque = opaque;
  }
}

static void
run_normal_main_loop_bottom_halves(void)
{
  QEMUBHFunc *completion = queued_completion_bh;
  void *opaque = queued_completion_opaque;

  queued_completion_bh = NULL;
  queued_completion_opaque = NULL;
  if (completion != NULL) {
    completion(opaque);
  }
  if (timer_bh_pending) {
    timer_bh_pending = false;
    timer_bh_visible = true;
    fake_cpu.interrupt_request |= TIMER_IRQ_BIT;
    bh_callback_icount = current_icount;
  }
}

static void
arm_virtual_timer(int64_t deadline_ns)
{
  timer_deadline_ns = deadline_ns;
  timer_armed = true;
}

int64_t
qemu_clock_advance_virtual_time(int64_t new_time)
{
  clock_advance_calls++;
  virtual_now_ns = new_time;
  return virtual_now_ns;
}

bool
qemu_clock_run_timers(int clock)
{
  (void)clock;
  run_timers_calls++;
  if (timer_armed && timer_deadline_ns <= virtual_now_ns) {
    timer_armed = false;
    timer_callback_icount = current_icount;
    timer_bh_pending = true;
    return true;
  }
  return false;
}

int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  (void)clock;
  (void)attrs;
  return timer_armed ? timer_deadline_ns - virtual_now_ns : -1;
}

int64_t
qemu_clock_get_ns(int clock)
{
  (void)clock;
  return virtual_now_ns;
}

AioContext *
qemu_get_aio_context(void)
{
  return &main_aio_context;
}

void
qemu_cpu_kick(CPUState *cpu)
{
  if (cpu == first_cpu) {
    cpu_kick_calls++;
  }
}

typedef enum NetClientDriver {
  NET_CLIENT_DRIVER_USER = 0,
  NET_CLIENT_DRIVER_NIC = 1,
} NetClientDriver;

typedef void(NetPacketSent)(NetClientState *sender, ssize_t ret);

typedef struct NetClientInfo {
  NetClientDriver type;
} NetClientInfo;

struct NetClientState {
  NetClientInfo *info;
  int link_down;
  NetQueue *incoming_queue;
  unsigned receive_disabled : 1;
  unsigned int queue_index;
  bool can_receive;
  struct NetClientState *peer;
  struct NetClientState *next;
};

typedef struct NetClientStateList {
  NetClientState *first;
} NetClientStateList;

NetClientStateList net_clients;

#define QTAILQ_FOREACH(var, head, field)                                    \
  for ((var) = (head)->first; (var) != NULL; (var) = (var)->field)

void
qemu_notify_event(void)
{
}

int
qemu_can_receive_packet(NetClientState *nc)
{
  return nc != NULL && !nc->receive_disabled && nc->can_receive;
}

ssize_t
qemu_receive_packet(NetClientState *nc, const uint8_t *buf, int size)
{
  (void)nc;
  (void)buf;
  return size;
}

bool
qemu_net_queue_append_lossless(NetQueue *queue, NetClientState *sender,
                               unsigned flags, const uint8_t *data,
                               size_t size, NetPacketSent *sent_cb)
{
  (void)queue;
  (void)sender;
  (void)flags;
  (void)data;
  (void)size;
  (void)sent_cb;
  return true;
}

bool
qemu_net_queue_flush(NetQueue *queue)
{
  (void)queue;
  return true;
}

#include "plugins/api-system.c"

static void
reset_observable_state(void)
{
  queued_cpu_work = NULL;
  queued_completion_bh = NULL;
  queued_completion_opaque = NULL;
  virtual_now_ns = 0;
  timer_deadline_ns = 0;
  timer_armed = false;
  timer_bh_pending = false;
  timer_bh_visible = false;
  current_icount = 0;
  timer_callback_icount = 0;
  bh_callback_icount = 0;
  async_queue_calls = 0;
  clock_advance_calls = 0;
  run_timers_calls = 0;
  completion_bh_schedules = 0;
  completion_calls = 0;
  cpu_kick_calls = 0;
  completion_status = INT_MIN;
  completion_target = -1;
  completion_observed_timer_bh = false;
  fake_cpu.interrupt_request = 0;
}

static void
record_completion(int status, int64_t target, void *userdata)
{
  unsigned int *counter = userdata;

  (*counter)++;
  completion_calls++;
  completion_status = status;
  completion_target = target;
  completion_observed_timer_bh = timer_bh_visible;
}

static bool
test_advance_fails_closed_without_owner(void)
{
  unsigned int callbacks = 0;

  reset_observable_state();
  if (qemu_plugin_register_time_advance_cb(record_completion, &callbacks) != 0) {
    return false;
  }
  return qemu_plugin_advance_time_ns(100) == -ENODEV &&
         queued_cpu_work == NULL && callbacks == 0;
}

static bool
test_time_control_owner_and_predicate(void)
{
  const void *first = qemu_plugin_request_time_control();
  const void *second = qemu_plugin_request_time_control();

  return first != NULL && second == NULL && qemu_plugin_has_time_control();
}

static bool
test_callback_safe_handoff_and_normal_bh_completion(void)
{
  unsigned int callbacks = 0;

  reset_observable_state();
  current_icount = 4096;
  arm_virtual_timer(1000);
  if (qemu_plugin_register_time_advance_cb(record_completion, &callbacks) != 0 ||
      qemu_plugin_advance_time_ns(1000) != 0) {
    return false;
  }

  if (virtual_now_ns != 0 || clock_advance_calls != 0 ||
      run_timers_calls != 0 || callbacks != 0 || async_queue_calls != 1 ||
      queued_cpu_work == NULL || !qemu_plugin_time_advance_is_pending()) {
    return false;
  }
  if (qemu_plugin_advance_time_ns(1001) != -EBUSY ||
      qemu_plugin_register_time_advance_cb(NULL, NULL) != -EBUSY) {
    return false;
  }

  run_queued_cpu_work();
  if (virtual_now_ns != 1000 || clock_advance_calls != 1 ||
      run_timers_calls != 1 || timer_callback_icount != 4096 ||
      !timer_bh_pending || timer_bh_visible || callbacks != 0 ||
      completion_bh_schedules != 1 || queued_completion_bh == NULL) {
    return false;
  }

  run_normal_main_loop_bottom_halves();
  if (callbacks != 0 || !timer_bh_visible || completion_bh_schedules != 2 ||
      queued_completion_bh == NULL) {
    return false;
  }
  run_normal_main_loop_bottom_halves();
  return callbacks == 1 && completion_calls == 1 && completion_status == 0 &&
         completion_target == 1000 && completion_observed_timer_bh &&
         bh_callback_icount == 4096 &&
         fake_cpu.interrupt_request == TIMER_IRQ_BIT && cpu_kick_calls == 1 &&
         !qemu_plugin_time_advance_is_pending();
}

static bool
test_backward_advance_reports_completion_failure(void)
{
  unsigned int callbacks = 0;

  reset_observable_state();
  virtual_now_ns = 2000;
  if (qemu_plugin_register_time_advance_cb(record_completion, &callbacks) != 0 ||
      qemu_plugin_advance_time_ns(1999) != 0) {
    return false;
  }
  run_queued_cpu_work();
  run_normal_main_loop_bottom_halves();
  run_normal_main_loop_bottom_halves();
  return callbacks == 1 && completion_status == -ERANGE &&
         completion_target == 1999 && virtual_now_ns == 2000 &&
         clock_advance_calls == 0 && run_timers_calls == 0;
}

static bool
test_invalid_and_unregistered_requests_fail_before_queue(void)
{
  reset_observable_state();
  if (qemu_plugin_register_time_advance_cb(NULL, NULL) != 0) {
    return false;
  }
  return qemu_plugin_advance_time_ns(-1) == -EINVAL &&
         qemu_plugin_advance_time_ns(1) == -ENODEV &&
         queued_cpu_work == NULL && async_queue_calls == 0;
}

int
main(void)
{
  if (!test_advance_fails_closed_without_owner()) {
    fprintf(stderr, "advance queued without time-control ownership\n");
    return 1;
  }
  if (!test_time_control_owner_and_predicate()) {
    fprintf(stderr, "time-control ownership was not exclusive\n");
    return 1;
  }
  if (!test_callback_safe_handoff_and_normal_bh_completion()) {
    fprintf(stderr, "callback-safe CPU-work/BH handoff failed\n");
    return 1;
  }
  if (!test_backward_advance_reports_completion_failure()) {
    fprintf(stderr, "backward advance did not fail at completion\n");
    return 1;
  }
  if (!test_invalid_and_unregistered_requests_fail_before_queue()) {
    fprintf(stderr, "invalid or unregistered advance was queued\n");
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_time_advance_fixture=true");
  puts("stock_negative_control=callback-return-before-queued-work");
  puts("time_control_predicate_symbol=qemu_plugin_has_time_control");
  puts("advance_symbol=qemu_plugin_advance_time_ns");
  puts("completion_symbol=qemu_plugin_register_time_advance_cb");
  puts("single_time_control_owner=true");
  puts("callback_entry_is_enqueue_only=true");
  puts("overlapping_advance_rejected=true");
  puts("callback_reconfiguration_while_pending_rejected=true");
  puts("pending_predicate_tracks_completion_barrier=true");
  puts("negative_target_rejected_before_queue=true");
  puts("backward_target_reports_completion_failure=true");
  puts("queued_worker_runs_virtual_timers=true");
  puts("completion_uses_normal_main_loop_bh=true");
  puts("completion_uses_two_stage_bh_barrier=true");
  puts("timer_bh_precedes_plugin_completion=true");
  puts("completion_kicks_first_vcpu=true");
  puts("callback_path_main_loop_reentry_absent=true");
  return 0;
}
