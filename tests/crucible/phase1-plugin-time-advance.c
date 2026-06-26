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

typedef struct run_on_cpu_data {
  long host_ulong;
} run_on_cpu_data;

struct AioContext {
  int unused;
};

struct CPUState {
  unsigned int interrupt_request;
};

static AioContext main_aio_context;
static CPUState fake_cpu;
static CPUState *current_cpu = &fake_cpu;

#define RUN_ON_CPU_HOST_ULONG(value) ((run_on_cpu_data){.host_ulong = (value)})
#define QEMU_CLOCK_VIRTUAL 1
#define QEMU_TIMER_ATTR_ALL 0
#define QEMU_NET_PACKET_FLAG_NONE 0

static void
async_run_on_cpu(CPUState *cpu, void (*fn)(CPUState *, run_on_cpu_data),
                 run_on_cpu_data data)
{
  fn(cpu, data);
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

#define QTAILQ_FOREACH(var, head, field)                                      \
  for ((var) = (head)->first; (var) != NULL; (var) = (var)->field)

static int64_t virtual_now_ns;
static int64_t timer_deadline_ns;
static bool timer_armed;
static bool timer_bh_pending;
static bool timer_bh_visible;
static bool completion_pending;
static bool completion_bh_pending;
static bool completion_visible;
static bool bql_is_locked;
static uint64_t current_icount;
static uint64_t timer_callback_icount;
static uint64_t bh_callback_icount;
static unsigned int clock_advance_calls;
static unsigned int run_timers_calls;
static unsigned int aio_bh_poll_calls;
static unsigned int main_loop_wait_calls;
static int main_loop_wait_last_nonblocking;

enum {
  TIMER_IRQ_BIT = 1u << 0,
  COMPLETION_IRQ_BIT = 1u << 1,
};

static void
reset_observable_state(void)
{
  virtual_now_ns = 0;
  timer_deadline_ns = 0;
  timer_armed = false;
  timer_bh_pending = false;
  timer_bh_visible = false;
  completion_pending = false;
  completion_bh_pending = false;
  completion_visible = false;
  bql_is_locked = false;
  current_icount = 0;
  timer_callback_icount = 0;
  bh_callback_icount = 0;
  clock_advance_calls = 0;
  run_timers_calls = 0;
  aio_bh_poll_calls = 0;
  main_loop_wait_calls = 0;
  main_loop_wait_last_nonblocking = -1;
  net_clients.first = NULL;
  fake_cpu.interrupt_request = 0;
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
  if (new_time > virtual_now_ns) {
    virtual_now_ns = new_time;
  }
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
  if (!timer_armed) {
    return -1;
  }
  return timer_deadline_ns - virtual_now_ns;
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

bool
bql_locked(void)
{
  return bql_is_locked;
}

int
aio_bh_poll(AioContext *ctx)
{
  bool progress = false;

  (void)ctx;
  aio_bh_poll_calls++;
  if (timer_bh_pending) {
    timer_bh_pending = false;
    timer_bh_visible = true;
    fake_cpu.interrupt_request |= TIMER_IRQ_BIT;
    bh_callback_icount = current_icount;
    progress = true;
  }
  if (completion_bh_pending) {
    completion_bh_pending = false;
    completion_visible = true;
    fake_cpu.interrupt_request |= COMPLETION_IRQ_BIT;
    progress = true;
  }
  return progress ? 1 : 0;
}

void
main_loop_wait(int nonblocking)
{
  main_loop_wait_calls++;
  main_loop_wait_last_nonblocking = nonblocking;
  if (completion_pending) {
    completion_pending = false;
    completion_bh_pending = true;
  }
}

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

struct AdvanceObservation {
  uint64_t producer_host_tick;
  uint64_t timer_icount;
  uint64_t bh_icount;
  bool bh_visible;
  unsigned int interrupt_request;
  int64_t virtual_ns;
};

static struct AdvanceObservation
run_skewed_direct_advance(uint64_t producer_host_tick)
{
  reset_observable_state();
  bql_is_locked = true;
  current_icount = 4096;
  arm_virtual_timer(1000);

  qemu_plugin_advance_virtual_time_direct(1000);

  return (struct AdvanceObservation){
      .producer_host_tick = producer_host_tick,
      .timer_icount = timer_callback_icount,
      .bh_icount = bh_callback_icount,
      .bh_visible = timer_bh_visible,
      .interrupt_request = fake_cpu.interrupt_request,
      .virtual_ns = virtual_now_ns,
  };
}

static void
stock_direct_advance_without_bh_drain(int64_t new_time)
{
  qemu_clock_advance_virtual_time(new_time);
  qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
}

static bool
test_direct_advance_fails_closed_without_owner(void)
{
  reset_observable_state();
  bql_is_locked = true;
  arm_virtual_timer(100);

  qemu_plugin_advance_virtual_time_direct(100);

  return virtual_now_ns == 0 && clock_advance_calls == 0 &&
         run_timers_calls == 0 && aio_bh_poll_calls == 0 &&
         !timer_bh_visible;
}

static bool
test_main_loop_drain_fails_closed_without_owner(void)
{
  reset_observable_state();
  bql_is_locked = true;
  completion_pending = true;

  qemu_plugin_drain_main_loop();

  return main_loop_wait_calls == 0 && completion_pending &&
         !completion_visible && virtual_now_ns == 0;
}

static bool
test_time_control_owner_and_predicate(void)
{
  const void *first = qemu_plugin_request_time_control();
  const void *second = qemu_plugin_request_time_control();

  return first != NULL && second == NULL && qemu_plugin_has_time_control();
}

static bool
test_direct_advance_runs_timer_and_bh_before_return(void)
{
  struct AdvanceObservation early = run_skewed_direct_advance(7);
  struct AdvanceObservation late = run_skewed_direct_advance(99);

  return early.producer_host_tick != late.producer_host_tick &&
         early.virtual_ns == 1000 && late.virtual_ns == 1000 &&
         early.timer_icount == 4096 && late.timer_icount == 4096 &&
         early.bh_icount == 4096 && late.bh_icount == 4096 &&
         early.bh_visible && late.bh_visible &&
         early.interrupt_request == TIMER_IRQ_BIT &&
         late.interrupt_request == TIMER_IRQ_BIT;
}

static bool
test_direct_advance_fails_closed_outside_bql_context(void)
{
  reset_observable_state();
  arm_virtual_timer(1000);

  qemu_plugin_advance_virtual_time_direct(1000);

  return virtual_now_ns == 0 && clock_advance_calls == 0 &&
         run_timers_calls == 0 && aio_bh_poll_calls == 0 &&
         fake_cpu.interrupt_request == 0;
}

static bool
test_main_loop_drain_fails_closed_outside_bql_context(void)
{
  reset_observable_state();
  completion_pending = true;

  qemu_plugin_drain_main_loop();

  return main_loop_wait_calls == 0 && completion_pending &&
         !completion_visible && fake_cpu.interrupt_request == 0;
}

static bool
test_direct_advance_noop_when_no_bh_pending(void)
{
  reset_observable_state();
  bql_is_locked = true;
  qemu_plugin_advance_virtual_time_direct(2000);

  return virtual_now_ns == 2000 && clock_advance_calls == 1 &&
         run_timers_calls == 1 && aio_bh_poll_calls == 1 &&
         !timer_bh_visible && fake_cpu.interrupt_request == 0;
}

static bool
test_drain_main_loop_nonblocking_no_time_advance(void)
{
  reset_observable_state();
  bql_is_locked = true;
  virtual_now_ns = 3000;
  completion_pending = true;

  qemu_plugin_drain_main_loop();

  return main_loop_wait_calls == 1 && main_loop_wait_last_nonblocking == 1 &&
         completion_visible && !completion_pending && virtual_now_ns == 3000 &&
         fake_cpu.interrupt_request == COMPLETION_IRQ_BIT;
}

static bool
test_stock_negative_control_bh_drift_without_drain(void)
{
  reset_observable_state();
  current_icount = 4096;
  arm_virtual_timer(1000);

  stock_direct_advance_without_bh_drain(1000);

  return timer_callback_icount == 4096 && timer_bh_pending &&
         !timer_bh_visible && aio_bh_poll_calls == 0 &&
         fake_cpu.interrupt_request == 0;
}

int
main(void)
{
  if (!test_direct_advance_fails_closed_without_owner()) {
    fprintf(stderr, "direct advance did not fail closed without owner\n");
    return 1;
  }
  if (!test_main_loop_drain_fails_closed_without_owner()) {
    fprintf(stderr, "main-loop drain did not fail closed without owner\n");
    return 1;
  }
  if (!test_time_control_owner_and_predicate()) {
    fprintf(stderr, "time-control ownership was not exclusive\n");
    return 1;
  }
  if (!test_direct_advance_runs_timer_and_bh_before_return()) {
    fprintf(stderr, "direct advance did not run timer and BH synchronously\n");
    return 1;
  }
  if (!test_direct_advance_fails_closed_outside_bql_context()) {
    fprintf(stderr, "direct advance did not fail closed outside BQL context\n");
    return 1;
  }
  if (!test_main_loop_drain_fails_closed_outside_bql_context()) {
    fprintf(stderr, "main-loop drain did not fail closed outside BQL context\n");
    return 1;
  }
  if (!test_direct_advance_noop_when_no_bh_pending()) {
    fprintf(stderr, "direct advance no-BH path was not a no-op drain\n");
    return 1;
  }
  if (!test_drain_main_loop_nonblocking_no_time_advance()) {
    fprintf(stderr, "main-loop drain was not nonblocking or changed time\n");
    return 1;
  }
  if (!test_stock_negative_control_bh_drift_without_drain()) {
    fprintf(stderr, "stock no-drain negative control did not expose BH drift\n");
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_time_advance_fixture=true");
  puts("time_control_predicate_symbol=qemu_plugin_has_time_control");
  puts("direct_advance_symbol=qemu_plugin_advance_virtual_time_direct");
  puts("main_loop_drain_symbol=qemu_plugin_drain_main_loop");
  puts("single_time_control_owner=true");
  puts("direct_advance_fails_closed_without_owner=true");
  puts("main_loop_drain_fails_closed_without_owner=true");
  puts("direct_advance_fails_closed_outside_bql_context=true");
  puts("main_loop_drain_fails_closed_outside_bql_context=true");
  puts("qemu_time_advance_synchronous=true");
  puts("qemu_time_advance_runs_virtual_timers=true");
  puts("qemu_time_advance_bh_drain=true");
  puts("timer_bh_interrupt_request_visible=true");
  puts("timer_bh_visible_before_direct_advance_return=true");
  puts("deterministic_propagation_icount_identical=true");
  puts("no_pending_bh_drain_noop=true");
  puts("qemu_main_loop_drain_nonblocking=true");
  puts("qemu_main_loop_drain_no_virtual_time_advance=true");
  puts("qemu_main_loop_drain_completion_deterministic=true");
  puts("completion_interrupt_request_visible=true");
  puts("stock_negative_control_bh_drift_without_drain=true");
  return 0;
}
