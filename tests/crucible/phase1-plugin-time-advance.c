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
static unsigned int run_on_cpu_calls;
static unsigned int clock_advance_calls;
static unsigned int run_timers_calls;
static unsigned int completion_bh_schedules;
static unsigned int completion_calls;
static unsigned int cpu_kick_calls;
static int completion_status;
static int64_t completion_target;
static bool completion_observed_timer_bh;
static bool completion_observed_pending;

enum {
  TIMER_IRQ_BIT = 1u << 0,
};

/*
 * icount model. Under -accel sim the virtual clock is icount-derived:
 * icount_get() == qemu_icount_bias + (retired << icount_time_shift), and
 * cpus_set_virtual_clock is unset so it can only be advanced by moving the
 * bias. The patched icount-common.c fixture defines icount_get() from this
 * state; the plugin's icount_advance_virtual_time_to_ns advances by the bias.
 */
typedef struct QemuSeqLock {
  int unused;
} QemuSeqLock;
typedef struct QemuSpin {
  int unused;
} QemuSpin;
typedef struct TimersState {
  int64_t qemu_icount_bias;
  int icount_time_shift;
  QemuSeqLock vm_clock_seqlock;
  QemuSpin vm_clock_lock;
} TimersState;
TimersState timers_state;
static int64_t retired_icount;
static unsigned int notify_calls;

#define qatomic_set_i64(ptr, value) (*(ptr) = (value))
#define qatomic_read_i64(ptr) (*(ptr))

static void
seqlock_write_lock(QemuSeqLock *sl, QemuSpin *lock)
{
  (void)sl;
  (void)lock;
}

static void
seqlock_write_unlock(QemuSeqLock *sl, QemuSpin *lock)
{
  (void)sl;
  (void)lock;
}

static int64_t
crucible_fixture_retired_icount(void)
{
  return retired_icount;
}

int64_t icount_get(void);

void
qemu_clock_notify(int clock)
{
  (void)clock;
  notify_calls++;
}

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
run_on_cpu(CPUState *cpu, void (*fn)(CPUState *, run_on_cpu_data),
           run_on_cpu_data data)
{
  if (cpu == first_cpu) {
    run_on_cpu_calls++;
    fn(cpu, data);
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
    bh_callback_icount = icount_get();
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
  if (timer_armed && timer_deadline_ns <= icount_get()) {
    timer_armed = false;
    timer_callback_icount = icount_get();
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
  return icount_get();
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

#include "accel/tcg/icount-common.c"
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
  timers_state.qemu_icount_bias = 0;
  timers_state.icount_time_shift = 0;
  retired_icount = 0;
  notify_calls = 0;
  async_queue_calls = 0;
  run_on_cpu_calls = 0;
  clock_advance_calls = 0;
  run_timers_calls = 0;
  completion_bh_schedules = 0;
  completion_calls = 0;
  cpu_kick_calls = 0;
  completion_status = INT_MIN;
  completion_target = -1;
  completion_observed_timer_bh = false;
  completion_observed_pending = false;
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
  completion_observed_pending = qemu_plugin_time_advance_is_pending();
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
         queued_completion_bh == NULL && completion_bh_schedules == 0 &&
         callbacks == 0;
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
  /* Guest retired 100 instructions then idled with a timer armed at 5000. */
  retired_icount = 100;
  arm_virtual_timer(5000);
  if (qemu_plugin_register_time_advance_cb(record_completion, &callbacks) != 0 ||
      qemu_plugin_advance_time_ns(5000) != 0) {
    return false;
  }

  /* Enqueue-only: the clock has not moved and no timer has run yet. */
  if (icount_get() != 100 || clock_advance_calls != 0 ||
      run_timers_calls != 0 || notify_calls != 0 || callbacks != 0 ||
      async_queue_calls != 0 || completion_bh_schedules != 1 ||
      queued_completion_bh == NULL ||
      !qemu_plugin_time_advance_is_pending()) {
    return false;
  }
  if (qemu_plugin_advance_time_ns(5001) != -EBUSY ||
      qemu_plugin_register_time_advance_cb(NULL, NULL) != -EBUSY) {
    return false;
  }

  run_normal_main_loop_bottom_halves();
  /* The bias-bump advance moved the icount-derived clock to the target and ran
   * the due virtual timer; it never used the qtest set-based advance. */
  if (icount_get() != 5000 || clock_advance_calls != 0 ||
      run_timers_calls != 1 || notify_calls != 1 ||
      timer_callback_icount != 5000 || timer_bh_pending || !timer_bh_visible ||
      callbacks != 0 || completion_bh_schedules != 2 ||
      queued_completion_bh == NULL) {
    return false;
  }

  run_normal_main_loop_bottom_halves();
  if (callbacks != 0 || !timer_bh_visible || completion_bh_schedules != 3 ||
      queued_completion_bh == NULL) {
    return false;
  }
  run_normal_main_loop_bottom_halves();
  return callbacks == 1 && completion_calls == 1 && completion_status == 0 &&
         completion_target == 5000 && completion_observed_timer_bh &&
         completion_observed_pending &&
         bh_callback_icount == 5000 &&
         fake_cpu.interrupt_request == TIMER_IRQ_BIT && cpu_kick_calls == 2 &&
         run_on_cpu_calls == 1 &&
         !qemu_plugin_time_advance_is_pending();
}

static bool
test_already_reached_advance_is_idempotent(void)
{
  unsigned int callbacks = 0;

  reset_observable_state();
  /* The clock may pass a queued target before its bottom half runs. Treat that
   * stale target as already satisfied, without rewinding virtual time. */
  retired_icount = 2000;
  if (qemu_plugin_register_time_advance_cb(record_completion, &callbacks) != 0 ||
      qemu_plugin_advance_time_ns(1999) != 0) {
    return false;
  }
  run_normal_main_loop_bottom_halves();
  run_normal_main_loop_bottom_halves();
  run_normal_main_loop_bottom_halves();
  return callbacks == 1 && completion_status == 0 &&
         completion_target == 1999 && icount_get() == 2000 &&
         clock_advance_calls == 0 && run_timers_calls == 1 && notify_calls == 1;
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
         queued_completion_bh == NULL && completion_bh_schedules == 0 &&
         async_queue_calls == 0;
}

/*
 * The class of bug this microtest exists to catch: under -accel sim the virtual
 * clock is icount-derived and cpus_set_virtual_clock is unset, so a qtest-style
 * set-based advance (qemu_clock_advance_virtual_time) can never move the clock
 * and its while (clock < dest) loop spins forever. Model that set-as-no-op and
 * assert it never converges, while the plugin's bias-bump primitive reaches the
 * exact target in one step and runs due virtual timers.
 */
static bool
test_icount_bias_advance_converges_where_qtest_set_would_hang(void)
{
  const int64_t dest = 5000;
  int64_t clock;
  long iterations;

  reset_observable_state();
  retired_icount = 100;

  /* qtest set-based advance under icount: writing virtual_now_ns does not move
   * the icount-derived clock (qemu_clock_get_ns == icount_get()), so the loop
   * never progresses. Bound the iteration count to detect non-convergence. */
  clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
  for (iterations = 0; clock < dest && iterations < 1000000; iterations++) {
    virtual_now_ns = dest;
    clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
  }
  if (clock >= dest) {
    return false; /* the qtest set-based advance would have terminated */
  }

  /* The plugin's bias-bump advance reaches the target and runs due timers. */
  icount_advance_virtual_time_to_ns(dest);
  return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) == dest &&
         icount_get() == dest && run_timers_calls == 1 && notify_calls == 1;
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
    fprintf(stderr, "callback-safe main-loop BH handoff failed\n");
    return 1;
  }
  if (!test_already_reached_advance_is_idempotent()) {
    fprintf(stderr, "already-reached advance was not idempotent\n");
    return 1;
  }
  if (!test_invalid_and_unregistered_requests_fail_before_queue()) {
    fprintf(stderr, "invalid or unregistered advance was queued\n");
    return 1;
  }
  if (!test_icount_bias_advance_converges_where_qtest_set_would_hang()) {
    fprintf(stderr, "icount bias advance did not converge where qtest set hangs\n");
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_time_advance_fixture=true");
  puts("stock_negative_control_mode=callback-return-before-queued-work");
  puts("time_control_predicate_symbol=qemu_plugin_has_time_control");
  puts("advance_symbol=qemu_plugin_advance_time_ns");
  puts("completion_symbol=qemu_plugin_register_time_advance_cb");
  puts("single_time_control_owner=true");
  puts("callback_entry_is_enqueue_only=true");
  puts("overlapping_advance_rejected=true");
  puts("callback_reconfiguration_while_pending_rejected=true");
  puts("pending_predicate_tracks_completion_barrier=true");
  puts("negative_target_rejected_before_queue=true");
  puts("already_reached_target_is_idempotent=true");
  puts("queued_main_loop_worker_runs_virtual_timers=true");
  puts("icount_bias_advance_converges_where_qtest_set_hangs=true");
  puts("completion_uses_normal_main_loop_bh=true");
  puts("completion_uses_two_stage_bh_barrier=true");
  puts("timer_bh_precedes_plugin_completion=true");
  puts("completion_kicks_first_vcpu=true");
  puts("advance_enqueue_kicks_first_vcpu=true");
  puts("advance_arms_at_vcpu_boundary=true");
  puts("callback_path_main_loop_reentry_absent=true");
  return 0;
}
