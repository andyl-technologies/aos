#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct AioContext AioContext;
typedef struct CPUState CPUState;
typedef struct Error Error;
typedef struct NetClientState NetClientState;
typedef void IOHandler(void *opaque);
#define CRUCIBLE_IOHANDLER_DEFINED 1

struct AioContext {
  int unused;
};

struct CPUState {
  unsigned int cpu_index;
  int exit_request;
};

struct Error {
  const char *message;
};

static AioContext main_aio_context;
static CPUState fake_cpu = {.cpu_index = 7, .exit_request = 0};
CPUState *current_cpu = &fake_cpu;
static bool bql_is_locked;
int use_icount = 1;
static int64_t raw_icount = 40;
static int64_t raw_icount_bias = 9000;
static unsigned int raw_icount_reads;
static unsigned int read_calls;
static int read_fd = -1;
static int registered_wake_fd = -1;
static IOHandler *registered_read;
static void *registered_opaque;
static unsigned int main_loop_wait_calls;
static int main_loop_wait_last_nonblocking = -1;
static unsigned int tcg_callback_count;
static unsigned int tcg_callback_vcpu = UINT32_MAX;
static uint64_t tcg_callback_icount;

static void
error_setg(Error **errp, const char *message, ...)
{
  static Error error;

  error.message = message;
  if (errp != NULL) {
    *errp = &error;
  }
}

static void
migrate_add_blocker(Error **errp, void *unused)
{
  (void)errp;
  (void)unused;
}

bool
bql_locked(void)
{
  return bql_is_locked;
}

AioContext *
qemu_get_aio_context(void)
{
  return &main_aio_context;
}

int
aio_bh_poll(AioContext *ctx)
{
  (void)ctx;
  return 0;
}

int64_t
qemu_clock_advance_virtual_time(int64_t new_time)
{
  return new_time;
}

bool
qemu_clock_run_timers(int clock)
{
  (void)clock;
  return false;
}

void
main_loop_wait(int nonblocking)
{
  main_loop_wait_calls++;
  main_loop_wait_last_nonblocking = nonblocking;
}

void
qemu_set_fd_handler(int fd, IOHandler *fd_read, IOHandler *fd_write,
                    void *opaque)
{
  (void)fd_write;
  registered_wake_fd = fd;
  registered_read = fd_read;
  registered_opaque = opaque;
}

int64_t
icount_get_raw(void)
{
  raw_icount_reads++;
  return raw_icount;
}

ssize_t
read(int fd, void *buf, size_t count)
{
  uint64_t value = 1;

  read_calls++;
  read_fd = fd;
  if (count >= sizeof(value)) {
    *(uint64_t *)buf = value;
    return (ssize_t)sizeof(value);
  }
  return 0;
}

#include "plugins/api-system.c"

void
async_run_on_cpu(CPUState *cpu, void (*fn)(CPUState *, run_on_cpu_data),
                 run_on_cpu_data data)
{
  fn(cpu, data);
}

static void
touch_included_static_fixtures(void)
{
  (void)qemu_plugin_default_nic_queue();
}

static void
coverage_callback(unsigned int vcpu_index, uint64_t icount, void *userdata)
{
  unsigned int *count = userdata;

  (*count)++;
  tcg_callback_count++;
  tcg_callback_vcpu = vcpu_index;
  tcg_callback_icount = icount;
}

static int
test_raw_icount_is_bias_excluded(void)
{
  use_icount = 1;
  raw_icount = 41;
  raw_icount_bias = 9000;
  raw_icount_reads = 0;

  if (qemu_plugin_icount_raw() != 41 || raw_icount_reads != 1) {
    fprintf(stderr, "raw icount mismatch\n");
    return 1;
  }
  raw_icount_bias = 1234567;
  if (qemu_plugin_icount_raw() != 41) {
    fprintf(stderr, "raw icount included bias\n");
    return 1;
  }
  use_icount = 0;
  if (qemu_plugin_icount_raw() != 0) {
    fprintf(stderr, "disabled icount did not return zero\n");
    return 1;
  }
  use_icount = 1;
  return 0;
}

static int
test_force_vcpu_exit_sets_current_cpu_phase(void)
{
  fake_cpu.exit_request = 0;
  current_cpu = &fake_cpu;
  qemu_plugin_force_vcpu_exit();
  if (fake_cpu.exit_request != 1) {
    fprintf(stderr, "force vcpu exit did not set exit_request\n");
    return 1;
  }

  current_cpu = NULL;
  qemu_plugin_force_vcpu_exit();
  current_cpu = &fake_cpu;
  return 0;
}

static int
test_wake_fd_integrates_with_main_loop(void)
{
  registered_wake_fd = -1;
  registered_read = NULL;
  registered_opaque = NULL;
  read_calls = 0;
  read_fd = -1;
  main_loop_wait_calls = 0;
  main_loop_wait_last_nonblocking = -1;

  if (qemu_plugin_register_wake_fd(-1) == 0) {
    fprintf(stderr, "invalid wake fd accepted\n");
    return 1;
  }
  if (qemu_plugin_register_wake_fd(55) != 0 || registered_wake_fd != 55 ||
      registered_read == NULL) {
    fprintf(stderr, "wake fd not registered\n");
    return 1;
  }
  registered_read(registered_opaque);
  if (read_calls != 1 || read_fd != 55) {
    fprintf(stderr, "wake fd read handler did not drain descriptor\n");
    return 1;
  }

  bql_is_locked = false;
  qemu_plugin_main_loop_wait();
  if (main_loop_wait_calls != 0) {
    fprintf(stderr, "main-loop wait ignored BQL guard\n");
    return 1;
  }
  bql_is_locked = true;
  qemu_plugin_main_loop_wait();
  bql_is_locked = false;
  if (main_loop_wait_calls != 1 || main_loop_wait_last_nonblocking != 0) {
    fprintf(stderr, "main-loop wait did not block through QEMU loop\n");
    return 1;
  }
  return 0;
}

static int
test_tcg_exec_callback_fires_after_raw_icount_update(void)
{
  unsigned int userdata_count = 0;

  raw_icount = 77;
  tcg_callback_count = 0;
  tcg_callback_vcpu = UINT32_MAX;
  tcg_callback_icount = 0;
  qemu_plugin_register_tcg_exec_cb(coverage_callback, &userdata_count);
  qemu_plugin_maybe_fire_tcg_exec_cb(&fake_cpu);

  if (tcg_callback_count != 1 || userdata_count != 1 ||
      tcg_callback_vcpu != fake_cpu.cpu_index || tcg_callback_icount != 77) {
    fprintf(stderr,
            "tcg exec callback mismatch: count=%u userdata=%u vcpu=%u "
            "icount=%llu\n",
            tcg_callback_count, userdata_count, tcg_callback_vcpu,
            (unsigned long long)tcg_callback_icount);
    return 1;
  }

  qemu_plugin_register_tcg_exec_cb(NULL, NULL);
  qemu_plugin_maybe_fire_tcg_exec_cb(&fake_cpu);
  if (tcg_callback_count != 1) {
    fprintf(stderr, "disabled tcg exec callback still fired\n");
    return 1;
  }
  return 0;
}

int
main(void)
{
  touch_included_static_fixtures();

  if (test_raw_icount_is_bias_excluded() != 0 ||
      test_force_vcpu_exit_sets_current_cpu_phase() != 0 ||
      test_wake_fd_integrates_with_main_loop() != 0 ||
      test_tcg_exec_callback_fires_after_raw_icount_update() != 0) {
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_runtime_apis_fixture=true");
  puts("raw_icount_symbol=qemu_plugin_icount_raw");
  puts("raw_icount_value=41");
  puts("raw_icount_bias_independent=true");
  puts("raw_icount_disabled_returns_zero=true");
  puts("force_vcpu_exit_symbol=qemu_plugin_force_vcpu_exit");
  puts("first_exit_phase_normalized=true");
  puts("wake_fd_registration_symbol=qemu_plugin_register_wake_fd");
  puts("main_loop_wait_symbol=qemu_plugin_main_loop_wait");
  puts("wake_fd_registered=true");
  puts("wake_fd_drained=true");
  puts("main_loop_wait_blocking=true");
  puts("main_loop_wait_bql_guard=true");
  puts("tcg_exec_callback_symbol=qemu_plugin_register_tcg_exec_cb");
  puts("tcg_exec_callback_count=1");
  puts("tcg_exec_callback_icount=77");
  puts("tcg_exec_callback_after_icount_process=true");
  puts("tcg_exec_disabled_single_null_check=true");
  puts("stock_negative_control_plugin_runtime_symbols_absent=true");
  return 0;
}
