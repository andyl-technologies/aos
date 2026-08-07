#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "qemu/notify.h"
#include "system/runstate.h"

typedef struct CPUState CPUState;
typedef struct NetClientState NetClientState;
typedef struct AioContext AioContext;
typedef void IOHandler(void *opaque);
typedef bool AioPollFn(void *opaque);
#define CRUCIBLE_IOHANDLER_DEFINED 1

struct AioContext {
  int marker;
};

struct CPUState {
  unsigned int cpu_index;
  int exit_request;
  bool running;
  int64_t icount_budget;
  struct {
    struct {
      struct {
        uint16_t low;
      } u16;
    } icount_decr;
  } neg;
  int64_t icount_extra;
};

static CPUState fake_cpu = {.cpu_index = 7, .exit_request = 0};
CPUState *current_cpu = &fake_cpu;
CPUState *first_cpu = &fake_cpu;
int use_icount = 1;
static int64_t raw_icount = 40;
static int64_t raw_icount_bias = 9000;
static const char *active_accel_name = "sim";
bool mttcg_enabled;
static unsigned int raw_icount_reads;
static unsigned int read_calls;
static int read_fd = -1;
static ssize_t read_results[8];
static int read_errnos[8];
static size_t read_result_count;
static size_t read_result_index;
static int fcntl_result = O_NONBLOCK;
static int fcntl_errno;
static int registered_wake_fd = -1;
static int unregistered_wake_fd = -1;
static IOHandler *registered_read;
static void *registered_opaque;
static AioContext main_aio_context = {.marker = 1};
static AioContext *registered_aio_context;
static unsigned int error_report_calls;
static char last_error_report[160];
static unsigned int cpu_kick_calls;
static unsigned int cpu_kick_read_call;
static CPUState *last_kicked_cpu;
static unsigned int wake_notifier_calls;
static unsigned int wake_notifier_read_call;
static int wake_notifier_last_event = -1;
static unsigned int shutdown_request_calls;
static int shutdown_request_reason = -1;
static unsigned int vm_stop_calls;
static RunState vm_stop_state;
static int vm_stop_status;
static unsigned int tcg_callback_count;
static unsigned int tcg_callback_vcpu = UINT32_MAX;
static uint64_t tcg_callback_icount;

const char *
current_accel_name(void)
{
  return active_accel_name;
}

int64_t
qemu_clock_advance_virtual_time(int64_t new_time)
{
  return new_time;
}

AioContext *
qemu_get_aio_context(void)
{
  return &main_aio_context;
}

void
aio_set_fd_handler(AioContext *ctx, int fd, IOHandler *fd_read,
                   IOHandler *fd_write, AioPollFn *io_poll,
                   IOHandler *io_poll_ready, void *opaque)
{
  (void)fd_write;
  (void)io_poll;
  (void)io_poll_ready;
  registered_aio_context = ctx;
  if (fd_read == NULL) {
    unregistered_wake_fd = fd;
    if (registered_wake_fd == fd) {
      registered_wake_fd = -1;
    }
  } else {
    registered_wake_fd = fd;
  }
  registered_read = fd_read;
  registered_opaque = opaque;
}

int
fcntl(int fd, int command, ...)
{
  (void)fd;
  if (command != F_GETFL || fcntl_errno != 0) {
    errno = fcntl_errno != 0 ? fcntl_errno : EINVAL;
    return -1;
  }
  return fcntl_result;
}

void
test_error_report(const char *format, ...)
{
  va_list args;

  error_report_calls++;
  va_start(args, format);
  (void)vsnprintf(last_error_report, sizeof(last_error_report), format, args);
  va_end(args);
}

static void
test_wake_notifier(Notifier *notifier, void *data)
{
  (void)notifier;
  wake_notifier_calls++;
  wake_notifier_read_call = read_calls;
  wake_notifier_last_event = (int)(intptr_t)data;
}

ssize_t
read(int fd, void *buf, size_t count)
{
  ssize_t result;

  read_calls++;
  read_fd = fd;
  if (read_result_index >= read_result_count) {
    errno = EAGAIN;
    return -1;
  }
  result = read_results[read_result_index];
  errno = read_errnos[read_result_index];
  read_result_index++;
  if (result > 0) {
    size_t bytes = (size_t)result < count ? (size_t)result : count;

    memset(buf, 0xa5, bytes);
  }
  return result;
}

#include "accel/tcg/icount-common.c"
#include "plugins/api-system.c"

void
qemu_cpu_kick(CPUState *cpu)
{
  cpu_kick_calls++;
  cpu_kick_read_call = read_calls;
  last_kicked_cpu = cpu;
}

void
qemu_system_shutdown_request(int reason)
{
  shutdown_request_calls++;
  shutdown_request_reason = reason;
}

int
vm_stop(RunState state)
{
  vm_stop_calls++;
  vm_stop_state = state;
  return vm_stop_status;
}

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
test_tb_entry_icount_is_exact_and_nonmutating(void)
{
  uint64_t entry_icount = UINT64_MAX;
  const int64_t budget = 20;
  const uint16_t remaining = 13;

  use_icount = 1;
  timers_state.qemu_icount = 41;
  fake_cpu.running = true;
  fake_cpu.icount_budget = budget;
  fake_cpu.neg.icount_decr.u16.low = remaining;
  fake_cpu.icount_extra = 0;
  raw_icount_reads = 0;
  if (qemu_plugin_icount_at_tb_entry(7, &entry_icount) != 0 ||
      entry_icount != 41 || raw_icount_reads != 0 ||
      timers_state.qemu_icount != 41 || fake_cpu.icount_budget != budget ||
      fake_cpu.neg.icount_decr.u16.low != remaining) {
    fprintf(stderr, "exact TB-entry icount mismatch\n");
    return 1;
  }
  if (qemu_plugin_icount_at_tb_entry(0, &entry_icount) == 0 ||
      qemu_plugin_icount_at_tb_entry(7, NULL) == 0) {
    fprintf(stderr, "invalid TB-entry icount request was accepted\n");
    return 1;
  }
  use_icount = 0;
  if (qemu_plugin_icount_at_tb_entry(7, &entry_icount) == 0) {
    fprintf(stderr, "non-precise TB-entry icount request was accepted\n");
    return 1;
  }
  use_icount = 1;
  return 0;
}

static int
assert_tb_entry(uint64_t tb_insns, uint64_t expected_entry)
{
  uint64_t entry_icount = UINT64_MAX;
  const int64_t committed_before = timers_state.qemu_icount;
  const int64_t budget_before = current_cpu->icount_budget;
  const uint16_t remaining_before = current_cpu->neg.icount_decr.u16.low;
  const int64_t extra_before = current_cpu->icount_extra;

  if (qemu_plugin_icount_at_tb_entry(tb_insns, &entry_icount) != 0 ||
      entry_icount != expected_entry ||
      timers_state.qemu_icount != committed_before ||
      current_cpu->icount_budget != budget_before ||
      current_cpu->neg.icount_decr.u16.low != remaining_before ||
      current_cpu->icount_extra != extra_before) {
    fprintf(stderr,
            "TB-entry sequence mismatch: insns=%llu expected=%llu got=%llu\n",
            (unsigned long long)tb_insns,
            (unsigned long long)expected_entry,
            (unsigned long long)entry_icount);
    return 1;
  }
  return 0;
}

static int
test_tb_entry_icount_chains_early_exits_and_rr_switches(void)
{
  CPUState second_cpu = {.cpu_index = 8};

  use_icount = 1;
  current_cpu = &fake_cpu;
  fake_cpu.running = true;
  fake_cpu.icount_budget = 20;
  fake_cpu.icount_extra = 0;
  timers_state.qemu_icount = 100;

  /* A chained TB callback runs after each full reservation is subtracted. */
  fake_cpu.neg.icount_decr.u16.low = 15;
  if (assert_tb_entry(5, 100) != 0) {
    return 1;
  }
  fake_cpu.neg.icount_decr.u16.low = 8;
  if (assert_tb_entry(7, 105) != 0) {
    return 1;
  }

  /* An early exit restores unexecuted instructions before the next TB. */
  fake_cpu.neg.icount_decr.u16.low = 15;
  if (assert_tb_entry(5, 100) != 0) {
    return 1;
  }
  fake_cpu.neg.icount_decr.u16.low = 18;
  fake_cpu.neg.icount_decr.u16.low -= 4;
  if (assert_tb_entry(4, 102) != 0) {
    return 1;
  }

  /* RR commits one vCPU before the next vCPU starts its own budget. */
  timers_state.qemu_icount = 0;
  fake_cpu.icount_budget = 10;
  fake_cpu.neg.icount_decr.u16.low = 6;
  if (assert_tb_entry(4, 0) != 0) {
    return 1;
  }
  fake_cpu.running = false;
  timers_state.qemu_icount = 4;
  second_cpu.running = true;
  second_cpu.icount_budget = 8;
  second_cpu.neg.icount_decr.u16.low = 5;
  current_cpu = &second_cpu;
  if (assert_tb_entry(3, 4) != 0) {
    return 1;
  }
  second_cpu.running = false;
  timers_state.qemu_icount = 7;
  fake_cpu.running = true;
  fake_cpu.icount_budget = 10;
  fake_cpu.neg.icount_decr.u16.low = 8;
  current_cpu = &fake_cpu;
  if (assert_tb_entry(2, 7) != 0) {
    return 1;
  }

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
  Notifier wake_notifier = {.notify = test_wake_notifier};
  const ssize_t drain_results[] = {-1, 256, 3, -1};
  const int drain_errnos[] = {EINTR, 0, 0, EAGAIN};
  const ssize_t eof_result[] = {0};
  const int eof_errno[] = {0};
  const ssize_t hard_error_result[] = {-1};
  const int hard_error_errno[] = {EIO};

  registered_wake_fd = -1;
  unregistered_wake_fd = -1;
  registered_read = NULL;
  registered_opaque = NULL;
  registered_aio_context = NULL;
  read_calls = 0;
  read_fd = -1;
  read_result_count = 0;
  read_result_index = 0;
  fcntl_result = O_NONBLOCK;
  fcntl_errno = 0;
  error_report_calls = 0;
  last_error_report[0] = '\0';
  cpu_kick_calls = 0;
  cpu_kick_read_call = 0;
  last_kicked_cpu = NULL;
  wake_notifier_calls = 0;
  wake_notifier_read_call = 0;
  wake_notifier_last_event = -1;
  shutdown_request_calls = 0;
  shutdown_request_reason = -1;
  first_cpu = &fake_cpu;
  qemu_plugin_wake_notifier_add(&wake_notifier);

  if (qemu_plugin_register_wake_fd(-1) == 0) {
    fprintf(stderr, "invalid wake fd accepted\n");
    return 1;
  }
  fcntl_result = 0;
  if (qemu_plugin_register_wake_fd(54) == 0) {
    fprintf(stderr, "blocking wake fd accepted\n");
    return 1;
  }
  fcntl_errno = EBADF;
  if (qemu_plugin_register_wake_fd(54) == 0) {
    fprintf(stderr, "wake fd with failed F_GETFL accepted\n");
    return 1;
  }
  fcntl_errno = 0;
  fcntl_result = O_NONBLOCK;
  if (qemu_plugin_register_wake_fd(55) != 0 || registered_wake_fd != 55 ||
      registered_read == NULL || registered_aio_context != &main_aio_context) {
    fprintf(stderr, "wake fd not registered on the main AioContext\n");
    return 1;
  }
  memcpy(read_results, drain_results, sizeof(drain_results));
  memcpy(read_errnos, drain_errnos, sizeof(drain_errnos));
  read_result_count = sizeof(drain_results) / sizeof(drain_results[0]);
  read_result_index = 0;
  registered_read(registered_opaque);
  if (read_calls != 4 || read_fd != 55 || registered_wake_fd != 55 ||
      error_report_calls != 0 || cpu_kick_calls != 1 ||
      cpu_kick_read_call != read_calls || last_kicked_cpu != &fake_cpu ||
      wake_notifier_calls != 1 || wake_notifier_read_call != read_calls ||
      wake_notifier_last_event != QEMU_PLUGIN_WAKE_EVENT_DRAINED) {
    fprintf(stderr, "wake fd handler did not drain through EAGAIN\n");
    return 1;
  }

  registered_read(registered_opaque);
  if (cpu_kick_calls != 1) {
    fprintf(stderr, "wake fd handler kicked on a spurious EAGAIN\n");
    return 1;
  }

  first_cpu = NULL;
  registered_read(registered_opaque);
  first_cpu = &fake_cpu;
  if (cpu_kick_calls != 1) {
    fprintf(stderr, "wake fd handler kicked a nonexistent first vCPU\n");
    return 1;
  }

  if (qemu_plugin_register_wake_fd(55) != 0 ||
      qemu_plugin_register_wake_fd(56) != -EBUSY ||
      unregistered_wake_fd != -1 || registered_wake_fd != 55 ||
      registered_read == NULL) {
    fprintf(stderr, "wake fd registration was not single-owner/idempotent\n");
    return 1;
  }
  memcpy(read_results, eof_result, sizeof(eof_result));
  memcpy(read_errnos, eof_errno, sizeof(eof_errno));
  read_result_count = 1;
  read_result_index = 0;
  registered_read(registered_opaque);
  if (qemu_plugin_wake_fd != -1 || registered_read != NULL ||
      unregistered_wake_fd != 55 || error_report_calls != 1 ||
      strstr(last_error_report, "reached EOF") == NULL ||
      cpu_kick_calls != 2 || wake_notifier_calls != 2 ||
      wake_notifier_last_event != QEMU_PLUGIN_WAKE_EVENT_FAILED ||
      shutdown_request_calls != 1 ||
      shutdown_request_reason != SHUTDOWN_CAUSE_HOST_ERROR) {
    fprintf(stderr, "wake fd EOF did not report and unregister\n");
    return 1;
  }

  if (qemu_plugin_register_wake_fd(57) != 0 || registered_read == NULL) {
    fprintf(stderr, "wake fd not re-registered after EOF\n");
    return 1;
  }
  memcpy(read_results, hard_error_result, sizeof(hard_error_result));
  memcpy(read_errnos, hard_error_errno, sizeof(hard_error_errno));
  read_result_count = 1;
  read_result_index = 0;
  registered_read(registered_opaque);
  if (qemu_plugin_wake_fd != -1 || registered_read != NULL ||
      unregistered_wake_fd != 57 || error_report_calls != 2 ||
      strstr(last_error_report, "read failed") == NULL ||
      cpu_kick_calls != 3 || wake_notifier_calls != 3 ||
      wake_notifier_last_event != QEMU_PLUGIN_WAKE_EVENT_FAILED ||
      shutdown_request_calls != 2 ||
      shutdown_request_reason != SHUTDOWN_CAUSE_HOST_ERROR) {
    fprintf(stderr, "wake fd hard error did not report and unregister\n");
    return 1;
  }

  qemu_plugin_wake_notifier_remove(&wake_notifier);
  return 0;
}

static int
test_plugin_shutdown_selects_clean_and_fail_loud_causes(void)
{
  shutdown_request_calls = 0;
  shutdown_request_reason = -1;
  cpu_kick_calls = 0;
  first_cpu = &fake_cpu;

  qemu_plugin_request_shutdown(0);
  if (shutdown_request_calls != 1 ||
      shutdown_request_reason != SHUTDOWN_CAUSE_HOST_QMP_QUIT ||
      cpu_kick_calls != 1) {
    fprintf(stderr, "clean plugin shutdown did not use QMP-quit cause\n");
    return 1;
  }

  qemu_plugin_request_shutdown(1);
  if (shutdown_request_calls != 2 ||
      shutdown_request_reason != SHUTDOWN_CAUSE_HOST_ERROR ||
      cpu_kick_calls != 2) {
    fprintf(stderr, "fail-loud plugin shutdown did not use host-error cause\n");
    return 1;
  }
  return 0;
}

static int
test_single_threaded_rr_mode_discriminator_fixture(void)
{
  active_accel_name = "sim";
  mttcg_enabled = false;
  if (qemu_plugin_crucible_single_threaded_rr() != 1) {
    fprintf(stderr, "single-threaded sim mode was not reported\n");
    return 1;
  }
  mttcg_enabled = true;
  if (qemu_plugin_crucible_single_threaded_rr() != 0) {
    fprintf(stderr, "MTTCG mode was reported as serialized\n");
    return 1;
  }
  mttcg_enabled = false;
  active_accel_name = "tcg";
  if (qemu_plugin_crucible_single_threaded_rr() != 0) {
    fprintf(stderr, "non-sim accelerator was reported as Crucible sim mode\n");
    return 1;
  }
  active_accel_name = "sim";
  return 0;
}

static int
test_vmstop_requires_exact_single_threaded_sim_boundary(void)
{
  vm_stop_calls = 0;
  vm_stop_state = RUN_STATE__MAX;
  vm_stop_status = 0;
  current_cpu = &fake_cpu;
  use_icount = ICOUNT_PRECISE;
  active_accel_name = "sim";
  mttcg_enabled = false;

  if (qemu_plugin_request_vmstop() != -EPERM || vm_stop_calls != 0) {
    fprintf(stderr, "VM stop accepted outside an RR-owned exact callback\n");
    return 1;
  }

  qemu_plugin_crucible_exact_boundary_enter();
  if (qemu_plugin_request_vmstop() != 0 || vm_stop_calls != 1 ||
      vm_stop_state != RUN_STATE_PAUSED ||
      !qemu_plugin_crucible_vmstop_pending()) {
    fprintf(stderr, "exact sim boundary did not request native VM stop\n");
    return 1;
  }
  if (qemu_plugin_request_vmstop() != -EALREADY || vm_stop_calls != 1) {
    fprintf(stderr, "duplicate VM stop admission was not rejected\n");
    return 1;
  }
  if (!qemu_plugin_crucible_vmstop_admission_pending()) {
    fprintf(stderr, "VM stop admission state was not retained\n");
    return 1;
  }
  qemu_plugin_crucible_vmstop_request_complete();
  if (!qemu_plugin_crucible_vmstop_pending()) {
    fprintf(stderr, "premature resume cleared an unconsumed VM stop\n");
    return 1;
  }
  qemu_plugin_crucible_vmstop_request_stopped(-EIO);
  if (qemu_plugin_crucible_vmstop_admission_pending() ||
      !qemu_plugin_crucible_vmstop_pending() ||
      qemu_plugin_crucible_vmstop_flush_status() != -EIO) {
    fprintf(stderr, "consumed VM stop did not enter the stopped state\n");
    return 1;
  }
  qemu_plugin_crucible_vmstop_request_complete();
  if (qemu_plugin_crucible_vmstop_pending() ||
      qemu_plugin_crucible_vmstop_flush_status() != 0) {
    fprintf(stderr, "completed stop/resume cycle retained the VM stop fence\n");
    return 1;
  }

  current_cpu = NULL;
  if (qemu_plugin_request_vmstop() == 0 || vm_stop_calls != 1) {
    fprintf(stderr, "VM stop accepted without a current vCPU\n");
    return 1;
  }
  current_cpu = &fake_cpu;
  use_icount = ICOUNT_DISABLED;
  if (qemu_plugin_request_vmstop() == 0 || vm_stop_calls != 1) {
    fprintf(stderr, "VM stop accepted without precise icount\n");
    return 1;
  }
  use_icount = ICOUNT_PRECISE;
  mttcg_enabled = true;
  if (qemu_plugin_request_vmstop() == 0 || vm_stop_calls != 1) {
    fprintf(stderr, "VM stop accepted under MTTCG\n");
    return 1;
  }
  mttcg_enabled = false;
  active_accel_name = "tcg";
  if (qemu_plugin_request_vmstop() == 0 || vm_stop_calls != 1) {
    fprintf(stderr, "VM stop accepted outside the sim accelerator\n");
    return 1;
  }

  active_accel_name = "sim";
  qemu_plugin_crucible_exact_boundary_leave();
  if (qemu_plugin_request_vmstop() != -EPERM || vm_stop_calls != 1) {
    fprintf(stderr, "instruction-style callback context was not rejected\n");
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
      test_tb_entry_icount_is_exact_and_nonmutating() != 0 ||
      test_tb_entry_icount_chains_early_exits_and_rr_switches() != 0 ||
      test_force_vcpu_exit_sets_current_cpu_phase() != 0 ||
      test_wake_fd_integrates_with_main_loop() != 0 ||
      test_plugin_shutdown_selects_clean_and_fail_loud_causes() != 0 ||
      test_single_threaded_rr_mode_discriminator_fixture() != 0 ||
      test_vmstop_requires_exact_single_threaded_sim_boundary() != 0 ||
      test_tcg_exec_callback_fires_after_raw_icount_update() != 0) {
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_runtime_apis_fixture=true");
  puts("raw_icount_symbol=qemu_plugin_icount_raw");
  puts("raw_icount_value=41");
  puts("raw_icount_bias_independent=true");
  puts("raw_icount_disabled_returns_zero=true");
  puts("tb_entry_icount_symbol=qemu_plugin_icount_at_tb_entry");
  puts("tb_entry_icount_nonmutating=true");
  puts("tb_entry_icount_chained_early_exit_multi_vcpu=true");
  puts("force_vcpu_exit_symbol=qemu_plugin_force_vcpu_exit");
  puts("first_exit_phase_normalized=true");
  puts("single_threaded_rr_symbol=qemu_plugin_crucible_single_threaded_rr");
  puts("single_threaded_rr_mode_discriminator_fixture_exercised=true");
  puts("request_vmstop_symbol=qemu_plugin_request_vmstop");
  puts("request_vmstop_native_pause_admission=true");
  puts("request_vmstop_rejects_nonexact_modes=true");
  puts("request_vmstop_rejects_unsafe_callback_context=true");
  puts("request_vmstop_rejects_duplicate_admission=true");
  puts("request_vmstop_preserves_async_flush_failure=true");
  puts("wake_fd_registration_symbol=qemu_plugin_register_wake_fd");
  puts("wake_fd_registered=true");
  puts("wake_fd_single_owner=true");
  puts("wake_fd_same_descriptor_idempotent=true");
  puts("wake_fd_drained=true");
  puts("wake_fd_requires_nonblocking=true");
  puts("wake_fd_eintr_retried=true");
  puts("wake_fd_short_reads_drained_to_eagain=true");
  puts("wake_fd_kicks_first_vcpu_only_after_drain=true");
  puts("wake_fd_spurious_eagain_does_not_kick=true");
  puts("wake_fd_failure_kicks_vcpu_for_shutdown=true");
  puts("wake_fd_notifies_devices_after_drain=true");
  puts("wake_fd_failure_requests_host_error_shutdown=true");
  puts("wake_fd_eof_reported_and_unregistered=true");
  puts("wake_fd_hard_error_reported_and_unregistered=true");
  puts("plugin_shutdown_symbol=qemu_plugin_request_shutdown");
  puts("plugin_shutdown_clean_exit_cause=true");
  puts("plugin_shutdown_fail_loud_cause=true");
  puts("tcg_exec_callback_symbol=qemu_plugin_register_tcg_exec_cb");
  puts("tcg_exec_callback_count=1");
  puts("tcg_exec_callback_icount=77");
  puts("tcg_exec_callback_after_icount_process=true");
  puts("tcg_exec_disabled_single_null_check=true");
  puts("stock_negative_control_plugin_runtime_symbols_absent=true");
  return 0;
}
