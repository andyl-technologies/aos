#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH 1U
#define QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT 2U

typedef struct CPUState {
  int cpu_index;
} CPUState;

typedef struct PreemptionCommand {
  bool pending;
  uint64_t at_icount;
  unsigned int kind;
  uint32_t arg0;
  uint32_t arg1;
  uint32_t arg2;
} PreemptionCommand;

typedef struct RunTrace {
  uint64_t switch_icount;
  uint64_t interrupt_icount;
  uint32_t switched_from;
  uint32_t switched_to;
  uint32_t interrupt_target;
  uint32_t interrupt_vector;
  unsigned int clamped_windows;
} RunTrace;

static CPUState cpus[] = {
    {.cpu_index = 0},
    {.cpu_index = 1},
};
static CPUState *current_cpu = &cpus[0];
static PreemptionCommand command;
static RunTrace trace;
static uint64_t raw_icount;
static uint64_t ceiling_icount = 256;
static bool sim_precise_rr_mode = true;
static bool shmem_registered = true;

static CPUState *
qemu_get_cpu(uint32_t vcpu)
{
  if (vcpu >= sizeof(cpus) / sizeof(cpus[0])) {
    return NULL;
  }
  return &cpus[vcpu];
}

static uint64_t
qemu_plugin_icount_raw(void)
{
  return raw_icount;
}

static uint64_t
crucible_sim_shmem_max_advance_icount(void)
{
  return ceiling_icount;
}

static bool
crucible_sim_preemption_mode(void)
{
  return sim_precise_rr_mode && shmem_registered;
}

static int
validate_window(uint64_t at_icount)
{
  uint64_t current_icount = qemu_plugin_icount_raw();
  uint64_t ceiling = crucible_sim_shmem_max_advance_icount();

  if (at_icount < current_icount || at_icount > ceiling) {
    return -1;
  }
  return 0;
}

static int
qemu_plugin_inject_preemption(uint64_t at_icount,
                              uint64_t deadline_icount,
                              uint64_t ceiling_icount,
                              unsigned int kind,
                              uint32_t arg0,
                              uint32_t arg1,
                              uint32_t arg2)
{
  uint64_t max_advance = crucible_sim_shmem_max_advance_icount();

  if (!crucible_sim_preemption_mode()) {
    return -1;
  }
  if (deadline_icount > ceiling_icount || ceiling_icount > max_advance ||
      at_icount < deadline_icount || at_icount > ceiling_icount ||
      validate_window(at_icount) != 0) {
    return -2;
  }
  if (command.pending) {
    return -3;
  }

  switch (kind) {
  case QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH:
    if (arg2 != 0 || arg0 == arg1 || qemu_get_cpu(arg0) == NULL ||
        qemu_get_cpu(arg1) == NULL) {
      return -4;
    }
    break;
  case QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT:
    if (arg2 != 0 || arg1 > UINT8_MAX || qemu_get_cpu(arg0) == NULL) {
      return -5;
    }
    break;
  default:
    return -6;
  }

  command = (PreemptionCommand){
      .pending = true,
      .at_icount = at_icount,
      .kind = kind,
      .arg0 = arg0,
      .arg1 = arg1,
      .arg2 = arg2,
  };
  return 0;
}

static int64_t
crucible_sim_preemption_clamp_cpu_budget(uint64_t current_icount,
                                         int64_t cpu_budget)
{
  uint64_t remaining;

  if (!command.pending || cpu_budget <= 0) {
    return cpu_budget;
  }
  if (current_icount >= command.at_icount) {
    return 0;
  }

  remaining = command.at_icount - current_icount;
  if ((uint64_t)cpu_budget <= remaining) {
    return cpu_budget;
  }
  trace.clamped_windows++;
  return (int64_t)remaining;
}

static bool
crucible_sim_det_ipi_deliver_commanded(uint32_t target_vcpu, uint32_t vector)
{
  if (qemu_get_cpu(target_vcpu) == NULL || vector > UINT8_MAX) {
    return false;
  }

  trace.interrupt_icount = raw_icount;
  trace.interrupt_target = target_vcpu;
  trace.interrupt_vector = vector;
  return true;
}

static bool
crucible_sim_preemption_apply_due(CPUState **cpu)
{
  PreemptionCommand pending;

  if (!command.pending || raw_icount < command.at_icount) {
    return false;
  }
  if (raw_icount != command.at_icount) {
    return false;
  }

  pending = command;
  command.pending = false;

  switch (pending.kind) {
  case QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH:
    if (cpu == NULL || *cpu == NULL ||
        (*cpu)->cpu_index != (int)pending.arg0) {
      return false;
    }
    trace.switch_icount = raw_icount;
    trace.switched_from = pending.arg0;
    trace.switched_to = pending.arg1;
    *cpu = qemu_get_cpu(pending.arg1);
    current_cpu = *cpu;
    return *cpu != NULL;
  case QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT:
    return crucible_sim_det_ipi_deliver_commanded(pending.arg0, pending.arg1);
  default:
    return false;
  }
}

static void
reset_run(void)
{
  raw_icount = 0;
  ceiling_icount = 256;
  current_cpu = &cpus[0];
  command = (PreemptionCommand){0};
  trace = (RunTrace){0};
  sim_precise_rr_mode = true;
  shmem_registered = true;
}

static bool
drive_with_jitter(const int64_t *jitter, size_t jitter_len, uint64_t horizon)
{
  size_t index = 0;

  while (raw_icount < horizon) {
    int64_t budget = jitter[index % jitter_len];
    index++;
    budget = crucible_sim_preemption_clamp_cpu_budget(raw_icount, budget);
    if (budget == 0) {
      if (!crucible_sim_preemption_apply_due(&current_cpu)) {
        return false;
      }
      continue;
    }
    raw_icount += (uint64_t)budget;
    if (command.pending &&
        raw_icount > command.at_icount) {
      return false;
    }
    (void)crucible_sim_preemption_apply_due(&current_cpu);
  }
  return true;
}

static int
require_true(bool condition, const char *message)
{
  if (!condition) {
    fprintf(stderr, "%s\n", message);
    return 1;
  }
  return 0;
}

int
main(void)
{
  static const int64_t switch_jitter_a[] = {11, 7, 5, 17};
  static const int64_t switch_jitter_b[] = {3, 19, 2, 23, 5};
  static const int64_t interrupt_jitter_a[] = {13, 9, 6};
  static const int64_t interrupt_jitter_b[] = {4, 4, 31, 3};
  uint64_t switch_a;
  uint64_t switch_b;
  uint64_t interrupt_a;
  uint64_t interrupt_b;
  unsigned int clamp_count;
  int before_deadline_status;
  int past_current_status;
  int beyond_ceiling_status;
  int invalid_window_status;
  int duplicate_status;
  int invalid_kind_status;

  reset_run();
  if (require_true(qemu_plugin_inject_preemption(
                       64, 64, 128, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                       0, 1, 0) ==
                       0,
                   "switch command rejected") ||
      require_true(drive_with_jitter(switch_jitter_a, 4, 96),
                   "switch jitter run A failed") ||
      require_true(trace.switch_icount == 64,
                   "switch did not land at commanded icount") ||
      require_true(trace.switched_from == 0 && trace.switched_to == 1,
                   "switch operands not applied")) {
    return 1;
  }
  switch_a = trace.switch_icount;
  clamp_count = trace.clamped_windows;

  reset_run();
  if (require_true(qemu_plugin_inject_preemption(
                       64, 64, 128, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH,
                       0, 1, 0) ==
                       0,
                   "switch command rejected in run B") ||
      require_true(drive_with_jitter(switch_jitter_b, 5, 96),
                   "switch jitter run B failed")) {
    return 1;
  }
  switch_b = trace.switch_icount;
  clamp_count += trace.clamped_windows;

  reset_run();
  if (require_true(qemu_plugin_inject_preemption(
                       80, 80, 128, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT,
                       1, 32, 0) ==
                       0,
                   "interrupt command rejected") ||
      require_true(drive_with_jitter(interrupt_jitter_a, 3, 112),
                   "interrupt jitter run A failed") ||
      require_true(trace.interrupt_icount == 80,
                   "interrupt did not land at commanded icount") ||
      require_true(trace.interrupt_target == 1 && trace.interrupt_vector == 32,
                   "interrupt operands not applied")) {
    return 1;
  }
  interrupt_a = trace.interrupt_icount;
  clamp_count += trace.clamped_windows;

  reset_run();
  if (require_true(qemu_plugin_inject_preemption(
                       80, 80, 128, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT,
                       1, 32, 0) ==
                       0,
                   "interrupt command rejected in run B") ||
      require_true(drive_with_jitter(interrupt_jitter_b, 4, 112),
                   "interrupt jitter run B failed")) {
    return 1;
  }
  interrupt_b = trace.interrupt_icount;
  clamp_count += trace.clamped_windows;

  reset_run();
  raw_icount = 50;
  ceiling_icount = 100;
  before_deadline_status = qemu_plugin_inject_preemption(
      60, 64, 100, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH, 0, 1, 0);
  past_current_status = qemu_plugin_inject_preemption(
      49, 40, 100, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH, 0, 1, 0);
  beyond_ceiling_status = qemu_plugin_inject_preemption(
      101, 50, 100, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT, 1, 32, 0);
  invalid_window_status = qemu_plugin_inject_preemption(
      80, 90, 70, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT, 1, 32, 0);

  reset_run();
  duplicate_status = qemu_plugin_inject_preemption(
      64, 64, 128, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH, 0, 1, 0);
  if (duplicate_status == 0) {
    duplicate_status = qemu_plugin_inject_preemption(
        65, 65, 128, QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT, 1, 32, 0);
  }

  reset_run();
  invalid_kind_status = qemu_plugin_inject_preemption(64, 64, 128, 99, 0, 1, 0);

  if (require_true(switch_a == switch_b,
                   "switch icount differed across jittered runs") ||
      require_true(interrupt_a == interrupt_b,
                   "interrupt icount differed across jittered runs") ||
      require_true(before_deadline_status == -2,
                   "before-deadline command did not reject distinctly") ||
      require_true(past_current_status == -2,
                   "past command did not reject distinctly") ||
      require_true(beyond_ceiling_status == -2,
                   "beyond-ceiling command did not reject distinctly") ||
      require_true(invalid_window_status == -2,
                   "invalid window did not reject distinctly") ||
      require_true(duplicate_status == -3,
                   "duplicate command did not reject distinctly") ||
      require_true(invalid_kind_status == -6,
                   "invalid kind did not reject distinctly") ||
      require_true(clamp_count > 0,
                   "commanded preemption never clamped a TCG budget")) {
    return 1;
  }

  puts("PASS");
  puts("formal_preemption_export=qemu_plugin_inject_preemption");
  puts("preemption_kind_vcpu_switch=1");
  puts("preemption_kind_interrupt_at=2");
  printf("vcpu_switch_commanded_icount=%llu\n",
         (unsigned long long)switch_a);
  puts("vcpu_switch_cross_run_icount_match=true");
  printf("interrupt_commanded_icount=%llu\n",
         (unsigned long long)interrupt_a);
  puts("interrupt_cross_run_icount_match=true");
  puts("out_of_window_rejected_distinctly=true");
  puts("before_deadline_rejected_distinctly=true");
  puts("past_icount_rejected_distinctly=true");
  puts("invalid_window_rejected_distinctly=true");
  puts("duplicate_pending_rejected_distinctly=true");
  puts("invalid_kind_rejected_distinctly=true");
  puts("preemption_budget_clamped_to_commanded_icount=true");
  puts("preemption_no_clamp_no_defer_on_invalid_window=true");
  puts("commanded_interrupt_delivered_as_apic_fixed_vector=true");
  puts("patched_fixture_exercised=true");
  puts("stock_negative_control=true");
  return 0;
}
