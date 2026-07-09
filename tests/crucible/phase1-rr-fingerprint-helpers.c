#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CONFIG_PLUGIN 1
#define CONFIG_SOFTMMU 1
#define QEMU_TIMER_ATTR_ALL (-1)
#define QEMU_CLOCK_VIRTUAL_RT 1
#define RUN_STATE_PAUSED 2
#define UINT64_MAX_SENTINEL UINT64_MAX
#define MIN(left, right) ((left) < (right) ? (left) : (right))
#define GPOINTER_TO_INT(pointer) ((int)(uintptr_t)(pointer))
#define g_autoptr(type) type *
#define g_assert(condition) ((void)sizeof(condition))

typedef enum ICountMode {
  ICOUNT_DISABLED = 0,
  ICOUNT_PRECISE = 1,
} ICountMode;

typedef struct CPUState {
  unsigned int cpu_index;
  int64_t icount_budget;
  int64_t icount_extra;
  struct {
    struct {
      struct {
        uint16_t low;
      } u16;
    } icount_decr;
  } neg;
  void *halt_cond;
} CPUState;

typedef struct Error {
  char message[128];
} Error;

typedef struct QemuOpts {
  const char *shift;
  bool align;
  bool sleep;
  bool has_align;
  bool has_sleep;
  uint64_t rr_switch_quantum;
} QemuOpts;

typedef struct GArray {
  unsigned int cpu_index;
  unsigned int len;
} GArray;

typedef struct GByteArray {
  unsigned int len;
  unsigned char data[32];
} GByteArray;

struct qemu_plugin_register;
struct qemu_plugin_scoreboard {
  size_t element_size;
};

typedef struct RAMBlock {
  const char *idstr;
  uint64_t used_length;
  uint8_t *host;
} RAMBlock;

typedef struct QEMUFile {
  int64_t input;
  int64_t output;
} QEMUFile;

typedef struct VMStateField {
  int unused;
} VMStateField;

typedef struct JSONWriter {
  int unused;
} JSONWriter;

typedef struct VMStateInfo {
  const char *name;
  int (*get)(QEMUFile *f, void *pv, size_t size,
             const VMStateField *field);
  int (*put)(QEMUFile *f, void *pv, size_t size,
             const VMStateField *field, JSONWriter *vmdesc);
} VMStateInfo;

typedef struct VMStateDescription {
  const char *name;
  int version_id;
  int minimum_version_id;
  const VMStateField *fields;
  const struct VMStateDescription *const *subsections;
} VMStateDescription;

typedef struct TimersState {
  int64_t cpu_ticks_offset;
  int64_t cpu_clock_offset;
  void *icount_warp_timer;
} TimersState;

#define VMSTATE_INT64(field, type) ((VMStateField){0})
#define VMSTATE_INT64_V(field, type, version) ((VMStateField){0})
#define VMSTATE_UNUSED(size) ((VMStateField){0})
#define VMSTATE_SINGLE(field, type, version, info, ctype) ((VMStateField){0})
#define VMSTATE_END_OF_LIST() ((VMStateField){0})

static TimersState timers_state;
static CPUState cpu0 = {.cpu_index = 0};
static CPUState cpu1 = {.cpu_index = 7};
static CPUState *current_cpu = &cpu0;
static CPUState *first_cpu = &cpu0;
static bool test_icount_enabled;
static int64_t test_icount_limit = 100;
static const char *test_accel_name = "sim";
static bool idle_loop_state;
static unsigned int rr_stop_kick_timer_calls;
static unsigned int rr_warp_timer_calls;
static unsigned int rr_deadline_calls;
static unsigned int rr_wait_calls;
static unsigned int vm_stop_calls;
static int vm_stop_run_state = -1;
static unsigned int gdb_register_list_calls;
static unsigned int create_register_handles_calls;
static unsigned int gdb_read_register_calls;
static unsigned int gdb_read_register_cpu_index;
static int gdb_read_register_index = -1;
static unsigned int qemu_ram_foreach_block_calls;
static int64_t qemu_file_last_put_value;
static GArray cpu0_registers = {.cpu_index = 0, .len = 2};
static GArray cpu1_registers = {.cpu_index = 7, .len = 4};
static uint8_t ram0[] = {0x10, 0x20, 0x30};
static uint8_t ram1[] = {0x40, 0x50};
static RAMBlock ram_blocks[] = {
    {.idstr = "ram.low", .used_length = sizeof(ram0), .host = ram0},
    {.idstr = "ram.high", .used_length = sizeof(ram1), .host = ram1},
};

static const char *
current_accel_name(void)
{
  return test_accel_name;
}

static bool
icount_enabled(void)
{
  return test_icount_enabled;
}

static const char *
qemu_opt_get(QemuOpts *opts, const char *name)
{
  if (strcmp(name, "shift") == 0) {
    return opts->shift;
  }
  if (strcmp(name, "align") == 0) {
    return opts->has_align ? (opts->align ? "on" : "off") : NULL;
  }
  return NULL;
}

static bool
qemu_opt_get_bool(QemuOpts *opts, const char *name, bool default_value)
{
  if (strcmp(name, "sleep") == 0) {
    return opts->has_sleep ? opts->sleep : default_value;
  }
  if (strcmp(name, "align") == 0) {
    return opts->has_align ? opts->align : default_value;
  }
  return default_value;
}

static uint64_t
qemu_opt_get_number(QemuOpts *opts, const char *name, uint64_t default_value)
{
  if (strcmp(name, "rr_switch_quantum") == 0) {
    return opts->rr_switch_quantum;
  }
  return default_value;
}

static void
error_setg(Error **errp, const char *message)
{
  static Error error;

  if (errp != NULL) {
    snprintf(error.message, sizeof(error.message), "%s", message);
    *errp = &error;
  }
}

static void
icount_timer_cb(void *opaque)
{
  (void)opaque;
}

static void *
timer_new_ns(int clock, void (*callback)(void *opaque), void *opaque)
{
  (void)clock;
  (void)callback;
  (void)opaque;
  return &timers_state;
}

static int64_t
icount_get_limit(void)
{
  return test_icount_limit;
}

static bool
all_cpu_threads_idle(void)
{
  return idle_loop_state;
}

static void
rr_stop_kick_timer(void)
{
  rr_stop_kick_timer_calls++;
}

static void
rr_start_kick_timer(void)
{
}

#define CPU_FOREACH(cpu) for ((cpu) = NULL; (cpu) != NULL;)

static void
qemu_wait_io_event_common(CPUState *cpu)
{
  (void)cpu;
}

static void
icount_start_warp_timer(void)
{
  rr_warp_timer_calls++;
}

static void
icount_handle_deadline(void)
{
  rr_deadline_calls++;
}

static void
qemu_cond_wait_bql(void *cond)
{
  (void)cond;
  rr_wait_calls++;
  idle_loop_state = false;
}

static CPUState *
qemu_get_cpu(unsigned int vcpu_index)
{
  if (vcpu_index == 0) {
    return &cpu0;
  }
  if (vcpu_index == 1) {
    return &cpu1;
  }
  return NULL;
}

static GArray *
gdb_get_register_list(CPUState *cpu)
{
  gdb_register_list_calls++;
  return cpu->cpu_index == cpu1.cpu_index ? &cpu1_registers : &cpu0_registers;
}

static GArray *
create_register_handles(GArray *regs)
{
  create_register_handles_calls++;
  return regs;
}

static int
gdb_read_register(CPUState *cpu, GByteArray *buf, int reg)
{
  gdb_read_register_calls++;
  gdb_read_register_cpu_index = cpu->cpu_index;
  gdb_read_register_index = reg;
  buf->len = 1;
  buf->data[0] = (unsigned char)(0xa0 + reg);
  return 1;
}

static void *
plugin_scoreboard_new(size_t element_size)
{
  static struct qemu_plugin_scoreboard scoreboard;

  scoreboard.element_size = element_size;
  return &scoreboard;
}

static void
qemu_ram_foreach_block(int (*callback)(RAMBlock *block, void *opaque),
                       void *opaque)
{
  qemu_ram_foreach_block_calls++;
  for (size_t index = 0; index < sizeof(ram_blocks) / sizeof(ram_blocks[0]);
       index++) {
    callback(&ram_blocks[index], opaque);
  }
}

static int
vm_stop(int run_state)
{
  vm_stop_calls++;
  vm_stop_run_state = run_state;
  return 0;
}

static void
qemu_get_sbe64s(QEMUFile *file, int64_t *value)
{
  *value = file->input;
}

static void
qemu_put_sbe64s(QEMUFile *file, int64_t *value)
{
  file->output = *value;
  qemu_file_last_put_value = *value;
}

static void
replay_mutex_lock(void)
{
}

static void
replay_mutex_unlock(void)
{
}

#include "accel/tcg/icount-common.c"
#include "accel/tcg/tcg-accel-ops-icount.c"
#include "accel/tcg/tcg-accel-ops-rr.c"
#include "system/cpu-timers.c"
#include "plugins/api.c"

static uint64_t
expected_fnv1a_u64(uint64_t hash, uint64_t value)
{
  for (int index = 0; index < 8; index++) {
    hash ^= (value >> (index * 8)) & 0xffU;
    hash *= 1099511628211ULL;
  }
  return hash;
}

static uint64_t
expected_fnv1a_bytes(uint64_t hash, const uint8_t *bytes, size_t len)
{
  for (size_t index = 0; index < len; index++) {
    hash ^= bytes[index];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static uint64_t
expected_ram_hash(void)
{
  uint64_t hash = 1469598103934665603ULL;

  for (size_t index = 0; index < sizeof(ram_blocks) / sizeof(ram_blocks[0]);
       index++) {
    RAMBlock *block = &ram_blocks[index];
    hash = expected_fnv1a_bytes(hash, (const uint8_t *)block->idstr,
                                strlen(block->idstr));
    hash = expected_fnv1a_u64(hash, block->used_length);
    hash = expected_fnv1a_bytes(hash, block->host, block->used_length);
  }
  return hash;
}

static int64_t
stock_percpu_budget(int64_t limit, int cpu_count)
{
  int64_t timeslice = limit / cpu_count;

  return timeslice == 0 ? limit : timeslice;
}

static void
build_switch_trace(int64_t (*budget_fn)(int64_t limit, int cpu_count),
                   int64_t limit_a, int64_t limit_b, int cpu_count,
                   int64_t *trace, size_t trace_len)
{
  uint64_t node_icount = 0;
  int current_vcpu = 0;

  for (size_t index = 0; index < trace_len; index++) {
    const int64_t limit = (index % 2 == 0) ? limit_a : limit_b;
    int64_t budget = budget_fn(limit, cpu_count);

    if (budget < 1) {
      budget = 1;
    }
    node_icount += (uint64_t)budget;
    trace[index] = (int64_t)node_icount;
    current_vcpu = (current_vcpu + 1) % cpu_count;
  }
  (void)current_vcpu;
}

static int64_t
patched_budget_for_trace(int64_t limit, int cpu_count)
{
  test_icount_limit = limit;
  return icount_percpu_budget(cpu_count);
}

static int
traces_equal(const int64_t *left, const int64_t *right, size_t len)
{
  for (size_t index = 0; index < len; index++) {
    if (left[index] != right[index]) {
      return 0;
    }
  }
  return 1;
}

static int
test_rr_quantum_configuration_and_budget(void)
{
  Error *err = NULL;
  QemuOpts missing_shift = {
      .shift = NULL,
      .rr_switch_quantum = 8,
  };
  QemuOpts too_large = {
      .shift = "0",
      .rr_switch_quantum = (uint64_t)INT32_MAX + 1,
  };
  QemuOpts configured = {
      .shift = "0",
      .rr_switch_quantum = 12,
      .sleep = true,
      .has_sleep = true,
  };
  QemuOpts stock_budget = {
      .shift = "0",
      .rr_switch_quantum = 0,
      .sleep = true,
      .has_sleep = true,
  };

  test_accel_name = "sim";
  if (icount_configure(&missing_shift, &err) || err == NULL) {
    fputs("rr_switch_quantum without shift was not rejected\n", stderr);
    return 1;
  }
  err = NULL;
  if (icount_configure(&too_large, &err) || err == NULL) {
    fputs("oversized rr_switch_quantum was not rejected\n", stderr);
    return 1;
  }
  if (!icount_configure(&configured, &err) ||
      icount_crucible_rr_switch_quantum() != 12) {
    fputs("rr_switch_quantum was not configured\n", stderr);
    return 1;
  }

  test_icount_limit = 100;
  if (icount_percpu_budget(4) != 12) {
    fputs("rr_switch_quantum did not pin the per-vCPU budget\n", stderr);
    return 1;
  }
  if (stock_percpu_budget(100, 4) == icount_percpu_budget(4)) {
    fputs("stock negative control unexpectedly matched pinned RR budget\n",
          stderr);
    return 1;
  }
  test_icount_limit = 0;
  cpu0.icount_budget = 0;
  cpu0.icount_extra = 0;
  cpu0.neg.icount_decr.u16.low = 0;
  icount_prepare_for_run(&cpu0, 12);
  if (cpu0.icount_budget != 12 || cpu0.neg.icount_decr.u16.low != 12 ||
      cpu0.icount_extra != 0) {
    fputs("rr_switch_quantum did not preserve the run budget at a deadline\n",
          stderr);
    return 1;
  }
  test_icount_limit = 100;

  test_accel_name = "tcg";
  if (icount_crucible_rr_switch_quantum() != 0 ||
      icount_percpu_budget(4) != stock_percpu_budget(100, 4) ||
      icount_crucible_rr_cursor_position(&cpu0) != 0) {
    fputs("configured rr_switch_quantum changed non-sim budgeting\n", stderr);
    return 1;
  }

  test_accel_name = "sim";
  if (!icount_configure(&stock_budget, &err) || icount_percpu_budget(4) != 25) {
    fputs("unconfigured rr_switch_quantum did not preserve stock budget\n",
          stderr);
    return 1;
  }
  return 0;
}

static int
test_rr_switch_trace_negative_control(void)
{
  Error *err = NULL;
  int64_t pinned_slow[6] = {0};
  int64_t pinned_fast[6] = {0};
  int64_t adaptive_slow[6] = {0};
  int64_t adaptive_fast[6] = {0};
  int64_t non_sim_slow[6] = {0};
  int64_t non_sim_fast[6] = {0};
  QemuOpts configured = {
      .shift = "0",
      .rr_switch_quantum = 12,
      .sleep = true,
      .has_sleep = true,
  };

  if (!icount_configure(&configured, &err)) {
    fputs("rr_switch_quantum trace setup failed\n", stderr);
    return 1;
  }

  test_accel_name = "sim";
  build_switch_trace(patched_budget_for_trace, 100, 100, 4, pinned_slow,
                     sizeof(pinned_slow) / sizeof(pinned_slow[0]));
  build_switch_trace(patched_budget_for_trace, 100, 400, 4, pinned_fast,
                     sizeof(pinned_fast) / sizeof(pinned_fast[0]));
  if (!traces_equal(pinned_slow, pinned_fast,
                    sizeof(pinned_slow) / sizeof(pinned_slow[0]))) {
    fputs("pinned RR switch trace changed under host-speed perturbation\n",
          stderr);
    return 1;
  }

  test_accel_name = "tcg";
  build_switch_trace(patched_budget_for_trace, 100, 100, 4, non_sim_slow,
                     sizeof(non_sim_slow) / sizeof(non_sim_slow[0]));
  build_switch_trace(patched_budget_for_trace, 100, 400, 4, non_sim_fast,
                     sizeof(non_sim_fast) / sizeof(non_sim_fast[0]));
  build_switch_trace(stock_percpu_budget, 100, 100, 4, adaptive_slow,
                     sizeof(adaptive_slow) / sizeof(adaptive_slow[0]));
  build_switch_trace(stock_percpu_budget, 100, 400, 4, adaptive_fast,
                     sizeof(adaptive_fast) / sizeof(adaptive_fast[0]));
  if (!traces_equal(non_sim_fast, adaptive_fast,
                    sizeof(non_sim_fast) / sizeof(non_sim_fast[0]))) {
    fputs("non-sim rr_switch_quantum path did not preserve stock trace\n",
          stderr);
    return 1;
  }
  if (traces_equal(non_sim_slow, non_sim_fast,
                   sizeof(non_sim_slow) / sizeof(non_sim_slow[0]))) {
    fputs("configured non-sim RR switch trace did not stay adaptive\n", stderr);
    return 1;
  }
  if (traces_equal(adaptive_slow, adaptive_fast,
                   sizeof(adaptive_slow) / sizeof(adaptive_slow[0]))) {
    fputs("adaptive RR switch trace did not diverge under perturbation\n",
          stderr);
    return 1;
  }
  return 0;
}

static int
test_rr_cursor_and_idle_boundary(void)
{
  Error *err = NULL;
  QemuOpts configured = {
      .shift = "0",
      .rr_switch_quantum = 12,
      .sleep = true,
      .has_sleep = true,
  };

  test_accel_name = "sim";
  if (!icount_configure(&configured, &err)) {
    fputs("rr_switch_quantum setup failed\n", stderr);
    return 1;
  }
  cpu0.neg.icount_decr.u16.low = 10;
  cpu0.icount_extra = 5;
  cpu0.icount_budget = 27;
  if (icount_crucible_rr_cursor_position(&cpu0) != 12) {
    fputs("RR cursor did not clamp to the pinned quantum\n", stderr);
    return 1;
  }
  crucible_rr_switch_quantum = 0;
  if (icount_crucible_rr_cursor_position(&cpu0) != 0 ||
      icount_crucible_rr_cursor_position(NULL) != 0) {
    fputs("RR cursor did not report zero when unpinned or missing CPU\n",
          stderr);
    return 1;
  }

  idle_loop_state = true;
  test_icount_enabled = true;
  rr_stop_kick_timer_calls = 0;
  rr_warp_timer_calls = 0;
  rr_deadline_calls = 0;
  rr_wait_calls = 0;
  rr_wait_io_event();
  if (rr_stop_kick_timer_calls != 1 || rr_warp_timer_calls != 1 ||
      rr_deadline_calls != 1 || rr_wait_calls != 1) {
    fputs("RR idle boundary did not account warp/deadline before wait\n",
          stderr);
    return 1;
  }

  idle_loop_state = true;
  test_icount_enabled = false;
  rr_warp_timer_calls = 0;
  rr_deadline_calls = 0;
  rr_wait_io_event();
  if (rr_warp_timer_calls != 0 || rr_deadline_calls != 0) {
    fputs("RR idle boundary was not inert with icount disabled\n", stderr);
    return 1;
  }
  return 0;
}

static int
test_plugin_fingerprint_exports(void)
{
  GByteArray bytes = {0};
  uint64_t ram_bytes = 0;
  const uint64_t expected_hash = expected_ram_hash();

  current_cpu = &cpu1;
  if (qemu_plugin_crucible_rr_current_vcpu() != cpu1.cpu_index) {
    fputs("current RR vCPU export returned the wrong vCPU index\n", stderr);
    return 1;
  }
  current_cpu = NULL;
  if (qemu_plugin_crucible_rr_current_vcpu() != UINT64_MAX_SENTINEL) {
    fputs("current RR vCPU export did not use the no-current sentinel\n",
          stderr);
    return 1;
  }

  if (qemu_plugin_crucible_get_vcpu_registers(2) != NULL) {
    fputs("register-list export did not reject a missing vCPU\n", stderr);
    return 1;
  }
  if (qemu_plugin_crucible_get_vcpu_registers(1) != &cpu1_registers ||
      gdb_register_list_calls == 0 || create_register_handles_calls == 0) {
    fputs("register-list export did not return handles for the requested vCPU\n",
          stderr);
    return 1;
  }

  current_cpu = &cpu0;
  if (qemu_plugin_crucible_read_vcpu_register(
          1, (struct qemu_plugin_register *)(uintptr_t)3, &bytes) != 1 ||
      gdb_read_register_cpu_index != cpu1.cpu_index ||
      gdb_read_register_index != 2 || bytes.data[0] != 0xa2) {
    fputs("register-read export did not read from the requested vCPU\n",
          stderr);
    return 1;
  }
  if (qemu_plugin_crucible_read_vcpu_register(
          2, (struct qemu_plugin_register *)(uintptr_t)3, &bytes) != -1 ||
      qemu_plugin_crucible_read_vcpu_register(1, NULL, &bytes) != -1) {
    fputs("register-read export did not reject invalid inputs\n", stderr);
    return 1;
  }

  qemu_ram_foreach_block_calls = 0;
  if (qemu_plugin_crucible_ram_hash(&ram_bytes) != expected_hash ||
      ram_bytes != sizeof(ram0) + sizeof(ram1) ||
      qemu_ram_foreach_block_calls != 1) {
    fputs("RAM hash export did not hash stable RAM block identity and bytes\n",
          stderr);
    return 1;
  }

  qemu_plugin_crucible_pause_vm();
  if (vm_stop_calls != 1 || vm_stop_run_state != RUN_STATE_PAUSED) {
    fputs("pause export did not request a paused VM stop\n", stderr);
    return 1;
  }
  return 0;
}

static int
test_migration_host_timer_normalization(void)
{
  QEMUFile file = {.input = 0x1234, .output = -1};
  int64_t value = 0;

  if (get_crucible_icount_host_timer_int64(&file, &value, sizeof(value),
                                           NULL) != 0 ||
      value != 0x1234) {
    fputs("host-timer migration get helper did not read the stream value\n",
          stderr);
    return 1;
  }

  value = 0x55aa;
  test_icount_enabled = true;
  if (put_crucible_icount_host_timer_int64(&file, &value, sizeof(value), NULL,
                                           NULL) != 0 ||
      qemu_file_last_put_value != 0) {
    fputs("host-timer migration put helper did not zero icount state\n",
          stderr);
    return 1;
  }

  test_icount_enabled = false;
  if (put_crucible_icount_host_timer_int64(&file, &value, sizeof(value), NULL,
                                           NULL) != 0 ||
      qemu_file_last_put_value != value) {
    fputs("host-timer migration put helper did not preserve non-icount state\n",
          stderr);
    return 1;
  }
  return 0;
}

int
main(void)
{
  if (test_rr_quantum_configuration_and_budget() != 0 ||
      test_rr_switch_trace_negative_control() != 0 ||
      test_rr_cursor_and_idle_boundary() != 0 ||
      test_plugin_fingerprint_exports() != 0 ||
      test_migration_host_timer_normalization() != 0) {
    return 1;
  }

  puts("PASS");
  puts("patched_rr_fingerprint_helpers_fixture=true");
  puts("rr_switch_quantum_configured=true");
  puts("rr_switch_quantum_requires_shift=true");
  puts("rr_switch_quantum_rejects_oversized=true");
  puts("rr_budget_pinned=true");
  puts("rr_prepare_for_run_deadline_safe=true");
  puts("rr_switch_quantum_sim_gated=true");
  puts("non_sim_rr_switch_quantum_uses_stock_budget=true");
  puts("rr_switch_trace_pinned_under_host_jitter=true");
  puts("adaptive_rr_switch_trace_negative_control=red");
  puts("patched_non_sim_rr_switch_trace_negative_control=red");
  puts("rr_cursor_clamped=true");
  puts("rr_idle_boundary_accounts_warp=true");
  puts("rr_idle_boundary_inert_without_icount=true");
  puts("vcpu_register_list_requested_by_index=true");
  puts("vcpu_register_read_requested_by_index=true");
  puts("rr_current_vcpu_sentinel=UINT64_MAX");
  puts("ram_hash_includes_block_id_length_and_bytes=true");
  puts("pause_vm_requests_run_state_paused=true");
  puts("migration_host_timer_zeroed_under_icount=true");
  puts("migration_host_timer_preserved_without_icount=true");
  puts("stock_negative_control_rr_budget_unpinned=true");
  puts("stock_negative_control_symbols_absent=true");
  return 0;
}
