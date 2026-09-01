#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_PLUGIN 1
#define CONFIG_SOFTMMU 1
#define QEMU_TIMER_ATTR_ALL (-1)
#define QEMU_CLOCK_VIRTUAL_RT 1
#define UINT64_MAX_SENTINEL UINT64_MAX
#define MIN(left, right) ((left) < (right) ? (left) : (right))
#define GPOINTER_TO_INT(pointer) ((int)(uintptr_t)(pointer))
#define g_autoptr(type) type *
#define g_assert(condition) ((void)sizeof(condition))
#define G_CHECKSUM_SHA256 2
#define G_MAXSIZE SIZE_MAX
#define g_steal_pointer(pp) test_g_steal_pointer((void **)(pp))
#define g_clear_pointer(pp, destroy)                                             \
  do {                                                                           \
    void *clear_pointer_value = *(void **)(pp);                                   \
    *(void **)(pp) = NULL;                                                        \
    if (clear_pointer_value != NULL) {                                            \
      destroy(clear_pointer_value);                                               \
    }                                                                            \
  } while (0)

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

typedef struct MigrationIncomingState MigrationIncomingState;

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
  unsigned char data[1024];
} GByteArray;

typedef size_t gsize;

typedef struct GChecksum {
  uint64_t state;
  uint64_t bytes;
} GChecksum;

struct qemu_plugin_register;
struct qemu_plugin_scoreboard {
  size_t element_size;
  GArray *data;
};

typedef struct {
  struct qemu_plugin_scoreboard *score;
} qemu_plugin_u64;

uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry, size_t index);

typedef struct RAMBlock {
  const char *idstr;
  uint64_t used_length;
  uint8_t *host;
  void *mr;
} RAMBlock;

typedef struct QIOChannelBuffer {
  uint8_t *data;
  size_t usage;
} QIOChannelBuffer;

#define QIO_CHANNEL(channel) (channel)
#define OBJECT(object) (object)

typedef struct QEMUFile {
  int64_t input;
  int64_t output;
  QIOChannelBuffer *buffer;
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
static unsigned int gdb_register_list_calls;
static unsigned int create_register_handles_calls;
static unsigned int gdb_read_register_calls;
static unsigned int gdb_read_register_cpu_index;
static int gdb_read_register_index = -1;
static unsigned int qemu_ram_foreach_block_calls;
static int64_t qemu_file_last_put_value;
static int qemu_save_device_state_status;
static int qemu_file_close_status;
static int schema_digest_status;
static uint64_t schema_sections = 3;
static unsigned int schema_variant;
static int64_t observed_icount = 9876;
static bool observed_running;
static unsigned int qemu_save_device_state_calls;
static unsigned int dirty_log_start_calls;
static unsigned int dirty_log_stop_calls;
static unsigned int global_dirty_tracking;
static bool test_bql_locked;
static unsigned int bql_lock_calls;
static unsigned int bql_unlock_calls;
static uint8_t serialized_device_state[] = {0x51, 0x45, 0x56, 0x4d, 0x01};
static QIOChannelBuffer device_state_buffer;
static QEMUFile device_state_file;
static GArray cpu0_registers = {.cpu_index = 0, .len = 2};
static GArray cpu1_registers = {.cpu_index = 7, .len = 4};
static uint8_t ram0[] = {0x10, 0x20, 0x30};
static uint8_t ram1[] = {0x40, 0x50};
static RAMBlock ram_blocks[] = {
    {.idstr = "ram.low", .used_length = sizeof(ram0), .host = ram0, .mr = &ram0},
    {.idstr = "ram.high", .used_length = sizeof(ram1), .host = ram1, .mr = &ram1},
};

#define GLOBAL_DIRTY_MIGRATION (1U << 0)

static void *
test_g_steal_pointer(void **pointer)
{
  void *value = *pointer;
  *pointer = NULL;
  return value;
}

static GByteArray *
g_byte_array_new(void)
{
  return calloc(1, sizeof(GByteArray));
}

static void
g_byte_array_append(GByteArray *array, const uint8_t *bytes, size_t length)
{
  if (array->len + length > sizeof(array->data)) {
    fputs("fingerprint capture fixture buffer overflow\n", stderr);
    abort();
  }
  memcpy(array->data + array->len, bytes, length);
  array->len += length;
}

static uint8_t *
g_byte_array_free(GByteArray *array, bool free_segment)
{
  uint8_t *data = NULL;

  if (!free_segment) {
    data = malloc(array->len);
    if (data != NULL) {
      memcpy(data, array->data, array->len);
    }
  }
  free(array);
  return data;
}

static void
g_free(void *pointer)
{
  free(pointer);
}

static void
error_free(Error *error)
{
  free(error);
}

static bool
bql_locked(void)
{
  return test_bql_locked;
}

static void
bql_lock(void)
{
  bql_lock_calls++;
  test_bql_locked = true;
}

static void
bql_unlock(void)
{
  bql_unlock_calls++;
  test_bql_locked = false;
}

static bool
memory_global_dirty_log_start(unsigned int flags, Error **error)
{
  (void)error;
  if (!test_bql_locked) {
    return false;
  }
  dirty_log_start_calls++;
  global_dirty_tracking |= flags;
  return true;
}

static void
memory_global_dirty_log_stop(unsigned int flags)
{
  dirty_log_stop_calls++;
  global_dirty_tracking &= ~flags;
}

static GChecksum *
g_checksum_new(int type)
{
  static GChecksum checksum;

  if (type != G_CHECKSUM_SHA256) {
    return NULL;
  }
  checksum.state = 14695981039346656037ULL;
  checksum.bytes = 0;
  return &checksum;
}

static void
g_checksum_update(GChecksum *checksum, const unsigned char *data, size_t len)
{
  for (size_t index = 0; index < len; index++) {
    checksum->state ^= data[index];
    checksum->state *= 1099511628211ULL;
  }
  checksum->bytes += len;
}

static void
g_checksum_get_digest(GChecksum *checksum, unsigned char *digest, gsize *len)
{
  const gsize output_len = *len < 32 ? *len : 32;

  for (gsize index = 0; index < output_len; index++) {
    digest[index] = (unsigned char)(checksum->state >> ((index % 8) * 8));
    digest[index] ^= (unsigned char)(checksum->bytes + index);
  }
  *len = output_len;
}

static void
g_checksum_free(GChecksum *checksum)
{
  (void)checksum;
}

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

#define CPU_FOREACH(cpu) \
  for ((cpu) = first_cpu; (cpu) != NULL; (cpu) = NULL)

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

uint64_t
qemu_plugin_u64_get(qemu_plugin_u64 entry, size_t index)
{
  (void)entry;
  return index;
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

static bool
memory_region_is_ram(void *mr)
{
  return mr != NULL;
}

static bool
memory_region_is_rom(void *mr)
{
  (void)mr;
  return false;
}

static bool
memory_region_is_ram_device(void *mr)
{
  (void)mr;
  return false;
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

static QIOChannelBuffer *
qio_channel_buffer_new(size_t capacity)
{
  (void)capacity;
  device_state_buffer.data = serialized_device_state;
  device_state_buffer.usage = 0;
  return &device_state_buffer;
}

static QEMUFile *
qemu_file_new_output(QIOChannelBuffer *buffer)
{
  device_state_file.buffer = buffer;
  return &device_state_file;
}

static int
qemu_save_device_state(QEMUFile *file)
{
  qemu_save_device_state_calls++;
  if (qemu_save_device_state_status == 0) {
    file->buffer->usage = sizeof(serialized_device_state);
  }
  return qemu_save_device_state_status;
}

static int
qemu_fflush(QEMUFile *file)
{
  (void)file;
  return 0;
}

static int
qemu_file_get_error(QEMUFile *file)
{
  (void)file;
  return 0;
}

static int
qemu_fclose(QEMUFile *file)
{
  (void)file;
  return qemu_file_close_status;
}

static void
object_unref(void *object)
{
  (void)object;
}

int
qemu_savevm_crucible_schema_sha256(uint8_t digest[32],
                                   uint64_t *sections_out)
{
  if (digest == NULL || sections_out == NULL) {
    return -EINVAL;
  }
  memset(digest, 0, 32);
  *sections_out = 0;
  if (schema_digest_status != 0) {
    return schema_digest_status;
  }
  for (size_t index = 0; index < 32; index++) {
    digest[index] = (unsigned char)(0x80U + index + schema_variant);
  }
  *sections_out = schema_sections;
  return 0;
}

static uint64_t
qemu_plugin_icount_raw(void)
{
  return observed_icount < 0 ? 0 : (uint64_t)observed_icount;
}

static bool
runstate_is_running(void)
{
  return observed_running;
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
  uint64_t device_hash = 0;
  uint64_t device_bytes = 0;
  uint64_t crypto_ram_bytes = 0;
  uint64_t crypto_device_bytes = 0;
  uint64_t device_sections = 0;
  uint8_t ram_digest[32] = {0};
  uint8_t device_digest[32] = {0};
  uint8_t schema_digest[32] = {0};
  uint8_t captured_ram_digest[32] = {0};
  uint8_t captured_device_digest[32] = {0};
  uint8_t *ram_material = NULL;
  uint8_t *device_material = NULL;
  uint64_t ram_material_length = 0;
  uint64_t device_material_length = 0;
  uint64_t captured_ram_bytes = 0;
  uint64_t captured_device_bytes = 0;
  const uint64_t expected_hash = expected_ram_hash();
  const uint64_t expected_device_hash = expected_fnv1a_bytes(
      14695981039346656037ULL,
      serialized_device_state,
      sizeof(serialized_device_state));

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

  qemu_save_device_state_status = 0;
  qemu_file_close_status = 0;
  qemu_save_device_state_calls = 0;
  if (qemu_plugin_crucible_device_state_hash(
          &device_hash, &device_bytes) != 0 ||
      device_hash != expected_device_hash ||
      device_bytes != sizeof(serialized_device_state) ||
      qemu_save_device_state_calls != 1) {
    fputs("device-state export did not hash the serialized non-RAM VMState\n",
          stderr);
    return 1;
  }

  device_hash = UINT64_MAX;
  device_bytes = UINT64_MAX;
  qemu_save_device_state_status = -EIO;
  if (qemu_plugin_crucible_device_state_hash(
          &device_hash, &device_bytes) != -EIO ||
      device_hash != 0 || device_bytes != 0) {
    fputs("device-state export did not clear outputs after save failure\n",
          stderr);
    return 1;
  }

  device_hash = UINT64_MAX;
  device_bytes = UINT64_MAX;
  qemu_save_device_state_status = 0;
  qemu_file_close_status = -EIO;
  if (qemu_plugin_crucible_device_state_hash(
          &device_hash, &device_bytes) != -EIO ||
      device_hash != 0 || device_bytes != 0) {
    fputs("device-state export did not clear outputs after close failure\n",
          stderr);
    return 1;
  }
  qemu_file_close_status = 0;

  if (qemu_plugin_crucible_guest_ram_sha256(
          ram_digest, &crypto_ram_bytes) != 0 ||
      crypto_ram_bytes != sizeof(ram0) + sizeof(ram1) ||
      ram_digest[0] == 0) {
    fputs("guest RAM SHA-256 export did not cover framed guest RAM\n", stderr);
    return 1;
  }
  if (qemu_plugin_crucible_device_state_sha256(
          device_digest, &crypto_device_bytes) != 0 ||
      crypto_device_bytes != sizeof(serialized_device_state) ||
      device_digest[0] == 0) {
    fputs("device VMState SHA-256 export did not cover serialized state\n",
          stderr);
    return 1;
  }
  dirty_log_start_calls = 0;
  dirty_log_stop_calls = 0;
  bql_lock_calls = 0;
  bql_unlock_calls = 0;
  test_bql_locked = false;
  global_dirty_tracking = 0;
  if (qemu_plugin_crucible_fingerprint_capture(
          &ram_material, &ram_material_length, &captured_ram_bytes,
          &device_material, &device_material_length,
          &captured_device_bytes) != 0 ||
      ram_material == NULL || device_material == NULL ||
      captured_ram_bytes != crypto_ram_bytes ||
      captured_device_bytes != crypto_device_bytes ||
      dirty_log_start_calls != 1 || dirty_log_stop_calls != 1 ||
      bql_lock_calls != 1 || bql_unlock_calls != 1 || test_bql_locked ||
      global_dirty_tracking != 0 ||
      qemu_plugin_crucible_sha256_bytes(
          ram_material, ram_material_length, captured_ram_digest) != 0 ||
      qemu_plugin_crucible_sha256_bytes(
          device_material, device_material_length,
          captured_device_digest) != 0 ||
      memcmp(captured_ram_digest, ram_digest, sizeof(ram_digest)) != 0 ||
      memcmp(captured_device_digest, device_digest,
             sizeof(device_digest)) != 0) {
    fputs("detached fingerprint capture did not match synchronous digests\n",
          stderr);
    return 1;
  }
  qemu_plugin_crucible_fingerprint_capture_free(ram_material);
  qemu_plugin_crucible_fingerprint_capture_free(device_material);
  ram_material = NULL;
  device_material = NULL;

  global_dirty_tracking = GLOBAL_DIRTY_MIGRATION;
  if (qemu_plugin_crucible_fingerprint_capture(
          &ram_material, &ram_material_length, &captured_ram_bytes,
          &device_material, &device_material_length,
          &captured_device_bytes) != 0 ||
      dirty_log_start_calls != 1 || dirty_log_stop_calls != 1 ||
      bql_lock_calls != 2 || bql_unlock_calls != 2 || test_bql_locked ||
      global_dirty_tracking != GLOBAL_DIRTY_MIGRATION) {
    fputs("fingerprint capture disturbed an existing dirty-log owner\n",
          stderr);
    return 1;
  }
  qemu_plugin_crucible_fingerprint_capture_free(ram_material);
  qemu_plugin_crucible_fingerprint_capture_free(device_material);
  global_dirty_tracking = 0;
  schema_digest_status = 0;
  if (qemu_plugin_crucible_device_state_schema_sha256(
          schema_digest, &device_sections) != 0 ||
      device_sections != schema_sections || schema_digest[0] != 0x80) {
    fputs("device VMState schema digest/count export failed\n", stderr);
    return 1;
  }
  schema_variant = 1;
  if (qemu_plugin_crucible_device_state_schema_sha256(
          schema_digest, &device_sections) != 0 || schema_digest[0] != 0x81) {
    fputs("device VMState field mutation did not change schema digest\n", stderr);
    return 1;
  }
  schema_variant = 2;
  if (qemu_plugin_crucible_device_state_schema_sha256(
          schema_digest, &device_sections) != 0 || schema_digest[0] != 0x82) {
    fputs("device VMState subsection mutation did not change schema digest\n",
          stderr);
    return 1;
  }
  schema_variant = 0;

  memset(device_digest, 0xff, sizeof(device_digest));
  crypto_device_bytes = UINT64_MAX;
  qemu_save_device_state_status = -EIO;
  if (qemu_plugin_crucible_device_state_sha256(
          device_digest, &crypto_device_bytes) != -EIO ||
      crypto_device_bytes != 0 || device_digest[0] != 0) {
    fputs("device VMState SHA-256 export did not clear outputs on error\n",
          stderr);
    return 1;
  }
  qemu_save_device_state_status = 0;

  observed_icount = 9876;
  observed_running = false;
  if (qemu_plugin_crucible_icount() != 9876 ||
      !qemu_plugin_crucible_vm_non_running()) {
    fputs("observed icount/runstate exports returned stale constants\n", stderr);
    return 1;
  }
  observed_icount = -1;
  observed_running = true;
  if (qemu_plugin_crucible_icount() != 0 ||
      qemu_plugin_crucible_vm_non_running()) {
    fputs("observed icount/runstate exports missed negative controls\n", stderr);
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
  puts("device_state_hash_covers_serialized_non_ram_vmstate=true");
  puts("device_state_error_status_clears_outputs=true");
  puts("crypto_component_digests_are_32_bytes=true");
  puts("fingerprint_capture_uses_dirty_tracking=true");
  puts("fingerprint_capture_acquires_bql=true");
  puts("fingerprint_capture_preserves_existing_dirty_owner=true");
  puts("captured_component_digests_match_synchronous=true");
  puts("device_state_schema_digest_and_count=true");
  puts("device_state_schema_field_and_subsection_mutations=true");
  puts("observed_icount_and_runstate=true");
  puts("migration_host_timer_zeroed_under_icount=true");
  puts("migration_host_timer_preserved_without_icount=true");
  puts("stock_negative_control_rr_budget_unpinned=true");
  puts("stock_negative_control_symbols_absent=true");
  return 0;
}
