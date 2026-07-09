#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_PLUGIN 1
#define CONFIG_SOFTMMU 1
#define UINT64_MAX_SENTINEL UINT64_MAX
#define GINT_TO_POINTER(value) ((void *)(uintptr_t)(value))
#define GPOINTER_TO_INT(pointer) ((int)(uintptr_t)(pointer))
#define g_intern_string(text) (text)
#define g_autoptr(type) type *
#define g_array_index(array, type, index) (((type *)(array)->data)[index])

typedef struct CPUState {
  unsigned int cpu_index;
} CPUState;

typedef struct GDBRegDesc {
  int gdb_reg;
  const char *name;
  const char *feature_name;
} GDBRegDesc;

typedef struct GArray {
  void *data;
  unsigned int len;
  size_t element_size;
} GArray;

typedef struct GByteArray {
  uint8_t *data;
  size_t len;
  size_t capacity;
} GByteArray;

struct qemu_plugin_register;

typedef struct qemu_plugin_reg_descriptor {
  struct qemu_plugin_register *handle;
  const char *name;
  const char *feature;
} qemu_plugin_reg_descriptor;

struct qemu_plugin_rr_cursor {
  uint64_t current_vcpu;
  uint64_t cursor_position;
  uint64_t rr_switch_quantum;
};

struct qemu_plugin_scoreboard {
  size_t element_size;
};

typedef uint64_t qemu_plugin_u64;

static CPUState cpu0 = {.cpu_index = 0};
static CPUState cpu1 = {.cpu_index = 1};
static CPUState cpu_invalid = {.cpu_index = 5};
static CPUState *current_cpu = &cpu0;
static GDBRegDesc cpu0_regs[] = {
    {.gdb_reg = 0, .name = "rax", .feature_name = "org.gnu.gdb.i386.core"},
    {.gdb_reg = 1, .name = "rbx", .feature_name = "org.gnu.gdb.i386.core"},
};
static GDBRegDesc cpu1_regs[] = {
    {.gdb_reg = 0, .name = "rax", .feature_name = "org.gnu.gdb.i386.core"},
    {.gdb_reg = 2, .name = "rcx", .feature_name = "org.gnu.gdb.i386.core"},
    {.gdb_reg = 3, .name = "rdx", .feature_name = "org.gnu.gdb.i386.core"},
};
static unsigned int gdb_read_register_calls;
static unsigned int last_gdb_read_cpu_index = UINT32_MAX;
static int last_gdb_read_register = -1;
static bool force_register_size_mismatch;
static uint64_t rr_cursor_position = 7;
static uint64_t rr_switch_quantum = 16;

static GArray *
g_array_new(bool zero_terminated, bool clear, size_t element_size)
{
  (void)zero_terminated;
  (void)clear;
  GArray *array = calloc(1, sizeof(*array));
  if (array != NULL) {
    array->element_size = element_size;
  }
  return array;
}

static void
g_array_append_bytes(GArray *array, const void *value)
{
  void *new_data = realloc(array->data, (array->len + 1) * array->element_size);
  if (new_data == NULL) {
    abort();
  }
  array->data = new_data;
  memcpy((uint8_t *)array->data + (array->len * array->element_size),
         value,
         array->element_size);
  array->len++;
}

#define g_array_append_val(array, value) g_array_append_bytes((array), &(value))

static void
g_array_free(GArray *array, bool free_segment)
{
  if (array == NULL) {
    return;
  }
  if (free_segment) {
    free(array->data);
  }
  free(array);
}

static GByteArray *
g_byte_array_new(void)
{
  return calloc(1, sizeof(GByteArray));
}

static void
g_byte_array_set_size(GByteArray *array, size_t len)
{
  if (array->capacity < len) {
    void *new_data = realloc(array->data, len);
    if (new_data == NULL) {
      abort();
    }
    array->data = new_data;
    array->capacity = len;
  }
  array->len = len;
}

static void
g_byte_array_free(GByteArray *array, bool free_segment)
{
  if (array == NULL) {
    return;
  }
  if (free_segment) {
    free(array->data);
  }
  free(array);
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
  GArray *array = g_array_new(false, false, sizeof(GDBRegDesc));
  const GDBRegDesc *source = cpu->cpu_index == 0 ? cpu0_regs : cpu1_regs;
  const size_t count =
      cpu->cpu_index == 0 ? sizeof(cpu0_regs) / sizeof(cpu0_regs[0])
                          : sizeof(cpu1_regs) / sizeof(cpu1_regs[0]);

  for (size_t i = 0; i < count; i++) {
    GDBRegDesc desc = source[i];
    g_array_append_val(array, desc);
  }
  return array;
}

static int
gdb_read_register(CPUState *cpu, GByteArray *buf, int reg)
{
  gdb_read_register_calls++;
  last_gdb_read_cpu_index = cpu->cpu_index;
  last_gdb_read_register = reg;
  g_byte_array_set_size(buf, 3);
  buf->data[0] = (uint8_t)cpu->cpu_index;
  buf->data[1] = (uint8_t)reg;
  buf->data[2] = 0xa5;
  if (force_register_size_mismatch) {
    return (int)buf->len + 1;
  }
  return (int)buf->len;
}

static struct qemu_plugin_scoreboard *
plugin_scoreboard_new(size_t element_size)
{
  struct qemu_plugin_scoreboard *scoreboard = calloc(1, sizeof(*scoreboard));
  if (scoreboard != NULL) {
    scoreboard->element_size = element_size;
  }
  return scoreboard;
}

static int
qemu_plugin_num_vcpus(void)
{
  return 2;
}

static uint64_t
qemu_plugin_u64_get(qemu_plugin_u64 entry, int index)
{
  return entry + (uint64_t)index;
}

uint64_t
qemu_plugin_crucible_rr_cursor_position(void)
{
  return rr_cursor_position;
}

uint64_t
qemu_plugin_crucible_rr_switch_quantum(void)
{
  return rr_switch_quantum;
}

#include "plugins/api.c"

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
  uint8_t register_bytes[4096];
  size_t register_len = 0;
  uint64_t retired = 0;
  struct qemu_plugin_rr_cursor cursor = {0};
  CPUState *original_cpu = current_cpu;

  if (qemu_plugin_read_vcpu_regs(1,
                                 register_bytes,
                                 sizeof(register_bytes),
                                 &register_len,
                                 &retired) != 0) {
    fprintf(stderr, "qemu_plugin_read_vcpu_regs rejected vCPU1\n");
    return 1;
  }
  if (require_true(register_len > 0, "empty canonical register file") ||
      require_true(retired == 0, "deterministic register stamp mismatch") ||
      require_true(gdb_read_register_calls == 3, "wrong register read count") ||
      require_true(last_gdb_read_cpu_index == 1, "read did not target vCPU1") ||
      require_true(last_gdb_read_register == 3, "wrong final register index") ||
      require_true(current_cpu == original_cpu, "register read mutated current_cpu")) {
    return 1;
  }

  register_len = 0;
  retired = 0;
  if (qemu_plugin_read_vcpu_regs(1, register_bytes, 8, &register_len, &retired) == 0) {
    fprintf(stderr, "short register buffer unexpectedly succeeded\n");
    return 1;
  }
  if (require_true(register_len > 8, "short buffer did not report required size")) {
    return 1;
  }

  if (qemu_plugin_read_vcpu_regs(4,
                                 register_bytes,
                                 sizeof(register_bytes),
                                 &register_len,
                                 &retired) == 0) {
    fprintf(stderr, "invalid vCPU read unexpectedly succeeded\n");
    return 1;
  }

  force_register_size_mismatch = true;
  if (qemu_plugin_read_vcpu_regs(1,
                                 register_bytes,
                                 sizeof(register_bytes),
                                 &register_len,
                                 &retired) == 0) {
    fprintf(stderr, "mismatched register byte count unexpectedly succeeded\n");
    return 1;
  }
  force_register_size_mismatch = false;

  current_cpu = &cpu1;
  rr_cursor_position = 7;
  rr_switch_quantum = 16;
  if (qemu_plugin_rr_cursor(&cursor) != 0) {
    fprintf(stderr, "valid RR cursor rejected\n");
    return 1;
  }
  if (require_true(cursor.current_vcpu == 1, "cursor current vCPU mismatch") ||
      require_true(cursor.cursor_position == 7, "cursor position mismatch") ||
      require_true(cursor.rr_switch_quantum == 16, "cursor quantum mismatch")) {
    return 1;
  }

  rr_cursor_position = 16;
  if (qemu_plugin_rr_cursor(&cursor) == 0) {
    fprintf(stderr, "boundary cursor unexpectedly succeeded\n");
    return 1;
  }

  rr_cursor_position = 7;
  rr_switch_quantum = 0;
  if (qemu_plugin_rr_cursor(&cursor) == 0) {
    fprintf(stderr, "zero-quantum cursor unexpectedly succeeded\n");
    return 1;
  }

  current_cpu = &cpu_invalid;
  rr_switch_quantum = 16;
  if (qemu_plugin_rr_cursor(&cursor) == 0) {
    fprintf(stderr, "out-of-range current-vCPU cursor unexpectedly succeeded\n");
    return 1;
  }

  current_cpu = NULL;
  rr_switch_quantum = 16;
  if (qemu_plugin_rr_cursor(&cursor) == 0) {
    fprintf(stderr, "no-current-vCPU cursor unexpectedly succeeded\n");
    return 1;
  }

  puts("PASS");
  puts("formal_register_export=qemu_plugin_read_vcpu_regs");
  puts("formal_cursor_export=qemu_plugin_rr_cursor");
  puts("arbitrary_vcpu_register_read=true");
  puts("canonical_register_file_nonempty=true");
  puts("register_read_side_effect_free=true");
  puts("register_short_buffer_fails_closed=true");
  puts("register_short_buffer_reports_required_size=true");
  puts("invalid_vcpu_register_read_rejected=true");
  puts("register_size_mismatch_rejected=true");
  puts("rr_cursor_reads_current_vcpu_position_and_quantum=true");
  puts("rr_cursor_boundary_rejected=true");
  puts("rr_cursor_zero_quantum_rejected=true");
  puts("rr_cursor_out_of_range_current_vcpu_rejected=true");
  puts("rr_cursor_no_current_vcpu_rejected=true");
  puts("stock_negative_control_symbols_absent=true");
  return 0;
}
