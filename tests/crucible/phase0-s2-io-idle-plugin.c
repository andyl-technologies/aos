#include <inttypes.h>
#include <limits.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum medium {
  MEDIUM_BLOCK = 0,
  MEDIUM_9P = 1,
  MEDIUM_COUNT = 2
};

struct traced_insn {
  uint8_t bytes[16];
  size_t size;
};

struct medium_stats {
  uint64_t operations;
  uint64_t completed_operations;
  uint64_t idled_operations;
  uint64_t busy_polled_operations;
  uint64_t operations_with_io_events;
  uint64_t operations_without_io_events;
  uint64_t total_operation_instructions;
  uint64_t max_operation_instructions;
  uint64_t total_busy_poll_instructions;
  uint64_t max_busy_poll_instructions;
  uint64_t total_hlt_events;
  uint64_t max_hlt_events;
  uint64_t total_io_events;
  uint64_t max_io_events;
};

static FILE *out_file;
static uint64_t retired_instructions;
static uint64_t hlt_events;
static uint64_t io_events;
static bool operation_active;
static enum medium active_medium;
static uint64_t operation_instructions;
static uint64_t operation_hlt_events;
static uint64_t operation_io_events;
static uint64_t marker_errors;
static struct medium_stats stats[MEDIUM_COUNT];

static const char *
medium_name(enum medium medium)
{
  switch (medium) {
  case MEDIUM_BLOCK:
    return "block";
  case MEDIUM_9P:
    return "ninep";
  case MEDIUM_COUNT:
    break;
  }

  return "unknown";
}

static uint64_t
fraction_ppm(uint64_t numerator, uint64_t denominator)
{
  if (denominator == 0) {
    return 0;
  }

  return (numerator * 1000000ULL) / denominator;
}

static bool
decode_marker(const struct traced_insn *insn, uint32_t *marker)
{
  if (insn->size != 8) {
    return false;
  }
  if (insn->bytes[0] != 0x0f || insn->bytes[1] != 0x1f ||
      insn->bytes[2] != 0x84 || insn->bytes[3] != 0x00) {
    return false;
  }

  *marker = ((uint32_t)insn->bytes[4]) |
            ((uint32_t)insn->bytes[5] << 8U) |
            ((uint32_t)insn->bytes[6] << 16U) |
            ((uint32_t)insn->bytes[7] << 24U);
  return (*marker & 0xffff0000U) == 0xc0100000U;
}

static bool
marker_to_operation(uint32_t marker, enum medium *medium, bool *begin)
{
  switch (marker) {
  case 0xc0100201U:
    *medium = MEDIUM_BLOCK;
    *begin = true;
    return true;
  case 0xc0100202U:
    *medium = MEDIUM_BLOCK;
    *begin = false;
    return true;
  case 0xc0100901U:
    *medium = MEDIUM_9P;
    *begin = true;
    return true;
  case 0xc0100902U:
    *medium = MEDIUM_9P;
    *begin = false;
    return true;
  default:
    return false;
  }
}

static void
begin_operation(enum medium medium)
{
  if (operation_active) {
    marker_errors++;
    return;
  }

  operation_active = true;
  active_medium = medium;
  operation_instructions = 0;
  operation_hlt_events = 0;
  operation_io_events = 0;
  stats[medium].operations++;
}

static void
end_operation(enum medium medium)
{
  if (!operation_active || active_medium != medium) {
    marker_errors++;
    return;
  }

  struct medium_stats *current = &stats[medium];
  current->completed_operations++;
  current->total_operation_instructions += operation_instructions;
  current->total_hlt_events += operation_hlt_events;
  current->total_io_events += operation_io_events;

  if (operation_instructions > current->max_operation_instructions) {
    current->max_operation_instructions = operation_instructions;
  }
  if (operation_hlt_events > current->max_hlt_events) {
    current->max_hlt_events = operation_hlt_events;
  }
  if (operation_io_events > current->max_io_events) {
    current->max_io_events = operation_io_events;
  }

  if (operation_hlt_events > 0) {
    current->idled_operations++;
  } else {
    current->busy_polled_operations++;
    current->total_busy_poll_instructions += operation_instructions;
    if (operation_instructions > current->max_busy_poll_instructions) {
      current->max_busy_poll_instructions = operation_instructions;
    }
  }

  if (operation_io_events > 0) {
    current->operations_with_io_events++;
  } else {
    current->operations_without_io_events++;
  }

  operation_active = false;
}

static bool
is_hlt(const struct traced_insn *insn)
{
  return insn->size == 1 && insn->bytes[0] == 0xf4;
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  (void)vcpu_index;
  const struct traced_insn *insn = userdata;
  uint32_t marker = 0;
  enum medium marker_medium = MEDIUM_BLOCK;
  bool marker_begin = false;

  retired_instructions++;

  if (decode_marker(insn, &marker)) {
    if (marker_to_operation(marker, &marker_medium, &marker_begin)) {
      if (marker_begin) {
        begin_operation(marker_medium);
      } else {
        end_operation(marker_medium);
      }
    } else {
      marker_errors++;
    }
    return;
  }

  if (operation_active) {
    operation_instructions++;
  }

  if (is_hlt(insn)) {
    hlt_events++;
    if (operation_active) {
      operation_hlt_events++;
    }
  }
}

static void
on_mem(
    unsigned int vcpu_index,
    qemu_plugin_meminfo_t info,
    uint64_t vaddr,
    void *userdata)
{
  (void)vcpu_index;
  (void)userdata;
  const struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);

  if (hwaddr != NULL && qemu_plugin_hwaddr_is_io(hwaddr)) {
    io_events++;
    if (operation_active) {
      operation_io_events++;
    }
  }
}

static void
on_tb_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  (void)id;
  const size_t count = qemu_plugin_tb_n_insns(tb);

  for (size_t i = 0; i < count; i++) {
    struct qemu_plugin_insn *qinsn = qemu_plugin_tb_get_insn(tb, i);
    struct traced_insn *insn = calloc(1, sizeof(*insn));
    if (insn == NULL) {
      qemu_plugin_outs("phase0-s2-io-idle-plugin: out of memory\n");
      return;
    }

    insn->size = qemu_plugin_insn_size(qinsn);
    if (insn->size > sizeof(insn->bytes)) {
      insn->size = sizeof(insn->bytes);
    }
    insn->size = qemu_plugin_insn_data(qinsn, insn->bytes, insn->size);

    qemu_plugin_register_vcpu_insn_exec_cb(
        qinsn, on_insn, QEMU_PLUGIN_CB_NO_REGS, insn);
    qemu_plugin_register_vcpu_mem_cb(
        qinsn, on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);
  }
}

static void
write_medium_stats(enum medium medium)
{
  const struct medium_stats *current = &stats[medium];
  const char *name = medium_name(medium);

  fprintf(out_file, "%s_operations=%" PRIu64 "\n", name, current->operations);
  fprintf(
      out_file,
      "%s_completed_operations=%" PRIu64 "\n",
      name,
      current->completed_operations);
  fprintf(
      out_file,
      "%s_idled_operations=%" PRIu64 "\n",
      name,
      current->idled_operations);
  fprintf(
      out_file,
      "%s_busy_polled_operations=%" PRIu64 "\n",
      name,
      current->busy_polled_operations);
  fprintf(
      out_file,
      "%s_operations_with_io_events=%" PRIu64 "\n",
      name,
      current->operations_with_io_events);
  fprintf(
      out_file,
      "%s_operations_without_io_events=%" PRIu64 "\n",
      name,
      current->operations_without_io_events);
  fprintf(
      out_file,
      "%s_idle_fraction_ppm=%" PRIu64 "\n",
      name,
      fraction_ppm(current->idled_operations, current->completed_operations));
  fprintf(
      out_file,
      "%s_total_operation_instructions=%" PRIu64 "\n",
      name,
      current->total_operation_instructions);
  fprintf(
      out_file,
      "%s_max_operation_instructions=%" PRIu64 "\n",
      name,
      current->max_operation_instructions);
  fprintf(
      out_file,
      "%s_total_busy_poll_instructions=%" PRIu64 "\n",
      name,
      current->total_busy_poll_instructions);
  fprintf(
      out_file,
      "%s_max_busy_poll_instructions=%" PRIu64 "\n",
      name,
      current->max_busy_poll_instructions);
  fprintf(out_file, "%s_total_hlt_events=%" PRIu64 "\n", name, current->total_hlt_events);
  fprintf(out_file, "%s_max_hlt_events=%" PRIu64 "\n", name, current->max_hlt_events);
  fprintf(out_file, "%s_total_io_events=%" PRIu64 "\n", name, current->total_io_events);
  fprintf(out_file, "%s_max_io_events=%" PRIu64 "\n", name, current->max_io_events);
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;
  if (out_file == NULL) {
    return;
  }

  fprintf(out_file, "retired_instructions=%" PRIu64 "\n", retired_instructions);
  fprintf(out_file, "hlt_events=%" PRIu64 "\n", hlt_events);
  fprintf(out_file, "io_events=%" PRIu64 "\n", io_events);
  fprintf(out_file, "marker_errors=%" PRIu64 "\n", marker_errors);
  fprintf(out_file, "open_operation=%s\n", operation_active ? "true" : "false");
  write_medium_stats(MEDIUM_BLOCK);
  write_medium_stats(MEDIUM_9P);
  fclose(out_file);
  out_file = NULL;
}

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
  (void)info;
  const char *out_path = NULL;

  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "out=", 4) == 0) {
      out_path = argv[i] + 4;
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase0-s2-io-idle-plugin: missing out=<path>\n");
    return -1;
  }

  out_file = fopen(out_path, "w");
  if (out_file == NULL) {
    qemu_plugin_outs("phase0-s2-io-idle-plugin: failed to open output\n");
    return -1;
  }

  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
