#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum plugin_mode {
  MODE_DISABLED,
  MODE_COUNT,
  MODE_COVERAGE,
};

struct tb_info {
  uint64_t id;
  uint64_t insns;
};

static enum plugin_mode mode = MODE_COUNT;
static FILE *out_file;
static uint8_t *coverage_seen;
static uint64_t coverage_capacity = 1ULL << 20;
static uint64_t translated_tbs;
static uint64_t tb_execs;
static uint64_t retired_instructions;
static uint64_t unique_coverage_entries;
static uint64_t coverage_overflow;

static void
on_tb_exec(unsigned int vcpu_index, void *userdata)
{
  (void)vcpu_index;

  const struct tb_info *info = userdata;
  tb_execs++;
  retired_instructions += info->insns;

  if (mode == MODE_COVERAGE) {
    if (info->id == 0 || info->id > coverage_capacity) {
      coverage_overflow = 1;
      return;
    }

    const uint64_t slot = info->id - 1;
    if (coverage_seen[slot] == 0) {
      coverage_seen[slot] = 1;
      unique_coverage_entries++;
    }
  }
}

static void
on_tb_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  (void)id;

  struct tb_info *info = calloc(1, sizeof(*info));
  if (info == NULL) {
    qemu_plugin_outs("phase0-coverage-plugin: out of memory\n");
    return;
  }

  translated_tbs++;
  info->id = translated_tbs;
  info->insns = qemu_plugin_tb_n_insns(tb);
  qemu_plugin_register_vcpu_tb_exec_cb(tb, on_tb_exec, QEMU_PLUGIN_CB_NO_REGS, info);
}

static const char *
mode_name(void)
{
  if (mode == MODE_DISABLED) {
    return "disabled";
  }
  if (mode == MODE_COVERAGE) {
    return "coverage";
  }
  return "count";
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  if (out_file == NULL) {
    return;
  }

  fprintf(out_file, "mode=%s\n", mode_name());
  fprintf(out_file, "retired_instructions=%" PRIu64 "\n", retired_instructions);
  fprintf(out_file, "tb_execs=%" PRIu64 "\n", tb_execs);
  fprintf(out_file, "translated_tbs=%" PRIu64 "\n", translated_tbs);
  fprintf(out_file, "coverage_set_capacity=%" PRIu64 "\n", coverage_capacity);
  fprintf(out_file, "unique_coverage_entries=%" PRIu64 "\n", unique_coverage_entries);
  fprintf(out_file, "coverage_overflow=%" PRIu64 "\n", coverage_overflow);
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
    } else if (strcmp(argv[i], "mode=disabled") == 0) {
      mode = MODE_DISABLED;
    } else if (strcmp(argv[i], "mode=coverage") == 0) {
      mode = MODE_COVERAGE;
    } else if (strcmp(argv[i], "mode=count") == 0) {
      mode = MODE_COUNT;
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase0-coverage-plugin: missing out=<path>\n");
    return -1;
  }

  if (mode == MODE_COVERAGE) {
    coverage_seen = calloc((size_t)coverage_capacity, sizeof(*coverage_seen));
    if (coverage_seen == NULL) {
      qemu_plugin_outs("phase0-coverage-plugin: failed to allocate coverage set\n");
      return -1;
    }
  }

  out_file = fopen(out_path, "w");
  if (out_file == NULL) {
    qemu_plugin_outs("phase0-coverage-plugin: failed to open output\n");
    return -1;
  }

  if (mode != MODE_DISABLED) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  }
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
