#include <inttypes.h>
#include <qemu-plugin.h>
#include <stddef.h>
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
  qemu_plugin_u64 seen;
  struct tb_info *next;
};

struct coverage_stats {
  uint64_t retired_instructions;
  uint64_t tb_execs;
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
static uint64_t exact_icount_failures;
static uint64_t icount_regressions;
static uint64_t first_entry_icount;
static uint64_t last_entry_icount;
static uint64_t flushes;
static int have_entry_icount;
static struct tb_info *tb_infos;
static struct qemu_plugin_scoreboard *stats_scoreboard;
static qemu_plugin_u64 retired_instructions_entry;
static qemu_plugin_u64 tb_execs_entry;

static void
free_tb_infos(void)
{
  while (tb_infos != NULL) {
    struct tb_info *info = tb_infos;
    tb_infos = info->next;
    if (info->seen.score != NULL) {
      qemu_plugin_scoreboard_free(info->seen.score);
    }
    free(info);
  }
}

static void
on_tb_exec(unsigned int vcpu_index, void *userdata)
{
  const struct tb_info *info = userdata;
  uint64_t entry_icount = 0;

  qemu_plugin_u64_set(info->seen, vcpu_index, 1);

  if (qemu_plugin_icount_at_tb_entry(info->insns, &entry_icount) != 0) {
    exact_icount_failures++;
  } else {
    if (have_entry_icount == 0) {
      first_entry_icount = entry_icount;
      have_entry_icount = 1;
    } else if (entry_icount < last_entry_icount) {
      icount_regressions++;
    }
    last_entry_icount = entry_icount;
  }
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
  info->next = tb_infos;
  tb_infos = info;

  qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
    tb,
    QEMU_PLUGIN_INLINE_ADD_U64,
    retired_instructions_entry,
    info->insns);
  qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
    tb,
    QEMU_PLUGIN_INLINE_ADD_U64,
    tb_execs_entry,
    1);

  if (mode == MODE_COVERAGE) {
    info->seen.score = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    if (info->seen.score == NULL) {
      qemu_plugin_outs("phase0-coverage-plugin: failed to allocate seen scoreboard\n");
      return;
    }
    info->seen.offset = 0;
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
      tb,
      on_tb_exec,
      QEMU_PLUGIN_CB_NO_REGS,
      QEMU_PLUGIN_COND_EQ,
      info->seen,
      0,
      info);
  }
}

static void
on_tb_flush(qemu_plugin_id_t id)
{
  (void)id;

  /* QEMU removes generated dynamic callbacks before invoking this callback. */
  free_tb_infos();
  flushes++;
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

  if (stats_scoreboard != NULL) {
    retired_instructions = qemu_plugin_u64_sum(retired_instructions_entry);
    tb_execs = qemu_plugin_u64_sum(tb_execs_entry);
  }

  fprintf(out_file, "mode=%s\n", mode_name());
  fprintf(out_file, "retired_instructions=%" PRIu64 "\n", retired_instructions);
  fprintf(out_file, "tb_execs=%" PRIu64 "\n", tb_execs);
  fprintf(out_file, "translated_tbs=%" PRIu64 "\n", translated_tbs);
  fprintf(out_file, "coverage_set_capacity=%" PRIu64 "\n", coverage_capacity);
  fprintf(out_file, "unique_coverage_entries=%" PRIu64 "\n", unique_coverage_entries);
  fprintf(out_file, "coverage_overflow=%" PRIu64 "\n", coverage_overflow);
  fprintf(out_file, "exact_icount_failures=%" PRIu64 "\n", exact_icount_failures);
  fprintf(out_file, "icount_regressions=%" PRIu64 "\n", icount_regressions);
  fprintf(out_file, "first_entry_icount=%" PRIu64 "\n", first_entry_icount);
  fprintf(out_file, "last_entry_icount=%" PRIu64 "\n", last_entry_icount);
  fprintf(out_file, "flushes=%" PRIu64 "\n", flushes);
  free_tb_infos();
  if (stats_scoreboard != NULL) {
    qemu_plugin_scoreboard_free(stats_scoreboard);
    stats_scoreboard = NULL;
  }
  free(coverage_seen);
  coverage_seen = NULL;
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

  if (mode != MODE_DISABLED) {
    stats_scoreboard = qemu_plugin_scoreboard_new(sizeof(struct coverage_stats));
    if (stats_scoreboard == NULL) {
      qemu_plugin_outs("phase0-coverage-plugin: failed to allocate stats scoreboard\n");
      return -1;
    }
    retired_instructions_entry = (qemu_plugin_u64) {
      stats_scoreboard,
      offsetof(struct coverage_stats, retired_instructions),
    };
    tb_execs_entry = (qemu_plugin_u64) {
      stats_scoreboard,
      offsetof(struct coverage_stats, tb_execs),
    };
  }

  out_file = fopen(out_path, "w");
  if (out_file == NULL) {
    qemu_plugin_outs("phase0-coverage-plugin: failed to open output\n");
    return -1;
  }

  if (mode != MODE_DISABLED) {
    qemu_plugin_register_flush_cb(id, on_tb_flush);
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  }
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
