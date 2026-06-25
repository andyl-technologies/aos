#include <errno.h>
#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

struct tb_info {
  uint64_t id;
  uint64_t insns;
};

static FILE *trace_file;
static uint64_t max_events = 256;
static uint64_t translated_tbs;
static uint64_t tb_execs;
static uint64_t retired_insns;

static int
parse_u64(const char *text, uint64_t *value)
{
  char *end = NULL;
  errno = 0;
  const unsigned long long parsed = strtoull(text, &end, 10);
  if (text[0] == '\0' || end == NULL || *end != '\0' || errno != 0 ||
      parsed == 0) {
    return 0;
  }
  *value = (uint64_t)parsed;
  return 1;
}

static void
on_tb_exec(unsigned int vcpu_index, void *userdata)
{
  const struct tb_info *info = userdata;

  tb_execs++;
  retired_insns += info->insns;

  if (trace_file == NULL || tb_execs > max_events) {
    return;
  }

  fprintf(
      trace_file,
      "tb_exec ordinal=%" PRIu64 " tb=%" PRIu64 " vcpu=%u rr_vcpu=%" PRIu64
      " cursor=%" PRIu64 " insns=%" PRIu64 " retired=%" PRIu64 "\n",
      tb_execs,
      info->id,
      vcpu_index,
      qemu_plugin_crucible_rr_current_vcpu(),
      qemu_plugin_crucible_rr_cursor_position(),
      info->insns,
      retired_insns);
  fflush(trace_file);
}

static void
on_tb_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  (void)id;

  struct tb_info *info = calloc(1, sizeof(*info));
  if (info == NULL) {
    qemu_plugin_outs("phase1-sim-accel-plugin: out of memory\n");
    return;
  }

  translated_tbs++;
  info->id = translated_tbs;
  info->insns = qemu_plugin_tb_n_insns(tb);
  qemu_plugin_register_vcpu_tb_exec_cb(tb, on_tb_exec, QEMU_PLUGIN_CB_NO_REGS, info);
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  if (trace_file != NULL) {
    fclose(trace_file);
    trace_file = NULL;
  }
}

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
  (void)info;

  const char *out_path = NULL;
  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "out=", 4) == 0) {
      out_path = argv[i] + 4;
    } else if (strncmp(argv[i], "max=", 4) == 0) {
      if (!parse_u64(argv[i] + 4, &max_events)) {
        qemu_plugin_outs("phase1-sim-accel-plugin: invalid max=<events>\n");
        return -1;
      }
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase1-sim-accel-plugin: missing out=<path>\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("phase1-sim-accel-plugin: failed to open trace output\n");
    return -1;
  }

  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
