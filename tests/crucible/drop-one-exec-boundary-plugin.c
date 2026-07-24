#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *trace_file;
static uint64_t ordinal;
static uint64_t stop_after;

static void
on_tcg_exec(unsigned int vcpu_index, uint64_t icount, void *userdata)
{
  (void)userdata;

  ordinal++;
  if (trace_file != NULL) {
    fprintf(
        trace_file,
        "%" PRIu64 "\t%u\t%" PRIu64 "\t%" PRId64 "\n",
        ordinal,
        vcpu_index,
        icount,
        qemu_plugin_clock_deadline_ns());
    fflush(trace_file);
  }

  if (stop_after != 0 && ordinal >= stop_after) {
    qemu_plugin_request_shutdown(0);
  }
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
    } else if (strncmp(argv[i], "stop_after=", 11) == 0) {
      char *end = NULL;
      const unsigned long long value = strtoull(argv[i] + 11, &end, 10);
      if (argv[i][11] == '\0' || end == NULL || *end != '\0' || value == 0) {
        qemu_plugin_outs(
            "drop-one-exec-boundary-plugin: invalid stop_after=<events>\n");
        return -1;
      }
      stop_after = (uint64_t)value;
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("drop-one-exec-boundary-plugin: missing out=<path>\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("drop-one-exec-boundary-plugin: failed to open output\n");
    return -1;
  }

  qemu_plugin_register_tcg_exec_cb(on_tcg_exec, NULL);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
