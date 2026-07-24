#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *result_file;
static uint64_t minimum_icount;
static uint64_t target_icount = UINT64_MAX;
static int published;

static uint64_t
max_advance_icount(void *userdata)
{
  (void)userdata;
  return target_icount;
}

static void
observe_icount(uint64_t current_icount, void *userdata)
{
  (void)current_icount;
  (void)userdata;
}

static void
on_vcpu_idle(unsigned int vcpu_index, uint64_t icount, void *userdata)
{
  (void)vcpu_index;
  (void)userdata;

  if (!published && icount >= minimum_icount) {
    published = 1;
    target_icount = icount;
    fprintf(
        result_file,
        "reached=%" PRIu64 "\tminimum=%" PRIu64 "\n",
        icount,
        minimum_icount);
    fflush(result_file);
  }
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  if (result_file != NULL) {
    fclose(result_file);
    result_file = NULL;
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
    } else if (strncmp(argv[i], "target=", 7) == 0) {
      char *end = NULL;
      const unsigned long long value = strtoull(argv[i] + 7, &end, 10);
      if (argv[i][7] == '\0' || end == NULL || *end != '\0' || value == 0) {
        qemu_plugin_outs(
            "drop-one-warp-boundary-plugin: invalid target=<icount>\n");
        return -1;
      }
      minimum_icount = (uint64_t)value;
    }
  }

  if (out_path == NULL || out_path[0] == '\0' || minimum_icount == 0) {
    qemu_plugin_outs(
        "drop-one-warp-boundary-plugin: out and target are required\n");
    return -1;
  }

  result_file = fopen(out_path, "w");
  if (result_file == NULL) {
    qemu_plugin_outs(
        "drop-one-warp-boundary-plugin: failed to open output\n");
    return -1;
  }

  qemu_plugin_register_sim_shmem_observer_cb(
      observe_icount, max_advance_icount, NULL);
  qemu_plugin_register_vcpu_idle_resume_cb(on_vcpu_idle, NULL, NULL);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
