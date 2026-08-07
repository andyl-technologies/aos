#include <dlfcn.h>
#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum target_mode {
  TARGET_MODE_FIXED,
  TARGET_MODE_DYNAMIC_INTERIOR,
};

struct traced_insn {
  uint64_t vaddr;
  size_t size;
  size_t tb_index;
  size_t tb_insns;
};

static FILE *trace_file;
static enum target_mode mode = TARGET_MODE_FIXED;
static const char *mode_name = "fixed";
static uint64_t configured_target;
static uint64_t choose_after;
static uint64_t dynamic_offset = 2;
static uint64_t retired_total;
static uint64_t selected_target;
static uint64_t request_retired;
static uint64_t request_vaddr;
static uint64_t exit_retired;
static uint64_t target_tb_index;
static uint64_t target_tb_insns;
static bool target_selected;
static bool stop_requested;
static bool deadline_api_available;

static bool
target_inside_tb(void)
{
  return target_tb_insns != UINT64_MAX && target_tb_index + 1U < target_tb_insns;
}

static bool
parse_u64(const char *text, uint64_t *out)
{
  char *end = NULL;
  unsigned long long value = strtoull(text, &end, 10);
  if (end == text || *end != '\0') {
    return false;
  }
  *out = (uint64_t)value;
  return true;
}

static void
record_capability(void)
{
  if (trace_file == NULL) {
    return;
  }

  fprintf(
      trace_file,
      "{\"event\":\"capability\",\"deadline_api_available\":%s"
      ",\"deadline_symbol\":\"qemu_plugin_clock_deadline_ns\"}\n",
      deadline_api_available ? "true" : "false");
  fflush(trace_file);
}

static void
record_selection(const struct traced_insn *insn)
{
  if (trace_file == NULL) {
    return;
  }

  fprintf(
      trace_file,
      "{\"event\":\"target_selected\",\"mode\":\"%s\""
      ",\"retired\":%" PRIu64
      ",\"target\":%" PRIu64
      ",\"tb_index\":%" PRIu64
      ",\"tb_insns\":%" PRIu64
      ",\"target_tb_index\":%" PRIu64
      ",\"target_tb_insns\":%" PRIu64
      ",\"target_inside_tb\":%s}\n",
      mode_name,
      retired_total,
      selected_target,
      (uint64_t)insn->tb_index,
      (uint64_t)insn->tb_insns,
      target_tb_index,
      target_tb_insns,
      target_inside_tb() ? "true" : "false");
  fflush(trace_file);
}

static void
record_pause_request(const struct traced_insn *insn)
{
  if (trace_file == NULL) {
    return;
  }

  fprintf(
      trace_file,
      "{\"event\":\"pause_request\",\"mode\":\"%s\""
      ",\"retired\":%" PRIu64
      ",\"target\":%" PRIu64
      ",\"vaddr\":%" PRIu64
      ",\"tb_index\":%" PRIu64
      ",\"tb_insns\":%" PRIu64
      ",\"request_exact\":%s"
      ",\"target_inside_tb\":%s}\n",
      mode_name,
      request_retired,
      selected_target,
      request_vaddr,
      (uint64_t)insn->tb_index,
      (uint64_t)insn->tb_insns,
      request_retired == selected_target ? "true" : "false",
      target_inside_tb() ? "true" : "false");
  fflush(trace_file);
}

static void
record_final(void)
{
  if (trace_file == NULL) {
    return;
  }

  exit_retired = retired_total;
  const bool request_exact = target_selected && request_retired == selected_target;
  const bool zero_overshoot = target_selected && exit_retired == selected_target;
  const uint64_t overshoot =
      target_selected && exit_retired >= selected_target ? exit_retired - selected_target : 0;

  fprintf(
      trace_file,
      "{\"event\":\"final\",\"mode\":\"%s\""
      ",\"deadline_api_available\":%s"
      ",\"deadline_exact\":false"
      ",\"idle_wake_icount_reported\":\"unavailable\""
      ",\"actual_timer_fire_icount\":\"not_measured_missing_deadline_api\""
      ",\"target_selected\":%s"
      ",\"target\":%" PRIu64
      ",\"request_retired\":%" PRIu64
      ",\"exit_retired\":%" PRIu64
      ",\"pause_overshoot\":%" PRIu64
      ",\"request_exact\":%s"
      ",\"zero_overshoot\":%s"
      ",\"target_tb_index\":%" PRIu64
      ",\"target_tb_insns\":%" PRIu64
      ",\"target_inside_tb\":%s"
      ",\"stop_requested\":%s}\n",
      mode_name,
      deadline_api_available ? "true" : "false",
      target_selected ? "true" : "false",
      selected_target,
      request_retired,
      exit_retired,
      overshoot,
      request_exact ? "true" : "false",
      zero_overshoot ? "true" : "false",
      target_tb_index,
      target_tb_insns,
      target_inside_tb() ? "true" : "false",
      stop_requested ? "true" : "false");
  fflush(trace_file);
}

static void
select_fixed_target(void)
{
  if (!target_selected && configured_target != 0) {
    selected_target = configured_target;
    target_selected = true;
    target_tb_index = UINT64_MAX;
    target_tb_insns = UINT64_MAX;
  }
}

static void
maybe_select_dynamic_target(const struct traced_insn *insn)
{
  if (target_selected || retired_total < choose_after) {
    return;
  }
  if (insn->tb_index != 0 || insn->tb_insns <= dynamic_offset + 1U) {
    return;
  }

  selected_target = retired_total + dynamic_offset;
  target_selected = true;
  target_tb_index = dynamic_offset;
  target_tb_insns = (uint64_t)insn->tb_insns;
  record_selection(insn);
}

static void
request_pause(const struct traced_insn *insn)
{
  stop_requested = true;
  request_retired = retired_total;
  request_vaddr = insn->vaddr;
  record_pause_request(insn);
  if (qemu_plugin_request_vmstop() != 0) {
    qemu_plugin_request_shutdown(1);
  }
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  (void)vcpu_index;
  const struct traced_insn *insn = userdata;

  retired_total++;

  if (mode == TARGET_MODE_DYNAMIC_INTERIOR) {
    maybe_select_dynamic_target(insn);
  }

  if (target_selected && !stop_requested && retired_total >= selected_target) {
    request_pause(insn);
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
      qemu_plugin_outs("phase0-s7-ceiling-plugin: out of memory\n");
      return;
    }

    insn->vaddr = qemu_plugin_insn_vaddr(qinsn);
    insn->size = qemu_plugin_insn_size(qinsn);
    insn->tb_index = i;
    insn->tb_insns = count;

    qemu_plugin_register_vcpu_insn_exec_cb(
        qinsn, on_insn, QEMU_PLUGIN_CB_NO_REGS, insn);
  }
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  record_final();
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
    } else if (strncmp(argv[i], "mode=", 5) == 0) {
      const char *value = argv[i] + 5;
      if (strcmp(value, "fixed") == 0) {
        mode = TARGET_MODE_FIXED;
        mode_name = "fixed";
      } else if (strcmp(value, "dynamic-interior") == 0) {
        mode = TARGET_MODE_DYNAMIC_INTERIOR;
        mode_name = "dynamic-interior";
      } else {
        qemu_plugin_outs("phase0-s7-ceiling-plugin: invalid mode\n");
        return -1;
      }
    } else if (strncmp(argv[i], "target=", 7) == 0) {
      if (!parse_u64(argv[i] + 7, &configured_target)) {
        qemu_plugin_outs("phase0-s7-ceiling-plugin: invalid target\n");
        return -1;
      }
    } else if (strncmp(argv[i], "choose_after=", 13) == 0) {
      if (!parse_u64(argv[i] + 13, &choose_after)) {
        qemu_plugin_outs("phase0-s7-ceiling-plugin: invalid choose_after\n");
        return -1;
      }
    } else if (strncmp(argv[i], "dynamic_offset=", 15) == 0) {
      if (!parse_u64(argv[i] + 15, &dynamic_offset)) {
        qemu_plugin_outs("phase0-s7-ceiling-plugin: invalid dynamic_offset\n");
        return -1;
      }
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase0-s7-ceiling-plugin: missing out=<path>\n");
    return -1;
  }
  if (mode == TARGET_MODE_FIXED && configured_target == 0) {
    qemu_plugin_outs("phase0-s7-ceiling-plugin: fixed mode requires target=<n>\n");
    return -1;
  }
  if (mode == TARGET_MODE_DYNAMIC_INTERIOR && choose_after == 0) {
    qemu_plugin_outs("phase0-s7-ceiling-plugin: dynamic mode requires choose_after=<n>\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("phase0-s7-ceiling-plugin: failed to open output\n");
    return -1;
  }

  deadline_api_available =
      dlsym(RTLD_DEFAULT, "qemu_plugin_clock_deadline_ns") != NULL;
  record_capability();
  select_fixed_target();

  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
