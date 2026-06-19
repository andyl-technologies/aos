#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

struct traced_insn {
  uint64_t vaddr;
  size_t size;
  unsigned char bytes[16];
};

static FILE *trace_file;
static uint64_t cadence = 100000;
static uint64_t next_sample = 100000;
static uint64_t retired;
static uint64_t stream_hash = 1469598103934665603ULL;

static uint64_t
fnv1a_u64(uint64_t hash, uint64_t value)
{
  for (unsigned int i = 0; i < 8; i++) {
    hash ^= (value >> (i * 8)) & 0xffU;
    hash *= 1099511628211ULL;
  }
  return hash;
}

static uint64_t
fnv1a_bytes(uint64_t hash, const unsigned char *bytes, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static void
record_sample(unsigned int vcpu_index)
{
  if (trace_file == NULL) {
    return;
  }

  fprintf(
      trace_file,
      "{\"retired\":%" PRIu64 ",\"vcpu\":%u,\"hash\":\"%016" PRIx64 "\"}\n",
      retired,
      vcpu_index,
      stream_hash);
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;

  retired++;
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);

  if (retired >= next_sample) {
    record_sample(vcpu_index);
    next_sample += cadence;
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
      qemu_plugin_outs("crucible-qemu-trace-plugin: out of memory\n");
      return;
    }

    insn->vaddr = qemu_plugin_insn_vaddr(qinsn);
    insn->size = qemu_plugin_insn_size(qinsn);
    if (insn->size > sizeof(insn->bytes)) {
      insn->size = sizeof(insn->bytes);
    }
    insn->size = qemu_plugin_insn_data(qinsn, insn->bytes, insn->size);

    qemu_plugin_register_vcpu_insn_exec_cb(
        qinsn, on_insn, QEMU_PLUGIN_CB_NO_REGS, insn);
  }
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  if (trace_file == NULL) {
    return;
  }

  fprintf(
      trace_file,
      "{\"retired\":%" PRIu64 ",\"final\":true,\"hash\":\"%016" PRIx64 "\"}\n",
      retired,
      stream_hash);
  fclose(trace_file);
  trace_file = NULL;
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

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
  (void)info;

  const char *out_path = NULL;
  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "out=", 4) == 0) {
      out_path = argv[i] + 4;
    } else if (strncmp(argv[i], "cadence=", 8) == 0) {
      uint64_t parsed = 0;
      if (!parse_u64(argv[i] + 8, &parsed) || parsed == 0) {
        qemu_plugin_outs("crucible-qemu-trace-plugin: invalid cadence\n");
        return -1;
      }
      cadence = parsed;
      next_sample = parsed;
    }
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("crucible-qemu-trace-plugin: missing out=<path>\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: failed to open trace file\n");
    return -1;
  }

  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
