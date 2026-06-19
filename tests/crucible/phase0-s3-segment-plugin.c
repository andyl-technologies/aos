#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define FNV1A64_OFFSET 1469598103934665603ULL
#define FNV1A64_PRIME 1099511628211ULL
#define MAX_TRACKED_VCPUS 32U

struct traced_insn {
  uint64_t vaddr;
  size_t size;
  unsigned char bytes[16];
};

struct register_set {
  qemu_plugin_reg_descriptor *registers;
  size_t count;
  bool initialized;
};

static FILE *trace_file;
static uint64_t start_at;
static uint64_t stop_after;
static uint64_t pause_at;
static uint64_t logical_base;
static uint64_t retired_total;
static uint64_t segment_retired;
static uint64_t stream_hash = FNV1A64_OFFSET;
static bool segment_started;
static bool stop_requested;
static bool extended_fingerprint;
static unsigned int tracked_vcpus = 1;
static uint64_t register_read_failures;
static struct register_set register_sets[MAX_TRACKED_VCPUS];

static uint64_t
fnv1a_u64(uint64_t hash, uint64_t value)
{
  for (unsigned int i = 0; i < 8; i++) {
    hash ^= (value >> (i * 8)) & 0xffU;
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

static uint64_t
fnv1a_bytes(uint64_t hash, const unsigned char *bytes, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

static uint64_t
fnv1a_cstr(uint64_t hash, const char *text)
{
  if (text == NULL) {
    return fnv1a_u64(hash, UINT64_MAX);
  }
  hash = fnv1a_bytes(hash, (const unsigned char *)text, strlen(text));
  return fnv1a_u64(hash, 0xffU);
}

static bool
init_register_set(unsigned int vcpu_index)
{
  if (vcpu_index >= MAX_TRACKED_VCPUS) {
    return false;
  }

  struct register_set *set = &register_sets[vcpu_index];
  if (set->initialized) {
    return true;
  }

  GArray *descriptors = qemu_plugin_crucible_get_vcpu_registers(vcpu_index);
  if (descriptors == NULL) {
    return false;
  }

  set->count = descriptors->len;
  if (set->count == 0) {
    g_array_free(descriptors, true);
    return false;
  }

  set->registers = calloc(set->count, sizeof(*set->registers));
  if (set->registers == NULL) {
    g_array_free(descriptors, true);
    return false;
  }

  memcpy(set->registers, descriptors->data, set->count * sizeof(*set->registers));
  set->initialized = true;
  g_array_free(descriptors, true);
  return true;
}

static uint64_t
hash_registers_for_vcpu(uint64_t hash, unsigned int vcpu_index, uint64_t *failures)
{
  if (!init_register_set(vcpu_index)) {
    *failures += 1;
    return fnv1a_u64(hash, UINT64_MAX);
  }

  const struct register_set *set = &register_sets[vcpu_index];
  GByteArray *buffer = g_byte_array_new();
  if (buffer == NULL) {
    *failures += 1;
    return fnv1a_u64(hash, UINT64_MAX - 1U);
  }

  hash = fnv1a_u64(hash, vcpu_index);
  hash = fnv1a_u64(hash, set->count);

  for (size_t i = 0; i < set->count; i++) {
    const qemu_plugin_reg_descriptor *reg = &set->registers[i];
    g_byte_array_set_size(buffer, 0);
    const int size =
        qemu_plugin_crucible_read_vcpu_register(vcpu_index, reg->handle, buffer);

    hash = fnv1a_cstr(hash, reg->name);
    hash = fnv1a_cstr(hash, reg->feature);
    if (size < 0) {
      *failures += 1;
      hash = fnv1a_u64(hash, UINT64_MAX);
      continue;
    }

    hash = fnv1a_u64(hash, (uint64_t)size);
    hash = fnv1a_bytes(hash, buffer->data, buffer->len);
  }

  g_byte_array_free(buffer, true);
  return hash;
}

static uint64_t
compute_register_hash(uint64_t *sample_failures, uint64_t counts[MAX_TRACKED_VCPUS])
{
  uint64_t aggregate = FNV1A64_OFFSET;

  *sample_failures = 0;
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    uint64_t failures = 0;
    const uint64_t per_vcpu_hash =
        hash_registers_for_vcpu(FNV1A64_OFFSET, vcpu, &failures);

    counts[vcpu] = register_sets[vcpu].initialized ? register_sets[vcpu].count : 0;
    *sample_failures += failures;
    aggregate = fnv1a_u64(aggregate, vcpu);
    aggregate = fnv1a_u64(aggregate, per_vcpu_hash);
  }

  register_read_failures += *sample_failures;
  return aggregate;
}

static void
record_sample(bool pause_sample)
{
  if (trace_file == NULL) {
    return;
  }

  uint64_t register_counts[MAX_TRACKED_VCPUS] = {0};
  uint64_t sample_failures = 0;
  const uint64_t register_hash =
      extended_fingerprint ? compute_register_hash(&sample_failures, register_counts) : 0;
  uint64_t ram_bytes = 0;
  const uint64_t ram_hash =
      extended_fingerprint ? qemu_plugin_crucible_ram_hash(&ram_bytes) : 0;
  const uint64_t rr_current_vcpu =
      extended_fingerprint ? qemu_plugin_crucible_rr_current_vcpu() : 0;
  const uint64_t rr_cursor_position =
      extended_fingerprint ? qemu_plugin_crucible_rr_cursor_position() : 0;
  const uint64_t rr_switch_quantum =
      extended_fingerprint ? qemu_plugin_crucible_rr_switch_quantum() : 0;
  uint64_t state_hash = FNV1A64_OFFSET;

  state_hash = fnv1a_u64(state_hash, stream_hash);
  state_hash = fnv1a_u64(state_hash, register_hash);
  state_hash = fnv1a_u64(state_hash, ram_hash);
  state_hash = fnv1a_u64(state_hash, segment_retired);
  state_hash = fnv1a_u64(state_hash, logical_base + segment_retired);
  state_hash = fnv1a_u64(state_hash, rr_current_vcpu);
  state_hash = fnv1a_u64(state_hash, rr_cursor_position);
  state_hash = fnv1a_u64(state_hash, rr_switch_quantum);

  fprintf(
      trace_file,
      "{\"retired_total\":%" PRIu64
      ",\"segment_retired\":%" PRIu64
      ",\"logical_retired\":%" PRIu64
      ",\"pause_sample\":%s"
      ",\"segment_started\":%s"
      ",\"stop_requested\":%s"
      ",\"stream_hash\":\"%016" PRIx64 "\""
      ",\"register_hash\":\"%016" PRIx64 "\""
      ",\"ram_hash\":\"%016" PRIx64 "\""
      ",\"ram_bytes\":%" PRIu64
      ",\"rr_current_vcpu\":%" PRIu64
      ",\"rr_cursor_position\":%" PRIu64
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"state_hash\":\"%016" PRIx64 "\""
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"register_counts\":[",
      retired_total,
      segment_retired,
      logical_base + segment_retired,
      pause_sample ? "true" : "false",
      segment_started ? "true" : "false",
      stop_requested ? "true" : "false",
      stream_hash,
      register_hash,
      ram_hash,
      ram_bytes,
      rr_current_vcpu,
      rr_cursor_position,
      rr_switch_quantum,
      state_hash,
      sample_failures,
      register_read_failures);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(trace_file, "%s%" PRIu64, vcpu == 0 ? "" : ",", register_counts[vcpu]);
  }
  fprintf(trace_file, "]}\n");
  fflush(trace_file);
}

static void
request_pause(void)
{
  stop_requested = true;
  record_sample(true);
  qemu_plugin_crucible_pause_vm();
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;

  retired_total++;

  if (pause_at != 0 && retired_total >= pause_at && !stop_requested) {
    request_pause();
    return;
  }

  if (retired_total <= start_at) {
    return;
  }
  if (stop_after != 0 && segment_retired >= stop_after) {
    return;
  }

  segment_started = true;
  segment_retired++;
  stream_hash = fnv1a_u64(stream_hash, vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);

  if (stop_after != 0 && segment_retired >= stop_after && !stop_requested) {
    request_pause();
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
      qemu_plugin_outs("phase0-s3-segment-plugin: out of memory\n");
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
on_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
  (void)id;
  if (extended_fingerprint) {
    (void)init_register_set(vcpu_index);
  }
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  record_sample(false);
  if (trace_file != NULL) {
    fclose(trace_file);
    trace_file = NULL;
  }
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

static bool
parse_bool_flag(const char *text)
{
  return strcmp(text, "1") == 0 || strcmp(text, "on") == 0 ||
         strcmp(text, "true") == 0 || strcmp(text, "yes") == 0;
}

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
  const char *out_path = NULL;

  if (info != NULL && info->system.smp_vcpus > 0) {
    tracked_vcpus = (unsigned int)info->system.smp_vcpus;
  }

  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "out=", 4) == 0) {
      out_path = argv[i] + 4;
    } else if (strncmp(argv[i], "start_at=", 9) == 0) {
      if (!parse_u64(argv[i] + 9, &start_at)) {
        qemu_plugin_outs("phase0-s3-segment-plugin: invalid start_at\n");
        return -1;
      }
    } else if (strncmp(argv[i], "stop_after=", 11) == 0) {
      if (!parse_u64(argv[i] + 11, &stop_after)) {
        qemu_plugin_outs("phase0-s3-segment-plugin: invalid stop_after\n");
        return -1;
      }
    } else if (strncmp(argv[i], "pause_at=", 9) == 0) {
      if (!parse_u64(argv[i] + 9, &pause_at)) {
        qemu_plugin_outs("phase0-s3-segment-plugin: invalid pause_at\n");
        return -1;
      }
    } else if (strncmp(argv[i], "logical_base=", 13) == 0) {
      if (!parse_u64(argv[i] + 13, &logical_base)) {
        qemu_plugin_outs("phase0-s3-segment-plugin: invalid logical_base\n");
        return -1;
      }
    } else if (strncmp(argv[i], "extended=", 9) == 0) {
      extended_fingerprint = parse_bool_flag(argv[i] + 9);
    } else if (strncmp(argv[i], "vcpus=", 6) == 0) {
      uint64_t parsed = 0;
      if (!parse_u64(argv[i] + 6, &parsed) || parsed == 0 ||
          parsed > MAX_TRACKED_VCPUS) {
        qemu_plugin_outs("phase0-s3-segment-plugin: invalid vcpus\n");
        return -1;
      }
      tracked_vcpus = (unsigned int)parsed;
    }
  }

  if (tracked_vcpus == 0 || tracked_vcpus > MAX_TRACKED_VCPUS) {
    qemu_plugin_outs("phase0-s3-segment-plugin: unsupported vCPU count\n");
    return -1;
  }
  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase0-s3-segment-plugin: missing out=<path>\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("phase0-s3-segment-plugin: failed to open output\n");
    return -1;
  }

  qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
