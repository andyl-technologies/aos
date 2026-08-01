#include <ctype.h>
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
#define MAX_TRACKED_VCPUS 8U
#define S5_MARKER 0xc0100505U

enum payload_kind {
  KIND_RESIDENT = 1,
  KIND_PAGE_SPAN = 2,
  KIND_PAGED_MMAP = 3,
};

struct traced_insn {
  uint64_t vaddr;
  size_t size;
  unsigned char bytes[16];
  bool marker;
};

struct register_set {
  qemu_plugin_reg_descriptor *registers;
  size_t count;
  struct qemu_plugin_register *rdi;
  struct qemu_plugin_register *rsi;
  struct qemu_plugin_register *rdx;
  bool initialized;
};

static FILE *out_file;
static bool read_enabled = true;
static unsigned int expected_markers = 3;
static unsigned int tracked_vcpus = 1;
static uint64_t retired;
static uint64_t stream_hash = FNV1A64_OFFSET;
static uint64_t marker_count;
static uint64_t read_attempts;
static uint64_t read_successes;
static uint64_t read_failures;
static uint64_t bytes_mismatches;
static uint64_t register_read_failures;
static bool stop_requested;
static bool final_recorded;
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

static const char *
kind_name(uint64_t kind)
{
  switch (kind) {
  case KIND_RESIDENT:
    return "resident";
  case KIND_PAGE_SPAN:
    return "page_spanning";
  case KIND_PAGED_MMAP:
    return "paged_mmap";
  default:
    return "unknown";
  }
}

static unsigned char
expected_byte(uint64_t kind, uint64_t offset)
{
  return (unsigned char)((kind * 37U + offset * 17U + (offset >> 3U)) & 0xffU);
}

static uint64_t
expected_hash_for(uint64_t kind, uint64_t len)
{
  uint64_t hash = FNV1A64_OFFSET;

  for (uint64_t i = 0; i < len; i++) {
    const unsigned char byte = expected_byte(kind, i);
    hash = fnv1a_bytes(hash, &byte, 1);
  }
  return hash;
}

static bool
buffer_matches_kind(uint64_t kind, const GByteArray *buffer)
{
  for (gsize i = 0; i < buffer->len; i++) {
    if (buffer->data[i] != expected_byte(kind, i)) {
      return false;
    }
  }
  return true;
}

static bool
decode_marker(const struct traced_insn *insn)
{
  uint32_t marker = 0;

  if (insn->size != 8) {
    return false;
  }
  if (insn->bytes[0] != 0x0f || insn->bytes[1] != 0x1f ||
      insn->bytes[2] != 0x84 || insn->bytes[3] != 0x00) {
    return false;
  }

  marker = ((uint32_t)insn->bytes[4]) |
           ((uint32_t)insn->bytes[5] << 8U) |
           ((uint32_t)insn->bytes[6] << 16U) |
           ((uint32_t)insn->bytes[7] << 24U);
  return marker == S5_MARKER;
}

static bool
name_matches(const char *name, const char *target)
{
  char lower[128];
  size_t n = 0;

  if (name == NULL) {
    return false;
  }

  for (; name[n] != '\0' && n + 1U < sizeof(lower); n++) {
    lower[n] = (char)tolower((unsigned char)name[n]);
  }
  lower[n] = '\0';

  if (strcmp(lower, target) == 0) {
    return true;
  }
  if (lower[0] == '%' && strcmp(lower + 1, target) == 0) {
    return true;
  }

  const size_t lower_len = strlen(lower);
  const size_t target_len = strlen(target);
  if (lower_len < target_len) {
    return false;
  }

  const size_t offset = lower_len - target_len;
  if (strcmp(lower + offset, target) != 0) {
    return false;
  }
  return offset == 0 || !isalnum((unsigned char)lower[offset - 1U]);
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

  GArray *descriptors = qemu_plugin_get_registers();
  if (descriptors == NULL || descriptors->len == 0) {
    if (descriptors != NULL) {
      g_array_free(descriptors, true);
    }
    return false;
  }

  set->count = descriptors->len;
  set->registers = calloc(set->count, sizeof(*set->registers));
  if (set->registers == NULL) {
    g_array_free(descriptors, true);
    return false;
  }

  memcpy(set->registers, descriptors->data, set->count * sizeof(*set->registers));
  for (size_t i = 0; i < set->count; i++) {
    const qemu_plugin_reg_descriptor *reg = &set->registers[i];
    if (name_matches(reg->name, "rdi")) {
      set->rdi = reg->handle;
    } else if (name_matches(reg->name, "rsi")) {
      set->rsi = reg->handle;
    } else if (name_matches(reg->name, "rdx")) {
      set->rdx = reg->handle;
    }
  }

  set->initialized = true;
  g_array_free(descriptors, true);
  return set->rdi != NULL && set->rsi != NULL && set->rdx != NULL;
}

static bool
read_register_u64(struct qemu_plugin_register *handle, uint64_t *out)
{
  GByteArray *buffer = g_byte_array_new();
  if (buffer == NULL) {
    return false;
  }

  const int size = qemu_plugin_read_register(handle, buffer);
  if (size <= 0) {
    g_byte_array_free(buffer, true);
    return false;
  }

  uint64_t value = 0;
  const gsize limit = buffer->len < 8U ? buffer->len : 8U;
  for (gsize i = 0; i < limit; i++) {
    value |= (uint64_t)buffer->data[i] << (i * 8U);
  }

  *out = value;
  g_byte_array_free(buffer, true);
  return true;
}

static uint64_t
hash_registers_for_vcpu(uint64_t hash, unsigned int vcpu_index, uint64_t *failures)
{
  if (vcpu_index >= MAX_TRACKED_VCPUS || !register_sets[vcpu_index].initialized) {
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

    counts[vcpu] =
        register_sets[vcpu].initialized ? register_sets[vcpu].count : 0;
    *sample_failures += failures;
    aggregate = fnv1a_u64(aggregate, vcpu);
    aggregate = fnv1a_u64(aggregate, per_vcpu_hash);
  }

  register_read_failures += *sample_failures;
  return aggregate;
}

static void
record_final_sample(bool pause_sample)
{
  if (final_recorded || out_file == NULL) {
    return;
  }

  uint64_t register_counts[MAX_TRACKED_VCPUS] = {0};
  uint64_t sample_failures = 0;
  const uint64_t register_hash =
      compute_register_hash(&sample_failures, register_counts);
  uint64_t ram_bytes = 0;
  const uint64_t ram_hash = qemu_plugin_crucible_ram_hash(&ram_bytes);
  uint64_t state_hash = FNV1A64_OFFSET;

  state_hash = fnv1a_u64(state_hash, stream_hash);
  state_hash = fnv1a_u64(state_hash, register_hash);
  state_hash = fnv1a_u64(state_hash, ram_hash);
  state_hash = fnv1a_u64(state_hash, marker_count);

  fprintf(
      out_file,
      "{\"final\":true"
      ",\"pause_sample\":%s"
      ",\"retired\":%" PRIu64
      ",\"markers\":%" PRIu64
      ",\"read_enabled\":%s"
      ",\"read_attempts\":%" PRIu64
      ",\"read_successes\":%" PRIu64
      ",\"read_failures\":%" PRIu64
      ",\"bytes_mismatches\":%" PRIu64
      ",\"stream_hash\":\"%016" PRIx64 "\""
      ",\"register_hash\":\"%016" PRIx64 "\""
      ",\"ram_hash\":\"%016" PRIx64 "\""
      ",\"ram_bytes\":%" PRIu64
      ",\"state_hash\":\"%016" PRIx64 "\""
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"register_counts\":[",
      pause_sample ? "true" : "false",
      retired,
      marker_count,
      read_enabled ? "true" : "false",
      read_attempts,
      read_successes,
      read_failures,
      bytes_mismatches,
      stream_hash,
      register_hash,
      ram_hash,
      ram_bytes,
      state_hash,
      sample_failures,
      register_read_failures);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(out_file, "%s%" PRIu64, vcpu == 0 ? "" : ",", register_counts[vcpu]);
  }
  fprintf(out_file, "]}\n");
  fflush(out_file);
  final_recorded = true;
}

static void
record_doorbell(unsigned int vcpu_index)
{
  uint64_t kind = 0;
  uint64_t addr = 0;
  uint64_t len = 0;
  bool register_read_ok = false;
  bool read_attempted = false;
  bool read_success = false;
  bool bytes_match = false;
  uint64_t payload_hash = 0;
  uint64_t expected_hash = 0;

  marker_count++;

  if (vcpu_index < MAX_TRACKED_VCPUS && init_register_set(vcpu_index)) {
    const struct register_set *set = &register_sets[vcpu_index];
    register_read_ok = read_register_u64(set->rdi, &kind) &&
                       read_register_u64(set->rsi, &addr) &&
                       read_register_u64(set->rdx, &len);
  }

  if (!register_read_ok || len == 0 || len > 4096U) {
    read_failures++;
  } else {
    expected_hash = expected_hash_for(kind, len);
    if (read_enabled) {
      GByteArray *buffer = g_byte_array_new();
      read_attempts++;
      read_attempted = true;
      if (buffer != NULL) {
        read_success = qemu_plugin_read_memory_vaddr(addr, buffer, len);
        if (read_success) {
          payload_hash = fnv1a_bytes(FNV1A64_OFFSET, buffer->data, buffer->len);
          bytes_match = buffer->len == len && buffer_matches_kind(kind, buffer);
          if (bytes_match) {
            read_successes++;
          } else {
            bytes_mismatches++;
          }
        } else {
          read_failures++;
        }
        g_byte_array_free(buffer, true);
      } else {
        read_failures++;
      }
    }
  }

  fprintf(
      out_file,
      "{\"event\":\"doorbell\""
      ",\"marker_index\":%" PRIu64
      ",\"marker_icount\":%" PRIu64
      ",\"vcpu\":%u"
      ",\"kind\":%" PRIu64
      ",\"name\":\"%s\""
      ",\"addr\":\"%016" PRIx64 "\""
      ",\"len\":%" PRIu64
      ",\"register_read_ok\":%s"
      ",\"read_enabled\":%s"
      ",\"read_attempted\":%s"
      ",\"read_success\":%s"
      ",\"bytes_match\":%s"
      ",\"payload_hash\":\"%016" PRIx64 "\""
      ",\"expected_hash\":\"%016" PRIx64 "\"}\n",
      marker_count,
      retired,
      vcpu_index,
      kind,
      kind_name(kind),
      addr,
      len,
      register_read_ok ? "true" : "false",
      read_enabled ? "true" : "false",
      read_attempted ? "true" : "false",
      read_success ? "true" : "false",
      bytes_match ? "true" : "false",
      payload_hash,
      expected_hash);
  fflush(out_file);

  if (expected_markers != 0 && marker_count >= expected_markers && !stop_requested) {
    stop_requested = true;
    record_final_sample(true);
    qemu_plugin_crucible_pause_vm();
  }
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;

  retired++;
  stream_hash = fnv1a_u64(stream_hash, vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);

  if (insn->marker) {
    record_doorbell(vcpu_index);
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
      qemu_plugin_outs("phase0-s5-virtual-memory-plugin: out of memory\n");
      return;
    }

    insn->vaddr = qemu_plugin_insn_vaddr(qinsn);
    insn->size = qemu_plugin_insn_size(qinsn);
    if (insn->size > sizeof(insn->bytes)) {
      insn->size = sizeof(insn->bytes);
    }
    insn->size = qemu_plugin_insn_data(qinsn, insn->bytes, insn->size);
    insn->marker = decode_marker(insn);

    qemu_plugin_register_vcpu_insn_exec_cb(
        qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS, insn);
  }
}

static void
on_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
  (void)id;
  if (vcpu_index < MAX_TRACKED_VCPUS) {
    (void)init_register_set(vcpu_index);
  }
}

static void
on_plugin_exit(qemu_plugin_id_t id, void *userdata)
{
  (void)id;
  (void)userdata;

  record_final_sample(false);
  if (out_file != NULL) {
    fclose(out_file);
    out_file = NULL;
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
    } else if (strncmp(argv[i], "read=", 5) == 0) {
      read_enabled = parse_bool_flag(argv[i] + 5);
    } else if (strncmp(argv[i], "expected_markers=", 17) == 0) {
      uint64_t parsed = 0;
      if (!parse_u64(argv[i] + 17, &parsed) || parsed > UINT_MAX) {
        qemu_plugin_outs("phase0-s5-virtual-memory-plugin: invalid expected_markers\n");
        return -1;
      }
      expected_markers = (unsigned int)parsed;
    } else if (strncmp(argv[i], "vcpus=", 6) == 0) {
      uint64_t parsed = 0;
      if (!parse_u64(argv[i] + 6, &parsed) || parsed == 0 ||
          parsed > MAX_TRACKED_VCPUS) {
        qemu_plugin_outs("phase0-s5-virtual-memory-plugin: invalid vcpus\n");
        return -1;
      }
      tracked_vcpus = (unsigned int)parsed;
    }
  }

  if (tracked_vcpus == 0 || tracked_vcpus > MAX_TRACKED_VCPUS) {
    qemu_plugin_outs("phase0-s5-virtual-memory-plugin: unsupported vCPU count\n");
    return -1;
  }
  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("phase0-s5-virtual-memory-plugin: missing out=<path>\n");
    return -1;
  }

  out_file = fopen(out_path, "w");
  if (out_file == NULL) {
    qemu_plugin_outs("phase0-s5-virtual-memory-plugin: failed to open output\n");
    return -1;
  }

  qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
