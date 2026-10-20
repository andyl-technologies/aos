#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define FNV1A64_OFFSET 1469598103934665603ULL
#define FNV1A64_PRIME 1099511628211ULL
#define MAX_TRACKED_VCPUS 8U
#define S5_OBSERVATION_ENABLE_MARKER 0xc0100504U
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

struct canonical_register_values {
  uint64_t count;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  bool has_rdi;
  bool has_rsi;
  bool has_rdx;
};

struct canonical_register_reader {
  const unsigned char *bytes;
  size_t length;
  size_t offset;
};

static FILE *out_file;
static qemu_plugin_id_t plugin_id;
static uint64_t activation_vaddr;
static atomic_bool measured_callbacks_active = false;
static atomic_uint_fast64_t dormant_tb_translations = 0;
static atomic_uint_fast64_t activation_marker_callbacks = 0;
static atomic_uint_fast64_t reset_completion_callbacks = 0;
static atomic_uint_fast64_t activation_errors = 0;
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
static unsigned int pending_marker_vcpu;
static bool marker_pending;
static bool stop_requested;
static bool stop_control_requested;
static bool stop_admitted;
static bool final_recorded;

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

static int
sha256_fd(int fd, uint64_t length, unsigned char digest[32])
{
  unsigned char buffer[64 * 1024];
  GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
  uint64_t remaining = length;

  if (fd < 0 || length == 0 || checksum == NULL) {
    if (checksum != NULL) {
      g_checksum_free(checksum);
    }
    return -1;
  }
  while (remaining != 0) {
    const size_t requested = remaining < sizeof(buffer)
                                 ? (size_t)remaining
                                 : sizeof(buffer);
    const ssize_t received = read(fd, buffer, requested);

    if (received <= 0) {
      g_checksum_free(checksum);
      return -1;
    }
    g_checksum_update(checksum, buffer, (gssize)received);
    remaining -= (uint64_t)received;
  }
  gsize digest_length = 32;
  g_checksum_get_digest(checksum, digest, &digest_length);
  g_checksum_free(checksum);
  return digest_length == 32 ? 0 : -1;
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
decode_marker(const struct traced_insn *insn, uint32_t expected_marker)
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
  return marker == expected_marker;
}

static bool
read_canonical_u64(struct canonical_register_reader *reader, uint64_t *value)
{
  if (reader->offset > reader->length ||
      reader->length - reader->offset < sizeof(*value)) {
    return false;
  }

  *value = 0;
  for (size_t index = 0; index < sizeof(*value); index++) {
    *value |= (uint64_t)reader->bytes[reader->offset + index] << (index * 8);
  }
  reader->offset += sizeof(*value);
  return true;
}

static bool
read_canonical_bytes(
    struct canonical_register_reader *reader,
    const unsigned char **bytes,
    size_t *length)
{
  uint64_t encoded_length;

  if (!read_canonical_u64(reader, &encoded_length) ||
      encoded_length > SIZE_MAX || reader->offset > reader->length ||
      encoded_length > reader->length - reader->offset) {
    return false;
  }

  *bytes = reader->bytes + reader->offset;
  *length = (size_t)encoded_length;
  reader->offset += *length;
  return true;
}

static bool
register_name_matches(
    const unsigned char *name,
    size_t name_len,
    const char *target)
{
  const size_t target_len = strlen(target);

  return (name_len == target_len && memcmp(name, target, target_len) == 0) ||
         (name_len == target_len + 1 && name[0] == '%' &&
          memcmp(name + 1, target, target_len) == 0);
}

static uint64_t
register_value_u64(const unsigned char *bytes, size_t length)
{
  uint64_t value = 0;
  const size_t limit = length < sizeof(value) ? length : sizeof(value);

  for (size_t index = 0; index < limit; index++) {
    value |= (uint64_t)bytes[index] << (index * 8);
  }
  return value;
}

static bool
read_canonical_register_file(
    unsigned int vcpu_index,
    unsigned char **canonical_registers,
    size_t *canonical_register_len,
    struct canonical_register_values *values)
{
  static const char format[] = "aos-qemu-vcpu-regs-v1";
  uint64_t canonical_retired = 0;

  *canonical_registers = NULL;
  *canonical_register_len = 0;
  memset(values, 0, sizeof(*values));

  const int size_status = qemu_plugin_read_vcpu_regs(
      vcpu_index,
      NULL,
      0,
      canonical_register_len,
      &canonical_retired);
  if (size_status == 0 || *canonical_register_len == 0) {
    return false;
  }

  *canonical_registers = malloc(*canonical_register_len);
  if (*canonical_registers == NULL) {
    return false;
  }
  const size_t canonical_register_capacity = *canonical_register_len;
  const int read_status = qemu_plugin_read_vcpu_regs(
      vcpu_index,
      *canonical_registers,
      canonical_register_capacity,
      canonical_register_len,
      &canonical_retired);
  if (read_status != 0 || *canonical_register_len == 0 ||
      *canonical_register_len > canonical_register_capacity) {
    free(*canonical_registers);
    *canonical_registers = NULL;
    return false;
  }

  struct canonical_register_reader reader = {
      .bytes = *canonical_registers,
      .length = *canonical_register_len,
  };
  const unsigned char *encoded_format;
  size_t encoded_format_len;
  uint64_t encoded_vcpu;

  if (!read_canonical_bytes(&reader, &encoded_format, &encoded_format_len) ||
      encoded_format_len != sizeof(format) - 1 ||
      memcmp(encoded_format, format, sizeof(format) - 1) != 0 ||
      !read_canonical_u64(&reader, &encoded_vcpu) ||
      encoded_vcpu != vcpu_index ||
      !read_canonical_u64(&reader, &values->count) || values->count == 0 ||
      values->count > *canonical_register_len / (3 * sizeof(uint64_t))) {
    free(*canonical_registers);
    *canonical_registers = NULL;
    return false;
  }

  for (uint64_t index = 0; index < values->count; index++) {
    const unsigned char *name;
    const unsigned char *feature;
    const unsigned char *value;
    size_t name_len;
    size_t feature_len;
    size_t value_len;

    if (!read_canonical_bytes(&reader, &name, &name_len) ||
        !read_canonical_bytes(&reader, &feature, &feature_len) ||
        !read_canonical_bytes(&reader, &value, &value_len)) {
      free(*canonical_registers);
      *canonical_registers = NULL;
      return false;
    }
    (void)feature;
    (void)feature_len;

    if (register_name_matches(name, name_len, "rdi")) {
      values->rdi = register_value_u64(value, value_len);
      values->has_rdi = true;
    } else if (register_name_matches(name, name_len, "rsi")) {
      values->rsi = register_value_u64(value, value_len);
      values->has_rsi = true;
    } else if (register_name_matches(name, name_len, "rdx")) {
      values->rdx = register_value_u64(value, value_len);
      values->has_rdx = true;
    }
  }

  if (reader.offset != reader.length) {
    free(*canonical_registers);
    *canonical_registers = NULL;
    return false;
  }
  return true;
}

static uint64_t
hash_registers_for_vcpu(
    uint64_t hash,
    unsigned int vcpu_index,
    uint64_t *failures,
    uint64_t *register_count)
{
  unsigned char *canonical_registers;
  size_t canonical_register_len;
  struct canonical_register_values values;

  if (!read_canonical_register_file(
          vcpu_index,
          &canonical_registers,
          &canonical_register_len,
          &values)) {
    *failures += 1;
    return fnv1a_u64(hash, UINT64_MAX);
  }

  hash = fnv1a_u64(hash, vcpu_index);
  hash = fnv1a_u64(hash, values.count);
  hash = fnv1a_bytes(hash, canonical_registers, canonical_register_len);
  *register_count = values.count;
  free(canonical_registers);
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
        hash_registers_for_vcpu(
            FNV1A64_OFFSET, vcpu, &failures, &counts[vcpu]);

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
  uint64_t register_sample_failures = 0;
  const uint64_t register_hash =
      compute_register_hash(&register_sample_failures, register_counts);
  unsigned char ram_digest[32] = {0};
  struct qemu_plugin_crucible_fingerprint_material material = {
      .ram_fd = -1,
      .device_fd = -1,
  };
  const int capture_status =
      qemu_plugin_crucible_capture_fingerprint_material(&material);
  const int digest_status = capture_status == 0
      ? sha256_fd(material.ram_fd, material.ram_material_length, ram_digest)
      : capture_status;
  if (material.ram_fd >= 0) {
    close(material.ram_fd);
  }
  if (material.device_fd >= 0 && material.device_fd != material.ram_fd) {
    close(material.device_fd);
  }
  const uint64_t capture_failures =
      digest_status != 0 || material.ram_bytes == 0 || material.device_bytes == 0;
  const uint64_t activation_count = atomic_load_explicit(
      &activation_marker_callbacks, memory_order_relaxed);
  const uint64_t reset_count = atomic_load_explicit(
      &reset_completion_callbacks, memory_order_relaxed);
  const uint64_t activation_error_count =
      atomic_load_explicit(&activation_errors, memory_order_relaxed);
  const bool measured_active =
      atomic_load_explicit(&measured_callbacks_active, memory_order_acquire);
  const uint64_t ram_hash = fnv1a_bytes(FNV1A64_OFFSET, ram_digest, 32);
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
      ",\"activation_marker_callbacks\":%" PRIu64
      ",\"reset_completion_callbacks\":%" PRIu64
      ",\"activation_errors\":%" PRIu64
      ",\"measured_callbacks_active\":%s"
      ",\"dormant_tb_translations\":%" PRIuFAST64
      ",\"read_enabled\":%s"
      ",\"read_attempts\":%" PRIu64
      ",\"read_successes\":%" PRIu64
      ",\"read_failures\":%" PRIu64
      ",\"bytes_mismatches\":%" PRIu64
      ",\"stream_hash\":\"%016" PRIx64 "\""
      ",\"register_hash\":\"%016" PRIx64 "\""
      ",\"ram_hash\":\"%016" PRIx64 "\""
      ",\"capture_status\":%d"
      ",\"digest_status\":%d"
      ",\"ram_bytes\":%" PRIu64
      ",\"ram_material_length\":%" PRIu64
      ",\"device_bytes\":%" PRIu64
      ",\"device_material_length\":%" PRIu64
      ",\"state_hash\":\"%016" PRIx64 "\""
      ",\"sample_register_failures\":%" PRIu64
      ",\"sample_capture_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"register_counts\":[",
      pause_sample ? "true" : "false",
      retired,
      marker_count,
      activation_count,
      reset_count,
      activation_error_count,
      measured_active ? "true" : "false",
      atomic_load_explicit(&dormant_tb_translations, memory_order_relaxed),
      read_enabled ? "true" : "false",
      read_attempts,
      read_successes,
      read_failures,
      bytes_mismatches,
      stream_hash,
      register_hash,
      ram_hash,
      capture_status,
      digest_status,
      material.ram_bytes,
      material.ram_material_length,
      material.device_bytes,
      material.device_material_length,
      state_hash,
      register_sample_failures,
      capture_failures,
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

  if (vcpu_index < tracked_vcpus) {
    unsigned char *canonical_registers;
    size_t canonical_register_len;
    struct canonical_register_values values;

    register_read_ok = read_canonical_register_file(
        vcpu_index,
        &canonical_registers,
        &canonical_register_len,
        &values);
    if (register_read_ok) {
      kind = values.rdi;
      addr = values.rsi;
      len = values.rdx;
      register_read_ok =
          values.has_rdi && values.has_rsi && values.has_rdx;
      free(canonical_registers);
    }
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
  }
}

static uint64_t
next_pause_boundary(void *userdata)
{
  (void)userdata;
  return marker_pending || (stop_requested && !stop_admitted)
      ? qemu_plugin_icount_raw()
      : UINT64_MAX;
}

static void
on_pause_boundary(uint64_t current_icount, void *userdata)
{
  (void)current_icount;
  (void)userdata;

  if (marker_pending) {
    const unsigned int vcpu_index = pending_marker_vcpu;

    marker_pending = false;
    record_doorbell(vcpu_index);
  }
  if (!stop_requested || stop_control_requested) {
    return;
  }
  stop_control_requested = true;
  if (qemu_plugin_request_control_boundary() != 0) {
    qemu_plugin_request_shutdown(1);
  }
}

static void
on_control_boundary(
    unsigned int vcpu_index,
    uint64_t current_icount,
    void *userdata)
{
  (void)vcpu_index;
  (void)current_icount;
  (void)userdata;

  if (!stop_requested || !stop_control_requested || stop_admitted) {
    return;
  }
  stop_admitted = true;
  record_final_sample(true);
  if (qemu_plugin_request_vmstop() != 0) {
    qemu_plugin_request_shutdown(1);
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

  /* Keep long pre-marker boots diagnosable without logging every callback. */
  if (retired >= (1ULL << 20) && (retired & (retired - 1)) == 0) {
    fprintf(
        out_file,
        "{\"diagnostic\":\"instruction-progress\""
        ",\"callback_retired\":%" PRIu64
        ",\"observed_raw_icount\":%" PRIu64
        ",\"observed_tick_ps\":%" PRId64
        ",\"vcpu\":%u"
        ",\"vaddr\":\"%016" PRIx64 "\"}\n",
        retired,
        qemu_plugin_icount_raw(),
        qemu_plugin_sim_tick_observed(),
        vcpu_index,
        insn->vaddr);
    fflush(out_file);
  }

  if (insn->marker) {
    /* Aggregate register reads are admitted at the next exact boundary. */
    if (marker_pending) {
      qemu_plugin_outs(
          "phase0-s5-virtual-memory-plugin: marker boundary overlapped\n");
      qemu_plugin_request_shutdown(1);
      return;
    }
    pending_marker_vcpu = vcpu_index;
    marker_pending = true;
  }
}

static void
on_measured_tb_translate(struct qemu_plugin_tb *tb, void *userdata)
{
  (void)userdata;
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
    insn->marker = decode_marker(insn, S5_MARKER);

    qemu_plugin_register_vcpu_insn_exec_cb(
        qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS, insn);
  }
}

static void
on_plugin_exit(void *userdata)
{
  (void)userdata;

  record_final_sample(false);
  if (out_file != NULL) {
    fclose(out_file);
    out_file = NULL;
  }
}

static void
on_reset_complete(void *userdata)
{
  (void)userdata;

  const uint64_t previous = atomic_fetch_add_explicit(
      &reset_completion_callbacks, 1, memory_order_relaxed);
  const uint64_t activation_count = atomic_load_explicit(
      &activation_marker_callbacks, memory_order_acquire);
  if (previous != 0 || activation_count != 1 ||
      atomic_load_explicit(&measured_callbacks_active, memory_order_relaxed)) {
    atomic_fetch_add_explicit(&activation_errors, 1, memory_order_relaxed);
    return;
  }

  qemu_plugin_register_vcpu_tb_trans_cb(
      plugin_id, on_measured_tb_translate, NULL);
  qemu_plugin_register_sim_shmem_observer_cb(
      on_pause_boundary, next_pause_boundary, NULL);
  qemu_plugin_register_control_boundary_cb(on_control_boundary, NULL);
  qemu_plugin_register_atexit_cb(plugin_id, on_plugin_exit, NULL);
  atomic_store_explicit(&measured_callbacks_active, true, memory_order_release);
}

static void
on_activation_marker(unsigned int vcpu_index, void *userdata)
{
  (void)vcpu_index;
  (void)userdata;

  const uint64_t previous = atomic_fetch_add_explicit(
      &activation_marker_callbacks, 1, memory_order_acq_rel);
  if (previous != 0) {
    atomic_fetch_add_explicit(&activation_errors, 1, memory_order_relaxed);
    return;
  }

  qemu_plugin_reset(plugin_id, on_reset_complete, NULL);
}

static void
on_dormant_tb_translate(struct qemu_plugin_tb *tb, void *userdata)
{
  (void)userdata;

  atomic_fetch_add_explicit(&dormant_tb_translations, 1, memory_order_relaxed);
  if (atomic_load_explicit(&activation_marker_callbacks, memory_order_acquire) != 0 ||
      qemu_plugin_tb_vaddr(tb) != activation_vaddr) {
    return;
  }

  struct qemu_plugin_insn *qinsn = qemu_plugin_tb_get_insn(tb, 0);
  struct traced_insn insn = {0};

  insn.size = qemu_plugin_insn_size(qinsn);
  if (insn.size > sizeof(insn.bytes)) {
    insn.size = sizeof(insn.bytes);
  }
  insn.size = qemu_plugin_insn_data(qinsn, insn.bytes, insn.size);
  if (!decode_marker(&insn, S5_OBSERVATION_ENABLE_MARKER)) {
    atomic_fetch_add_explicit(&activation_errors, 1, memory_order_relaxed);
    return;
  }

  qemu_plugin_register_vcpu_insn_exec_cb(
      qinsn, on_activation_marker, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

static bool
parse_u64(const char *text, uint64_t *out)
{
  char *end = NULL;

  errno = 0;
  unsigned long long value = strtoull(text, &end, 0);
  if (errno == ERANGE || text[0] == '\0' || end == text || *end != '\0') {
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
  bool have_activation_vaddr = false;

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
    } else if (strncmp(argv[i], "activate-vaddr=", 15) == 0) {
      have_activation_vaddr =
          parse_u64(argv[i] + 15, &activation_vaddr) && activation_vaddr != 0;
      if (!have_activation_vaddr) {
        qemu_plugin_outs(
            "phase0-s5-virtual-memory-plugin: invalid activate-vaddr=<address>\n");
        return -1;
      }
    } else {
      qemu_plugin_outs("phase0-s5-virtual-memory-plugin: unknown option\n");
      return -1;
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
  if (!have_activation_vaddr) {
    qemu_plugin_outs(
        "phase0-s5-virtual-memory-plugin: missing activate-vaddr=<address>\n");
    return -1;
  }

  out_file = fopen(out_path, "w");
  if (out_file == NULL) {
    qemu_plugin_outs("phase0-s5-virtual-memory-plugin: failed to open output\n");
    return -1;
  }

  plugin_id = id;
  qemu_plugin_register_vcpu_tb_trans_cb(id, on_dormant_tb_translate, NULL);
  qemu_plugin_register_sim_shmem_observer_cb(
      on_pause_boundary, next_pause_boundary, NULL);
  qemu_plugin_register_control_boundary_cb(on_control_boundary, NULL);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
