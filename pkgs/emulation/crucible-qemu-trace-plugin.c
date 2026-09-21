/* SPDX-License-Identifier: GPL-2.0-only */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define FNV1A64_OFFSET 14695981039346656037ULL
#define FNV1A64_PRIME 1099511628211ULL
#define MAX_TRACKED_VCPUS 256U
#define RAW_COPY_CHUNK_BYTES (1024U * 1024U)
#define TRACE_FINGERPRINT_SCHEMA "crucible.qemu.trace-fingerprint.v7"
#define ZERO_SHA256_HEX \
  "0000000000000000000000000000000000000000000000000000000000000000"

struct traced_insn {
  uint64_t vaddr;
  size_t size;
  unsigned char bytes[16];
};

struct register_digest_summary {
  unsigned char per_vcpu[MAX_TRACKED_VCPUS][32];
  unsigned char register_schema[MAX_TRACKED_VCPUS][32];
  uint64_t register_counts[MAX_TRACKED_VCPUS];
  uint64_t register_file_bytes[MAX_TRACKED_VCPUS];
  uint64_t register_retired[MAX_TRACKED_VCPUS];
  uint64_t sample_failures;
};

struct device_state_summary {
  unsigned char digest[32];
  unsigned char schema_digest[32];
  uint64_t bytes;
  uint64_t schema_sections;
  int status;
  int schema_status;
};

struct fingerprint_component_summary {
  unsigned char ram_digest[32];
  uint64_t ram_bytes;
  int ram_status;
  struct device_state_summary device_state;
};

static FILE *trace_file;
static uint64_t cadence = 100000;
static uint64_t next_sample = 100000;
static uint64_t stop_at;
static uint64_t retired;
static uint64_t stream_hash = FNV1A64_OFFSET;
static uint64_t device_event_hash = FNV1A64_OFFSET;
static uint64_t memory_event_hash = FNV1A64_OFFSET;
static uint64_t memory_events;
static uint64_t io_events;
static uint64_t register_read_failures;
static uint64_t device_state_failures;
static bool capture_memory_events;
static bool stop_requested;
static bool horizon_emitted;
static bool final_sample_emitted;
static bool sample_control_pending;
static uint64_t pending_sample_icount;
static unsigned int tracked_vcpus = 1;
static bool initialized_vcpus[MAX_TRACKED_VCPUS];
static uint64_t per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t rr_handoff_per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t rr_handoff_retired;
static uint64_t last_rr_switch_quantum;
static uint64_t last_valid_rr_current_vcpu = UINT64_MAX;
static uint64_t last_valid_rr_cursor_position = UINT64_MAX;
static uint64_t last_valid_rr_switch_quantum;
static bool last_valid_rr_cursor_available;
static uint64_t rr_switch_events;
static const char *launch_definition_digest = ZERO_SHA256_HEX;
static const char *qemu_build_digest = ZERO_SHA256_HEX;
static const char *trace_plugin_build_digest = ZERO_SHA256_HEX;
static struct qemu_plugin_crucible_process_argv_attestation
    process_argv_attestation;
static int process_argv_status = -1;

static uint64_t
on_sim_observer_max_advance_icount(void *userdata)
{
  (void)userdata;

  if (sample_control_pending) {
    return pending_sample_icount;
  }
  if (stop_at != 0 && stop_requested) {
    return stop_at;
  }
  if (stop_at != 0 && !horizon_emitted && stop_at < next_sample) {
    return stop_at;
  }
  return next_sample;
}

static int
request_exact_vmstop(void)
{
  const int status = qemu_plugin_request_vmstop();

  if (status != 0) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: exact VM stop request failed\n");
    qemu_plugin_request_shutdown(1);
  }
  return status;
}

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

static void
checksum_u64(GChecksum *checksum, uint64_t value)
{
  unsigned char encoded[8];

  for (size_t i = 0; i < sizeof(encoded); i++) {
    encoded[sizeof(encoded) - i - 1] = value & 0xffU;
    value >>= 8;
  }
  g_checksum_update(checksum, encoded, sizeof(encoded));
}

static void
checksum_bytes(GChecksum *checksum, const void *bytes, size_t length)
{
  checksum_u64(checksum, length);
  if (length != 0) {
    g_checksum_update(checksum, bytes, length);
  }
}

static void
checksum_string(GChecksum *checksum, const char *text)
{
  if (text == NULL) {
    checksum_u64(checksum, UINT64_MAX);
  } else {
    checksum_bytes(checksum, text, strlen(text));
  }
}

static bool
checksum_finish(GChecksum *checksum, unsigned char digest[32])
{
  gsize length = 32;

  g_checksum_get_digest(checksum, digest, &length);
  return length == 32;
}

static bool
digest_is_zero(const unsigned char digest[32])
{
  unsigned char accumulated = 0;

  for (size_t index = 0; index < 32; index++) {
    accumulated |= digest[index];
  }
  return accumulated == 0;
}

static void
digest_hex(const unsigned char digest[32], char output[65])
{
  static const char hexadecimal[] = "0123456789abcdef";

  for (size_t i = 0; i < 32; i++) {
    output[i * 2] = hexadecimal[digest[i] >> 4];
    output[i * 2 + 1] = hexadecimal[digest[i] & 0x0fU];
  }
  output[64] = '\0';
}

struct canonical_register_reader {
  const unsigned char *bytes;
  size_t length;
  size_t offset;
};

static bool
read_canonical_u64(struct canonical_register_reader *reader, uint64_t *value)
{
  if (reader->offset > reader->length ||
      reader->length - reader->offset < sizeof(*value)) {
    return false;
  }

  *value = 0;
  for (size_t i = 0; i < sizeof(*value); i++) {
    *value |= (uint64_t)reader->bytes[reader->offset + i] << (i * 8);
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
canonical_register_schema(
    const unsigned char *canonical_registers,
    size_t canonical_register_len,
    unsigned int vcpu_index,
    uint64_t *register_count,
    unsigned char digest[32])
{
  static const char format[] = "aos-qemu-vcpu-regs-v1";
  struct canonical_register_reader reader = {
      .bytes = canonical_registers,
      .length = canonical_register_len,
  };
  const unsigned char *encoded_format;
  size_t encoded_format_len;
  uint64_t encoded_vcpu;
  uint64_t encoded_count;
  GChecksum *checksum = NULL;
  bool ok = false;

  if (!read_canonical_bytes(&reader, &encoded_format, &encoded_format_len) ||
      encoded_format_len != sizeof(format) - 1 ||
      memcmp(encoded_format, format, sizeof(format) - 1) != 0 ||
      !read_canonical_u64(&reader, &encoded_vcpu) ||
      encoded_vcpu != vcpu_index ||
      !read_canonical_u64(&reader, &encoded_count) || encoded_count == 0 ||
      encoded_count > canonical_register_len / (3 * sizeof(uint64_t))) {
    return false;
  }

  checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    return false;
  }
  checksum_string(checksum, "crucible.qemu.register-schema.v1");
  checksum_u64(checksum, vcpu_index);
  checksum_u64(checksum, encoded_count);

  for (uint64_t index = 0; index < encoded_count; index++) {
    const unsigned char *name;
    const unsigned char *feature;
    size_t name_len;
    size_t feature_len;
    uint64_t value_len;

    if (!read_canonical_bytes(&reader, &name, &name_len) ||
        !read_canonical_bytes(&reader, &feature, &feature_len) ||
        !read_canonical_u64(&reader, &value_len) || value_len > SIZE_MAX ||
        reader.offset > reader.length ||
        value_len > reader.length - reader.offset) {
      goto out;
    }

    checksum_bytes(checksum, name, name_len);
    checksum_bytes(checksum, feature, feature_len);
    reader.offset += (size_t)value_len;
  }

  if (reader.offset != reader.length) {
    goto out;
  }

  *register_count = encoded_count;
  ok = checksum_finish(checksum, digest);

out:
  g_checksum_free(checksum);
  return ok;
}

static uint64_t
hash_mem_value(uint64_t hash, qemu_plugin_mem_value value)
{
  hash = fnv1a_u64(hash, (uint64_t)value.type);
  switch (value.type) {
  case QEMU_PLUGIN_MEM_VALUE_U8:
    hash = fnv1a_u64(hash, value.data.u8);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U16:
    hash = fnv1a_u64(hash, value.data.u16);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U32:
    hash = fnv1a_u64(hash, value.data.u32);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U64:
    hash = fnv1a_u64(hash, value.data.u64);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U128:
    hash = fnv1a_u64(hash, value.data.u128.low);
    hash = fnv1a_u64(hash, value.data.u128.high);
    break;
  }
  return hash;
}

static uint64_t
current_device_event_hash(void)
{
  return fnv1a_u64(device_event_hash, io_events);
}

static bool
is_sha256_hex(const char *text)
{
  if (text == NULL || strlen(text) != 64) {
    return false;
  }
  for (size_t i = 0; i < 64; i++) {
    const unsigned char byte = (unsigned char)text[i];
    if (!((byte >= '0' && byte <= '9') ||
          (byte >= 'a' && byte <= 'f') ||
          (byte >= 'A' && byte <= 'F'))) {
      return false;
    }
  }
  return true;
}

static bool
digest_registers_for_vcpu(
    unsigned int vcpu_index,
    uint64_t *failures,
    uint64_t *register_count,
    uint64_t *register_file_bytes,
    uint64_t *canonical_retired_out,
    unsigned char schema_digest[32],
    unsigned char digest[32])
{
  unsigned char *canonical_registers = NULL;
  size_t canonical_register_len = 0;
  uint64_t canonical_retired = 0;

  *register_count = 0;
  *register_file_bytes = 0;
  *canonical_retired_out = 0;
  memset(schema_digest, 0, 32);
  memset(digest, 0, 32);

  if (vcpu_index >= tracked_vcpus || !initialized_vcpus[vcpu_index]) {
    *failures += 1;
    return false;
  }

  /*
   * Ask the aggregate API for its exact canonical byte count, then perform one
   * side-effect-free read. The returned stream carries the descriptor schema
   * and values together, so no retired per-register ABI is needed.
   */
  int canonical_status = qemu_plugin_read_vcpu_regs(
      vcpu_index, NULL, 0, &canonical_register_len, &canonical_retired);
  if (canonical_status == 0 || canonical_register_len == 0) {
    *failures += 1;
    return false;
  }

  canonical_registers = malloc(canonical_register_len);
  if (canonical_registers == NULL) {
    *failures += 1;
    return false;
  }

  const size_t canonical_register_capacity = canonical_register_len;
  canonical_status = qemu_plugin_read_vcpu_regs(
      vcpu_index,
      canonical_registers,
      canonical_register_capacity,
      &canonical_register_len,
      &canonical_retired);
  if (canonical_status != 0 || canonical_register_len == 0 ||
      canonical_register_len > canonical_register_capacity) {
    free(canonical_registers);
    *failures += 1;
    return false;
  }
  if (!canonical_register_schema(
          canonical_registers,
          canonical_register_len,
          vcpu_index,
          register_count,
          schema_digest)) {
    free(canonical_registers);
    *failures += 1;
    return false;
  }

  GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    free(canonical_registers);
    *failures += 1;
    return false;
  }
  *register_file_bytes = canonical_register_len;
  *canonical_retired_out = canonical_retired;
  checksum_string(checksum, "crucible.qemu.register-file.v1");
  checksum_u64(checksum, vcpu_index);
  checksum_bytes(checksum, canonical_registers, canonical_register_len);
  const bool ok = checksum_finish(checksum, digest);
  g_checksum_free(checksum);
  free(canonical_registers);
  if (!ok) {
    *failures += 1;
    memset(digest, 0, 32);
    return false;
  }

  return true;
}

static bool
read_rr_cursor_snapshot(
    uint64_t *rr_current_vcpu,
    uint64_t *rr_cursor_position,
    uint64_t *rr_switch_quantum)
{
  struct qemu_plugin_rr_cursor cursor;

  if (qemu_plugin_rr_cursor(&cursor) != 0) {
    *rr_current_vcpu = UINT64_MAX;
    *rr_cursor_position = UINT64_MAX;
    *rr_switch_quantum = 0;
    return false;
  }

  *rr_current_vcpu = cursor.current_vcpu;
  *rr_cursor_position = cursor.cursor_position;
  *rr_switch_quantum = cursor.rr_switch_quantum;
  return true;
}

static struct register_digest_summary
compute_register_digests(void)
{
  struct register_digest_summary summary = {
      .sample_failures = 0,
  };

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    uint64_t failures = 0;
    uint64_t canonical_retired = 0;

    (void)digest_registers_for_vcpu(
        vcpu,
        &failures,
        &summary.register_counts[vcpu],
        &summary.register_file_bytes[vcpu],
        &canonical_retired,
        summary.register_schema[vcpu],
        summary.per_vcpu[vcpu]);
    summary.register_retired[vcpu] = per_vcpu_retired[vcpu];
    summary.sample_failures += failures;
  }

  register_read_failures += summary.sample_failures;
  return summary;
}

static uint64_t
diagnostic_register_fnv(const struct register_digest_summary *summary)
{
  uint64_t hash = FNV1A64_OFFSET;

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    hash = fnv1a_bytes(hash, summary->per_vcpu[vcpu], 32);
  }
  return hash;
}

static int
hash_fingerprint_material_fd(
    int fd,
    uint64_t material_length,
    uint64_t observed_bytes,
    unsigned char digest[32])
{
  struct stat metadata;
  GChecksum *checksum = NULL;
  unsigned char buffer[64 * 1024];
  uint64_t remaining = material_length;
  const int required_seals =
      F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
  const int descriptor_flags = fcntl(fd, F_GETFD);
  int status = 0;

  if (fd < 0 || material_length == 0 || observed_bytes == 0 ||
      fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_size < 0 || (uint64_t)metadata.st_size != material_length ||
      lseek(fd, 0, SEEK_CUR) != 0 ||
      descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0 ||
      fcntl(fd, F_GET_SEALS) != required_seals) {
    return -EINVAL;
  }

  checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    return -ENOMEM;
  }
  while (remaining != 0) {
    const size_t requested = remaining < sizeof(buffer)
                                 ? (size_t)remaining
                                 : sizeof(buffer);
    const ssize_t received = read(fd, buffer, requested);

    if (received < 0 && errno == EINTR) {
      continue;
    }
    if (received <= 0) {
      status = received == 0 ? -EIO : -errno;
      break;
    }
    g_checksum_update(checksum, buffer, (gssize)received);
    remaining -= (uint64_t)received;
  }
  if (status == 0 && !checksum_finish(checksum, digest)) {
    status = -EIO;
  }
  g_checksum_free(checksum);
  if (status != 0) {
    memset(digest, 0, 32);
  }
  return status;
}

static struct fingerprint_component_summary
capture_fingerprint_components(void)
{
  struct fingerprint_component_summary summary = {0};
  struct qemu_plugin_crucible_fingerprint_material material = {
      .ram_fd = -1,
      .device_fd = -1,
  };
  struct stat ram_metadata;
  struct stat device_metadata;

  summary.ram_status =
      qemu_plugin_crucible_capture_fingerprint_material(&material);
  summary.device_state.status = summary.ram_status;
  summary.device_state.schema_status = summary.ram_status;
  if (summary.ram_status == 0 &&
      (material.ram_fd < 0 || material.device_fd < 0 ||
       material.ram_fd == material.device_fd || material.ram_bytes == 0 ||
       material.device_bytes == 0 || material.device_schema_sections == 0 ||
       digest_is_zero(material.device_schema_digest) ||
       fstat(material.ram_fd, &ram_metadata) != 0 ||
       fstat(material.device_fd, &device_metadata) != 0 ||
       (ram_metadata.st_dev == device_metadata.st_dev &&
        ram_metadata.st_ino == device_metadata.st_ino))) {
    summary.ram_status = -EINVAL;
    summary.device_state.status = -EINVAL;
    summary.device_state.schema_status = -EINVAL;
  }
  if (summary.ram_status == 0) {
    summary.ram_bytes = material.ram_bytes;
    summary.device_state.bytes = material.device_bytes;
    summary.device_state.schema_sections = material.device_schema_sections;
    memcpy(
        summary.device_state.schema_digest,
        material.device_schema_digest,
        sizeof(summary.device_state.schema_digest));
    summary.ram_status = hash_fingerprint_material_fd(
        material.ram_fd,
        material.ram_material_length,
        material.ram_bytes,
        summary.ram_digest);
    summary.device_state.status = hash_fingerprint_material_fd(
        material.device_fd,
        material.device_material_length,
        material.device_bytes,
        summary.device_state.digest);
    summary.device_state.schema_status =
        digest_is_zero(summary.device_state.schema_digest) ? -EINVAL : 0;
  }
  if (material.ram_fd >= 0) {
    close(material.ram_fd);
  }
  if (material.device_fd >= 0 && material.device_fd != material.ram_fd) {
    close(material.device_fd);
  }
  if (summary.ram_status != 0 || summary.ram_bytes == 0 ||
      summary.device_state.status != 0 || summary.device_state.bytes == 0 ||
      summary.device_state.schema_status != 0) {
    device_state_failures++;
  }
  return summary;
}

static void
record_sample(unsigned int vcpu_index, bool final)
{
  if (trace_file == NULL) {
    return;
  }

  const struct register_digest_summary register_digests =
      compute_register_digests();
  const struct fingerprint_component_summary components =
      capture_fingerprint_components();
  const struct device_state_summary device_state = components.device_state;
  const unsigned char *ram_digest = components.ram_digest;
  const uint64_t ram_bytes = components.ram_bytes;
  const int ram_status = components.ram_status;
  uint64_t rr_current_vcpu;
  uint64_t rr_cursor_position;
  uint64_t rr_switch_quantum;
  const uint64_t device_event_component_hash =
      capture_memory_events ? current_device_event_hash() : 0;
  uint64_t register_diagnostic_fnv = FNV1A64_OFFSET;
  uint64_t aggregate_fingerprint_fnv = FNV1A64_OFFSET;
  const uint64_t observed_icount = qemu_plugin_icount_raw();
  const bool horizon_boundary =
      !final && stop_at != 0 && observed_icount >= stop_at;
  char ram_digest_hex[65];
  char device_state_digest_hex[65];
  char device_state_schema_digest_hex[65];
  char process_argv_digest_hex[65];

  register_diagnostic_fnv = diagnostic_register_fnv(&register_digests);
  digest_hex(ram_digest, ram_digest_hex);
  digest_hex(device_state.digest, device_state_digest_hex);
  digest_hex(device_state.schema_digest, device_state_schema_digest_hex);
  digest_hex(process_argv_attestation.sha256, process_argv_digest_hex);

  const bool rr_cursor_valid = read_rr_cursor_snapshot(
      &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum);
  bool emitted_rr_cursor_valid = rr_cursor_valid;
  bool rr_cursor_from_last_instruction = false;

  if (final && last_valid_rr_cursor_available) {
    rr_current_vcpu = last_valid_rr_current_vcpu;
    rr_cursor_position = last_valid_rr_cursor_position;
    rr_switch_quantum = last_valid_rr_switch_quantum;
    emitted_rr_cursor_valid = true;
    rr_cursor_from_last_instruction = true;
  }

  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, stream_hash);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, register_diagnostic_fnv);
  aggregate_fingerprint_fnv =
      fnv1a_bytes(aggregate_fingerprint_fnv, ram_digest, 32);
  aggregate_fingerprint_fnv =
      fnv1a_bytes(aggregate_fingerprint_fnv, device_state.digest, 32);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, device_state.bytes);
  aggregate_fingerprint_fnv = fnv1a_u64(
      aggregate_fingerprint_fnv, (uint64_t)(int64_t)device_state.status);
  aggregate_fingerprint_fnv = fnv1a_u64(
      aggregate_fingerprint_fnv, capture_memory_events ? 1U : 0U);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, device_event_component_hash);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, rr_current_vcpu);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, rr_cursor_position);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, rr_switch_quantum);
  aggregate_fingerprint_fnv = fnv1a_u64(
      aggregate_fingerprint_fnv, emitted_rr_cursor_valid ? 1U : 0U);
  aggregate_fingerprint_fnv = fnv1a_u64(
      aggregate_fingerprint_fnv, rr_cursor_from_last_instruction ? 1U : 0U);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, tracked_vcpus);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, stop_at);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, memory_event_hash);
  aggregate_fingerprint_fnv =
      fnv1a_u64(aggregate_fingerprint_fnv, observed_icount);

  fprintf(
      trace_file,
      "{\"schema\":\"" TRACE_FINGERPRINT_SCHEMA "\""
      ",\"retired\":%" PRIu64
      ",\"vcpu\":%u"
      ",\"final\":%s"
      ",\"tracked_vcpus\":%u"
      ",\"stop_at\":%" PRIu64
      ",\"stop_requested\":%s"
      ",\"trigger\":\"%s\""
      ",\"event_boundary\":%s"
      ",\"observed_icount\":%" PRIu64
      ",\"rr_current_vcpu\":%" PRIu64
      ",\"rr_cursor_position\":%" PRIu64
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"rr_cursor_valid\":%s"
      ",\"rr_cursor_source\":\"%s\""
      ",\"launch_definition_digest\":\"%s\""
      ",\"qemu_build_digest\":\"%s\""
      ",\"trace_plugin_build_digest\":\"%s\""
      ",\"process_argv_attestation_version\":%" PRIu32
      ",\"process_argv_encoding\":\"raw-unix-argv-v2\""
      ",\"process_argv_argc\":%" PRIu64
      ",\"process_argv_raw_bytes\":%" PRIu64
      ",\"process_argv_digest\":\"%s\""
      ",\"process_argv_status\":%d"
      ",\"stream_hash\":\"%016" PRIx64 "\""
      ",\"register_digests\":[",
      retired,
      vcpu_index,
      final ? "true" : "false",
      tracked_vcpus,
      stop_at,
      stop_requested ? "true" : "false",
      horizon_boundary ? "event" : "periodic",
      horizon_boundary ? "\"horizon-advance\"" : "null",
      observed_icount,
      rr_current_vcpu,
      rr_cursor_position,
      rr_switch_quantum,
      emitted_rr_cursor_valid ? "true" : "false",
      rr_cursor_from_last_instruction ? "last_executed_instruction" : "live_instruction",
      launch_definition_digest,
      qemu_build_digest,
      trace_plugin_build_digest,
      process_argv_attestation.version,
      process_argv_attestation.argc,
      process_argv_attestation.raw_bytes,
      process_argv_digest_hex,
      process_argv_status,
      stream_hash);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    char encoded[65];
    digest_hex(register_digests.per_vcpu[vcpu], encoded);
    fprintf(trace_file, "%s\"%s\"", vcpu == 0 ? "" : ",", encoded);
  }

  fprintf(
      trace_file,
      "]"
      ",\"register_counts\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_counts[vcpu]);
  }

  fprintf(trace_file, "]" ",\"register_file_bytes\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_file_bytes[vcpu]);
  }

  fprintf(trace_file, "]" ",\"register_schema_digests\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    char encoded[65];
    digest_hex(register_digests.register_schema[vcpu], encoded);
    fprintf(trace_file, "%s\"%s\"", vcpu == 0 ? "" : ",", encoded);
  }

  fprintf(trace_file, "]" ",\"register_retired\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_retired[vcpu]);
  }

  fprintf(
      trace_file,
      "]"
      ",\"memory_event_hash\":\"%016" PRIx64 "\""
      ",\"ram_digest\":\"%s\""
      ",\"ram_status\":%d"
      ",\"device_state_digest\":\"%s\""
      ",\"device_state_schema_digest\":\"%s\""
      ",\"device_state_sections\":%" PRIu64
      ",\"device_state_bytes\":%" PRIu64
      ",\"device_state_status\":%d"
      ",\"device_state_schema_status\":%d"
      ",\"device_state_complete\":%s",
      memory_event_hash,
      ram_digest_hex,
      ram_status,
      device_state_digest_hex,
      device_state_schema_digest_hex,
      device_state.schema_sections,
      device_state.bytes,
      device_state.status,
      device_state.schema_status,
      device_state.status == 0 && device_state.bytes != 0 &&
              device_state.schema_status == 0
          ? "true"
          : "false");
  if (capture_memory_events) {
    fprintf(
        trace_file,
        ",\"device_event_hash\":\"%016" PRIx64 "\"",
        device_event_component_hash);
  } else {
    fprintf(trace_file, ",\"device_event_hash\":null");
  }
  fprintf(
      trace_file,
      ",\"device_event_capture\":%s"
      ",\"aggregate_fingerprint_fnv\":\"%016" PRIx64 "\""
      ",\"ram_bytes\":%" PRIu64
      ",\"memory_events\":%" PRIu64
      ",\"io_events\":%" PRIu64
      ",\"memory_events_enabled\":%s"
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"device_state_failures\":%" PRIu64
      "}\n",
      capture_memory_events ? "true" : "false",
      aggregate_fingerprint_fnv,
      ram_bytes,
      memory_events,
      io_events,
      capture_memory_events ? "true" : "false",
      register_digests.sample_failures,
      register_read_failures,
      device_state_failures);
  fflush(trace_file);
}

static void
on_rr_handoff(unsigned int from_vcpu, unsigned int to_vcpu,
              uint64_t rr_switch_quantum, uint64_t source_retired_delta,
              void *userdata)
{
  (void)userdata;

  if (trace_file == NULL || from_vcpu >= tracked_vcpus ||
      to_vcpu >= tracked_vcpus || rr_switch_quantum == 0) {
    return;
  }

  if (source_retired_delta == 0) {
    return;
  }
  if (source_retired_delta > rr_switch_quantum ||
      UINT64_MAX - rr_handoff_retired < source_retired_delta ||
      UINT64_MAX - rr_handoff_per_vcpu_retired[from_vcpu] <
          source_retired_delta) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: invalid RR handoff accounting\n");
    qemu_plugin_request_shutdown(1);
    return;
  }

  rr_handoff_retired += source_retired_delta;
  rr_handoff_per_vcpu_retired[from_vcpu] += source_retired_delta;

  const uint64_t previous_rr_switch_quantum =
      last_rr_switch_quantum == 0 ? rr_switch_quantum
                                  : last_rr_switch_quantum;

  rr_switch_events++;
  fprintf(
      trace_file,
      "{\"kind\":\"rr_switch\""
      ",\"rr_switch_event\":%" PRIu64
      ",\"retired\":%" PRIu64
      ",\"from_vcpu\":%" PRIu64
      ",\"to_vcpu\":%" PRIu64
      ",\"rr_cursor_position\":%" PRIu64
      ",\"previous_rr_switch_quantum\":%" PRIu64
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"per_vcpu_retired\":[",
      rr_switch_events,
      rr_handoff_retired,
      from_vcpu,
      to_vcpu,
      UINT64_C(0),
      previous_rr_switch_quantum,
      rr_switch_quantum);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        rr_handoff_per_vcpu_retired[vcpu]);
  }

  fprintf(trace_file, "],\"per_vcpu_delta\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    const uint64_t delta = vcpu == from_vcpu ? source_retired_delta : 0;
    fprintf(trace_file, "%s%" PRIu64, vcpu == 0 ? "" : ",", delta);
  }

  fprintf(trace_file, "]}\n");
  fflush(trace_file);
  last_rr_switch_quantum = rr_switch_quantum;
}

static void
on_mem(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *userdata)
{
  (void)userdata;

  const struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  const bool is_io = hwaddr != NULL && qemu_plugin_hwaddr_is_io(hwaddr);
  const uint64_t phys_addr = hwaddr == NULL ? UINT64_MAX : qemu_plugin_hwaddr_phys_addr(hwaddr);
  const bool is_store = qemu_plugin_mem_is_store(info);
  const qemu_plugin_mem_value value = qemu_plugin_mem_get_value(info);
  uint64_t event_hash = FNV1A64_OFFSET;

  memory_events++;
  event_hash = fnv1a_u64(event_hash, vcpu_index);
  event_hash = fnv1a_u64(event_hash, vaddr);
  event_hash = fnv1a_u64(event_hash, phys_addr);
  event_hash = fnv1a_u64(event_hash, qemu_plugin_mem_size_shift(info));
  event_hash = fnv1a_u64(event_hash, is_store ? 1U : 0U);
  event_hash = fnv1a_u64(event_hash, is_io ? 1U : 0U);
  event_hash = hash_mem_value(event_hash, value);
  memory_event_hash = fnv1a_u64(memory_event_hash, memory_events);
  memory_event_hash = fnv1a_u64(memory_event_hash, event_hash);
  if (!is_io) {
    return;
  }

  io_events++;
  device_event_hash = fnv1a_u64(device_event_hash, io_events);
  device_event_hash = fnv1a_u64(device_event_hash, event_hash);
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;
  bool reached_stop = false;

  retired++;
  if (vcpu_index < MAX_TRACKED_VCPUS) {
    per_vcpu_retired[vcpu_index]++;
  }
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);
  uint64_t rr_current_vcpu;
  uint64_t rr_cursor_position;
  uint64_t rr_switch_quantum;
  if (read_rr_cursor_snapshot(
          &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum)) {
    last_valid_rr_current_vcpu = rr_current_vcpu;
    last_valid_rr_cursor_position = rr_cursor_position;
    last_valid_rr_switch_quantum = rr_switch_quantum;
    last_valid_rr_cursor_available = true;
  }
  reached_stop = stop_at != 0 && retired >= stop_at && !stop_requested;
  if (reached_stop) {
    stop_requested = true;
  }
  if (reached_stop) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: stop_at reached\n");
  }
}

static void
record_due_sample(uint64_t current_icount)
{
  const bool horizon_due =
      stop_at != 0 && !horizon_emitted && current_icount >= stop_at;
  const bool periodic_due = current_icount >= next_sample;

  if (!periodic_due && !horizon_due) {
    return;
  }

  uint64_t boundary_rr_current_vcpu;
  uint64_t boundary_rr_cursor_position;
  uint64_t boundary_rr_switch_quantum;
  const bool boundary_rr_cursor_valid = read_rr_cursor_snapshot(
      &boundary_rr_current_vcpu,
      &boundary_rr_cursor_position,
      &boundary_rr_switch_quantum);

  if (boundary_rr_cursor_valid) {
    last_valid_rr_current_vcpu = boundary_rr_current_vcpu;
    last_valid_rr_cursor_position = boundary_rr_cursor_position;
    last_valid_rr_switch_quantum = boundary_rr_switch_quantum;
    last_valid_rr_cursor_available = true;
  }

  if (!boundary_rr_cursor_valid) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: missing exact-boundary RR cursor\n");
    stop_requested = true;
    horizon_emitted = true;
    next_sample = UINT64_MAX;
    (void)request_exact_vmstop();
    return;
  }
  if (horizon_due) {
    stop_requested = true;
  }
  record_sample(
      last_valid_rr_cursor_available
          ? (unsigned int)last_valid_rr_current_vcpu
          : 0,
      false);
  if (horizon_due) {
    horizon_emitted = true;
    next_sample = UINT64_MAX;
    record_sample(UINT_MAX, true);
    final_sample_emitted = true;
    (void)request_exact_vmstop();
    return;
  }
  if (periodic_due) {
    if (UINT64_MAX - next_sample < cadence) {
      next_sample = UINT64_MAX;
    } else {
      next_sample += cadence;
    }
  }
}

static void
on_control_boundary(
    unsigned int vcpu_index, uint64_t observed_icount, void *userdata)
{
  (void)vcpu_index;
  (void)userdata;

  if (!sample_control_pending) {
    return;
  }
  if (observed_icount != pending_sample_icount) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: control boundary changed sample coordinate\n");
    qemu_plugin_request_shutdown(1);
    return;
  }

  record_due_sample(observed_icount);
  sample_control_pending = false;
}

static void
on_sim_observe_icount(uint64_t current_icount, void *userdata)
{
  (void)userdata;

  const bool horizon_due =
      stop_at != 0 && !horizon_emitted && current_icount >= stop_at;
  const bool periodic_due = current_icount >= next_sample;

  if (!periodic_due && !horizon_due) {
    return;
  }

  if (sample_control_pending) {
    if (current_icount != pending_sample_icount) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: pending sample coordinate advanced\n");
      qemu_plugin_request_shutdown(1);
    }
    return;
  }

  sample_control_pending = true;
  pending_sample_icount = current_icount;
  if (qemu_plugin_request_control_boundary() != 0) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: control boundary request failed\n");
    qemu_plugin_request_shutdown(1);
  }
}

static void
on_tb_translate(struct qemu_plugin_tb *tb, void *userdata)
{
  (void)userdata;

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
        qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS, insn);
    if (capture_memory_events) {
      qemu_plugin_register_vcpu_mem_cb(
          qinsn, on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);
    }
  }
}

static void
on_vcpu_init(unsigned int vcpu_index, void *userdata)
{
  (void)userdata;

  if (vcpu_index >= tracked_vcpus || vcpu_index >= MAX_TRACKED_VCPUS) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: initialized vCPU exceeds bound\n");
    qemu_plugin_request_shutdown(1);
    return;
  }
  initialized_vcpus[vcpu_index] = true;
}

static void
on_plugin_exit(void *userdata)
{
  (void)userdata;

  if (trace_file == NULL) {
    return;
  }

  if (stop_at == 0) {
    record_sample(UINT_MAX, true);
  } else if (!final_sample_emitted) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: missing stopped-boundary final sample\n");
  }
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

  memset(&process_argv_attestation, 0, sizeof(process_argv_attestation));
  process_argv_status = qemu_plugin_crucible_process_argv_attestation(
      &process_argv_attestation);
  if (process_argv_status != 0 || process_argv_attestation.version != 2 ||
      process_argv_attestation.argc == 0 ||
      digest_is_zero(process_argv_attestation.sha256)) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: invalid process argv self-attestation\n");
    return -1;
  }

  if (info != NULL && info->system.smp_vcpus > 0) {
    tracked_vcpus = (unsigned int)info->system.smp_vcpus;
  }

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
    } else if (strncmp(argv[i], "mem_events=", 11) == 0) {
      capture_memory_events = parse_bool_flag(argv[i] + 11);
    } else if (strncmp(argv[i], "stop_at=", 8) == 0) {
      if (!parse_u64(argv[i] + 8, &stop_at)) {
        qemu_plugin_outs("crucible-qemu-trace-plugin: invalid stop_at\n");
        return -1;
      }
    } else if (strncmp(argv[i], "vcpus=", 6) == 0) {
      uint64_t parsed = 0;
      if (!parse_u64(argv[i] + 6, &parsed) || parsed == 0 ||
          parsed > MAX_TRACKED_VCPUS) {
        qemu_plugin_outs("crucible-qemu-trace-plugin: invalid vcpus\n");
        return -1;
      }
      tracked_vcpus = (unsigned int)parsed;
    } else if (strncmp(argv[i], "launch_digest=", 14) == 0) {
      launch_definition_digest = argv[i] + 14;
    } else if (strncmp(argv[i], "qemu_build_digest=", 18) == 0) {
      qemu_build_digest = argv[i] + 18;
    } else if (strncmp(argv[i], "plugin_build_digest=", 20) == 0) {
      trace_plugin_build_digest = argv[i] + 20;
    }
  }

  if (tracked_vcpus == 0 || tracked_vcpus > MAX_TRACKED_VCPUS) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: unsupported vCPU count\n");
    return -1;
  }

  if (out_path == NULL || out_path[0] == '\0') {
    qemu_plugin_outs("crucible-qemu-trace-plugin: missing out=<path>\n");
    return -1;
  }

  if (!is_sha256_hex(launch_definition_digest) ||
      !is_sha256_hex(qemu_build_digest) ||
      !is_sha256_hex(trace_plugin_build_digest)) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: invalid provenance digest\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: failed to open trace file\n");
    return -1;
  }

  qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init, NULL);
  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate, NULL);
  qemu_plugin_register_control_boundary_cb(on_control_boundary, NULL);
  qemu_plugin_register_rr_handoff_cb(on_rr_handoff, NULL);
  qemu_plugin_register_sim_shmem_observer_cb(
      on_sim_observe_icount, on_sim_observer_max_advance_icount, NULL);
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
