/* SPDX-License-Identifier: GPL-2.0-only */

#include <errno.h>
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

#define FNV1A64_OFFSET 14695981039346656037ULL
#define FNV1A64_PRIME 1099511628211ULL
#define MAX_TRACKED_VCPUS 256U
#define RAW_COPY_CHUNK_BYTES (1024U * 1024U)
#define TRACE_FINGERPRINT_SCHEMA "crucible.qemu.trace-fingerprint.v6"
#define ZERO_SHA256_HEX \
  "0000000000000000000000000000000000000000000000000000000000000000"

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
  uint64_t sections;
  int status;
  int schema_status;
};

struct raw_ram_summary {
  unsigned char digest[32];
  unsigned char region_map_digest[32];
  uint64_t bytes;
  uint64_t regions;
  int status;
};

struct raw_vmstate_summary {
  unsigned char digest[32];
  uint64_t bytes;
  int status;
  bool export_attempted;
};

static FILE *trace_file;
static uint64_t cadence = 100000;
static uint64_t next_sample = 100000;
static uint64_t stop_at;
static uint64_t retired;
static uint64_t stream_hash = FNV1A64_OFFSET;
static uint64_t device_event_hash = FNV1A64_OFFSET;
static uint64_t memory_event_hash = FNV1A64_OFFSET;
static uint64_t trajectory_hash = FNV1A64_OFFSET;
static unsigned char trajectory_digest[32];
static unsigned char memory_event_digest[32];
static unsigned char device_event_digest[32];
static uint64_t memory_events;
static uint64_t io_events;
static uint64_t register_read_failures;
static uint64_t device_state_failures;
static uint64_t trajectory_digest_failures;
static bool extended_fingerprint;
static bool capture_memory_events;
static bool definition_only;
static bool definition_emitted;
static bool definition_pause_requested;
static bool definition_callback_completed;
static int definition_pause_status = -1;
static bool post_boundary_samples;
static bool trace_rr_switch_events = true;
static bool det_ipi_probe;
static bool det_ipi_probe_commanded;
static bool stop_requested;
static bool horizon_emitted;
static bool terminal_horizon;
static bool terminal_pause_requested;
static bool terminal_callback_completed;
static bool terminal_state_emitted;
static bool terminal_final_emitted;
static bool final_sample_emitted;
static bool terminal_state_complete;
static int terminal_pause_status = -1;
static uint64_t terminal_observed_icount;
static unsigned int tracked_vcpus = 1;
static struct register_set register_sets[MAX_TRACKED_VCPUS];
static uint64_t per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t last_switch_per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t last_rr_current_vcpu = UINT64_MAX;
static uint64_t last_rr_cursor_position = UINT64_MAX;
static uint64_t last_rr_switch_quantum;
static uint64_t last_valid_rr_current_vcpu = UINT64_MAX;
static uint64_t last_valid_rr_cursor_position = UINT64_MAX;
static uint64_t last_valid_rr_switch_quantum;
static bool last_valid_rr_cursor_available;
static uint64_t rr_switch_events;
static uint64_t det_ipi_events;
static uint64_t trajectory_steps;
static uint64_t required_pc = UINT64_MAX;
static uint64_t required_pc_first_retired = UINT64_MAX;
static bool required_pc_seen;
static bool rr_switch_trace_initialized;
static const char *launch_definition_digest = ZERO_SHA256_HEX;
static const char *qemu_build_digest = ZERO_SHA256_HEX;
static const char *trace_plugin_build_digest = ZERO_SHA256_HEX;
static struct qemu_plugin_crucible_process_argv_attestation
    process_argv_attestation;
static int process_argv_status = -1;

static void
on_sim_publish_icount(uint64_t current_icount, void *userdata)
{
  (void)current_icount;
  (void)userdata;
}

static uint64_t
on_sim_max_advance_icount(void *userdata)
{
  (void)userdata;
  return UINT64_MAX;
}

static uint64_t
on_sim_observer_max_advance_icount(void *userdata)
{
  (void)userdata;

  if (terminal_horizon || (stop_at != 0 && stop_requested)) {
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

static bool
register_schema_digest(
    const struct register_set *set,
    unsigned int vcpu_index,
    unsigned char digest[32])
{
  GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);

  if (checksum == NULL) {
    return false;
  }
  checksum_string(checksum, "crucible.qemu.register-schema.v1");
  checksum_u64(checksum, vcpu_index);
  checksum_u64(checksum, set->count);
  for (size_t i = 0; i < set->count; i++) {
    checksum_string(checksum, set->registers[i].name);
    checksum_string(checksum, set->registers[i].feature);
  }
  const bool ok = checksum_finish(checksum, digest);
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

static void
checksum_mem_value(GChecksum *checksum, qemu_plugin_mem_value value)
{
  checksum_u64(checksum, (uint64_t)value.type);
  switch (value.type) {
  case QEMU_PLUGIN_MEM_VALUE_U8:
    checksum_u64(checksum, value.data.u8);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U16:
    checksum_u64(checksum, value.data.u16);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U32:
    checksum_u64(checksum, value.data.u32);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U64:
    checksum_u64(checksum, value.data.u64);
    break;
  case QEMU_PLUGIN_MEM_VALUE_U128:
    checksum_u64(checksum, value.data.u128.low);
    checksum_u64(checksum, value.data.u128.high);
    break;
  }
}

static bool
advance_memory_event_digest(
    unsigned char digest[32],
    const char *domain,
    uint64_t sequence,
    unsigned int vcpu_index,
    uint64_t vaddr,
    uint64_t phys_addr,
    qemu_plugin_meminfo_t info,
    bool is_store,
    bool is_io,
    qemu_plugin_mem_value value)
{
  GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
  unsigned char next[32] = {0};

  if (checksum == NULL) {
    memset(digest, 0, 32);
    return false;
  }
  checksum_string(checksum, domain);
  checksum_bytes(checksum, digest, 32);
  checksum_u64(checksum, sequence);
  checksum_u64(checksum, vcpu_index);
  checksum_u64(checksum, vaddr);
  checksum_u64(checksum, phys_addr);
  checksum_u64(checksum, qemu_plugin_mem_size_shift(info));
  checksum_u64(checksum, is_store ? 1U : 0U);
  checksum_u64(checksum, is_io ? 1U : 0U);
  checksum_mem_value(checksum, value);
  const bool ok = checksum_finish(checksum, next);
  g_checksum_free(checksum);
  if (!ok) {
    memset(digest, 0, 32);
    return false;
  }
  memcpy(digest, next, 32);
  return true;
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

  if (set->count > 0) {
    set->registers = calloc(set->count, sizeof(*set->registers));
    if (set->registers == NULL) {
      g_array_free(descriptors, true);
      return false;
    }

    memcpy(
        set->registers,
        descriptors->data,
        set->count * sizeof(*set->registers));
  }

  set->initialized = true;
  g_array_free(descriptors, true);
  return true;
}

static bool
digest_registers_for_vcpu(
    unsigned int vcpu_index,
    uint64_t *failures,
    uint64_t *register_file_bytes,
    uint64_t *canonical_retired_out,
    unsigned char digest[32])
{
  unsigned char *canonical_registers = NULL;
  size_t canonical_register_len = 0;
  uint64_t canonical_retired = 0;

  *register_file_bytes = 0;
  *canonical_retired_out = 0;
  memset(digest, 0, 32);

  if (!init_register_set(vcpu_index)) {
    *failures += 1;
    return false;
  }

  /*
   * Size the fast path from the architecture's descriptor count. The generous
   * per-register allowance keeps ordinary exports to one side-effect-free
   * read, while the ABI-reported required length permits an exact retry for an
   * unusually large future register.
   */
  if (register_sets[vcpu_index].count > (SIZE_MAX - 4096) / 256) {
    *failures += 1;
    return false;
  }
  size_t canonical_register_capacity =
      4096 + register_sets[vcpu_index].count * 256;
  canonical_registers = malloc(canonical_register_capacity);
  if (canonical_registers == NULL) {
    *failures += 1;
    return false;
  }

  canonical_register_len = canonical_register_capacity;
  int canonical_status = qemu_plugin_read_vcpu_regs(
      vcpu_index,
      canonical_registers,
      canonical_register_capacity,
      &canonical_register_len,
      &canonical_retired);
  if (canonical_status != 0 &&
      canonical_register_len > canonical_register_capacity) {
    unsigned char *resized = realloc(canonical_registers, canonical_register_len);
    if (resized == NULL) {
      free(canonical_registers);
      *failures += 1;
      return false;
    }
    canonical_registers = resized;
    canonical_register_capacity = canonical_register_len;
    canonical_status = qemu_plugin_read_vcpu_regs(
        vcpu_index,
        canonical_registers,
        canonical_register_capacity,
        &canonical_register_len,
        &canonical_retired);
  }
  if (canonical_status != 0 || canonical_register_len == 0 ||
      canonical_register_len > canonical_register_capacity) {
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
  /*
   * qemu_plugin_rr_cursor() is the formal export consumed here. The QEMU patch
   * stack backs it with qemu_plugin_crucible_rr_current_vcpu,
   * qemu_plugin_crucible_rr_cursor_position, and
   * qemu_plugin_crucible_rr_switch_quantum.
   */
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
        &summary.register_file_bytes[vcpu],
        &canonical_retired,
        summary.per_vcpu[vcpu]);
    summary.register_counts[vcpu] =
        register_sets[vcpu].initialized ? register_sets[vcpu].count : 0;
    if (!register_sets[vcpu].initialized ||
        !register_schema_digest(
            &register_sets[vcpu], vcpu, summary.register_schema[vcpu])) {
      failures++;
      memset(summary.register_schema[vcpu], 0, 32);
    }
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

static struct device_state_summary
capture_device_state(void)
{
  struct device_state_summary summary = {0};

  summary.status = qemu_plugin_crucible_device_state_sha256(
      summary.digest, &summary.bytes);
  summary.schema_status = qemu_plugin_crucible_device_state_schema_sha256(
      summary.schema_digest, &summary.sections);
  if (summary.status != 0 || summary.bytes == 0 ||
      summary.schema_status != 0 || summary.sections == 0) {
    device_state_failures++;
  }
  return summary;
}

static struct raw_ram_summary
capture_terminal_raw_ram(void)
{
  struct raw_ram_summary summary = {0};
  struct qemu_plugin_crucible_ram_region *regions = NULL;
  unsigned char *buffer = NULL;
  GChecksum *bytes_checksum = NULL;
  GChecksum *map_checksum = NULL;
  uint64_t count = 0;

  summary.status = qemu_plugin_crucible_guest_ram_regions(NULL, 0, &count);
  if (summary.status != -ENOSPC || count == 0 ||
      count > SIZE_MAX / sizeof(*regions)) {
    if (summary.status == 0) {
      summary.status = -ENODATA;
    }
    return summary;
  }

  regions = calloc((size_t)count, sizeof(*regions));
  buffer = malloc(RAW_COPY_CHUNK_BYTES);
  bytes_checksum = g_checksum_new(G_CHECKSUM_SHA256);
  map_checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (regions == NULL || buffer == NULL || bytes_checksum == NULL ||
      map_checksum == NULL) {
    summary.status = -ENOMEM;
    goto out;
  }

  summary.status =
      qemu_plugin_crucible_guest_ram_regions(regions, count, &summary.regions);
  if (summary.status != 0 || summary.regions != count) {
    if (summary.status == 0) {
      summary.status = -ESTALE;
    }
    goto out;
  }

  checksum_string(map_checksum, "crucible.qemu.raw-ram-region-map.v1");
  checksum_u64(map_checksum, count);
  for (uint64_t index = 0; index < count; index++) {
    const struct qemu_plugin_crucible_ram_region *region = &regions[index];
    const char *name_end = memchr(
        region->memory_region_name,
        '\0',
        sizeof(region->memory_region_name));

    if (region->length == 0 || name_end == NULL ||
        region->length > UINT64_MAX - region->guest_physical_base ||
        region->length > UINT64_MAX - summary.bytes) {
      summary.status = -EOVERFLOW;
      goto out;
    }
    if (index != 0) {
      const struct qemu_plugin_crucible_ram_region *previous =
          &regions[index - 1];
      if (previous->length >
              UINT64_MAX - previous->guest_physical_base ||
          previous->guest_physical_base + previous->length >
              region->guest_physical_base) {
        summary.status = -ESTALE;
        goto out;
      }
    }

    checksum_u64(map_checksum, region->guest_physical_base);
    checksum_u64(map_checksum, region->length);
    checksum_u64(map_checksum, region->memory_region_offset);
    checksum_bytes(
        map_checksum,
        region->memory_region_name,
        (size_t)(name_end - region->memory_region_name));

    uint64_t offset = 0;
    while (offset < region->length) {
      const uint64_t remaining = region->length - offset;
      const uint64_t chunk = remaining < RAW_COPY_CHUNK_BYTES
                                 ? remaining
                                 : RAW_COPY_CHUNK_BYTES;

      summary.status = qemu_plugin_crucible_guest_ram_region_copy(
          region, offset, buffer, chunk);
      if (summary.status != 0) {
        goto out;
      }
      g_checksum_update(bytes_checksum, buffer, (gssize)chunk);
      offset += chunk;
    }
    summary.bytes += region->length;
  }

  if (!checksum_finish(bytes_checksum, summary.digest) ||
      !checksum_finish(map_checksum, summary.region_map_digest)) {
    summary.status = -EIO;
    memset(summary.digest, 0, sizeof(summary.digest));
    memset(summary.region_map_digest, 0, sizeof(summary.region_map_digest));
  }

out:
  if (bytes_checksum != NULL) {
    g_checksum_free(bytes_checksum);
  }
  if (map_checksum != NULL) {
    g_checksum_free(map_checksum);
  }
  free(buffer);
  free(regions);
  return summary;
}

static struct raw_vmstate_summary
capture_terminal_vmstate(void)
{
  struct raw_vmstate_summary summary = {0};
  struct qemu_plugin_crucible_vmstate_snapshot *snapshot = NULL;
  unsigned char *buffer = NULL;
  GChecksum *checksum = NULL;

  summary.export_attempted = true;
  summary.status = qemu_plugin_crucible_vmstate_snapshot_begin(&snapshot);
  if (summary.status != 0 || snapshot == NULL) {
    if (summary.status == 0) {
      summary.status = -EIO;
    }
    return summary;
  }

  summary.status =
      qemu_plugin_crucible_vmstate_snapshot_size(snapshot, &summary.bytes);
  if (summary.status != 0 || summary.bytes == 0) {
    if (summary.status == 0) {
      summary.status = -ENODATA;
    }
    goto out;
  }

  buffer = malloc(RAW_COPY_CHUNK_BYTES);
  checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (buffer == NULL || checksum == NULL) {
    summary.status = -ENOMEM;
    goto out;
  }
  for (uint64_t offset = 0; offset < summary.bytes;) {
    const uint64_t remaining = summary.bytes - offset;
    const uint64_t chunk = remaining < RAW_COPY_CHUNK_BYTES
                               ? remaining
                               : RAW_COPY_CHUNK_BYTES;

    summary.status = qemu_plugin_crucible_vmstate_snapshot_copy(
        snapshot, offset, buffer, chunk);
    if (summary.status != 0) {
      goto out;
    }
    g_checksum_update(checksum, buffer, (gssize)chunk);
    offset += chunk;
  }
  if (!checksum_finish(checksum, summary.digest)) {
    summary.status = -EIO;
    memset(summary.digest, 0, sizeof(summary.digest));
  }

out:
  if (checksum != NULL) {
    g_checksum_free(checksum);
  }
  free(buffer);
  qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
  return summary;
}

static bool
all_register_sets_initialized(void)
{
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    if (!register_sets[vcpu].initialized) {
      return false;
    }
  }
  return true;
}

static void
record_definition(void)
{
  if (trace_file == NULL || definition_emitted ||
      !all_register_sets_initialized()) {
    return;
  }

  const struct register_digest_summary register_digests =
      compute_register_digests();
  unsigned char ram_digest[32] = {0};
  uint64_t ram_bytes = 0;
  const int ram_status =
      qemu_plugin_crucible_guest_ram_sha256(ram_digest, &ram_bytes);
  /*
   * Authoritative RR genesis-quiescence probe: definition raw-state validation,
   * not a live cursor-source fallback. record_definition() runs only in
   * definition_only mode at a pre-execution boundary where no vCPU is yet
   * current, so it reads the individual RR primitives directly rather than the
   * qemu_plugin_rr_cursor() aggregate (which fails closed without a current
   * vCPU and would zero the quantum here). The values are validated as
   * genesis-canonical (quantum nonzero, cursor 0, vCPU in range) and are never
   * carried as live cursor evidence: the per-instruction cursor stream is
   * sourced independently through read_rr_cursor_snapshot()/last_valid_rr_* so
   * this C observer remains a differential oracle whose live cursor derivation
   * does not depend on the patched-QEMU helpers.
   */
  const uint64_t rr_switch_quantum =
      qemu_plugin_crucible_rr_switch_quantum();
  const uint64_t rr_current_vcpu =
      qemu_plugin_crucible_rr_current_vcpu();
  const uint64_t rr_cursor_position =
      qemu_plugin_crucible_rr_cursor_position();
  const bool rr_current_vcpu_present = rr_current_vcpu != UINT64_MAX;
  const int rr_state_status =
      rr_switch_quantum == 0 || rr_cursor_position != 0 ||
              (rr_current_vcpu_present && rr_current_vcpu >= tracked_vcpus)
          ? -1
          : 0;
  /* Terminal VMState serialization may run mutating pre_save hooks. */
  const struct device_state_summary device_state = capture_device_state();
  const bool device_state_complete =
      device_state.status == 0 && device_state.bytes != 0 &&
      device_state.schema_status == 0 && device_state.sections != 0;
  char ram_digest_hex[65];
  char device_state_digest_hex[65];
  char device_state_schema_digest_hex[65];
  char process_argv_digest_hex[65];

  definition_emitted = true;
  stop_requested = true;
  const uint64_t observed_icount = qemu_plugin_crucible_icount();
  const bool observed_non_running =
      qemu_plugin_crucible_vm_non_running();
  digest_hex(ram_digest, ram_digest_hex);
  digest_hex(device_state.digest, device_state_digest_hex);
  digest_hex(device_state.schema_digest, device_state_schema_digest_hex);
  digest_hex(process_argv_attestation.sha256, process_argv_digest_hex);
  fprintf(
      trace_file,
      "{\"kind\":\"definition\""
      ",\"schema\":\"" TRACE_FINGERPRINT_SCHEMA "\""
      ",\"definition_only\":true"
      ",\"definition_pause_requested\":%s"
      ",\"definition_callback_completed\":%s"
      ",\"definition_pause_status\":%d"
      ",\"retired\":%" PRIu64
      ",\"observed_icount\":%" PRIu64
      ",\"observed_non_running\":%s"
      ",\"tracked_vcpus\":%u"
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"rr_state_status\":%d"
      ",\"rr_current_vcpu_present\":%s"
      ",\"rr_current_vcpu\":%" PRIu64
      ",\"rr_cursor_position\":%" PRIu64
      ",\"launch_definition_digest\":\"%s\""
      ",\"qemu_build_digest\":\"%s\""
      ",\"trace_plugin_build_digest\":\"%s\""
      ",\"process_argv_attestation_version\":%" PRIu32
      ",\"process_argv_encoding\":\"raw-unix-argv-v2\""
      ",\"process_argv_argc\":%" PRIu64
      ",\"process_argv_raw_bytes\":%" PRIu64
      ",\"process_argv_digest\":\"%s\""
      ",\"process_argv_status\":%d"
      ",\"register_counts\":[",
      definition_pause_requested ? "true" : "false",
      definition_callback_completed ? "true" : "false",
      definition_pause_status,
      retired,
      observed_icount,
      observed_non_running ? "true" : "false",
      tracked_vcpus,
      rr_switch_quantum,
      rr_state_status,
      rr_current_vcpu_present ? "true" : "false",
      rr_current_vcpu_present ? rr_current_vcpu : 0,
      rr_cursor_position,
      launch_definition_digest,
      qemu_build_digest,
      trace_plugin_build_digest,
      process_argv_attestation.version,
      process_argv_attestation.argc,
      process_argv_attestation.raw_bytes,
      process_argv_digest_hex,
      process_argv_status);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_counts[vcpu]);
  }
  fprintf(trace_file, "],\"register_file_bytes\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_file_bytes[vcpu]);
  }
  fprintf(trace_file, "],\"register_digests\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    char encoded[65];
    digest_hex(register_digests.per_vcpu[vcpu], encoded);
    fprintf(trace_file, "%s\"%s\"", vcpu == 0 ? "" : ",", encoded);
  }
  fprintf(trace_file, "],\"register_schema_digests\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    char encoded[65];
    digest_hex(register_digests.register_schema[vcpu], encoded);
    fprintf(trace_file, "%s\"%s\"", vcpu == 0 ? "" : ",", encoded);
  }
  fprintf(
      trace_file,
      "]"
      ",\"ram_digest\":\"%s\""
      ",\"ram_bytes\":%" PRIu64
      ",\"ram_status\":%d"
      ",\"device_state_digest\":\"%s\""
      ",\"device_state_schema_digest\":\"%s\""
      ",\"device_state_sections\":%" PRIu64
      ",\"device_state_bytes\":%" PRIu64
      ",\"device_state_status\":%d"
      ",\"device_state_schema_status\":%d"
      ",\"device_state_complete\":%s"
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"device_state_failures\":%" PRIu64
      "}\n",
      ram_digest_hex,
      ram_bytes,
      ram_status,
      device_state_digest_hex,
      device_state_schema_digest_hex,
      device_state.sections,
      device_state.bytes,
      device_state.status,
      device_state.schema_status,
      device_state_complete ? "true" : "false",
      register_digests.sample_failures,
      register_read_failures,
      device_state_failures);
  fflush(trace_file);
}

static void
record_terminal_final(void)
{
  char process_argv_digest_hex[65];

  if (trace_file == NULL || terminal_final_emitted) {
    return;
  }
  terminal_final_emitted = true;
  digest_hex(process_argv_attestation.sha256, process_argv_digest_hex);
  fprintf(
      trace_file,
      "{\"kind\":\"terminal_final\""
      ",\"schema\":\"" TRACE_FINGERPRINT_SCHEMA "\""
      ",\"terminal_state_schema\":\"crucible.qemu.terminal-horizon.v1\""
      ",\"final\":true"
      ",\"retired\":%" PRIu64
      ",\"stop_at\":%" PRIu64
      ",\"stop_requested\":%s"
      ",\"observed_icount\":%" PRIu64
      ",\"terminal_pause_requested\":%s"
      ",\"terminal_pause_status\":%d"
      ",\"terminal_callback_completed\":%s"
      ",\"terminal_state_emitted\":%s"
      ",\"terminal_state_complete\":%s"
      ",\"launch_definition_digest\":\"%s\""
      ",\"qemu_build_digest\":\"%s\""
      ",\"trace_plugin_build_digest\":\"%s\""
      ",\"process_argv_attestation_version\":%" PRIu32
      ",\"process_argv_encoding\":\"raw-unix-argv-v2\""
      ",\"process_argv_argc\":%" PRIu64
      ",\"process_argv_raw_bytes\":%" PRIu64
      ",\"process_argv_digest\":\"%s\""
      ",\"process_argv_status\":%d"
      "}\n",
      retired,
      stop_at,
      stop_requested ? "true" : "false",
      terminal_observed_icount,
      terminal_pause_requested ? "true" : "false",
      terminal_pause_status,
      terminal_callback_completed ? "true" : "false",
      terminal_state_emitted ? "true" : "false",
      terminal_state_complete ? "true" : "false",
      launch_definition_digest,
      qemu_build_digest,
      trace_plugin_build_digest,
      process_argv_attestation.version,
      process_argv_attestation.argc,
      process_argv_attestation.raw_bytes,
      process_argv_digest_hex,
      process_argv_status);
  fflush(trace_file);
}

static void
record_terminal_horizon(int paused_status)
{
  struct register_digest_summary register_digests = {0};
  struct raw_ram_summary ram = {0};
  struct raw_vmstate_summary vmstate = {0};
  uint64_t rr_current_vcpu = UINT64_MAX;
  uint64_t rr_cursor_position = UINT64_MAX;
  uint64_t rr_switch_quantum = 0;
  uint64_t register_retired_sum = 0;
  int capture_status = paused_status;
  bool rr_cursor_valid = false;
  bool observed_non_running = false;
  const char *rr_cursor_source = "terminal_paused_boundary";
  char ram_digest_hex[65];
  char ram_region_map_digest_hex[65];
  char vmstate_digest_hex[65];
  char process_argv_digest_hex[65];

  if (trace_file == NULL || terminal_state_emitted) {
    return;
  }
  terminal_state_emitted = true;
  terminal_pause_status = paused_status;
  terminal_observed_icount = qemu_plugin_crucible_icount();
  observed_non_running = qemu_plugin_crucible_vm_non_running();

  if (paused_status == 0) {
    register_digests = compute_register_digests();
    rr_cursor_valid = read_rr_cursor_snapshot(
        &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum);
    if (!rr_cursor_valid && last_valid_rr_cursor_available) {
      rr_current_vcpu = last_valid_rr_current_vcpu;
      rr_cursor_position = last_valid_rr_cursor_position;
      rr_switch_quantum = last_valid_rr_switch_quantum;
      rr_cursor_valid = true;
      rr_cursor_source = "terminal_last_executed_instruction";
    }
    ram = capture_terminal_raw_ram();

    /*
     * VMState pre_save hooks may mutate device bookkeeping. This must remain
     * the final state observation; beginning it seals QEMU even on a failed
     * serialization attempt.
     */
    vmstate = capture_terminal_vmstate();
  } else {
    ram.status = -ECANCELED;
    vmstate.status = -ECANCELED;
  }

  if (capture_status == 0 && terminal_observed_icount != stop_at) {
    capture_status = -ERANGE;
  }
  if (capture_status == 0 && !observed_non_running) {
    capture_status = -EBUSY;
  }
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    if (UINT64_MAX - register_retired_sum <
        register_digests.register_retired[vcpu]) {
      capture_status = capture_status == 0 ? -EOVERFLOW : capture_status;
    } else {
      register_retired_sum += register_digests.register_retired[vcpu];
    }
  }
  if (capture_status == 0 &&
      (register_digests.sample_failures != 0 ||
       register_retired_sum != retired || trajectory_digest_failures != 0)) {
    capture_status = -EIO;
  }
  if (capture_status == 0 &&
      (!rr_cursor_valid || rr_current_vcpu >= tracked_vcpus ||
       rr_switch_quantum == 0)) {
    capture_status = -EIO;
  }
  if (capture_status == 0 && ram.status != 0) {
    capture_status = ram.status;
  }
  if (capture_status == 0 && vmstate.status != 0) {
    capture_status = vmstate.status;
  }
  terminal_state_complete = capture_status == 0;

  digest_hex(ram.digest, ram_digest_hex);
  digest_hex(ram.region_map_digest, ram_region_map_digest_hex);
  digest_hex(vmstate.digest, vmstate_digest_hex);
  digest_hex(process_argv_attestation.sha256, process_argv_digest_hex);
  fprintf(
      trace_file,
      "{\"kind\":\"terminal_horizon\""
      ",\"schema\":\"" TRACE_FINGERPRINT_SCHEMA "\""
      ",\"terminal_state_schema\":\"crucible.qemu.terminal-horizon.v1\""
      ",\"final\":false"
      ",\"retired\":%" PRIu64
      ",\"vcpu\":%" PRIu64
      ",\"tracked_vcpus\":%u"
      ",\"stop_at\":%" PRIu64
      ",\"stop_requested\":%s"
      ",\"trigger\":\"event\""
      ",\"event_boundary\":\"horizon-advance\""
      ",\"observed_icount\":%" PRIu64
      ",\"observed_non_running\":%s"
      ",\"terminal_pause_status\":%d"
      ",\"terminal_capture_status\":%d"
      ",\"terminal_state_complete\":%s"
      ",\"terminal_vmstate_export\":%s"
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
      rr_current_vcpu,
      tracked_vcpus,
      stop_at,
      stop_requested ? "true" : "false",
      terminal_observed_icount,
      observed_non_running ? "true" : "false",
      terminal_pause_status,
      capture_status,
      terminal_state_complete ? "true" : "false",
      vmstate.status == 0 && vmstate.export_attempted ? "true" : "false",
      rr_current_vcpu,
      rr_cursor_position,
      rr_switch_quantum,
      rr_cursor_valid ? "true" : "false",
      rr_cursor_source,
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
  fprintf(trace_file, "],\"register_counts\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_counts[vcpu]);
  }
  fprintf(trace_file, "],\"register_file_bytes\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        register_digests.register_file_bytes[vcpu]);
  }
  fprintf(trace_file, "],\"register_schema_digests\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    char encoded[65];
    digest_hex(register_digests.register_schema[vcpu], encoded);
    fprintf(trace_file, "%s\"%s\"", vcpu == 0 ? "" : ",", encoded);
  }
  fprintf(trace_file, "],\"register_retired\":[");
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
      ",\"raw_ram_digest\":\"%s\""
      ",\"raw_ram_region_map_digest\":\"%s\""
      ",\"raw_ram_regions\":%" PRIu64
      ",\"raw_ram_bytes\":%" PRIu64
      ",\"raw_ram_status\":%d"
      ",\"vmstate_digest\":\"%s\""
      ",\"vmstate_bytes\":%" PRIu64
      ",\"vmstate_status\":%d"
      ",\"memory_event_hash\":\"%016" PRIx64 "\""
      ",\"device_event_hash\":\"%016" PRIx64 "\""
      ",\"memory_events\":%" PRIu64
      ",\"io_events\":%" PRIu64
      ",\"memory_events_enabled\":%s"
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"trajectory_digest_failures\":%" PRIu64
      "}\n",
      ram_digest_hex,
      ram_region_map_digest_hex,
      ram.regions,
      ram.bytes,
      ram.status,
      vmstate_digest_hex,
      vmstate.bytes,
      vmstate.status,
      memory_event_hash,
      current_device_event_hash(),
      memory_events,
      io_events,
      capture_memory_events ? "true" : "false",
      register_digests.sample_failures,
      register_read_failures,
      trajectory_digest_failures);
  fflush(trace_file);
}

static void
on_terminal_paused(int status, void *userdata)
{
  (void)userdata;

  if (terminal_callback_completed) {
    return;
  }
  record_terminal_horizon(status);
  terminal_callback_completed = true;
  /*
   * This final record is the one-shot trace-publication barrier, not process
   * exit evidence. QEMU remains terminally sealed and paused until its owner
   * issues the later QMP quit; the atexit callback only closes the trace.
   */
  record_terminal_final();
}

static void
fold_trajectory_state(
    uint64_t boundary_icount,
    unsigned int vcpu_index,
    const struct register_digest_summary *register_digests,
    const unsigned char *ram_digest,
    const struct traced_insn *insn,
    uint64_t rr_current_vcpu,
    uint64_t rr_cursor_position,
    uint64_t rr_switch_quantum,
    bool rr_cursor_valid,
    bool post_boundary)
{
  const uint64_t register_diagnostic_fnv =
      diagnostic_register_fnv(register_digests);
  const uint64_t ram_diagnostic_fnv =
      ram_digest == NULL ? 0 : fnv1a_bytes(FNV1A64_OFFSET, ram_digest, 32);
  GChecksum *checksum;
  unsigned char next_digest[32] = {0};

  trajectory_steps++;
  trajectory_hash = fnv1a_u64(trajectory_hash, boundary_icount);
  trajectory_hash = fnv1a_u64(trajectory_hash, vcpu_index);
  trajectory_hash = fnv1a_u64(trajectory_hash, stream_hash);
  trajectory_hash = fnv1a_u64(trajectory_hash, register_diagnostic_fnv);
  trajectory_hash = fnv1a_u64(trajectory_hash, memory_event_hash);
  trajectory_hash = fnv1a_u64(trajectory_hash, current_device_event_hash());
  trajectory_hash = fnv1a_u64(trajectory_hash, memory_events);
  trajectory_hash = fnv1a_u64(trajectory_hash, io_events);
  trajectory_hash = fnv1a_u64(trajectory_hash, rr_current_vcpu);
  trajectory_hash = fnv1a_u64(trajectory_hash, rr_cursor_position);
  trajectory_hash = fnv1a_u64(trajectory_hash, rr_switch_quantum);
  trajectory_hash = fnv1a_u64(trajectory_hash, rr_cursor_valid ? 1U : 0U);
  trajectory_hash = fnv1a_u64(trajectory_hash, post_boundary ? 1U : 0U);
  trajectory_hash = fnv1a_u64(trajectory_hash, ram_diagnostic_fnv);

  if (trajectory_digest_failures != 0) {
    return;
  }
  checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    memset(trajectory_digest, 0, 32);
    trajectory_digest_failures++;
    return;
  }
  checksum_string(checksum, "crucible.qemu.execution-trajectory.v1");
  checksum_bytes(checksum, trajectory_digest, 32);
  checksum_u64(checksum, trajectory_steps);
  checksum_u64(checksum, boundary_icount);
  checksum_u64(checksum, vcpu_index);
  checksum_u64(checksum, post_boundary ? 1U : 0U);
  if (insn == NULL) {
    checksum_u64(checksum, 0);
  } else {
    checksum_u64(checksum, 1);
    checksum_u64(checksum, insn->vaddr);
    checksum_bytes(checksum, insn->bytes, insn->size);
  }
  checksum_u64(checksum, tracked_vcpus);
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    checksum_bytes(checksum, register_digests->per_vcpu[vcpu], 32);
    checksum_u64(checksum, register_digests->register_retired[vcpu]);
  }
  if (ram_digest == NULL) {
    checksum_u64(checksum, 0);
  } else {
    checksum_u64(checksum, 1);
    checksum_bytes(checksum, ram_digest, 32);
  }
  checksum_bytes(checksum, memory_event_digest, 32);
  checksum_bytes(checksum, device_event_digest, 32);
  checksum_u64(checksum, memory_events);
  checksum_u64(checksum, io_events);
  checksum_u64(checksum, rr_current_vcpu);
  checksum_u64(checksum, rr_cursor_position);
  checksum_u64(checksum, rr_switch_quantum);
  checksum_u64(checksum, rr_cursor_valid ? 1U : 0U);
  const bool ok = checksum_finish(checksum, next_digest);
  g_checksum_free(checksum);
  if (!ok) {
    memset(trajectory_digest, 0, 32);
    trajectory_digest_failures++;
    return;
  }
  memcpy(trajectory_digest, next_digest, 32);
}

static void
record_sample(unsigned int vcpu_index, bool final)
{
  if (trace_file == NULL) {
    return;
  }

  if (!extended_fingerprint) {
    if (final) {
      fprintf(
          trace_file,
          "{\"retired\":%" PRIu64 ",\"final\":true,\"hash\":\"%016" PRIx64 "\"}\n",
          retired,
          stream_hash);
    } else {
      fprintf(
          trace_file,
          "{\"retired\":%" PRIu64 ",\"vcpu\":%u,\"hash\":\"%016" PRIx64 "\"}\n",
          retired,
          vcpu_index,
          stream_hash);
    }
    fflush(trace_file);
    return;
  }

  const struct register_digest_summary register_digests =
      compute_register_digests();
  const struct device_state_summary device_state = capture_device_state();
  unsigned char ram_digest[32] = {0};
  uint64_t ram_bytes = 0;
  const int ram_status =
      qemu_plugin_crucible_guest_ram_sha256(ram_digest, &ram_bytes);
  uint64_t rr_current_vcpu;
  uint64_t rr_cursor_position;
  uint64_t rr_switch_quantum;
  const uint64_t device_event_component_hash =
      capture_memory_events ? current_device_event_hash() : 0;
  uint64_t register_diagnostic_fnv = FNV1A64_OFFSET;
  uint64_t diagnostic_extended_fnv = FNV1A64_OFFSET;
  const uint64_t observed_icount = qemu_plugin_crucible_icount();
  const bool horizon_boundary =
      !final && stop_at != 0 && observed_icount >= stop_at;
  char ram_digest_hex[65];
  char device_state_digest_hex[65];
  char device_state_schema_digest_hex[65];
  char trajectory_digest_hex[65];
  char process_argv_digest_hex[65];

  register_diagnostic_fnv = diagnostic_register_fnv(&register_digests);
  digest_hex(ram_digest, ram_digest_hex);
  digest_hex(device_state.digest, device_state_digest_hex);
  digest_hex(device_state.schema_digest, device_state_schema_digest_hex);
  digest_hex(trajectory_digest, trajectory_digest_hex);
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

  diagnostic_extended_fnv = fnv1a_u64(diagnostic_extended_fnv, stream_hash);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, register_diagnostic_fnv);
  diagnostic_extended_fnv =
      fnv1a_bytes(diagnostic_extended_fnv, ram_digest, 32);
  diagnostic_extended_fnv =
      fnv1a_bytes(diagnostic_extended_fnv, device_state.digest, 32);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, device_state.bytes);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, (uint64_t)(int64_t)device_state.status);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, capture_memory_events ? 1U : 0U);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, device_event_component_hash);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, rr_current_vcpu);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, rr_cursor_position);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, rr_switch_quantum);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, emitted_rr_cursor_valid ? 1U : 0U);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, rr_cursor_from_last_instruction ? 1U : 0U);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, tracked_vcpus);
  diagnostic_extended_fnv = fnv1a_u64(diagnostic_extended_fnv, stop_at);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, trajectory_hash);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, memory_event_hash);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, post_boundary_samples ? 1U : 0U);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, observed_icount);
  diagnostic_extended_fnv = fnv1a_u64(diagnostic_extended_fnv, required_pc);
  diagnostic_extended_fnv = fnv1a_u64(
      diagnostic_extended_fnv, required_pc_seen ? 1U : 0U);
  diagnostic_extended_fnv =
      fnv1a_u64(diagnostic_extended_fnv, required_pc_first_retired);

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
      ",\"post_boundary_sample\":%s"
      ",\"trajectory_steps\":%" PRIu64
      ",\"required_pc\":%" PRIu64
      ",\"required_pc_seen\":%s"
      ",\"required_pc_first_retired\":%" PRIu64
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
      post_boundary_samples ? "true" : "false",
      trajectory_steps,
      required_pc,
      required_pc_seen ? "true" : "false",
      required_pc_first_retired,
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
      ",\"trajectory_hash\":\"%016" PRIx64 "\""
      ",\"trajectory_digest\":\"%s\""
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
      trajectory_hash,
      trajectory_digest_hex,
      memory_event_hash,
      ram_digest_hex,
      ram_status,
      device_state_digest_hex,
      device_state_schema_digest_hex,
      device_state.sections,
      device_state.bytes,
      device_state.status,
      device_state.schema_status,
      device_state.status == 0 && device_state.bytes != 0 &&
              device_state.schema_status == 0 && device_state.sections != 0
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
      ",\"diagnostic_extended_fnv\":\"%016" PRIx64 "\""
      ",\"ram_bytes\":%" PRIu64
      ",\"memory_events\":%" PRIu64
      ",\"io_events\":%" PRIu64
      ",\"memory_events_enabled\":%s"
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      ",\"device_state_failures\":%" PRIu64
      ",\"trajectory_digest_failures\":%" PRIu64
      "}\n",
      capture_memory_events ? "true" : "false",
      diagnostic_extended_fnv,
      ram_bytes,
      memory_events,
      io_events,
      capture_memory_events ? "true" : "false",
      register_digests.sample_failures,
      register_read_failures,
      device_state_failures,
      trajectory_digest_failures);
  fflush(trace_file);
}

static void
record_rr_switch_event(void)
{
  if (trace_file == NULL || !extended_fingerprint || !trace_rr_switch_events) {
    return;
  }

  uint64_t rr_current_vcpu;
  uint64_t rr_cursor_position;
  uint64_t rr_switch_quantum;

  if (!read_rr_cursor_snapshot(
          &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum)) {
    rr_switch_trace_initialized = false;
    last_rr_current_vcpu = UINT64_MAX;
    last_rr_cursor_position = UINT64_MAX;
    last_rr_switch_quantum = 0;
    return;
  }

  if (rr_current_vcpu == UINT64_MAX || rr_current_vcpu >= tracked_vcpus) {
    return;
  }

  if (!rr_switch_trace_initialized) {
    rr_switch_trace_initialized = true;
    last_rr_current_vcpu = rr_current_vcpu;
    last_rr_cursor_position = rr_cursor_position;
    last_rr_switch_quantum = rr_switch_quantum;
    return;
  }

  if (rr_current_vcpu == last_rr_current_vcpu) {
    last_rr_cursor_position = rr_cursor_position;
    last_rr_switch_quantum = rr_switch_quantum;
    return;
  }

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
      retired,
      last_rr_current_vcpu,
      rr_current_vcpu,
      rr_cursor_position,
      last_rr_switch_quantum,
      rr_switch_quantum);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s%" PRIu64,
        vcpu == 0 ? "" : ",",
        per_vcpu_retired[vcpu]);
  }

  fprintf(trace_file, "],\"per_vcpu_delta\":[");
  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    const uint64_t delta =
        per_vcpu_retired[vcpu] - last_switch_per_vcpu_retired[vcpu];
    fprintf(trace_file, "%s%" PRIu64, vcpu == 0 ? "" : ",", delta);
    last_switch_per_vcpu_retired[vcpu] = per_vcpu_retired[vcpu];
  }

  fprintf(trace_file, "]}\n");
  fflush(trace_file);
  last_rr_current_vcpu = rr_current_vcpu;
  last_rr_cursor_position = rr_cursor_position;
  last_rr_switch_quantum = rr_switch_quantum;
}

static void
maybe_command_det_ipi_probe(
    uint64_t delivery_icount,
    unsigned int dst_vcpu,
    unsigned int delivery_mode)
{
  const unsigned int target_vcpu = dst_vcpu == 0 ? 1 : 0;

  if (!det_ipi_probe || det_ipi_probe_commanded || tracked_vcpus < 2 ||
      delivery_mode != 6 || dst_vcpu >= tracked_vcpus ||
      target_vcpu >= tracked_vcpus) {
    return;
  }

  if (qemu_plugin_inject_preemption(
          delivery_icount,
          delivery_icount,
          UINT64_MAX,
          QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT,
          target_vcpu,
          0x51,
          0) == 0) {
    det_ipi_probe_commanded = true;
  }
}

static void
on_det_ipi_delivery(
    uint64_t event_id,
    uint64_t delivery_icount,
    unsigned int src_vcpu,
    unsigned int dst_vcpu,
    unsigned int delivery_mode,
    unsigned int vector,
    void *userdata)
{
  (void)userdata;

  det_ipi_events++;
  if (trace_file == NULL || !extended_fingerprint) {
    return;
  }

  fprintf(
      trace_file,
      "{\"kind\":\"det_ipi\""
      ",\"det_ipi_event\":%" PRIu64
      ",\"event_id\":%" PRIu64
      ",\"retired\":%" PRIu64
      ",\"delivery_icount\":%" PRIu64
      ",\"src_vcpu\":%u"
      ",\"dst_vcpu\":%u"
      ",\"delivery_mode\":%u"
      ",\"vector\":%u"
      "}\n",
      det_ipi_events,
      event_id,
      retired,
      delivery_icount,
      src_vcpu,
      dst_vcpu,
      delivery_mode,
      vector);
  fflush(trace_file);

  maybe_command_det_ipi_probe(delivery_icount, dst_vcpu, delivery_mode);
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
  if (post_boundary_samples || terminal_horizon) {
    memory_event_hash = fnv1a_u64(memory_event_hash, memory_events);
    memory_event_hash = fnv1a_u64(memory_event_hash, event_hash);
    if (post_boundary_samples && required_pc_seen &&
        trajectory_digest_failures == 0 &&
        !advance_memory_event_digest(
          memory_event_digest,
          "crucible.qemu.memory-event-trajectory.v1",
          memory_events,
          vcpu_index,
          vaddr,
          phys_addr,
          info,
          is_store,
          is_io,
          value)) {
      trajectory_digest_failures++;
    }
  }
  if (!is_io) {
    return;
  }

  io_events++;
  device_event_hash = fnv1a_u64(device_event_hash, io_events);
  device_event_hash = fnv1a_u64(device_event_hash, event_hash);
  if (post_boundary_samples && required_pc_seen &&
      trajectory_digest_failures == 0 &&
      !advance_memory_event_digest(
        device_event_digest,
        "crucible.qemu.device-event-trajectory.v1",
        io_events,
        vcpu_index,
        vaddr,
        phys_addr,
        info,
        is_store,
        true,
        value)) {
    trajectory_digest_failures++;
  }
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;
  bool sampled_this_instruction = false;
  bool reached_stop = false;

  retired++;
  if (vcpu_index < MAX_TRACKED_VCPUS) {
    per_vcpu_retired[vcpu_index]++;
  }
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);
  if (!required_pc_seen && insn->vaddr == required_pc) {
    required_pc_seen = true;
    required_pc_first_retired = retired;
  }
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
  record_rr_switch_event();

  if (post_boundary_samples && required_pc_seen) {
    const struct register_digest_summary register_digests =
        compute_register_digests();
    const bool rr_cursor_valid = rr_current_vcpu != UINT64_MAX;
    fold_trajectory_state(
        retired,
        vcpu_index,
        &register_digests,
        NULL,
        insn,
        rr_current_vcpu,
        rr_cursor_position,
        rr_switch_quantum,
        rr_cursor_valid,
        false);
  }

  reached_stop = stop_at != 0 && retired >= stop_at && !stop_requested;
  if (reached_stop) {
    stop_requested = true;
  }

  if (!extended_fingerprint && retired >= next_sample) {
    record_sample(vcpu_index, false);
    sampled_this_instruction = true;
    next_sample += cadence;
  }
  if (reached_stop) {
    if (!extended_fingerprint && !sampled_this_instruction) {
      record_sample(vcpu_index, false);
    }
    qemu_plugin_outs("crucible-qemu-trace-plugin: stop_at reached\n");
  }
}

static void
on_final_sample_paused(int status, void *userdata)
{
  (void)userdata;

  if (final_sample_emitted) {
    return;
  }
  if (status != 0) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: final sample pause failed\n");
    qemu_plugin_request_shutdown(1);
    return;
  }

  /*
   * Canonical register export is admitted only after every vCPU is stopped
   * under QEMU's serialized boundary. Process-exit callbacks do not own that
   * boundary and therefore cannot serve as final architectural evidence.
   */
  record_sample(UINT_MAX, true);
  final_sample_emitted = true;
}

static void
on_sim_observe_icount(uint64_t current_icount, void *userdata)
{
  (void)userdata;

  const bool horizon_due =
      stop_at != 0 && !horizon_emitted && current_icount >= stop_at;

  if (terminal_horizon) {
    int status;

    if (!horizon_due) {
      return;
    }
    stop_requested = true;
    horizon_emitted = true;
    next_sample = UINT64_MAX;
    terminal_observed_icount = current_icount;
    if (!horizon_due || current_icount != stop_at) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: terminal horizon boundary was not exact\n");
      terminal_pause_status = -ERANGE;
      const int vmstop_status = request_exact_vmstop();

      on_terminal_paused(
          vmstop_status == 0 ? terminal_pause_status : vmstop_status, NULL);
      return;
    }

    terminal_pause_requested = true;
    status = qemu_plugin_crucible_request_terminal_pause(
        on_terminal_paused, NULL);
    if (status != 0) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: terminal pause request failed\n");
      terminal_pause_status = status;
      const int vmstop_status = request_exact_vmstop();

      on_terminal_paused(vmstop_status == 0 ? status : vmstop_status, NULL);
    }
    return;
  }

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

  if (post_boundary_samples) {
    const struct register_digest_summary register_digests =
        compute_register_digests();
    unsigned char ram_digest[32] = {0};
    uint64_t ram_bytes = 0;
    const int ram_status =
        qemu_plugin_crucible_guest_ram_sha256(ram_digest, &ram_bytes);
    uint64_t rr_current_vcpu;
    uint64_t rr_cursor_position;
    uint64_t rr_switch_quantum;
    const bool rr_cursor_valid = read_rr_cursor_snapshot(
        &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum);

    fold_trajectory_state(
        current_icount,
        UINT_MAX,
        &register_digests,
        ram_status == 0 ? ram_digest : NULL,
        NULL,
        rr_current_vcpu,
        rr_cursor_position,
        rr_switch_quantum,
        rr_cursor_valid,
        true);
  }

  const bool rr_cursor_required =
      tracked_vcpus > 1 || qemu_plugin_crucible_rr_switch_quantum() != 0;
  if (!boundary_rr_cursor_valid && rr_cursor_required) {
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
    terminal_pause_requested = true;
    const int status = qemu_plugin_crucible_request_terminal_pause(
        on_final_sample_paused, NULL);

    if (status != 0) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: final sample pause request failed\n");
      qemu_plugin_request_shutdown(1);
    }
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
        qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS, insn);
    if (extended_fingerprint && capture_memory_events) {
      qemu_plugin_register_vcpu_mem_cb(
          qinsn, on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);
    }
  }
}

static void
on_definition_paused(int status, void *userdata)
{
  (void)userdata;

  definition_callback_completed = true;
  definition_pause_status = status;
  if (status != 0) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: genesis pause callback failed\n");
    qemu_plugin_request_shutdown(1);
    return;
  }

  record_definition();
  if (!definition_emitted) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: genesis definition was incomplete\n");
    qemu_plugin_request_shutdown(1);
  }
}

static void
on_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
  (void)id;

  if (extended_fingerprint) {
    (void)init_register_set(vcpu_index);
  }
  if (definition_only && !definition_pause_requested &&
      all_register_sets_initialized()) {
    definition_pause_requested = true;
    const int status = qemu_plugin_crucible_request_terminal_pause(
        on_definition_paused, NULL);

    if (status != 0) {
      definition_pause_status = status;
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: genesis pause request failed\n");
      qemu_plugin_request_shutdown(1);
    }
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

  if (terminal_horizon) {
    if (!terminal_final_emitted) {
      terminal_observed_icount = qemu_plugin_crucible_icount();
      record_terminal_final();
    }
  } else if (definition_only) {
    if (!definition_emitted) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: definition record was not emitted\n");
    }
  } else if (stop_at == 0) {
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

static bool
digest_is_zero(const unsigned char digest[32])
{
  for (size_t i = 0; i < 32; i++) {
    if (digest[i] != 0) {
      return false;
    }
  }
  return true;
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
    } else if (strncmp(argv[i], "extended=", 9) == 0) {
      extended_fingerprint = parse_bool_flag(argv[i] + 9);
    } else if (strncmp(argv[i], "terminal_horizon=", 17) == 0) {
      terminal_horizon = parse_bool_flag(argv[i] + 17);
    } else if (strncmp(argv[i], "definition_only=", 16) == 0) {
      definition_only = parse_bool_flag(argv[i] + 16);
    } else if (strncmp(argv[i], "mem_events=", 11) == 0) {
      capture_memory_events = parse_bool_flag(argv[i] + 11);
    } else if (strncmp(argv[i], "post_boundary=", 14) == 0) {
      post_boundary_samples = parse_bool_flag(argv[i] + 14);
    } else if (strncmp(argv[i], "required_pc=", 12) == 0) {
      if (!parse_u64(argv[i] + 12, &required_pc)) {
        qemu_plugin_outs("crucible-qemu-trace-plugin: invalid required_pc\n");
        return -1;
      }
    } else if (strncmp(argv[i], "rr_switch_events=", 17) == 0) {
      trace_rr_switch_events = parse_bool_flag(argv[i] + 17);
    } else if (strncmp(argv[i], "det_ipi_probe=", 14) == 0) {
      det_ipi_probe = parse_bool_flag(argv[i] + 14);
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

  if (definition_only) {
    extended_fingerprint = true;
    if (stop_at != 0 || post_boundary_samples || det_ipi_probe) {
      qemu_plugin_outs(
          "crucible-qemu-trace-plugin: definition-only mode cannot execute or schedule guest boundaries\n");
      return -1;
    }
  }

  if (terminal_horizon &&
      (!extended_fingerprint || !capture_memory_events || stop_at == 0 ||
       definition_only || post_boundary_samples || det_ipi_probe)) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: terminal horizon requires dedicated extended memory-event capture with nonzero stop_at\n");
    return -1;
  }

  if (post_boundary_samples &&
      (!extended_fingerprint || !capture_memory_events || required_pc == UINT64_MAX)) {
    qemu_plugin_outs(
        "crucible-qemu-trace-plugin: post-boundary sampling requires extended memory-event capture and required_pc\n");
    return -1;
  }

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: failed to open trace file\n");
    return -1;
  }

  qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
  if (!definition_only) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
    qemu_plugin_crucible_register_ipi_delivery_cb(on_det_ipi_delivery, NULL);
    qemu_plugin_register_sim_shmem_observer_cb(
        on_sim_observe_icount, on_sim_observer_max_advance_icount, NULL);
    if (det_ipi_probe) {
      qemu_plugin_register_sim_shmem_dispatch_cb(
          on_sim_publish_icount, on_sim_max_advance_icount, NULL);
    }
  }
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
