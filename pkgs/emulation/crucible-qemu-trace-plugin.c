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
#define MAX_TRACKED_VCPUS 256U

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

struct register_hash_summary {
  uint64_t aggregate;
  uint64_t per_vcpu[MAX_TRACKED_VCPUS];
  uint64_t register_counts[MAX_TRACKED_VCPUS];
  uint64_t sample_failures;
};

static FILE *trace_file;
static uint64_t cadence = 100000;
static uint64_t next_sample = 100000;
static uint64_t stop_at;
static uint64_t retired;
static uint64_t stream_hash = FNV1A64_OFFSET;
static uint64_t device_event_xor;
static uint64_t device_event_sum;
static uint64_t memory_events;
static uint64_t io_events;
static uint64_t register_read_failures;
static bool extended_fingerprint;
static bool capture_memory_events;
static bool trace_rr_switch_events = true;
static bool det_ipi_probe;
static bool det_ipi_probe_commanded;
static bool stop_requested;
static unsigned int tracked_vcpus = 1;
static struct register_set register_sets[MAX_TRACKED_VCPUS];
static uint64_t per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t last_switch_per_vcpu_retired[MAX_TRACKED_VCPUS];
static uint64_t last_rr_current_vcpu = UINT64_MAX;
static uint64_t last_rr_cursor_position = UINT64_MAX;
static uint64_t rr_switch_events;
static uint64_t det_ipi_events;
static bool rr_switch_trace_initialized;

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
  uint64_t hash = FNV1A64_OFFSET;

  hash = fnv1a_u64(hash, device_event_xor);
  hash = fnv1a_u64(hash, device_event_sum);
  hash = fnv1a_u64(hash, io_events);
  return hash;
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

static uint64_t
hash_registers_for_vcpu(uint64_t hash, unsigned int vcpu_index, uint64_t *failures)
{
  unsigned char canonical_registers[4096];
  size_t canonical_register_len = 0;
  uint64_t canonical_retired = 0;

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

  const int canonical_status = qemu_plugin_read_vcpu_regs(
      vcpu_index,
      canonical_registers,
      sizeof(canonical_registers),
      &canonical_register_len,
      &canonical_retired);
  if (canonical_status != 0 || canonical_register_len == 0 ||
      canonical_register_len > sizeof(canonical_registers)) {
    *failures += 1;
    hash = fnv1a_u64(hash, UINT64_MAX - 2U);
  } else {
    hash = fnv1a_u64(hash, canonical_register_len);
    hash = fnv1a_bytes(hash, canonical_registers, canonical_register_len);
    hash = fnv1a_u64(hash, canonical_retired);
  }

  return hash;
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

static struct register_hash_summary
compute_register_hash(void)
{
  struct register_hash_summary summary = {
      .aggregate = FNV1A64_OFFSET,
      .sample_failures = 0,
  };

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    uint64_t failures = 0;
    const uint64_t per_vcpu_hash =
        hash_registers_for_vcpu(FNV1A64_OFFSET, vcpu, &failures);

    summary.per_vcpu[vcpu] = per_vcpu_hash;
    summary.register_counts[vcpu] =
        register_sets[vcpu].initialized ? register_sets[vcpu].count : 0;
    summary.sample_failures += failures;
    summary.aggregate = fnv1a_u64(summary.aggregate, vcpu);
    summary.aggregate = fnv1a_u64(summary.aggregate, per_vcpu_hash);
  }

  register_read_failures += summary.sample_failures;
  return summary;
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

  const struct register_hash_summary register_hashes = compute_register_hash();
  uint64_t ram_bytes = 0;
  const uint64_t ram_hash = qemu_plugin_crucible_ram_hash(&ram_bytes);
  uint64_t rr_current_vcpu;
  uint64_t rr_cursor_position;
  uint64_t rr_switch_quantum;
  const uint64_t device_component_hash =
      capture_memory_events ? current_device_event_hash() : 0;
  uint64_t extended_hash = FNV1A64_OFFSET;

  const bool rr_cursor_valid = read_rr_cursor_snapshot(
      &rr_current_vcpu, &rr_cursor_position, &rr_switch_quantum);

  extended_hash = fnv1a_u64(extended_hash, stream_hash);
  extended_hash = fnv1a_u64(extended_hash, register_hashes.aggregate);
  extended_hash = fnv1a_u64(extended_hash, ram_hash);
  extended_hash = fnv1a_u64(extended_hash, capture_memory_events ? 1U : 0U);
  extended_hash = fnv1a_u64(extended_hash, device_component_hash);
  extended_hash = fnv1a_u64(extended_hash, rr_current_vcpu);
  extended_hash = fnv1a_u64(extended_hash, rr_cursor_position);
  extended_hash = fnv1a_u64(extended_hash, rr_switch_quantum);
  extended_hash = fnv1a_u64(extended_hash, rr_cursor_valid ? 1U : 0U);
  extended_hash = fnv1a_u64(extended_hash, tracked_vcpus);
  extended_hash = fnv1a_u64(extended_hash, stop_at);

  fprintf(
      trace_file,
      "{\"retired\":%" PRIu64
      ",\"vcpu\":%u"
      ",\"final\":%s"
      ",\"tracked_vcpus\":%u"
      ",\"stop_at\":%" PRIu64
      ",\"stop_requested\":%s"
      ",\"rr_current_vcpu\":%" PRIu64
      ",\"rr_cursor_position\":%" PRIu64
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"rr_cursor_valid\":%s"
      ",\"stream_hash\":\"%016" PRIx64 "\""
      ",\"register_hash\":\"%016" PRIx64 "\""
      ",\"register_hashes\":[",
      retired,
      vcpu_index,
      final ? "true" : "false",
      tracked_vcpus,
      stop_at,
      stop_requested ? "true" : "false",
      rr_current_vcpu,
      rr_cursor_position,
      rr_switch_quantum,
      rr_cursor_valid ? "true" : "false",
      stream_hash,
      register_hashes.aggregate);

  for (unsigned int vcpu = 0; vcpu < tracked_vcpus; vcpu++) {
    fprintf(
        trace_file,
        "%s\"%016" PRIx64 "\"",
        vcpu == 0 ? "" : ",",
        register_hashes.per_vcpu[vcpu]);
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
        register_hashes.register_counts[vcpu]);
  }

  fprintf(trace_file, "]" ",\"ram_hash\":\"%016" PRIx64 "\"", ram_hash);
  if (capture_memory_events) {
    fprintf(
        trace_file,
        ",\"device_event_hash\":\"%016" PRIx64 "\"",
        device_component_hash);
  } else {
    fprintf(trace_file, ",\"device_event_hash\":null");
  }
  fprintf(
      trace_file,
      ",\"device_event_capture\":%s"
      ",\"extended_hash\":\"%016" PRIx64 "\""
      ",\"ram_bytes\":%" PRIu64
      ",\"memory_events\":%" PRIu64
      ",\"io_events\":%" PRIu64
      ",\"memory_events_enabled\":%s"
      ",\"sample_register_failures\":%" PRIu64
      ",\"register_read_failures\":%" PRIu64
      "}\n",
      capture_memory_events ? "true" : "false",
      extended_hash,
      ram_bytes,
      memory_events,
      io_events,
      capture_memory_events ? "true" : "false",
      register_hashes.sample_failures,
      register_read_failures);
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
    return;
  }

  if (rr_current_vcpu == UINT64_MAX || rr_current_vcpu >= tracked_vcpus) {
    return;
  }

  if (!rr_switch_trace_initialized) {
    rr_switch_trace_initialized = true;
    last_rr_current_vcpu = rr_current_vcpu;
    last_rr_cursor_position = rr_cursor_position;
    return;
  }

  if (rr_current_vcpu == last_rr_current_vcpu &&
      rr_cursor_position >= last_rr_cursor_position) {
    last_rr_cursor_position = rr_cursor_position;
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
      ",\"rr_switch_quantum\":%" PRIu64
      ",\"per_vcpu_retired\":[",
      rr_switch_events,
      retired,
      last_rr_current_vcpu,
      rr_current_vcpu,
      rr_cursor_position,
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

  memory_events++;
  if (is_io) {
    io_events++;
  } else {
    return;
  }

  uint64_t event_hash = FNV1A64_OFFSET;

  event_hash = fnv1a_u64(event_hash, vcpu_index);
  event_hash = fnv1a_u64(event_hash, vaddr);
  event_hash = fnv1a_u64(event_hash, phys_addr);
  event_hash = fnv1a_u64(event_hash, qemu_plugin_mem_size_shift(info));
  const bool is_store = qemu_plugin_mem_is_store(info);
  event_hash = fnv1a_u64(event_hash, is_store ? 1U : 0U);
  event_hash = fnv1a_u64(event_hash, is_io ? 1U : 0U);
  if (is_store) {
    event_hash = hash_mem_value(event_hash, qemu_plugin_mem_get_value(info));
  } else {
    event_hash = fnv1a_u64(event_hash, UINT64_MAX);
  }
  device_event_xor ^= event_hash;
  device_event_sum += event_hash;
}

static void
on_insn(unsigned int vcpu_index, void *userdata)
{
  const struct traced_insn *insn = userdata;
  bool sampled_this_instruction = false;

  retired++;
  if (vcpu_index < MAX_TRACKED_VCPUS) {
    per_vcpu_retired[vcpu_index]++;
  }
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)vcpu_index);
  stream_hash = fnv1a_u64(stream_hash, insn->vaddr);
  stream_hash = fnv1a_u64(stream_hash, (uint64_t)insn->size);
  stream_hash = fnv1a_bytes(stream_hash, insn->bytes, insn->size);
  record_rr_switch_event();

  if (retired >= next_sample) {
    record_sample(vcpu_index, false);
    sampled_this_instruction = true;
    next_sample += cadence;
  }
  if (stop_at != 0 && retired >= stop_at && !stop_requested) {
    if (!sampled_this_instruction) {
      record_sample(vcpu_index, false);
    }
    stop_requested = true;
    qemu_plugin_outs("crucible-qemu-trace-plugin: stop_at reached\n");
    qemu_plugin_crucible_pause_vm();
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
    if (extended_fingerprint && capture_memory_events) {
      qemu_plugin_register_vcpu_mem_cb(
          qinsn, on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);
    }
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

  if (trace_file == NULL) {
    return;
  }

  record_sample(UINT_MAX, true);
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
    } else if (strncmp(argv[i], "mem_events=", 11) == 0) {
      capture_memory_events = parse_bool_flag(argv[i] + 11);
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

  trace_file = fopen(out_path, "w");
  if (trace_file == NULL) {
    qemu_plugin_outs("crucible-qemu-trace-plugin: failed to open trace file\n");
    return -1;
  }

  qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
  qemu_plugin_crucible_register_ipi_delivery_cb(on_det_ipi_delivery, NULL);
  if (det_ipi_probe) {
    qemu_plugin_register_sim_shmem_dispatch_cb(
        on_sim_publish_icount, on_sim_max_advance_icount, NULL);
  }
  qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
  return 0;
}
