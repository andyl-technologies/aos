#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
  SOURCE_COUNT = 2,
  FRAMES_PER_SOURCE = 16,
  TOTAL_FRAMES = SOURCE_COUNT * FRAMES_PER_SOURCE,
  RING_CAPACITY = 64,
  MAX_FRAME_DATA = 32,
  FIRST_DELIVERY_ICOUNT = 1000,
  DELIVERY_STEP_ICOUNT = 100,
  MAX_WAIT_POLLS = 200000
};

enum run_mode {
  RUN_PRODUCER_SKEW = 0,
  RUN_CONSUMER_SKEW = 1
};

struct ring_header {
  atomic_uint_fast64_t read_idx;
  unsigned char pad_read[56];
  atomic_uint_fast64_t write_idx;
  unsigned char pad_write[56];
};

struct frame_entry {
  uint64_t delivery_icount;
  uint32_t src_node;
  uint32_t seq;
  uint16_t len;
  unsigned char pad[6];
  unsigned char data[MAX_FRAME_DATA];
};

struct ring_slot {
  struct frame_entry frame;
  uint32_t publish_order;
};

struct ring {
  struct ring_header header;
  struct ring_slot entries[RING_CAPACITY];
};

struct expected_frame {
  uint64_t delivery_icount;
  uint32_t src_node;
  uint32_t seq;
  unsigned int ring_index;
};

struct delivery_record {
  uint64_t delivery_icount;
  uint64_t visible_icount;
  uint32_t src_node;
  uint32_t seq;
  uint32_t payload_hash;
  uint32_t publish_order;
};

struct shared_run {
  atomic_int start;
  atomic_int failed;
  atomic_uint producers_done;
  atomic_uint publish_counter;
  atomic_uint_fast64_t consumer_current_icount;
  atomic_uint ceiling_wait_observed;
  atomic_uint early_peek_observed;
  char error[256];
  struct ring rings[SOURCE_COUNT];
  struct delivery_record records[TOTAL_FRAMES];
};

static uint64_t
delivery_for_seq(uint32_t seq)
{
  return FIRST_DELIVERY_ICOUNT + ((uint64_t)seq / 2U) * DELIVERY_STEP_ICOUNT;
}

static uint32_t
src_node_for_ring(unsigned int ring_index)
{
  return (uint32_t)ring_index + 1U;
}

static void
sleep_us(unsigned int usec)
{
  struct timespec ts = {
      .tv_sec = usec / 1000000U,
      .tv_nsec = (long)(usec % 1000000U) * 1000L,
  };

  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

static uint32_t
payload_hash(const struct frame_entry *entry)
{
  uint32_t hash = 2166136261U;

  for (uint16_t i = 0; i < entry->len; i++) {
    hash ^= entry->data[i];
    hash *= 16777619U;
  }

  return hash;
}

static void
set_error(struct shared_run *run, const char *message)
{
  int expected = 0;
  if (atomic_compare_exchange_strong(&run->failed, &expected, 1)) {
    snprintf(run->error, sizeof(run->error), "%s", message);
  }
}

static int
compare_expected(const void *left_ptr, const void *right_ptr)
{
  const struct expected_frame *left = left_ptr;
  const struct expected_frame *right = right_ptr;

  if (left->delivery_icount < right->delivery_icount) {
    return -1;
  }
  if (left->delivery_icount > right->delivery_icount) {
    return 1;
  }
  if (left->src_node < right->src_node) {
    return -1;
  }
  if (left->src_node > right->src_node) {
    return 1;
  }
  if (left->seq < right->seq) {
    return -1;
  }
  if (left->seq > right->seq) {
    return 1;
  }

  return 0;
}

static void
build_expected(struct expected_frame expected[TOTAL_FRAMES])
{
  size_t pos = 0;

  for (unsigned int ring = 0; ring < SOURCE_COUNT; ring++) {
    for (uint32_t seq = 0; seq < FRAMES_PER_SOURCE; seq++) {
      expected[pos++] = (struct expected_frame){
          .delivery_icount = delivery_for_seq(seq),
          .src_node = src_node_for_ring(ring),
          .seq = seq,
          .ring_index = ring,
      };
    }
  }

  qsort(expected, TOTAL_FRAMES, sizeof(expected[0]), compare_expected);
}

static bool
entry_matches_expected(const struct frame_entry *entry, const struct expected_frame *expected)
{
  return entry->delivery_icount == expected->delivery_icount &&
         entry->src_node == expected->src_node &&
         entry->seq == expected->seq;
}

static bool
ring_peek_at(const struct ring *ring, uint64_t offset, struct ring_slot *slot)
{
  const uint64_t head = atomic_load_explicit(&ring->header.read_idx, memory_order_relaxed);
  const uint64_t tail = atomic_load_explicit(&ring->header.write_idx, memory_order_acquire);

  if (tail - head <= offset) {
    return false;
  }

  *slot = ring->entries[(head + offset) & (RING_CAPACITY - 1U)];
  return true;
}

static bool
ring_dequeue(struct ring *ring, struct ring_slot *slot)
{
  const uint64_t head = atomic_load_explicit(&ring->header.read_idx, memory_order_relaxed);
  const uint64_t tail = atomic_load_explicit(&ring->header.write_idx, memory_order_acquire);

  if (tail == head) {
    return false;
  }

  *slot = ring->entries[head & (RING_CAPACITY - 1U)];
  atomic_store_explicit(&ring->header.read_idx, head + 1U, memory_order_release);
  return true;
}

static bool
ring_enqueue(struct ring *ring, const struct ring_slot *slot)
{
  const uint64_t tail = atomic_load_explicit(&ring->header.write_idx, memory_order_relaxed);
  const uint64_t head = atomic_load_explicit(&ring->header.read_idx, memory_order_acquire);

  if (tail - head >= RING_CAPACITY) {
    return false;
  }

  ring->entries[tail & (RING_CAPACITY - 1U)] = *slot;
  atomic_store_explicit(&ring->header.write_idx, tail + 1U, memory_order_release);
  return true;
}

static bool
guarded_enqueue(
    struct shared_run *run,
    unsigned int ring_index,
    const struct ring_slot *slot)
{
  const uint64_t current =
      atomic_load_explicit(&run->consumer_current_icount, memory_order_acquire);

  if (current >= slot->frame.delivery_icount) {
    set_error(run, "late enqueue: consumer has already reached delivery icount");
    return false;
  }

  while (!ring_enqueue(&run->rings[ring_index], slot)) {
    if (atomic_load(&run->failed) != 0) {
      return false;
    }
    sleep_us(50);
  }

  return true;
}

static void
fill_frame(struct frame_entry *entry, unsigned int ring_index, uint32_t seq)
{
  memset(entry, 0, sizeof(*entry));
  entry->delivery_icount = delivery_for_seq(seq);
  entry->src_node = src_node_for_ring(ring_index);
  entry->seq = seq;
  entry->len = 8;
  entry->data[0] = (unsigned char)entry->src_node;
  entry->data[1] = (unsigned char)seq;
  entry->data[2] = (unsigned char)(entry->delivery_icount & 0xffU);
  entry->data[3] = (unsigned char)((entry->delivery_icount >> 8U) & 0xffU);
  entry->data[4] = 0x53;
  entry->data[5] = 0x34;
  entry->data[6] = 0xc0;
  entry->data[7] = 0xde;
}

static unsigned int
producer_delay_us(enum run_mode mode, unsigned int ring_index, uint32_t seq)
{
  if (mode == RUN_CONSUMER_SKEW) {
    return 20U + (ring_index * 10U);
  }

  if (ring_index == 0) {
    return 700U + (seq % 3U) * 120U;
  }

  return 80U + (seq % 2U) * 40U;
}

static void
producer_main(struct shared_run *run, enum run_mode mode, unsigned int ring_index)
{
  while (atomic_load_explicit(&run->start, memory_order_acquire) == 0) {
    sleep_us(50);
  }

  for (uint32_t seq = 0; seq < FRAMES_PER_SOURCE; seq++) {
    struct ring_slot slot;
    memset(&slot, 0, sizeof(slot));
    slot.publish_order =
        atomic_fetch_add_explicit(&run->publish_counter, 1U, memory_order_acq_rel) + 1U;
    fill_frame(&slot.frame, ring_index, seq);
    sleep_us(producer_delay_us(mode, ring_index, seq));

    if (!guarded_enqueue(run, ring_index, &slot)) {
      _exit(2);
    }
  }

  atomic_fetch_add_explicit(&run->producers_done, 1U, memory_order_acq_rel);
  _exit(0);
}

static bool
group_ready(
    struct shared_run *run,
    const struct expected_frame expected[TOTAL_FRAMES],
    size_t group_start,
    size_t group_end)
{
  uint64_t offsets[SOURCE_COUNT] = {0};

  for (size_t i = group_start; i < group_end; i++) {
    struct ring_slot slot;
    const unsigned int ring_index = expected[i].ring_index;

    if (!ring_peek_at(&run->rings[ring_index], offsets[ring_index], &slot)) {
      return false;
    }
    if (!entry_matches_expected(&slot.frame, &expected[i])) {
      set_error(run, "ring head does not match deterministic delivery order");
      return false;
    }
    offsets[ring_index]++;
  }

  return true;
}

static void
observe_future_head(struct shared_run *run, uint64_t current_icount)
{
  for (unsigned int ring = 0; ring < SOURCE_COUNT; ring++) {
    struct ring_slot slot;
    if (ring_peek_at(&run->rings[ring], 0, &slot) &&
        slot.frame.delivery_icount > current_icount) {
      atomic_store(&run->early_peek_observed, 1U);
    }
  }
}

static void
consumer_main(
    struct shared_run *run,
    enum run_mode mode,
    const struct expected_frame expected[TOTAL_FRAMES])
{
  size_t delivered = 0;
  uint64_t current_icount = 0;

  while (atomic_load_explicit(&run->start, memory_order_acquire) == 0) {
    sleep_us(50);
  }

  while (delivered < TOTAL_FRAMES && atomic_load(&run->failed) == 0) {
    const size_t group_start = delivered;
    const uint64_t delivery_icount = expected[group_start].delivery_icount;
    size_t group_end = group_start + 1U;
    unsigned int wait_polls = 0;

    while (group_end < TOTAL_FRAMES &&
           expected[group_end].delivery_icount == delivery_icount) {
      group_end++;
    }

    if (mode == RUN_CONSUMER_SKEW) {
      sleep_us(1800U + (unsigned int)(group_start * 11U));
    }

    current_icount = delivery_icount - 1U;
    atomic_store_explicit(
        &run->consumer_current_icount, current_icount, memory_order_release);
    observe_future_head(run, current_icount);

    while (!group_ready(run, expected, group_start, group_end)) {
      if (atomic_load(&run->failed) != 0) {
        _exit(2);
      }
      atomic_store(&run->ceiling_wait_observed, 1U);
      if (++wait_polls > MAX_WAIT_POLLS) {
        set_error(run, "timed out waiting at delivery ceiling");
        _exit(2);
      }
      sleep_us(50);
    }

    current_icount = delivery_icount;
    atomic_store_explicit(
        &run->consumer_current_icount, current_icount, memory_order_release);

    for (size_t i = group_start; i < group_end; i++) {
      struct ring_slot slot;
      if (!ring_dequeue(&run->rings[expected[i].ring_index], &slot)) {
        set_error(run, "ready frame disappeared before dequeue");
        _exit(2);
      }
      if (!entry_matches_expected(&slot.frame, &expected[i])) {
        set_error(run, "dequeued frame violates deterministic order");
        _exit(2);
      }
      if (slot.publish_order == 0) {
        set_error(run, "released frame slot has no publish order");
        _exit(2);
      }

      run->records[delivered++] = (struct delivery_record){
          .delivery_icount = slot.frame.delivery_icount,
          .visible_icount = current_icount,
          .src_node = slot.frame.src_node,
          .seq = slot.frame.seq,
          .payload_hash = payload_hash(&slot.frame),
          .publish_order = slot.publish_order,
      };
    }
  }

  _exit(atomic_load(&run->failed) == 0 ? 0 : 2);
}

static bool
records_match(const struct delivery_record left[TOTAL_FRAMES],
              const struct delivery_record right[TOTAL_FRAMES])
{
  for (size_t i = 0; i < TOTAL_FRAMES; i++) {
    if (left[i].delivery_icount != right[i].delivery_icount ||
        left[i].visible_icount != right[i].visible_icount ||
        left[i].src_node != right[i].src_node ||
        left[i].seq != right[i].seq ||
        left[i].payload_hash != right[i].payload_hash) {
      return false;
    }
  }

  return true;
}

static bool
records_follow_expected(
    const struct delivery_record records[TOTAL_FRAMES],
    const struct expected_frame expected[TOTAL_FRAMES])
{
  for (size_t i = 0; i < TOTAL_FRAMES; i++) {
    if (records[i].delivery_icount != expected[i].delivery_icount ||
        records[i].visible_icount != expected[i].delivery_icount ||
        records[i].src_node != expected[i].src_node ||
        records[i].seq != expected[i].seq) {
      return false;
    }
  }

  return true;
}

static bool
arrival_order_differs(const struct delivery_record records[TOTAL_FRAMES])
{
  for (size_t i = 0; i < TOTAL_FRAMES; i++) {
    for (size_t j = i + 1U; j < TOTAL_FRAMES; j++) {
      if (records[i].delivery_icount == records[j].delivery_icount &&
          records[i].publish_order > records[j].publish_order) {
        return true;
      }
    }
  }

  return false;
}

static bool
publish_orders_unique_nonzero(const struct delivery_record records[TOTAL_FRAMES])
{
  bool seen[TOTAL_FRAMES + 1U] = {false};

  for (size_t i = 0; i < TOTAL_FRAMES; i++) {
    if (records[i].publish_order == 0 || records[i].publish_order > TOTAL_FRAMES) {
      return false;
    }
    if (seen[records[i].publish_order]) {
      return false;
    }
    seen[records[i].publish_order] = true;
  }

  return true;
}

static bool
arrival_order_negative_control_fails(const struct delivery_record records[TOTAL_FRAMES])
{
  struct delivery_record arrival_order[TOTAL_FRAMES];
  memcpy(arrival_order, records, sizeof(arrival_order));

  for (size_t i = 1; i < TOTAL_FRAMES; i++) {
    struct delivery_record key = arrival_order[i];
    size_t j = i;
    while (j > 0 && arrival_order[j - 1U].publish_order > key.publish_order) {
      arrival_order[j] = arrival_order[j - 1U];
      j--;
    }
    arrival_order[j] = key;
  }

  for (size_t i = 0; i < TOTAL_FRAMES; i++) {
    if (arrival_order[i].delivery_icount != records[i].delivery_icount ||
        arrival_order[i].src_node != records[i].src_node ||
        arrival_order[i].seq != records[i].seq) {
      return true;
    }
  }

  return false;
}

static bool
late_enqueue_negative_control_fails(void)
{
  struct shared_run *run = mmap(
      NULL,
      sizeof(*run),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS,
      -1,
      0);
  if (run == MAP_FAILED) {
    return false;
  }

  memset(run, 0, sizeof(*run));
  struct ring_slot slot;
  memset(&slot, 0, sizeof(slot));
  slot.publish_order = 1;
  fill_frame(&slot.frame, 0, 0);
  atomic_store(&run->consumer_current_icount, slot.frame.delivery_icount);
  const bool accepted = guarded_enqueue(run, 0, &slot);
  const bool failed = !accepted && atomic_load(&run->failed) != 0;
  munmap(run, sizeof(*run));
  return failed;
}

static bool
run_once(
    enum run_mode mode,
    const struct expected_frame expected[TOTAL_FRAMES],
    struct delivery_record records[TOTAL_FRAMES],
    bool *ceiling_wait_observed,
    bool *early_peek_observed,
    bool *arrival_inversion_observed)
{
  struct shared_run *run = mmap(
      NULL,
      sizeof(*run),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS,
      -1,
      0);
  if (run == MAP_FAILED) {
    perror("mmap");
    return false;
  }

  memset(run, 0, sizeof(*run));
  pid_t children[SOURCE_COUNT + 1U];
  size_t child_count = 0;

  for (unsigned int ring = 0; ring < SOURCE_COUNT; ring++) {
    pid_t pid = fork();
    if (pid < 0) {
      perror("fork producer");
      munmap(run, sizeof(*run));
      return false;
    }
    if (pid == 0) {
      producer_main(run, mode, ring);
    }
    children[child_count++] = pid;
  }

  pid_t consumer = fork();
  if (consumer < 0) {
    perror("fork consumer");
    munmap(run, sizeof(*run));
    return false;
  }
  if (consumer == 0) {
    consumer_main(run, mode, expected);
  }
  children[child_count++] = consumer;

  atomic_store_explicit(&run->start, 1, memory_order_release);

  bool ok = true;
  for (size_t i = 0; i < child_count; i++) {
    int status = 0;
    if (waitpid(children[i], &status, 0) < 0) {
      perror("waitpid");
      ok = false;
      continue;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      ok = false;
    }
  }

  if (atomic_load(&run->failed) != 0) {
    fprintf(stderr, "S4 run failed: %s\n", run->error);
    ok = false;
  }

  memcpy(records, run->records, sizeof(run->records));
  *ceiling_wait_observed = atomic_load(&run->ceiling_wait_observed) != 0;
  *early_peek_observed = atomic_load(&run->early_peek_observed) != 0;
  *arrival_inversion_observed = arrival_order_differs(records);

  munmap(run, sizeof(*run));
  return ok;
}

int
main(void)
{
  struct expected_frame expected[TOTAL_FRAMES];
  struct delivery_record producer_skew_records[TOTAL_FRAMES];
  struct delivery_record consumer_skew_records[TOTAL_FRAMES];
  bool producer_ceiling_wait = false;
  bool producer_early_peek = false;
  bool producer_arrival_inversion = false;
  bool consumer_ceiling_wait = false;
  bool consumer_early_peek = false;
  bool consumer_arrival_inversion = false;

  build_expected(expected);

  if (!run_once(
          RUN_PRODUCER_SKEW,
          expected,
          producer_skew_records,
          &producer_ceiling_wait,
          &producer_early_peek,
          &producer_arrival_inversion)) {
    return 1;
  }
  if (!run_once(
          RUN_CONSUMER_SKEW,
          expected,
          consumer_skew_records,
          &consumer_ceiling_wait,
          &consumer_early_peek,
          &consumer_arrival_inversion)) {
    return 1;
  }

  const bool producer_order_matches =
      records_follow_expected(producer_skew_records, expected);
  const bool consumer_order_matches =
      records_follow_expected(consumer_skew_records, expected);
  const bool visibility_vectors_match =
      records_match(producer_skew_records, consumer_skew_records);
  const bool arrival_differs =
      producer_arrival_inversion || consumer_arrival_inversion;
  const bool publish_orders_stable =
      publish_orders_unique_nonzero(producer_skew_records) &&
      publish_orders_unique_nonzero(consumer_skew_records);
  const bool arrival_negative_fails =
      arrival_order_negative_control_fails(producer_skew_records);
  const bool late_enqueue_negative_fails =
      late_enqueue_negative_control_fails();

  if (!producer_order_matches || !consumer_order_matches ||
      !visibility_vectors_match || !arrival_differs ||
      !publish_orders_stable ||
      !arrival_negative_fails || !late_enqueue_negative_fails ||
      !producer_ceiling_wait || !consumer_early_peek) {
    fprintf(stderr, "S4 visibility assertions failed\n");
    return 1;
  }

  puts("PASS");
  puts("spike=producer-consumer-shmem-visibility");
  puts("check=checks.crucible.phase0.s4ShmemVisibility");
  puts("model=shmem_scheduler_node_double");
  puts("shared_memory=MAP_SHARED");
  puts("ring_ordering=release_acquire_spsc");
  printf("source_nodes=%u\n", SOURCE_COUNT);
  puts("consumer_nodes=1");
  printf("rings=%u\n", SOURCE_COUNT);
  printf("frames_per_source=%u\n", FRAMES_PER_SOURCE);
  printf("total_frames=%u\n", TOTAL_FRAMES);
  puts("delivery_groups=8");
  puts("run_x_skew=producer_publish_path");
  puts("run_y_skew=consumer_poll_path");
  puts("delivery_rule=delivery_icount_lte_current_icount");
  puts("tie_break_key=delivery_icount_src_node_seq");
  puts("consumer_ceiling=delivery_icount_minus_1_until_group_present");
  puts("producer_skew_ceiling_wait_observed=true");
  printf("producer_skew_early_peek_observed=%s\n", producer_early_peek ? "true" : "false");
  puts("consumer_skew_early_peek_observed=true");
  printf("consumer_skew_ceiling_wait_observed=%s\n", consumer_ceiling_wait ? "true" : "false");
  puts("arrival_order_differs=true");
  puts("publish_order_unique_nonzero=true");
  puts("visibility_vectors_match=true");
  puts("visibility_icounts_equal_delivery_icount=true");
  puts("injection_order_match=true");
  puts("arrival_order_negative_control_failed=true");
  puts("late_enqueue_negative_control_failed=true");
  puts("late_delivery_failures=0");
  puts("early_delivery_failures=0");
  puts("late_enqueue_failures=0");
  puts("fallback_adopted=false");
  puts("scope=phase0_shmem_visibility_discipline_not_qemu_device_injection");
  puts("s4_complete=true");
  return 0;
}
