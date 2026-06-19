#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  RING_CAPACITY = 8,
  FRAME_BYTES = 32,
  OVERLAY_SECTORS = 6,
  SECTOR_BYTES = 64,
  RNG_DRAWS = 11
};

struct frame {
  uint64_t delivery_icount;
  uint32_t src_node;
  uint32_t seq;
  uint16_t len;
  unsigned char data[FRAME_BYTES];
};

struct ring {
  uint64_t read_idx;
  uint64_t write_idx;
  struct frame entries[RING_CAPACITY];
};

struct ring_snapshot {
  uint64_t live_count;
  struct frame entries[RING_CAPACITY];
};

struct overlay_delta {
  uint32_t sector;
  unsigned char bytes[SECTOR_BYTES];
};

struct rng_state {
  uint64_t state;
  uint64_t draws;
};

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
fill_frame(struct frame *frame, uint32_t src_node, uint32_t seq)
{
  memset(frame, 0, sizeof(*frame));
  frame->delivery_icount = 1000U + (uint64_t)seq * 17U;
  frame->src_node = src_node;
  frame->seq = seq;
  frame->len = FRAME_BYTES;
  for (uint16_t i = 0; i < frame->len; i++) {
    frame->data[i] = (unsigned char)(src_node * 31U + seq * 7U + i);
  }
}

static bool
ring_enqueue(struct ring *ring, const struct frame *frame)
{
  if (ring->write_idx - ring->read_idx >= RING_CAPACITY) {
    return false;
  }
  ring->entries[ring->write_idx & (RING_CAPACITY - 1U)] = *frame;
  ring->write_idx++;
  return true;
}

static struct ring_snapshot
snapshot_ring(const struct ring *ring)
{
  struct ring_snapshot snapshot;
  memset(&snapshot, 0, sizeof(snapshot));
  snapshot.live_count = ring->write_idx - ring->read_idx;
  for (uint64_t i = 0; i < snapshot.live_count; i++) {
    snapshot.entries[i] = ring->entries[(ring->read_idx + i) & (RING_CAPACITY - 1U)];
  }
  return snapshot;
}

static struct ring
restore_ring(const struct ring_snapshot *snapshot)
{
  struct ring ring;
  memset(&ring, 0, sizeof(ring));
  for (uint64_t i = 0; i < snapshot->live_count; i++) {
    (void)ring_enqueue(&ring, &snapshot->entries[i]);
  }
  return ring;
}

static uint64_t
hash_ring_live(const struct ring *ring)
{
  uint64_t hash = 1469598103934665603ULL;
  const uint64_t live_count = ring->write_idx - ring->read_idx;

  hash = fnv1a_u64(hash, live_count);
  for (uint64_t i = 0; i < live_count; i++) {
    const struct frame *frame =
        &ring->entries[(ring->read_idx + i) & (RING_CAPACITY - 1U)];
    hash = fnv1a_u64(hash, frame->delivery_icount);
    hash = fnv1a_u64(hash, frame->src_node);
    hash = fnv1a_u64(hash, frame->seq);
    hash = fnv1a_u64(hash, frame->len);
    hash = fnv1a_bytes(hash, frame->data, frame->len);
  }

  return hash;
}

static void
fill_overlay(struct overlay_delta overlay[OVERLAY_SECTORS])
{
  for (uint32_t sector = 0; sector < OVERLAY_SECTORS; sector++) {
    overlay[sector].sector = sector * 3U + 1U;
    for (uint32_t i = 0; i < SECTOR_BYTES; i++) {
      overlay[sector].bytes[i] = (unsigned char)(0xa5U ^ sector ^ (i * 13U));
    }
  }
}

static uint64_t
hash_overlay(const struct overlay_delta overlay[OVERLAY_SECTORS])
{
  uint64_t hash = 1469598103934665603ULL;

  for (uint32_t i = 0; i < OVERLAY_SECTORS; i++) {
    hash = fnv1a_u64(hash, overlay[i].sector);
    hash = fnv1a_bytes(hash, overlay[i].bytes, SECTOR_BYTES);
  }

  return hash;
}

static uint64_t
rng_next(struct rng_state *rng)
{
  uint64_t x = rng->state;
  x ^= x << 13U;
  x ^= x >> 7U;
  x ^= x << 17U;
  rng->state = x;
  rng->draws++;
  return x;
}

int
main(void)
{
  struct ring ring;
  struct overlay_delta overlay[OVERLAY_SECTORS];
  struct rng_state rng = {
      .state = 0x0010c0015eed1234ULL,
      .draws = 0,
  };
  memset(&ring, 0, sizeof(ring));

  for (uint32_t seq = 0; seq < 5; seq++) {
    struct frame frame;
    fill_frame(&frame, 7, seq);
    if (!ring_enqueue(&ring, &frame)) {
      return 1;
    }
  }
  ring.read_idx = 2;
  for (uint32_t seq = 5; seq < 7; seq++) {
    struct frame frame;
    fill_frame(&frame, 7, seq);
    if (!ring_enqueue(&ring, &frame)) {
      return 1;
    }
  }

  const uint64_t ring_before = hash_ring_live(&ring);
  const struct ring_snapshot ring_snapshot = snapshot_ring(&ring);
  const struct ring restored_ring = restore_ring(&ring_snapshot);
  const uint64_t ring_after = hash_ring_live(&restored_ring);

  fill_overlay(overlay);
  const uint64_t overlay_before = hash_overlay(overlay);
  struct overlay_delta restored_overlay[OVERLAY_SECTORS];
  memcpy(restored_overlay, overlay, sizeof(restored_overlay));
  const uint64_t overlay_after = hash_overlay(restored_overlay);

  for (uint32_t i = 0; i < RNG_DRAWS; i++) {
    (void)rng_next(&rng);
  }
  const struct rng_state rng_snapshot = rng;
  struct rng_state restored_rng = rng_snapshot;
  const bool rng_snapshot_restored = restored_rng.state == rng_snapshot.state &&
                                     restored_rng.draws == rng_snapshot.draws;
  const uint64_t rng_before = rng_next(&rng);
  const uint64_t rng_after = rng_next(&restored_rng);

  if (ring_before != ring_after || overlay_before != overlay_after ||
      !rng_snapshot_restored || rng.state != restored_rng.state ||
      rng.draws != restored_rng.draws || rng_before != rng_after) {
    return 1;
  }

  puts("owned_state_roundtrip=pass");
  puts("ring_snapshot_restore=pass");
  printf("ring_live_entries=%" PRIu64 "\n", ring_snapshot.live_count);
  printf("ring_live_hash=%016" PRIx64 "\n", ring_after);
  puts("overlay_delta_roundtrip=pass");
  printf("overlay_sectors=%u\n", OVERLAY_SECTORS);
  printf("overlay_hash=%016" PRIx64 "\n", overlay_after);
  puts("rng_position_roundtrip=pass");
  printf("rng_draws=%" PRIu64 "\n", restored_rng.draws);
  printf("rng_next=%016" PRIx64 "\n", rng_after);
  return 0;
}
