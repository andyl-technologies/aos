#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  REPLICAS = 4,
  MAX_MESSAGES = 14,
  MAX_LOG_INDEX = 3,
  MAX_FAULTS = 4,
  SEARCH_DEPTH_LIMIT = 4,
  RAW_DEPTH_LIMIT = 5,
  FRONTIER_BUDGET = 64,
  FRONTIER_CAP = 64,
  UNBOUNDED_FRONTIER_CAP = 32768,
  MAX_SEEN = 262144,
  MAX_DECISIONS = 64,
  CHECKPOINT_BYTES = 192,
  STORE_BUDGET_BYTES = 196608,
  REQUIRED_ACCEPTED_COVERAGE_BITS = 32,
  REQUIRED_EXPANDED_COVERAGE_BITS = 24,
};

enum message_kind {
  MSG_APPEND = 0,
  MSG_ACK = 1,
  MSG_HEARTBEAT = 2,
};

enum decision_kind {
  DEC_DELIVER = 0,
  DEC_DROP = 1,
  DEC_CRASH = 2,
  DEC_PARTITION = 3,
  DEC_HEAL = 4,
  DEC_TIMER = 5,
};

enum insert_result {
  INSERT_ACCEPTED,
  INSERT_REPLACED,
  INSERT_DROPPED,
};

struct replica {
  uint8_t log_index;
  uint8_t ack_mask;
  uint8_t crashed;
  uint8_t rng_position;
};

struct message {
  uint8_t src;
  uint8_t dst;
  uint8_t kind;
  uint8_t payload;
};

struct state {
  struct replica replicas[REPLICAS];
  struct message messages[MAX_MESSAGES];
  uint8_t message_count;
  uint8_t partitions;
  uint8_t fault_count;
  uint8_t rng_cursor;
  uint8_t event_log_offset;
  uint8_t materialized_refs;
};

struct decision {
  uint8_t kind;
  uint8_t index;
  uint8_t src;
  uint8_t dst;
  uint8_t payload;
  uint8_t pair;
  uint8_t touch_mask;
};

struct successor {
  struct state state;
  uint64_t hash;
};

struct node {
  struct state state;
  uint64_t hash;
  uint8_t depth;
  uint64_t coverage;
  int32_t score;
};

struct metrics {
  uint64_t raw_edges;
  uint64_t reduced_edges;
  uint64_t partial_order_skipped_edges;
  uint64_t symmetry_skipped_edges;
  uint64_t dedup_hits;
  uint64_t accepted_nodes;
  uint64_t seen_nodes;
  uint64_t expanded_nodes;
  uint64_t frontier_pruned;
  uint64_t frontier_dropped;
  uint64_t frontier_replaced;
  size_t max_frontier;
  uint64_t accepted_coverage;
  uint64_t expanded_coverage;
};

static uint64_t seen_hashes[MAX_SEEN];
static struct node frontier[UNBOUNDED_FRONTIER_CAP];
static size_t frontier_len;
static bool seen_saturated;

static const uint8_t permutations[24][REPLICAS] = {
    {0, 1, 2, 3},
    {0, 1, 3, 2},
    {0, 2, 1, 3},
    {0, 2, 3, 1},
    {0, 3, 1, 2},
    {0, 3, 2, 1},
    {1, 0, 2, 3},
    {1, 0, 3, 2},
    {1, 2, 0, 3},
    {1, 2, 3, 0},
    {1, 3, 0, 2},
    {1, 3, 2, 0},
    {2, 0, 1, 3},
    {2, 0, 3, 1},
    {2, 1, 0, 3},
    {2, 1, 3, 0},
    {2, 3, 0, 1},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {3, 0, 2, 1},
    {3, 1, 0, 2},
    {3, 1, 2, 0},
    {3, 2, 0, 1},
    {3, 2, 1, 0},
};

static uint64_t
saturating_add(uint64_t a, uint64_t b)
{
  if (UINT64_MAX - a < b) {
    return UINT64_MAX;
  }
  return a + b;
}

static uint64_t
saturating_mul(uint64_t a, uint64_t b)
{
  if (a != 0 && b > UINT64_MAX / a) {
    return UINT64_MAX;
  }
  return a * b;
}

static uint32_t
popcount64(uint64_t value)
{
  uint32_t count = 0;
  while (value != 0) {
    count += (uint32_t)(value & 1U);
    value >>= 1;
  }
  return count;
}

static uint8_t
pair_index(uint8_t a, uint8_t b)
{
  uint8_t index = 0;
  if (a > b) {
    const uint8_t tmp = a;
    a = b;
    b = tmp;
  }

  for (uint8_t i = 0; i < REPLICAS; i++) {
    for (uint8_t j = (uint8_t)(i + 1); j < REPLICAS; j++) {
      if (i == a && j == b) {
        return index;
      }
      index++;
    }
  }

  return 0;
}

static uint8_t
pair_mask(uint8_t a, uint8_t b)
{
  return (uint8_t)(1U << pair_index(a, b));
}

static bool
partitioned(const struct state *state, uint8_t a, uint8_t b)
{
  return (state->partitions & pair_mask(a, b)) != 0;
}

static uint8_t
partition_count(uint8_t partitions)
{
  uint8_t count = 0;
  for (uint8_t bit = 0; bit < 6; bit++) {
    count = (uint8_t)(count + ((partitions >> bit) & 1U));
  }
  return count;
}

static uint8_t
permute_node_mask(uint8_t mask, const uint8_t perm[REPLICAS])
{
  uint8_t mapped = 0;
  for (uint8_t node = 0; node < REPLICAS; node++) {
    if ((mask & (1U << node)) != 0) {
      mapped = (uint8_t)(mapped | (1U << perm[node]));
    }
  }
  return mapped;
}

static uint8_t
permute_partitions(uint8_t partitions, const uint8_t perm[REPLICAS])
{
  uint8_t mapped = 0;
  for (uint8_t i = 0; i < REPLICAS; i++) {
    for (uint8_t j = (uint8_t)(i + 1); j < REPLICAS; j++) {
      if ((partitions & pair_mask(i, j)) != 0) {
        mapped = (uint8_t)(mapped | pair_mask(perm[i], perm[j]));
      }
    }
  }
  return mapped;
}

static int
message_compare(const struct message *a, const struct message *b)
{
  if (a->src != b->src) {
    return (int)a->src - (int)b->src;
  }
  if (a->dst != b->dst) {
    return (int)a->dst - (int)b->dst;
  }
  if (a->kind != b->kind) {
    return (int)a->kind - (int)b->kind;
  }
  return (int)a->payload - (int)b->payload;
}

static void
sort_messages(struct state *state)
{
  for (uint8_t i = 1; i < state->message_count; i++) {
    const struct message value = state->messages[i];
    uint8_t j = i;
    while (j > 0 && message_compare(&state->messages[j - 1], &value) > 0) {
      state->messages[j] = state->messages[j - 1];
      j--;
    }
    state->messages[j] = value;
  }
  for (uint8_t i = state->message_count; i < MAX_MESSAGES; i++) {
    state->messages[i] = (struct message){0, 0, 0, 0};
  }
}

static void
encode_state(const struct state *state, uint8_t bytes[96])
{
  size_t cursor = 0;
  for (uint8_t i = 0; i < REPLICAS; i++) {
    bytes[cursor++] = state->replicas[i].log_index;
    bytes[cursor++] = state->replicas[i].ack_mask;
    bytes[cursor++] = state->replicas[i].crashed;
    bytes[cursor++] = state->replicas[i].rng_position;
  }

  bytes[cursor++] = state->message_count;
  for (uint8_t i = 0; i < MAX_MESSAGES; i++) {
    bytes[cursor++] = state->messages[i].src;
    bytes[cursor++] = state->messages[i].dst;
    bytes[cursor++] = state->messages[i].kind;
    bytes[cursor++] = state->messages[i].payload;
  }

  bytes[cursor++] = state->partitions;
  bytes[cursor++] = state->fault_count;
  bytes[cursor++] = state->rng_cursor;
  bytes[cursor++] = state->event_log_offset;
  bytes[cursor++] = state->materialized_refs;

  while (cursor < 96) {
    bytes[cursor++] = 0;
  }
}

static uint64_t
hash_bytes(const uint8_t *bytes, size_t len)
{
  uint64_t hash = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  if (hash == 0) {
    return 0x9e3779b97f4a7c15ULL;
  }
  return hash;
}

static void
apply_permutation(const struct state *src, const uint8_t perm[REPLICAS], struct state *dst)
{
  memset(dst, 0, sizeof(*dst));
  for (uint8_t old = 0; old < REPLICAS; old++) {
    const uint8_t mapped = perm[old];
    dst->replicas[mapped] = src->replicas[old];
    dst->replicas[mapped].ack_mask = permute_node_mask(src->replicas[old].ack_mask, perm);
  }

  dst->message_count = src->message_count;
  for (uint8_t i = 0; i < src->message_count; i++) {
    dst->messages[i] = (struct message){
        .src = perm[src->messages[i].src],
        .dst = perm[src->messages[i].dst],
        .kind = src->messages[i].kind,
        .payload = src->messages[i].payload,
    };
  }

  dst->partitions = permute_partitions(src->partitions, perm);
  dst->fault_count = src->fault_count;
  dst->rng_cursor = src->rng_cursor;
  dst->event_log_offset = src->event_log_offset;
  dst->materialized_refs = src->materialized_refs;
  sort_messages(dst);
}

static uint64_t
canonicalize_state(const struct state *state, struct state *canonical)
{
  uint8_t best_bytes[96];
  bool have_best = false;

  for (size_t i = 0; i < sizeof(permutations) / sizeof(permutations[0]); i++) {
    struct state candidate;
    uint8_t bytes[96];
    apply_permutation(state, permutations[i], &candidate);
    encode_state(&candidate, bytes);
    if (!have_best || memcmp(bytes, best_bytes, sizeof(bytes)) < 0) {
      memcpy(best_bytes, bytes, sizeof(best_bytes));
      *canonical = candidate;
      have_best = true;
    }
  }

  return hash_bytes(best_bytes, sizeof(best_bytes));
}

static bool
add_message(struct state *state, uint8_t src, uint8_t dst, uint8_t kind, uint8_t payload)
{
  if (state->message_count >= MAX_MESSAGES) {
    return false;
  }
  state->messages[state->message_count++] = (struct message){
      .src = src,
      .dst = dst,
      .kind = kind,
      .payload = payload,
  };
  sort_messages(state);
  return true;
}

static void
remove_message(struct state *state, uint8_t index)
{
  if (index >= state->message_count) {
    return;
  }
  for (uint8_t i = index; (uint8_t)(i + 1) < state->message_count; i++) {
    state->messages[i] = state->messages[i + 1];
  }
  state->message_count--;
  sort_messages(state);
}

static void
advance_coordinates(struct state *state, const struct decision *decision)
{
  state->event_log_offset = (uint8_t)(state->event_log_offset + 1);
  if (state->event_log_offset % 3U == 0 && state->materialized_refs < 7) {
    state->materialized_refs++;
  }
  if (decision->kind == DEC_DROP || decision->kind == DEC_CRASH ||
      decision->kind == DEC_PARTITION || decision->kind == DEC_TIMER) {
    state->rng_cursor = (uint8_t)((state->rng_cursor * 5U + decision->kind +
                                   decision->src + decision->dst + decision->payload + 1U) &
                                  15U);
  }
}

static uint8_t
ack_count(uint8_t mask)
{
  uint8_t count = 0;
  for (uint8_t i = 0; i < REPLICAS; i++) {
    count = (uint8_t)(count + ((mask >> i) & 1U));
  }
  return count;
}

static void
deliver_message(struct state *state, struct message message)
{
  struct replica *dst = &state->replicas[message.dst];
  if (dst->crashed != 0) {
    return;
  }

  if (message.kind == MSG_APPEND) {
    if (message.payload > dst->log_index) {
      dst->log_index = message.payload;
    }
    (void)add_message(state, message.dst, message.src, MSG_ACK, message.payload);
  } else if (message.kind == MSG_ACK) {
    dst->ack_mask = (uint8_t)(dst->ack_mask | (1U << message.src));
    if (ack_count(dst->ack_mask) >= 3 && message.payload > dst->log_index) {
      dst->log_index = message.payload;
    }
  } else {
    dst->rng_position = (uint8_t)((dst->rng_position + message.payload + message.src + 1U) & 7U);
  }
}

static void
apply_decision(const struct state *state, const struct decision *decision, struct state *next)
{
  *next = *state;
  advance_coordinates(next, decision);

  if (decision->kind == DEC_DELIVER) {
    const struct message message = next->messages[decision->index];
    remove_message(next, decision->index);
    deliver_message(next, message);
  } else if (decision->kind == DEC_DROP) {
    remove_message(next, decision->index);
    next->fault_count = (uint8_t)(next->fault_count + 1);
  } else if (decision->kind == DEC_CRASH) {
    next->replicas[decision->src].crashed = 1;
    next->fault_count = (uint8_t)(next->fault_count + 1);
  } else if (decision->kind == DEC_PARTITION) {
    next->partitions = (uint8_t)(next->partitions | (1U << decision->pair));
    next->fault_count = (uint8_t)(next->fault_count + 1);
  } else if (decision->kind == DEC_HEAL) {
    next->partitions = (uint8_t)(next->partitions & (uint8_t)~(1U << decision->pair));
  } else {
    struct replica *replica = &next->replicas[decision->src];
    replica->rng_position = (uint8_t)((replica->rng_position + next->rng_cursor + 1U) & 7U);
    const uint8_t payload = (uint8_t)((replica->log_index < MAX_LOG_INDEX)
                                          ? replica->log_index + 1
                                          : MAX_LOG_INDEX);
    for (uint8_t dst = 0; dst < REPLICAS; dst++) {
      if (dst != decision->src && next->replicas[dst].crashed == 0) {
        (void)add_message(next, decision->src, dst, MSG_APPEND, payload);
      }
    }
    if (next->message_count < MAX_MESSAGES) {
      for (uint8_t dst = 0; dst < REPLICAS; dst++) {
        if (dst != decision->src && next->replicas[dst].crashed == 0) {
          (void)add_message(next, decision->src, dst, MSG_HEARTBEAT, replica->rng_position);
          break;
        }
      }
    }
  }

  sort_messages(next);
}

static bool
can_deliver(const struct state *state, const struct message *message)
{
  return state->replicas[message->dst].crashed == 0 &&
      !partitioned(state, message->src, message->dst);
}

static size_t
enumerate_decisions(const struct state *state, struct decision out[MAX_DECISIONS])
{
  size_t count = 0;

  for (uint8_t i = 0; i < state->message_count; i++) {
    const struct message *message = &state->messages[i];
    if (can_deliver(state, message)) {
      out[count++] = (struct decision){
          .kind = DEC_DELIVER,
          .index = i,
          .src = message->src,
          .dst = message->dst,
          .payload = message->payload,
          .pair = pair_index(message->src, message->dst),
          .touch_mask = (uint8_t)((1U << message->src) | (1U << message->dst)),
      };
    }
    if (state->fault_count < MAX_FAULTS) {
      out[count++] = (struct decision){
          .kind = DEC_DROP,
          .index = i,
          .src = message->src,
          .dst = message->dst,
          .payload = message->payload,
          .pair = pair_index(message->src, message->dst),
          .touch_mask = (uint8_t)((1U << message->src) | (1U << message->dst)),
      };
    }
  }

  if (state->fault_count < MAX_FAULTS) {
    for (uint8_t node = 0; node < REPLICAS; node++) {
      if (state->replicas[node].crashed == 0) {
        out[count++] = (struct decision){
            .kind = DEC_CRASH,
            .src = node,
            .dst = node,
            .touch_mask = (uint8_t)(1U << node),
        };
      }
    }

    if (partition_count(state->partitions) < 2) {
      for (uint8_t a = 0; a < REPLICAS; a++) {
        for (uint8_t b = (uint8_t)(a + 1); b < REPLICAS; b++) {
          const uint8_t pair = pair_index(a, b);
          if ((state->partitions & (1U << pair)) == 0) {
            out[count++] = (struct decision){
                .kind = DEC_PARTITION,
                .src = a,
                .dst = b,
                .pair = pair,
                .touch_mask = (uint8_t)((1U << a) | (1U << b)),
            };
          }
        }
      }
    }
  }

  for (uint8_t pair = 0; pair < 6; pair++) {
    if ((state->partitions & (1U << pair)) != 0) {
      uint8_t seen = 0;
      for (uint8_t a = 0; a < REPLICAS; a++) {
        for (uint8_t b = (uint8_t)(a + 1); b < REPLICAS; b++) {
          if (seen == pair) {
            out[count++] = (struct decision){
                .kind = DEC_HEAL,
                .src = a,
                .dst = b,
                .pair = pair,
                .touch_mask = (uint8_t)((1U << a) | (1U << b)),
            };
          }
          seen++;
        }
      }
    }
  }

  if (state->message_count <= MAX_MESSAGES - (REPLICAS - 1)) {
    for (uint8_t node = 0; node < REPLICAS; node++) {
      if (state->replicas[node].crashed == 0 &&
          state->replicas[node].log_index < MAX_LOG_INDEX) {
        out[count++] = (struct decision){
            .kind = DEC_TIMER,
            .src = node,
            .dst = node,
            .payload = state->replicas[node].log_index,
            .touch_mask = 0x0f,
        };
      }
    }
  }

  return count;
}

static bool
skip_by_partial_order(const struct decision *candidate, const struct decision kept[MAX_DECISIONS], size_t kept_len)
{
  (void)candidate;
  (void)kept;
  (void)kept_len;
  return false;
}

static size_t
reduced_successors(
    const struct state *state,
    struct successor out[MAX_DECISIONS],
    uint64_t *partial_order_skipped_edges,
    uint64_t *symmetry_skipped_edges)
{
  struct decision decisions[MAX_DECISIONS];
  struct decision kept[MAX_DECISIONS];
  size_t kept_len = 0;
  size_t count = 0;
  const size_t decision_count = enumerate_decisions(state, decisions);

  for (size_t i = 0; i < decision_count; i++) {
    if (skip_by_partial_order(&decisions[i], kept, kept_len)) {
      (*partial_order_skipped_edges)++;
      continue;
    }

    struct state next;
    struct state canonical;
    apply_decision(state, &decisions[i], &next);
    const uint64_t hash = canonicalize_state(&next, &canonical);

    bool duplicate = false;
    for (size_t j = 0; j < count; j++) {
      if (out[j].hash == hash) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      (*symmetry_skipped_edges)++;
      continue;
    }

    kept[kept_len++] = decisions[i];
    out[count++] = (struct successor){
        .state = canonical,
        .hash = hash,
    };
  }

  return count;
}

static uint64_t
coverage_for_state(const struct state *state)
{
  uint64_t coverage = 0;
  for (uint8_t i = 0; i < REPLICAS; i++) {
    coverage |= 1ULL << state->replicas[i].log_index;
    if (state->replicas[i].crashed != 0) {
      coverage |= 1ULL << (4 + i);
    }
    coverage |= 1ULL << (8 + ack_count(state->replicas[i].ack_mask));
    coverage |= 1ULL << (13 + state->replicas[i].rng_position);
  }

  coverage |= 1ULL << (21 + state->message_count / 2);
  coverage |= 1ULL << (30 + partition_count(state->partitions));
  coverage |= 1ULL << (33 + state->fault_count);
  coverage |= 1ULL << (38 + (state->rng_cursor & 7U));
  coverage |= 1ULL << (46 + state->materialized_refs);
  coverage |= 1ULL << (54 + (state->event_log_offset & 7U));

  for (uint8_t i = 0; i < state->message_count; i++) {
    coverage |= 1ULL << (61 + state->messages[i].kind);
  }

  return coverage;
}

static int32_t
score_for(uint64_t coverage, uint8_t depth, uint64_t accepted_coverage, uint8_t message_count)
{
  const uint32_t novel = popcount64(coverage & ~accepted_coverage);
  const uint32_t total = popcount64(coverage);
  return (int32_t)(novel * 10000U + total * 100U - depth * 7U + message_count);
}

static int
better_node(const struct node *a, const struct node *b)
{
  if (a->score != b->score) {
    return a->score > b->score;
  }
  if (a->depth != b->depth) {
    return a->depth < b->depth;
  }
  return a->hash < b->hash;
}

static enum insert_result
insert_frontier(const struct node *candidate, size_t cap, struct metrics *metrics)
{
  if (frontier_len < cap) {
    frontier[frontier_len++] = *candidate;
    if (frontier_len > metrics->max_frontier) {
      metrics->max_frontier = frontier_len;
    }
    return INSERT_ACCEPTED;
  }

  size_t worst = 0;
  for (size_t i = 1; i < frontier_len; i++) {
    if (better_node(&frontier[worst], &frontier[i])) {
      worst = i;
    }
  }

  metrics->frontier_pruned++;
  if (better_node(candidate, &frontier[worst])) {
    frontier[worst] = *candidate;
    metrics->frontier_replaced++;
    return INSERT_REPLACED;
  }

  metrics->frontier_dropped++;
  return INSERT_DROPPED;
}

static struct node
pop_best(void)
{
  size_t best = 0;
  for (size_t i = 1; i < frontier_len; i++) {
    if (better_node(&frontier[i], &frontier[best])) {
      best = i;
    }
  }

  const struct node result = frontier[best];
  frontier[best] = frontier[frontier_len - 1];
  frontier_len--;
  return result;
}

static void
reset_seen(void)
{
  memset(seen_hashes, 0, sizeof(seen_hashes));
  seen_saturated = false;
}

static bool
seen_contains(uint64_t hash)
{
  size_t index = (size_t)(hash & (MAX_SEEN - 1));
  for (size_t probe = 0; probe < MAX_SEEN; probe++) {
    const uint64_t found = seen_hashes[index];
    if (found == 0) {
      return false;
    }
    if (found == hash) {
      return true;
    }
    index = (index + 1) & (MAX_SEEN - 1);
  }
  return false;
}

static void
seen_insert(uint64_t hash)
{
  size_t index = (size_t)(hash & (MAX_SEEN - 1));
  for (size_t probe = 0; probe < MAX_SEEN; probe++) {
    if (seen_hashes[index] == 0 || seen_hashes[index] == hash) {
      seen_hashes[index] = hash;
      return;
    }
    index = (index + 1) & (MAX_SEEN - 1);
  }
  seen_saturated = true;
}

static struct state
initial_state(void)
{
  struct state state;
  memset(&state, 0, sizeof(state));
  for (uint8_t node = 0; node < REPLICAS; node++) {
    state.replicas[node].ack_mask = (uint8_t)(1U << node);
  }
  for (uint8_t src = 0; src < REPLICAS; src++) {
    for (uint8_t dst = 0; dst < REPLICAS; dst++) {
      if (src != dst) {
        (void)add_message(&state, src, dst, MSG_APPEND, 1);
      }
    }
  }
  return state;
}

static uint64_t
raw_branching_proxy(const struct state *start, uint8_t depth)
{
  struct state state = *start;
  uint64_t total = 1;
  uint64_t width = 1;

  for (uint8_t level = 0; level < depth; level++) {
    struct decision decisions[MAX_DECISIONS];
    const size_t decision_count = enumerate_decisions(&state, decisions);
    if (decision_count == 0) {
      break;
    }

    width = saturating_mul(width, decision_count);
    total = saturating_add(total, width);

    size_t chosen = 0;
    for (size_t i = 0; i < decision_count; i++) {
      if (decisions[i].kind == DEC_DELIVER) {
        chosen = i;
        break;
      }
    }
    struct state next;
    apply_decision(&state, &decisions[chosen], &next);
    state = next;
  }

  return total;
}

static struct metrics
run_search(const struct state *start, size_t cap)
{
  struct metrics metrics;
  struct state canonical_start;
  const uint64_t start_hash = canonicalize_state(start, &canonical_start);
  const uint64_t start_coverage = coverage_for_state(&canonical_start);

  memset(&metrics, 0, sizeof(metrics));
  reset_seen();
  frontier_len = 0;

  seen_insert(start_hash);
  metrics.seen_nodes = 1;
  metrics.accepted_nodes = 1;
  metrics.accepted_coverage |= start_coverage;

  const struct node start_node = {
      .state = canonical_start,
      .hash = start_hash,
      .depth = 0,
      .coverage = start_coverage,
      .score = score_for(start_coverage, 0, 0, canonical_start.message_count),
  };
  (void)insert_frontier(&start_node, cap, &metrics);

  while (frontier_len > 0) {
    const struct node current = pop_best();
    metrics.expanded_nodes++;
    metrics.expanded_coverage |= current.coverage;

    if (current.depth >= SEARCH_DEPTH_LIMIT) {
      continue;
    }

    struct decision decisions[MAX_DECISIONS];
    const size_t raw_count = enumerate_decisions(&current.state, decisions);
    struct successor successors[MAX_DECISIONS];
    const size_t reduced_count = reduced_successors(
        &current.state,
        successors,
        &metrics.partial_order_skipped_edges,
        &metrics.symmetry_skipped_edges);
    metrics.raw_edges += raw_count;
    metrics.reduced_edges += reduced_count;

    for (size_t i = 0; i < reduced_count; i++) {
      if (seen_contains(successors[i].hash)) {
        metrics.dedup_hits++;
        continue;
      }

      const uint64_t coverage = coverage_for_state(&successors[i].state);
      const struct node candidate = {
          .state = successors[i].state,
          .hash = successors[i].hash,
          .depth = (uint8_t)(current.depth + 1),
          .coverage = coverage,
          .score = score_for(
              coverage,
              (uint8_t)(current.depth + 1),
              metrics.accepted_coverage,
              successors[i].state.message_count),
      };
      const enum insert_result inserted = insert_frontier(&candidate, cap, &metrics);
      if (inserted != INSERT_DROPPED) {
        seen_insert(successors[i].hash);
        metrics.seen_nodes++;
        metrics.accepted_nodes++;
        metrics.accepted_coverage |= coverage;
      }
    }
  }

  return metrics;
}

int
main(void)
{
  const struct state start = initial_state();
  const uint64_t raw_proxy = raw_branching_proxy(&start, RAW_DEPTH_LIMIT);
  const struct metrics bounded = run_search(&start, FRONTIER_CAP);
  const struct metrics uncapped = run_search(&start, UNBOUNDED_FRONTIER_CAP);

  const uint64_t estimated_store_bytes = bounded.seen_nodes * CHECKPOINT_BYTES;
  const uint32_t accepted_coverage_bits = popcount64(bounded.accepted_coverage);
  const uint32_t expanded_coverage_bits = popcount64(bounded.expanded_coverage);
  const uint32_t uncapped_coverage_bits = popcount64(uncapped.expanded_coverage);
  const bool pass = !seen_saturated &&
      bounded.max_frontier <= FRONTIER_BUDGET &&
      uncapped.max_frontier > FRONTIER_BUDGET &&
      uncapped.frontier_pruned == 0 &&
      estimated_store_bytes <= STORE_BUDGET_BYTES &&
      accepted_coverage_bits >= REQUIRED_ACCEPTED_COVERAGE_BITS &&
      expanded_coverage_bits >= REQUIRED_EXPANDED_COVERAGE_BITS &&
      raw_proxy > bounded.seen_nodes * 100U &&
      bounded.dedup_hits > 0 &&
      bounded.symmetry_skipped_edges > 0 &&
      bounded.partial_order_skipped_edges == 0 &&
      bounded.frontier_pruned > 0 &&
      bounded.frontier_dropped > 0 &&
      bounded.frontier_replaced > 0 &&
      uncapped.seen_nodes >= bounded.seen_nodes &&
      uncapped_coverage_bits >= expanded_coverage_bits;

  puts(pass ? "PASS" : "FAIL");
  puts("spike=search-tree-growth");
  puts("scenario=pending-message-fault-temporal-graph");
  printf("replicas=%u\n", REPLICAS);
  printf("pending_message_slots=%u\n", MAX_MESSAGES);
  printf("max_faults=%u\n", MAX_FAULTS);
  printf("search_depth_limit=%u\n", SEARCH_DEPTH_LIMIT);
  printf("raw_depth_limit=%u\n", RAW_DEPTH_LIMIT);
  printf("checkpoint_bytes=%u\n", CHECKPOINT_BYTES);
  printf("raw_branching_proxy=%" PRIu64 "\n", raw_proxy);
  printf("bounded_seen_nodes=%" PRIu64 "\n", bounded.seen_nodes);
  printf("bounded_accepted_nodes=%" PRIu64 "\n", bounded.accepted_nodes);
  printf("bounded_expanded_nodes=%" PRIu64 "\n", bounded.expanded_nodes);
  printf("bounded_raw_edges=%" PRIu64 "\n", bounded.raw_edges);
  printf("bounded_reduced_edges=%" PRIu64 "\n", bounded.reduced_edges);
  printf("partial_order_skipped_edges=%" PRIu64 "\n", bounded.partial_order_skipped_edges);
  printf("symmetry_skipped_edges=%" PRIu64 "\n", bounded.symmetry_skipped_edges);
  printf("dedup_hits=%" PRIu64 "\n", bounded.dedup_hits);
  printf("frontier_pruned=%" PRIu64 "\n", bounded.frontier_pruned);
  printf("frontier_dropped=%" PRIu64 "\n", bounded.frontier_dropped);
  printf("frontier_replaced=%" PRIu64 "\n", bounded.frontier_replaced);
  printf("bounded_max_frontier=%zu\n", bounded.max_frontier);
  printf("frontier_budget=%u\n", FRONTIER_BUDGET);
  printf("uncapped_seen_nodes=%" PRIu64 "\n", uncapped.seen_nodes);
  printf("uncapped_expanded_nodes=%" PRIu64 "\n", uncapped.expanded_nodes);
  printf("uncapped_max_frontier=%zu\n", uncapped.max_frontier);
  printf("uncapped_frontier_pruned=%" PRIu64 "\n", uncapped.frontier_pruned);
  printf("accepted_coverage_bits=%u\n", accepted_coverage_bits);
  printf("expanded_coverage_bits=%u\n", expanded_coverage_bits);
  printf("uncapped_expanded_coverage_bits=%u\n", uncapped_coverage_bits);
  printf("required_accepted_coverage_bits=%u\n", REQUIRED_ACCEPTED_COVERAGE_BITS);
  printf("required_expanded_coverage_bits=%u\n", REQUIRED_EXPANDED_COVERAGE_BITS);
  printf("estimated_store_bytes=%" PRIu64 "\n", estimated_store_bytes);
  printf("store_budget_bytes=%u\n", STORE_BUDGET_BYTES);
  printf("dedup_compression_ratio_x1000=%" PRIu64 "\n", (raw_proxy * 1000U) / bounded.seen_nodes);
  printf("seen_saturated=%u\n", seen_saturated ? 1U : 0U);
  return pass ? 0 : 1;
}
