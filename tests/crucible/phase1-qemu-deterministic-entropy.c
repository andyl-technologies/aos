#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t guint32;
typedef unsigned int guint;

typedef struct Error {
  const char *message;
} Error;

typedef struct GRand {
  uint32_t state;
} GRand;

enum {
  REPLAY_MODE_PLAY = 1,
  REPLAY_MODE_RECORD = 2,
};

static int replay_mode;
static Error *error_fatal;
static unsigned int host_random_calls;
static unsigned int replay_read_calls;
static unsigned int replay_save_calls;
static unsigned int g_rand_new_calls;
static unsigned int g_rand_new_seed_array_calls;
static unsigned int g_rand_int_calls;
static unsigned int g_random_set_seed_calls;
static guint32 g_random_last_seed;
static guint32 g_random_state;
static guint32 seed_array_words[2];
static guint seed_array_len;
static uint32_t seeded_thread_initial_state;

#define unlikely(value) (value)
#define g_assert(expr)                                                         \
  do {                                                                         \
    if (!(expr)) {                                                             \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static uint32_t
next_word(uint32_t value)
{
  return value * 1664525u + 1013904223u;
}

static GRand *
alloc_rand(uint32_t state)
{
  GRand *rand = malloc(sizeof(*rand));
  if (rand == NULL) {
    abort();
  }
  rand->state = state;
  return rand;
}

static GRand *
g_rand_new(void)
{
  g_rand_new_calls++;
  return alloc_rand(0xa5a5a5a5u);
}

static GRand *
g_rand_new_with_seed_array(const guint32 *seed, guint len)
{
  uint32_t state = 0x811c9dc5u;
  guint copied = len < 2 ? len : 2;

  g_rand_new_seed_array_calls++;
  seed_array_len = len;
  memcpy(seed_array_words, seed, copied * sizeof(*seed));
  for (guint index = 0; index < len; index++) {
    guint32 word = 0;
    memcpy(&word, seed + index, sizeof(word));
    state ^= word;
    state *= 16777619u;
  }
  seeded_thread_initial_state = state;
  return alloc_rand(state);
}

static guint32
g_rand_int(GRand *rand)
{
  g_rand_int_calls++;
  rand->state = next_word(rand->state);
  return rand->state;
}

static void
g_random_set_seed(guint32 seed)
{
  g_random_set_seed_calls++;
  g_random_last_seed = seed;
  g_random_state = seed;
}

static guint32
g_random_int(void)
{
  g_random_state = next_word(g_random_state);
  return g_random_state;
}

static int
parse_uint_full(const char *seedstr, int base, uint64_t *seed)
{
  char *end = NULL;

  *seed = strtoull(seedstr, &end, base);
  if (seedstr[0] == '\0' || *end != '\0') {
    return -1;
  }
  return 0;
}

static void
error_setg(Error **errp, const char *message, ...)
{
  static Error error;

  error.message = message;
  if (errp != NULL) {
    *errp = &error;
  }
}

static int
qcrypto_random_bytes(void *buf, size_t len, Error **errp)
{
  (void)errp;
  host_random_calls++;
  memset(buf, 0xa5, len);
  return 0;
}

static int
replay_read_random(void *buf, size_t len)
{
  replay_read_calls++;
  memset(buf, 0x5a, len);
  return 0;
}

static void
replay_save_random(int ret, const void *buf, size_t len)
{
  (void)ret;
  (void)buf;
  (void)len;
  replay_save_calls++;
}

static const char *current_accel_label = "tcg";

const char *
current_accel_name(void)
{
  return current_accel_label;
}

#include "util/guest-random.c"

#ifdef CRUCIBLE_EXPECT_SIM_GETRANDOM_GUARD
static int
stock_qemu_guest_getrandom_without_sim_guard(void *buf, size_t len,
                                             Error **errp)
{
  int ret;

  if (replay_mode == REPLAY_MODE_PLAY) {
    return replay_read_random(buf, len);
  }
  if (unlikely(deterministic)) {
    ret = glib_random_bytes(buf, len);
  } else {
    ret = qcrypto_random_bytes(buf, len, errp);
  }
  if (replay_mode == REPLAY_MODE_RECORD) {
    replay_save_random(ret, buf, len);
  }
  return ret;
}
#endif

struct SeedObservation {
  uint32_t glib_seed;
  guint32 seed_words[2];
  guint seed_len;
  uint32_t initial_state;
  unsigned char random_bytes[12];
};

static void
reset_instrumentation(void)
{
  host_random_calls = 0;
  replay_read_calls = 0;
  replay_save_calls = 0;
  g_rand_new_calls = 0;
  g_rand_new_seed_array_calls = 0;
  g_rand_int_calls = 0;
  g_random_set_seed_calls = 0;
  g_random_last_seed = 0;
  g_random_state = 0;
  seed_array_words[0] = 0;
  seed_array_words[1] = 0;
  seed_array_len = 0;
  seeded_thread_initial_state = 0;
}

static void
reset_qemu_guest_random_state(void)
{
  replay_mode = 0;
  deterministic = false;
  thread_rand = NULL;
  error_fatal = NULL;
}

static int
stock_qemu_guest_random_seed_main_without_glib_seed(const char *seedstr,
                                                    Error **errp)
{
  uint64_t seed;
  bool stock_deterministic;
  GRand *stock_thread_rand = NULL;

  if (parse_uint_full(seedstr, 0, &seed)) {
    error_setg(errp, "Invalid seed number: %s", seedstr);
    return -1;
  }

  stock_deterministic = true;
  if (stock_deterministic) {
    stock_thread_rand =
        g_rand_new_with_seed_array((const guint32 *)&seed,
                                   sizeof(seed) / sizeof(guint32));
  }

  return stock_thread_rand == NULL ? -1 : 0;
}

static uint32_t
folded_glib_seed(uint64_t seed)
{
  return (uint32_t)(seed ^ (seed >> 32));
}

static void
expected_seed_words(uint64_t seed, guint32 words[2])
{
  memcpy(words, &seed, sizeof(seed));
}

static int
observe_seeded_run(const char *seedstr, uint64_t run_seed,
                   struct SeedObservation *observation)
{
  unsigned char random_bytes[sizeof(observation->random_bytes)];
  guint32 expected_words[2];
  Error *err = NULL;

  reset_instrumentation();
  reset_qemu_guest_random_state();
  expected_seed_words(run_seed, expected_words);

  if (qemu_guest_random_seed_main(seedstr, &err) != 0 || err != NULL) {
    fputs("seed parsing failed unexpectedly\n", stderr);
    return 1;
  }
  if (!deterministic) {
    fputs("deterministic predicate was not enabled by run seed\n", stderr);
    return 1;
  }
  if (g_random_set_seed_calls != 1 ||
      g_random_last_seed != folded_glib_seed(run_seed)) {
    fprintf(stderr, "GLib seed mismatch: calls=%u seed=0x%08x expected=0x%08x\n",
            g_random_set_seed_calls, g_random_last_seed,
            folded_glib_seed(run_seed));
    return 1;
  }
  if (g_rand_new_seed_array_calls != 1 || seed_array_len != 2 ||
      seed_array_words[0] != expected_words[0] ||
      seed_array_words[1] != expected_words[1]) {
    fprintf(stderr,
            "guest-random seed array mismatch: calls=%u len=%u w0=0x%08x/%08x w1=0x%08x/%08x\n",
            g_rand_new_seed_array_calls, seed_array_len, seed_array_words[0],
            expected_words[0], seed_array_words[1], expected_words[1]);
    return 1;
  }

  if (qemu_guest_getrandom(random_bytes, sizeof(random_bytes), &err) != 0) {
    fputs("deterministic guest-random draw failed\n", stderr);
    return 1;
  }
  if (host_random_calls != 0 || g_rand_int_calls == 0 ||
      replay_read_calls != 0 || replay_save_calls != 0) {
    fprintf(stderr,
            "guest-random used wrong source: host=%u g_rand=%u replay_read=%u replay_save=%u\n",
            host_random_calls, g_rand_int_calls, replay_read_calls,
            replay_save_calls);
    return 1;
  }

  observation->glib_seed = g_random_last_seed;
  observation->seed_words[0] = seed_array_words[0];
  observation->seed_words[1] = seed_array_words[1];
  observation->seed_len = seed_array_len;
  observation->initial_state = seeded_thread_initial_state;
  memcpy(observation->random_bytes, random_bytes,
         sizeof(observation->random_bytes));
  return 0;
}

int
main(void)
{
  const uint64_t run_seed = 0x0123456789abcdefull;
  const uint64_t other_seed = 0x0123456789abcdeeull;
  const uint32_t expected_glib_seed = folded_glib_seed(run_seed);
  unsigned char unseeded_bytes[4];
  struct SeedObservation first;
  struct SeedObservation second;
  Error *err = NULL;

  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "tcg";
  if (stock_qemu_guest_random_seed_main_without_glib_seed("81985529216486895",
                                                          &err) != 0 ||
      err != NULL || g_random_set_seed_calls != 0 ||
      g_rand_new_seed_array_calls != 1) {
    fprintf(stderr,
            "stock seed negative control mismatch: err=%p glib_seed_calls=%u seed_array_calls=%u\n",
            (void *)err, g_random_set_seed_calls,
            g_rand_new_seed_array_calls);
    return 1;
  }

  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "tcg";
  if (qemu_guest_getrandom(unseeded_bytes, sizeof(unseeded_bytes), &err) != 0 ||
      host_random_calls != 1 || g_rand_new_calls != 0 ||
      g_rand_int_calls != 0 || g_random_set_seed_calls != 0) {
    fprintf(stderr,
            "unseeded random path mismatch: host=%u g_rand_new=%u g_rand_int=%u glib_seed=%u\n",
            host_random_calls, g_rand_new_calls, g_rand_int_calls,
            g_random_set_seed_calls);
    return 1;
  }

#ifdef CRUCIBLE_EXPECT_SIM_GETRANDOM_GUARD
  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "sim";
  if (stock_qemu_guest_getrandom_without_sim_guard(unseeded_bytes,
                                                   sizeof(unseeded_bytes),
                                                   &err) != 0 ||
      host_random_calls != 1 || err != NULL) {
    fprintf(stderr,
            "stock sim negative control did not use host crypto: host=%u err=%p\n",
            host_random_calls, (void *)err);
    return 1;
  }

  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "sim";
  if (qemu_guest_getrandom(unseeded_bytes, sizeof(unseeded_bytes), &err) == 0 ||
      host_random_calls != 0 || g_rand_new_calls != 0 ||
      g_rand_int_calls != 0 || err == NULL ||
      strcmp(err->message,
             "-accel sim requires -seed for deterministic guest random") != 0) {
    fprintf(stderr,
            "sim unseeded getrandom guard mismatch: host=%u g_rand_new=%u g_rand=%u err=%p\n",
            host_random_calls, g_rand_new_calls, g_rand_int_calls,
            (void *)err);
    return 1;
  }

  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "tcg";
  err = NULL;
  if (qemu_guest_getrandom(unseeded_bytes, sizeof(unseeded_bytes), &err) != 0 ||
      host_random_calls != 1 || err != NULL) {
    fprintf(stderr,
            "non-sim unseeded getrandom path mismatch: host=%u err=%p\n",
            host_random_calls, (void *)err);
    return 1;
  }
#endif

  reset_instrumentation();
  reset_qemu_guest_random_state();
  current_accel_label = "tcg";
  if (qemu_guest_random_seed_thread_part1() != 0 ||
      g_rand_new_seed_array_calls != 0 || g_rand_int_calls != 0) {
    fprintf(stderr,
            "unseeded thread seed path should stay disabled: seed_array=%u g_rand=%u\n",
            g_rand_new_seed_array_calls, g_rand_int_calls);
    return 1;
  }
  qemu_guest_random_seed_thread_part2(run_seed);
  if (thread_rand != NULL || g_rand_new_seed_array_calls != 0) {
    fprintf(stderr,
            "unseeded thread seed part2 created deterministic stream: rand=%p calls=%u\n",
            (void *)thread_rand, g_rand_new_seed_array_calls);
    return 1;
  }

  if (observe_seeded_run("81985529216486895", run_seed, &first) != 0) {
    return 1;
  }
  if (observe_seeded_run("81985529216486894", other_seed, &second) != 0) {
    return 1;
  }
  if (first.initial_state == second.initial_state ||
      memcmp(first.random_bytes, second.random_bytes,
             sizeof(first.random_bytes)) == 0) {
    fputs("different run seeds did not produce different guest-random streams\n",
          stderr);
    return 1;
  }
  if (first.seed_words[0] == second.seed_words[0] &&
      first.seed_words[1] == second.seed_words[1]) {
    fputs("different run seeds did not change guest-random seed words\n", stderr);
    return 1;
  }

  g_random_set_seed(first.glib_seed);
  const uint32_t glib_first = g_random_int();
  g_random_set_seed(first.glib_seed);
  const uint32_t glib_repeat = g_random_int();
  if (glib_first != glib_repeat) {
    fprintf(stderr,
            "GLib global PRNG is not repeatable: first=0x%08x repeat=0x%08x\n",
            glib_first, glib_repeat);
    return 1;
  }

  reset_instrumentation();
  reset_qemu_guest_random_state();
  if (qemu_guest_random_seed_main("81985529216486895", &err) != 0 ||
      err != NULL) {
    fputs("seed parsing failed before thread seed probe\n", stderr);
    return 1;
  }
  uint64_t thread_seed = qemu_guest_random_seed_thread_part1();
  guint32 expected_thread_words[2];
  if (thread_seed == 0 || host_random_calls != 0 || g_rand_int_calls != 2) {
    fprintf(stderr,
            "seeded thread seed path did not use deterministic stream: seed=0x%016llx host=%u g_rand=%u\n",
            (unsigned long long)thread_seed, host_random_calls,
            g_rand_int_calls);
    return 1;
  }
  expected_seed_words(thread_seed, expected_thread_words);
  thread_rand = NULL;
  g_rand_new_seed_array_calls = 0;
  seed_array_len = 0;
  seed_array_words[0] = 0;
  seed_array_words[1] = 0;
  qemu_guest_random_seed_thread_part2(thread_seed);
  if (thread_rand == NULL || g_rand_new_seed_array_calls != 1 ||
      seed_array_len != 2 || seed_array_words[0] != expected_thread_words[0] ||
      seed_array_words[1] != expected_thread_words[1]) {
    fprintf(stderr,
            "seeded thread handoff mismatch: rand=%p calls=%u len=%u w0=0x%08x/%08x w1=0x%08x/%08x\n",
            (void *)thread_rand, g_rand_new_seed_array_calls, seed_array_len,
            seed_array_words[0], expected_thread_words[0], seed_array_words[1],
            expected_thread_words[1]);
    return 1;
  }

  puts("PASS");
  puts("patched_guest_random_fixture=true");
  printf("run_seed=0x%016llx\n", (unsigned long long)run_seed);
  printf("glib_seed=0x%08x\n", expected_glib_seed);
  printf("guest_random_seed_array_len=%u\n", first.seed_len);
  printf("guest_random_seed_word0=0x%08x\n", first.seed_words[0]);
  printf("guest_random_seed_word1=0x%08x\n", first.seed_words[1]);
  printf("guest_random_initial_state=0x%08x\n", first.initial_state);
  puts("guest_random_uses_run_seed=true");
  puts("guest_random_thread_seed_part1_uses_run_seed=true");
  puts("guest_random_thread_seed_part2_gated=true");
  puts("different_run_seed_changes_guest_random=true");
  puts("glib_global_prng_uses_run_seed=true");
  puts("unseeded_guest_random_uses_host_crypto=true");
  puts("host_entropy_calls=0");
#ifdef CRUCIBLE_EXPECT_SIM_GETRANDOM_GUARD
  puts("sim_unseeded_guest_random_fails_closed=true");
  puts("sim_unseeded_host_entropy_calls=0");
  puts("non_sim_unseeded_guest_random_uses_host_crypto=true");
  puts("stock_sim_unseeded_negative_control_uses_host_crypto=true");
#endif
  puts("stock_negative_control_glib_unseeded=true");
  return 0;
}
