#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  QEMU_CLOCK_VIRTUAL = 0,
  QEMU_CLOCK_REALTIME = 1,
  QEMU_TIMER_ATTR_ALL = 0,
  REPLAY_MODE_PLAY = 1,
};

enum icount_mode {
  ICOUNT_PRECISE = 1,
  ICOUNT_ADAPTATIVE = 2,
};

static int replay_mode;
static enum icount_mode current_icount_mode;
static int64_t current_virtual_deadline;
static int64_t current_realtime_deadline;
static unsigned int current_shift;
static const char *current_accel = "sim";
static unsigned int virtual_deadline_reads;
static unsigned int realtime_deadline_reads;

#define icount_enabled() (current_icount_mode)

const char *
current_accel_name(void)
{
  return current_accel;
}

static int64_t
qemu_soonest_timeout(int64_t left, int64_t right)
{
  if (left < 0) {
    return right;
  }
  if (right < 0) {
    return left;
  }
  return left < right ? left : right;
}

static int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  (void)attrs;

  if (clock == QEMU_CLOCK_VIRTUAL) {
    virtual_deadline_reads++;
    return current_virtual_deadline;
  }
  if (clock == QEMU_CLOCK_REALTIME) {
    realtime_deadline_reads++;
    return current_realtime_deadline;
  }

  return -1;
}

static int64_t
icount_round(int64_t ns)
{
  return (ns + ((int64_t)1 << current_shift) - 1) >> current_shift;
}

static int64_t
replay_get_instructions(void)
{
  return 12345;
}

#include "accel/tcg/tcg-accel-ops-icount.c"

static int64_t
stock_budget_insns(int64_t virtual_deadline_ns, int64_t realtime_deadline_ns,
                   unsigned int shift)
{
  int64_t deadline =
      qemu_soonest_timeout(virtual_deadline_ns, realtime_deadline_ns);
  if (deadline < 0 || deadline > INT32_MAX) {
    deadline = INT32_MAX;
  }
  return (deadline + ((int64_t)1 << shift) - 1) >> shift;
}

static int64_t
run_patched_limit(const char *accel, enum icount_mode mode, int64_t virtual_deadline_ns,
                  int64_t realtime_deadline_ns, unsigned int shift,
                  unsigned int *virtual_reads, unsigned int *realtime_reads)
{
  replay_mode = 0;
  current_accel = accel;
  current_icount_mode = mode;
  current_virtual_deadline = virtual_deadline_ns;
  current_realtime_deadline = realtime_deadline_ns;
  current_shift = shift;
  virtual_deadline_reads = 0;
  realtime_deadline_reads = 0;

  const int64_t limit = icount_get_limit();
  *virtual_reads = virtual_deadline_reads;
  *realtime_reads = realtime_deadline_reads;
  return limit;
}

int
main(void)
{
  const unsigned int shift = 3;
  const int64_t virtual_deadline = 4096;
  const int64_t fast_host_realtime = 8;
  const int64_t slow_host_realtime = 2048;
  unsigned int precise_fast_virtual_reads = 0;
  unsigned int precise_fast_realtime_reads = 0;
  unsigned int precise_slow_virtual_reads = 0;
  unsigned int precise_slow_realtime_reads = 0;
  unsigned int adaptive_fast_virtual_reads = 0;
  unsigned int adaptive_fast_realtime_reads = 0;
  unsigned int adaptive_slow_virtual_reads = 0;
  unsigned int adaptive_slow_realtime_reads = 0;

  unsigned int tcg_precise_virtual_reads = 0;
  unsigned int tcg_precise_realtime_reads = 0;

  const int64_t precise_fast = run_patched_limit(
      "sim", ICOUNT_PRECISE, virtual_deadline, fast_host_realtime, shift,
      &precise_fast_virtual_reads, &precise_fast_realtime_reads);
  const int64_t precise_slow = run_patched_limit(
      "sim", ICOUNT_PRECISE, virtual_deadline, slow_host_realtime, shift,
      &precise_slow_virtual_reads, &precise_slow_realtime_reads);
  const int64_t adaptive_fast = run_patched_limit(
      "sim", ICOUNT_ADAPTATIVE, virtual_deadline, fast_host_realtime, shift,
      &adaptive_fast_virtual_reads, &adaptive_fast_realtime_reads);
  const int64_t adaptive_slow = run_patched_limit(
      "sim", ICOUNT_ADAPTATIVE, virtual_deadline, slow_host_realtime, shift,
      &adaptive_slow_virtual_reads, &adaptive_slow_realtime_reads);
  const int64_t tcg_precise = run_patched_limit(
      "tcg", ICOUNT_PRECISE, virtual_deadline, fast_host_realtime, shift,
      &tcg_precise_virtual_reads, &tcg_precise_realtime_reads);
  const int64_t stock_precise_fast =
      stock_budget_insns(virtual_deadline, fast_host_realtime, shift);
  const int64_t stock_precise_slow =
      stock_budget_insns(virtual_deadline, slow_host_realtime, shift);
  const int64_t expected_precise = icount_round(virtual_deadline);

  if (precise_fast != expected_precise || precise_slow != expected_precise) {
    fprintf(stderr,
            "precise mode used realtime deadline: fast=%lld slow=%lld expected=%lld\n",
            (long long)precise_fast, (long long)precise_slow,
            (long long)expected_precise);
    return 1;
  }
  if (precise_fast_realtime_reads != 0 || precise_slow_realtime_reads != 0) {
    fprintf(stderr,
            "precise mode consulted realtime clock: fast=%u slow=%u\n",
            precise_fast_realtime_reads, precise_slow_realtime_reads);
    return 1;
  }
  if (precise_fast_virtual_reads != 1 || precise_slow_virtual_reads != 1) {
    fprintf(stderr, "precise mode did not consult the virtual clock exactly once\n");
    return 1;
  }
  if (adaptive_fast == adaptive_slow) {
    fprintf(stderr, "adaptive mode did not observe realtime deadline variation\n");
    return 1;
  }
  if (adaptive_fast != icount_round(fast_host_realtime) ||
      adaptive_slow != icount_round(slow_host_realtime)) {
    fprintf(stderr, "adaptive mode did not choose soonest realtime deadline\n");
    return 1;
  }
  if (adaptive_fast_realtime_reads != 1 || adaptive_slow_realtime_reads != 1) {
    fprintf(stderr, "adaptive mode did not consult realtime clock exactly once\n");
    return 1;
  }
  if (tcg_precise != stock_precise_fast || tcg_precise_realtime_reads != 1 ||
      tcg_precise_virtual_reads != 1) {
    fprintf(stderr,
            "non-sim precise icount did not retain upstream realtime budget: budget=%lld stock=%lld rt_reads=%u virt_reads=%u\n",
            (long long)tcg_precise, (long long)stock_precise_fast,
            tcg_precise_realtime_reads, tcg_precise_virtual_reads);
    return 1;
  }
  if (stock_precise_fast == stock_precise_slow) {
    fprintf(stderr, "stock negative control unexpectedly ignored realtime deadline\n");
    return 1;
  }

  puts("PASS");
  printf("precise_budget_fast=%lld\n", (long long)precise_fast);
  printf("precise_budget_slow=%lld\n", (long long)precise_slow);
  printf("non_sim_precise_budget=%lld\n", (long long)tcg_precise);
  printf("adaptive_budget_fast=%lld\n", (long long)adaptive_fast);
  printf("adaptive_budget_slow=%lld\n", (long long)adaptive_slow);
  printf("stock_precise_budget_fast=%lld\n", (long long)stock_precise_fast);
  printf("stock_precise_budget_slow=%lld\n", (long long)stock_precise_slow);
  puts("precise_realtime_reads_fast=0");
  puts("precise_realtime_reads_slow=0");
  puts("patched_icount_get_limit_fixture=true");
  puts("synthetic_fast_slow_realtime_deadlines=true");
  puts("sim_precise_tb_exit_budget_identical=true");
  puts("precise_realtime_independent=true");
  puts("non_sim_precise_realtime_consulted=true");
  puts("adaptive_realtime_consulted=true");
  puts("stock_negative_control_realtime_dependent=true");
  return 0;
}
