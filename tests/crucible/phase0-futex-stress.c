#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
  STATUS_RUNNING = 0,
  STATUS_IDLE = 1,
};

struct shared_state {
  _Atomic uint32_t wake_signal;
  _Atomic uint32_t status;
  _Atomic uint64_t idle_wake_icount;
  _Atomic uint64_t max_advance_icount;
  _Atomic uint64_t waiter_ready;
  _Atomic uint64_t waiter_observed;
  _Atomic uint64_t waiter_done;
  _Atomic uint64_t lost_wakes;
  _Atomic uint64_t spurious_advances;
  _Atomic uint64_t timed_out_after_wake;
  _Atomic uint64_t successful_wait_returns;
  _Atomic uint64_t successful_spurious_wait_returns;
  _Atomic uint64_t race_returns;
  _Atomic uint64_t futex_wait_calls;
  _Atomic uint64_t futex_wake_calls;
  _Atomic uint64_t spurious_wake_calls;
  _Atomic uint64_t spurious_wake_phase;
  _Atomic uint64_t spurious_waiter_ready;
  _Atomic uint64_t spurious_waiter_observed;
  _Atomic uint64_t spurious_waiter_done;
  _Atomic uint32_t spurious_waiter_started;
  _Atomic uint32_t stop_jitter;
};

static int
futex_wait_shared(uint32_t *addr, uint32_t expected)
{
  struct timespec timeout = {
      .tv_sec = 5,
      .tv_nsec = 0,
  };
  return (int)syscall(SYS_futex, addr, FUTEX_WAIT, expected, &timeout, NULL, 0);
}

static int
futex_wake_shared(uint32_t *addr)
{
  return (int)syscall(SYS_futex, addr, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static uint64_t
parse_u64_arg(const char *text, const char *name)
{
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0) {
    fprintf(stderr, "invalid %s: %s\n", name, text);
    exit(2);
  }
  return (uint64_t)value;
}

static void
inject_jitter(uint64_t iteration)
{
  if ((iteration & 1U) == 0) {
    sched_yield();
  }
  if ((iteration & 1023U) == 0) {
    for (unsigned int i = 0; i < 16; i++) {
      sched_yield();
    }
  }
}

static void
yield_to_waiter(void)
{
  for (unsigned int i = 0; i < 16; i++) {
    sched_yield();
  }
}

static int
waiter_loop(struct shared_state *state, uint64_t iterations)
{
  uint32_t *wake_word = (uint32_t *)&state->wake_signal;

  for (uint64_t i = 1; i <= iterations; i++) {
    atomic_store_explicit(&state->idle_wake_icount, i, memory_order_release);
    atomic_store_explicit(&state->status, STATUS_IDLE, memory_order_release);
    atomic_store_explicit(&state->waiter_ready, i, memory_order_release);

    uint32_t observed = atomic_load_explicit(&state->wake_signal, memory_order_acquire);
    atomic_store_explicit(&state->waiter_observed, i, memory_order_release);
    inject_jitter(i);

    while (atomic_load_explicit(&state->max_advance_icount, memory_order_acquire) < i) {
      if (atomic_load_explicit(&state->max_advance_icount, memory_order_acquire) >= i) {
        break;
      }
      atomic_fetch_add_explicit(&state->futex_wait_calls, 1, memory_order_relaxed);
      int rc = futex_wait_shared(wake_word, observed);
      if (rc == -1) {
        int err = errno;
        if (err == EAGAIN || err == EINTR) {
          atomic_fetch_add_explicit(&state->race_returns, 1, memory_order_relaxed);
        } else if (err == ETIMEDOUT) {
          atomic_fetch_add_explicit(&state->lost_wakes, 1, memory_order_relaxed);
          if (atomic_load_explicit(&state->max_advance_icount, memory_order_acquire) >= i) {
            atomic_fetch_add_explicit(&state->timed_out_after_wake, 1, memory_order_relaxed);
          }
          return 1;
        } else {
          fprintf(stderr, "FUTEX_WAIT failed at iteration %" PRIu64 ": %s\n", i, strerror(err));
          return 1;
        }
      } else {
        atomic_fetch_add_explicit(&state->successful_wait_returns, 1, memory_order_relaxed);
      }
      observed = atomic_load_explicit(&state->wake_signal, memory_order_acquire);
    }

    if (atomic_load_explicit(&state->max_advance_icount, memory_order_acquire) < i) {
      atomic_fetch_add_explicit(&state->spurious_advances, 1, memory_order_relaxed);
      return 1;
    }

    atomic_store_explicit(&state->status, STATUS_RUNNING, memory_order_release);
    atomic_store_explicit(&state->waiter_done, i, memory_order_release);
  }

  return 0;
}

static int
waker_loop(struct shared_state *state, uint64_t iterations)
{
  uint32_t *wake_word = (uint32_t *)&state->wake_signal;

  for (uint64_t i = 1; i <= iterations; i++) {
    while (atomic_load_explicit(&state->waiter_ready, memory_order_acquire) < i ||
           atomic_load_explicit(&state->idle_wake_icount, memory_order_acquire) != i ||
           atomic_load_explicit(&state->status, memory_order_acquire) != STATUS_IDLE ||
           atomic_load_explicit(&state->waiter_observed, memory_order_acquire) < i) {
      sched_yield();
    }

    yield_to_waiter();
    inject_jitter(i);
    atomic_store_explicit(&state->max_advance_icount, i, memory_order_release);
    atomic_fetch_add_explicit(&state->wake_signal, 1, memory_order_release);
    atomic_fetch_add_explicit(&state->futex_wake_calls, 1, memory_order_relaxed);
    if (futex_wake_shared(wake_word) == -1) {
      fprintf(stderr, "FUTEX_WAKE failed at iteration %" PRIu64 ": %s\n", i, strerror(errno));
      return 1;
    }

    while (atomic_load_explicit(&state->waiter_done, memory_order_acquire) < i) {
      sched_yield();
    }
  }

  return 0;
}

static int
spurious_waiter_loop(struct shared_state *state, uint64_t iterations)
{
  uint32_t *wake_word = (uint32_t *)&state->wake_signal;

  atomic_store_explicit(&state->idle_wake_icount, iterations + 1, memory_order_release);
  atomic_store_explicit(&state->status, STATUS_IDLE, memory_order_release);
  atomic_store_explicit(&state->spurious_waiter_started, 1, memory_order_release);

  while (atomic_load_explicit(&state->spurious_wake_phase, memory_order_acquire) < iterations) {
    atomic_fetch_add_explicit(&state->spurious_waiter_ready, 1, memory_order_release);
    uint32_t observed = atomic_load_explicit(&state->wake_signal, memory_order_acquire);
    atomic_fetch_add_explicit(&state->spurious_waiter_observed, 1, memory_order_release);
    int rc = futex_wait_shared(wake_word, observed);
    if (rc == -1) {
      int err = errno;
      if (err == EAGAIN || err == EINTR) {
        atomic_fetch_add_explicit(&state->race_returns, 1, memory_order_relaxed);
      } else if (err == ETIMEDOUT) {
        fprintf(
            stderr,
            "spurious wake phase timed out before completion: phase=%" PRIu64
            " ready=%" PRIu64 " observed=%" PRIu64 " done=%" PRIu64
            " wake_signal=%" PRIu32 " max_advance=%" PRIu64 "\n",
            atomic_load_explicit(&state->spurious_wake_phase, memory_order_acquire),
            atomic_load_explicit(&state->spurious_waiter_ready, memory_order_acquire),
            atomic_load_explicit(&state->spurious_waiter_observed, memory_order_acquire),
            atomic_load_explicit(&state->spurious_waiter_done, memory_order_acquire),
            atomic_load_explicit(&state->wake_signal, memory_order_acquire),
            atomic_load_explicit(&state->max_advance_icount, memory_order_acquire));
        return 1;
      } else {
        fprintf(stderr, "spurious FUTEX_WAIT failed: %s\n", strerror(err));
        return 1;
      }
    } else if (atomic_load_explicit(&state->max_advance_icount, memory_order_acquire) <
               iterations + 1) {
      atomic_fetch_add_explicit(&state->successful_spurious_wait_returns, 1, memory_order_relaxed);
    } else {
      atomic_fetch_add_explicit(&state->spurious_advances, 1, memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&state->spurious_waiter_done, 1, memory_order_release);
  }

  return 0;
}

static int
spurious_waker_loop(struct shared_state *state, uint64_t iterations)
{
  uint32_t *wake_word = (uint32_t *)&state->wake_signal;

  while (atomic_load_explicit(&state->spurious_waiter_started, memory_order_acquire) == 0) {
    sched_yield();
  }

  for (uint64_t i = 1; i <= iterations; i++) {
    while (atomic_load_explicit(&state->spurious_waiter_ready, memory_order_acquire) < i ||
           atomic_load_explicit(&state->spurious_waiter_observed, memory_order_acquire) < i) {
      sched_yield();
    }
    yield_to_waiter();
    inject_jitter(i);
    atomic_fetch_add_explicit(&state->wake_signal, 1, memory_order_release);
    atomic_fetch_add_explicit(&state->spurious_wake_calls, 1, memory_order_relaxed);
    if (futex_wake_shared(wake_word) == -1) {
      fprintf(stderr, "spurious FUTEX_WAKE failed at iteration %" PRIu64 ": %s\n", i, strerror(errno));
      return 1;
    }
    atomic_store_explicit(&state->spurious_wake_phase, i, memory_order_release);
    while (atomic_load_explicit(&state->spurious_waiter_done, memory_order_acquire) < i) {
      sched_yield();
    }
  }

  return 0;
}

static int
jitter_loop(struct shared_state *state)
{
  uint64_t sink = 0;
  while (atomic_load_explicit(&state->stop_jitter, memory_order_acquire) == 0) {
    for (uint64_t i = 0; i < 4096; i++) {
      sink = (sink * 1103515245U) + 12345U + i;
    }
    atomic_signal_fence(memory_order_seq_cst);
    sched_yield();
  }
  return (int)(sink & 1U);
}

static bool
child_failed(int status)
{
  return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int
main(int argc, char **argv)
{
  const uint64_t iterations = argc > 1 ? parse_u64_arg(argv[1], "iterations") : 2000000;
  const uint64_t jitter_workers = argc > 2 ? parse_u64_arg(argv[2], "jitter_workers") : 2;

  struct shared_state *state = mmap(
      NULL,
      sizeof(*state),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS,
      -1,
      0);
  if (state == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
    return 1;
  }
  memset(state, 0, sizeof(*state));

  pid_t *jitter_pids = calloc((size_t)jitter_workers, sizeof(*jitter_pids));
  if (jitter_pids == NULL) {
    fprintf(stderr, "calloc failed\n");
    return 1;
  }

  for (uint64_t i = 0; i < jitter_workers; i++) {
    pid_t pid = fork();
    if (pid == -1) {
      fprintf(stderr, "fork jitter worker failed: %s\n", strerror(errno));
      return 1;
    }
    if (pid == 0) {
      return jitter_loop(state);
    }
    jitter_pids[i] = pid;
  }

  pid_t waiter = fork();
  if (waiter == -1) {
    fprintf(stderr, "fork waiter failed: %s\n", strerror(errno));
    return 1;
  }
  if (waiter == 0) {
    return waiter_loop(state, iterations);
  }

  pid_t waker = fork();
  if (waker == -1) {
    fprintf(stderr, "fork waker failed: %s\n", strerror(errno));
    kill(waiter, SIGTERM);
    return 1;
  }
  if (waker == 0) {
    return waker_loop(state, iterations);
  }

  bool failed = false;
  for (unsigned int remaining = 2; remaining > 0; remaining--) {
    int status = 0;
    pid_t child = wait(&status);
    if (child == -1) {
      fprintf(stderr, "wait failed: %s\n", strerror(errno));
      failed = true;
      break;
    }
    if (child_failed(status)) {
      failed = true;
      kill(waiter, SIGTERM);
      kill(waker, SIGTERM);
    }
  }

  if (!failed) {
    atomic_store_explicit(&state->status, STATUS_RUNNING, memory_order_release);
    atomic_store_explicit(&state->idle_wake_icount, 0, memory_order_release);

    pid_t spurious_waiter = fork();
    if (spurious_waiter == -1) {
      fprintf(stderr, "fork spurious waiter failed: %s\n", strerror(errno));
      failed = true;
    } else if (spurious_waiter == 0) {
      return spurious_waiter_loop(state, iterations);
    }

    pid_t spurious_waker = -1;
    if (!failed) {
      spurious_waker = fork();
      if (spurious_waker == -1) {
        fprintf(stderr, "fork spurious waker failed: %s\n", strerror(errno));
        kill(spurious_waiter, SIGTERM);
        failed = true;
      } else if (spurious_waker == 0) {
        return spurious_waker_loop(state, iterations);
      }
    }

    for (unsigned int remaining = failed ? 0 : 2; remaining > 0; remaining--) {
      int status = 0;
      pid_t child = wait(&status);
      if (child == -1) {
        fprintf(stderr, "wait failed during spurious phase: %s\n", strerror(errno));
        failed = true;
        break;
      }
      if (child_failed(status)) {
        failed = true;
        kill(spurious_waiter, SIGTERM);
        kill(spurious_waker, SIGTERM);
      }
    }
  }

  atomic_store_explicit(&state->stop_jitter, 1, memory_order_release);
  for (uint64_t i = 0; i < jitter_workers; i++) {
    int status = 0;
    if (jitter_pids[i] > 0) {
      waitpid(jitter_pids[i], &status, 0);
    }
  }

  const uint64_t lost_wakes = atomic_load_explicit(&state->lost_wakes, memory_order_acquire);
  const uint64_t spurious_advances =
      atomic_load_explicit(&state->spurious_advances, memory_order_acquire);
  const uint64_t timed_out_after_wake =
      atomic_load_explicit(&state->timed_out_after_wake, memory_order_acquire);
  const uint64_t successful_wait_returns =
      atomic_load_explicit(&state->successful_wait_returns, memory_order_acquire);
  const uint64_t successful_spurious_wait_returns =
      atomic_load_explicit(&state->successful_spurious_wait_returns, memory_order_acquire);
  const uint64_t minimum_successful_returns = iterations / 2;
  if (lost_wakes != 0 || timed_out_after_wake != 0 || spurious_advances != 0 ||
      successful_wait_returns < minimum_successful_returns ||
      successful_spurious_wait_returns < minimum_successful_returns ||
      atomic_load_explicit(&state->spurious_waiter_done, memory_order_acquire) == 0) {
    failed = true;
  }

  printf("%s\n", failed ? "FAIL" : "PASS");
  printf("spike=cross-process-futex\n");
  printf("iterations=%" PRIu64 "\n", iterations);
  printf("jitter_workers=%" PRIu64 "\n", jitter_workers);
  printf("futex_private=false\n");
  printf("lost_wakes=%" PRIu64 "\n", lost_wakes);
  printf("timed_out_after_wake=%" PRIu64 "\n", timed_out_after_wake);
  printf("spurious_advances=%" PRIu64 "\n", spurious_advances);
  printf("successful_wait_returns=%" PRIu64 "\n", successful_wait_returns);
  printf("minimum_successful_returns=%" PRIu64 "\n", minimum_successful_returns);
  printf(
      "successful_spurious_wait_returns=%" PRIu64 "\n",
      successful_spurious_wait_returns);
  printf(
      "race_returns=%" PRIu64 "\n",
      atomic_load_explicit(&state->race_returns, memory_order_acquire));
  printf(
      "futex_wait_calls=%" PRIu64 "\n",
      atomic_load_explicit(&state->futex_wait_calls, memory_order_acquire));
  printf(
      "futex_wake_calls=%" PRIu64 "\n",
      atomic_load_explicit(&state->futex_wake_calls, memory_order_acquire));
  printf(
      "waiter_observed=%" PRIu64 "\n",
      atomic_load_explicit(&state->waiter_observed, memory_order_acquire));
  printf(
      "spurious_wake_calls=%" PRIu64 "\n",
      atomic_load_explicit(&state->spurious_wake_calls, memory_order_acquire));
  printf(
      "spurious_waiter_ready=%" PRIu64 "\n",
      atomic_load_explicit(&state->spurious_waiter_ready, memory_order_acquire));
  printf(
      "spurious_waiter_observed=%" PRIu64 "\n",
      atomic_load_explicit(&state->spurious_waiter_observed, memory_order_acquire));
  printf(
      "spurious_waiter_done=%" PRIu64 "\n",
      atomic_load_explicit(&state->spurious_waiter_done, memory_order_acquire));

  return failed ? 1 : 0;
}
