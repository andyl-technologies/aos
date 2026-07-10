#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define QEMU_PLUGIN_BLK_POLL_PENDING (-2)

typedef struct CPUState {
    int exit_request;
    bool stop;
    bool unplug;
    bool work_pending;
    struct CPUState *next;
} CPUState;

static CPUState first_fixture_cpu;
static bool fixture_sim_mode;
static bool fixture_all_idle;
static unsigned int fixture_event_common_calls;
static unsigned int fixture_cond_wait_calls;
static unsigned int fixture_idle_callbacks;
static unsigned int fixture_resume_callbacks;
static unsigned int fixture_idle_advance_work_calls;
static unsigned int fixture_yield_calls;
static unsigned int fixture_resume_waiter_calls;
static unsigned int fixture_poll_calls;
static bool fixture_response_ready;
static bool fixture_request_waiting;
static bool fixture_wake_failed;
static bool fixture_wake_before_park;
static uint64_t fixture_wake_generation;
static uint64_t fixture_published_icount;
static uint64_t fixture_max_advance_icount;
static bool fixture_time_advance_pending;
static bool fixture_timer_wake_before_completion;
static bool fixture_resume_while_advance_pending;
static unsigned int fixture_idle_advances_to_queue;

typedef struct SimShmemFixture {
    uint64_t *published_icount;
    uint64_t *max_advance_icount;
} SimShmemFixture;

static bool rr_crucible_sim_mode(void)
{
    return fixture_sim_mode;
}

static bool rr_crucible_sim_single_vcpu(void)
{
    return rr_crucible_sim_mode() && first_fixture_cpu.next == NULL;
}

static CPUState *rr_crucible_sim_loop_cpu(CPUState *cpu)
{
    if (rr_crucible_sim_single_vcpu()) {
        return &first_fixture_cpu;
    }
    return cpu;
}

static void rr_crucible_sim_reset_exit_request(CPUState *cpu)
{
    if (cpu != NULL) {
        cpu->exit_request = 0;
    }
}

static void rr_crucible_sim_normalize_first_exit(CPUState *cpu)
{
    if (cpu != NULL) {
        cpu->exit_request = 1;
    }
}

static bool cpu_work_list_empty(CPUState *cpu)
{
    return cpu != NULL && !cpu->work_pending;
}

static bool rr_crucible_sim_skip_second_events_pass(CPUState *cpu)
{
    return rr_crucible_sim_mode() &&
           cpu_work_list_empty(cpu) &&
           !cpu->stop &&
           !cpu->unplug;
}

static void qemu_wait_io_event_common(CPUState *cpu)
{
    if (cpu != NULL) {
        fixture_event_common_calls++;
        if (fixture_time_advance_pending && cpu->work_pending) {
            cpu->work_pending = false;
            fixture_idle_advance_work_calls++;
        }
    }
}

static void rr_wait_io_event_second_pass_fixture(void)
{
    if (!rr_crucible_sim_skip_second_events_pass(&first_fixture_cpu)) {
        qemu_wait_io_event_common(&first_fixture_cpu);
    }
}

static bool all_cpu_threads_idle(void)
{
    return fixture_all_idle && !first_fixture_cpu.work_pending;
}

static void qemu_cond_wait_bql(void)
{
    fixture_cond_wait_calls++;
    if (fixture_time_advance_pending) {
        if (fixture_timer_wake_before_completion) {
            fixture_timer_wake_before_completion = false;
            fixture_all_idle = false;
        } else {
            fixture_time_advance_pending = false;
        }
    }
}

static bool qemu_plugin_time_advance_is_pending(void)
{
    return fixture_time_advance_pending;
}

static bool rr_crucible_sim_maybe_fire_idle_callback(
    bool *idle_reported, bool *idle_advance_waiting)
{
    if (!rr_crucible_sim_mode() || *idle_reported) {
        return false;
    }

    fixture_idle_callbacks++;
    if (fixture_idle_advances_to_queue != 0) {
        fixture_idle_advances_to_queue--;
        fixture_time_advance_pending = true;
        first_fixture_cpu.work_pending = true;
    } else {
        fixture_all_idle = false;
    }
    *idle_reported = true;
    *idle_advance_waiting = qemu_plugin_time_advance_is_pending();
    return true;
}

static void rr_crucible_sim_maybe_rearm_idle_callback(
    bool *idle_reported, bool *idle_advance_waiting)
{
    if (!rr_crucible_sim_mode() || !*idle_advance_waiting ||
        qemu_plugin_time_advance_is_pending()) {
        return;
    }

    *idle_advance_waiting = false;
    *idle_reported = false;
}

static void rr_crucible_sim_process_queued_idle_advance(
    bool idle_callback_fired, bool idle_advance_waiting)
{
    if (!rr_crucible_sim_mode() || !idle_callback_fired ||
        !idle_advance_waiting) {
        return;
    }

    qemu_wait_io_event_common(&first_fixture_cpu);
}

static void rr_crucible_sim_maybe_fire_resume_callback(bool *idle_reported)
{
    if (!rr_crucible_sim_mode() || !*idle_reported) {
        return;
    }

    fixture_resume_callbacks++;
    fixture_resume_while_advance_pending =
        qemu_plugin_time_advance_is_pending();
    *idle_reported = false;
}

static void rr_wait_io_event_idle_fixture(void)
{
    bool idle_reported = false;
    bool idle_advance_waiting = false;

    while (all_cpu_threads_idle() ||
           (rr_crucible_sim_mode() &&
            qemu_plugin_time_advance_is_pending())) {
        bool idle_callback_fired;

        rr_crucible_sim_maybe_rearm_idle_callback(
            &idle_reported, &idle_advance_waiting);
        idle_callback_fired = rr_crucible_sim_maybe_fire_idle_callback(
            &idle_reported, &idle_advance_waiting);
        rr_crucible_sim_process_queued_idle_advance(
            idle_callback_fired, idle_advance_waiting);
        if (qemu_plugin_time_advance_is_pending()) {
            qemu_cond_wait_bql();
            continue;
        }
        if (!all_cpu_threads_idle()) {
            break;
        }
        qemu_cond_wait_bql();
    }

    rr_crucible_sim_maybe_fire_resume_callback(&idle_reported);
}

static int64_t fixture_poll_callback(void)
{
    fixture_poll_calls++;
    return fixture_response_ready ? 64 : QEMU_PLUGIN_BLK_POLL_PENDING;
}

static void crucible_shmem_wait_one_poll(uint64_t observed_generation)
{
    if (fixture_wake_failed ||
        fixture_wake_generation != observed_generation) {
        return;
    }
    fixture_yield_calls++;
    fixture_request_waiting = true;
}

static void crucible_shmem_wake(bool failed)
{
    if (failed) {
        fixture_wake_failed = true;
    }
    fixture_wake_generation++;
    if (fixture_request_waiting) {
        fixture_request_waiting = false;
        fixture_resume_waiter_calls++;
    }
}

static int64_t crucible_shmem_poll_or_park_fixture(void)
{
    int64_t ret;
    uint64_t observed_generation;

    if (fixture_wake_failed) {
        return -1;
    }
    observed_generation = fixture_wake_generation;
    ret = fixture_poll_callback();
    if (ret == QEMU_PLUGIN_BLK_POLL_PENDING) {
        if (fixture_wake_before_park) {
            fixture_wake_before_park = false;
            crucible_shmem_wake(false);
        }
        crucible_shmem_wait_one_poll(observed_generation);
    }
    return ret;
}

typedef void (*qemu_plugin_sim_shmem_publish_icount_cb_t)(uint64_t current_icount,
                                                          void *userdata);
typedef uint64_t (*qemu_plugin_sim_shmem_max_advance_icount_cb_t)(void *userdata);

static uint64_t crucible_current_icount;
static qemu_plugin_sim_shmem_publish_icount_cb_t crucible_publish_icount_cb;
static qemu_plugin_sim_shmem_max_advance_icount_cb_t crucible_max_advance_icount_cb;
static void *crucible_sim_shmem_userdata;

static void qemu_plugin_register_sim_shmem_dispatch_cb(
    qemu_plugin_sim_shmem_publish_icount_cb_t publish_icount_cb,
    qemu_plugin_sim_shmem_max_advance_icount_cb_t max_advance_icount_cb,
    void *userdata)
{
    crucible_sim_shmem_userdata = userdata;
    crucible_max_advance_icount_cb = max_advance_icount_cb;
    crucible_publish_icount_cb = publish_icount_cb;
}

static bool crucible_sim_shmem_dispatch_registered(void)
{
    return crucible_max_advance_icount_cb != NULL;
}

static void crucible_sim_shmem_publish_current_icount(uint64_t current_icount)
{
    crucible_current_icount = current_icount;
    if (crucible_publish_icount_cb != NULL) {
        crucible_publish_icount_cb(current_icount, crucible_sim_shmem_userdata);
    }
}

static uint64_t crucible_sim_shmem_current_icount(void)
{
    return crucible_current_icount;
}

static uint64_t crucible_sim_shmem_max_advance_icount(void)
{
    if (crucible_max_advance_icount_cb != NULL) {
        return crucible_max_advance_icount_cb(crucible_sim_shmem_userdata);
    }

    return UINT64_MAX;
}

static int64_t crucible_sim_shmem_clamp_cpu_budget(uint64_t current_icount,
                                                   int64_t cpu_budget)
{
    uint64_t max_advance_icount;
    uint64_t remaining;

    if (cpu_budget <= 0) {
        return cpu_budget;
    }

    max_advance_icount = crucible_sim_shmem_max_advance_icount();
    if (current_icount >= max_advance_icount) {
        return 0;
    }

    remaining = max_advance_icount - current_icount;
    if (remaining > (uint64_t)INT64_MAX || (uint64_t)cpu_budget <= remaining) {
        return cpu_budget;
    }
    return (int64_t)remaining;
}

static bool crucible_sim_shmem_may_advance_to(uint64_t candidate_icount)
{
    return candidate_icount <= crucible_sim_shmem_max_advance_icount();
}

static void fixture_publish_icount(uint64_t current_icount, void *userdata)
{
    SimShmemFixture *fixture = userdata;
    *fixture->published_icount = current_icount;
}

static uint64_t fixture_read_max_advance(void *userdata)
{
    SimShmemFixture *fixture = userdata;
    return *fixture->max_advance_icount;
}

static void require_bool(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    CPUState other_cpu = {.exit_request = 7, .next = NULL};

    fixture_sim_mode = true;
    first_fixture_cpu.exit_request = 7;
    first_fixture_cpu.next = NULL;
    require_bool(rr_crucible_sim_loop_cpu(&other_cpu) == &first_fixture_cpu,
                 "sim loop did not select first_cpu for single-vCPU mode");
    rr_crucible_sim_reset_exit_request(&first_fixture_cpu);
    require_bool(first_fixture_cpu.exit_request == 0,
                 "exit_request reset was not deterministic");
    rr_crucible_sim_normalize_first_exit(&first_fixture_cpu);
    require_bool(first_fixture_cpu.exit_request == 1,
                 "first exit phase was not normalized");

    fixture_event_common_calls = 0;
    first_fixture_cpu.work_pending = false;
    first_fixture_cpu.stop = false;
    first_fixture_cpu.unplug = false;
    rr_wait_io_event_second_pass_fixture();
    require_bool(fixture_event_common_calls == 0,
                 "sim mode did not skip redundant second events pass");
    first_fixture_cpu.work_pending = true;
    rr_wait_io_event_second_pass_fixture();
    require_bool(fixture_event_common_calls == 1,
                 "sim mode skipped pending CPU work in second events pass");
    first_fixture_cpu.work_pending = false;
    fixture_sim_mode = false;
    rr_wait_io_event_second_pass_fixture();
    require_bool(fixture_event_common_calls == 2,
                 "non-sim mode did not preserve second events pass");

    fixture_sim_mode = true;
    fixture_response_ready = false;
    fixture_yield_calls = 0;
    fixture_resume_waiter_calls = 0;
    fixture_poll_calls = 0;
    fixture_request_waiting = false;
    fixture_wake_failed = false;
    fixture_wake_before_park = false;
    fixture_wake_generation = 0;
    require_bool(crucible_shmem_poll_or_park_fixture() ==
                     QEMU_PLUGIN_BLK_POLL_PENDING,
                 "shmem request did not park while pending");
    require_bool(fixture_poll_calls == 1 && fixture_yield_calls == 1 &&
                     fixture_request_waiting,
                 "shmem request did not enter the wake-driven wait queue");
    fixture_response_ready = true;
    crucible_shmem_wake(false);
    require_bool(fixture_resume_waiter_calls == 1 &&
                     !fixture_request_waiting,
                 "scheduler wake did not resume the pending request");
    require_bool(crucible_shmem_poll_or_park_fixture() == 64,
                 "resumed shmem request did not observe its response");
    require_bool(fixture_poll_calls == 2,
                 "wake-driven shmem request did not re-poll exactly once");
    require_bool(fixture_yield_calls == 1,
                 "wake-driven shmem request spun instead of parking once");
    fixture_response_ready = false;
    fixture_wake_before_park = true;
    require_bool(crucible_shmem_poll_or_park_fixture() ==
                     QEMU_PLUGIN_BLK_POLL_PENDING,
                 "pre-park scheduler wake did not preserve pending result");
    require_bool(!fixture_request_waiting && fixture_yield_calls == 1,
                 "pre-park scheduler wake was lost and left a waiter parked");
    fixture_response_ready = false;
    require_bool(crucible_shmem_poll_or_park_fixture() ==
                     QEMU_PLUGIN_BLK_POLL_PENDING,
                 "second shmem request did not park");
    crucible_shmem_wake(true);
    require_bool(crucible_shmem_poll_or_park_fixture() == -1,
                 "wake-fd failure did not fail the parked request");

    fixture_all_idle = true;
    fixture_idle_callbacks = 0;
    fixture_resume_callbacks = 0;
    fixture_idle_advance_work_calls = 0;
    fixture_cond_wait_calls = 0;
    fixture_time_advance_pending = false;
    fixture_timer_wake_before_completion = false;
    fixture_resume_while_advance_pending = false;
    fixture_idle_advances_to_queue = 0;
    rr_wait_io_event_idle_fixture();
    require_bool(fixture_idle_callbacks == 1,
                 "idle callback did not fire exactly once");
    require_bool(fixture_resume_callbacks == 1,
                 "resume callback did not fire after idle wake");
    require_bool(fixture_cond_wait_calls == 0,
                 "idle callback wake was missed before qemu_cond_wait_bql");

    fixture_all_idle = true;
    first_fixture_cpu.work_pending = false;
    fixture_event_common_calls = 0;
    fixture_idle_callbacks = 0;
    fixture_resume_callbacks = 0;
    fixture_idle_advance_work_calls = 0;
    fixture_cond_wait_calls = 0;
    fixture_time_advance_pending = false;
    fixture_timer_wake_before_completion = true;
    fixture_resume_while_advance_pending = false;
    fixture_idle_advances_to_queue = 1;
    rr_wait_io_event_idle_fixture();
    require_bool(fixture_idle_callbacks == 1 &&
                     fixture_idle_advance_work_calls == 1,
                 "queued idle advance did not run exactly one vCPU work item");
    require_bool(fixture_cond_wait_calls == 2,
                 "timer wake was not held until normal-loop completion");
    require_bool(fixture_resume_callbacks == 1 &&
                     !fixture_resume_while_advance_pending &&
                     !fixture_time_advance_pending,
                 "resume callback ran before idle-advance completion");

    fixture_all_idle = true;
    first_fixture_cpu.work_pending = false;
    fixture_event_common_calls = 0;
    fixture_idle_callbacks = 0;
    fixture_resume_callbacks = 0;
    fixture_idle_advance_work_calls = 0;
    fixture_cond_wait_calls = 0;
    fixture_time_advance_pending = false;
    fixture_timer_wake_before_completion = false;
    fixture_resume_while_advance_pending = false;
    fixture_idle_advances_to_queue = 1;
    rr_wait_io_event_idle_fixture();
    require_bool(fixture_idle_callbacks == 2 &&
                     fixture_idle_advance_work_calls == 1,
                 "completed idle advance did not rearm the still-idle callback");
    require_bool(fixture_resume_callbacks == 1 &&
                     !fixture_resume_while_advance_pending,
                 "still-idle rearm reported a pending guest resume");

    fixture_published_icount = 0;
    fixture_max_advance_icount = 10;
    SimShmemFixture shmem_fixture = {
        .published_icount = &fixture_published_icount,
        .max_advance_icount = &fixture_max_advance_icount,
    };
    require_bool(!crucible_sim_shmem_dispatch_registered(),
                 "sim shmem dispatch was active without callbacks");
    qemu_plugin_register_sim_shmem_dispatch_cb(fixture_publish_icount,
                                               fixture_read_max_advance,
                                               &shmem_fixture);
    require_bool(crucible_sim_shmem_dispatch_registered(),
                 "sim shmem dispatch did not activate after callback registration");
    crucible_sim_shmem_publish_current_icount(7);
    require_bool(crucible_sim_shmem_current_icount() == 7,
                 "sim shmem current icount was not stored");
    require_bool(fixture_published_icount == 7,
                 "sim shmem publish callback did not receive current icount");
    require_bool(crucible_sim_shmem_may_advance_to(10),
                 "sim shmem ceiling rejected allowed candidate");
    require_bool(!crucible_sim_shmem_may_advance_to(11),
                 "sim shmem ceiling allowed candidate past max_advance_icount");
    require_bool(crucible_sim_shmem_clamp_cpu_budget(8, 100) == 2,
                 "sim shmem budget was not clamped to remaining ceiling");
    require_bool(crucible_sim_shmem_clamp_cpu_budget(10, 100) == 0,
                 "sim shmem budget did not park at the ceiling");

    puts("PASS");
    puts("stock_negative_control=true");
    puts("sim_loop_bookkeeping_microtest=true");
    puts("sim_first_exit_microtest=true");
    puts("sim_skip_second_events_microtest=true");
    puts("sim_second_events_lifecycle_work_microtest=true");
    puts("sim_block_wake_coqueue_microtest=true");
    puts("sim_block_prepark_wake_not_lost=true");
    puts("sim_block_wake_failure_fails_waiter=true");
    puts("sim_idle_callbacks_missed_wake_microtest=true");
    puts("sim_idle_advance_completion_barrier_microtest=true");
    puts("sim_idle_advance_rearms_while_halted=true");
    puts("sim_shmem_dispatch_inert_without_callbacks=true");
    puts("sim_shmem_dispatch_ceiling_microtest=true");
    puts("sim_shmem_budget_clamp_microtest=true");
    return 0;
}
