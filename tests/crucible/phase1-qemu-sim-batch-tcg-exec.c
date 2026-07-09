#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EXCP_DEBUG 0x10002
#define EXCP_HALTED 0x10003
#define EXCP_ATOMIC 0x10004
#define EXCP_NONE 0
#define RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT 4

typedef struct CPUState {
    bool can_run;
    bool work_pending;
    int exit_request;
    bool stop;
    bool unplug;
} CPUState;

typedef struct Trace {
    uint64_t icounts[16];
    unsigned int len;
    unsigned int outer_iterations;
    unsigned int timer_runs;
    unsigned int main_loop_waits;
} Trace;

static bool fixture_sim_mode;
static bool fixture_shmem_dispatch_registered;
static int fixture_cpu_count;
static unsigned int fixture_batch_limit;
static unsigned int fixture_timer_runs;
static unsigned int fixture_budget_refreshes;
static unsigned int fixture_main_loop_waits;
static unsigned int fixture_guest_debugs;
static unsigned int fixture_atomic_steps;
static unsigned int fixture_exec_callbacks;
static unsigned int fixture_publish_calls;
static uint64_t fixture_current_icount;
static uint64_t fixture_max_advance_icount;
static int64_t fixture_next_budget;
static const int *fixture_exits;
static const uint64_t *fixture_deltas;
static unsigned int fixture_exit_count;
static unsigned int fixture_exit_index;
static Trace *fixture_trace;

static void require_bool(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static bool rr_crucible_sim_mode(void)
{
    return fixture_sim_mode;
}

static bool cpu_can_run(CPUState *cpu)
{
    return cpu != NULL && cpu->can_run;
}

static bool cpu_work_list_empty(CPUState *cpu)
{
    return cpu != NULL && !cpu->work_pending;
}

static bool icount_enabled(void)
{
    return true;
}

static void bql_unlock(void)
{
}

static void bql_lock(void)
{
}

static void replay_mutex_lock(void)
{
}

static void replay_mutex_unlock(void)
{
}

static void icount_account_warp_timer(void)
{
}

static void qemu_clock_run_timers(int clock)
{
    (void)clock;
    fixture_timer_runs++;
}

static void icount_handle_deadline(void)
{
}

static int rr_cpu_count(void)
{
    return fixture_cpu_count;
}

static int64_t icount_percpu_budget(int cpu_count)
{
    (void)cpu_count;
    return fixture_next_budget;
}

static void icount_prepare_for_run(CPUState *cpu, int64_t cpu_budget)
{
    (void)cpu;
    require_bool(cpu_budget > 0, "tcg exec prepared with empty budget");
}

static int tcg_cpu_exec(CPUState *cpu)
{
    uint64_t delta;
    int exit_reason;

    require_bool(cpu_can_run(cpu), "tcg exec ran a CPU that cannot run");
    require_bool(fixture_exit_index < fixture_exit_count,
                 "tcg exec consumed past the fixture sequence");

    delta = fixture_deltas[fixture_exit_index];
    exit_reason = fixture_exits[fixture_exit_index];
    fixture_exit_index++;
    fixture_current_icount += delta;
    if (fixture_exit_index == fixture_exit_count) {
        cpu->exit_request = 1;
    }

    if (fixture_trace != NULL) {
        require_bool(fixture_trace->len < 16, "trace fixture overflowed");
        fixture_trace->icounts[fixture_trace->len] = fixture_current_icount;
        fixture_trace->len++;
    }

    return exit_reason;
}

static void icount_process_data(CPUState *cpu)
{
    (void)cpu;
}

static bool crucible_sim_shmem_dispatch_registered(void)
{
    return fixture_shmem_dispatch_registered;
}

static uint64_t qemu_plugin_icount_raw(void)
{
    return fixture_current_icount;
}

static void crucible_sim_shmem_publish_current_icount(uint64_t current_icount)
{
    fixture_publish_calls++;
    fixture_current_icount = current_icount;
}

static uint64_t crucible_sim_shmem_max_advance_icount(void)
{
    return fixture_max_advance_icount;
}

static int64_t crucible_sim_shmem_clamp_cpu_budget(uint64_t current_icount,
                                                   int64_t cpu_budget)
{
    uint64_t remaining;

    if (cpu_budget <= 0) {
        return cpu_budget;
    }
    if (current_icount >= crucible_sim_shmem_max_advance_icount()) {
        return 0;
    }

    remaining = crucible_sim_shmem_max_advance_icount() - current_icount;
    if ((uint64_t)cpu_budget <= remaining) {
        return cpu_budget;
    }
    return (int64_t)remaining;
}

static void qemu_plugin_main_loop_wait(void)
{
    fixture_main_loop_waits++;
}

static void qemu_plugin_maybe_fire_tcg_exec_cb(CPUState *cpu)
{
    (void)cpu;
    fixture_exec_callbacks++;
}

static void cpu_handle_guest_debug(CPUState *cpu)
{
    (void)cpu;
    fixture_guest_debugs++;
}

static void cpu_exec_step_atomic(CPUState *cpu)
{
    (void)cpu;
    fixture_atomic_steps++;
}

static unsigned int rr_crucible_sim_tcg_batch_limit(void)
{
    if (!rr_crucible_sim_mode() || rr_cpu_count() > 1) {
        return 1;
    }
    return fixture_batch_limit;
}

static bool rr_crucible_sim_tcg_batch_continue(CPUState *cpu,
                                               unsigned int runs,
                                               int last_exit)
{
    if (!rr_crucible_sim_mode() ||
        runs >= rr_crucible_sim_tcg_batch_limit()) {
        return false;
    }

    if (last_exit == EXCP_HALTED ||
        last_exit == EXCP_DEBUG ||
        last_exit == EXCP_ATOMIC) {
        return false;
    }

    return cpu &&
           cpu_can_run(cpu) &&
           cpu_work_list_empty(cpu) &&
           !cpu->exit_request &&
           !cpu->stop &&
           !cpu->unplug;
}

static void rr_crucible_sim_refresh_batch_budget(int64_t *cpu_budget)
{
    int cpu_count;

    if (!icount_enabled()) {
        return;
    }

    bql_unlock();
    replay_mutex_lock();
    bql_lock();

    icount_account_warp_timer();
    qemu_clock_run_timers(0);
    icount_handle_deadline();
    cpu_count = rr_cpu_count();
    *cpu_budget = icount_percpu_budget(cpu_count);
    fixture_budget_refreshes++;

    replay_mutex_unlock();
}

static bool rr_crucible_sim_run_tcg_batch(CPUState *cpu, int64_t *cpu_budget)
{
    unsigned int runs = 0;

    while (true) {
        int r;

        if (rr_crucible_sim_mode() &&
            crucible_sim_shmem_dispatch_registered()) {
            uint64_t current_icount = qemu_plugin_icount_raw();

            *cpu_budget = crucible_sim_shmem_clamp_cpu_budget(current_icount,
                                                              *cpu_budget);
            if (*cpu_budget == 0) {
                crucible_sim_shmem_publish_current_icount(current_icount);
                qemu_plugin_main_loop_wait();
                return true;
            }
        }

        bql_unlock();
        if (icount_enabled()) {
            icount_prepare_for_run(cpu, *cpu_budget);
        }
        r = tcg_cpu_exec(cpu);
        if (icount_enabled()) {
            icount_process_data(cpu);
        }
        if (rr_crucible_sim_mode() &&
            crucible_sim_shmem_dispatch_registered()) {
            crucible_sim_shmem_publish_current_icount(qemu_plugin_icount_raw());
        }
        qemu_plugin_maybe_fire_tcg_exec_cb(cpu);
        bql_lock();

        runs++;

        if (r == EXCP_DEBUG) {
            cpu_handle_guest_debug(cpu);
            return true;
        } else if (r == EXCP_ATOMIC) {
            bql_unlock();
            cpu_exec_step_atomic(cpu);
            bql_lock();
            return true;
        } else if (r == EXCP_HALTED) {
            return false;
        }

        if (!rr_crucible_sim_tcg_batch_continue(cpu, runs, r)) {
            return false;
        }

        rr_crucible_sim_refresh_batch_budget(cpu_budget);
    }
}

static void reset_fixture(const int *exits, const uint64_t *deltas,
                          unsigned int count)
{
    fixture_sim_mode = true;
    fixture_shmem_dispatch_registered = false;
    fixture_cpu_count = 1;
    fixture_batch_limit = RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT;
    fixture_timer_runs = 0;
    fixture_budget_refreshes = 0;
    fixture_main_loop_waits = 0;
    fixture_guest_debugs = 0;
    fixture_atomic_steps = 0;
    fixture_exec_callbacks = 0;
    fixture_publish_calls = 0;
    fixture_current_icount = 0;
    fixture_max_advance_icount = UINT64_MAX;
    fixture_next_budget = 10;
    fixture_exits = exits;
    fixture_deltas = deltas;
    fixture_exit_count = count;
    fixture_exit_index = 0;
    fixture_trace = NULL;
}

static void run_trace(unsigned int batch_limit, Trace *trace)
{
    static const int exits[] = {
        EXCP_NONE, EXCP_NONE, EXCP_NONE, EXCP_NONE, EXCP_NONE, EXCP_NONE,
    };
    static const uint64_t deltas[] = {1, 2, 1, 3, 1, 2};
    CPUState cpu = {.can_run = true};

    reset_fixture(exits, deltas, 6);
    fixture_batch_limit = batch_limit;
    fixture_trace = trace;

    while (fixture_exit_index < fixture_exit_count) {
        int64_t cpu_budget = fixture_next_budget;

        trace->outer_iterations++;
        (void)rr_crucible_sim_run_tcg_batch(&cpu, &cpu_budget);
    }
    trace->timer_runs = fixture_timer_runs;
    trace->main_loop_waits = fixture_main_loop_waits;
}

static bool traces_match(const Trace *left, const Trace *right)
{
    unsigned int index;

    if (left->len != right->len) {
        return false;
    }
    for (index = 0; index < left->len; index++) {
        if (left->icounts[index] != right->icounts[index]) {
            return false;
        }
    }
    return true;
}

int main(void)
{
    static const int halted_exits[] = {EXCP_NONE, EXCP_HALTED, EXCP_NONE};
    static const int debug_exits[] = {EXCP_DEBUG, EXCP_NONE};
    static const int atomic_exits[] = {EXCP_ATOMIC, EXCP_NONE};
    static const int ceiling_exits[] = {EXCP_NONE, EXCP_NONE, EXCP_NONE};
    static const uint64_t small_deltas[] = {1, 1, 1};
    static const uint64_t ceiling_deltas[] = {2, 1, 1};
    Trace batch_off = {0};
    Trace batch_on = {0};
    CPUState cpu = {.can_run = true};
    int64_t cpu_budget;

    fixture_sim_mode = true;
    fixture_cpu_count = 1;
    fixture_batch_limit = RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT;
    require_bool(rr_crucible_sim_tcg_batch_limit() == 4,
                 "single-vCPU sim batch limit is not the fixed TCG batch size");
    fixture_cpu_count = 2;
    require_bool(rr_crucible_sim_tcg_batch_limit() == 1,
                 "multi-vCPU sim mode did not retain one tcg exec per RR slot");
    fixture_sim_mode = false;
    fixture_cpu_count = 1;
    require_bool(rr_crucible_sim_tcg_batch_limit() == 1,
                 "non-sim mode did not retain one tcg exec per loop");

    run_trace(1, &batch_off);
    run_trace(RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT, &batch_on);
    require_bool(traces_match(&batch_off, &batch_on),
                 "batching changed the icount trace");
    require_bool(batch_on.outer_iterations < batch_off.outer_iterations,
                 "batching did not reduce outer loop iterations");
    require_bool(batch_on.timer_runs == batch_on.len - batch_on.outer_iterations,
                 "virtual timers did not run between batched TCG slots");
    require_bool(batch_on.main_loop_waits == 0,
                 "batching waited on the main loop without a shmem ceiling");

    reset_fixture(halted_exits, small_deltas, 3);
    cpu_budget = fixture_next_budget;
    require_bool(!rr_crucible_sim_run_tcg_batch(&cpu, &cpu_budget),
                 "EXCP_HALTED did not return to the RR handoff");
    require_bool(fixture_exit_index == 2,
                 "EXCP_HALTED did not stop before the next fixture exec");

    reset_fixture(debug_exits, small_deltas, 2);
    cpu_budget = fixture_next_budget;
    require_bool(rr_crucible_sim_run_tcg_batch(&cpu, &cpu_budget),
                 "EXCP_DEBUG did not break the batch");
    require_bool(fixture_guest_debugs == 1,
                 "EXCP_DEBUG did not dispatch guest debug handling");
    require_bool(fixture_exit_index == 1,
                 "EXCP_DEBUG did not stop the batch immediately");

    reset_fixture(atomic_exits, small_deltas, 2);
    cpu_budget = fixture_next_budget;
    require_bool(rr_crucible_sim_run_tcg_batch(&cpu, &cpu_budget),
                 "EXCP_ATOMIC did not break the batch");
    require_bool(fixture_atomic_steps == 1,
                 "EXCP_ATOMIC did not dispatch atomic stepping");
    require_bool(fixture_exit_index == 1,
                 "EXCP_ATOMIC did not stop the batch immediately");

    reset_fixture(ceiling_exits, ceiling_deltas, 3);
    fixture_shmem_dispatch_registered = true;
    fixture_max_advance_icount = 3;
    cpu_budget = fixture_next_budget;
    require_bool(rr_crucible_sim_run_tcg_batch(&cpu, &cpu_budget),
                 "shmem ceiling did not park the batch");
    require_bool(fixture_exit_index == 2,
                 "shmem ceiling allowed execution past max_advance_icount");
    require_bool(fixture_main_loop_waits == 1,
                 "shmem ceiling did not wait for scheduler wake");
    require_bool(fixture_publish_calls >= 3,
                 "shmem ceiling did not publish current icount at boundaries");

    puts("PASS");
    puts("stock_negative_control=true");
    puts("sim_batch_tcg_exec_single_vcpu_fixed_limit=true");
    puts("sim_batch_tcg_exec_multivcpu_limit_guard=true");
    puts("sim_batch_tcg_exec_on_off_icount_trace_identical=true");
    puts("sim_batch_tcg_exec_halted_returns_to_rr_handoff=true");
    puts("sim_batch_tcg_exec_breaks_on_debug_atomic=true");
    puts("sim_batch_tcg_exec_timer_between_slots=true");
    puts("sim_batch_tcg_exec_shmem_ceiling_guard=true");
    return 0;
}
