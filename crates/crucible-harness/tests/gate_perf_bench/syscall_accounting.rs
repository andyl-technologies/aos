//! Verifies the advance-path arithmetic kernel-entry model and its errors.

use crucible_harness::perf::{
    PerfBenchError, advance_syscall_count, canonical_perf_bench_input, run_perf_bench_gate,
};

/// [PERF-8] - the advance path has no per-quantum socket/control round trips and
/// accounts for every current host/plugin futex and eventfd category separately.
#[test]
fn advance_path_accounts_for_futex_and_eventfd_kernel_entries() {
    let count = advance_syscall_count(10_000, 8, 4, 5, 3, 2, 6);
    assert_eq!(count.per_quantum_socket_control_round_trips, 0);
    assert_eq!(count.futex_ceiling_wakes, count.quanta);
    assert_eq!(count.futex_wait_calls, 8);
    assert_eq!(count.futex_service_release_wakes, 4);
    assert_eq!(count.futex_delivery_wakes, 5);
    assert_eq!(count.futex_wake_wait, count.quanta + 8 + 4 + 5);
    assert_eq!(count.eventfd_quantum_wake_writes, count.quanta);
    assert_eq!(count.eventfd_wake_writes, count.quanta + 3 + 2);
    assert_eq!(count.eventfd_unchanged_icount_wake_writes, 3);
    assert_eq!(count.eventfd_service_wake_writes, 2);
    assert_eq!(count.host_poll_sleep_calls, 6);

    let report = run_perf_bench_gate(&canonical_perf_bench_input()).expect("gate must pass");
    assert_eq!(report.advance_syscalls, count);
}

#[test]
fn kernel_entry_accounting_error_is_truthful() {
    let error = PerfBenchError::AdvanceKernelEntryAccounting {
        entry: "delivery futex wake",
        expected: 5,
        actual: 4,
    };
    assert_eq!(
        error.to_string(),
        "advance-path delivery futex wake bookkeeping expected 5, found 4"
    );
}
