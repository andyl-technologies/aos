//! Checks clock-domain conversion against genuine physical scheduler receipts.
//!
//! These physical and arithmetic components create no Source, semantic Original,
//! native borrower, completed work unit or next-idle completion witness.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_shmem::NodeSlot;

#[test]
fn actual_prepared_command_preserves_logical_bias_and_rounds_raw_ceiling_down() {
    let ticks = crucible_engine::SIM_TICKS_PER_INSTRUCTION;
    for bias in [0, 1, ticks - 1, ticks + 7] {
        for remaining in [0, 1, ticks - 1, ticks, ticks + 1, 7 * ticks - 1] {
            let slot = NodeSlot::default();
            let raw = 11;
            let current = raw * ticks + bias;
            slot.publish_pause_quiesced(current, raw).unwrap();
            let before = slot.snapshot();
            let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();
            let generation = prepared.generation();

            let (result, counts) = TestAllocationObserver::count(|| {
                command_coordinates(
                    &prepared,
                    current + remaining,
                    crate::QemuQuantumStopCondition::Ceiling,
                    23,
                )
            });

            let command = result.unwrap();
            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert!(!counts.overflow);
            assert_eq!(command.scheduler_generation, generation);
            assert_eq!(command.initial_raw_icount, raw);
            assert_eq!(command.maximum_raw_icount, raw + remaining / ticks);
            assert_eq!(command.logical_tick_ceiling, current + remaining);
            assert_eq!(command.native_monotonic_ns_ceiling, 0);
            assert_eq!(command.frontier, 23);
            assert_eq!(command.stop, PublisherStopMode::RetiredCeiling);
            assert!(bias + command.maximum_raw_icount * ticks <= current + remaining);
            assert!(bias + (command.maximum_raw_icount + 1) * ticks > current + remaining);

            drop(prepared);
            let after = slot.snapshot();
            assert_eq!(after.current_icount, before.current_icount);
            assert_eq!(after.max_advance_icount, before.max_advance_icount);
            assert_eq!(after.wake_signal, before.wake_signal);
            assert_eq!(after.advance_publication_sequence, generation);
        }
    }
}

#[test]
fn actual_prepared_command_refuses_a_ceiling_before_entry_without_allocation_or_wake() {
    let slot = NodeSlot::default();
    let current = 13 * crucible_engine::SIM_TICKS_PER_INSTRUCTION + 3;
    slot.publish_pause_quiesced(current, 13).unwrap();
    let before = slot.snapshot();
    let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();

    let (result, counts) = TestAllocationObserver::count(|| {
        command_coordinates(
            &prepared,
            current - 1,
            crate::QemuQuantumStopCondition::Ceiling,
            0,
        )
    });

    assert_eq!(result, Err(HostSupervisionError::InvalidBudget));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    drop(prepared);
    let after = slot.snapshot();
    assert_eq!(after.max_advance_icount, before.max_advance_icount);
    assert_eq!(after.wake_signal, before.wake_signal);
}

#[test]
fn next_idle_target_names_the_fresh_reservation_without_claiming_a_completion() {
    let slot = NodeSlot::default();
    let previous = slot.reserve_scheduler_advance().unwrap();
    let old_generation = previous.generation();
    drop(previous);
    let prepared = slot.observe_scheduler_advance().unwrap().reserve().unwrap();

    let command = command_coordinates(
        &prepared,
        100,
        crate::QemuQuantumStopCondition::NextAuthenticatedIdle,
        0,
    )
    .unwrap();

    assert_eq!(command.scheduler_generation, old_generation + 2);
    assert_eq!(
        command.stop,
        PublisherStopMode::NextIdle {
            target_generation: old_generation + 2,
        }
    );
    drop(prepared);
    assert_eq!(slot.snapshot().current_icount, 0);
    assert_eq!(slot.snapshot().wake_signal, 0);
}

#[test]
fn native_ceiling_includes_every_present_end_in_every_planned_row() {
    for count in 1..=4 {
        for row in 0..count {
            for field in 0..4 {
                let mut cohort = super::super::tests::current().observation;
                cohort.row_count = count;
                for parent in &mut cohort.parents[..count as usize] {
                    parent.total_end_ns = 800;
                    parent.progress_end_ns = 900;
                    parent.outer_end_ns = 1000;
                    parent.private_end_ns = 1100;
                }
                let parent = &mut cohort.parents[row as usize];
                match field {
                    0 => parent.total_end_ns = 17,
                    1 => parent.progress_end_ns = 17,
                    2 => parent.outer_end_ns = 17,
                    3 => parent.private_end_ns = 17,
                    _ => unreachable!(),
                }
                assert_eq!(
                    native_ceiling(&cohort).unwrap(),
                    17,
                    "rows {count}, row {row}, end {field}"
                );
                cohort.cohort_current = false;
                assert_eq!(
                    native_ceiling(&cohort),
                    Err(HostSupervisionError::Unavailable)
                );
            }
        }
    }
    let mut absent = super::super::tests::current().observation;
    assert_eq!(native_ceiling(&absent).unwrap(), 0);
    absent.row_count = 0;
    assert_eq!(
        native_ceiling(&absent),
        Err(HostSupervisionError::Unavailable)
    );
    absent.row_count = 5;
    assert_eq!(
        native_ceiling(&absent),
        Err(HostSupervisionError::Unavailable)
    );
}
