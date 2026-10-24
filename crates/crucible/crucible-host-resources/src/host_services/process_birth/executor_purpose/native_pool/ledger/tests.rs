//! Pure accounting refusals, not authenticated Main/Source issuance controls.

// SPDX-License-Identifier: Apache-2.0

use super::*;

fn ceiling() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 1000,
        backing_peak_bytes: 1000,
        metadata_bytes: 200,
        staging_bytes: 100,
        cpu_slots: 4,
        task_slots: 20,
        file_descriptors: 64,
        paging_io_slots: 10,
    }
}

fn requests() -> [NativeNodeReservation; 2] {
    [
        NativeNodeReservation {
            node: [1; 32],
            source_host_descriptors: 5,
            target_host_descriptors: 7,
            resources: HostResourceVector {
                resident_peak_bytes: 100,
                backing_peak_bytes: 200,
                metadata_bytes: 30,
                staging_bytes: 10,
                cpu_slots: 1,
                task_slots: 3,
                file_descriptors: 8,
                paging_io_slots: 2,
            },
        },
        NativeNodeReservation {
            node: [2; 32],
            source_host_descriptors: 6,
            target_host_descriptors: 8,
            resources: HostResourceVector {
                resident_peak_bytes: 150,
                backing_peak_bytes: 300,
                metadata_bytes: 50,
                staging_bytes: 20,
                cpu_slots: 2,
                task_slots: 4,
                file_descriptors: 12,
                paging_io_slots: 3,
            },
        },
    ]
}

#[test]
fn distinct_node_payloads_and_controls_conserve_all_axes() {
    let controls = HostResourceVector {
        resident_peak_bytes: 8,
        metadata_bytes: 8,
        ..HostResourceVector::default()
    };
    let (sum, windows) = checked_selection(ceiling(), controls, &requests()).unwrap();

    assert_eq!(
        sum,
        HostResourceVector {
            resident_peak_bytes: 258,
            backing_peak_bytes: 500,
            metadata_bytes: 88,
            staging_bytes: 30,
            cpu_slots: 3,
            task_slots: 7,
            file_descriptors: 46,
            paging_io_slots: 5,
        }
    );
    assert_eq!(windows, 26);
}

#[test]
fn one_short_on_any_aggregate_axis_refuses_the_whole_selection() {
    let (sum, _) =
        checked_selection(ceiling(), HostResourceVector::default(), &requests()).unwrap();
    macro_rules! short {
        ($($axis:ident),+ $(,)?) => {$(
            let mut limit = ceiling();
            limit.$axis = sum.$axis - 1;
            assert!(checked_selection(limit, HostResourceVector::default(), &requests()).is_err(), stringify!($axis));
        )+};
    }
    short!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        cpu_slots,
        task_slots,
        file_descriptors,
        paging_io_slots
    );
}

#[test]
fn duplicate_or_unordered_nodes_and_unfunded_landings_refuse() {
    let mut nodes = requests();
    nodes[1].node = nodes[0].node;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());

    let mut nodes = requests();
    nodes.swap(0, 1);
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());

    let mut nodes = requests();
    nodes[0].target_host_descriptors = 0;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());
}

#[test]
fn overflow_never_becomes_an_additional_pool_allowance() {
    let used = HostResourceVector {
        resident_peak_bytes: u64::MAX,
        ..HostResourceVector::default()
    };
    assert!(checked_selection(ceiling(), used, &requests()).is_err());

    let mut nodes = requests();
    nodes[0].source_host_descriptors = u64::MAX;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());
}

#[test]
fn concurrent_world_template_and_replay_selections_share_one_ceiling() {
    let mut limit = ceiling();
    limit.cpu_slots = 3;
    let request = [requests()[0]];
    let initial = HostResourceVector::default();
    let (world, _) = checked_selection(limit, initial, &request).unwrap();
    let (template, _) = checked_selection(limit, world, &request).unwrap();
    let (replay, _) = checked_selection(limit, template, &request).unwrap();

    assert_eq!(replay.cpu_slots, 3);
    assert_eq!(replay.resident_peak_bytes, 300);
    assert_eq!(replay.file_descriptors, 60);
    assert!(checked_selection(limit, replay, &request).is_err());
}

#[test]
fn node_count_is_not_the_private_four_worker_roster_width() {
    let mut limit = ceiling();
    limit.cpu_slots = 6;
    limit.file_descriptors = 120;
    limit.paging_io_slots = 12;
    let nodes: [_; 6] = std::array::from_fn(|index| {
        let mut request = requests()[0];
        request.node = [u8::try_from(index + 1).unwrap(); 32];
        request.resources.backing_peak_bytes = 100;
        request
    });
    let (sum, peak) = checked_selection(limit, HostResourceVector::default(), &nodes).unwrap();

    assert_eq!(sum.cpu_slots, 6);
    assert_eq!(sum.file_descriptors, 120);
    assert_eq!(peak, 72);
}

#[test]
fn containing_control_geometry_refuses_before_root_publication() {
    let mut limit = ceiling();
    limit.resident_peak_bytes = u64::MAX;
    limit.metadata_bytes = u64::MAX;
    assert!(super::super::checked_layout(limit, u64::MAX, 1).is_err());

    limit.metadata_bytes = 1;
    assert!(super::super::checked_layout(limit, 0, 1).is_err());
}

#[test]
fn shared_and_node_landings_share_the_same_descriptor_ceiling() {
    let shared = HostResourceVector {
        file_descriptors: 19,
        ..HostResourceVector::default()
    };
    // 19 shared + 20 native tables + 26 Main landings is one over 64.
    assert!(checked_selection(ceiling(), shared, &requests()).is_err());
    let fitting = HostResourceVector {
        file_descriptors: 18,
        ..shared
    };
    let (used, _) = checked_selection(ceiling(), fitting, &requests()).unwrap();
    assert_eq!(used.file_descriptors, 64);
}

#[test]
fn simultaneous_world_containing_bodies_share_the_same_bank() {
    let limit = ceiling();
    let used = charge_world_controls(limit, HostResourceVector::default(), 100).unwrap();
    let used = charge_world_controls(limit, used, 100).unwrap();

    assert_eq!(used.resident_peak_bytes, 200);
    assert_eq!(used.metadata_bytes, 200);
    assert!(charge_world_controls(limit, used, 1).is_err());
    assert_eq!(
        subtract(
            used,
            HostResourceVector {
                resident_peak_bytes: 100,
                metadata_bytes: 100,
                ..HostResourceVector::default()
            }
        )
        .unwrap(),
        charge_world_controls(limit, HostResourceVector::default(), 100).unwrap()
    );
}

#[test]
fn permanent_worker_controls_compete_with_every_world_without_a_second_bank() {
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    assert!(ledger.reserve_worker_controls(0).is_err());
    assert_eq!(ledger.used, initial);
    assert!(ledger.reserve_worker_controls(201).is_err());
    assert_eq!(ledger.used, initial);
    ledger.reserve_worker_controls(112).unwrap();
    assert_eq!(ledger.used.metadata_bytes, 120);
    assert_eq!(ledger.used.resident_peak_bytes, 120);
    assert_eq!(ledger.used.file_descriptors, 3);
    let (whole, _) = checked_selection(ceiling(), ledger.used, &requests()).unwrap();
    assert_eq!(whole.metadata_bytes, 200);
    assert!(charge_world_controls(ceiling(), whole, 1).is_err());
    let used = ledger.used;
    assert!(ledger.reserve_worker_controls(1).is_err());
    assert_eq!(ledger.used, used);
}

fn selected_ledger_with_supervisor() -> (
    PoolLedger,
    u64,
    crate::host_supervision::HostOperationSupervisor,
) {
    use crate::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let (epoch, _, _) = ledger
        .assign(
            NativeWorldIdentity {
                owner: [1; 32],
                selection: [2; 32],
            },
            &requests(),
            16,
            &original,
        )
        .unwrap();
    let window = crate::host_services::HostServiceAllocator::new(1, 26, 1)
        .unwrap()
        .reserve_resources(0, 26, 0)
        .unwrap();
    ledger.bind_window(epoch, window).unwrap();
    (ledger, epoch, supervisor)
}

fn selected_ledger() -> (PoolLedger, u64) {
    let (ledger, epoch, _) = selected_ledger_with_supervisor();
    (ledger, epoch)
}

fn ready_return(ledger: &PoolLedger, epoch: u64) -> (usize, HostResourceVector, u64, u64) {
    match ledger.prepare_world_return(epoch).unwrap() {
        WorldReturnPreparation::Ready {
            index,
            used,
            peak,
            tables,
        } => (index, used, peak, tables),
        WorldReturnPreparation::PendingBody => {
            panic!("actual containing-body custody is still open")
        }
    }
}

#[test]
fn never_born_return_keeps_body_debt_until_explicit_owner_destruction() {
    let (mut ledger, epoch) = selected_ledger();
    let charged = ledger.used;
    ledger.take_consumer(epoch).unwrap();

    ledger.verify_never_born(epoch).unwrap();
    assert!(matches!(
        ledger.prepare_world_return(epoch).unwrap(),
        WorldReturnPreparation::PendingBody
    ));
    assert_eq!(ledger.used, charged);
    assert!(ledger.verify_never_born(epoch + 1).is_err());

    ledger.close_consumer(epoch).unwrap();
    let (index, remaining, windows, tables) = ready_return(&ledger, epoch);
    assert_eq!(windows, 26);
    assert_eq!(tables, 20);
    assert_eq!(remaining.metadata_bytes, 8);
    assert_eq!(remaining.resident_peak_bytes, 8);
    assert_eq!(remaining.file_descriptors, 3);
    assert_eq!(ledger.used, charged);

    ledger.commit_world_return(index, epoch, remaining);
    assert_eq!(ledger.used, remaining);
    assert!(ledger.prepare_world_return(epoch).is_err());
    assert!(ledger.verify_never_born(epoch).is_err());
}

#[test]
fn actual_node_entry_cannot_become_never_born_after_physical_return() {
    let (mut ledger, epoch) = selected_ledger();
    ledger.verify_never_born(epoch).unwrap();

    let (index, assignment) = ledger.take_node(epoch, requests()[0].node).unwrap();
    assert!(ledger.verify_never_born(epoch).is_err());
    let charged = ledger.used;
    assert!(
        ledger
            .prepare_node_return(epoch, assignment + 1, index)
            .is_err()
    );
    assert_eq!(ledger.used, charged);
    let prepared = ledger
        .prepare_node_return(epoch, assignment, index)
        .unwrap();
    assert_eq!(ledger.used, charged);
    ledger.commit_node_return(prepared);
    assert!(ledger.verify_never_born(epoch).is_err());
    assert_eq!(ledger.unissued_node_count(epoch).unwrap(), 1);
}

mod pending_worlds;

#[test]
fn cleanup_verification_reads_only_the_exact_latched_guard() {
    use crate::host_supervision::HostOperationClass;

    let (ledger, epoch, supervisor) = selected_ledger_with_supervisor();
    let foreign = Arc::new(
        supervisor
            .begin_control(HostOperationClass::Cleanup)
            .unwrap(),
    );
    assert!(ledger.saved_cleanup(epoch).is_err());
    assert!(ledger.verify_cleanup(epoch, &foreign).is_err());
    assert!(
        ledger
            .worlds
            .iter()
            .flatten()
            .all(|world| world.cleanup.get().is_none())
    );

    let saved = ledger.retained_cleanup(epoch).unwrap();
    assert!(!Arc::ptr_eq(&saved, &foreign));
    assert!(ledger.verify_cleanup(epoch, &foreign).is_err());
    assert!(ledger.verify_cleanup(epoch + 1, &saved).is_err());
    ledger.verify_cleanup(epoch, &saved).unwrap();
    assert!(Arc::ptr_eq(&saved, &ledger.saved_cleanup(epoch).unwrap()));

    let original = Arc::clone(&ledger.worlds.iter().flatten().next().unwrap()._original);
    ledger.verify_world_original(epoch, &original).unwrap();
    let other = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    assert!(ledger.verify_world_original(epoch, &other).is_err());
}

#[test]
fn terminal_local_parent_keeps_same_cleanup_but_cannot_admit_work() {
    use crate::host_supervision::HostOperationClass;

    // This is a local supervisor/ledger control, not authenticated Main issuance.
    let (ledger, epoch, supervisor) = selected_ledger_with_supervisor();
    let original = Arc::clone(&ledger.worlds.iter().flatten().next().unwrap()._original);
    let saved = ledger.retained_cleanup(epoch).unwrap();
    supervisor.cancel().unwrap();

    assert!(
        original
            .verify_operation_class(HostOperationClass::Preparation)
            .is_err()
    );
    assert!(supervisor.begin(HostOperationClass::Preparation).is_err());
    ledger.verify_cleanup(epoch, &saved).unwrap();
    assert!(Arc::ptr_eq(
        &saved,
        &ledger.retained_cleanup(epoch).unwrap()
    ));
    assert_eq!(
        ready_return_after_body_close(ledger, epoch)
            .1
            .file_descriptors,
        3
    );
}

fn ready_return_after_body_close(
    mut ledger: PoolLedger,
    epoch: u64,
) -> (usize, HostResourceVector, u64, u64) {
    ledger.take_consumer(epoch).unwrap();
    ledger.close_consumer(epoch).unwrap();
    ready_return(&ledger, epoch)
}

#[test]
fn first_cleanup_admission_refusal_is_not_replaced_after_capacity_returns() {
    use crate::host_supervision::{HostOperationClass, HostSupervisionError, MAX_HOST_OPERATIONS};

    let (ledger, epoch, supervisor) = selected_ledger_with_supervisor();
    let blockers: Vec<_> = (1..MAX_HOST_OPERATIONS)
        .map(|_| {
            supervisor
                .begin_control(HostOperationClass::Cleanup)
                .unwrap()
        })
        .collect();
    assert!(ledger.retained_cleanup(epoch).is_err());
    let world = ledger.worlds.iter().flatten().next().unwrap();
    assert!(matches!(
        world.cleanup.get(),
        Some(Err(HostSupervisionError::CapacityExhausted))
    ));

    drop(blockers);
    let available = supervisor
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    assert!(ledger.retained_cleanup(epoch).is_err());
    assert!(matches!(
        world.cleanup.get(),
        Some(Err(HostSupervisionError::CapacityExhausted))
    ));
    assert!(ledger.verify_cleanup(epoch, &Arc::new(available)).is_err());
}

#[test]
fn committed_return_preserves_post_refusal_without_a_second_subtraction() {
    use crate::host_supervision::HostOperationClass;

    let (mut ledger, epoch) = selected_ledger();
    let saved = ledger.retained_cleanup(epoch).unwrap();
    ledger.take_consumer(epoch).unwrap();
    ledger.close_consumer(epoch).unwrap();
    let (index, remaining, _, _) = ready_return(&ledger, epoch);
    ledger.commit_world_return(index, epoch, remaining);

    // Real operation completion makes the independent post refuse. The pure
    // ledger commit models no kernel write or authenticated resource issuance.
    saved.complete().unwrap();
    let report = NativePoolReturnError::finish(
        Ok(()),
        saved.verify_operation_class(HostOperationClass::Cleanup),
    )
    .unwrap_err();
    assert!(report.first_error().is_none());
    assert!(report.post_error().is_some());
    assert_eq!(ledger.used, remaining);
    assert!(ledger.prepare_world_return(epoch).is_err());
    assert_eq!(ledger.used, remaining);

    let report = NativePoolReturnError::finish::<()>(
        Err(ServiceBirthError::policy("actual retained work refusal")),
        saved.verify_operation_class(HostOperationClass::Cleanup),
    )
    .unwrap_err();
    assert!(report.first_error().is_some());
    assert!(report.post_error().is_some());
    assert_eq!(ledger.used, remaining);
}

#[test]
fn cleanup_arc_geometry_is_included_once_per_finite_world_cell() {
    let (cleanup, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<HostOperationGuard>())
    .unwrap();
    let per_cell = cleanup.pad_to_align().size()
        + std::mem::size_of::<Option<WorldSlot>>()
        + std::mem::size_of::<Option<NodeSlot>>()
        + std::mem::size_of::<NativeNodeReservation>();
    assert_eq!(
        super::super::structure_bytes(2).unwrap() - super::super::structure_bytes(1).unwrap(),
        u64::try_from(per_cell).unwrap(),
    );
    assert!(super::super::structure_bytes(usize::MAX).is_err());
}

#[test]
fn absent_row_requires_a_published_epoch_and_survives_exact_cell_reuse() {
    let (mut ledger, epoch) = selected_ledger();
    assert!(ledger.observe_world_returned(0).is_err());
    assert!(ledger.observe_world_returned(epoch + 1).is_err());
    assert!(!ledger.observe_world_returned(epoch).unwrap());
    ledger.take_consumer(epoch).unwrap();
    ledger.close_consumer(epoch).unwrap();
    let (index, remaining, _, _) = ready_return(&ledger, epoch);
    ledger.commit_world_return(index, epoch, remaining);
    assert!(ledger.observe_world_returned(epoch).unwrap());

    let supervisor = crate::host_supervision::HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets::default(),
        None,
    )
    .unwrap();
    let original = Arc::new(
        supervisor
            .begin(crate::host_supervision::HostOperationClass::Preparation)
            .unwrap(),
    );
    let (next, _, _) = ledger
        .assign(
            NativeWorldIdentity {
                owner: [1; 32],
                selection: [3; 32],
            },
            &requests(),
            16,
            &original,
        )
        .unwrap();
    assert!(next > epoch);
    assert!(ledger.observe_world_returned(epoch).unwrap());
    assert!(!ledger.observe_world_returned(next).unwrap());
    assert!(ledger.observe_world_returned(next + 1).is_err());
}

mod source_admission;

mod node_custody;
