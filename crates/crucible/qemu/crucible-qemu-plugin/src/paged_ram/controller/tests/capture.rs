//! Exercises actual controller admission while a modeled checkpoint owns its cut.

use super::*;

struct NoGuestWork;

impl SourceOperationFactory for NoGuestWork {
    fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        panic!("policy hold must not execute guest work")
    }
}

pub(in crate::paged_ram::controller) fn capture_controller()
-> (LivePagerController, RamControlPolicy, RamControlResources) {
    let (controller, policy, resources) = applied_controller();
    let owner = PausedPagingOwner::new(
        crate::args::PluginRamResources {
            resident_peak_bytes: resources.resident_peak_bytes,
            backing_peak_bytes: resources.backing_peak_bytes,
            metadata_bytes: resources.metadata_bytes,
            staging_bytes: resources.staging_bytes,
            paging_io_slots: resources.paging_io_slots,
            cpu_slots: resources.cpu_slots,
            task_slots: resources.task_slots,
            file_descriptors: resources.file_descriptors,
        },
        Arc::new(NoGuestWork),
    )
    .unwrap();
    controller.state.lock().unwrap().owner = Some(owner);
    (controller, policy, resources)
}

#[test]
fn retained_checkpoint_blocks_actual_apply_of_the_same_policy() {
    let (controller, policy, resources) = capture_controller();
    // The original fixture owner has no installed policy. Its refused snapshot
    // must not be mistaken for the checkpoint admission gate.
    let mismatched = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(mismatched.disposition, RamControlDisposition::Unavailable);
    assert!(!controller.state.lock().unwrap().checkpoint.is_held());
    controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .record_capture_fixture_policy(policy, 1);
    let healthy = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(healthy.disposition, RamControlDisposition::Accepted);

    controller.prepare_checkpoint_policy(11).unwrap();

    let refused = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(refused.disposition, RamControlDisposition::Unavailable);
    assert_eq!(refused.convergence, RamControlConvergence::Blocked);
    assert!(controller.state.lock().unwrap().checkpoint.is_held());

    controller.release_checkpoint_policy(11).unwrap();
    let accepted = controller.apply(0, 1, 0, policy, resources);
    assert_eq!(accepted.disposition, RamControlDisposition::Accepted);
}

#[test]
fn admitted_operation_settles_but_no_new_page_or_observer_token_is_born() {
    let (controller, _, _) = capture_controller();
    let pending = controller.begin(SourceOperationClass::PageIn).unwrap();
    controller.prepare_checkpoint_policy(12).unwrap();
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);

    assert!(controller.begin(SourceOperationClass::PageIn).is_err());
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    let mut observed = false;
    let refusal = controller.with_entered_observation(|_| observed = true);
    assert!(refusal.is_err());
    assert!(!observed);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);

    pending.complete().unwrap();
    drop(pending);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    // Even zero live slots cannot dispose the independently retained capture.
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
    controller.release_checkpoint_policy(12).unwrap();
}

#[test]
fn control_and_cleanup_remain_available_without_reopening_guest_admission() {
    let (controller, _, _) = capture_controller();
    controller.prepare_checkpoint_policy(13).unwrap();

    for class in [
        SourceOperationClass::ControlSetup,
        SourceOperationClass::Cleanup,
    ] {
        let operation = controller.begin(class).unwrap();
        operation.complete().unwrap();
    }
    assert!(controller.begin(SourceOperationClass::Writeback).is_err());
    controller.check_checkpoint_policy(13).unwrap();
}

#[test]
fn busy_or_applying_policy_refuses_a_capture_cut_without_reopening_existing_work() {
    let (controller, _, _) = capture_controller();
    let mut state = controller.state.lock().unwrap();
    assert!(controller.prepare_checkpoint_policy(14).is_err());
    assert!(!state.checkpoint.is_held());
    state.policy_applying = true;
    drop(state);

    assert!(controller.prepare_checkpoint_policy(14).is_err());
    let mut state = controller.state.lock().unwrap();
    assert!(!state.checkpoint.is_held());
    state.policy_applying = false;
    drop(state);
    controller.prepare_checkpoint_policy(14).unwrap();
}

#[test]
fn stale_disposition_cannot_release_or_reissue_an_actual_hold() {
    let (controller, _, _) = capture_controller();
    controller.prepare_checkpoint_policy(15).unwrap();
    controller.prepare_checkpoint_policy(15).unwrap();
    assert!(controller.prepare_checkpoint_policy(16).is_err());
    assert!(controller.release_checkpoint_policy(14).is_err());
    controller.check_checkpoint_policy(15).unwrap();

    controller.release_checkpoint_policy(15).unwrap();
    assert!(controller.release_checkpoint_policy(15).is_err());
    assert!(controller.prepare_checkpoint_policy(15).is_err());
    controller.prepare_checkpoint_policy(16).unwrap();
}

#[test]
fn cancellation_and_changed_tuple_retain_the_actual_gate() {
    let (controller, _, _) = capture_controller();
    controller.prepare_checkpoint_policy(17).unwrap();
    controller.state.lock().unwrap().reservation_revision += 1;
    assert!(controller.check_checkpoint_policy(17).is_err());
    assert!(controller.release_checkpoint_policy(17).is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());

    controller.canceled.store(true, Ordering::Release);
    assert!(controller.check_checkpoint_policy(17).is_err());
    assert!(controller.release_checkpoint_policy(17).is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn expired_outer_original_keeps_the_gate_without_restarting_a_deadline() {
    let (controller, _, _) = capture_controller();
    controller.prepare_checkpoint_policy(18).unwrap();
    controller.state.lock().unwrap().outer = Some(RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: 1,
        allowance_ns: Some(1),
        state: RamControlOuterState::Running,
    });

    assert!(controller.check_checkpoint_policy(18).is_err());
    assert!(controller.release_checkpoint_policy(18).is_err());
    let state = controller.state.lock().unwrap();
    assert!(state.outer_expired);
    assert!(state.checkpoint.is_held());
    assert_eq!(state.outer.unwrap().original_monotonic_ns, 1);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn released_operation_capacity_cannot_hide_unfinished_admitted_work() {
    let (controller, _, _) = capture_controller();
    let pending = controller.begin(SourceOperationClass::PageIn).unwrap();
    controller.prepare_checkpoint_policy(21).unwrap();
    assert!(controller.check_checkpoint_prior_work(21).is_err());

    drop(pending);

    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    assert!(controller.check_checkpoint_prior_work(21).is_err());
    assert!(controller.release_checkpoint_policy(21).is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn completed_receipt_can_stay_owned_without_blocking_classified_work() {
    let (controller, _, _) = capture_controller();
    let pending = controller.begin(SourceOperationClass::Writeback).unwrap();
    controller.prepare_checkpoint_policy(22).unwrap();
    assert!(controller.check_checkpoint_prior_work(22).is_err());

    pending.complete().unwrap();

    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    controller.check_checkpoint_prior_work(22).unwrap();
    assert!(pending.complete().is_err());
    controller.check_checkpoint_prior_work(22).unwrap();
    drop(pending);
    controller.check_checkpoint_prior_work(22).unwrap();
}

#[test]
fn refused_birth_during_hold_does_not_taint_existing_disposition() {
    let (controller, _, _) = capture_controller();
    controller.prepare_checkpoint_policy(23).unwrap();

    assert!(controller.begin(SourceOperationClass::PageIn).is_err());
    assert!(
        controller
            .with_entered_observation(|_| panic!("must refuse"))
            .is_err()
    );

    controller.check_checkpoint_prior_work(23).unwrap();
    controller.release_checkpoint_policy(23).unwrap();
}

#[test]
fn unfinished_borrowed_observation_is_not_disposed_by_stack_return() {
    let (controller, _, _) = capture_controller();
    controller.with_entered_observation(|_| {}).unwrap();
    controller.prepare_checkpoint_policy(24).unwrap();

    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    assert!(controller.check_checkpoint_prior_work(24).is_err());
}

#[test]
fn actual_observation_completion_preserves_settlement_after_body_return() {
    let (controller, _, _) = capture_controller();
    controller
        .with_entered_observation(|operation| {
            operation.complete_observation().unwrap();
        })
        .unwrap();
    controller.prepare_checkpoint_policy(25).unwrap();

    controller.check_checkpoint_prior_work(25).unwrap();
}

#[test]
fn admitted_performance_dispatch_stays_pending_after_state_unlock() {
    let (controller, _, _) = capture_controller();
    let mut dispatch = {
        let _state = controller.state.lock().unwrap();
        super::super::capture::work::PerformanceDispatch::begin(controller.operations.clone())
            .unwrap()
    };
    controller.prepare_checkpoint_policy(26).unwrap();
    assert!(controller.check_checkpoint_prior_work(26).is_err());

    dispatch.settle();

    controller.check_checkpoint_prior_work(26).unwrap();
    drop(dispatch);
    controller.check_checkpoint_prior_work(26).unwrap();
}

#[test]
fn dispatch_unwind_retains_uncertainty_after_releasing_capacity() {
    let (controller, _, _) = capture_controller();
    let registry = controller.operations.clone();
    let result = std::panic::catch_unwind(|| {
        let _dispatch = super::super::capture::work::PerformanceDispatch::begin(registry).unwrap();
        panic!("actual dispatch did not settle");
    });
    assert!(result.is_err());
    controller.prepare_checkpoint_policy(27).unwrap();

    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    assert!(controller.check_checkpoint_prior_work(27).is_err());
}

fn queued_work_controller(transaction: u64) -> Arc<LivePagerController> {
    queued_work_controller_with_detach(transaction, true)
}

fn queued_work_controller_with_detach(
    transaction: u64,
    detached: bool,
) -> Arc<LivePagerController> {
    let (controller, policy, resources) = applied_controller();
    let controller = Arc::new(controller);
    let owner = PausedPagingOwner::new(
        crate::args::PluginRamResources {
            resident_peak_bytes: resources.resident_peak_bytes,
            backing_peak_bytes: resources.backing_peak_bytes,
            metadata_bytes: resources.metadata_bytes,
            staging_bytes: resources.staging_bytes,
            paging_io_slots: resources.paging_io_slots,
            cpu_slots: resources.cpu_slots,
            task_slots: resources.task_slots,
            file_descriptors: resources.file_descriptors,
        },
        controller.clone(),
    )
    .unwrap();
    owner.record_capture_fixture_policy(policy, 1);
    owner
        .admit_checkpoint_work_for_test(1, transaction)
        .unwrap();
    controller.state.lock().unwrap().owner = Some(owner);
    controller.prepare_checkpoint_policy(transaction).unwrap();
    let owner = controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();
    if detached {
        owner.detach_checkpoint_work_for_test(transaction).unwrap();
    }
    controller
}

#[test]
fn actual_held_queued_receipt_is_classified_without_completing_original_work() {
    let controller = queued_work_controller(101);
    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);

    controller.check_checkpoint_prior_work(101).unwrap();

    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    assert!(controller.operations.check_settled().is_err());
    assert!(controller.release_checkpoint_policy(101).is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn held_queued_receipt_does_not_hide_unrelated_live_work() {
    let (controller, policy, _) = capture_controller();
    let unrelated = controller.begin(SourceOperationClass::PageIn).unwrap();
    let controller = Arc::new(controller);
    let resources = controller.state.lock().unwrap().resources;
    let owner = PausedPagingOwner::new(
        crate::args::PluginRamResources {
            resident_peak_bytes: resources.resident_peak_bytes,
            backing_peak_bytes: resources.backing_peak_bytes,
            metadata_bytes: resources.metadata_bytes,
            staging_bytes: resources.staging_bytes,
            paging_io_slots: resources.paging_io_slots,
            cpu_slots: resources.cpu_slots,
            task_slots: resources.task_slots,
            file_descriptors: resources.file_descriptors,
        },
        controller.clone(),
    )
    .unwrap();
    owner.record_capture_fixture_policy(policy, 1);
    owner.admit_checkpoint_work_for_test(1, 102).unwrap();
    owner.detach_checkpoint_work_for_test(102).unwrap();
    controller.state.lock().unwrap().owner = Some(owner);
    controller.prepare_checkpoint_policy(102).unwrap();

    assert!(controller.check_checkpoint_prior_work(102).is_err());
    unrelated.complete().unwrap();
    controller.check_checkpoint_prior_work(102).unwrap();
    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
}

#[test]
fn restored_receipt_stays_unfinished_and_is_not_restored_twice() {
    let controller = queued_work_controller(103);
    controller.check_checkpoint_prior_work(103).unwrap();
    let owner = controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();
    let restored = AtomicUsize::new(0);
    owner
        .restore_checkpoint_work_for_test(103, || {
            restored.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();
    owner
        .restore_checkpoint_work_for_test(103, || {
            restored.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();

    assert!(controller.check_checkpoint_prior_work(103).is_err());
    controller.release_checkpoint_policy(103).unwrap();

    assert_eq!(restored.load(Ordering::Acquire), 1);
    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    assert!(!controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn dropped_work_loan_taints_registry_without_completing_or_refunding_original() {
    let controller = queued_work_controller(104);
    controller.check_checkpoint_prior_work(104).unwrap();
    let owner = controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();

    owner.abandon_checkpoint_work_for_test();

    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    assert!(controller.operations.check_settled().is_err());
    assert!(controller.check_checkpoint_prior_work(104).is_err());
    assert!(controller.release_checkpoint_policy(104).is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn foreign_real_operation_cannot_be_subtracted_from_the_named_registry() {
    let controller = queued_work_controller(105);
    let (foreign, _, _) = capture_controller();
    let foreign_operation: Arc<dyn SourceOperation> =
        Arc::from(foreign.begin(SourceOperationClass::Quiescence).unwrap());

    let refused = controller.with_checkpoint_work_admission(105, |admission| {
        foreign_operation.clone().retain_checkpoint_work(admission)
    });

    assert!(refused.is_err());
    assert_eq!(foreign.operations.unfinished.load(Ordering::Acquire), 1);
    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    controller.check_checkpoint_prior_work(105).unwrap();
}

#[test]
fn canceled_final_disposition_retains_restored_journal_and_original_work() {
    let controller = queued_work_controller(106);
    controller.check_checkpoint_prior_work(106).unwrap();
    let owner = controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();
    let restores = AtomicUsize::new(0);
    owner
        .restore_checkpoint_work_for_test(106, || {
            restores.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();

    controller.canceled.store(true, Ordering::Release);
    assert!(controller.release_checkpoint_policy(106).is_err());
    owner
        .restore_checkpoint_work_for_test(106, || {
            restores.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();

    assert_eq!(restores.load(Ordering::Acquire), 1);
    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    assert!(controller.operations.check_settled().is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn requested_queue_without_detached_mailbox_cannot_classify_held_work() {
    let controller = queued_work_controller_with_detach(107, false);

    assert!(controller.check_checkpoint_prior_work(107).is_err());

    assert_eq!(controller.operations.unfinished.load(Ordering::Acquire), 1);
    assert!(controller.operations.check_settled().is_err());
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
}

#[test]
fn checkpoint_hold_excludes_entitled_fault_exit_without_hiding_observation() {
    let (mut controller, _, _) = capture_controller();
    controller.fault_actor_test_entitlement = Some([7; 32]);
    controller.state.lock().unwrap().outer = Some(RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: crate::paged_ram::supervision::monotonic_ns().unwrap(),
        allowance_ns: Some(30_000_000_000),
        state: RamControlOuterState::Running,
    });
    controller.prepare_checkpoint_policy(108).unwrap();

    let exit = controller.test_fault_actor([7; 32], 1, RamControlFaultActorAction::RequestExit);
    assert_eq!(exit.disposition, RamControlDisposition::AdmissionRefused);
    let observation = controller.test_fault_actor([7; 32], 1, RamControlFaultActorAction::Observe);
    assert_eq!(observation.disposition, RamControlDisposition::Unavailable);
    assert!(controller.state.lock().unwrap().checkpoint.is_held());
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    assert!(!controller.canceled.load(Ordering::Acquire));

    controller.release_checkpoint_policy(108).unwrap();
    let no_actor = controller.test_fault_actor([7; 32], 1, RamControlFaultActorAction::RequestExit);
    assert_eq!(no_actor.disposition, RamControlDisposition::Unavailable);
}
