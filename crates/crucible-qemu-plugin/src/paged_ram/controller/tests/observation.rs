//! Separates acknowledged configuration from unavailable physical observations.

use super::*;

struct NoStatusOperations;

impl SourceOperationFactory for NoStatusOperations {
    fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        panic!("status cannot start or renew an operation")
    }
}

fn observed_controller() -> LivePagerController {
    let controller = controller();
    let owner = PausedPagingOwner::new(
        crate::args::PluginRamResources {
            resident_peak_bytes: 16384,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        },
        Arc::new(NoStatusOperations),
    )
    .unwrap_or_else(|error| panic!("component observation owner: {error}"));
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("component controller state: {error}"))
        .owner = Some(owner);
    controller
}

fn assert_counters_unavailable(reply: &RamControlReply) {
    assert!(!reply.measurements_available);
    assert_eq!(reply.private_resident_bytes, 0);
    assert_eq!(reply.shared_resident_bytes_observed, 0);
    assert_eq!(reply.preserved_backing_bytes, 0);
    assert_eq!(reply.private_dirty_bytes, 0);
    assert_eq!(reply.writeback_pending_bytes, 0);
}

#[test]
fn equal_managed_revisions_do_not_fabricate_physical_measurements() {
    let (controller, _, _) = applied_controller();
    let reply = controller.status();

    assert_eq!(
        reply.requested_policy_revision,
        reply.applied_policy_revision
    );
    assert_eq!(reply.convergence, RamControlConvergence::Blocked);
    assert_counters_unavailable(&reply);
}

#[test]
fn owner_identity_mismatch_is_unavailable_without_overriding_initiating_refusal() {
    let controller = observed_controller();
    let mut state = controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("component mismatch state: {error}"));
    state.requested_revision = 1;

    let observed = controller.reply(&mut state, RamControlDisposition::Accepted);
    assert_eq!(observed.disposition, RamControlDisposition::Unavailable);
    assert_eq!(observed.convergence, RamControlConvergence::Blocked);
    assert_counters_unavailable(&observed);
    for initiating in [
        RamControlDisposition::RevisionConflict,
        RamControlDisposition::NotCurrent,
        RamControlDisposition::AdmissionRefused,
        RamControlDisposition::Canceled,
    ] {
        let refused = controller.reply(&mut state, initiating);
        assert_eq!(refused.disposition, initiating);
        assert_counters_unavailable(&refused);
    }
}

#[test]
fn retained_failure_is_reported_without_reopening_physical_measurements() {
    let controller = observed_controller();
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("component failure state: {error}"))
        .failed = true;
    let reply = controller.status();

    assert_eq!(reply.convergence, RamControlConvergence::Failed);
    assert_counters_unavailable(&reply);
}

#[test]
fn cancellation_keeps_observation_blocked_without_creating_work() {
    let controller = observed_controller();
    let reply = controller.cancel(controller.target.arena_generation);

    assert_eq!(reply.disposition, RamControlDisposition::Canceled);
    assert_eq!(reply.convergence, RamControlConvergence::Blocked);
    assert_counters_unavailable(&reply);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn expired_original_is_failed_without_a_new_deadline_or_operation() {
    let controller = observed_controller();
    controller
        .state
        .lock()
        .unwrap_or_else(|error| panic!("component expired original: {error}"))
        .outer = Some(RamControlOuterCap {
        cap_id: [8; 32],
        revision: 0,
        original_monotonic_ns: 1,
        allowance_ns: Some(1),
        state: RamControlOuterState::Running,
    });

    let reply = controller.status();
    assert_eq!(reply.convergence, RamControlConvergence::Failed);
    assert_counters_unavailable(&reply);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn placement_status_preserves_full_execution_peak_across_advisory_and_strict_modes() {
    let controller = observed_controller();
    let mut state = controller.state.lock().unwrap();
    let owner = state.owner.as_ref().unwrap().clone();
    owner.seal_geometry(1, 8192).unwrap();
    state.resources = RamControlResources {
        resident_peak_bytes: 16384,
        backing_peak_bytes: 16384,
        metadata_bytes: 4096,
        staging_bytes: 4096,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: 3,
    };
    state.inventory = Some(Inventory {
        report: RamControlInventoryReport {
            topology_generation: 1,
            logical_bytes: 8192,
            region_count: 1,
            native_metadata_bytes: 4096,
            native_scratch_bytes: 4096,
            rust_metadata_required_bytes: 4096,
            owner_resources: RamControlOwnerInventory {
                existing_tasks: 1,
                existing_file_descriptors: 3,
                registered_service_tasks: 0,
                prospective_tasks: 0,
                prospective_file_descriptors: 0,
            },
            granted: false,
        },
        regions: vec![RamControlInventoryRegion::new(0, 8192, 1, "main").unwrap()],
        grant: None,
        operation: None,
    });
    let mut policy = RamControlPolicy {
        mode: RamControlMode::Managed,
        resident_target_bytes: 0,
        eviction_preference: 100,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        budgets: state.budgets,
    };
    let retained_resources = state.resources;
    drop(state);

    // These are acknowledged configuration observations, without native lock,
    // reclaim or physical convergence claims. Status must not start an operation.
    for (revision, mode, target, effective, limited) in [
        (1, RamControlMode::Managed, 0, 0, true),
        (2, RamControlMode::DiskOriented, 4096, 4096, true),
        (3, RamControlMode::ResidentRequired, 0, 8192, false),
        (4, RamControlMode::Managed, 8192, 8192, false),
    ] {
        policy.mode = mode;
        policy.resident_target_bytes = target;
        owner.record_capture_fixture_policy(policy, revision);
        let mut state = controller.state.lock().unwrap();
        state.policy = Some(policy);
        state.requested_revision = revision;
        state.applied_revision = revision;
        drop(state);

        let reply = controller.status();
        assert_eq!(reply.disposition, RamControlDisposition::Accepted);
        assert_eq!(reply.effective_resident_target_bytes, effective);
        assert_eq!(
            reply.limitation_reasons & RAM_LIMIT_EXECUTION_PEAK != 0,
            limited
        );
        assert_eq!(reply.convergence, RamControlConvergence::Blocked);
        assert_counters_unavailable(&reply);
        assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
        assert_eq!(
            controller.state.lock().unwrap().resources,
            retained_resources
        );
        if mode != RamControlMode::ResidentRequired {
            owner.admit_policy(&policy).unwrap();
        }
    }

    // A smaller target is still not authority to run with a smaller peak.
    let insufficient = PausedPagingOwner::new(
        crate::args::PluginRamResources {
            resident_peak_bytes: 12288,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        },
        Arc::new(NoStatusOperations),
    )
    .unwrap();
    insufficient.seal_geometry(1, 8192).unwrap();
    policy.resident_target_bytes = 0;
    assert!(matches!(
        insufficient.admit_policy(&policy),
        Err(RamError::MetadataAdmission {
            required: 16384,
            admitted: 12288
        })
    ));
}

#[test]
fn policy_admission_bounds_target_by_retained_logical_geometry() {
    let controller = observed_controller();
    let state = controller.state.lock().unwrap();
    let owner = state.owner.as_ref().unwrap().clone();
    let mut policy = RamControlPolicy {
        mode: RamControlMode::Managed,
        resident_target_bytes: 0,
        eviction_preference: 100,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        budgets: state.budgets,
    };
    drop(state);
    owner.seal_geometry(1, 8192).unwrap();
    let before = owner.authority_snapshot().unwrap();

    for mode in [RamControlMode::Managed, RamControlMode::DiskOriented] {
        policy.mode = mode;
        for target in [0, 8192] {
            policy.resident_target_bytes = target;
            owner.admit_policy(&policy).unwrap();
        }
    }
    for mode in [
        RamControlMode::Managed,
        RamControlMode::DiskOriented,
        RamControlMode::ResidentRequired,
    ] {
        policy.mode = mode;
        for target in [8193, u64::MAX] {
            policy.resident_target_bytes = target;
            assert!(matches!(
                owner.admit_policy(&policy),
                Err(RamError::Invariant("resident target exceeds logical RAM"))
            ));
        }
    }

    // Admission checks geometry without a placement or native activation effect.
    let after = owner.authority_snapshot().unwrap();
    assert_eq!(after.logical_bytes, before.logical_bytes);
    assert_eq!(after.topology_generation, before.topology_generation);
    assert_eq!(after.full_peak_bytes, before.full_peak_bytes);
    assert!(!after.activated);
    assert!(!after.failed);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn unknown_inventory_does_not_advertise_a_low_execution_peak_or_strict_size() {
    let (controller, mut policy, _) = applied_controller();
    policy.mode = RamControlMode::ResidentRequired;
    controller.state.lock().unwrap().policy = Some(policy);

    let reply = controller.status();

    assert_eq!(reply.logical_ram_bytes, 0);
    assert_eq!(reply.effective_resident_target_bytes, 0);
    assert_eq!(reply.limitation_reasons & RAM_LIMIT_EXECUTION_PEAK, 0);
    assert_eq!(reply.convergence, RamControlConvergence::Blocked);
    assert_counters_unavailable(&reply);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}
