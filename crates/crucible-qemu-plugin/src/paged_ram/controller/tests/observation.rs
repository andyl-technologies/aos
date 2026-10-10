//! Separates acknowledged configuration from unavailable physical observations.

use super::*;

struct NoStatusOperations;

impl SourceOperationFactory for NoStatusOperations {
    fn with_fingerprint_operation(
        &self,
        _: &mut dyn FnMut(&dyn SourceOperation),
    ) -> Result<(), ObservationOperationError> {
        panic!("status cannot start a guest observation")
    }

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
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
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
    assert_eq!(controller.operations.load(Ordering::Acquire), 0);
}
