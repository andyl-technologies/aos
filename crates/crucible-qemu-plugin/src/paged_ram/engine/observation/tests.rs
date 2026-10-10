//! Checks evidence selection and refuses unavailable retained ownership.
//!
//! Scalar convergence fixtures model proof inputs only. They perform no mlock,
//! manufacture no kernel receipt and do not qualify a physical paging backend.

use super::*;

fn policy(mode: RamControlMode) -> RamControlPolicy {
    RamControlPolicy {
        mode,
        resident_target_bytes: 8192,
        eviction_preference: 0,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        budgets: [crucible_protocol::ram_control::RamControlBudget {
            poll_ms: 1,
            progress_ms: None,
            total_ms: Some(30_000),
        }; crucible_protocol::ram_control::RAM_CONTROL_BUDGET_COUNT],
    }
}

fn authority() -> PagingAuthoritySnapshot {
    PagingAuthoritySnapshot {
        logical_bytes: 8192,
        topology_generation: 7,
        activated: true,
        failed: false,
        full_peak_bytes: 16384,
        permanent_resident_bytes: 8192,
    }
}

fn receipt(mode: RamControlMode) -> RamControlPlacementReceipt {
    RamControlPlacementReceipt {
        mode,
        policy_revision: 3,
        topology_generation: 7,
        placement_epoch: 1,
        locked_bytes: 8192,
        disk_preserved_logical_pages: 0,
        disk_preserved_logical_bytes: 0,
        ram_write_generation_at_cut: 0,
    }
}

#[test]
fn complete_live_lock_evidence_is_required_for_resident_convergence() {
    let observed = |receipt, locked| {
        observed_convergence(
            authority(),
            Some(policy(RamControlMode::ResidentRequired)),
            3,
            false,
            receipt,
            locked,
        )
    };

    assert_eq!(observed(None, None), RamControlConvergence::Blocked);
    let current = receipt(RamControlMode::ResidentRequired);
    assert_eq!(
        observed(Some(current), None),
        RamControlConvergence::Blocked
    );
    assert_eq!(
        observed(Some(current), Some(4096)),
        RamControlConvergence::Blocked
    );
    assert_eq!(
        observed(Some(current), Some(8192)),
        RamControlConvergence::Stable
    );
}

#[test]
fn stale_incomplete_or_inactive_lock_proofs_cannot_report_stable() {
    let current = receipt(RamControlMode::ResidentRequired);
    for changed in [
        RamControlPlacementReceipt {
            policy_revision: 2,
            ..current
        },
        RamControlPlacementReceipt {
            topology_generation: 6,
            ..current
        },
        RamControlPlacementReceipt {
            placement_epoch: 0,
            ..current
        },
        RamControlPlacementReceipt {
            locked_bytes: 4096,
            ..current
        },
        RamControlPlacementReceipt {
            mode: RamControlMode::Managed,
            ..current
        },
    ] {
        assert_eq!(
            observed_convergence(
                authority(),
                Some(policy(RamControlMode::ResidentRequired)),
                3,
                false,
                Some(changed),
                Some(changed.locked_bytes)
            ),
            RamControlConvergence::Blocked,
        );
    }
    for changed in [
        PagingAuthoritySnapshot {
            activated: false,
            ..authority()
        },
        PagingAuthoritySnapshot {
            logical_bytes: 0,
            ..authority()
        },
    ] {
        assert_eq!(
            observed_convergence(
                changed,
                Some(policy(RamControlMode::ResidentRequired)),
                3,
                false,
                Some(current),
                Some(8192)
            ),
            RamControlConvergence::Blocked,
        );
    }
}

#[test]
fn managed_acknowledgement_and_historical_disk_cut_are_not_measurements() {
    for mode in [RamControlMode::Managed, RamControlMode::DiskOriented] {
        assert_eq!(
            observed_convergence(
                authority(),
                Some(policy(mode)),
                3,
                false,
                Some(receipt(mode)),
                Some(8192)
            ),
            RamControlConvergence::Blocked,
        );
    }
}

#[test]
fn pending_work_and_retained_failure_precede_success_evidence() {
    let proof = Some(receipt(RamControlMode::ResidentRequired));
    let policy = Some(policy(RamControlMode::ResidentRequired));
    assert_eq!(
        observed_convergence(authority(), policy, 3, true, proof, Some(8192)),
        RamControlConvergence::Applying,
    );
    assert_eq!(
        observed_convergence(
            PagingAuthoritySnapshot {
                failed: true,
                ..authority()
            },
            policy,
            3,
            true,
            proof,
            Some(8192)
        ),
        RamControlConvergence::Failed,
    );
}

struct NoOperations;

impl SourceOperationFactory for NoOperations {
    fn with_fingerprint_operation(
        &self,
        _: &mut dyn FnMut(&dyn SourceOperation),
    ) -> Result<(), crate::paged_ram::source::ObservationOperationError> {
        panic!("a status snapshot cannot request guest observation authority")
    }

    fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        panic!("a status snapshot cannot create or renew an operation")
    }
}

fn owner() -> Arc<PausedPagingOwner> {
    PausedPagingOwner::new(
        PluginRamResources {
            resident_peak_bytes: 16384,
            backing_peak_bytes: 16384,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 3,
        },
        Arc::new(NoOperations),
    )
    .unwrap_or_else(|error| panic!("component owner admission: {error}"))
}

#[test]
fn read_only_snapshot_does_not_start_an_operation_or_invent_authority() {
    let owner = owner();
    let snapshot = owner
        .status_snapshot(None, 0)
        .unwrap_or_else(|error| panic!("empty retained snapshot: {error}"));

    assert_eq!(snapshot.authority.logical_bytes, 0);
    assert!(!snapshot.authority.activated);
    assert!(snapshot.placement_receipt.is_none());
    assert_eq!(snapshot.convergence, RamControlConvergence::Blocked);
}

#[test]
fn each_contended_owner_refuses_without_waiting_or_replacing_custody() {
    let owner = owner();
    let policy = owner
        .policy
        .lock()
        .unwrap_or_else(|error| panic!("fixture policy: {error}"));
    assert!(owner.status_snapshot(None, 0).is_err());
    drop(policy);
    let queued = owner
        .queued_operation
        .lock()
        .unwrap_or_else(|error| panic!("fixture queue: {error}"));
    assert!(owner.status_snapshot(None, 0).is_err());
    drop(queued);
    let receipt = owner
        .placement_receipt
        .lock()
        .unwrap_or_else(|error| panic!("fixture receipt: {error}"));
    assert!(owner.status_snapshot(None, 0).is_err());
    drop(receipt);
    let locks = owner
        .locks
        .lock()
        .unwrap_or_else(|error| panic!("fixture locks: {error}"));
    assert!(owner.status_snapshot(None, 0).is_err());
    drop(locks);
    let active = owner
        .active
        .lock()
        .unwrap_or_else(|error| panic!("fixture active: {error}"));
    assert!(owner.status_snapshot(None, 0).is_err());
    drop(active);
    assert!(owner.status_snapshot(None, 0).is_ok());
}

#[test]
fn policy_identity_mismatch_is_unavailable_and_retained_failure_is_failed() {
    let owner = owner();
    assert!(owner.status_snapshot(None, 1).is_err());
    assert!(
        owner
            .status_snapshot(Some(policy(RamControlMode::Managed)), 0)
            .is_err()
    );
    owner.failed.store(true, Ordering::Release);

    let snapshot = owner
        .status_snapshot(None, 0)
        .unwrap_or_else(|error| panic!("retained failure observation: {error}"));
    assert_eq!(snapshot.convergence, RamControlConvergence::Failed);
}
