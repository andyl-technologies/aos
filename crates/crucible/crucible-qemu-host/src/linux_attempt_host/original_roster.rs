//! Retains native account credit outside the genuine factory and state controls.
//!
//! The fixed roster is sized by the authored one, two or four native workers.
//! Normal shared storage is prepaid by the same Main through final Weak free;
//! private/component storage remains inside the initial actor structure. Each native
//! pair remains charged throughout the campaign; closing a slot only permits
//! reuse after that exact owner's physical vector and native control close.
//! This account binding does not issue Source, backing or launch permission.

use std::sync::{Arc, Mutex};

use crucible_host_resources::host_supervision::HostOperationGuard;

use super::native_account::{OriginalActorAccountError, OriginalNativeAccountCredit};
use super::native_resources::NativeResourceState;
use super::native_resources::OriginalNativeControlRetirement;
use crate::QemuVmRealizationError;
use crate::linux_attempt_process::LinuxQemuAttemptProcessOwner;
use crate::linux_attempt_storage::LinuxQemuAttemptStorageOwner;

pub(crate) mod device_digest;
mod fork_target;
pub(super) mod process_purpose;
mod target_dispatcher;
pub(in crate::linux_attempt_host) use fork_target::ForkTargetReservation;
pub(crate) use fork_target::{TargetCleanupLoan, TargetCleanupOriginal};
pub use fork_target::{QemuForkTargetConstructionError, QemuForkTargetConstructionLoan};
pub(crate) use target_dispatcher::TargetWatcherOriginal;
mod retirement;
mod storage;

use storage::{RosterOwner, RosterWeak};
use crucible_host_resources::host_services::process_birth::NativeRosterAllocationFunding;

use process_purpose::{cleanup_control_extent, fresh_launch_control_extent};

pub(crate) use device_digest::OriginalDeviceDigestWorkspacePurpose;
pub(crate) use process_purpose::{
    InstalledIncarnationRetirement, InstalledProcessPurposeError, InstalledProcessPurposeLoan,
    InstalledSourceAdmission, InstalledSourceSubject, IssuedProcessConsumer, SetupMappingRequest,
    SourceCleanupLender, SourceCleanupOriginal,
};

const MAX_NATIVE_WORKERS: usize = 4;
// The fixed workflow has one VM; its existing lifecycle admits one active
// generation and one staged successor. This is not another native vector.
const MAX_ORIGINAL_NATIVE_NODE_GENERATIONS: u8 = 2;

/// Retains the finite original native account roster outside all funded owners.
///
/// Abandoning this owner retains its actual allocation and all original pairs.
/// Final factory, Source, namespace and enclosing allocation retirement remain
/// separate from an individual slot's physical vector closure.
#[must_use = "retain original native accounts through genuine factory retirement"]
pub struct OriginalNativeAccountRoster {
    held: Option<RosterOwner>,
    retiring_credits: [Option<OriginalNativeAccountCredit>; MAX_NATIVE_WORKERS],
}

impl std::fmt::Debug for OriginalNativeAccountRoster {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OriginalNativeAccountRoster { .. }")
    }
}

#[cfg(test)]
mod family_constructor_tests;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these actual loan/guard/slot controls panic only when custody, original refusal or generation exclusion fails; they mint no authenticated parent or kernel grant.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_host_resources::host_services::HostServiceError;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    fn roster() -> (
        OriginalNativeAccountRoster,
        OriginalNativeAccountFactoryBinding,
        HostOperationSupervisor,
    ) {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let (credit, _, _) = OriginalNativeAccountCredit::mechanism_credit(preparation).unwrap();
        let (roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();
        (roster, binding, supervisor)
    }

    #[test]
    fn target_loan_refuses_missing_source_control_before_occupying_its_slot() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let contract = crate::QemuChildProcessContract::for_test(control.into(), event, 4096);
        let held = attempt.roster.upgrade().unwrap();
        let before = held.lock().unwrap().slots[attempt.index]
            .assigned_metadata_bytes()
            .unwrap();

        assert!(attempt.reserve_fork_target(&contract).is_err());

        let state = held.lock().unwrap();
        let slot = &state.slots[attempt.index];
        assert!(!slot.fork_target.is_owned());
        assert_eq!(slot.active, Some(attempt.generation));
        assert_eq!(slot.assigned_metadata_bytes().unwrap(), before);
        assert!(slot.installed_process.is_none());
    }

    #[test]
    fn installed_issuer_refuses_missing_physical_control_without_entering_launch() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let held = attempt.roster.upgrade().unwrap();
        let before = held.lock().unwrap().slots[attempt.index]
            .assigned_metadata_bytes()
            .unwrap();

        assert!(attempt.require_live_launch_control().is_err());

        let state = held.lock().unwrap();
        let slot = &state.slots[attempt.index];
        assert_eq!(slot.active, Some(attempt.generation));
        assert_eq!(slot.assigned_metadata_bytes().unwrap(), before);
        assert_eq!(slot.node_bindings_live, 0);
        assert!(!slot.launch_in_flight);
        assert!(slot.installed_process.is_none());
    }

    #[test]
    fn installed_issuer_cannot_follow_a_reused_original_generation() {
        let (_roster, binding, _supervisor) = roster();
        let old = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        assert!(old.close_vector().is_err());
        old.cleanup().unwrap();
        old.close_vector().unwrap();
        let successor = binding.claim(1, 512 << 20, 1 << 30).unwrap();

        assert!(old.require_live_launch_control().is_err());

        let state = successor.roster.upgrade().unwrap();
        let state = state.lock().unwrap();
        let slot = &state.slots[successor.index];
        assert_eq!(slot.active, Some(successor.generation));
        assert!(!slot.launch_in_flight);
        assert_eq!(slot.node_bindings_live, 0);
    }

    #[test]
    fn cleanup_guard_history_stays_assigned_across_slot_reuse() {
        let (_roster, binding, _supervisor) = roster();
        let first = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let first_cleanup = first.cleanup().unwrap();
        let held = first.roster.upgrade().unwrap();
        let initial = held.lock().unwrap().slots[first.index].cleanup_controls_bytes;
        assert!(initial > 0);

        first.close_vector().unwrap();
        let second = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let second_cleanup = second.cleanup().unwrap();

        assert!(!Arc::ptr_eq(&first_cleanup, &second_cleanup));
        let state = held.lock().unwrap();
        assert_eq!(
            state.slots[second.index].cleanup_controls_bytes,
            2 * initial
        );
        assert_eq!(
            state.slots[second.index].assigned_metadata_bytes().unwrap(),
            2 * initial
                + state.slots[second.index].launch_controls_bytes
                + state.slots[second.index].process_binding_bytes
        );
    }

    #[test]
    fn claim_prepays_process_binding_and_fresh_controls_before_process_sealing() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let held = attempt.roster.upgrade().unwrap();
        let state = held.lock().unwrap();
        let slot = &state.slots[attempt.index];
        let binding_extent = crate::QemuProcessStageBinding::retained_control_bytes().unwrap();
        let preparation_extent = slot
            .credit
            .as_ref()
            .unwrap()
            .normal_preparation_extent()
            .unwrap();
        let target_extent = fork_target::retained_control_extent().unwrap();

        assert_eq!(
            slot.process_binding_bytes,
            binding_extent
                .checked_add(preparation_extent)
                .and_then(|bytes| bytes.checked_add(target_extent))
                .unwrap()
        );
        assert_eq!(
            slot.launch_controls_bytes,
            fresh_launch_control_extent().unwrap()
        );
        assert_eq!(
            slot.assigned_metadata_bytes().unwrap(),
            slot.process_binding_bytes + slot.launch_controls_bytes
        );
        assert!(!slot.launch_in_flight);
        assert!(slot.cleanup.is_none());
        assert!(slot.installed_process.is_none());
    }

    #[test]
    fn refused_early_assignment_preserves_unclaimed_generation_and_charge() {
        let (_roster, binding, _supervisor) = roster();
        let held = binding.roster.upgrade().unwrap();
        let next = {
            let mut state = held.lock().unwrap();
            let slot = &mut state.slots[0];
            slot.cleanup_controls_bytes = slot.credit.as_ref().unwrap().total_metadata_bytes();
            state.next_generation
        };

        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());

        let state = held.lock().unwrap();
        let slot = &state.slots[0];
        assert_eq!(state.next_generation, next);
        assert!(slot.active.is_none());
        assert_eq!(slot.process_binding_bytes, 0);
        assert_eq!(slot.launch_controls_bytes, 0);
        assert_eq!(
            slot.cleanup_controls_bytes,
            slot.credit.as_ref().unwrap().total_metadata_bytes()
        );
    }

    #[test]
    fn descriptor_fixture_cannot_issue_a_complete_process_purpose() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let (control, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let contract = crate::QemuChildProcessContract::for_test(control.into(), event, 1 << 30);
        let held = attempt.roster.upgrade().unwrap();
        let before = held.lock().unwrap().slots[attempt.index]
            .assigned_metadata_bytes()
            .unwrap();

        assert!(matches!(
            attempt.bind_configured_process_family(&contract),
            Err(InstalledProcessPurposeError::Identity)
        ));

        let state = held.lock().unwrap();
        let slot = &state.slots[attempt.index];
        assert!(slot.installed_process.is_none());
        assert_eq!(slot.assigned_metadata_bytes().unwrap(), before);
        assert_eq!(slot.active, Some(attempt.generation));
    }

    #[test]
    fn original_cancellation_precedes_process_identity_and_keeps_slot_credit() {
        let (_roster, binding, supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let (control, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let contract = crate::QemuChildProcessContract::for_test(control.into(), event, 1 << 30);
        supervisor.cancel().unwrap();

        assert!(matches!(
            attempt.bind_configured_process_family(&contract),
            Err(InstalledProcessPurposeError::Original(
                OriginalActorAccountError::Supervision(_)
            ))
        ));

        let held = attempt.roster.upgrade().unwrap();
        let state = held.lock().unwrap();
        let slot = &state.slots[attempt.index];
        assert!(slot.installed_process.is_none());
        assert!(slot.credit.is_some());
        assert_eq!(slot.active, Some(attempt.generation));
        assert!(slot.process_binding_bytes > 0);
    }

    #[test]
    fn launch_assignment_cannot_spend_retained_cleanup_credit_again() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let _cleanup = attempt.cleanup().unwrap();
        let held = attempt.roster.upgrade().unwrap();
        {
            let state = held.lock().unwrap();
            let slot = &state.slots[attempt.index];
            let total = slot.credit.as_ref().unwrap().total_metadata_bytes();
            assert!(slot.require_metadata_assignment(total).is_err());
            assert!(slot.launch_controls_bytes > 0);
        }

        let preparation = attempt.prepare_fresh_launch().unwrap();
        assert!(held.lock().unwrap().slots[attempt.index].launch_controls_bytes > 0);
        drop(preparation);
        assert!(!held.lock().unwrap().slots[attempt.index].launch_in_flight);
    }

    #[test]
    fn factory_capture_requires_the_same_returned_guard_allocation() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let different = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let (credit, _, _) =
            OriginalNativeAccountCredit::mechanism_credit(Arc::clone(&original)).unwrap();
        let (_roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();

        binding.verify_preparation(&original).unwrap();
        assert!(matches!(
            binding.verify_preparation(&different),
            Err(OriginalActorAccountError::Unavailable)
        ));
        supervisor.cancel().unwrap();
        assert!(matches!(
            binding.verify_preparation(&original),
            Err(OriginalActorAccountError::Supervision(_))
        ));
    }

    #[test]
    fn exact_caps_live_original_and_one_active_generation_are_required() {
        let (_roster, binding, supervisor) = roster();
        for (cpu, resident, backing) in [
            (2, 512 << 20, 1 << 30),
            (1, 1536 * (1 << 20) + 1, 1 << 30),
            (1, 512 << 20, (4 << 30) + 1),
        ] {
            assert!(binding.claim(cpu, resident, backing).is_err());
        }
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());
        supervisor.cancel().unwrap();
        assert!(matches!(
            attempt.require_original(),
            Err(OriginalActorAccountError::Supervision(_))
        ));
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());
    }

    #[test]
    fn slot_transition_keeps_credit_and_rejects_stale_or_exhausted_generation() {
        let (_roster, binding, _supervisor) = roster();
        let old = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let cleanup = old.cleanup().unwrap();
        // This private transition exercises slot bookkeeping only. The real
        // caller performs process/storage/control retirement before this cut.
        old.close_vector().unwrap();
        drop(cleanup);
        let current = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        assert_ne!(old.generation, current.generation);
        assert!(old.require_original().is_err());
        assert!(old.close_vector().is_err());
        current.require_original().unwrap();
        let cleanup = current.cleanup().unwrap();
        current.close_vector().unwrap();
        drop(cleanup);
        let live = binding.roster.upgrade().unwrap();
        live.lock().unwrap().next_generation = u64::MAX;
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());
        assert!(live.lock().unwrap().slots[0].active.is_none());
    }

    #[test]
    fn dropping_external_roster_does_not_refund_pair_or_same_guard() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let witness = Arc::downgrade(&preparation);
        let (credit, resident, metadata) =
            OriginalNativeAccountCredit::mechanism_credit(preparation).unwrap();
        let (roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();
        drop(binding);
        drop(roster);
        assert!(matches!(
            resident.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));
        assert!(matches!(
            metadata.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));
        assert!(witness.upgrade().is_some());
        eprintln!(
            "original_roster_control={}",
            OriginalNativeAccountRoster::allocation_extent().unwrap()
        );
    }

    fn generic_storage() -> (tempfile::TempDir, LinuxQemuAttemptStorageOwner, i32) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("attempt")).unwrap();
        std::fs::write(root.path().join("attempt/retained"), b"owned bytes").unwrap();
        let (owner, descriptor) =
            LinuxQemuAttemptStorageOwner::unvalidated_directory_fixture(root.path(), "attempt")
                .unwrap();
        (root, owner, descriptor)
    }

    #[test]
    fn physical_retirement_witness_refuses_terminal_cleanup_before_storage_release() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let cleanup = attempt.cleanup().unwrap();
        let (root, storage, descriptor) = generic_storage();
        let mut host = super::super::LinuxQemuAttemptHostOwner {
            process: None,
            storage: Some(storage),
            maximum_vcpus: 1,
            maximum_resident_bytes: 512 << 20,
            maximum_writable_bytes: 1 << 30,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: Some(attempt),
            fork_target: None,
            terminal: false,
        };
        cleanup.complete().unwrap();

        assert!(host.prepare_original_native_retirement().is_err());

        assert!(std::fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
        assert_eq!(
            std::fs::read(root.path().join("attempt/retained")).unwrap(),
            b"owned bytes"
        );
        assert!(host.storage.is_some());
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());
    }

    #[test]
    fn physical_retirement_witness_closes_actual_storage_before_same_slot_reuse() {
        let (_roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let generation = attempt.generation;
        let (root, storage, descriptor) = generic_storage();
        use std::os::unix::fs::MetadataExt;
        let descriptor_path = format!("/proc/self/fd/{descriptor}");
        let retained = std::fs::metadata(&descriptor_path).unwrap();
        let original_identity = (retained.dev(), retained.ino());
        let mut host = super::super::LinuxQemuAttemptHostOwner {
            process: None,
            storage: Some(storage),
            maximum_vcpus: 1,
            maximum_resident_bytes: 512 << 20,
            maximum_writable_bytes: 1 << 30,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: Some(attempt),
            fork_target: None,
            terminal: false,
        };
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());

        host.prepare_original_native_retirement()
            .unwrap()
            .unwrap()
            .close()
            .unwrap();

        // Parallel tests may reuse the numeric slot after the actual close.
        // The saved inode identity distinguishes reuse from our retained pin.
        match std::fs::metadata(&descriptor_path) {
            Ok(current) => assert_ne!((current.dev(), current.ino()), original_identity),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
        assert!(!root.path().join("attempt").exists());
        assert!(host.storage.is_none());
        let next = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        assert_ne!(next.generation, generation);
        next.require_original().unwrap();
        // This fixture has no installed cgroup/native control. It proves the
        // real saved-Cleanup storage close precedes slot generation reuse.
        let cleanup = next.cleanup().unwrap();
        next.close_vector().unwrap();
        drop(cleanup);
    }

    #[test]
    fn host_unwind_moves_actual_storage_into_the_same_active_slot() {
        let (mut roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let generation = attempt.generation;
        let (root, storage, descriptor) = generic_storage();
        let pinned = std::path::PathBuf::from(format!("/proc/self/fd/{descriptor}"));
        let before = std::fs::metadata(&pinned).unwrap();
        let host = super::super::LinuxQemuAttemptHostOwner {
            process: None,
            storage: Some(storage),
            maximum_vcpus: 1,
            maximum_resident_bytes: 512 << 20,
            maximum_writable_bytes: 1 << 30,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: Some(attempt),
            fork_target: None,
            terminal: false,
        };

        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _host = host;
                panic!("exercise actual host Drop during unwind");
            }))
            .is_err()
        );

        use std::os::unix::fs::MetadataExt;
        let retained = std::fs::metadata(&pinned).unwrap();
        assert_eq!(
            (retained.dev(), retained.ino()),
            (before.dev(), before.ino())
        );
        assert_eq!(
            std::fs::read(root.path().join("attempt/retained")).unwrap(),
            b"owned bytes"
        );
        let held = binding.roster.upgrade().unwrap();
        {
            let state = held.lock().unwrap();
            assert_eq!(state.slots[0].active, Some(generation));
            assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());
        }
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());

        roster.retry_unsettled().unwrap();

        assert!(!root.path().join("attempt").exists());
        match std::fs::metadata(&pinned) {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
            Ok(after) => assert_ne!((after.dev(), after.ino()), (before.dev(), before.ino())),
        }
        assert!(held.lock().unwrap().slots[0].active.is_none());
        assert!(held.lock().unwrap().slots[0].unsettled.is_none());
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_ok());
    }

    #[test]
    fn terminal_cleanup_refuses_retry_and_keeps_actual_storage_and_generation() {
        let (mut roster, binding, _supervisor) = roster();
        let attempt = binding.claim(1, 512 << 20, 1 << 30).unwrap();
        let cleanup = attempt.cleanup().unwrap();
        let (root, storage, descriptor) = generic_storage();
        attempt
            .retain_unsettled(RetainedNativeHost {
                process: None,
                storage: Some(storage),
                native_resources: None,
                unconfigured: None,
            })
            .unwrap();
        cleanup.complete().unwrap();

        assert!(roster.retry_unsettled().is_err());

        assert!(std::fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
        assert_eq!(
            std::fs::read(root.path().join("attempt/retained")).unwrap(),
            b"owned bytes"
        );
        assert!(binding.claim(1, 512 << 20, 1 << 30).is_err());
        assert!(attempt.close_vector().is_err());
        let held = binding.roster.upgrade().unwrap();
        let state = held.lock().unwrap();
        assert_eq!(state.slots[0].active, Some(attempt.generation));
        assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());
        assert!(Arc::ptr_eq(
            state.slots[0].cleanup.as_ref().unwrap(),
            &cleanup
        ));
    }

    fn node_roster() -> (
        OriginalNativeAccountRoster,
        OriginalNativeAccountFactoryBinding,
        Arc<HostOperationGuard>,
        HostOperationSupervisor,
    ) {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let (credit, _, _) =
            OriginalNativeAccountCredit::mechanism_credit(Arc::clone(&original)).unwrap();
        let (roster, factory) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1).unwrap();
        (roster, factory, original, supervisor)
    }

    #[test]
    fn unqualified_device_workspace_refuses_before_purpose_assignment() {
        let (_roster, factory, original, _supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let held = factory.roster.upgrade().unwrap();
        let before_generation = held.lock().unwrap().next_workspace_generation;

        assert!(matches!(
            attempt.prepare_device_digest_workspace(&original, 1),
            Err(OriginalActorAccountError::Unavailable)
        ));

        let state = held.lock().unwrap();
        assert_eq!(state.next_workspace_generation, before_generation);
        assert!(
            state.slots[0]
                .digest_purposes
                .iter()
                .all(|purpose| !purpose.is_live())
        );
        assert_eq!(state.slots[0].active, Some(attempt.generation));
        assert!(!state.slots[0].launch_abandoned);
        drop(state);
        attempt.cleanup().unwrap();
        attempt.close_vector().unwrap();
    }

    #[test]
    fn device_workspace_refusal_preserves_actual_original_cancellation() {
        let (_roster, factory, original, supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        supervisor.cancel().unwrap();

        assert!(matches!(
            attempt.prepare_device_digest_workspace(&original, 1),
            Err(OriginalActorAccountError::Supervision(_))
        ));

        let held = factory.roster.upgrade().unwrap();
        let state = held.lock().unwrap();
        assert!(
            state.slots[0]
                .digest_purposes
                .iter()
                .all(|purpose| !purpose.is_live())
        );
        assert_eq!(state.slots[0].active, Some(attempt.generation));
    }

    #[test]
    fn active_and_staged_node_witnesses_block_control_and_reuse_until_both_drop() {
        let (_roster, factory, original, _supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let witness = attempt.prepare_node_binding(&original).unwrap();
        attempt.cleanup().unwrap();

        witness.verify_against(&attempt, &original).unwrap();
        let staged = attempt.prepare_node_binding(&original).unwrap();
        assert!(attempt.prepare_node_binding(&original).is_err());
        assert!(attempt.close_vector().is_err());
        assert!(factory.claim(1, 512 << 20, 1 << 30).is_err());
        let held = factory.roster.upgrade().unwrap();
        assert_eq!(held.lock().unwrap().slots[0].node_bindings_live, 2);

        drop(witness);
        assert!(attempt.close_vector().is_err());
        drop(staged);
        attempt.close_vector().unwrap();
        let next = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        assert_ne!(next.generation, attempt.generation);
        assert_eq!(held.lock().unwrap().slots[0].node_bindings_live, 0);
        assert!(attempt.prepare_node_binding(&original).is_err());
        next.prepare_node_binding(&original).unwrap();
    }

    #[test]
    fn node_witness_rejects_other_roster_and_preparation_before_binding() {
        let (_roster, factory, original, _supervisor) = node_roster();
        let (_other_roster, other_factory, other_original, _other_supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let other_attempt = other_factory.claim(1, 512 << 20, 1 << 30).unwrap();
        assert_eq!(attempt.generation, other_attempt.generation);
        assert!(attempt.prepare_node_binding(&other_original).is_err());
        let witness = attempt.prepare_node_binding(&original).unwrap();

        assert!(
            witness
                .verify_against(&other_attempt, &other_original)
                .is_err()
        );
        assert!(witness.verify_against(&attempt, &other_original).is_err());
        witness.verify_against(&attempt, &original).unwrap();
    }

    #[test]
    fn node_witness_real_cancellation_keeps_outstanding_generation() {
        let (_roster, factory, original, supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let witness = attempt.prepare_node_binding(&original).unwrap();
        supervisor.cancel().unwrap();

        assert!(matches!(
            witness.verify_against(&attempt, &original),
            Err(OriginalActorAccountError::Supervision(_))
        ));
        assert!(attempt.prepare_node_binding(&original).is_err());
        assert!(attempt.close_vector().is_err());
        let held = factory.roster.upgrade().unwrap();
        assert_eq!(held.lock().unwrap().slots[0].node_bindings_live, 1);
        drop(witness);
        assert_eq!(held.lock().unwrap().slots[0].node_bindings_live, 0);
        assert_eq!(
            held.lock().unwrap().slots[0].active,
            Some(attempt.generation)
        );
    }

    #[test]
    fn fixed_launch_refusal_retains_same_paid_control_and_terminal_slot() {
        let (_roster, factory, original, supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let preparation = attempt.prepare_fresh_launch().unwrap();
        let held = factory.roster.upgrade().unwrap();
        let assigned = held.lock().unwrap().slots[0].launch_controls_bytes;
        assert!(assigned > 0);
        drop(preparation);
        drop(attempt.prepare_fresh_launch().unwrap());
        assert_eq!(
            held.lock().unwrap().slots[0].launch_controls_bytes,
            assigned
        );
        let cleanup = attempt.cleanup().unwrap();
        let mut preparation = attempt.prepare_fresh_launch().unwrap();
        preparation.enter_mechanism();

        supervisor.cancel().unwrap();
        let after = original.wait_slice().unwrap_err();
        let retained = attempt.retain_launch_refusal(
            preparation.mechanism_refusal(OriginalActorAccountError::Unavailable, after),
        );
        assert_eq!(retained.original_after(), Some(&after));
        assert!(std::error::Error::source(retained.as_ref()).is_some());
        assert!(retained.same_owner(
            held.lock().unwrap().slots[0]
                .launch_refusal
                .as_ref()
                .unwrap(),
        ));
        assert!(attempt.prepare_fresh_launch().is_err());
        assert!(attempt.prepare_node_binding(&original).is_err());
        assert!(attempt.close_vector().is_err());
        assert!(factory.claim(1, 512 << 20, 1 << 30).is_err());
        // Terminal launch refusal prevents reuse, but it does not remove the
        // independently saved cleanup control from the same physical owner.
        assert!(Arc::ptr_eq(
            &cleanup,
            held.lock().unwrap().slots[0].cleanup.as_ref().unwrap(),
        ));
        drop(retained);
        assert!(held.lock().unwrap().slots[0].launch_refusal.is_some());
    }

    #[test]
    fn same_slot_concurrent_launch_refuses_until_unused_preparation_drops() {
        let (_roster, factory, _original, _supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let preparation = attempt.prepare_fresh_launch().unwrap();

        std::thread::scope(|scope| {
            let second = scope.spawn(|| attempt.prepare_fresh_launch().is_err());
            assert!(second.join().unwrap());
        });
        assert!(attempt.close_vector().is_err());
        drop(preparation);

        let next = attempt.prepare_fresh_launch().unwrap();
        let held = factory.roster.upgrade().unwrap();
        assert!(held.lock().unwrap().slots[0].launch_in_flight);
        assert!(!held.lock().unwrap().slots[0].launch_abandoned);
        drop(next);
        assert!(!held.lock().unwrap().slots[0].launch_in_flight);
    }

    #[test]
    fn entered_launch_unwind_retains_terminal_slot_without_an_error_arc() {
        let (_roster, factory, _original, _supervisor) = node_roster();
        let attempt = factory.claim(1, 512 << 20, 1 << 30).unwrap();
        let preparation = attempt.prepare_fresh_launch().unwrap();

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut preparation = preparation;
            preparation.enter_mechanism();
            panic!("actual entered preparation unwind");
        }));
        assert!(unwind.is_err());

        let held = factory.roster.upgrade().unwrap();
        let state = held.lock().unwrap();
        assert!(!state.slots[0].launch_in_flight);
        assert!(state.slots[0].launch_abandoned);
        assert!(state.slots[0].launch_refusal.is_none());
        assert_eq!(state.slots[0].active, Some(attempt.generation));
        drop(state);
        assert!(attempt.prepare_fresh_launch().is_err());
        assert!(attempt.close_vector().is_err());
        assert!(factory.claim(1, 512 << 20, 1 << 30).is_err());
    }
}

/// Binds one genuine factory to the original external roster without credit.
///
/// This move-only weak handle owns no loan, bank or replacement clock. It can
/// only be obtained from the already admitted roster; it is not a domain or
/// process-birth permission.
pub struct OriginalNativeAccountFactoryBinding {
    roster: RosterWeak,
}

/// Identifies one admitted native generation from birth through node destruction.
///
/// Only the actual attempt issues this move-only witness. Its weak reference
/// uses the existing roster allocation; its outstanding count blocks reuse until
/// the node has physically dropped this inline field. It is not a Source or
/// process-birth permission.
pub(crate) struct OriginalNativeNodeBinding {
    roster: RosterWeak,
    index: usize,
    generation: u64,
    installed_process: Option<InstalledProcessPurposeLoan>,
    issued_process_record: Option<process_purpose::IssuedInstalledProcessRecord>,
    source_host: Option<
        crucible_host_resources::host_services::process_birth::AuthenticatedSourceHostPurpose,
    >,
}

#[cfg(feature = "private-measurement-domain")]
mod parent_park_cleanup;
#[cfg(feature = "private-measurement-domain")]
pub use parent_park_cleanup::OriginalParentParkCleanup;

pub(crate) struct NativeAccountAttempt {
    roster: RosterWeak,
    index: usize,
    generation: u64,
}

/// Preserves a physical refusal before its separate original postcheck.
#[derive(Debug)]
struct NativeAccountBoundaryError {
    primary: Option<QemuVmRealizationError>,
    original: OriginalActorAccountError,
}

impl std::fmt::Display for NativeAccountBoundaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "original native boundary refused: primary={:?}; original={}",
            self.primary, self.original
        )
    }
}

impl std::error::Error for NativeAccountBoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.primary
            .as_ref()
            .map_or(Some(&self.original), |primary| Some(primary))
    }
}

pub(super) fn original_error(original: OriginalActorAccountError) -> QemuVmRealizationError {
    match original {
        OriginalActorAccountError::NativeReturn(source) => {
            QemuVmRealizationError::NativePoolReturn { source }
        }
        original => QemuVmRealizationError::ModelCopy {
            source: Box::new(original),
        },
    }
}

#[derive(Debug, thiserror::Error)]
#[error("native setup failed: {primary}; cleanup: {cleanup:?}; original: {original_after:?}")]
struct NativeSetupRefusal {
    #[source]
    primary: QemuVmRealizationError,
    cleanup: Option<QemuVmRealizationError>,
    original_after: Option<OriginalActorAccountError>,
}

pub(super) fn setup_refusal(
    attempt: &NativeAccountAttempt,
    primary: QemuVmRealizationError,
    cleanup: Result<(), QemuVmRealizationError>,
) -> QemuVmRealizationError {
    QemuVmRealizationError::ModelCopy {
        source: Box::new(NativeSetupRefusal {
            primary,
            cleanup: cleanup.err(),
            original_after: attempt.require_original().err(),
        }),
    }
}

pub(super) fn after_cleanup<T>(
    result: Result<T, QemuVmRealizationError>,
    cleanup: &HostOperationGuard,
) -> Result<T, QemuVmRealizationError> {
    after_boundary(result, cleanup.wait_slice().map(|_| ()).map_err(Into::into))
}

pub(in crate::linux_attempt_host) fn after_boundary<T>(
    result: Result<T, QemuVmRealizationError>,
    original: Result<(), OriginalActorAccountError>,
) -> Result<T, QemuVmRealizationError> {
    match (result, original) {
        (result, Ok(())) => result,
        (Ok(_), Err(original)) => Err(original_error(original)),
        (Err(primary), Err(original)) => Err(QemuVmRealizationError::ModelCopy {
            source: Box::new(NativeAccountBoundaryError {
                primary: Some(primary),
                original,
            }),
        }),
    }
}

struct NativeRoster {
    slots: [NativeSlot; MAX_NATIVE_WORKERS],
    width: usize,
    next_generation: u64,
    next_workspace_generation: u64,
}

struct NativeSlot {
    credit: Option<OriginalNativeAccountCredit>,
    active: Option<u64>,
    node_bindings_live: u8,
    digest_purposes:
        [device_digest::DigestPurposeState; MAX_ORIGINAL_NATIVE_NODE_GENERATIONS as usize],
    launch_controls_bytes: u64,
    cleanup_controls_bytes: u64,
    process_binding_bytes: u64,
    issuer_controls_bytes: u64,
    family_constructor_bytes: u64,
    installed_process: Option<process_purpose::InstalledProcessState>,
    source_control_payer:
        Option<crucible_host_resources::host_services::process_birth::SourceHostControlPayer>,
    launch_in_flight: bool,
    launch_abandoned: bool,
    launch_refusal: Option<super::original_node::RetainedNativeFreshLaunchError>,
    source_controller: Option<super::original_node::RetainedNativeFreshLaunchError>,
    source_cleanup_assigned: bool,
    control: Option<OriginalNativeControlRetirement>,
    cleanup: Option<Arc<HostOperationGuard>>,
    unsettled: Option<RetainedNativeHost>,
    fork_target: fork_target::ForkTargetSlot,
}

impl NativeSlot {
    fn assigned_metadata_bytes(&self) -> Result<u64, OriginalActorAccountError> {
        self.digest_purposes.iter().try_fold(
            self.launch_controls_bytes
                .checked_add(self.cleanup_controls_bytes)
                .and_then(|bytes| bytes.checked_add(self.process_binding_bytes))
                .and_then(|bytes| bytes.checked_add(self.issuer_controls_bytes))
                .and_then(|bytes| bytes.checked_add(self.family_constructor_bytes))
                .ok_or(OriginalActorAccountError::Unavailable)?,
            |used, purpose| {
                used.checked_add(purpose.metadata_bytes())
                    .ok_or(OriginalActorAccountError::Unavailable)
            },
        )
    }

    /// Prices fixed helper copies before entering their constructor frame.
    fn reserve_family_constructor(&mut self) -> Result<(), OriginalActorAccountError> {
        let extent = process_purpose::family_constructor_extent()?;
        if self.family_constructor_bytes == extent {
            return Ok(());
        }
        if self.family_constructor_bytes != 0 {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.require_metadata_assignment(extent)?;
        // This peak is reused under this slot's exclusive lock. Keeping it
        // assigned avoids a new history debit for every successful campaign.
        self.family_constructor_bytes = extent;
        Ok(())
    }

    fn require_metadata_assignment(&self, bytes: u64) -> Result<(), OriginalActorAccountError> {
        self.require_metadata_assignment_replacing_pending(bytes, 0)
    }

    fn require_metadata_assignment_replacing_pending(
        &self,
        bytes: u64,
        pending: u64,
    ) -> Result<(), OriginalActorAccountError> {
        let credit = self
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let total = self
            .assigned_metadata_bytes()?
            .checked_add(bytes)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let process_bytes = self.installed_process.as_ref().map_or(
            0,
            process_purpose::InstalledProcessState::reserved_metadata_bytes,
        );
        let process_bytes = process_bytes
            .checked_sub(pending)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if total
            .checked_add(process_bytes)
            .is_none_or(|total| total > credit.total_metadata_bytes())
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(())
    }
}

/// The same created owners, moved before a refusal can drop or replace them.
pub(super) struct RetainedNativeHost {
    pub(super) process: Option<LinuxQemuAttemptProcessOwner>,
    pub(super) storage: Option<LinuxQemuAttemptStorageOwner>,
    pub(super) native_resources: Option<Arc<NativeResourceState>>,
    pub(super) unconfigured: Option<crate::linux_cgroup::LinuxQemuCgroupCleanupAuthority>,
}

impl RetainedNativeHost {
    // Each field is cleared only after its actual physical close above the
    // independent Cleanup postcut. This observation does not issue cleanup.
    fn bodies_returned(&self) -> bool {
        self.process.is_none()
            && self.storage.is_none()
            && self.native_resources.is_none()
            && self.unconfigured.is_none()
    }

    fn finish(&mut self, cleanup: &HostOperationGuard) -> Result<(), QemuVmRealizationError> {
        cleanup
            .wait_slice()
            .map_err(|source| original_error(source.into()))?;
        if let Some(process) = self.process.as_mut() {
            process.finish_under_original(cleanup)?;
        }
        self.process = None;
        if let Some(group) = self.unconfigured.as_mut() {
            group.remove_under_original(cleanup)?;
        }
        self.unconfigured = None;
        if let Some(state) = self.native_resources.as_ref() {
            NativeResourceState::drain(state);
        }
        self.native_resources = None;
        cleanup
            .wait_slice()
            .map_err(|source| original_error(source.into()))?;
        let result = if let Some(storage) = self.storage.as_mut() {
            storage.cleanup_under_original(cleanup)
        } else {
            Ok(())
        };
        if result.is_ok() {
            // Physical release is recorded before the separate original
            // postcut. Refusal leaves the actual owner in this same slot.
            self.storage = None;
        }
        after_cleanup(result, cleanup)
    }
}

impl std::fmt::Debug for OriginalNativeAccountFactoryBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalNativeAccountFactoryBinding")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeAccountAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAccountAttempt")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl OriginalNativeAccountRoster {
    /// Publishes a width-one normal roster from its same prepaid credit slot.
    ///
    /// Geometry, genuine normal-purpose checks and the same Main's independent
    /// allocation charge precede credit movement. Allocation and returned holder
    /// construction are infallible after that cut.
    ///
    /// # Errors
    /// Refuses absent credit, wrong control geometry or lack of a genuine normal
    /// subdivision before moving the original credit from its source slot.
    pub(super) fn publish_normal_credit(
        credit: &mut Option<OriginalNativeAccountCredit>,
    ) -> Result<(Self, OriginalNativeAccountFactoryBinding), OriginalActorAccountError> {
        let controls = Self::shared_allocation_extent()?;
        let retained = credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if retained.normal_controls_bytes != controls {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let original = retained
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let normal = original
            .normal
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;

        // Main prepays the full Arc allocation before the native pair moves.
        // Weak observers retain this separate charge after the body closes.
        let funding = normal.reserve_roster_allocation(controls, &original.preparation)?;
        let credit = credit
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(Self::publish_allocated(
            [Some(credit), None, None, None],
            1,
            Some(funding),
        ))
    }

    pub(super) fn matches_binding(&self, binding: &OriginalNativeAccountFactoryBinding) -> bool {
        self.held
            .as_ref()
            .is_some_and(|held| binding.roster.matches_owner(held))
    }

    pub(super) fn publish(
        credits: [Option<OriginalNativeAccountCredit>; MAX_NATIVE_WORKERS],
        width: usize,
    ) -> Result<(Self, OriginalNativeAccountFactoryBinding), OriginalActorAccountError> {
        if !matches!(width, 1 | 2 | 4)
            || credits.iter().take(width).any(Option::is_none)
            || credits.iter().skip(width).any(Option::is_some)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(Self::publish_allocated(credits, width, None))
    }

    fn publish_allocated(
        credits: [Option<OriginalNativeAccountCredit>; MAX_NATIVE_WORKERS],
        width: usize,
        funding: Option<NativeRosterAllocationFunding>,
    ) -> (Self, OriginalNativeAccountFactoryBinding) {
        let roster = RosterOwner::new(
            Mutex::new(NativeRoster {
                slots: credits.map(|credit| NativeSlot {
                    issuer_controls_bytes: credit
                        .as_ref()
                        .map_or(0, |held| held.normal_controls_bytes),
                    credit,
                    family_constructor_bytes: 0,
                    active: None,
                    node_bindings_live: 0,
                    digest_purposes: [device_digest::DigestPurposeState::default();
                        MAX_ORIGINAL_NATIVE_NODE_GENERATIONS as usize],
                    launch_controls_bytes: 0,
                    cleanup_controls_bytes: 0,
                    process_binding_bytes: 0,
                    installed_process: None,
                    source_control_payer: None,
                    launch_in_flight: false,
                    launch_abandoned: false,
                    launch_refusal: None,
                    source_controller: None,
                    source_cleanup_assigned: false,
                    control: None,
                    cleanup: None,
                    unsettled: None,
                    fork_target: fork_target::ForkTargetSlot::default(),
                }),
                width,
                next_generation: 1,
                next_workspace_generation: 1,
            }),
            funding,
        );
        let binding = OriginalNativeAccountFactoryBinding {
            roster: roster.downgrade(),
        };
        (
            Self {
                held: Some(roster),
                retiring_credits: std::array::from_fn(|_| None),
            },
            binding,
        )
    }

    /// Prices shared roster storage while the fixed pool pays its external facade.
    ///
    /// # Errors
    /// Refuses an overflowing actual allocation layout or unrepresentable extent.
    pub(super) fn shared_allocation_extent() -> Result<u64, OriginalActorAccountError> {
        Self::allocation_extent()?
            .checked_sub(std::mem::size_of::<Self>() as u64)
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(super) fn allocation_extent() -> Result<u64, OriginalActorAccountError> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Mutex<NativeRoster>>())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<Self>())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        u64::try_from(bytes).map_err(|_| OriginalActorAccountError::Unavailable)
    }

    /// Retries the same retained physical owners under their original Cleanup.
    ///
    /// This starts no worker and accepts no caller retirement assertion. Each
    /// stored owner must actually finish before its native control closes and
    /// the slot becomes reusable. Paired account credit remains charged. On
    /// expiry, poison or physical refusal, the actual owners remain here for
    /// the enclosing ParentVM's physical containment and retirement.
    ///
    /// # Errors
    /// Preserves the first physical refusal and its independent original cut,
    /// or refuses consumed custody, original expiry and surviving aliases.
    pub fn retry_unsettled(&mut self) -> Result<(), QemuVmRealizationError> {
        // Actual failed Source bodies are driven before the pure quiescence
        // gate. The short roster clone lock is gone before any body work.
        let launch_return = self.retry_failed_launch_bodies();
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
        // Contention must not wait beyond the caller's saved Cleanup.
        // Refusal leaves the same roster and every physical owner untouched.
        let width = held
            .try_lock()
            .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?
            .width;
        for index in 0..width {
            let generation = {
                let state = held
                    .try_lock()
                    .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
                let slot = &state.slots[index];
                slot.active
                    .filter(|_| slot.unsettled.is_some() && !slot.fork_target.is_owned())
            };
            if let Some(generation) = generation {
                NativeAccountAttempt {
                    roster: held.downgrade(),
                    index,
                    generation,
                }
                .cleanup()
                .map_err(original_error)?;
            }
        }
        let mut state = held
            .try_lock()
            .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
        for slot in &mut state.slots {
            fork_target::retry_unsettled_target(slot)?;
            if slot.fork_target.is_owned() || slot.unsettled.is_none() {
                continue;
            }
            let cleanup = slot
                .cleanup
                .as_ref()
                .map(Arc::clone)
                .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
            slot.unsettled
                .as_mut()
                .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
                .finish(&cleanup)?;
            close_slot(slot).map_err(original_error)?;
            slot.unsettled = None;
        }
        launch_return.map_err(original_error)
    }
}

impl Drop for OriginalNativeAccountRoster {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            // An absent facade or body does not prove physical retirement,
            // final Weak control closure, or the enclosing factory's free.
            std::mem::forget(held);
        }
    }
}

impl OriginalNativeAccountFactoryBinding {
    /// Verifies the exact returned guard retained by this original roster.
    ///
    /// This verifies identity and liveness only. It creates no account, guard,
    /// domain or launch permission and exposes none of the retained authority.
    ///
    /// # Errors
    /// Refuses missing custody, poison, a different guard allocation or the
    /// same original's cancellation, terminal state or absolute deadline.
    pub fn verify_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        for slot in state.slots.iter().take(state.width) {
            slot.credit
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?
                .verify_preparation(preparation)?;
        }
        Ok(())
    }

    pub(super) fn claim(
        &self,
        vcpus: u32,
        resident: u64,
        backing: u64,
    ) -> Result<NativeAccountAttempt, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let index = state
            .slots
            .iter()
            .take(state.width)
            .position(|slot| {
                slot.active.is_none()
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = state.slots[index]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        credit.require_vcpu_ceiling(vcpus)?;
        if vcpus != 1
            || resident == 0
            || resident > credit.full_resident_bytes()
            || backing == 0
            || backing > credit.full_backing_bytes()
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let generation = state.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // Contract sealing creates this shared control before fresh-launch
        // preparation. Its Weak witnesses can retain the header after the last
        // descriptor closes, so keep the history assigned until roster free.
        let extent = crate::QemuProcessStageBinding::retained_control_bytes()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .checked_add(credit.normal_preparation_extent()?)
            .and_then(|bytes| bytes.checked_add(fork_target::retained_control_extent().ok()?))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let slot = &mut state.slots[index];
        let launch = if slot.launch_controls_bytes == 0 {
            fresh_launch_control_extent()?
        } else {
            0
        };
        slot.require_metadata_assignment(
            extent
                .checked_add(launch)
                .ok_or(OriginalActorAccountError::Unavailable)?,
        )?;
        if launch != 0 {
            slot.launch_controls_bytes = launch;
        }
        slot.process_binding_bytes = slot
            .process_binding_bytes
            .checked_add(extent)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if let Err(error) = slot
            .credit
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .enter_normal_preparation()
        {
            slot.launch_abandoned = true;
            return Err(error);
        }
        let controller = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .prepare_launch_controller()?;
        slot.source_controller = Some(controller);
        slot.source_cleanup_assigned = false;
        state.next_generation = next_generation;
        state.slots[index].active = Some(generation);
        // Publish the funded controller before the independent Original post.
        // A refused post retains the same allocation and excludes slot reuse.
        if let Err(error) = state.slots[index]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .require_original()
        {
            state.slots[index].launch_abandoned = true;
            return Err(error);
        }
        Ok(NativeAccountAttempt {
            roster: RosterWeak::clone(&self.roster),
            index,
            generation,
        })
    }
}

impl NativeAccountAttempt {
    /// Checks retained physical control before a lent issuer can enter a body.
    pub(super) fn require_live_launch_control(&self) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
                    && slot
                        .control
                        .as_ref()
                        .is_some_and(OriginalNativeControlRetirement::is_available)
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .require_original()
    }

    /// Lends the same generation without creating a replacement account or loan.
    pub(super) fn borrow_installed_issuer_attempt(
        &self,
        contract: &crate::QemuChildProcessContract,
    ) -> Result<Self, OriginalActorAccountError> {
        self.require_live_launch_control()?;
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !slot
            .installed_process
            .as_ref()
            .is_some_and(|purpose| purpose.matches_launch_contract(contract))
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(Self {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        })
    }

    pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        let original = self.cleanup_entry()?;
        original.wait_slice()?;
        Ok(original)
    }

    fn cleanup_entry(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let controller = {
            let mut state = roster
                .try_lock()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            let slot = state
                .slots
                .get_mut(self.index)
                .filter(|slot| slot.active == Some(self.generation))
                .ok_or(OriginalActorAccountError::Unavailable)?;
            assign_source_cleanup(slot)?;
            slot.source_controller
                .as_ref()
                .cloned()
                .ok_or(OriginalActorAccountError::Unavailable)?
        };
        // The real preborn controller owns the cache across unwind/refusal.
        // No roster lock is held while beginning or observing its Original.
        let original = controller.retained_cleanup()?;
        let mut state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot
                        .source_controller
                        .as_ref()
                        .is_some_and(|saved| saved.same_owner(&controller))
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if slot.cleanup.is_none() {
            slot.cleanup = Some(Arc::clone(&original));
        }
        if !slot
            .cleanup
            .as_ref()
            .is_some_and(|saved| Arc::ptr_eq(saved, &original))
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(original)
    }

    pub(super) fn retain_unsettled(
        &self,
        owners: RetainedNativeHost,
    ) -> Result<(), OriginalActorAccountError> {
        let Some(roster) = self.roster.upgrade() else {
            std::mem::forget(owners);
            return Err(OriginalActorAccountError::Unavailable);
        };
        let Ok(mut state) = roster.lock() else {
            std::mem::forget(owners);
            return Err(OriginalActorAccountError::Unavailable);
        };
        let Some(slot) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation) && slot.unsettled.is_none())
        else {
            std::mem::forget(owners);
            return Err(OriginalActorAccountError::Unavailable);
        };
        // Publication precedes every diagnostic or original post-refusal.
        // Dropping either facade must never dispatch the ordinary worker.
        slot.unsettled = Some(owners);
        Ok(())
    }

    pub(crate) fn after<T>(
        &self,
        result: Result<T, QemuVmRealizationError>,
    ) -> Result<T, QemuVmRealizationError> {
        after_boundary(result, self.require_original())
    }

    pub(crate) fn after_refusal(&self, primary: QemuVmRealizationError) -> QemuVmRealizationError {
        match self.require_original() {
            Ok(()) => primary,
            Err(original) => QemuVmRealizationError::ModelCopy {
                source: Box::new(NativeAccountBoundaryError {
                    primary: Some(primary),
                    original,
                }),
            },
        }
    }

    pub(super) fn prepare_fresh_launch(
        &self,
    ) -> Result<super::original_node::OriginalNativeFreshPreparation, OriginalActorAccountError>
    {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
                    && !slot.launch_in_flight
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        credit.require_original()?;

        // claim() assigns this actual target extent before process sealing.
        if slot.launch_controls_bytes == 0 {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let controller = slot
            .source_controller
            .as_ref()
            .cloned()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let preparation = credit.prepare_fresh_launch(
            NativeAccountAttempt {
                roster: RosterWeak::clone(&self.roster),
                index: self.index,
                generation: self.generation,
            },
            controller,
        )?;
        slot.launch_in_flight = true;
        Ok(preparation)
    }

    pub(super) fn finish_fresh_launch(&self, entered: bool, completed: bool) {
        let Some(roster) = self.roster.upgrade() else {
            return;
        };
        let Ok(mut state) = roster.lock() else {
            return;
        };
        if let Some(slot) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation) && slot.launch_in_flight)
        {
            slot.launch_in_flight = false;
            if entered && !completed {
                // A failed or unwound entered launch is terminal even if no
                // typed error reached publication. Its physical owners and
                // precharged error purpose remain in this same active slot.
                slot.launch_abandoned = true;
            }
        }
    }

    pub(super) fn retain_launch_refusal(
        &self,
        retained: super::original_node::RetainedNativeFreshLaunchError,
    ) -> super::original_node::RetainedNativeFreshLaunchError {
        // Only a successful fixed-purpose preparation calls this method. The
        // external slot already holds its complete error-control assignment;
        // preserve the actual cause even if later publication itself is unsure.
        let Some(roster) = self.roster.upgrade() else {
            std::mem::forget(retained.clone());
            return retained;
        };
        let Ok(mut state) = roster.lock() else {
            std::mem::forget(retained.clone());
            return retained;
        };
        let Some(slot) = state.slots.get_mut(self.index).filter(|slot| {
            slot.active == Some(self.generation)
                && slot.launch_controls_bytes != 0
                && slot.launch_in_flight
                && slot.launch_refusal.is_none()
                && !slot.launch_abandoned
        }) else {
            std::mem::forget(retained.clone());
            return retained;
        };
        slot.launch_refusal = Some(retained.clone());
        retained
    }

    pub(crate) fn prepare_node_binding(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<OriginalNativeNodeBinding, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.node_bindings_live < MAX_ORIGINAL_NATIVE_NODE_GENERATIONS
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        credit.verify_preparation(original)?;

        // The external native pair already retains TOTAL metadata. This inline
        // purpose belongs within that same TOTAL; it supplies no additional
        // native allowance. A completed native-floor calculation must include
        // this field before native installation can become eligible.
        let extent = u64::try_from(std::mem::size_of::<Option<OriginalNativeNodeBinding>>())
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        if extent > credit.total_metadata_bytes() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        slot.node_bindings_live += 1;
        let binding = OriginalNativeNodeBinding {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            installed_process: None,
            issued_process_record: None,
            source_host: None,
        };
        drop(state);
        if let Err(error) = self.require_original() {
            drop(binding);
            return Err(error);
        }
        Ok(binding)
    }

    pub(crate) fn require_original(&self) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .require_original()
    }

    pub(super) fn retain_control(
        &self,
        control: OriginalNativeControlRetirement,
    ) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.control.is_none()
                    && slot.unsettled.is_none()
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.control = Some(control);
        Ok(())
    }

    pub(super) fn matches_controller(
        &self,
        controller: &super::LinuxQemuNativeResourceController,
    ) -> Result<bool, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation) && slot.unsettled.is_none())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.cleanup
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .wait_slice()?;
        Ok(slot
            .control
            .as_ref()
            .is_some_and(|control| control.matches_controller(controller)))
    }

    pub(super) fn after_registry_retirement(
        &self,
        result: Result<(), QemuVmRealizationError>,
    ) -> Result<(), QemuVmRealizationError> {
        let observed = (|| {
            let roster = self
                .roster
                .upgrade()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            let state = roster
                .lock()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            let slot = state
                .slots
                .get(self.index)
                .filter(|slot| slot.active == Some(self.generation) && slot.unsettled.is_none())
                .ok_or(OriginalActorAccountError::Unavailable)?;
            slot.cleanup
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?
                .wait_slice()?;
            Ok(())
        })();
        after_boundary(result, observed)
    }

    pub(super) fn close_registry_control(
        &self,
        controller: &mut super::LinuxQemuNativeResourceController,
    ) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation) && slot.unsettled.is_none())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.cleanup
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .wait_slice()?;
        slot.control
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .release_registry_alias(controller)
            .map_err(|source| OriginalActorAccountError::NativeControlBoundary {
                source,
                original: None,
            })?;
        let result = close_control(slot);
        if result.is_err()
            && let Some(control) = slot.control.as_ref()
        {
            // An in-flight borrower prevents closure. Restore this same registry
            // alias before returning; its row and lease remain retained.
            control.restore_registry_alias(controller);
        }
        result
    }

    /// Called only after the same host owner closed its process and storage.
    pub(super) fn close_vector(&self) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        close_slot(slot)
    }
}

fn assign_source_cleanup(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.source_cleanup_assigned {
        return Ok(());
    }
    if slot.source_controller.is_none() {
        return Err(OriginalActorAccountError::Unavailable);
    }
    let extent = cleanup_control_extent()?;
    let next = slot
        .cleanup_controls_bytes
        .checked_add(extent)
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let pending = match slot.installed_process.as_ref() {
        Some(purpose) if purpose.pending_cleanup_is(extent) => extent,
        Some(_) => return Err(OriginalActorAccountError::Unavailable),
        None => 0,
    };
    // The guard moves this exact existing floor into assigned history. It
    // does not add another simultaneous copy of the same reserved extent.
    slot.require_metadata_assignment_replacing_pending(extent, pending)?;
    if let Some(purpose) = slot.installed_process.as_mut()
        && !purpose.consume_cleanup(extent)
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    slot.cleanup_controls_bytes = next;
    slot.source_cleanup_assigned = true;
    Ok(())
}

fn close_control(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot
        .source_controller
        .as_ref()
        .is_some_and(|controller| !controller.physical_owners_returned())
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    if slot.node_bindings_live != 0
        || slot
            .digest_purposes
            .iter()
            .any(device_digest::DigestPurposeState::is_live)
        || slot.launch_refusal.is_some()
        || slot.launch_in_flight
        || slot.launch_abandoned
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.wait_slice()?;
    if let Some(control) = slot.control.as_mut() {
        let closed = control.close();
        let after = cleanup.wait_slice();
        if let Err(source) = closed {
            return Err(OriginalActorAccountError::NativeControlBoundary {
                source,
                original: after.err(),
            });
        }
        after?;
    }
    slot.control = None;
    Ok(())
}

fn close_slot(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.node_bindings_live != 0
        || slot
            .digest_purposes
            .iter()
            .any(device_digest::DigestPurposeState::is_live)
        || slot.launch_refusal.is_some()
        || slot.launch_in_flight
        || slot.launch_abandoned
        || slot.fork_target.is_owned()
        || slot
            .installed_process
            .as_ref()
            .is_some_and(|purpose| !purpose.can_retire())
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    close_control(slot)?;
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.complete()?;
    slot.cleanup = None;
    slot.source_controller = None;
    slot.source_cleanup_assigned = false;
    // The host calls this only after actual process/descendant and storage
    // containment. Drop the family witness before allowing another generation.
    slot.installed_process = None;
    slot.source_control_payer = None;
    // Paired credit remains fully charged after genuine vector closure.
    slot.active = None;
    Ok(())
}

impl OriginalNativeNodeBinding {
    pub(crate) fn verify_against(
        &self,
        attempt: &NativeAccountAttempt,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        if !RosterWeak::ptr_eq(&self.roster, &attempt.roster)
            || self.index != attempt.index
            || self.generation != attempt.generation
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.node_bindings_live > 0
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .verify_preparation(original)
    }
}

impl Drop for OriginalNativeNodeBinding {
    fn drop(&mut self) {
        let Some(roster) = self.roster.upgrade() else {
            return;
        };
        let Ok(mut state) = roster.lock() else {
            return;
        };
        if let Some(slot) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation) && slot.node_bindings_live > 0)
        {
            slot.node_bindings_live -= 1;
        }
    }
}

impl NativeAccountAttempt {
    pub(super) fn reserve_contract_controls(
        &self,
        contract: &crate::QemuChildProcessContract,
        descriptors: u64,
        bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        OriginalActorAccountError,
    > {
        self.require_original()?;
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.unsettled.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let source = slot
            .installed_process
            .as_ref()
            .is_some_and(|purpose| purpose.matches_launch_contract(contract));
        if !source && !slot.fork_target.matches_live_contract(contract) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let payer = slot
            .source_control_payer
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        payer
            .reserve_controls(descriptors, bytes)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod normal_credit_tests;
