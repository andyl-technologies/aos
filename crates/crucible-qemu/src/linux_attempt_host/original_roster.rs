//! Retains native account credit outside the genuine factory and state controls.
//!
//! The fixed roster is sized by the authored one, two or four native workers.
//! Its own shared allocation is paid as initial actor structure. Each native
//! pair remains charged throughout the campaign; closing a slot only permits
//! reuse after that exact owner's physical vector and native control close.
//! This account binding does not issue Source, backing or launch permission.

use std::sync::{Arc, Mutex, Weak};

use crucible_linux_resource::host_supervision::HostOperationGuard;

use super::native_resources::NativeResourceState;
use super::native_resources::OriginalNativeControlRetirement;
use super::original_actor::{OriginalActorAccountError, OriginalNativeAccountCredit};
use crate::QemuVmRealizationError;
use crate::linux_attempt_process::LinuxQemuAttemptProcessOwner;
use crate::linux_attempt_storage::LinuxQemuAttemptStorageOwner;

const MAX_NATIVE_WORKERS: usize = 4;

/// Retains the finite original native account roster outside all funded owners.
///
/// Abandoning this owner retains its actual allocation and all original pairs.
/// Final factory, Source, namespace and enclosing allocation retirement remain
/// separate from an individual slot's physical vector closure.
#[must_use = "retain original native accounts through genuine factory retirement"]
pub struct OriginalNativeAccountRoster {
    held: Option<Arc<Mutex<NativeRoster>>>,
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these actual loan/guard/slot controls panic only when custody, original refusal or generation exclusion fails; they mint no authenticated parent or kernel grant.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_services::HostServiceError;
    use crucible_linux_resource::host_supervision::{
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
}

/// Binds one genuine factory to the original external roster without credit.
///
/// This move-only weak handle owns no loan, bank or replacement clock. It can
/// only be obtained from the already admitted roster; it is not a domain or
/// process-birth permission.
pub struct OriginalNativeAccountFactoryBinding {
    roster: Weak<Mutex<NativeRoster>>,
}

pub(crate) struct NativeAccountAttempt {
    roster: Weak<Mutex<NativeRoster>>,
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
    QemuVmRealizationError::ModelCopy {
        source: Box::new(original),
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

fn after_boundary<T>(
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
}

struct NativeSlot {
    credit: Option<OriginalNativeAccountCredit>,
    active: Option<u64>,
    control: Option<OriginalNativeControlRetirement>,
    cleanup: Option<Arc<HostOperationGuard>>,
    unsettled: Option<RetainedNativeHost>,
}

/// The same created owners, moved before a refusal can drop or replace them.
pub(super) struct RetainedNativeHost {
    pub(super) process: Option<LinuxQemuAttemptProcessOwner>,
    pub(super) storage: Option<LinuxQemuAttemptStorageOwner>,
    pub(super) native_resources: Option<Arc<NativeResourceState>>,
    pub(super) unconfigured: Option<crate::linux_cgroup::LinuxQemuCgroupCleanupAuthority>,
}

impl RetainedNativeHost {
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
        let roster = Arc::new(Mutex::new(NativeRoster {
            slots: credits.map(|credit| NativeSlot {
                credit,
                active: None,
                control: None,
                cleanup: None,
                unsettled: None,
            }),
            width,
            next_generation: 1,
        }));
        let binding = OriginalNativeAccountFactoryBinding {
            roster: Arc::downgrade(&roster),
        };
        Ok((Self { held: Some(roster) }, binding))
    }

    pub(super) fn allocation_extent() -> Result<u64, OriginalActorAccountError> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Mutex<NativeRoster>>())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
        u64::try_from(layout.pad_to_align().size())
            .map_err(|_| OriginalActorAccountError::Unavailable)
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
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
        let mut state = held
            .lock()
            .map_err(|_| original_error(OriginalActorAccountError::Unavailable))?;
        for slot in &mut state.slots {
            if slot.unsettled.is_none() {
                continue;
            }
            let cleanup = retain_cleanup(slot).map_err(original_error)?;
            slot.unsettled
                .as_mut()
                .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
                .finish(&cleanup)?;
            close_slot(slot).map_err(original_error)?;
            slot.unsettled = None;
        }
        Ok(())
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
            .position(|slot| slot.active.is_none() && slot.unsettled.is_none())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = state.slots[index]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        credit.require_original()?;
        if vcpus != 1
            || resident == 0
            || resident > credit.full_resident_bytes()
            || backing == 0
            || backing > credit.full_backing_bytes()
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let generation = state.next_generation;
        state.next_generation = generation
            .checked_add(1)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        state.slots[index].active = Some(generation);
        Ok(NativeAccountAttempt {
            roster: Weak::clone(&self.roster),
            index,
            generation,
        })
    }
}

impl NativeAccountAttempt {
    pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
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
        retain_cleanup(slot)
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
            .filter(|slot| slot.active == Some(self.generation) && slot.unsettled.is_none())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        close_slot(slot)
    }
}

fn retain_cleanup(
    slot: &mut NativeSlot,
) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    if slot.cleanup.is_none() {
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // The guard Arc is within the already admitted TOTAL metadata. The
        // finite supervisor BTree was charged once as initial actor structure.
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let extent = u64::try_from(layout.pad_to_align().size())
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        if extent > credit.total_metadata_bytes() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        slot.cleanup = Some(Arc::new(credit.begin_cleanup()?));
    }
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.wait_slice()?;
    Ok(Arc::clone(cleanup))
}

fn close_control(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
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
    close_control(slot)?;
    let cleanup = slot
        .cleanup
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    cleanup.complete()?;
    slot.cleanup = None;
    // Paired credit remains fully charged after genuine vector closure.
    slot.active = None;
    Ok(())
}
