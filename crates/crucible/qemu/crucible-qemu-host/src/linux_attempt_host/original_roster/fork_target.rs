//! Retains the second incarnation's nominal loan and actual physical custody.
//!
//! This fixed slot belongs to the already-issued Source family. A permit is
//! reserved before target cgroup birth and cannot release its share after birth
//! until real process, controller, contract and cleanup aliases have closed.

use super::*;
use crate::spawn::{ConfiguredProcessEnvelope, QemuProcessStageRetirement};

#[derive(Default)]
pub(super) struct ForkTargetSlot {
    next_epoch: u64,
    returned_epoch: u64,
    last_reserved_process_generation: u64,
    reserved_process_generation: Option<u64>,
    occupied: Option<u64>,
    born: bool,
    physical_closed: bool,
    envelope: Option<ConfiguredProcessEnvelope>,
    process_generation: Option<u64>,
    ram_registration_generation: Option<u64>,
    process_binding: Option<QemuProcessStageRetirement>,
    control: Option<OriginalNativeControlRetirement>,
    preparation: Option<Arc<HostOperationGuard>>,
    cleanup: Option<Arc<TargetCleanup>>,
    cleanup_completion_failure:
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    unsettled: Option<RetainedNativeHost>,
}

/// Preserves actual Target construction cleanup causes without another Box.
///
/// The physical owner remains in its canonical roster or containing guard.
/// This report itself never grants cleanup or attests resource return.
#[derive(Debug, thiserror::Error)]
pub enum QemuForkTargetConstructionError {
    /// The exact issuer, epoch, saved Cleanup or native control refused.
    #[error("Target construction original refused: {0}")]
    Original(#[from] OriginalActorAccountError),
    /// An existing retained process or cgroup cleanup failed.
    #[error("Target construction physical cleanup refused: {0}")]
    Physical(#[source] QemuVmRealizationError),
}

impl QemuForkTargetConstructionError {
    pub(super) fn into_realization(self) -> QemuVmRealizationError {
        match self {
            Self::Original(first) => original_error(first),
            Self::Physical(first) => first,
        }
    }
}

/// Retains cleanup access to one genuinely occupied Target construction.
///
/// Only its original move-only permit creates this loan. It grants no launch,
/// work or subdivision authority, and cannot select another Target epoch. The
/// containing constructor retains its real Source owner until it observes this
/// exact Target's return; loss of the roster is never inferred to mean closure.
#[must_use = "retain the same Target construction loan until exact physical return"]
pub struct QemuForkTargetConstructionLoan {
    attempt: NativeAccountAttempt,
    epoch: u64,
    process_generation: u64,
    returned: bool,
    failed_permit: Option<crate::linux_attempt_host::LinuxQemuForkTargetPermit>,
}

impl QemuForkTargetConstructionLoan {
    /// Returns the process generation reserved by this exact native Target role.
    ///
    /// This is distinct from the scheduler's modeled node generation and
    /// supplies no authority to create a RAM registration or native process.
    #[must_use]
    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }

    /// Borrows this exact Target's once-entered cleanup for a bounded close step.
    ///
    /// This enters no new preparation or clock. The saved Target origin alone
    /// may admit its existing eligible Cleanup; returned or foreign epochs are
    /// never reused to authorize another physical operation.
    ///
    /// # Errors
    /// Preserves the same cached admission refusal, or refuses unavailable,
    /// mismatched, returned, poisoned or terminal cleanup custody.
    pub fn retained_cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, QemuForkTargetConstructionError> {
        if self.returned {
            return Err(OriginalActorAccountError::Unavailable.into());
        }
        let roster = self
            .attempt
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.attempt.index)
            .filter(|slot| slot.active == Some(self.attempt.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if slot.fork_target.occupied != Some(self.epoch)
            || slot.fork_target.reserved_process_generation != Some(self.process_generation)
        {
            return Err(OriginalActorAccountError::Unavailable.into());
        }
        slot.fork_target.cleanup().map_err(Into::into)
    }

    /// Retries only this Target's canonical partial owners and saved Cleanup.
    ///
    /// A successful return means this exact Target role has closed. It does
    /// not retire the parent Source, World or original family reservation.
    ///
    /// # Errors
    /// Refuses foreign, stale, poisoned or still externally owned custody,
    /// failed physical cleanup, or the original Target Cleanup's refusal.
    pub fn try_finish(&mut self) -> Result<(), QemuForkTargetConstructionError> {
        if self.returned {
            return Ok(());
        }
        let (returned, result) = self
            .attempt
            .retry_target_construction(self.epoch, self.process_generation);
        // Record the irreversible slot return before propagating its report.
        self.returned |= returned;
        if self.returned {
            drop(self.failed_permit.take());
        }
        result
    }

    pub(in crate::linux_attempt_host) fn retain_failed_permit(
        &mut self,
        permit: crate::linux_attempt_host::LinuxQemuForkTargetPermit,
    ) {
        self.failed_permit = Some(permit);
    }

    /// Observes only the exact return already latched by this loan's retry.
    ///
    /// This fact issues no cleanup, return or new-work permission.
    #[must_use]
    pub const fn is_physically_returned(&self) -> bool {
        self.returned
    }
}

/// Shares this exact Target's once-entered Cleanup independently of roster locks.
pub(super) struct TargetCleanup {
    preparation: Arc<HostOperationGuard>,
    completed: bool,
    entered: std::sync::OnceLock<
        Result<
            Arc<HostOperationGuard>,
            crucible_host_resources::host_supervision::HostSupervisionError,
        >,
    >,
}

impl TargetCleanup {
    fn new(preparation: Arc<HostOperationGuard>) -> Self {
        Self {
            preparation,
            completed: false,
            entered: std::sync::OnceLock::new(),
        }
    }

    // Native close receipts are checked by close_target_slot before this
    // operation is reached. Completed only selects an observation of this SAME
    // saved guard; it never substitutes for physical closure or a fresh guard.
    fn complete_for_return(
        &mut self,
    ) -> Result<(), crucible_host_resources::host_supervision::HostSupervisionError> {
        use crucible_host_resources::host_supervision::{
            HostOperationClass, HostOperationState, HostSupervisionError,
        };
        let cleanup = self
            .entered
            .get_mut()
            .ok_or(HostSupervisionError::Unavailable)?
            .as_mut()
            .map_err(|first| *first)?;
        let guard = Arc::get_mut(cleanup).ok_or(HostSupervisionError::BorrowedOperation)?;
        let observed = if self.completed {
            guard.status()
        } else {
            let (completed, result) = guard.complete_observed();
            self.completed |= completed;
            result
        }?;
        if !self.completed
            || observed.class != HostOperationClass::Cleanup
            || observed.state != HostOperationState::Completed
        {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn guard(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        // The initializer has no user callback or roster borrow. All actual
        // Target consumers share this one admission and its first refusal.
        // Eligible terminal Preparation remains the origin of Cleanup; it is
        // not renewed or checked as live work authority before this cut.
        let entered = self.entered.get_or_init(|| {
            self.preparation
                .begin_original_cleanup_control()
                .map(Arc::new)
        });
        let guard = entered
            .as_ref()
            .map_err(|source| OriginalActorAccountError::from(*source))?;
        guard.wait_slice()?;
        Ok(Arc::clone(guard))
    }
}

impl ForkTargetSlot {
    pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        self.cleanup
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .guard()
    }

    pub(super) fn matches_live_contract(&self, contract: &crate::QemuChildProcessContract) -> bool {
        self.is_owned()
            && self.born
            && !self.physical_closed
            && self.unsettled.is_none()
            && self
                .envelope
                .as_ref()
                .is_some_and(|envelope| envelope.matches_contract(contract))
    }

    pub(super) fn active_envelope(&self) -> Option<&ConfiguredProcessEnvelope> {
        (self.is_owned() && self.born && !self.physical_closed && self.unsettled.is_none())
            .then_some(self.envelope.as_ref())
            .flatten()
    }

    pub(super) fn retain_process_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), OriginalActorAccountError> {
        if !self.born
            || !self.is_owned()
            || self.process_generation.is_some()
            || self.reserved_process_generation != Some(generation)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.process_generation = Some(generation);
        Ok(())
    }

    pub(super) fn retained_preparation(&self) -> Option<&Arc<HostOperationGuard>> {
        self.is_owned()
            .then_some(self.preparation.as_ref())
            .flatten()
    }

    pub(super) fn watcher_cleanup(&self) -> Result<&Arc<TargetCleanup>, OriginalActorAccountError> {
        self.watcher_preparation()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        self.cleanup
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(super) fn watcher_preparation(&self) -> Option<(u64, &Arc<HostOperationGuard>)> {
        if !self.born || self.physical_closed || self.unsettled.is_some() {
            return None;
        }
        Some((self.occupied?, self.preparation.as_ref()?))
    }

    pub(super) fn is_owned(&self) -> bool {
        self.occupied.is_some()
    }
}

/// Owns the one fixed target slot; copied limits cannot construct this loan.
#[derive(Debug)]
pub(in crate::linux_attempt_host) struct ForkTargetReservation {
    pub(in crate::linux_attempt_host) attempt: NativeAccountAttempt,
    epoch: u64,
    pub(in crate::linux_attempt_host) ceilings: (u32, u64, u64),
    pub(in crate::linux_attempt_host) descriptors: u64,
    pub(in crate::linux_attempt_host) credentials: (u32, u32),
    consumed: bool,
}

pub(super) fn retained_control_extent() -> Result<u64, OriginalActorAccountError> {
    crate::QemuProcessStageBinding::retained_control_bytes()
        .and_then(|bytes| bytes.checked_add(OriginalNativeControlRetirement::allocation_extent()?))
        .and_then(|bytes| bytes.checked_add(cleanup_control_extent().ok()?.checked_mul(2)?))
        .and_then(|bytes| {
            let (layout, _) = std::alloc::Layout::new::<(usize, usize)>()
                .extend(std::alloc::Layout::new::<TargetCleanup>())
                .ok()?;
            bytes.checked_add(u64::try_from(layout.pad_to_align().size()).ok()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(u64::try_from(std::mem::size_of::<TargetWatcherOriginal>()).ok()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                u64::try_from(std::mem::size_of::<
                    crate::linux_attempt_host::LinuxQemuAttemptHostOwner,
                >())
                .ok()?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                u64::try_from(std::mem::size_of::<
                    crate::linux_attempt_process::OriginalProcessSetupCustody,
                >())
                .ok()?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                u64::try_from(std::mem::size_of::<
                    crate::linux_attempt_host::LinuxQemuForkTargetPermit,
                >())
                .ok()?,
            )
        })
        .ok_or(OriginalActorAccountError::Unavailable)
}

impl NativeAccountAttempt {
    fn retry_target_construction(
        &self,
        epoch: u64,
        process_generation: u64,
    ) -> (bool, Result<(), QemuForkTargetConstructionError>) {
        let unavailable =
            || QemuForkTargetConstructionError::Original(OriginalActorAccountError::Unavailable);
        let Some(roster) = self.roster.upgrade() else {
            return (false, Err(unavailable()));
        };
        let Ok(mut state) = roster.lock() else {
            return (false, Err(unavailable()));
        };
        let Some(slot) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation))
        else {
            return (false, Err(unavailable()));
        };
        if epoch == 0 || epoch > slot.fork_target.next_epoch {
            return (false, Err(unavailable()));
        }
        if slot.fork_target.returned_epoch >= epoch {
            return (true, Ok(()));
        }
        if slot.fork_target.occupied != Some(epoch)
            || slot.fork_target.reserved_process_generation != Some(process_generation)
        {
            return (false, Err(unavailable()));
        }
        let result = if slot.fork_target.unsettled.is_some() {
            retry_unsettled_target_raw(slot)
        } else if slot.fork_target.physical_closed {
            finish_target_control_return(slot)
        } else if !slot.fork_target.born {
            // begin_birth precedes the first dispatcher/cgroup effect. Every
            // canonical physical field must also be absent before this exact
            // logical role can close under its existing Cleanup.
            let target = &slot.fork_target;
            if target.envelope.is_some()
                || target.process_binding.is_some()
                || target.control.is_some()
                || target.process_generation.is_some()
                || target.ram_registration_generation.is_some()
            {
                Err(unavailable())
            } else {
                match target.cleanup() {
                    Err(first) => Err(first.into()),
                    Ok(cleanup) => {
                        let before = cleanup.wait_slice().map(|_| ()).map_err(|first| {
                            QemuForkTargetConstructionError::Original(first.into())
                        });
                        drop(cleanup);
                        match before {
                            Err(first) => Err(first),
                            Ok(()) => {
                                slot.fork_target.physical_closed = true;
                                close_target_slot(slot)
                                    .map_err(QemuForkTargetConstructionError::Original)
                            }
                        }
                    }
                }
            }
        } else {
            // A successfully returned host guard remains the physical owner;
            // the cleanup loan must never steal it or attest its destruction.
            Err(unavailable())
        };
        (slot.fork_target.returned_epoch >= epoch, result)
    }

    pub(in crate::linux_attempt_host) fn fork_target_is_owned(&self) -> bool {
        let Some(roster) = self.roster.upgrade() else {
            return true;
        };
        let Ok(state) = roster.lock() else {
            return true;
        };
        state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .is_none_or(|slot| slot.fork_target.is_owned())
    }

    pub(in crate::linux_attempt_host) fn reserve_fork_target(
        &self,
        source: &crate::QemuChildProcessContract,
    ) -> Result<
        (
            ForkTargetReservation,
            QemuForkTargetConstructionLoan,
            Option<crucible_host_resources::host_services::process_birth::NativePoolRefusal>,
        ),
        OriginalActorAccountError,
    > {
        self.require_live_launch_control()?;
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
            .filter(|slot| slot.active == Some(self.generation) && !slot.fork_target.is_owned())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let (vcpus, resident, writable, descriptors, credentials) = slot
            .installed_process
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .fork_target_geometry(source)
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        descriptors
            .checked_mul(u64::from(MAX_ORIGINAL_NATIVE_NODE_GENERATIONS))
            .filter(|sum| {
                slot.credit
                    .as_ref()
                    .is_some_and(|credit| *sum <= credit.descriptor_ceiling())
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let epoch = slot
            .fork_target
            .next_epoch
            .checked_add(1)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let process_generation = slot
            .installed_process
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .next_target_generation(slot.fork_target.last_reserved_process_generation)?;
        // A failed admission burns this generation too; closing a role never
        // rewinds the journal or permits replay of a prior request.
        slot.fork_target.last_reserved_process_generation = process_generation;
        let normal = slot
            .credit
            .as_ref()
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // Claim prepays this exact guard allocation before a Target operation
        // enters the unchanged Main supervisor. Retries keep the same guard.
        let preparation = Arc::new(normal.begin_native_preparation()?);
        slot.fork_target.cleanup = Some(Arc::new(TargetCleanup::new(Arc::clone(&preparation))));
        slot.fork_target.preparation = Some(Arc::clone(&preparation));
        slot.fork_target.next_epoch = epoch;
        slot.fork_target.occupied = Some(epoch);
        slot.fork_target.reserved_process_generation = Some(process_generation);
        // Mint the nonissuing cleanup borrow under this same locked actual
        // issuer, before any fallible landing admission or postcut. There is
        // no second roster lock/lookup that can lose a born role on refusal.
        let cleanup = QemuForkTargetConstructionLoan {
            attempt: NativeAccountAttempt {
                roster: Weak::clone(&self.roster),
                index: self.index,
                generation: self.generation,
            },
            epoch,
            process_generation,
            returned: false,
            failed_permit: None,
        };
        let landing_refusal = normal.reserve_node_target_window(&preparation).err();
        Ok((
            ForkTargetReservation {
                attempt: NativeAccountAttempt {
                    roster: Weak::clone(&self.roster),
                    index: self.index,
                    generation: self.generation,
                },
                epoch,
                ceilings: (vcpus, resident, writable),
                descriptors,
                credentials,
                consumed: false,
            },
            cleanup,
            landing_refusal,
        ))
    }

    pub(in crate::linux_attempt_host) fn verify_fork_target_contract(
        &self,
        contract: &crate::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        self.require_original()?;
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .map(|slot| &slot.fork_target)
            .filter(|target| {
                target.is_owned()
                    && target.born
                    && !target.physical_closed
                    && target.unsettled.is_none()
                    && target
                        .envelope
                        .as_ref()
                        .is_some_and(|envelope| envelope.matches_contract(contract))
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(())
    }
}

impl ForkTargetReservation {
    pub(in crate::linux_attempt_host) fn borrow_attempt(&self) -> NativeAccountAttempt {
        NativeAccountAttempt {
            roster: Weak::clone(&self.attempt.roster),
            index: self.attempt.index,
            generation: self.attempt.generation,
        }
    }

    fn with_slot<T>(
        &self,
        operation: impl FnOnce(&mut NativeSlot) -> Result<T, OriginalActorAccountError>,
    ) -> Result<T, OriginalActorAccountError> {
        let roster = self
            .attempt
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get_mut(self.attempt.index)
            .filter(|slot| {
                slot.active == Some(self.attempt.generation)
                    && slot.fork_target.occupied == Some(self.epoch)
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        operation(slot)
    }

    pub(in crate::linux_attempt_host) fn belongs_to_factory(
        &self,
        binding: &OriginalNativeAccountFactoryBinding,
    ) -> bool {
        Weak::ptr_eq(&binding.roster, &self.attempt.roster)
    }

    pub(in crate::linux_attempt_host) fn check_logical_reservation(
        &self,
    ) -> Result<u64, OriginalActorAccountError> {
        self.with_slot(|slot| {
            let target = &slot.fork_target;
            if target.born || target.physical_closed || target.unsettled.is_some() {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let generation = target
                .reserved_process_generation
                .ok_or(OriginalActorAccountError::Unavailable)?;
            let original = target
                .preparation
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            let credit = slot
                .credit
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            credit.require_original()?;
            credit
                .original
                .as_ref()
                .and_then(|held| held.normal.as_ref())
                .ok_or(OriginalActorAccountError::Unavailable)?
                .verify_native_preparation(original)?;
            original.wait_slice()?;
            Ok(generation)
        })
    }

    pub(in crate::linux_attempt_host) fn bind_ram_registration(
        &self,
        contract: &crate::QemuChildProcessContract,
    ) -> Result<u64, OriginalActorAccountError> {
        self.with_slot(|slot| {
            let generation = slot
                .fork_target
                .reserved_process_generation
                .ok_or(OriginalActorAccountError::Unavailable)?;
            let target = &slot.fork_target;
            if !target.matches_live_contract(contract)
                || target
                    .ram_registration_generation
                    .is_some_and(|saved| saved != generation)
                || target
                    .process_generation
                    .is_some_and(|saved| saved != generation)
            {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let original = target
                .preparation
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            process_purpose::verify_subdivision_preparation(slot, original, 1)?;
            original.wait_slice()?;
            slot.fork_target.ram_registration_generation = Some(generation);
            Ok(generation)
        })
    }

    pub(in crate::linux_attempt_host) fn check_ram_registration(
        &self,
        contract: &crate::QemuChildProcessContract,
        generation: u64,
        cleanup: bool,
    ) -> Result<(), OriginalActorAccountError> {
        self.with_slot(|slot| {
            let target = &slot.fork_target;
            if target.ram_registration_generation != Some(generation) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            if cleanup {
                let entered = target
                    .cleanup
                    .as_ref()
                    .and_then(|saved| saved.entered.get())
                    .and_then(|entered| entered.as_ref().ok())
                    .ok_or(OriginalActorAccountError::Unavailable)?;
                entered.wait_slice()?;
                return Ok(());
            }
            if !target.matches_live_contract(contract) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let original = target
                .preparation
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            process_purpose::verify_subdivision_preparation(slot, original, 1)?;
            original.wait_slice()?;
            Ok(())
        })
    }

    pub(in crate::linux_attempt_host) fn verify_factory(
        &self,
        binding: &OriginalNativeAccountFactoryBinding,
    ) -> Result<(), OriginalActorAccountError> {
        if !Weak::ptr_eq(&binding.roster, &self.attempt.roster) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.attempt.require_original()?;
        self.with_slot(|slot| {
            if slot.fork_target.born || slot.fork_target.unsettled.is_some() {
                return Err(OriginalActorAccountError::Unavailable);
            }
            Ok(())
        })
    }

    pub(in crate::linux_attempt_host) fn begin_birth(
        &mut self,
    ) -> Result<(), OriginalActorAccountError> {
        self.attempt.require_original()?;
        self.with_slot(|slot| {
            if slot.fork_target.born {
                return Err(OriginalActorAccountError::Unavailable);
            }
            slot.fork_target.born = true;
            Ok(())
        })?;
        self.consumed = true;
        Ok(())
    }

    pub(in crate::linux_attempt_host) fn bind_contract(
        &self,
        contract: &crate::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        let envelope = contract
            .configured_process_envelope()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        self.with_slot(|slot| {
            slot.installed_process
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?
                .verify_fork_target_envelope(&envelope)
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            let target = &mut slot.fork_target;
            if !target.born || target.envelope.is_some() || target.unsettled.is_some() {
                return Err(OriginalActorAccountError::Unavailable);
            }
            target.process_binding = Some(contract.retain_process_stage_retirement());
            target.envelope = Some(envelope);
            Ok(())
        })?;
        self.attempt.require_original()
    }

    pub(in crate::linux_attempt_host) fn retain_control(
        &self,
        pin: OriginalNativeControlRetirement,
    ) -> Result<(), OriginalActorAccountError> {
        let mut pin = Some(pin);
        let result = self.with_slot(|slot| {
            let target = &mut slot.fork_target;
            if target.control.is_some() || target.physical_closed {
                return Err(OriginalActorAccountError::Unavailable);
            }
            target.control = pin.take();
            Ok(())
        });
        if let Some(pin) = pin {
            std::mem::forget(pin);
        }
        result
    }

    pub(in crate::linux_attempt_host) fn cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        self.with_slot(|slot| slot.fork_target.cleanup())
    }

    pub(in crate::linux_attempt_host) fn mark_physical_closed(
        &self,
    ) -> Result<(), OriginalActorAccountError> {
        self.with_slot(|slot| {
            let target = &mut slot.fork_target;
            if target.unsettled.is_some() {
                return Err(OriginalActorAccountError::Unavailable);
            }
            target.physical_closed = true;
            target.envelope = None;
            Ok(())
        })
    }

    pub(in crate::linux_attempt_host) fn matches_controller(
        &self,
        controller: &super::super::LinuxQemuNativeResourceController,
    ) -> Result<bool, OriginalActorAccountError> {
        self.with_slot(|slot| {
            Ok(slot
                .fork_target
                .control
                .as_ref()
                .is_some_and(|pin| pin.matches_controller(controller)))
        })
    }

    pub(in crate::linux_attempt_host) fn close_registry_control(
        &self,
        controller: &mut super::super::LinuxQemuNativeResourceController,
    ) -> Result<(), OriginalActorAccountError> {
        self.with_slot(|slot| {
            let target = &mut slot.fork_target;
            if !target.physical_closed {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let cleanup = target.cleanup()?;
            let pin = target
                .control
                .as_mut()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            pin.release_registry_alias(controller).map_err(|source| {
                OriginalActorAccountError::NativeControlBoundary {
                    source,
                    original: None,
                }
            })?;
            let closed = pin.close();
            let after = cleanup.wait_slice();
            if let Err(source) = closed {
                pin.restore_registry_alias(controller);
                return Err(OriginalActorAccountError::NativeControlBoundary {
                    source,
                    original: after.err(),
                });
            }
            target.control = None;
            after?;
            Ok(())
        })
    }

    pub(in crate::linux_attempt_host) fn close(&mut self) -> Result<(), OriginalActorAccountError> {
        self.with_slot(close_target_slot)?;
        self.consumed = false;
        Ok(())
    }

    pub(in crate::linux_attempt_host) fn retain_unsettled(&self, owners: RetainedNativeHost) {
        let mut owners = Some(owners);
        let _retained = self.with_slot(|slot| {
            if slot.fork_target.unsettled.is_some() {
                return Err(OriginalActorAccountError::Unavailable);
            }
            slot.fork_target.unsettled = owners.take();
            Ok(())
        });
        if let Some(owners) = owners {
            std::mem::forget(owners);
        }
    }
}

impl Drop for ForkTargetReservation {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        let _closed = self.with_slot(|slot| {
            if slot.fork_target.born {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let preparation = slot
                .fork_target
                .preparation
                .as_mut()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            preparation.wait_slice()?;
            let cleanup = slot
                .fork_target
                .cleanup
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            if Arc::strong_count(cleanup) != 1
                || cleanup.entered.get().is_some()
                || Arc::strong_count(preparation) != 2
                || Arc::weak_count(preparation) != 0
            {
                return Err(OriginalActorAccountError::Unavailable);
            }
            drop(slot.fork_target.cleanup.take());
            Arc::get_mut(preparation).ok_or(OriginalActorAccountError::Unavailable)?;
            slot.fork_target.preparation = None;
            slot.fork_target.returned_epoch = self.epoch;
            slot.fork_target.occupied = None;
            Ok(())
        });
    }
}

fn close_target_slot(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    let target = &mut slot.fork_target;
    let epoch = target
        .occupied
        .ok_or(OriginalActorAccountError::Unavailable)?;
    if !target.physical_closed
        || target.unsettled.is_some()
        || target.control.is_some()
        || target.process_generation.is_some_and(|generation| {
            slot.digest_purposes
                .iter()
                .any(|purpose| purpose.belongs_to_process(generation))
        })
        || slot
            .installed_process
            .as_ref()
            .is_some_and(|purpose| purpose.fork_target_incarnation_is_retained())
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    if let Some(binding) = target.process_binding.as_mut() {
        binding
            .close()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
    }
    target.process_binding = None;
    let cell = target
        .cleanup
        .as_mut()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let unique = Arc::get_mut(cell).ok_or(OriginalActorAccountError::Unavailable)?;
    let preparation = target
        .preparation
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    if !Arc::ptr_eq(preparation, &unique.preparation)
        || Arc::strong_count(preparation) != 2
        || Arc::weak_count(preparation) != 0
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    if let Err(post) = unique.complete_for_return() {
        let first = *target.cleanup_completion_failure.get_or_insert(post);
        return Err(OriginalActorAccountError::TargetCleanupBoundary {
            source: first,
            post: (post != first).then_some(post),
        });
    }
    drop(target.cleanup.take());
    let preparation = target
        .preparation
        .as_mut()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    Arc::get_mut(preparation).ok_or(OriginalActorAccountError::Unavailable)?;
    target.preparation = None;
    target.process_generation = None;
    target.reserved_process_generation = None;
    target.ram_registration_generation = None;
    target.born = false;
    target.physical_closed = false;
    target.returned_epoch = epoch;
    target.occupied = None;
    // Journal physical role return before delivering the actual historical
    // completion cause. No later retry may repeat these irreversible closes.
    match target.cleanup_completion_failure.take() {
        Some(source) => {
            Err(OriginalActorAccountError::TargetCleanupBoundary { source, post: None })
        }
        None => Ok(()),
    }
}

pub(super) fn retry_unsettled_target(slot: &mut NativeSlot) -> Result<(), QemuVmRealizationError> {
    retry_unsettled_target_raw(slot).map_err(QemuForkTargetConstructionError::into_realization)
}

fn retry_unsettled_target_raw(
    slot: &mut NativeSlot,
) -> Result<(), QemuForkTargetConstructionError> {
    let target = &mut slot.fork_target;
    if target.unsettled.is_none() {
        return Ok(());
    }
    let cleanup = target
        .cleanup()
        .map_err(QemuForkTargetConstructionError::Original)?;
    let work = target
        .unsettled
        .as_mut()
        .ok_or(QemuForkTargetConstructionError::Original(
            OriginalActorAccountError::Unavailable,
        ))?
        .finish(&cleanup);
    if let Err(first) = work {
        // Retain the actual post error, while recording bodies that this SAME
        // retained owner already destroyed. The next attempt reconciles only
        // remaining controls/role; it cannot repeat process or storage cleanup.
        if target
            .unsettled
            .as_ref()
            .is_some_and(RetainedNativeHost::bodies_returned)
        {
            target.unsettled = None;
            target.envelope = None;
            target.physical_closed = true;
        }
        return Err(QemuForkTargetConstructionError::Physical(first));
    }
    target.unsettled = None;
    target.envelope = None;
    target.physical_closed = true;
    drop(cleanup);
    finish_target_control_return(slot)
}

fn finish_target_control_return(
    slot: &mut NativeSlot,
) -> Result<(), QemuForkTargetConstructionError> {
    let target = &mut slot.fork_target;
    // Surviving native registry aliases deliberately keep this slot occupied.
    if let Some(pin) = target.control.as_mut() {
        let cleanup = target
            .cleanup
            .as_ref()
            .ok_or(QemuForkTargetConstructionError::Original(
                OriginalActorAccountError::Unavailable,
            ))?
            .guard()
            .map_err(QemuForkTargetConstructionError::Original)?;
        let work = pin.close();
        let post = cleanup.wait_slice();
        match work {
            Ok(()) => {
                // Native alias closure is irreversible even when the SAME
                // saved operation independently refuses the following post.
                target.control = None;
                post.map_err(|first| QemuForkTargetConstructionError::Original(first.into()))?;
            }
            Err(source) => {
                return Err(QemuForkTargetConstructionError::Original(
                    OriginalActorAccountError::NativeControlBoundary {
                        source,
                        original: post.err(),
                    },
                ));
            }
        }
    }
    target.control = None;
    close_target_slot(slot).map_err(QemuForkTargetConstructionError::Original)
}

#[cfg(test)]
mod construction_tests;
