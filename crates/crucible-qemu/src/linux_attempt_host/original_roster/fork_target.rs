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
    unsettled: Option<RetainedNativeHost>,
}

/// Shares this exact Target's once-entered Cleanup independently of roster locks.
pub(super) struct TargetCleanup {
    preparation: Arc<HostOperationGuard>,
    entered: std::sync::OnceLock<
        Result<
            Arc<HostOperationGuard>,
            crucible_linux_resource::host_supervision::HostSupervisionError,
        >,
    >,
}

impl TargetCleanup {
    fn new(preparation: Arc<HostOperationGuard>) -> Self {
        Self {
            preparation,
            entered: std::sync::OnceLock::new(),
        }
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
    ) -> Result<ForkTargetReservation, OriginalActorAccountError> {
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
        slot.fork_target.preparation = Some(preparation);
        slot.fork_target.next_epoch = epoch;
        slot.fork_target.occupied = Some(epoch);
        slot.fork_target.reserved_process_generation = Some(process_generation);
        // Publish the saved operation and occupied Target before its Main-table
        // landing admission. A refused postcut retains the same node debt.
        let normal = slot
            .credit
            .as_ref()
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        normal.reserve_node_target_window(
            slot.fork_target
                .preparation
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?,
        )?;
        Ok(ForkTargetReservation {
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
        })
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
            slot.fork_target.occupied = None;
            Ok(())
        });
    }
}

fn close_target_slot(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    let target = &mut slot.fork_target;
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
    let cleanup = unique
        .entered
        .get_mut()
        .ok_or(OriginalActorAccountError::Unavailable)?
        .as_mut()
        .map_err(|source| OriginalActorAccountError::from(*source))?;
    Arc::get_mut(cleanup)
        .ok_or(OriginalActorAccountError::Unavailable)?
        .complete()?;
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
    target.occupied = None;
    Ok(())
}

pub(super) fn retry_unsettled_target(slot: &mut NativeSlot) -> Result<(), QemuVmRealizationError> {
    let target = &mut slot.fork_target;
    if target.unsettled.is_none() {
        return Ok(());
    }
    let cleanup = target.cleanup().map_err(original_error)?;
    target
        .unsettled
        .as_mut()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
        .finish(&cleanup)?;
    target.unsettled = None;
    target.envelope = None;
    target.physical_closed = true;
    // Surviving native registry aliases deliberately keep this slot occupied.
    if let Some(pin) = target.control.as_mut() {
        pin.close().map_err(|source| {
            original_error(OriginalActorAccountError::NativeControlBoundary {
                source,
                original: cleanup.wait_slice().err(),
            })
        })?;
    }
    target.control = None;
    drop(cleanup);
    close_target_slot(slot).map_err(original_error)
}
