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
    occupied: Option<u64>,
    born: bool,
    physical_closed: bool,
    envelope: Option<ConfiguredProcessEnvelope>,
    process_generation: Option<u64>,
    process_binding: Option<QemuProcessStageRetirement>,
    control: Option<OriginalNativeControlRetirement>,
    preparation: Option<Arc<HostOperationGuard>>,
    cleanup: Option<Arc<HostOperationGuard>>,
    unsettled: Option<RetainedNativeHost>,
}

impl ForkTargetSlot {
    pub(super) fn active_envelope(&self) -> Option<&ConfiguredProcessEnvelope> {
        (self.is_owned() && self.born && !self.physical_closed && self.unsettled.is_none())
            .then_some(self.envelope.as_ref())
            .flatten()
    }

    pub(super) fn retain_process_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), OriginalActorAccountError> {
        if !self.born || !self.is_owned() || self.process_generation.is_some() || generation == 0 {
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
        let normal = slot
            .credit
            .as_ref()
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        // Claim prepays this exact guard allocation before a Target operation
        // enters the unchanged Main supervisor. Retries keep the same guard.
        let preparation = Arc::new(normal.begin_native_preparation()?);
        slot.fork_target.preparation = Some(preparation);
        slot.fork_target.next_epoch = epoch;
        slot.fork_target.occupied = Some(epoch);
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
        self.with_slot(|slot| {
            let target = &mut slot.fork_target;
            if target.cleanup.is_none() {
                let preparation = target
                    .preparation
                    .as_ref()
                    .ok_or(OriginalActorAccountError::Unavailable)?;
                // Enter once from the actual Target operation. Source's
                // completed admission and terminal Cleanup stay untouched.
                target.cleanup = Some(Arc::new(preparation.begin_original_cleanup_control()?));
            }
            let cleanup = target
                .cleanup
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            cleanup.wait_slice()?;
            Ok(Arc::clone(cleanup))
        })
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
            let cleanup = target
                .cleanup
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            cleanup.wait_slice()?;
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
    let cleanup = target
        .cleanup
        .as_mut()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    let unique = Arc::get_mut(cleanup).ok_or(OriginalActorAccountError::Unavailable)?;
    let preparation = target
        .preparation
        .as_mut()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    Arc::get_mut(preparation).ok_or(OriginalActorAccountError::Unavailable)?;
    unique.complete()?;
    target.cleanup = None;
    target.preparation = None;
    target.process_generation = None;
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
    if target.cleanup.is_none() {
        target.cleanup = Some(Arc::new(
            target
                .preparation
                .as_ref()
                .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
                .begin_original_cleanup_control()
                .map_err(|source| original_error(source.into()))?,
        ));
    }
    let cleanup = target
        .cleanup
        .as_ref()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?;
    target
        .unsettled
        .as_mut()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
        .finish(cleanup)?;
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
    close_target_slot(slot).map_err(original_error)
}
