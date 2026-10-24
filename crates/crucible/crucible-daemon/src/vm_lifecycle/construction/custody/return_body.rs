//! Moves completed bodies through their original carrier and return witness.
//!
//! These pure ownership cuts validate before taking actual owners. They neither
//! run native cleanup nor allocate replacement bodies or reservation tokens.

use super::*;

impl ProductionVmConstructionCustody {
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn has_empty_return_slot(&mut self) -> bool {
        self.retirement_slot().is_some()
    }

    /// Installs the body held by the exclusive validated live return state.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn install_owned_return(
        self: Box<Self>,
        lifecycle: ProductionVmLifecycleLoop,
    ) -> Box<Self> {
        self.install_returned_body(lifecycle, None)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn install_returned_body(
        mut self: Box<Self>,
        lifecycle: ProductionVmLifecycleLoop,
        destination: Option<crate::lifecycle_cleanup::SourceBodyReturn>,
    ) -> Box<Self> {
        // The exclusive Main pair or validated public conversion owns this
        // pristine carrier; no caller can access its phase during this move.
        self.return_destination = destination;
        let phase = match self.phase.get_mut() {
            Ok(phase) => phase,
            Err(poison) => poison.into_inner(),
        };
        *phase = Phase::Complete(lifecycle);
        self
    }

    /// Cancels a still unexported witness before restoring this Box to Main.
    ///
    /// The exact same token is restored; the irreversible work gate is never
    /// reopened. This pure ownership operation runs no saved-cleanup effects.
    ///
    /// # Errors
    /// Preserves both actual values if contradictory occupied header slots exist.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn cancel_prepared_body_return(
        &mut self,
    ) -> Result<(), LifecycleApiError> {
        if self.reservation.is_some() && self.return_destination.is_some() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        if let Some(destination) = self.return_destination.take() {
            self.reservation = Some(destination.cancel_unexported());
        }
        Ok(())
    }

    /// Installs a complete Source held by its own required private Main pair.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn install_owned_source(
        mut self: Box<Self>,
        source: ProductionVmHotForkSourceWorld,
    ) -> Box<Self> {
        let phase = match self.phase.get_mut() {
            Ok(phase) => phase,
            Err(poison) => poison.into_inner(),
        };
        *phase = Phase::Source(source);
        self
    }

    /// Retains the same shared allocation until exclusion permits its destruction.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn install_owned_shared_source(
        mut self: Box<Self>,
        source: std::sync::Arc<std::sync::Mutex<ProductionVmHotForkSourceWorld>>,
        selector: crate::lifecycle_cleanup::PreparedSourceSelector,
        parent_park: crate::vm_lifecycle::hot_fork::shared_source::ParentParkCustody,
    ) -> Box<Self> {
        let phase = match self.phase.get_mut() {
            Ok(phase) => phase,
            Err(poison) => poison.into_inner(),
        };
        *phase = Phase::SharedSource(
            crate::vm_lifecycle::hot_fork::shared_source::SharedSourceBody::new(
                source,
                selector,
                parent_park,
            ),
        );
        self
    }

    /// Retains the whole old rearm failure without claiming physical recovery.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn install_owned_source_rearm_failure(
        mut self: Box<Self>,
        failure: ProductionVmHotForkSourceWorldPreparationFailure,
    ) -> Box<Self> {
        let phase = match self.phase.get_mut() {
            Ok(phase) => phase,
            Err(poison) => poison.into_inner(),
        };
        *phase = Phase::SourceRearmFailure(
            crate::vm_lifecycle::hot_fork::rearm_return::SourceRearmBody::new(failure),
        );
        self
    }

    /// Attaches the original required pair to a detached completed body.
    ///
    /// This pure final helper is shared by ordinary and captured Source export.
    /// Refusal keeps the same carrier and every header field unchanged.
    ///
    /// # Errors
    /// Returns this same carrier unless both it and the detached Loop are ready
    /// for their exact original external-body ownership transfer.
    #[cfg(target_os = "linux")]
    pub(in crate::vm_lifecycle) fn attach_exported_lifecycle(
        mut self: Box<Self>,
        lifecycle: &mut ProductionVmLifecycleLoop,
    ) -> Result<(), Box<Self>> {
        if self.first.is_some()
            || self.physically_closed.load(Ordering::Acquire)
            || self.reservation.is_some()
            || self.return_destination.is_none()
            || !matches!(self.phase.get_mut(), Ok(Phase::Empty))
            || !matches!(
                lifecycle.construction_custody,
                LifecycleConstructionCustody::Unissued(None)
            )
        {
            return Err(self);
        }
        match self.return_destination.take() {
            Some(destination) => {
                lifecycle.construction_custody = LifecycleConstructionCustody::Main {
                    carrier: self,
                    destination,
                };
                Ok(())
            }
            None => Err(self),
        }
    }

    /// Moves the complete lifecycle with its original carrier attached.
    ///
    /// # Errors
    /// Returns this same Box if custody is failed, closed, reserved, poisoned
    /// or does not contain a complete lifecycle.
    pub(crate) fn into_loop(self: Box<Self>) -> Result<ProductionVmLifecycleLoop, Box<Self>> {
        self.into_loop_mode(false)
    }

    /// Reserves the actual external-body destination before the final pure move.
    ///
    /// Refusal restores the same token and complete lifecycle into this carrier.
    /// A successful export owns its original destination inside the actual Loop.
    pub(crate) fn into_loop_with_return(
        self: Box<Self>,
    ) -> Result<ProductionVmLifecycleLoop, Box<Self>> {
        self.into_loop_mode(true)
    }

    /// Exports only operations over a completed body with its original pair.
    ///
    /// # Errors
    /// Returns this same carrier with its actual frame when export or return
    /// reservation refuses. No owning failure wrapper is allocated.
    #[cfg(target_os = "linux")]
    pub(crate) fn into_main_lifecycle_with_return(
        mut self: Box<Self>,
    ) -> Result<crate::vm_lifecycle::MainSourceLifecycle, Box<Self>> {
        if self.first.is_some() || self.physically_closed.load(Ordering::Acquire) {
            return Err(self);
        }
        let mut lifecycle = match self.phase.get_mut() {
            Ok(phase) => match std::mem::replace(phase, Phase::Empty) {
                Phase::Complete(lifecycle) => lifecycle,
                other => {
                    *phase = other;
                    return Err(self);
                }
            },
            Err(_) => return Err(self),
        };
        let prepared = lifecycle
            .prepare_source_body_return(&mut self.reservation, &mut self.return_destination);
        if prepared.is_ok() {
            if let Some(destination) = self.return_destination.take() {
                return Ok(crate::vm_lifecycle::MainSourceLifecycle::from_return_pair(
                    lifecycle,
                    self,
                    destination,
                ));
            }
        }
        let phase = match self.phase.get_mut() {
            Ok(phase) => phase,
            Err(poisoned) => poisoned.into_inner(),
        };
        *phase = Phase::Complete(lifecycle);
        Err(self)
    }

    fn into_loop_mode(
        mut self: Box<Self>,
        external_return: bool,
    ) -> Result<ProductionVmLifecycleLoop, Box<Self>> {
        if self.first.is_some() || self.physically_closed.load(Ordering::Acquire) {
            return Err(self);
        }
        let mut lifecycle = match self.phase.get_mut() {
            Ok(phase) => match std::mem::replace(phase, Phase::Empty) {
                Phase::Complete(lifecycle) => lifecycle,
                other => {
                    *phase = other;
                    return Err(self);
                }
            },
            Err(_) => return Err(self),
        };
        #[cfg(target_os = "linux")]
        if external_return {
            if lifecycle
                .prepare_source_body_return(&mut self.reservation, &mut self.return_destination)
                .is_err()
            {
                let phase = match self.phase.get_mut() {
                    Ok(phase) => phase,
                    Err(poison) => poison.into_inner(),
                };
                *phase = Phase::Complete(lifecycle);
                return Err(self);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _external_return = external_return;
        // There are no callbacks, effects or fallible operations after the
        // original return destination is reserved and before this pure export.
        #[cfg(target_os = "linux")]
        if self.return_destination.is_some() {
            return match self.attach_exported_lifecycle(&mut lifecycle) {
                Ok(()) => Ok(lifecycle),
                Err(mut carrier) => {
                    // A pure validation refusal never exports the body. Restore
                    // the original weak token before retaining it back in Main.
                    if let Err(first) = carrier.cancel_prepared_body_return() {
                        carrier.first.get_or_insert(first);
                    }
                    let phase = match carrier.phase.get_mut() {
                        Ok(phase) => phase,
                        Err(poison) => poison.into_inner(),
                    };
                    *phase = Phase::Complete(lifecycle);
                    Err(carrier)
                }
            };
        }
        lifecycle.construction_custody = LifecycleConstructionCustody::Unissued(Some(self));
        Ok(lifecycle)
    }
}

impl ProductionVmLifecycleLoop {
    /// Moves the whole lifecycle back into its original empty construction Box.
    ///
    /// This is custody publication preparation, never execution authority or
    /// evidence that a semantic shutdown result proved physical retirement.
    ///
    /// # Errors
    /// Returns the same complete lifecycle if its original carrier is missing,
    /// occupied, or poisoned. No replacement carrier is allocated.
    pub fn into_construction_custody(
        mut self,
    ) -> Result<Box<ProductionVmConstructionCustody>, Self> {
        #[cfg(target_os = "linux")]
        {
            let (carrier, destination) = match self.take_retirement_custody() {
                Ok(parts) => parts,
                Err(_) => return Err(self),
            };
            return Ok(carrier.install_returned_body(self, destination));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let LifecycleConstructionCustody::Unissued(Some(mut carrier)) = std::mem::replace(
                &mut self.construction_custody,
                LifecycleConstructionCustody::Unissued(None),
            ) else {
                return Err(self);
            };
            let Some(phase) = carrier.retirement_slot() else {
                self.construction_custody = LifecycleConstructionCustody::Unissued(Some(carrier));
                return Err(self);
            };
            *phase = Phase::Complete(self);
            Ok(carrier)
        }
    }

    /// Moves the existing Loop Box only after its original carrier is validated.
    ///
    /// # Errors
    /// Returns this same Box and all owners on unusable original custody.
    pub fn into_construction_custody_from_box(
        mut self: Box<Self>,
    ) -> Result<Box<ProductionVmConstructionCustody>, Box<Self>> {
        #[cfg(target_os = "linux")]
        {
            let (carrier, destination) = match self.take_retirement_custody() {
                Ok(parts) => parts,
                Err(_) => return Err(self),
            };
            return Ok(carrier.install_returned_body(*self, destination));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let LifecycleConstructionCustody::Unissued(Some(mut carrier)) = std::mem::replace(
                &mut self.construction_custody,
                LifecycleConstructionCustody::Unissued(None),
            ) else {
                return Err(self);
            };
            let Some(phase) = carrier.retirement_slot() else {
                self.construction_custody = LifecycleConstructionCustody::Unissued(Some(carrier));
                return Err(self);
            };
            *phase = Phase::Complete(*self);
            Ok(carrier)
        }
    }
}
