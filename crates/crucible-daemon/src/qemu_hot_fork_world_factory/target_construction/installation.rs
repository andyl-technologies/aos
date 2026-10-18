//! Builds and exports the API frame while Main retains the Target constructor.
//!
//! The aggregate, exact cleanup loans and source checkout remain in Pending.
//! Only a completed Loop leaves through its original carrier and destination.
//! Refusal keeps every partial input in the same Pending or carrier allocation.

use super::*;

impl<F> PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Retains the existing auxiliary broker before launching this Target.
    pub(crate) fn bind_auxiliary(
        &mut self,
        broker: Option<QemuHotForkWorldAuxiliaryResourceBroker<F::Guard>>,
    ) -> bool {
        if self.resources.is_some() || self.guard.is_some() || self.auxiliary.is_some() {
            return false;
        }
        self.auxiliary = broker;
        true
    }

    /// Installs actual adoptions and the launcher before any API construction IO.
    pub(crate) fn prepare_api_frame(
        &mut self,
        scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        run_state_root: PathBuf,
        terminal_checkpoints: Option<Arc<ExactCheckpointStore>>,
        cancellation: crate::ExecutionCancellation,
    ) -> bool {
        if self.first_failure().is_some()
            || self.api_prepared
            || self.exported
            || self.launch_input.is_some()
            || self.continuation.is_some()
            || self.adopting_child.is_some()
            || self.adopting_identity.is_some()
            || !self.complete.as_ref().is_some_and(|world| world.is_empty())
            || self.reservation.is_none()
            || self.construction.is_none()
        {
            return false;
        }
        let terminal_source = if terminal_checkpoints.is_some() {
            match source.try_clone_admitted() {
                Ok(source) => Some(source),
                Err(first) => {
                    self.first_setup.get_or_insert(first.into());
                    return false;
                }
            }
        } else {
            None
        };
        let (Some(resources), Some(members)) = (self.resources.as_mut(), self.members.as_mut())
        else {
            return false;
        };
        let lifecycle_guard = match resources.lifecycle_guard() {
            Ok(guard) => guard,
            Err(first) => {
                self.first_setup.get_or_insert(first.into());
                return false;
            }
        };
        let generation_owner = crate::QemuAttemptGenerationResourceOwner::new(
            lifecycle_guard,
            members.generation_storage(),
        );
        // All ownership fields were validated before issuing the guard. This
        // allocation has an actual before-birth World control measurement.
        let mut launcher = crate::QemuAttemptProductionVmNodeLauncher::new(generation_owner)
            .with_target_return::<Self>();
        if let Some(reservation) = self.reservation.take() {
            launcher = launcher.with_cleanup_reservation(reservation);
        }
        if let (Some(checkpoints), Some(source)) = (terminal_checkpoints, terminal_source) {
            launcher = launcher.with_terminal_checkpoint_import(checkpoints, source, cancellation);
        }
        self.launch_input = Some(Box::new(launcher));
        let Some(world) = self.complete.take() else {
            return false;
        };
        match world.into_adopted_continuation() {
            Ok(continuation) => self.continuation = Some(continuation),
            Err(world) => {
                self.complete = Some(world);
                return false;
            }
        }
        let Some(custody) = self.construction.as_mut() else {
            return false;
        };
        if let Err(first) = custody.install_hot_fork_inputs(
            &mut self.launch_input,
            &mut self.continuation,
            &mut self.adoptions,
        ) {
            self.first_setup.get_or_insert(first.into());
            return false;
        }
        if let Err(first) = crate::vm_lifecycle::prepare_retained_hot_fork_construction(
            scenario,
            source,
            custody,
            run_state_root,
        ) {
            self.first_setup.get_or_insert(first.into());
            return false;
        }
        self.api_prepared = true;
        true
    }

    /// Moves only the complete Loop into its original external return pair.
    ///
    /// Every native authority stays in this same Main-owned constructor. A
    /// refused commit or return reservation restores the original carrier.
    pub(crate) fn export_lifecycle(&mut self) -> Option<crate::vm_lifecycle::MainSourceLifecycle> {
        if !self.api_prepared || self.exported || self.first_failure().is_some() {
            return None;
        }
        let service = self.selector.typed::<Self>().service_main_handle();
        match service.commit_work(|| {
            let custody = self.construction.take()?;
            match custody.into_main_lifecycle_with_return() {
                Ok(lifecycle) => {
                    self.exported = true;
                    Some(lifecycle)
                }
                Err(custody) => {
                    self.construction = Some(custody);
                    self.first_setup
                        .get_or_insert(LifecycleApiError::ConstructionCustodyUnavailable.into());
                    None
                }
            }
        }) {
            Ok(result) => result,
            Err(first) => {
                self.first_main
                    .get_or_insert(TargetMainAdmissionError::Main(first));
                None
            }
        }
    }
}

impl<F> PendingTargetConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Binds post-shutdown auxiliary work after actual node leases returned.
    ///
    /// # Errors
    /// Refuses an incomplete reconciliation roster or unavailable aggregate.
    pub(crate) fn finish_modeled_shutdown(&mut self) -> Result<(), LifecycleApiError> {
        let completed =
            self.reconciliations
                .as_ref()
                .ok_or_else(|| LifecycleApiError::LoopFactory {
                    message: String::from("Target reconciliation registry is absent"),
                })?;
        completed.validate_operational_handoff()?;
        if let Some(broker) = self.auxiliary.as_ref() {
            let resources =
                self.resources
                    .as_ref()
                    .ok_or_else(|| LifecycleApiError::LoopFactory {
                        message: String::from("Target aggregate is absent after shutdown"),
                    })?;
            self.auxiliary_binding =
                Some(
                    broker
                        .bind(resources)
                        .map_err(|first| LifecycleApiError::LoopFactory {
                            message: first.to_string(),
                        })?,
                );
        }
        Ok(())
    }

    /// Keeps the actual API refusal in the original Target owner.
    pub(crate) fn retain_api_failure(&mut self, first: LifecycleApiError) {
        self.first_setup.get_or_insert(first.into());
    }

    /// Records the durable outcome before the actual Loop returns to Main.
    ///
    /// # Errors
    /// Refuses a conflicting second outcome without changing the first.
    pub(crate) fn record_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<(), LifecycleApiError> {
        if self.disposition.is_some_and(|saved| saved != disposition) {
            return Err(LifecycleApiError::LoopFactory {
                message: String::from("Target publication disposition changed"),
            });
        }
        self.disposition = Some(disposition);
        Ok(())
    }
}
