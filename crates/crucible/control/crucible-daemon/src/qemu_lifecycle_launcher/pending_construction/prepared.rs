//! Drives one Main-owned Source preparation and its all-or-restore transfers.
//!
//! The native guard and paid launcher stay in the original Pending allocation
//! through every fallible publication cut. The no-entry proof is consumed
//! before host World entry; a transferred shell cannot certify World return.

use super::*;

#[derive(Debug, thiserror::Error)]
pub(super) enum SourcePreparationFirst {
    #[error("selected fork worker request refused: {0}")]
    WorkerGeometry(#[source] crucible_engine::BackendError),
    #[error(transparent)]
    Lifecycle(#[from] crate::QemuAttemptProductionVmLifecycleError),
    #[error(transparent)]
    Role(#[from] crate::lifecycle_cleanup::ServiceMainPreclaimError),
    #[error(transparent)]
    Selection(#[from] crate::executor_worker::SelectedCheckpointSlotError),
}

impl SourcePreparationFirst {
    fn failure_ref(&self) -> crate::LifecycleFailureRef<'_> {
        use crate::LifecycleFailureRef as Failure;

        match self {
            Self::Lifecycle(first) => Failure::Lifecycle(first),
            Self::Role(first) => Failure::Role(first),
            Self::Selection(first) => Failure::Selection(first),
            Self::WorkerGeometry(first) => Failure::Backend(first),
        }
    }
}

/// Preserves a refusal to use or restore the same canonical Service context.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalContextError {
    /// The genuine containing Main refused the context observation.
    #[error(transparent)]
    Main(#[from] crate::lifecycle_cleanup::ServiceMainPreclaimError),
    /// The retained context belongs to another World request.
    #[error("retained Service context does not match this World request")]
    Mismatch,
    /// The original selected-root slot refused its context transfer.
    #[error(transparent)]
    Selection(#[from] crate::executor_worker::SelectedCheckpointSlotError),
}

impl CanonicalContextError {
    fn into_first(self) -> SourcePreparationFirst {
        match self {
            Self::Main(first) => SourcePreparationFirst::Role(first),
            Self::Selection(first) => SourcePreparationFirst::Selection(first),
            Self::Mismatch => SourcePreparationFirst::Lifecycle(
                crate::QemuAttemptProductionVmLifecycleError::ResourceContractMismatch,
            ),
        }
    }
}

/// Keeps initiating and native-retirement causes in the same Main-paid body.
#[derive(Debug, Default)]
pub(super) struct SourcePreparationHistory {
    pub(super) first: Option<SourcePreparationFirst>,
    pub(super) native: Option<QemuVmRealizationError>,
    pub(super) cleanup_first:
        Option<crucible_host_resources::host_services::process_birth::ServiceBirthError>,
    pub(super) cleanup_post:
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(super) context_restore: Option<CanonicalContextError>,
    pub(super) body_acceptance: Option<crate::lifecycle_cleanup::ServiceMainPreclaimError>,
    pub(super) preparation:
        Option<crate::vm_lifecycle::ProductionVmHotForkSourcePreparationHistory>,
}

impl SourcePreparationHistory {
    fn first_failure(&self) -> Option<crate::LifecycleFailureRef<'_>> {
        use crate::LifecycleFailureRef as Failure;
        use crate::vm_lifecycle::ProductionVmHotForkSourcePreparationError as First;

        if let Some(first) = &self.first {
            return Some(first.failure_ref());
        }
        if let Some(history) = &self.preparation {
            match history.first_error() {
                Some(First::Scheduler { source, .. }) => return Some(Failure::Scheduler(source)),
                Some(First::Backend { source, .. }) => return Some(Failure::Backend(source)),
                Some(First::Allocation(source)) => return Some(Failure::Allocation(source)),
                Some(First::Original(source)) => return Some(Failure::Control(source)),
                Some(First::EventIdentity(source)) => return Some(Failure::Engine(source)),
                Some(First::PostRefused) | None => {
                    if let Some(post) = history.post_failure() {
                        return Some(Failure::Control(post));
                    }
                }
                Some(first) => return Some(Failure::Preparation(first)),
            }
        }
        self.native
            .as_ref()
            .map(Failure::Realization)
            .or_else(|| self.cleanup_first.as_ref().map(Failure::ServiceBirth))
            .or_else(|| self.cleanup_post.as_ref().map(Failure::Supervision))
            .or_else(|| self.context_restore.as_ref().map(Failure::Context))
            .or_else(|| self.body_acceptance.as_ref().map(Failure::Role))
    }

    fn history(&self) -> crate::LifecycleHistoryRef<'_> {
        crate::LifecycleHistoryRef::SourcePreparation {
            first: self.first.as_ref().map(SourcePreparationFirst::failure_ref),
            native: self.native.as_ref(),
            cleanup_first: self.cleanup_first.as_ref(),
            cleanup_post: self.cleanup_post.as_ref(),
            context_restore: self.context_restore.as_ref(),
            body_acceptance: self.body_acceptance.as_ref(),
            capture: self.preparation.as_ref(),
        }
    }
}

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    /// Refuses re-entry before checkpoint IO or configuration/model copies.
    pub(crate) fn require_pristine_request(&self) -> Result<(), ()> {
        if self.construction_started
            || self.history.first.is_some()
            || self.history.native.is_some()
            || self.transferred
            || self.carrier_active
            || self.launcher.is_some()
            || self.launch_input.is_some()
            || self.checkpoint_input.is_some()
            || self.body_cleanup_complete
            || self.post_body.is_some()
            || self.body_disposed
            || self.post_body_taken
        {
            return Err(());
        }
        Ok(())
    }

    fn with_canonical_context<T>(
        &self,
        context: &crate::AttemptExecutionContext,
        apply: impl FnOnce(&crate::AttemptExecutionContext) -> T,
    ) -> Result<T, CanonicalContextError> {
        self.service.with_start(|start| {
            if !start.world_start_is_allowed() || !start.matches_world_context(context) {
                return Err(CanonicalContextError::Mismatch);
            }
            let actual = start.ready().map_or(context, |service| service.context());
            Ok(apply(actual))
        })?
    }

    fn require_world_context(
        &mut self,
        context: &crate::AttemptExecutionContext,
    ) -> Result<(), ()> {
        match self.with_canonical_context(context, |_| ()) {
            Ok(()) => Ok(()),
            Err(first) => {
                self.history.first.get_or_insert(first.into_first());
                Err(())
            }
        }
    }

    /// Checks the one-shot selected Root in the actual retained Service context.
    pub(crate) fn validate_resume_request(
        &mut self,
        checkpoint: crucible_campaign::ExactCheckpointId,
        basis: crate::QemuExactResumeBasis<'_>,
        context: &crate::AttemptExecutionContext,
    ) -> Result<(), ()> {
        if context.resume_checkpoint() != Some(checkpoint) {
            self.record_construction_first(
                crate::QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(
                    checkpoint,
                ),
            );
            return Err(());
        }
        match self.with_canonical_context(context, |actual| {
            crate::qemu_campaign_lifecycle::validate_exact_resume_request(checkpoint, basis, actual)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(first)) => {
                self.record_construction_first(first);
                Err(())
            }
            Err(first) => {
                self.history.first.get_or_insert(first.into_first());
                Err(())
            }
        }
    }

    fn take_canonical_selection(
        &mut self,
        context: &crate::AttemptExecutionContext,
    ) -> Result<(), ()> {
        let selected = self
            .with_canonical_context(context, |actual| {
                if actual.resume_checkpoint() != context.resume_checkpoint() {
                    return Err(CanonicalContextError::Mismatch);
                }
                actual
                    .try_take_selected_checkpoint()
                    .map_err(CanonicalContextError::Selection)
            })
            .and_then(|result| result);
        match selected {
            Ok(selected) => {
                self.selected_checkpoint = selected;
                let matches_request = match context.resume_checkpoint() {
                    Some(checkpoint) => self
                        .selected_checkpoint
                        .as_ref()
                        .is_some_and(|selected| selected.authorizes(checkpoint)),
                    None => self.selected_checkpoint.is_none(),
                };
                if !matches_request {
                    self.record_construction_first(
                        crate::QemuAttemptProductionVmLifecycleError::ResourceContractMismatch,
                    );
                    self.restore_canonical_selection(context);
                    return Err(());
                }
                Ok(())
            }
            Err(first) => {
                self.history.first.get_or_insert(first.into_first());
                Err(())
            }
        }
    }

    fn restore_canonical_selection(&mut self, context: &crate::AttemptExecutionContext) {
        let mut retained = self.selected_checkpoint.take();
        let mut restore_refusal = None;
        let result = self.with_canonical_context(context, |actual| {
            if let Some(selected) = retained.take() {
                if let Err((selected, first)) = actual.try_restore_selected_checkpoint(selected) {
                    retained = Some(selected);
                    restore_refusal = Some(first);
                }
            }
        });
        self.selected_checkpoint = retained;
        match result {
            Err(first) => {
                self.history.context_restore.get_or_insert(first);
            }
            Ok(()) => {
                if let Some(first) = restore_refusal {
                    self.history
                        .context_restore
                        .get_or_insert(CanonicalContextError::Selection(first));
                }
            }
        }
    }

    /// Enters the one genuine configured World path while Main retains this Box.
    pub(crate) fn begin_world(
        &mut self,
        context: &crate::AttemptExecutionContext,
        source: &crucible_engine::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
        consumer_geometry: impl FnOnce() -> Result<u64, LifecycleApiError>,
    ) -> Result<crucible_campaign::AttemptResourceLimits, ()>
    where
        F::Guard: crate::QemuAttemptProcessResourceGuard,
    {
        if self.construction_started || self.transferred || self.history.first.is_some() {
            return Err(());
        }
        self.construction_started = true;

        self.require_world_context(context)?;

        let prepared = match crate::qemu_campaign_lifecycle::QemuAttemptProductionVmLifecycleFactory::<
            F,
        >::prepare_native_world_with_geometry(
            context, source, config, consumer_geometry
        ) {
            Ok(prepared) => prepared,
            Err(first) => {
                self.record_construction_first(first);
                return Err(());
            }
        };
        if self.factory.is_none() {
            self.record_construction_first(
                crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    QemuVmRealizationError::CleanupRetained {
                        operation: "retain actual Source factory before World admission",
                    },
                ),
            );
            return Err(());
        }
        self.take_canonical_selection(context)?;
        let Some(factory) = self.factory.as_mut() else {
            self.record_unavailable();
            return Err(());
        };
        let crate::qemu_campaign_lifecycle::PreparedNativeWorld {
            registration,
            process_resources,
            consumer_control_bytes,
        } = prepared;
        let mut metadata_failure = None;
        let mut receiver = PendingWorldBeforeEffects {
            generation_storage: &mut self.generation_storage,
            target_nodes: &mut self.target_nodes,
            target_retained_nodes: &mut self.target_retained_nodes,
            target_storage: &mut self.target_storage,
            target_node_selection: &mut self.target_node_selection,
            target_node_storage: &mut self.target_node_storage,
            world: &mut self.world,
            reservation: &self.reservation,
            controls: &mut self.controls,
            first_failure: &mut self.history.native,
            source,
            metadata_failure: &mut metadata_failure,
        };
        let selected_checkpoint = self.selected_checkpoint.take();
        // Consuming the producer proof precedes the actual call, even when
        // that call returns no delivered loan or fails before claiming World.
        drop(self.not_started.take());
        let result = factory.begin_world(
            process_resources,
            context.cancellation().clone(),
            selected_checkpoint,
            consumer_control_bytes,
            registration.as_ref(),
            &mut receiver,
        );
        drop(receiver);
        match result {
            Ok(guard) => {
                self.returned_guard = Some(guard);
                self.admitted_resources = Some(process_resources);
                Ok(process_resources)
            }
            Err(failure) => {
                let (boundary, selected_checkpoint) = failure.into_parts();
                self.selected_checkpoint = selected_checkpoint;
                let first = match metadata_failure {
                    Some(first) => {
                        crate::QemuAttemptProductionVmLifecycleError::SourceGenerationStorage(
                            crate::qemu_campaign_lifecycle::SourceGenerationStorageRefusal::from_boundary(first, boundary),
                        )
                    }
                    None => {
                        crate::QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(
                            boundary,
                        )
                    }
                };
                self.record_construction_first(first);
                self.restore_canonical_selection(context);
                Err(())
            }
        }
    }

    /// Publishes the actual launcher only at the original role's pure commit cut.
    pub(crate) fn prepare_launcher(
        &mut self,
        context: &crate::AttemptExecutionContext,
        source: &crucible_engine::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
        registration: crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration,
        terminal_checkpoints: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
    ) -> Result<Box<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>, ()>
    where
        F::Guard: crate::QemuAttemptProcessResourceGuard,
    {
        self.prepare_retained_launcher(
            context,
            source,
            config,
            registration,
            terminal_checkpoints,
        )?;
        let service = self.service.clone();
        match service.commit_work(|| {
            let launcher =
                self.take_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>()?;
            self.transferred = true;
            Ok::<_, &'static str>(launcher)
        }) {
            Ok(Ok(launcher)) => Ok(launcher),
            Ok(Err(_)) => {
                self.record_unavailable();
                Err(())
            }
            Err(first) => {
                self.history
                    .first
                    .get_or_insert(SourcePreparationFirst::Role(first));
                Err(())
            }
        }
    }

    /// Builds and validates the existing paid launcher under Main custody.
    pub(super) fn prepare_retained_launcher(
        &mut self,
        context: &crate::AttemptExecutionContext,
        source: &crucible_engine::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
        registration: crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration,
        terminal_checkpoints: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
    ) -> Result<(), ()>
    where
        F::Guard: crate::QemuAttemptProcessResourceGuard,
    {
        if self.construction_started
            || self.transferred
            || self.history.first.is_some()
            || self.launcher.is_some()
        {
            return Err(());
        }
        self.require_world_context(context)?;
        let terminal_source = if terminal_checkpoints.is_some() {
            match source.try_clone_admitted() {
                Ok(source) => Some(source),
                Err(first) => {
                    self.record_construction_first(
                        crate::QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(first)),
                    );
                    return Err(());
                }
            }
        } else {
            None
        };
        let workers = match self.worker_geometry {
            Some(workers) => workers,
            None => match crucible_qemu_host::QemuHotForkWorkerGeometry::capture() {
                Ok(workers) => {
                    self.worker_geometry = Some(workers);
                    workers
                }
                Err(first) => {
                    self.history
                        .first
                        .get_or_insert(SourcePreparationFirst::WorkerGeometry(first));
                    return Err(());
                }
            },
        };
        let expected = self.begin_world(context, source, config, || {
            crate::QemuAttemptProductionVmNodeLauncher::<F::Guard, F>::retained_source_launcher_control_bytes(
                source.world().vm_nodes().iter().map(|node| &node.id),
                workers,
            )
        })?;
        let (guard, storage, factory, reservation, custody, world, targets) = self
            .take_launcher_parts()
            .map_err(|_| self.record_unavailable())?;
        // Every part and this empty destination were validated before moving.
        // This is the original selected launcher allocation, not another carrier.
        self.launcher = Some(Box::new(
            crate::QemuAttemptProductionVmNodeLauncher::new_registered(
                crate::QemuAttemptGenerationResourceOwner::new(guard, storage),
                registration,
                Some(factory),
            )
            .with_cleanup_reservation(reservation)
            .with_construction_custody(custody)
            .with_world_cleanup_loan(world)
            .with_target_construction_storage(targets),
        ));
        // The parts moved to this retained launcher, not an external body.
        // Main again owns the whole body before any fallible installation cut.
        self.transferred = false;
        self.finish_launcher = Some(
            finish_retained_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>,
        );
        self.take_launcher_post_body = Some(
            take_retained_launcher_post_body::<
                crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>,
            >,
        );
        let installed = self.with_launcher::<
            crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>, _,
        >(|launcher| {
            launcher.with_native_guard(|guard| {
                crate::qemu_campaign_lifecycle::QemuAttemptProductionVmLifecycleFactory::<F>::complete_native_world_guard_installation(
                    context, source, config, guard, expected,
                )
            })
        });
        match installed {
            Ok(Ok(())) => {}
            Ok(Err(first)) => {
                self.record_construction_first(first.into_original());
                return Err(());
            }
            Err(_) => {
                self.record_unavailable();
                return Err(());
            }
        }
        if let (Some(checkpoints), Some(source)) = (terminal_checkpoints, terminal_source) {
            self.with_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>, _>(
                |launcher| {
                    launcher.install_terminal_checkpoint_import(
                        checkpoints,
                        source,
                        context.cancellation().clone(),
                    )
                },
            )
            .map_err(|_| self.record_unavailable())?;
        }
        Ok(())
    }

    /// Builds the same complete body while Main continues owning the carrier.
    pub(crate) fn prepare_lifecycle(
        &mut self,
        context: &crate::AttemptExecutionContext,
        scenario: &crucible_engine::ScenarioDef,
        source: &crucible_engine::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
        registration: crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration,
        terminal: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
        checkpoint: Option<crate::vm_lifecycle::ProductionVmExactCheckpointSet>,
        exposure: crate::vm_lifecycle::RetainedConstructionExposure,
    ) -> Result<(), ()>
    where
        F::Guard: crate::QemuAttemptProcessResourceGuard,
    {
        if self.checkpoint_input.is_some() || self.launch_input.is_some() || self.carrier_active {
            return Err(());
        }
        self.checkpoint_input = checkpoint;
        self.prepare_retained_launcher(context, source, config, registration, terminal)?;
        // This internal move stays beneath the same prepared borrow. Only the
        // final complete Loop handoff is committed to the outside caller.
        let mut launcher = self
            .take_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>>()
            .map_err(|_| self.record_unavailable())?;
        // Both assignments are pure ownership moves. No callback or fallible
        // work occurs between the validated typed transfer and Main custody.
        self.construction_custody = launcher.take_construction_custody();
        self.launch_input = Some(launcher);
        let Some(custody) = self.construction_custody.as_mut() else {
            self.record_construction_first(
                crate::QemuAttemptProductionVmLifecycleError::Lifecycle(
                    LifecycleApiError::ConstructionCustodyUnavailable,
                ),
            );
            return Err(());
        };
        if let Err(first) =
            custody.install_inputs(&mut self.launch_input, &mut self.checkpoint_input)
        {
            self.record_construction_first(
                crate::QemuAttemptProductionVmLifecycleError::Lifecycle(first),
            );
            return Err(());
        }
        self.carrier_active = true;
        if let Err(first) = crate::vm_lifecycle::prepare_retained_construction(
            scenario,
            source,
            config,
            custody.as_mut(),
            exposure,
        ) {
            self.record_construction_first(
                crate::QemuAttemptProductionVmLifecycleError::Lifecycle(first),
            );
            return Err(());
        }
        Ok(())
    }

    /// Exports only the already prepared Loop at its final pure commit cut.
    pub(crate) fn finish_lifecycle(&mut self) -> Result<crate::ProductionVmLifecycleLoop, ()> {
        let service = self.service.clone();
        match service.commit_work(|| {
            let Some(custody) = self.construction_custody.take() else {
                self.record_unavailable();
                return Err(());
            };
            match custody.into_loop_with_return() {
                Ok(lifecycle) => {
                    self.carrier_active = false;
                    self.transferred = true;
                    Ok(lifecycle)
                }
                Err(custody) => {
                    self.construction_custody = Some(custody);
                    self.record_unavailable();
                    Err(())
                }
            }
        }) {
            Ok(result) => result,
            Err(first) => {
                self.history
                    .first
                    .get_or_insert(SourcePreparationFirst::Role(first));
                Err(())
            }
        }
    }

    /// Publishes replay controllers only while this same Pending owns the guard.
    pub(crate) fn begin_replay_world(
        &mut self,
        context: &crate::AttemptExecutionContext,
        source: &crucible_engine::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
    ) -> Result<(), ()>
    where
        F::Guard: crate::QemuAttemptProcessResourceGuard,
    {
        let expected = self.begin_world(context, source, config, || {
            crate::qemu_baked_genesis::replay_world_control_bytes(source)
        })?;
        let Some(guard) = self.returned_guard.as_mut() else {
            self.record_unavailable();
            return Err(());
        };
        match crate::qemu_campaign_lifecycle::QemuAttemptProductionVmLifecycleFactory::<F>::complete_native_world_guard_installation(
            context, source, config, guard, expected,
        ) {
            Ok(()) => match self.service.commit_work(|| ()) {
                Ok(()) => Ok(()),
                Err(first) => {
                    self.history.first.get_or_insert(SourcePreparationFirst::Role(first));
                    Err(())
                }
            },
            Err(first) => {
                self.record_construction_first(first.into_original());
                Err(())
            }
        }
    }

    /// Borrows the exact concrete launcher without moving its allocation.
    pub(crate) fn with_launcher<T: Send + 'static, U>(
        &mut self,
        apply: impl FnOnce(&mut T) -> U,
    ) -> Result<U, &'static str> {
        let launcher = self
            .launcher
            .as_mut()
            .and_then(|launcher| launcher.downcast_mut::<T>())
            .ok_or("same prepared launcher is absent or has another type")?;
        Ok(apply(launcher))
    }

    /// Moves the same successfully installed Box to its actual lifecycle.
    pub(crate) fn take_launcher<T: Send + 'static>(&mut self) -> Result<Box<T>, &'static str> {
        if self.history.first.is_some()
            || self
                .launcher
                .as_ref()
                .is_none_or(|launcher| !launcher.is::<T>())
        {
            return Err("same prepared launcher is not ready for transfer");
        }
        let Some(launcher) = self.launcher.take() else {
            return Err("same prepared launcher is absent");
        };
        match launcher.downcast::<T>() {
            Ok(launcher) => {
                self.finish_launcher = None;
                self.take_launcher_post_body = None;
                Ok(launcher)
            }
            Err(launcher) => {
                self.launcher = Some(launcher);
                Err("same prepared launcher type changed during transfer")
            }
        }
    }

    /// Returns the actual successful World request saved with its retained guard.
    pub(crate) fn admitted_resources(&self) -> Option<crucible_campaign::AttemptResourceLimits> {
        self.admitted_resources
    }

    /// Borrows an entered native guard without granting a second World entry.
    pub(crate) fn with_native<T>(
        &mut self,
        apply: impl FnOnce(&mut F::Guard) -> T,
    ) -> Result<T, crate::lifecycle_cleanup::ServiceMainPreclaimError> {
        if !self.construction_started
            || self.not_started.is_some()
            || self.transferred
            || self.history.first.is_some()
        {
            return Err(crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                "same prepared Source has no active retained native guard",
            ));
        }
        let guard = self.returned_guard.as_mut().ok_or(
            crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                "same prepared Source native guard is absent",
            ),
        )?;
        Ok(apply(guard))
    }

    /// Borrows the original typed construction cause without moving custody.
    pub(crate) fn first_error(&self) -> Option<crate::LifecycleFailureRef<'_>> {
        self.history.first_failure()
    }

    /// Projects only this concrete Pending type from its original Main Box.
    pub(crate) fn project_first_error(
        owner: &(dyn std::any::Any + Send),
    ) -> Option<crate::LifecycleFailureRef<'_>> {
        owner.downcast_ref::<Self>().and_then(Self::first_error)
    }

    /// Borrows every independent cause without moving the retained body.
    pub(crate) fn project_history(
        owner: &(dyn std::any::Any + Send),
        apply: &mut dyn FnMut(&'static str, crate::LifecycleHistoryRef<'_>),
    ) {
        let Some(owner) = owner.downcast_ref::<Self>() else {
            return;
        };
        apply("Source preparation", owner.history.history());
    }

    pub(super) fn record_unavailable(&mut self) {
        self.record_construction_first(crate::QemuAttemptProductionVmLifecycleError::Lifecycle(
            LifecycleApiError::ConstructionCustodyUnavailable,
        ));
    }

    /// Retains the initiating raw error before returning a role-bound report.
    ///
    /// Callers pass only errors from the scoped operation. Protected role
    /// reports are created after releasing Main's borrow and returned outward;
    /// retaining one here would pin this same role and recurse in diagnostics.
    pub(crate) fn record_construction_first(
        &mut self,
        first: crate::QemuAttemptProductionVmLifecycleError,
    ) {
        self.history.first.get_or_insert(first.into());
    }

    /// Borrows Service without creating another owning Service alias.
    pub(crate) fn service_main_handle(&self) -> crate::lifecycle_cleanup::ServiceMainHandle {
        self.service.clone()
    }

    /// Moves every validated part once, leaving the same Main Box as a tombstone.
    ///
    /// No callback, allocation or fallible physical effect separates validation
    /// from the moves. The tombstone cannot certify World return; its history
    /// must meet the actual launcher postbody in the original role.
    pub(crate) fn take_launcher_parts(
        &mut self,
    ) -> Result<
        (
            F::Guard,
            crate::QemuAttemptGenerationStorage,
            F,
            crate::WorldLifecycleCleanupReservation,
            Box<crate::ProductionVmConstructionCustody>,
            AuthenticatedNativeWorldCleanupLoan,
            TargetConstructionStorage,
        ),
        &'static str,
    > {
        if self.transferred
            || self.launcher.is_some()
            || self.finish_launcher.is_some()
            || self.take_launcher_post_body.is_some()
            || self.history.first.is_some()
            || self.history.native.is_some()
            || self.not_started.is_some()
            || self.returned_guard.is_none()
            || self.generation_storage.is_none()
            || self.target_storage.is_none()
            || self.factory.is_none()
            || self
                .reservation
                .as_ref()
                .is_none_or(|reservation| !reservation.is_reserved())
            || self.controls.is_some()
            || self.construction_custody.is_none()
            || self.world.is_none()
        {
            return Err("same Pending retains an incomplete launcher transfer");
        }

        let parts = (
            self.returned_guard.take(),
            self.generation_storage.take(),
            self.factory.take(),
            self.reservation.take(),
            self.construction_custody.take(),
            self.world.take(),
            self.target_storage.take(),
        );
        match parts {
            (
                Some(guard),
                Some(storage),
                Some(factory),
                Some(reservation),
                Some(custody),
                Some(world),
                Some(targets),
            ) => {
                self.transferred = true;
                Ok((
                    guard,
                    storage,
                    factory,
                    reservation,
                    custody,
                    world,
                    targets,
                ))
            }
            (guard, storage, factory, reservation, custody, world, targets) => {
                // Preserve all original owners even if this validation is
                // changed incorrectly in a future refactor.
                self.returned_guard = guard;
                self.generation_storage = storage;
                self.factory = factory;
                self.reservation = reservation;
                self.construction_custody = custody;
                self.world = world;
                self.target_storage = targets;
                Err("same Pending required parts changed during transfer")
            }
        }
    }
}

fn finish_retained_launcher<T>(
    owner: &mut (dyn std::any::Any + Send),
) -> Result<(), crate::ProductionVmConstructionCleanupError>
where
    T: ProductionVmNodeLauncher + Send + 'static,
{
    let launcher = owner
        .downcast_mut::<T>()
        .ok_or(LifecycleApiError::ConstructionCustodyUnavailable)?;
    launcher.finish()
}

fn take_retained_launcher_post_body<T>(
    owner: &mut (dyn std::any::Any + Send),
) -> Result<
    Option<crate::ProductionVmConstructionPostBody>,
    crate::ProductionVmConstructionCleanupError,
>
where
    T: ProductionVmNodeLauncher + Send + 'static,
{
    let launcher = owner
        .downcast_mut::<T>()
        .ok_or(LifecycleApiError::ConstructionCustodyUnavailable)?;
    ProductionVmCleanupOwner::take_post_body(launcher)
}

/// Borrows only delivery/preparation fields, never a second native factory.
struct PendingWorldBeforeEffects<'a, G: QemuAttemptResourceGuard> {
    generation_storage: &'a mut Option<crate::QemuAttemptGenerationStorage>,
    target_nodes:
        &'a mut Option<Vec<crate::qemu_hot_fork_reconciliation::TargetNodeConstruction<G>>>,
    target_retained_nodes:
        &'a mut Option<Vec<crate::qemu_hot_fork_reconciliation::TargetNodeConstruction<G>>>,
    target_node_selection:
        &'a mut Option<crate::qemu_resource_guard::QemuGenerationStorageSelection>,
    target_storage: &'a mut Option<TargetConstructionStorage>,
    target_node_storage: &'a mut Option<crate::QemuAttemptGenerationStorage>,
    world: &'a mut Option<AuthenticatedNativeWorldCleanupLoan>,
    reservation: &'a Option<crate::WorldLifecycleCleanupReservation>,
    controls: &'a mut Option<AuthenticatedNativeWorldControlLease>,
    first_failure: &'a mut Option<QemuVmRealizationError>,
    source: &'a crucible_engine::ScenarioDefForm,
    metadata_failure: &'a mut Option<LifecycleApiError>,
}

impl<G: QemuAttemptResourceGuard> crucible_qemu_host::LinuxQemuNativeWorldConstructor
    for PendingWorldBeforeEffects<'_, G>
{
    fn retain_world(
        &mut self,
        loan: AuthenticatedNativeWorldCleanupLoan,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Result<(), &'static str> {
        *self.world = Some(loan);
        let returned = match self.reservation.as_ref() {
            Some(reservation) => reservation.attach_controls(controls),
            None => Err(controls),
        };
        match returned {
            Ok(()) => Ok(()),
            Err(controls) => {
                *self.controls = Some(controls);
                self.first_failure
                    .get_or_insert(QemuVmRealizationError::CleanupRetained {
                        operation: "attach exact World controls to its Main preclaim",
                    });
                Err("attach exact World controls to its Main preclaim")
            }
        }
    }

    fn prepare_world(&mut self) -> Result<(), QemuVmRealizationError> {
        let prepared = if self.generation_storage.is_some() {
            Err(launcher_message("generation storage was already prepared"))
        } else {
            crate::QemuAttemptGenerationStorage::prepare(
                self.source.world().vm_nodes().iter().map(|node| &node.id),
            )
        };
        match prepared {
            Ok(storage) => {
                // Hold the actual registry even if the independent row payload
                // cannot be allocated. All World ownership already reached Main.
                *self.target_node_selection = Some(storage.selection());
                *self.target_node_storage = Some(storage.lend_existing());
                let rows = crate::qemu_hot_fork_reconciliation::TargetNodeConstruction::prepare(
                    self.source.world().vm_nodes().iter().map(|node| &node.id),
                    &storage,
                );
                *self.generation_storage = Some(storage);
                match rows {
                    Ok(rows) => {
                        *self.target_nodes = Some(rows);
                        let storage = self.generation_storage.as_ref().ok_or(
                            QemuVmRealizationError::CleanupRetained {
                                operation: "retain selected Source generation storage",
                            },
                        )?;
                        // Both actual buffers are priced by this same World
                        // before Source birth. Retain the first on refusal of
                        // the second; failure is not an empty metadata proof.
                        *self.target_retained_nodes = Some(
                            crate::qemu_hot_fork_reconciliation::TargetNodeConstruction::prepare(
                                self.source.world().vm_nodes().iter().map(|node| &node.id),
                                storage,
                            )
                            .map_err(|first| {
                                *self.metadata_failure = Some(first);
                                QemuVmRealizationError::CleanupRetained {
                                    operation: "prepare durable Target row payload",
                                }
                            })?,
                        );
                        match TargetConstructionStorage::prepare(
                            self.source.world().vm_nodes().iter().map(|node| &node.id),
                            storage,
                        ) {
                            Ok(target_storage) => {
                                *self.target_storage = Some(target_storage);
                                Ok(())
                            }
                            Err(first) => {
                                *self.metadata_failure = Some(first);
                                Err(QemuVmRealizationError::CleanupRetained {
                                    operation: "selected Target native storage preparation refused",
                                })
                            }
                        }
                    }
                    Err(first) => {
                        *self.metadata_failure = Some(first);
                        Err(QemuVmRealizationError::CleanupRetained {
                            operation: "selected Target row preparation refused",
                        })
                    }
                }
            }
            Err(first) => {
                *self.metadata_failure = Some(first);
                Err(QemuVmRealizationError::CleanupRetained {
                    operation: "selected generation preparation refused",
                })
            }
        }
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;

    fn native(message: &str) -> QemuVmRealizationError {
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "component prepared history",
            message: message.to_owned(),
        }
    }

    #[test]
    fn pending_history_preserves_constructor_and_independent_native_allocation() {
        let constructor = native("constructor first");
        let cleanup = native("later native cleanup");
        let pointer = |error: &QemuVmRealizationError| match error {
            QemuVmRealizationError::ExecutorUnavailable { message, .. } => message.as_ptr(),
            _ => panic!("unexpected fixture variant"),
        };
        let constructor_pointer = pointer(&constructor);
        let cleanup_pointer = pointer(&cleanup);
        let history = SourcePreparationHistory {
            first: Some(SourcePreparationFirst::Lifecycle(
                crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(constructor),
            )),
            native: Some(cleanup),
            ..SourcePreparationHistory::default()
        };

        let Some(crate::LifecycleFailureRef::Lifecycle(original)) = history.first_failure() else {
            panic!("the original lifecycle cause remains selected");
        };
        let crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(original) = original
        else {
            panic!("original typed cause was replaced");
        };
        assert_eq!(pointer(original), constructor_pointer);
        assert_eq!(pointer(history.native.as_ref().unwrap()), cleanup_pointer);

        let crate::LifecycleHistoryRef::SourcePreparation {
            first: Some(crate::LifecycleFailureRef::Lifecycle(first)),
            native: Some(native),
            ..
        } = history.history()
        else {
            panic!("the original first and independent cleanup remain observable together");
        };
        let crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(first) = first
        else {
            panic!("the typed constructor cause changed");
        };
        assert_eq!(pointer(first), constructor_pointer);
        assert_eq!(pointer(native), cleanup_pointer);
    }

    #[test]
    fn pending_capture_preserves_initiating_leaf_and_independent_work_post() {
        use crate::vm_lifecycle::{
            ProductionVmHotForkSourcePreparationError as First,
            ProductionVmHotForkSourcePreparationHistory,
        };
        // Diagnostic values only: no Main role or cleanup authority is issued.
        let message = String::from("capture boundary refused");
        let original_allocation = message.as_ptr();
        let post = String::from("independent capture post refused");
        let post_allocation = post.as_ptr();
        let history = SourcePreparationHistory {
            preparation: Some(ProductionVmHotForkSourcePreparationHistory::from_failures(
                Some(First::Scheduler {
                    operation: "component source capture",
                    source: crucible_engine::SchedulerError::BoundaryViolation { message },
                }),
                Some(crucible_control_api::LifecycleApiError::LoopFactory { message: post }),
            )),
            native: Some(native("later native cleanup")),
            ..Default::default()
        };

        let Some(crate::LifecycleFailureRef::Scheduler(original)) = history.first_failure() else {
            panic!("the original scheduler capture cause remains selected");
        };

        let crucible_engine::SchedulerError::BoundaryViolation { message } = original else {
            panic!("the actual capture leaf remains selected");
        };
        assert_eq!(message.as_ptr(), original_allocation);
        let Some(crucible_control_api::LifecycleApiError::LoopFactory { message }) =
            history.preparation.as_ref().unwrap().post_failure()
        else {
            panic!("the independent work post remains separately retained");
        };
        assert_eq!(message.as_ptr(), post_allocation);
        assert!(history.native.is_some());
    }

    #[test]
    fn pending_capture_post_precedes_later_native_cleanup_without_replacing_it() {
        use crate::vm_lifecycle::{
            ProductionVmHotForkSourcePreparationError as First,
            ProductionVmHotForkSourcePreparationHistory,
        };
        let message = String::from("actual capture post refused");
        let original_allocation = message.as_ptr();
        let cleanup = native("later native cleanup");
        let QemuVmRealizationError::ExecutorUnavailable {
            message: cleanup_message,
            ..
        } = &cleanup else {
            panic!("unexpected fixture variant");
        };
        let cleanup_allocation = cleanup_message.as_ptr();
        let history = SourcePreparationHistory {
            preparation: Some(ProductionVmHotForkSourcePreparationHistory::from_failures(
                Some(First::PostRefused),
                Some(crucible_control_api::LifecycleApiError::LoopFactory { message }),
            )),
            native: Some(cleanup),
            ..Default::default()
        };

        let Some(crate::LifecycleFailureRef::Control(original)) = history.first_failure() else {
            panic!("the actual capture post remains selected");
        };

        let crucible_control_api::LifecycleApiError::LoopFactory { message } = original else {
            panic!("the actual post remains selected instead of its marker");
        };
        assert_eq!(message.as_ptr(), original_allocation);
        let capture = history.preparation.as_ref().unwrap();
        assert!(matches!(capture.first_error(), Some(First::PostRefused)));
        assert!(std::ptr::eq(original, capture.post_failure().unwrap()));
        let Some(QemuVmRealizationError::ExecutorUnavailable { message, .. }) = &history.native
        else {
            panic!("the independent native cleanup cause remains retained");
        };
        assert_eq!(message.as_ptr(), cleanup_allocation);
    }

    #[test]
    fn pending_history_keeps_same_constructor_and_body_error_allocations() {
        // Actual Pending history storage only: no role, World or closed-body
        // flag is manufactured to test diagnostic ownership.
        let first = native("constructor first");
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &first else {
            panic!("unexpected fixture variant");
        };
        let first_pointer = message.as_ptr();
        let cleanup_message = String::from("body return refused");
        let cleanup_pointer = cleanup_message.as_ptr();
        let history = SourcePreparationHistory {
            first: Some(SourcePreparationFirst::Lifecycle(
                crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(first),
            )),
            cleanup_first: Some(
                crucible_host_resources::host_services::process_birth::ServiceBirthError::Policy(
                    cleanup_message,
                ),
            ),
            ..SourcePreparationHistory::default()
        };

        let Some(crate::LifecycleFailureRef::Lifecycle(original)) = history.first_failure() else {
            panic!("the original lifecycle cause remains selected");
        };
        let crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::ExecutorUnavailable { message, .. },
        ) = original
        else {
            panic!("original cause was replaced");
        };
        assert_eq!(message.as_ptr(), first_pointer);
        let Some(crucible_host_resources::host_services::process_birth::ServiceBirthError::Policy(
            message,
        )) = &history.cleanup_first
        else {
            panic!("body cause was replaced");
        };
        assert_eq!(message.as_ptr(), cleanup_pointer);
        let Some(SourcePreparationFirst::Lifecycle(stored)) = history.first.as_ref() else {
            panic!("the original constructor phase remains retained");
        };
        assert!(std::ptr::eq(original, stored));
        assert!(history.cleanup_post.is_none());
    }

    #[test]
    fn pending_history_keeps_begin_rollback_separate_from_later_cleanup() {
        let failure = crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::rollback(
            native("constructor first"),
            crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(
                native("begin rollback"),
            ),
        );
        let (report, _) = failure.into_parts();
        let history = SourcePreparationHistory {
            first: Some(SourcePreparationFirst::Lifecycle(
                crate::QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report),
            )),
            native: Some(native("later actual cleanup")),
            ..SourcePreparationHistory::default()
        };

        let Some(crate::LifecycleFailureRef::Lifecycle(original)) = history.first_failure() else {
            panic!("the original lifecycle cause remains selected");
        };
        let crate::QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report) =
            original
        else {
            panic!("begin report was replaced");
        };
        assert!(
            matches!(report.first_error(), QemuVmRealizationError::ExecutorUnavailable { message, .. } if message == "constructor first")
        );
        assert!(
            matches!(report.cleanup_error(), Some(QemuVmRealizationError::ExecutorUnavailable { message, .. }) if message == "begin rollback")
        );
        assert!(
            matches!(history.native, Some(QemuVmRealizationError::ExecutorUnavailable { message, .. }) if message == "later actual cleanup")
        );
    }
}
