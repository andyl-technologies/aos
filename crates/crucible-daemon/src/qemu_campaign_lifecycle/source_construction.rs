//! Joins actual before-effects custody to the boxed Source launcher and API.

use super::*;
use crate::qemu_lifecycle_launcher::PendingSourceConstruction;
mod capture;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
mod native_observation;
mod retained;
pub(super) use capture::authenticate_resume_contents;
pub(crate) use capture::{capture_exact_prepared_source, capture_fresh_prepared_source};
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
pub(crate) use native_observation::{NativeObservationOwner, NativeObservationRetirementError};
pub(super) use retained::RetainedSourceInstall;

/// Preserves authenticated import custody before a Source Main role is born.
///
/// The exact input remains here on every failed fixed birth check. Later
/// Service and World refusals use their already installed role-bound report.
#[derive(Error)]
#[error("prepare imported Source before Main reservation: {first}")]
pub struct ImportedSourcePreparationFailure {
    capsule: crate::imported_checkpoint::UnpublishedImportedInput,
    #[source]
    first: QemuAttemptProductionVmLifecycleError,
}

impl ImportedSourcePreparationFailure {
    /// Borrows the initiating refusal without changing the retained input.
    pub fn first_error(&self) -> &QemuAttemptProductionVmLifecycleError {
        &self.first
    }

    /// Retires only the same unpublished input after its proven pre-Main refusal.
    ///
    /// The returned receipt retains the actual Transfer completion and posts.
    /// This operation creates no Service, World, launch permit or new Original.
    ///
    /// # Errors
    /// Returns the same failure if its unpublished input was already consumed.
    pub fn into_retirement(
        self,
    ) -> Result<
        (
            crate::imported_checkpoint::ImportedCheckpointReturn,
            QemuAttemptProductionVmLifecycleError,
        ),
        Self,
    > {
        let Self { capsule, first } = self;
        match capsule.into_retirement() {
            Ok(returned) => Ok((returned, first)),
            Err(capsule) => Err(Self { capsule, first }),
        }
    }
}

impl std::fmt::Debug for ImportedSourcePreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedSourcePreparationFailure")
            .field("first", &self.first)
            .finish_non_exhaustive()
    }
}

/// Preserves the actual original Main refusal before a Source body is born.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct SourceMainPreparationRefusal {
    first: crate::lifecycle_cleanup::ServiceMainPreclaimError,
}

struct SourcePreparationFailure<I> {
    input: I,
    first: QemuAttemptProductionVmLifecycleError,
}

/// Preserves metadata refusal and the native boundary's independent result.
#[derive(Debug, Error)]
#[error("Source generation storage refused: {source}; native boundary: {boundary}")]
pub struct SourceGenerationStorageRefusal {
    #[source]
    source: LifecycleApiError,
    boundary: crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport,
}

impl SourceGenerationStorageRefusal {
    /// Borrows the native boundary's original refusal and rollback history.
    #[must_use]
    pub fn native_boundary(
        &self,
    ) -> &crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport {
        &self.boundary
    }
}

/// Preserves the exact entered post-installation operation that refused.
#[derive(Debug, Error)]
pub enum SourcePostInstallationRefusal {
    /// The actual guard does not match its admitted resources or cancellation.
    #[error("Source guard does not match its admitted contract")]
    ContractMismatch,
    /// Actual native ownership or publication refused.
    #[error(transparent)]
    Native(#[from] QemuVmRealizationError),
    /// Actual host RAM ownership or publication refused.
    #[error(transparent)]
    HostRam(#[from] crucible_api::host_operational::HostRamAdmissionError),
}

impl SourceGenerationStorageRefusal {
    pub(crate) fn from_boundary(
        source: LifecycleApiError,
        boundary: crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport,
    ) -> Self {
        Self { source, boundary }
    }
}

impl SourcePostInstallationRefusal {
    pub(crate) fn into_original(self) -> QemuAttemptProductionVmLifecycleError {
        match self {
            Self::ContractMismatch => {
                QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
            }
            Self::Native(first) => {
                QemuAttemptProductionVmLifecycleError::ResourceInstallation(first)
            }
            Self::HostRam(first) => QemuAttemptProductionVmLifecycleError::HostRamAdmission(first),
        }
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Installs the same preborn constructor before the first Service effect.
    pub(crate) fn prepare_source_construction(
        &mut self,
    ) -> Result<crate::lifecycle_cleanup::ServiceMainHandle, QemuAttemptProductionVmLifecycleError>
    {
        match self.prepare_source_with_input((), PendingSourceConstruction::<R>::new_prepared) {
            Ok(handle) => Ok(handle),
            Err(SourcePreparationFailure { input: (), first }) => Err(first),
        }
    }

    /// Retains actual imported input before any startup callback can refuse.
    pub(crate) fn prepare_source_construction_with_import(
        &mut self,
        capsule: crate::imported_checkpoint::RetainedImportedCheckpoint,
    ) -> Result<crate::lifecycle_cleanup::ServiceMainHandle, ImportedSourcePreparationFailure> {
        match self.prepare_source_with_input(
            capsule,
            PendingSourceConstruction::<R>::new_prepared_with_import,
        ) {
            Ok(handle) => Ok(handle),
            Err(SourcePreparationFailure {
                input: capsule,
                first,
            }) => Err(ImportedSourcePreparationFailure {
                capsule: crate::imported_checkpoint::UnpublishedImportedInput::new(capsule),
                first,
            }),
        }
    }

    fn prepare_source_with_input<I>(
        &mut self,
        input: I,
        build: fn(
            (R, I),
            crate::WorldLifecycleCleanupReservation,
        ) -> (
            Box<PendingSourceConstruction<R>>,
            Option<crate::packaged_qemu_executor::RetainedServiceStart>,
        ),
    ) -> Result<crate::lifecycle_cleanup::ServiceMainHandle, SourcePreparationFailure<I>> {
        if let Err(first) = self.refresh_prepared_source() {
            return Err(SourcePreparationFailure { input, first });
        }
        if let Some(prepared) = self.prepared_source.as_ref() {
            return Err(SourcePreparationFailure {
                input,
                first: prepared
                    .failure("Source construction is already prepared")
                    .into(),
            });
        }
        if let Err(first) = self.require_install_vacancy() {
            return Err(SourcePreparationFailure { input, first });
        }
        let Some(factory) = self.resources.retain_fork_target_factory() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    QemuVmRealizationError::CleanupRetained {
                        operation: "retain actual Source factory before Main preparation",
                    },
                ),
            });
        };
        let Some(producer) = self.resources.source_main_producer() else {
            return Err(SourcePreparationFailure {
                input,
                first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                    SourceMainPreparationRefusal {
                        first: crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                            "actual Main has no prepared Source producer",
                        ),
                    },
                ),
            });
        };
        let bytes = match PendingSourceConstruction::<R>::control_bytes() {
            Ok(bytes) => bytes,
            Err(first) => {
                return Err(SourcePreparationFailure {
                    input,
                    first: QemuAttemptProductionVmLifecycleError::Lifecycle(first),
                });
            }
        };
        // Every fallible Main/slot/geometry check precedes the fixed birth.
        // Refusal returns the same input before a cell or body can be lost.
        let installed = match producer.reserve_with_prepared(
            crate::lifecycle_cleanup::PreparedRole::Source,
            (factory, input),
            bytes,
            build,
            crate::lifecycle_cleanup::PreparedSourceProjections {
                first: PendingSourceConstruction::<R>::project_first_error,
                history: PendingSourceConstruction::<R>::project_history,
                terminal_metadata_return: None,
            },
        ) {
            Ok(installed) => installed,
            Err(((_, input), first)) => {
                return Err(SourcePreparationFailure {
                    input,
                    first: QemuAttemptProductionVmLifecycleError::SourceMainPreparation(
                        SourceMainPreparationRefusal { first },
                    ),
                });
            }
        };
        let prepared = crate::qemu_lifecycle_launcher::PreparedSourceHandle::from_main(installed);
        let service = prepared.service_main_handle();
        self.prepared_source = Some(prepared);
        Ok(service)
    }

    /// Copies the selector for this factory's already installed Main body.
    ///
    /// Absence is a nonowning access refusal, not a fabricated cleanup receipt.
    pub(crate) fn prepared_source_handle(
        &self,
    ) -> Result<
        crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
        crate::lifecycle_cleanup::ServiceMainPreclaimError,
    > {
        self.prepared_source.clone().ok_or(
            crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                "Source construction was not prepared",
            ),
        )
    }

    fn refresh_prepared_source(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        let Some(prepared) = self.prepared_source.as_ref() else {
            return Ok(());
        };
        match prepared.is_released() {
            Ok(true) => {
                // This journal follows actual body and protected-history
                // destruction in the original role, not merely Service stop.
                self.prepared_source = None;
                self.lifecycle_outstanding = false;
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(first) => Err(prepared
                .failure_with_refusal("observe original Source role disposal", first)
                .into()),
        }
    }

    pub(super) fn selected_prepared_source(
        &mut self,
    ) -> Result<
        crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
        QemuAttemptProductionVmLifecycleError,
    > {
        self.refresh_prepared_source()?;
        self.require_install_vacancy()?;
        if self.prepared_source.is_none() {
            self.prepare_source_construction()?;
        }
        self.prepared_source_handle().map_err(|_| {
            QemuAttemptProductionVmLifecycleError::Lifecycle(
                LifecycleApiError::ConstructionCustodyUnavailable,
            )
        })
    }

    fn prepare_attempt_launcher(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        config: &ProductionVmLifecycleConfig,
        registration: ConfiguredParkDrainRegistration,
    ) -> Result<
        Box<QemuAttemptProductionVmNodeLauncher<R::Guard, R>>,
        QemuAttemptProductionVmLifecycleError,
    > {
        let prepared = self.selected_prepared_source()?;
        let terminal = self.terminal_checkpoints.clone();
        match prepared.with_pending(|pending| {
            pending.prepare_launcher(context, source, config, registration, terminal)
        }) {
            Ok(Ok(launcher)) => Ok(launcher),
            Ok(Err(())) => Err(prepared.failure("prepare Source launcher").into()),
            Err(first) => Err(prepared
                .failure_with_refusal("borrow Source launcher", first)
                .into()),
        }
    }
}

/// Restores an exact checkpoint through the already installed Source owner.
///
/// The same validation and Restore operations serve the ordinary factory and
/// its existing debug continuation. Selecting a prepared body neither reserves
/// another role nor recreates its resource factory.
pub(crate) fn resume_prepared_source<R>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    base_config: &ProductionVmLifecycleConfig,
    terminal: Option<Arc<ExactCheckpointStore>>,
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    context: &AttemptExecutionContext,
    exposure: crate::vm_lifecycle::RetainedConstructionExposure,
) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    resume_prepared_source_with(
        prepared,
        base_config,
        terminal,
        checkpoints,
        checkpoint,
        basis,
        context,
        exposure,
        || Ok(Some(())),
        |pending, ()| pending.finish_lifecycle(),
    )?
    .ok_or(QemuAttemptProductionVmLifecycleError::ResourceContractMismatch)
}

pub(super) fn resume_prepared_source_with<R, B, T>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    base_config: &ProductionVmLifecycleConfig,
    terminal: Option<Arc<ExactCheckpointStore>>,
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    context: &AttemptExecutionContext,
    exposure: crate::vm_lifecycle::RetainedConstructionExposure,
    prepare_boundary: impl FnOnce() -> Result<Option<B>, QemuAttemptProductionVmLifecycleError>,
    finish: impl FnOnce(&mut PendingSourceConstruction<R>, B) -> Result<T, ()>,
) -> Result<Option<T>, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let result = prepared.with_pending(|pending| {
        pending.require_pristine_request()?;
        pending.validate_resume_request(checkpoint, basis, context)?;
        let boundary = match prepare_boundary() {
            Ok(Some(boundary)) => boundary,
            Ok(None) => {
                // No World call occurred. The same nominal producer proof is
                // retained for actual Service-only retirement, not another try.
                pending.close_unentered_request();
                return Ok(None);
            }
            Err(first) => {
                pending.record_construction_first(first);
                return Err(());
            }
        };
        let inputs = (|| {
            let QemuExactResumeBasis {
                scenario,
                source,
                initial,
                post_selection,
            } = basis;

            let maximum_nodes = source.world().vm_nodes().len();
            if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
                return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                    maximum_nodes,
                ));
            }

            let installed = install_attempt_production_resume_checkpoint(
                checkpoints,
                checkpoint,
                source,
                initial,
                post_selection,
                context.cancellation(),
            )
            .map_err(|error| {
                QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(error))
            })?;
            let config = production_lifecycle_config_for_start(
                base_config,
                source,
                installed.configuration(),
                None,
                &[],
            )?;
            let (config, park_drain_registration) =
                config_for_assignment_host_watchdog(config, context)?;
            let decoded = installed.into_decoded();
            Ok::<_, QemuAttemptProductionVmLifecycleError>((
                scenario,
                source,
                config,
                park_drain_registration,
                decoded.into_checkpoint(),
            ))
        })();
        let (scenario, source, config, registration, checkpoint) = match inputs {
            Ok(inputs) => inputs,
            Err(first) => {
                pending.record_construction_first(first);
                return Err(());
            }
        };
        pending.prepare_lifecycle(
            context,
            scenario,
            source,
            &config,
            registration,
            terminal,
            Some(checkpoint),
            exposure,
        )?;
        finish(pending, boundary).map(Some)
    });
    complete_prepared_request(prepared, result)
}

/// Validates semantic inputs without selecting Main or starting a Service.
///
/// # Errors
/// Refuses a resume checkpoint, inconsistent scenario identity or invalid VM count.
pub(super) fn validate_fresh_source_request(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<(), QemuAttemptProductionVmLifecycleError> {
    if let Some(checkpoint) = context.resume_checkpoint() {
        return Err(QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint));
    }
    if source.scenario_def() != *scenario {
        return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
    }
    let maximum_nodes = source.world().vm_nodes().len();
    if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
        return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
            maximum_nodes,
        ));
    }
    Ok(())
}

/// Constructs the request validated before its caller selected the Main role.
///
/// # Errors
/// Retains configuration, construction and cleanup refusals in the selected role.
pub(super) fn fresh_prepared_source<R>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    base_config: &ProductionVmLifecycleConfig,
    selected_config: Option<ProductionVmLifecycleConfig>,
    terminal: Option<Arc<ExactCheckpointStore>>,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fresh_prepared_source_with(
        prepared,
        terminal,
        scenario,
        source,
        context,
        || match selected_config {
            Some(config) => Ok(config),
            None => base_config.try_clone_admitted().map_err(|source| {
                QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(source))
            }),
        },
        |pending| pending.finish_lifecycle(),
    )
}

/// Builds one validated request; capture validates within its config callback.
///
/// # Errors
/// Preserves the original role and its typed refusal when setup or completion fails.
pub(super) fn fresh_prepared_source_with<R, T>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    terminal: Option<Arc<ExactCheckpointStore>>,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
    make_config: impl FnOnce() -> Result<
        ProductionVmLifecycleConfig,
        QemuAttemptProductionVmLifecycleError,
    >,
    finish: impl FnOnce(&mut PendingSourceConstruction<R>) -> Result<T, ()>,
) -> Result<T, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let result = prepared.with_pending(|pending| {
        pending.require_pristine_request()?;
        let inputs =
            make_config().and_then(|config| config_for_assignment_host_watchdog(config, context));
        let (config, registration) = match inputs {
            Ok(inputs) => inputs,
            Err(first) => {
                pending.record_construction_first(first);
                return Err(());
            }
        };
        pending.prepare_lifecycle(
            context,
            scenario,
            source,
            &config,
            registration,
            terminal,
            None,
            crate::vm_lifecycle::RetainedConstructionExposure::Released,
        )?;
        finish(pending)
    });
    complete_prepared_request(prepared, result)
}

fn complete_prepared_request<R, T>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    result: Result<Result<T, ()>, crate::lifecycle_cleanup::ServiceMainPreclaimError>,
) -> Result<T, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    match result {
        Ok(Ok(lifecycle)) => Ok(lifecycle),
        Ok(Err(())) => Err(prepared.failure("construct Source lifecycle").into()),
        Err(first) => Err(prepared
            .failure_with_refusal("borrow Source constructor", first)
            .into()),
    }
}
